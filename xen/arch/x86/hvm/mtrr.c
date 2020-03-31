/*
 * mtrr.c: MTRR/PAT virtualization
 *
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <asm/e820.h>
#include <asm/iocap.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mtrr.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <public/hvm/e820.h>

/* Get page attribute fields (PAn) from PAT MSR. */
#define pat_cr_2_paf(pat_cr,n)  ((((uint64_t)pat_cr) >> ((n)<<3)) & 0xff)

/* PAT entry to PTE flags (PAT, PCD, PWT bits). */
static const uint8_t pat_entry_2_pte_flags[8] = {
    0,           _PAGE_PWT,
    _PAGE_PCD,   _PAGE_PCD | _PAGE_PWT,
    _PAGE_PAT,   _PAGE_PAT | _PAGE_PWT,
    _PAGE_PAT | _PAGE_PCD, _PAGE_PAT | _PAGE_PCD | _PAGE_PWT };

/* Effective mm type lookup table, according to MTRR and PAT. */
static const uint8_t mm_type_tbl[MTRR_NUM_TYPES][PAT_TYPE_NUMS] = {
#define RS MEMORY_NUM_TYPES
#define UC MTRR_TYPE_UNCACHABLE
#define WB MTRR_TYPE_WRBACK
#define WC MTRR_TYPE_WRCOMB
#define WP MTRR_TYPE_WRPROT
#define WT MTRR_TYPE_WRTHROUGH

/*          PAT(UC, WC, RS, RS, WT, WP, WB, UC-) */
/* MTRR(UC) */ {UC, WC, RS, RS, UC, UC, UC, UC},
/* MTRR(WC) */ {UC, WC, RS, RS, UC, UC, WC, WC},
/* MTRR(RS) */ {RS, RS, RS, RS, RS, RS, RS, RS},
/* MTRR(RS) */ {RS, RS, RS, RS, RS, RS, RS, RS},
/* MTRR(WT) */ {UC, WC, RS, RS, WT, WP, WT, UC},
/* MTRR(WP) */ {UC, WC, RS, RS, WT, WP, WP, WC},
/* MTRR(WB) */ {UC, WC, RS, RS, WT, WP, WB, UC}

#undef UC
#undef WC
#undef WT
#undef WP
#undef WB
#undef RS
};

/*
 * Reverse lookup table, to find a pat type according to MTRR and effective
 * memory type. This table is dynamically generated.
 */
static uint8_t __read_mostly mtrr_epat_tbl[MTRR_NUM_TYPES][MEMORY_NUM_TYPES] =
    { [0 ... MTRR_NUM_TYPES-1] =
        { [0 ... MEMORY_NUM_TYPES-1] = INVALID_MEM_TYPE }
    };

/* Lookup table for PAT entry of a given PAT value in host PAT. */
static uint8_t __read_mostly pat_entry_tbl[PAT_TYPE_NUMS] =
    { [0 ... PAT_TYPE_NUMS-1] = INVALID_MEM_TYPE };

static int __init hvm_mtrr_pat_init(void)
{
    unsigned int i, j;

    for ( i = 0; i < MTRR_NUM_TYPES; i++ )
    {
        for ( j = 0; j < PAT_TYPE_NUMS; j++ )
        {
            unsigned int tmp = mm_type_tbl[i][j];

            if ( tmp < MEMORY_NUM_TYPES )
                mtrr_epat_tbl[i][tmp] = j;
        }
    }

    for ( i = 0; i < PAT_TYPE_NUMS; i++ )
    {
        for ( j = 0; j < PAT_TYPE_NUMS; j++ )
        {
            if ( pat_cr_2_paf(XEN_MSR_PAT, j) == i )
            {
                pat_entry_tbl[i] = j;
                break;
            }
        }
    }

    return 0;
}
__initcall(hvm_mtrr_pat_init);

uint8_t pat_type_2_pte_flags(uint8_t pat_type)
{
    unsigned int pat_entry = pat_entry_tbl[pat_type];

    /*
     * INVALID_MEM_TYPE, means doesn't find the pat_entry in host PAT for a
     * given pat_type. If host PAT covers all the PAT types, it can't happen.
     */
    if ( unlikely(pat_entry == INVALID_MEM_TYPE) )
        pat_entry = pat_entry_tbl[PAT_TYPE_UNCACHABLE];

    return pat_entry_2_pte_flags[pat_entry];
}

int hvm_vcpu_cacheattr_init(struct vcpu *v)
{
    struct mtrr_state *m = &v->arch.hvm.mtrr;
    unsigned int num_var_ranges =
        is_hardware_domain(v->domain) ? MASK_EXTR(mtrr_state.mtrr_cap,
                                                  MTRRcap_VCNT)
                                      : MTRR_VCNT;

    if ( num_var_ranges > MTRR_VCNT_MAX )
    {
        ASSERT(is_hardware_domain(v->domain));
        printk("WARNING: limited Dom%u variable range MTRRs from %u to %u\n",
               v->domain->domain_id, num_var_ranges, MTRR_VCNT_MAX);
        num_var_ranges = MTRR_VCNT_MAX;
    }

    memset(m, 0, sizeof(*m));

    m->var_ranges = xzalloc_array(struct mtrr_var_range, num_var_ranges);
    if ( m->var_ranges == NULL )
        return -ENOMEM;

    m->mtrr_cap = (1u << 10) | (1u << 8) | num_var_ranges;

    v->arch.hvm.pat_cr =
        ((uint64_t)PAT_TYPE_WRBACK) |               /* PAT0: WB */
        ((uint64_t)PAT_TYPE_WRTHROUGH << 8) |       /* PAT1: WT */
        ((uint64_t)PAT_TYPE_UC_MINUS << 16) |       /* PAT2: UC- */
        ((uint64_t)PAT_TYPE_UNCACHABLE << 24) |     /* PAT3: UC */
        ((uint64_t)PAT_TYPE_WRBACK << 32) |         /* PAT4: WB */
        ((uint64_t)PAT_TYPE_WRTHROUGH << 40) |      /* PAT5: WT */
        ((uint64_t)PAT_TYPE_UC_MINUS << 48) |       /* PAT6: UC- */
        ((uint64_t)PAT_TYPE_UNCACHABLE << 56);      /* PAT7: UC */

    if ( is_hardware_domain(v->domain) )
    {
        /* Copy values from the host. */
        struct domain *d = v->domain;
        unsigned int i;

        if ( mtrr_state.have_fixed )
            for ( i = 0; i < NUM_FIXED_MSR; i++ )
                mtrr_fix_range_msr_set(d, m, i,
                                      ((uint64_t *)mtrr_state.fixed_ranges)[i]);

        for ( i = 0; i < num_var_ranges; i++ )
        {
            mtrr_var_range_msr_set(d, m, MSR_IA32_MTRR_PHYSBASE(i),
                                   mtrr_state.var_ranges[i].base);
            mtrr_var_range_msr_set(d, m, MSR_IA32_MTRR_PHYSMASK(i),
                                   mtrr_state.var_ranges[i].mask);
        }

        mtrr_def_type_msr_set(d, m,
                              mtrr_state.def_type |
                              MASK_INSR(mtrr_state.fixed_enabled,
                                        MTRRdefType_FE) |
                              MASK_INSR(mtrr_state.enabled, MTRRdefType_E));
    }

    return 0;
}

void hvm_vcpu_cacheattr_destroy(struct vcpu *v)
{
    xfree(v->arch.hvm.mtrr.var_ranges);
}

/*
 * Get MTRR memory type for physical address pa.
 *
 * May return a negative value when order > 0, indicating to the caller
 * that the respective mapping needs splitting.
 */
static int get_mtrr_type(const struct mtrr_state *m,
                         paddr_t pa, unsigned int order)
{
   uint8_t     overlap_mtrr = 0;
   uint8_t     overlap_mtrr_pos = 0;
   uint64_t    mask = -(uint64_t)PAGE_SIZE << order;
   unsigned int seg, num_var_ranges = MASK_EXTR(m->mtrr_cap, MTRRcap_VCNT);

   if ( unlikely(!m->enabled) )
       return MTRR_TYPE_UNCACHABLE;

   pa &= mask;
   if ( (pa < 0x100000) && m->fixed_enabled )
   {
       /* Fixed range MTRR takes effect. */
       uint32_t addr = (uint32_t)pa, index;

       if ( addr < 0x80000 )
       {
           /* 0x00000 ... 0x7FFFF in 64k steps */
           if ( order > 4 )
               return -1;
           seg = (addr >> 16);
           return m->fixed_ranges[seg];
       }
       else if ( addr < 0xc0000 )
       {
           /* 0x80000 ... 0xBFFFF in 16k steps */
           if ( order > 2 )
               return -1;
           seg = (addr - 0x80000) >> 14;
           index = (seg >> 3) + 1;
           seg &= 7;            /* select 0-7 segments */
           return m->fixed_ranges[index*8 + seg];
       }
       else
       {
           /* 0xC0000 ... 0xFFFFF in 4k steps */
           if ( order )
               return -1;
           seg = (addr - 0xc0000) >> 12;
           index = (seg >> 3) + 3;
           seg &= 7;            /* select 0-7 segments */
           return m->fixed_ranges[index*8 + seg];
       }
   }

   /* Match with variable MTRRs. */
   for ( seg = 0; seg < num_var_ranges; seg++ )
   {
       uint64_t phys_base = m->var_ranges[seg].base;
       uint64_t phys_mask = m->var_ranges[seg].mask;

       if ( phys_mask & MTRR_PHYSMASK_VALID )
       {
           phys_mask &= mask;
           if ( (pa & phys_mask) == (phys_base & phys_mask) )
           {
               if ( unlikely(m->overlapped) || order )
               {
                    overlap_mtrr |= 1 << (phys_base & MTRR_PHYSBASE_TYPE_MASK);
                    overlap_mtrr_pos = phys_base & MTRR_PHYSBASE_TYPE_MASK;
               }
               else
               {
                   /* If no overlap, return the found one */
                   return (phys_base & MTRR_PHYSBASE_TYPE_MASK);
               }
           }
       }
   }

   /* Not found? */
   if ( unlikely(overlap_mtrr == 0) )
       return m->def_type;

   /* One match, or multiple identical ones? */
   if ( likely(overlap_mtrr == (1 << overlap_mtrr_pos)) )
       return overlap_mtrr_pos;

   if ( order )
       return -1;

   /* Two or more matches, one being UC? */
   if ( overlap_mtrr & (1 << MTRR_TYPE_UNCACHABLE) )
       return MTRR_TYPE_UNCACHABLE;

   /* Two or more matches, all of them WT and WB? */
   if ( overlap_mtrr ==
        ((1 << MTRR_TYPE_WRTHROUGH) | (1 << MTRR_TYPE_WRBACK)) )
       return MTRR_TYPE_WRTHROUGH;

   /* Behaviour is undefined, but return the last overlapped type. */
   return overlap_mtrr_pos;
}

/*
 * return the memory type from PAT.
 * NOTE: valid only when paging is enabled.
 *       Only 4K page PTE is supported now.
 */
static uint8_t page_pat_type(uint64_t pat_cr, uint32_t pte_flags)
{
    int32_t pat_entry;

    /* PCD/PWT -> bit 1/0 of PAT entry */
    pat_entry = ( pte_flags >> 3 ) & 0x3;
    /* PAT bits as bit 2 of PAT entry */
    if ( pte_flags & _PAGE_PAT )
        pat_entry |= 4;

    return (uint8_t)pat_cr_2_paf(pat_cr, pat_entry);
}

/*
 * Effective memory type for leaf page.
 */
static uint8_t effective_mm_type(struct mtrr_state *m,
                                 uint64_t pat,
                                 paddr_t gpa,
                                 uint32_t pte_flags,
                                 uint8_t gmtrr_mtype)
{
    uint8_t mtrr_mtype, pat_value;
   
    /* if get_pat_flags() gives a dedicated MTRR type,
     * just use it
     */ 
    if ( gmtrr_mtype == NO_HARDCODE_MEM_TYPE )
        mtrr_mtype = get_mtrr_type(m, gpa, 0);
    else
        mtrr_mtype = gmtrr_mtype;

    pat_value = page_pat_type(pat, pte_flags);

    return mm_type_tbl[mtrr_mtype][pat_value];
}

uint32_t get_pat_flags(struct vcpu *v,
                       uint32_t gl1e_flags,
                       paddr_t gpaddr,
                       paddr_t spaddr,
                       uint8_t gmtrr_mtype)
{
    uint8_t guest_eff_mm_type;
    uint8_t shadow_mtrr_type;
    uint8_t pat_entry_value;
    uint64_t pat = v->arch.hvm.pat_cr;
    struct mtrr_state *g = &v->arch.hvm.mtrr;

    /* 1. Get the effective memory type of guest physical address,
     * with the pair of guest MTRR and PAT
     */
    guest_eff_mm_type = effective_mm_type(g, pat, gpaddr, 
                                          gl1e_flags, gmtrr_mtype);
    /* 2. Get the memory type of host physical address, with MTRR */
    shadow_mtrr_type = get_mtrr_type(&mtrr_state, spaddr, 0);

    /* 3. Find the memory type in PAT, with host MTRR memory type
     * and guest effective memory type.
     */
    pat_entry_value = mtrr_epat_tbl[shadow_mtrr_type][guest_eff_mm_type];
    /* If conflit occurs(e.g host MTRR is UC, guest memory type is
     * WB),set UC as effective memory. Here, returning PAT_TYPE_UNCACHABLE will
     * always set effective memory as UC.
     */
    if ( pat_entry_value == INVALID_MEM_TYPE )
    {
        struct domain *d = v->domain;
        p2m_type_t p2mt;
        get_gfn_query_unlocked(d, paddr_to_pfn(gpaddr), &p2mt);
        if (p2m_is_ram(p2mt))
            gdprintk(XENLOG_WARNING,
                    "Conflict occurs for a given guest l1e flags:%x "
                    "at %"PRIx64" (the effective mm type:%d), "
                    "because the host mtrr type is:%d\n",
                    gl1e_flags, (uint64_t)gpaddr, guest_eff_mm_type,
                    shadow_mtrr_type);
        pat_entry_value = PAT_TYPE_UNCACHABLE;
    }
    /* 4. Get the pte flags */
    return pat_type_2_pte_flags(pat_entry_value);
}

static inline bool_t valid_mtrr_type(uint8_t type)
{
    switch ( type )
    {
    case MTRR_TYPE_UNCACHABLE:
    case MTRR_TYPE_WRBACK:
    case MTRR_TYPE_WRCOMB:
    case MTRR_TYPE_WRPROT:
    case MTRR_TYPE_WRTHROUGH:
        return 1;
    }
    return 0;
}

bool_t mtrr_def_type_msr_set(struct domain *d, struct mtrr_state *m,
                             uint64_t msr_content)
{
    uint8_t def_type = msr_content & 0xff;
    bool fixed_enabled = MASK_EXTR(msr_content, MTRRdefType_FE);
    bool enabled = MASK_EXTR(msr_content, MTRRdefType_E);

    if ( unlikely(!valid_mtrr_type(def_type)) )
    {
         HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid MTRR def type:%x\n", def_type);
         return 0;
    }

    if ( unlikely(msr_content && (msr_content & ~0xcffUL)) )
    {
         HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid msr content:%"PRIx64"\n",
                     msr_content);
         return 0;
    }

    if ( m->enabled != enabled || m->fixed_enabled != fixed_enabled ||
         m->def_type != def_type )
    {
        m->enabled = enabled;
        m->def_type = def_type;
        m->fixed_enabled = fixed_enabled;
        memory_type_changed(d);
    }

    return 1;
}

bool_t mtrr_fix_range_msr_set(struct domain *d, struct mtrr_state *m,
                              uint32_t row, uint64_t msr_content)
{
    uint64_t *fixed_range_base = (uint64_t *)m->fixed_ranges;

    if ( fixed_range_base[row] != msr_content )
    {
        uint8_t *range = (uint8_t*)&msr_content;
        unsigned int i;

        for ( i = 0; i < 8; i++ )
            if ( unlikely(!valid_mtrr_type(range[i])) )
                return 0;

        fixed_range_base[row] = msr_content;

        if ( m->enabled && m->fixed_enabled )
            memory_type_changed(d);
    }

    return 1;
}

bool_t mtrr_var_range_msr_set(
    struct domain *d, struct mtrr_state *m, uint32_t msr, uint64_t msr_content)
{
    uint32_t index, phys_addr;
    uint64_t msr_mask;
    uint64_t *var_range_base = (uint64_t*)m->var_ranges;

    index = msr - MSR_IA32_MTRR_PHYSBASE(0);
    if ( (index / 2) >= MASK_EXTR(m->mtrr_cap, MTRRcap_VCNT) )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    if ( var_range_base[index] == msr_content )
        return 1;

    if ( unlikely(!valid_mtrr_type((uint8_t)msr_content)) )
        return 0;

    if ( d == current->domain )
        phys_addr = d->arch.cpuid->extd.maxphysaddr;
    else
        phys_addr = paddr_bits;
    msr_mask = ~((((uint64_t)1) << phys_addr) - 1);
    msr_mask |= (index & 1) ? 0x7ffUL : 0xf00UL;
    if ( unlikely(msr_content & msr_mask) )
    {
        HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid msr content:%"PRIx64"\n",
                    msr_content);
        return 0;
    }

    var_range_base[index] = msr_content;

    m->overlapped = is_var_mtrr_overlapped(m);

    if ( m->enabled )
        memory_type_changed(d);

    return 1;
}

bool mtrr_pat_not_equal(const struct vcpu *vd, const struct vcpu *vs)
{
    const struct mtrr_state *md = &vd->arch.hvm.mtrr;
    const struct mtrr_state *ms = &vs->arch.hvm.mtrr;

    if ( md->enabled != ms->enabled )
        return true;

    if ( md->enabled )
    {
        unsigned int num_var_ranges = MASK_EXTR(md->mtrr_cap, MTRRcap_VCNT);

        /* Test default type MSR. */
        if ( md->def_type != ms->def_type )
            return true;

        /* Test fixed ranges. */
        if ( md->fixed_enabled != ms->fixed_enabled )
            return true;

        if ( md->fixed_enabled &&
             memcmp(md->fixed_ranges, ms->fixed_ranges,
                    sizeof(md->fixed_ranges)) )
            return true;

        /* Test variable ranges. */
        if ( num_var_ranges != MASK_EXTR(ms->mtrr_cap, MTRRcap_VCNT) ||
             memcmp(md->var_ranges, ms->var_ranges,
                    num_var_ranges * sizeof(*md->var_ranges)) )
            return true;
    }

    /* Test PAT. */
    return vd->arch.hvm.pat_cr != vs->arch.hvm.pat_cr;
}

struct hvm_mem_pinned_cacheattr_range {
    struct list_head list;
    uint64_t start, end;
    uint32_t type;
    struct rcu_head rcu;
};

static DEFINE_RCU_READ_LOCK(pinned_cacheattr_rcu_lock);

void hvm_init_cacheattr_region_list(struct domain *d)
{
    INIT_LIST_HEAD(&d->arch.hvm.pinned_cacheattr_ranges);
}

void hvm_destroy_cacheattr_region_list(struct domain *d)
{
    struct list_head *head = &d->arch.hvm.pinned_cacheattr_ranges;
    struct hvm_mem_pinned_cacheattr_range *range;

    while ( !list_empty(head) )
    {
        range = list_entry(head->next,
                           struct hvm_mem_pinned_cacheattr_range,
                           list);
        list_del(&range->list);
        xfree(range);
    }
}

int hvm_get_mem_pinned_cacheattr(struct domain *d, gfn_t gfn,
                                 unsigned int order)
{
    struct hvm_mem_pinned_cacheattr_range *range;
    uint64_t mask = ~(uint64_t)0 << order;
    int rc = -ENXIO;

    ASSERT(is_hvm_domain(d));

    rcu_read_lock(&pinned_cacheattr_rcu_lock);
    list_for_each_entry_rcu ( range,
                              &d->arch.hvm.pinned_cacheattr_ranges,
                              list )
    {
        if ( ((gfn_x(gfn) & mask) >= range->start) &&
             ((gfn_x(gfn) | ~mask) <= range->end) )
        {
            rc = range->type;
            break;
        }
        if ( ((gfn_x(gfn) & mask) <= range->end) &&
             ((gfn_x(gfn) | ~mask) >= range->start) )
        {
            rc = -EADDRNOTAVAIL;
            break;
        }
    }
    rcu_read_unlock(&pinned_cacheattr_rcu_lock);

    return rc;
}

static void free_pinned_cacheattr_entry(struct rcu_head *rcu)
{
    xfree(container_of(rcu, struct hvm_mem_pinned_cacheattr_range, rcu));
}

int hvm_set_mem_pinned_cacheattr(struct domain *d, uint64_t gfn_start,
                                 uint64_t gfn_end, uint32_t type)
{
    struct hvm_mem_pinned_cacheattr_range *range;
    int rc = 1;

    if ( !is_hvm_domain(d) )
        return -EOPNOTSUPP;

    if ( gfn_end < gfn_start || (gfn_start | gfn_end) >> paddr_bits )
        return -EINVAL;

    switch ( type )
    {
    case XEN_DOMCTL_DELETE_MEM_CACHEATTR:
        /* Remove the requested range. */
        rcu_read_lock(&pinned_cacheattr_rcu_lock);
        list_for_each_entry_rcu ( range,
                                  &d->arch.hvm.pinned_cacheattr_ranges,
                                  list )
            if ( range->start == gfn_start && range->end == gfn_end )
            {
                rcu_read_unlock(&pinned_cacheattr_rcu_lock);
                list_del_rcu(&range->list);
                type = range->type;
                call_rcu(&range->rcu, free_pinned_cacheattr_entry);
                p2m_memory_type_changed(d);
                switch ( type )
                {
                case PAT_TYPE_UC_MINUS:
                    /*
                     * For EPT we can also avoid the flush in this case;
                     * see epte_get_entry_emt().
                     */
                    if ( hap_enabled(d) && cpu_has_vmx )
                case PAT_TYPE_UNCACHABLE:
                        break;
                    /* fall through */
                default:
                    flush_all(FLUSH_CACHE);
                    break;
                }
                return 0;
            }
        rcu_read_unlock(&pinned_cacheattr_rcu_lock);
        return -ENOENT;

    case PAT_TYPE_UC_MINUS:
    case PAT_TYPE_UNCACHABLE:
    case PAT_TYPE_WRBACK:
    case PAT_TYPE_WRCOMB:
    case PAT_TYPE_WRPROT:
    case PAT_TYPE_WRTHROUGH:
        break;

    default:
        return -EINVAL;
    }

    rcu_read_lock(&pinned_cacheattr_rcu_lock);
    list_for_each_entry_rcu ( range,
                              &d->arch.hvm.pinned_cacheattr_ranges,
                              list )
    {
        if ( range->start == gfn_start && range->end == gfn_end )
        {
            range->type = type;
            rc = 0;
            break;
        }
        if ( range->start <= gfn_end && gfn_start <= range->end )
        {
            rc = -EBUSY;
            break;
        }
    }
    rcu_read_unlock(&pinned_cacheattr_rcu_lock);
    if ( rc <= 0 )
        return rc;

    range = xzalloc(struct hvm_mem_pinned_cacheattr_range);
    if ( range == NULL )
        return -ENOMEM;

    range->start = gfn_start;
    range->end = gfn_end;
    range->type = type;

    list_add_rcu(&range->list, &d->arch.hvm.pinned_cacheattr_ranges);
    p2m_memory_type_changed(d);
    if ( type != PAT_TYPE_WRBACK )
        flush_all(FLUSH_CACHE);

    return 0;
}

static int hvm_save_mtrr_msr(struct vcpu *v, hvm_domain_context_t *h)
{
    const struct mtrr_state *mtrr_state = &v->arch.hvm.mtrr;
    struct hvm_hw_mtrr hw_mtrr = {
        .msr_mtrr_def_type = mtrr_state->def_type |
                             MASK_INSR(mtrr_state->fixed_enabled,
                                       MTRRdefType_FE) |
                            MASK_INSR(mtrr_state->enabled, MTRRdefType_E),
        .msr_mtrr_cap      = mtrr_state->mtrr_cap,
    };
    unsigned int i;

    if ( MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT) >
         (ARRAY_SIZE(hw_mtrr.msr_mtrr_var) / 2) )
    {
        dprintk(XENLOG_G_ERR,
                "HVM save: %pv: too many (%lu) variable range MTRRs\n",
                v, MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT));
        return -EINVAL;
    }

    hvm_get_guest_pat(v, &hw_mtrr.msr_pat_cr);

    for ( i = 0; i < MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT); i++ )
    {
        hw_mtrr.msr_mtrr_var[i * 2] = mtrr_state->var_ranges->base;
        hw_mtrr.msr_mtrr_var[i * 2 + 1] = mtrr_state->var_ranges->mask;
    }

    BUILD_BUG_ON(sizeof(hw_mtrr.msr_mtrr_fixed) !=
                 sizeof(mtrr_state->fixed_ranges));

    memcpy(hw_mtrr.msr_mtrr_fixed, mtrr_state->fixed_ranges,
           sizeof(hw_mtrr.msr_mtrr_fixed));

    return hvm_save_entry(MTRR, v->vcpu_id, h, &hw_mtrr);
}

static int hvm_load_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid, i;
    struct vcpu *v;
    struct mtrr_state *mtrr_state;
    struct hvm_hw_mtrr hw_mtrr;

    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry(MTRR, h, &hw_mtrr) != 0 )
        return -EINVAL;

    if ( MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT) > MTRR_VCNT )
    {
        dprintk(XENLOG_G_ERR,
                "HVM restore: %pv: too many (%lu) variable range MTRRs\n",
                v, MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT));
        return -EINVAL;
    }

    mtrr_state = &v->arch.hvm.mtrr;

    hvm_set_guest_pat(v, hw_mtrr.msr_pat_cr);

    mtrr_state->mtrr_cap = hw_mtrr.msr_mtrr_cap;

    for ( i = 0; i < NUM_FIXED_MSR; i++ )
        mtrr_fix_range_msr_set(d, mtrr_state, i, hw_mtrr.msr_mtrr_fixed[i]);

    for ( i = 0; i < MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT); i++ )
    {
        mtrr_var_range_msr_set(d, mtrr_state,
                               MSR_IA32_MTRR_PHYSBASE(i),
                               hw_mtrr.msr_mtrr_var[i * 2]);
        mtrr_var_range_msr_set(d, mtrr_state,
                               MSR_IA32_MTRR_PHYSMASK(i),
                               hw_mtrr.msr_mtrr_var[i * 2 + 1]);
    }

    mtrr_def_type_msr_set(d, mtrr_state, hw_mtrr.msr_mtrr_def_type);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(MTRR, hvm_save_mtrr_msr, hvm_load_mtrr_msr, 1,
                          HVMSR_PER_VCPU);

void memory_type_changed(struct domain *d)
{
    if ( (is_iommu_enabled(d) || cache_flush_permitted(d)) &&
         d->vcpu && d->vcpu[0] )
    {
        p2m_memory_type_changed(d);
        flush_all(FLUSH_CACHE);
    }
}

int epte_get_entry_emt(struct domain *d, unsigned long gfn, mfn_t mfn,
                       unsigned int order, uint8_t *ipat, bool_t direct_mmio)
{
    int gmtrr_mtype, hmtrr_mtype;
    struct vcpu *v = current;

    *ipat = 0;

    if ( v->domain != d )
        v = d->vcpu ? d->vcpu[0] : NULL;

    /* Mask, not add, for order so it works with INVALID_MFN on unmapping */
    if ( rangeset_overlaps_range(mmio_ro_ranges, mfn_x(mfn),
                                 mfn_x(mfn) | ((1UL << order) - 1)) )
    {
        if ( !order || rangeset_contains_range(mmio_ro_ranges, mfn_x(mfn),
                                               mfn_x(mfn) | ((1UL << order) - 1)) )
        {
            *ipat = 1;
            return MTRR_TYPE_UNCACHABLE;
        }
        /* Force invalid memory type so resolve_misconfig() will split it */
        return -1;
    }

    if ( direct_mmio )
    {
        if ( (mfn_x(mfn) ^ mfn_x(d->arch.hvm.vmx.apic_access_mfn)) >> order )
            return MTRR_TYPE_UNCACHABLE;
        if ( order )
            return -1;
        *ipat = 1;
        return MTRR_TYPE_WRBACK;
    }

    if ( !mfn_valid(mfn) )
    {
        *ipat = 1;
        return MTRR_TYPE_UNCACHABLE;
    }

    if ( !is_iommu_enabled(d) && !cache_flush_permitted(d) )
    {
        *ipat = 1;
        return MTRR_TYPE_WRBACK;
    }

    gmtrr_mtype = hvm_get_mem_pinned_cacheattr(d, _gfn(gfn), order);
    if ( gmtrr_mtype >= 0 )
    {
        *ipat = 1;
        return gmtrr_mtype != PAT_TYPE_UC_MINUS ? gmtrr_mtype
                                                : MTRR_TYPE_UNCACHABLE;
    }
    if ( gmtrr_mtype == -EADDRNOTAVAIL )
        return -1;

    gmtrr_mtype = is_hvm_domain(d) && v ?
                  get_mtrr_type(&v->arch.hvm.mtrr,
                                gfn << PAGE_SHIFT, order) :
                  MTRR_TYPE_WRBACK;
    hmtrr_mtype = get_mtrr_type(&mtrr_state, mfn_x(mfn) << PAGE_SHIFT, order);
    if ( gmtrr_mtype < 0 || hmtrr_mtype < 0 )
        return -1;

    /* If both types match we're fine. */
    if ( likely(gmtrr_mtype == hmtrr_mtype) )
        return hmtrr_mtype;

    /* If either type is UC, we have to go with that one. */
    if ( gmtrr_mtype == MTRR_TYPE_UNCACHABLE ||
         hmtrr_mtype == MTRR_TYPE_UNCACHABLE )
        return MTRR_TYPE_UNCACHABLE;

    /* If either type is WB, we have to go with the other one. */
    if ( gmtrr_mtype == MTRR_TYPE_WRBACK )
        return hmtrr_mtype;
    if ( hmtrr_mtype == MTRR_TYPE_WRBACK )
        return gmtrr_mtype;

    /*
     * At this point we have disagreeing WC, WT, or WP types. The only
     * combination that can be cleanly resolved is WT:WP. The ones involving
     * WC need to be converted to UC, both due to the memory ordering
     * differences and because WC disallows reads to be cached (WT and WP
     * permit this), while WT and WP require writes to go straight to memory
     * (WC can buffer them).
     */
    if ( (gmtrr_mtype == MTRR_TYPE_WRTHROUGH &&
          hmtrr_mtype == MTRR_TYPE_WRPROT) ||
         (gmtrr_mtype == MTRR_TYPE_WRPROT &&
          hmtrr_mtype == MTRR_TYPE_WRTHROUGH) )
        return MTRR_TYPE_WRPROT;

    return MTRR_TYPE_UNCACHABLE;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
