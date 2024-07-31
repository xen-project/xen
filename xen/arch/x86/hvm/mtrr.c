/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mtrr.c: MTRR/PAT virtualization
 *
 * Copyright (c) 2007, Intel Corporation.
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
#define pat_cr_2_paf(pat_cr, n) (((uint64_t)(pat_cr) >> ((n) << 3)) & 0xff)

/* Effective mm type lookup table, according to MTRR and PAT. */
static const uint8_t mm_type_tbl[MTRR_NUM_TYPES][X86_NUM_MT] = {
#define RS MEMORY_NUM_TYPES
#define UC X86_MT_UC
#define WB X86_MT_WB
#define WC X86_MT_WC
#define WP X86_MT_WP
#define WT X86_MT_WT

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
static uint8_t __read_mostly pat_entry_tbl[X86_NUM_MT] =
    { [0 ... X86_NUM_MT - 1] = INVALID_MEM_TYPE };

static int __init cf_check hvm_mtrr_pat_init(void)
{
    unsigned int i, j;

    for ( i = 0; i < MTRR_NUM_TYPES; i++ )
    {
        for ( j = 0; j < X86_NUM_MT; j++ )
        {
            unsigned int tmp = mm_type_tbl[i][j];

            if ( tmp < MEMORY_NUM_TYPES )
                mtrr_epat_tbl[i][tmp] = j;
        }
    }

    for ( i = 0; i < X86_NUM_MT; i++ )
    {
        for ( j = 0; j < X86_NUM_MT; j++ )
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
        pat_entry = pat_entry_tbl[X86_MT_UC];

    return cacheattr_to_pte_flags(pat_entry);
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
        ((uint64_t)X86_MT_WB) |           /* PAT0: WB */
        ((uint64_t)X86_MT_WT << 8) |      /* PAT1: WT */
        ((uint64_t)X86_MT_UCM << 16) |    /* PAT2: UC- */
        ((uint64_t)X86_MT_UC << 24) |     /* PAT3: UC */
        ((uint64_t)X86_MT_WB << 32) |     /* PAT4: WB */
        ((uint64_t)X86_MT_WT << 40) |     /* PAT5: WT */
        ((uint64_t)X86_MT_UCM << 48) |    /* PAT6: UC- */
        ((uint64_t)X86_MT_UC << 56);      /* PAT7: UC */

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
int mtrr_get_type(const struct mtrr_state *m, paddr_t pa, unsigned int order)
{
   uint8_t     overlap_mtrr = 0;
   uint8_t     overlap_mtrr_pos = 0;
   uint64_t    mask = -(uint64_t)PAGE_SIZE << order;
   unsigned int seg, num_var_ranges = MASK_EXTR(m->mtrr_cap, MTRRcap_VCNT);

   if ( unlikely(!m->enabled) )
       return X86_MT_UC;

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
   if ( overlap_mtrr & (1 << X86_MT_UC) )
       return X86_MT_UC;

   /* Two or more matches, all of them WT and WB? */
   if ( overlap_mtrr ==
        ((1 << X86_MT_WT) | (1 << X86_MT_WB)) )
       return X86_MT_WT;

   /* Behaviour is undefined, but return the last overlapped type. */
   return overlap_mtrr_pos;
}

#ifdef CONFIG_SHADOW_PAGING

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
        mtrr_mtype = mtrr_get_type(m, gpa, 0);
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
    shadow_mtrr_type = mtrr_get_type(&mtrr_state, spaddr, 0);

    /* 3. Find the memory type in PAT, with host MTRR memory type
     * and guest effective memory type.
     */
    pat_entry_value = mtrr_epat_tbl[shadow_mtrr_type][guest_eff_mm_type];
    /* If conflit occurs(e.g host MTRR is UC, guest memory type is
     * WB), set UC as effective memory. Here, returning X86_MT_UC will
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
        pat_entry_value = X86_MT_UC;
    }
    /* 4. Get the pte flags */
    return pat_type_2_pte_flags(pat_entry_value);
}

#endif /* CONFIG_SHADOW_PAGING */

static inline bool valid_mtrr_type(uint8_t type)
{
    switch ( type )
    {
    case X86_MT_UC:
    case X86_MT_WB:
    case X86_MT_WC:
    case X86_MT_WP:
    case X86_MT_WT:
        return 1;
    }
    return 0;
}

bool mtrr_def_type_msr_set(struct domain *d, struct mtrr_state *m,
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

bool mtrr_fix_range_msr_set(struct domain *d, struct mtrr_state *m,
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

bool mtrr_var_range_msr_set(
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

static void cf_check free_pinned_cacheattr_entry(struct rcu_head *rcu)
{
    xfree(container_of(rcu, struct hvm_mem_pinned_cacheattr_range, rcu));
}

int hvm_set_mem_pinned_cacheattr(struct domain *d, uint64_t gfn_start,
                                 uint64_t gfn_end, uint32_t type)
{
    struct hvm_mem_pinned_cacheattr_range *range, *newr;
    unsigned int nr = 0;
    int rc = 1;

    if ( !is_hvm_domain(d) )
        return -EOPNOTSUPP;

    if ( gfn_end < gfn_start || (gfn_start | gfn_end) >> paddr_bits )
        return -EINVAL;

    switch ( type )
    {
    case XEN_DOMCTL_DELETE_MEM_CACHEATTR:
        /* Remove the requested range. */
        domain_lock(d);
        list_for_each_entry ( range,
                              &d->arch.hvm.pinned_cacheattr_ranges,
                              list )
            if ( range->start == gfn_start && range->end == gfn_end )
            {
                list_del_rcu(&range->list);
                domain_unlock(d);

                type = range->type;
                call_rcu(&range->rcu, free_pinned_cacheattr_entry);
                p2m_memory_type_changed(d);
                switch ( type )
                {
                case X86_MT_UCM:
                    /*
                     * For EPT we can also avoid the flush in this case;
                     * see epte_get_entry_emt().
                     */
                    if ( hap_enabled(d) && cpu_has_vmx )
                case X86_MT_UC:
                        break;
                    /* fall through */
                default:
                    flush_all(FLUSH_CACHE);
                    break;
                }
                return 0;
            }
        domain_unlock(d);
        return -ENOENT;

    case X86_MT_UCM:
    case X86_MT_UC:
    case X86_MT_WB:
    case X86_MT_WC:
    case X86_MT_WP:
    case X86_MT_WT:
        break;

    default:
        return -EINVAL;
    }

    newr = xzalloc(struct hvm_mem_pinned_cacheattr_range);

    domain_lock(d);

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
        ++nr;
    }

    if ( rc <= 0 )
        /* nothing */;
    else if ( nr >= 64 /* The limit is arbitrary. */ )
        rc = -ENOSPC;
    else if ( !newr )
        rc = -ENOMEM;
    else
    {
        newr->start = gfn_start;
        newr->end = gfn_end;
        newr->type = type;

        list_add_rcu(&newr->list, &d->arch.hvm.pinned_cacheattr_ranges);

        newr = NULL;
        rc = 0;
    }

    domain_unlock(d);

    xfree(newr);

    p2m_memory_type_changed(d);
    if ( type != X86_MT_WB )
        flush_all(FLUSH_CACHE);

    return rc;
}

static int cf_check hvm_save_mtrr_msr(struct vcpu *v, hvm_domain_context_t *h)
{
    const struct mtrr_state *m = &v->arch.hvm.mtrr;
    struct hvm_hw_mtrr hw_mtrr = {
        .msr_mtrr_def_type = m->def_type |
                             MASK_INSR(m->fixed_enabled,
                                       MTRRdefType_FE) |
                            MASK_INSR(m->enabled, MTRRdefType_E),
        .msr_mtrr_cap      = m->mtrr_cap,
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
        hw_mtrr.msr_mtrr_var[i * 2] = m->var_ranges->base;
        hw_mtrr.msr_mtrr_var[i * 2 + 1] = m->var_ranges->mask;
    }

    BUILD_BUG_ON(sizeof(hw_mtrr.msr_mtrr_fixed) !=
                 sizeof(m->fixed_ranges));

    memcpy(hw_mtrr.msr_mtrr_fixed, m->fixed_ranges,
           sizeof(hw_mtrr.msr_mtrr_fixed));

    return hvm_save_entry(MTRR, v->vcpu_id, h, &hw_mtrr);
}

static int cf_check hvm_load_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid, i;
    struct vcpu *v;
    struct mtrr_state *m;
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

    m = &v->arch.hvm.mtrr;

    hvm_set_guest_pat(v, hw_mtrr.msr_pat_cr);

    m->mtrr_cap = hw_mtrr.msr_mtrr_cap;

    for ( i = 0; i < NUM_FIXED_MSR; i++ )
        mtrr_fix_range_msr_set(d, m, i, hw_mtrr.msr_mtrr_fixed[i]);

    for ( i = 0; i < MASK_EXTR(hw_mtrr.msr_mtrr_cap, MTRRcap_VCNT); i++ )
    {
        mtrr_var_range_msr_set(d, m,
                               MSR_IA32_MTRR_PHYSBASE(i),
                               hw_mtrr.msr_mtrr_var[i * 2]);
        mtrr_var_range_msr_set(d, m,
                               MSR_IA32_MTRR_PHYSMASK(i),
                               hw_mtrr.msr_mtrr_var[i * 2 + 1]);
    }

    mtrr_def_type_msr_set(d, m, hw_mtrr.msr_mtrr_def_type);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(MTRR, hvm_save_mtrr_msr, NULL, hvm_load_mtrr_msr, 1,
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
