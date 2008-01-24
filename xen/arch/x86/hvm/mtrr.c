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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <public/hvm/e820.h>
#include <xen/types.h>
#include <asm/e820.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/domain_page.h>
#include <asm/mtrr.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>

/* Xen holds the native MTRR MSRs */
extern struct mtrr_state mtrr_state;

static uint64_t phys_base_msr_mask;
static uint64_t phys_mask_msr_mask;
static uint32_t size_or_mask;
static uint32_t size_and_mask;

static void init_pat_entry_tbl(uint64_t pat);
static void init_mtrr_epat_tbl(void);
static uint8_t get_mtrr_type(struct mtrr_state *m, paddr_t pa);
/* get page attribute fields (PAn) from PAT MSR */
#define pat_cr_2_paf(pat_cr,n)  ((((uint64_t)pat_cr) >> ((n)<<3)) & 0xff)
/* pat entry to PTE flags (PAT, PCD, PWT bits) */
static uint8_t pat_entry_2_pte_flags[8] = {
    0,           _PAGE_PWT,
    _PAGE_PCD,   _PAGE_PCD | _PAGE_PWT,
    _PAGE_PAT,   _PAGE_PAT | _PAGE_PWT,
    _PAGE_PAT | _PAGE_PCD, _PAGE_PAT | _PAGE_PCD | _PAGE_PWT };

/* effective mm type lookup table, according to MTRR and PAT */
static uint8_t mm_type_tbl[MTRR_NUM_TYPES][PAT_TYPE_NUMS] = {
/********PAT(UC,WC,RS,RS,WT,WP,WB,UC-)*/
/* RS means reserved type(2,3), and type is hardcoded here */
 /*MTRR(UC):(UC,WC,RS,RS,UC,UC,UC,UC)*/
            {0, 1, 2, 2, 0, 0, 0, 0},
 /*MTRR(WC):(UC,WC,RS,RS,UC,UC,WC,WC)*/
            {0, 1, 2, 2, 0, 0, 1, 1},
 /*MTRR(RS):(RS,RS,RS,RS,RS,RS,RS,RS)*/
            {2, 2, 2, 2, 2, 2, 2, 2},
 /*MTRR(RS):(RS,RS,RS,RS,RS,RS,RS,RS)*/
            {2, 2, 2, 2, 2, 2, 2, 2},
 /*MTRR(WT):(UC,WC,RS,RS,WT,WP,WT,UC)*/
            {0, 1, 2, 2, 4, 5, 4, 0},
 /*MTRR(WP):(UC,WC,RS,RS,WT,WP,WP,WC)*/
            {0, 1, 2, 2, 4, 5, 5, 1},
 /*MTRR(WB):(UC,WC,RS,RS,WT,WP,WB,UC)*/
            {0, 1, 2, 2, 4, 5, 6, 0}
};

/* reverse lookup table, to find a pat type according to MTRR and effective
 * memory type. This table is dynamically generated
 */
static uint8_t mtrr_epat_tbl[MTRR_NUM_TYPES][MEMORY_NUM_TYPES];

/* lookup table for PAT entry of a given PAT value in host pat */
static uint8_t pat_entry_tbl[PAT_TYPE_NUMS];

static void get_mtrr_range(uint64_t base_msr, uint64_t mask_msr,
                           uint64_t *base, uint64_t *end)
{
    uint32_t mask_lo = (uint32_t)mask_msr;
    uint32_t mask_hi = (uint32_t)(mask_msr >> 32);
    uint32_t base_lo = (uint32_t)base_msr;
    uint32_t base_hi = (uint32_t)(base_msr >> 32);
    uint32_t size;

    if ( (mask_lo & 0x800) == 0 )
    {
        /* Invalid (i.e. free) range */
        *base = 0;
        *end = 0;
        return;
    }

    /* Work out the shifted address mask. */
    mask_lo = (size_or_mask | (mask_hi << (32 - PAGE_SHIFT)) |
               (mask_lo >> PAGE_SHIFT));

    /* This works correctly if size is a power of two (a contiguous range). */
    size = -mask_lo;
    *base = base_hi << (32 - PAGE_SHIFT) | base_lo >> PAGE_SHIFT;
    *end = *base + size - 1;
}

bool_t is_var_mtrr_overlapped(struct mtrr_state *m)
{
    int32_t seg, i;
    uint64_t phys_base, phys_mask, phys_base_pre, phys_mask_pre;
    uint64_t base_pre, end_pre, base, end;
    uint8_t num_var_ranges = (uint8_t)m->mtrr_cap;

    for ( i = 0; i < num_var_ranges; i++ )
    {
        phys_base_pre = ((uint64_t*)m->var_ranges)[i*2];
        phys_mask_pre = ((uint64_t*)m->var_ranges)[i*2 + 1];

        get_mtrr_range(phys_base_pre, phys_mask_pre,
                        &base_pre, &end_pre);

        for ( seg = i + 1; seg < num_var_ranges; seg ++ )
        {
            phys_base = ((uint64_t*)m->var_ranges)[seg*2];
            phys_mask = ((uint64_t*)m->var_ranges)[seg*2 + 1];

            get_mtrr_range(phys_base, phys_mask,
                            &base, &end);

            if ( ((base_pre != end_pre) && (base != end))
                 || ((base >= base_pre) && (base <= end_pre))
                 || ((end >= base_pre) && (end <= end_pre))
                 || ((base_pre >= base) && (base_pre <= end))
                 || ((end_pre >= base) && (end_pre <= end)) )
            {
                /* MTRR is overlapped. */
                return 1;
            }
        }
    }
    return 0;
}

/* reserved mtrr for guest OS */
#define RESERVED_MTRR 2
#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)
bool_t mtrr_var_range_msr_set(struct mtrr_state *m, uint32_t msr,
                              uint64_t msr_content);
bool_t mtrr_def_type_msr_set(struct mtrr_state *m, uint64_t msr_content);
bool_t mtrr_fix_range_msr_set(struct mtrr_state *m, uint32_t row,
                              uint64_t msr_content);
static void set_var_mtrr(uint32_t reg, struct mtrr_state *m,
                         uint32_t base, uint32_t size,
                         uint32_t type)
{
    struct mtrr_var_range *vr;

    vr = &m->var_ranges[reg];

    if ( size == 0 )
    {
        /* The invalid bit is kept in the mask, so we simply clear the
         * relevant mask register to disable a range.
         */
        mtrr_var_range_msr_set(m, MTRRphysMask_MSR(reg), 0);
    }
    else
    {
        vr->base_lo = base << PAGE_SHIFT | type;
        vr->base_hi = (base & size_and_mask) >> (32 - PAGE_SHIFT);
        vr->mask_lo = -size << PAGE_SHIFT | 0x800;
        vr->mask_hi = (-size & size_and_mask) >> (32 - PAGE_SHIFT);

        mtrr_var_range_msr_set(m, MTRRphysBase_MSR(reg), *(uint64_t *)vr);
        mtrr_var_range_msr_set(m, MTRRphysMask_MSR(reg),
                               *((uint64_t *)vr + 1));
    }
}
/* From Intel Vol. III Section 10.11.4, the Range Size and Base Alignment has
 * some kind of requirement:
 * 1. The range size must be 2^N byte for N >= 12 (i.e 4KB minimum).
 * 2. The base address must be 2^N aligned, where the N here is equal to
 * the N in previous requirement. So a 8K range must be 8K aligned not 4K aligned.
 */
static uint32_t range_to_mtrr(uint32_t reg, struct mtrr_state *m,
                              uint32_t range_startk, uint32_t range_sizek,
                              uint8_t type)
{
    if ( !range_sizek || (reg >= ((m->mtrr_cap & 0xff) - RESERVED_MTRR)) )
    {
        gdprintk(XENLOG_WARNING,
                "Failed to init var mtrr msr[%d]"
                "range_size:%x, total available MSR:%d\n",
                reg, range_sizek,
                (uint32_t)((m->mtrr_cap & 0xff) - RESERVED_MTRR));
        return reg;
    }

    while ( range_sizek )
    {
        uint32_t max_align, align, sizek;

        max_align = (range_startk == 0) ? 32 : ffs(range_startk);
        align = min_t(uint32_t, fls(range_sizek), max_align);
        sizek = 1 << (align - 1);

        set_var_mtrr(reg++, m, range_startk, sizek, type);

        range_startk += sizek;
        range_sizek  -= sizek;

        if ( reg >= ((m->mtrr_cap & 0xff) - RESERVED_MTRR) )
        {
            gdprintk(XENLOG_WARNING,
                    "Failed to init var mtrr msr[%d],"
                    "total available MSR:%d\n",
                    reg, (uint32_t)((m->mtrr_cap & 0xff) - RESERVED_MTRR));
            break;
        }
    }

    return reg;
}

static void setup_fixed_mtrrs(struct vcpu *v)
{
    uint64_t content;
    int32_t i;
    struct mtrr_state *m = &v->arch.hvm_vcpu.mtrr;

    /* 1. Map (0~A0000) as WB */
    content = 0x0606060606060606ull;
    mtrr_fix_range_msr_set(m, 0, content);
    mtrr_fix_range_msr_set(m, 1, content);
    /* 2. Map VRAM(A0000~C0000) as WC */
    content = 0x0101010101010101;
    mtrr_fix_range_msr_set(m, 2, content);
    /* 3. Map (C0000~100000) as UC */
    for ( i = 3; i < 11; i++)
        mtrr_fix_range_msr_set(m, i, 0);
}

static void setup_var_mtrrs(struct vcpu *v)
{
    p2m_type_t p2m;
    uint64_t e820_mfn;
    int8_t *p = NULL;
    uint8_t nr = 0;
    int32_t i;
    uint32_t reg = 0;
    uint64_t size = 0;
    uint64_t addr = 0;
    struct e820entry *e820_table;

    e820_mfn = mfn_x(gfn_to_mfn(v->domain,
                    HVM_E820_PAGE >> PAGE_SHIFT, &p2m));

    p = (int8_t *)map_domain_page(e820_mfn);

    nr = *(uint8_t*)(p + HVM_E820_NR_OFFSET);
    e820_table = (struct e820entry*)(p + HVM_E820_OFFSET);
    /* search E820 table, set MTRR for RAM */
    for ( i = 0; i < nr; i++)
    {
        if ( (e820_table[i].addr >= 0x100000) &&
             (e820_table[i].type == E820_RAM) )
        {
            if ( e820_table[i].addr == 0x100000 )
            {
                size = e820_table[i].size + 0x100000 + PAGE_SIZE * 4;
                addr = 0;
            }
            else
            {
                /* Larger than 4G */
                size = e820_table[i].size;
                addr = e820_table[i].addr;
            }

            reg = range_to_mtrr(reg, &v->arch.hvm_vcpu.mtrr,
                                addr >> PAGE_SHIFT, size >> PAGE_SHIFT,
                                MTRR_TYPE_WRBACK);
        }
    }
}

void init_mtrr_in_hyper(struct vcpu *v)
{
    /* TODO:MTRR should be initialized in BIOS or other places.
     * workaround to do it in here
     */
    if ( v->arch.hvm_vcpu.mtrr.is_initialized )
        return;

    setup_fixed_mtrrs(v);
    setup_var_mtrrs(v);
    /* enable mtrr */
    mtrr_def_type_msr_set(&v->arch.hvm_vcpu.mtrr, 0xc00);

    v->arch.hvm_vcpu.mtrr.is_initialized = 1;
}

static int32_t reset_mtrr(struct mtrr_state *m)
{
    m->var_ranges = xmalloc_array(struct mtrr_var_range, MTRR_VCNT);
    if ( m->var_ranges == NULL )
        return -ENOMEM;
    memset(m->var_ranges, 0, MTRR_VCNT * sizeof(struct mtrr_var_range));
    memset(m->fixed_ranges, 0, sizeof(m->fixed_ranges));
    m->enabled = 0;
    m->def_type = 0;/*mtrr is disabled*/
    m->mtrr_cap = (0x5<<8)|MTRR_VCNT;/*wc,fix enabled, and vcnt=8*/
    m->overlapped = 0;
    return 0;
}

/* init global variables for MTRR and PAT */
void global_init_mtrr_pat(void)
{
    extern uint64_t host_pat;
    uint32_t phys_addr;

    init_mtrr_epat_tbl();
    init_pat_entry_tbl(host_pat);
    /* Get max physical address, set some global variable */
    if ( cpuid_eax(0x80000000) < 0x80000008 )
        phys_addr = 36;
    else
        phys_addr = cpuid_eax(0x80000008);

    phys_base_msr_mask = ~((((uint64_t)1) << phys_addr) - 1) | 0xf00UL;
    phys_mask_msr_mask = ~((((uint64_t)1) << phys_addr) - 1) | 0x7ffUL;

    size_or_mask = ~((1 << (phys_addr - PAGE_SHIFT)) - 1);
    size_and_mask = ~size_or_mask & 0xfff00000;
}

static void init_pat_entry_tbl(uint64_t pat)
{
    int32_t i, j;

    memset(&pat_entry_tbl, INVALID_MEM_TYPE,
           PAT_TYPE_NUMS * sizeof(pat_entry_tbl[0]));

    for ( i = 0; i < PAT_TYPE_NUMS; i++ )
    {
        for ( j = 0; j < PAT_TYPE_NUMS; j++ )
        {
            if ( pat_cr_2_paf(pat, j) == i )
            {
                pat_entry_tbl[i] = j;
                break;
            }
        }
    }
}

uint8_t pat_type_2_pte_flags(uint8_t pat_type)
{
    int32_t pat_entry = pat_entry_tbl[pat_type];

    /* INVALID_MEM_TYPE, means doesn't find the pat_entry in host pat for
     * a given pat_type. If host pat covers all the pat types,
     * it can't happen.
     */
    if ( likely(pat_entry != INVALID_MEM_TYPE) )
        return pat_entry_2_pte_flags[pat_entry];

    return pat_entry_2_pte_flags[pat_entry_tbl[PAT_TYPE_UNCACHABLE]];
}

int32_t reset_vmsr(struct mtrr_state *m, uint64_t *pat_ptr)
{
    int32_t rc;

    rc = reset_mtrr(m);
    if ( rc != 0 )
        return rc;

    *pat_ptr = ((uint64_t)PAT_TYPE_WRBACK) |               /* PAT0: WB */
               ((uint64_t)PAT_TYPE_WRTHROUGH << 8) |       /* PAT1: WT */
               ((uint64_t)PAT_TYPE_UC_MINUS << 16) |       /* PAT2: UC- */
               ((uint64_t)PAT_TYPE_UNCACHABLE << 24) |     /* PAT3: UC */
               ((uint64_t)PAT_TYPE_WRBACK << 32) |         /* PAT4: WB */
               ((uint64_t)PAT_TYPE_WRTHROUGH << 40) |      /* PAT5: WT */
               ((uint64_t)PAT_TYPE_UC_MINUS << 48) |       /* PAT6: UC- */
               ((uint64_t)PAT_TYPE_UNCACHABLE << 56);      /* PAT7: UC */

    return 0;
}

/*
 * Get MTRR memory type for physical address pa.
 */
static uint8_t get_mtrr_type(struct mtrr_state *m, paddr_t pa)
{
   int32_t     addr, seg, index;
   uint8_t     overlap_mtrr = 0;
   uint8_t     overlap_mtrr_pos = 0;
   uint64_t    phys_base;
   uint64_t    phys_mask;
   uint8_t     num_var_ranges = m->mtrr_cap & 0xff;

   if ( unlikely(!(m->enabled & 0x2)) )
       return MTRR_TYPE_UNCACHABLE;

   if ( (pa < 0x100000) && (m->enabled & 1) )
   {
       /* Fixed range MTRR takes effective */
       addr = (uint32_t) pa;
       if ( addr < 0x80000 )
       {
           seg = (addr >> 16);
           return m->fixed_ranges[seg];
       }
       else if ( addr < 0xc0000 )
       {
           seg = (addr - 0x80000) >> 14;
           index = (seg >> 3) + 1;
           seg &= 7;            /* select 0-7 segments */
           return m->fixed_ranges[index*8 + seg];
       }
       else
       {
           /* 0xC0000 --- 0x100000 */
           seg = (addr - 0xc0000) >> 12;
           index = (seg >> 3) + 3;
           seg &= 7;            /* select 0-7 segments */
           return m->fixed_ranges[index*8 + seg];
       }
   }

   /* Match with variable MTRRs. */
   for ( seg = 0; seg < num_var_ranges; seg++ )
   {
       phys_base = ((uint64_t*)m->var_ranges)[seg*2];
       phys_mask = ((uint64_t*)m->var_ranges)[seg*2 + 1];
       if ( phys_mask & (1 << MTRR_PHYSMASK_VALID_BIT) )
       {
           if ( ((uint64_t) pa & phys_mask) >> MTRR_PHYSMASK_SHIFT ==
                (phys_base & phys_mask) >> MTRR_PHYSMASK_SHIFT )
           {
               if ( unlikely(m->overlapped) )
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

   /* Overlapped or not found. */
   if ( unlikely(overlap_mtrr == 0) )
       return m->def_type;

   if ( likely(!(overlap_mtrr & ~( ((uint8_t)1) << overlap_mtrr_pos ))) )
       /* Covers both one variable memory range matches and
        * two or more identical match.
        */
       return overlap_mtrr_pos;

   if ( overlap_mtrr & 0x1 )
       /* Two or more match, one is UC. */
       return MTRR_TYPE_UNCACHABLE;

   if ( !(overlap_mtrr & 0xaf) )
       /* Two or more match, WT and WB. */
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
                                 uint32_t pte_flags)
{
    uint8_t mtrr_mtype, pat_value, effective;

    mtrr_mtype = get_mtrr_type(m, gpa);

    pat_value = page_pat_type(pat, pte_flags);

    effective = mm_type_tbl[mtrr_mtype][pat_value];

    return effective;
}

static void init_mtrr_epat_tbl(void)
{
    int32_t i, j;
    /* set default value to an invalid type, just for checking conflict */
    memset(&mtrr_epat_tbl, INVALID_MEM_TYPE, sizeof(mtrr_epat_tbl));

    for ( i = 0; i < MTRR_NUM_TYPES; i++ )
    {
        for ( j = 0; j < PAT_TYPE_NUMS; j++ )
        {
            int32_t tmp = mm_type_tbl[i][j];
            if ( (tmp >= 0) && (tmp < MEMORY_NUM_TYPES) )
                mtrr_epat_tbl[i][tmp] = j;
        }
    }
}

uint32_t get_pat_flags(struct vcpu *v,
                       uint32_t gl1e_flags,
                       paddr_t gpaddr,
                       paddr_t spaddr)
{
    uint8_t guest_eff_mm_type;
    uint8_t shadow_mtrr_type;
    uint8_t pat_entry_value;
    uint64_t pat = v->arch.hvm_vcpu.pat_cr;
    struct mtrr_state *g = &v->arch.hvm_vcpu.mtrr;

    /* 1. Get the effective memory type of guest physical address,
     * with the pair of guest MTRR and PAT
     */
    guest_eff_mm_type = effective_mm_type(g, pat, gpaddr, gl1e_flags);
    /* 2. Get the memory type of host physical address, with MTRR */
    shadow_mtrr_type = get_mtrr_type(&mtrr_state, spaddr);

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

/* Helper funtions for seting mtrr/pat */
bool_t pat_msr_set(uint64_t *pat, uint64_t msr_content)
{
    uint8_t *value = (uint8_t*)&msr_content;
    int32_t i;

    if ( *pat != msr_content )
    {
        for ( i = 0; i < 8; i++ )
            if ( unlikely(!(value[i] == 0 || value[i] == 1 ||
                            value[i] == 4 || value[i] == 5 ||
                            value[i] == 6 || value[i] == 7)) )
                return 0;

        *pat = msr_content;
    }

    return 1;
}

bool_t mtrr_def_type_msr_set(struct mtrr_state *m, uint64_t msr_content)
{
    uint8_t def_type = msr_content & 0xff;
    uint8_t enabled = (msr_content >> 10) & 0x3;

    if ( unlikely(!(def_type == 0 || def_type == 1 || def_type == 4 ||
                    def_type == 5 || def_type == 6)) )
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

    m->enabled = enabled;
    m->def_type = def_type;

    return 1;
}

bool_t mtrr_fix_range_msr_set(struct mtrr_state *m, uint32_t row,
                              uint64_t msr_content)
{
    uint64_t *fixed_range_base = (uint64_t *)m->fixed_ranges;

    if ( fixed_range_base[row] != msr_content )
    {
        uint8_t *range = (uint8_t*)&msr_content;
        int32_t i, type;

        for ( i = 0; i < 8; i++ )
        {
            type = range[i];
            if ( unlikely(!(type == 0 || type == 1 ||
                            type == 4 || type == 5 || type == 6)) )
                return 0;
        }

        fixed_range_base[row] = msr_content;
    }

    return 1;
}

bool_t mtrr_var_range_msr_set(struct mtrr_state *m, uint32_t msr,
                              uint64_t msr_content)
{
    uint32_t index;
    uint64_t msr_mask;
    uint64_t *var_range_base = (uint64_t*)m->var_ranges;

    index = msr - MSR_IA32_MTRR_PHYSBASE0;

    if ( var_range_base[index] != msr_content )
    {
        uint32_t type = msr_content & 0xff;

        msr_mask = (index & 1) ? phys_mask_msr_mask : phys_base_msr_mask;

        if ( unlikely(!(type == 0 || type == 1 ||
                        type == 4 || type == 5 || type == 6)) )
            return 0;

        if ( unlikely(msr_content && (msr_content & msr_mask)) )
        {
            HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid msr content:%"PRIx64"\n",
                        msr_content);
            return 0;
        }

        var_range_base[index] = msr_content;
    }

    m->overlapped = is_var_mtrr_overlapped(m);

    return 1;
}

bool_t mtrr_pat_not_equal(struct vcpu *vd, struct vcpu *vs)
{
    struct mtrr_state *md = &vd->arch.hvm_vcpu.mtrr;
    struct mtrr_state *ms = &vs->arch.hvm_vcpu.mtrr;
    int32_t res;
    uint8_t num_var_ranges = (uint8_t)md->mtrr_cap;

    /* Test fixed ranges. */
    res = memcmp(md->fixed_ranges, ms->fixed_ranges,
            NUM_FIXED_RANGES*sizeof(mtrr_type));
    if ( res )
        return 1;

    /* Test var ranges. */
    res = memcmp(md->var_ranges, ms->var_ranges,
            num_var_ranges*sizeof(struct mtrr_var_range));
    if ( res )
        return 1;

    /* Test default type MSR. */
    if ( (md->def_type != ms->def_type)
            && (md->enabled != ms->enabled) )
        return 1;

    /* Test PAT. */
    if ( vd->arch.hvm_vcpu.pat_cr != vs->arch.hvm_vcpu.pat_cr )
        return 1;

    return 0;
}

void hvm_init_cacheattr_region_list(
    struct domain *d)
{
    INIT_LIST_HEAD(&d->arch.hvm_domain.pinned_cacheattr_ranges);
}

void hvm_destroy_cacheattr_region_list(
    struct domain *d)
{
    struct list_head *head = &d->arch.hvm_domain.pinned_cacheattr_ranges;
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

int32_t hvm_get_mem_pinned_cacheattr(
    struct domain *d,
    uint64_t guest_fn,
    uint32_t *type)
{
    struct hvm_mem_pinned_cacheattr_range *range;

    *type = 0;

    if ( !is_hvm_domain(d) )
        return 0;

    list_for_each_entry_rcu ( range,
                              &d->arch.hvm_domain.pinned_cacheattr_ranges,
                              list )
    {
        if ( (guest_fn >= range->start) && (guest_fn <= range->end) )
        {
            *type = range->type;
            return 1;
        }
    }

    return 0;
}

int32_t hvm_set_mem_pinned_cacheattr(
    struct domain *d,
    uint64_t gfn_start,
    uint64_t gfn_end,
    uint32_t  type)
{
    struct hvm_mem_pinned_cacheattr_range *range;

    if ( !((type == PAT_TYPE_UNCACHABLE) ||
           (type == PAT_TYPE_WRCOMB) ||
           (type == PAT_TYPE_WRTHROUGH) ||
           (type == PAT_TYPE_WRPROT) ||
           (type == PAT_TYPE_WRBACK) ||
           (type == PAT_TYPE_UC_MINUS)) ||
         !is_hvm_domain(d) )
        return -EINVAL;

    range = xmalloc(struct hvm_mem_pinned_cacheattr_range);
    if ( range == NULL )
        return -ENOMEM;

    memset(range, 0, sizeof(*range));

    range->start = gfn_start;
    range->end = gfn_end;
    range->type = type;

    list_add_rcu(&range->list, &d->arch.hvm_domain.pinned_cacheattr_ranges);

    return 0;
}

static int hvm_save_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    int i;
    struct vcpu *v;
    struct hvm_hw_mtrr hw_mtrr;
    struct mtrr_state *mtrr_state;
    /* save mtrr&pat */
    for_each_vcpu(d, v)
    {
        mtrr_state = &v->arch.hvm_vcpu.mtrr;

        hw_mtrr.msr_pat_cr = v->arch.hvm_vcpu.pat_cr;

        hw_mtrr.msr_mtrr_def_type = mtrr_state->def_type
                                | (mtrr_state->enabled << 10);
        hw_mtrr.msr_mtrr_cap = mtrr_state->mtrr_cap;

        for ( i = 0; i < MTRR_VCNT; i++ )
        {
            /* save physbase */
            hw_mtrr.msr_mtrr_var[i*2] =
                ((uint64_t*)mtrr_state->var_ranges)[i*2];
            /* save physmask */
            hw_mtrr.msr_mtrr_var[i*2+1] =
                ((uint64_t*)mtrr_state->var_ranges)[i*2+1];
        }

        for ( i = 0; i < NUM_FIXED_MSR; i++ )
            hw_mtrr.msr_mtrr_fixed[i] =
                ((uint64_t*)mtrr_state->fixed_ranges)[i];

        if ( hvm_save_entry(MTRR, v->vcpu_id, h, &hw_mtrr) != 0 )
            return 1;
    }
    return 0;
}

static int hvm_load_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid, i;
    struct vcpu *v;
    struct mtrr_state *mtrr_state;
    struct hvm_hw_mtrr hw_mtrr;

    vcpuid = hvm_load_instance(h);
    if ( vcpuid > MAX_VIRT_CPUS || (v = d->vcpu[vcpuid]) == NULL )
    {
        gdprintk(XENLOG_ERR, "HVM restore: domain has no vcpu %u\n", vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry(MTRR, h, &hw_mtrr) != 0 )
        return -EINVAL;

    mtrr_state = &v->arch.hvm_vcpu.mtrr;

    pat_msr_set(&v->arch.hvm_vcpu.pat_cr, hw_mtrr.msr_pat_cr);

    mtrr_state->mtrr_cap = hw_mtrr.msr_mtrr_cap;

    for ( i = 0; i < NUM_FIXED_MSR; i++ )
        mtrr_fix_range_msr_set(mtrr_state, i, hw_mtrr.msr_mtrr_fixed[i]);

    for ( i = 0; i < MTRR_VCNT; i++ )
    {
        mtrr_var_range_msr_set(mtrr_state,
                MTRRphysBase_MSR(i), hw_mtrr.msr_mtrr_var[i*2]);
        mtrr_var_range_msr_set(mtrr_state,
                MTRRphysMask_MSR(i), hw_mtrr.msr_mtrr_var[i*2+1]);
    }

    mtrr_def_type_msr_set(mtrr_state, hw_mtrr.msr_mtrr_def_type);

    v->arch.hvm_vcpu.mtrr.is_initialized = 1;
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(MTRR, hvm_save_mtrr_msr, hvm_load_mtrr_msr,
                          1, HVMSR_PER_VCPU);
