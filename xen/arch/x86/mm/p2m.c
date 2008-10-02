/******************************************************************************
 * arch/x86/mm/p2m.c
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h> /* ept_p2m_init() */
#include <xen/iommu.h>

/* Debugging and auditing of the P2M code? */
#define P2M_AUDIT     0
#define P2M_DEBUGGING 0

/*
 * The P2M lock.  This protects all updates to the p2m table.
 * Updates are expected to be safe against concurrent reads,
 * which do *not* require the lock.
 *
 * Locking discipline: always acquire this lock before the shadow or HAP one
 */

#define p2m_lock_init(_p2m)                     \
    do {                                        \
        spin_lock_init(&(_p2m)->lock);          \
        (_p2m)->locker = -1;                    \
        (_p2m)->locker_function = "nobody";     \
    } while (0)

#define p2m_lock(_p2m)                                          \
    do {                                                        \
        if ( unlikely((_p2m)->locker == current->processor) )   \
        {                                                       \
            printk("Error: p2m lock held by %s\n",              \
                   (_p2m)->locker_function);                    \
            BUG();                                              \
        }                                                       \
        spin_lock(&(_p2m)->lock);                               \
        ASSERT((_p2m)->locker == -1);                           \
        (_p2m)->locker = current->processor;                    \
        (_p2m)->locker_function = __func__;                     \
    } while (0)

#define p2m_unlock(_p2m)                                \
    do {                                                \
        ASSERT((_p2m)->locker == current->processor);   \
        (_p2m)->locker = -1;                            \
        (_p2m)->locker_function = "nobody";             \
        spin_unlock(&(_p2m)->lock);                     \
    } while (0)

#define p2m_locked_by_me(_p2m)                            \
    (current->processor == (_p2m)->locker)

/* Printouts */
#define P2M_PRINTK(_f, _a...)                                \
    debugtrace_printk("p2m: %s(): " _f, __func__, ##_a)
#define P2M_ERROR(_f, _a...)                                 \
    printk("pg error: %s(): " _f, __func__, ##_a)
#if P2M_DEBUGGING
#define P2M_DEBUG(_f, _a...)                                 \
    debugtrace_printk("p2mdebug: %s(): " _f, __func__, ##_a)
#else
#define P2M_DEBUG(_f, _a...) do { (void)(_f); } while(0)
#endif


/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) (frame_table + mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))


/* PTE flags for the various types of p2m entry */
#define P2M_BASE_FLAGS \
        (_PAGE_PRESENT | _PAGE_USER | _PAGE_DIRTY | _PAGE_ACCESSED)

static unsigned long p2m_type_to_flags(p2m_type_t t) 
{
    unsigned long flags = (t & 0x7UL) << 9;
    switch(t)
    {
    case p2m_invalid:
    default:
        return flags;
    case p2m_ram_rw:
        return flags | P2M_BASE_FLAGS | _PAGE_RW;
    case p2m_ram_logdirty:
        return flags | P2M_BASE_FLAGS;
    case p2m_ram_ro:
        return flags | P2M_BASE_FLAGS;
    case p2m_mmio_dm:
        return flags;
    case p2m_mmio_direct:
        return flags | P2M_BASE_FLAGS | _PAGE_RW | _PAGE_PCD;
    }
}


// Find the next level's P2M entry, checking for out-of-range gfn's...
// Returns NULL on error.
//
static l1_pgentry_t *
p2m_find_entry(void *table, unsigned long *gfn_remainder,
                   unsigned long gfn, u32 shift, u32 max)
{
    u32 index;

    index = *gfn_remainder >> shift;
    if ( index >= max )
    {
        P2M_DEBUG("gfn=0x%lx out of range "
                  "(gfn_remainder=0x%lx shift=%d index=0x%x max=0x%x)\n",
                  gfn, *gfn_remainder, shift, index, max);
        return NULL;
    }
    *gfn_remainder &= (1 << shift) - 1;
    return (l1_pgentry_t *)table + index;
}

// Walk one level of the P2M table, allocating a new table if required.
// Returns 0 on error.
//
static int
p2m_next_level(struct domain *d, mfn_t *table_mfn, void **table,
               unsigned long *gfn_remainder, unsigned long gfn, u32 shift,
               u32 max, unsigned long type)
{
    l1_pgentry_t *l1_entry;
    l1_pgentry_t *p2m_entry;
    l1_pgentry_t new_entry;
    void *next;
    int i;
    ASSERT(d->arch.p2m->alloc_page);

    if ( !(p2m_entry = p2m_find_entry(*table, gfn_remainder, gfn,
                                      shift, max)) )
        return 0;

    if ( !(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT) )
    {
        struct page_info *pg = d->arch.p2m->alloc_page(d);
        if ( pg == NULL )
            return 0;
        list_add_tail(&pg->list, &d->arch.p2m->pages);
        pg->u.inuse.type_info = type | 1 | PGT_validated;
        pg->count_info = 1;

        new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)),
                                 __PAGE_HYPERVISOR|_PAGE_USER);

        switch ( type ) {
        case PGT_l3_page_table:
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 4);
            break;
        case PGT_l2_page_table:
#if CONFIG_PAGING_LEVELS == 3
            /* for PAE mode, PDPE only has PCD/PWT/P bits available */
            new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)), _PAGE_PRESENT);
#endif
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 3);
            break;
        case PGT_l1_page_table:
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 2);
            break;
        default:
            BUG();
            break;
        }
    }

    ASSERT(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT);

    /* split single large page into 4KB page in P2M table */
    if ( type == PGT_l1_page_table && (l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
    {
        unsigned long flags, pfn;
        struct page_info *pg = d->arch.p2m->alloc_page(d);
        if ( pg == NULL )
            return 0;
        list_add_tail(&pg->list, &d->arch.p2m->pages);
        pg->u.inuse.type_info = PGT_l1_page_table | 1 | PGT_validated;
        pg->count_info = 1;
        
        /* New splintered mappings inherit the flags of the old superpage, 
         * with a little reorganisation for the _PAGE_PSE_PAT bit. */
        flags = l1e_get_flags(*p2m_entry);
        pfn = l1e_get_pfn(*p2m_entry);
        if ( pfn & 1 )           /* ==> _PAGE_PSE_PAT was set */
            pfn -= 1;            /* Clear it; _PAGE_PSE becomes _PAGE_PAT */
        else
            flags &= ~_PAGE_PSE; /* Clear _PAGE_PSE (== _PAGE_PAT) */
        
        l1_entry = map_domain_page(mfn_x(page_to_mfn(pg)));
        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            new_entry = l1e_from_pfn(pfn + i, flags);
            paging_write_p2m_entry(d, gfn,
                                   l1_entry+i, *table_mfn, new_entry, 1);
        }
        unmap_domain_page(l1_entry);
        
        new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)),
                                 __PAGE_HYPERVISOR|_PAGE_USER);
        paging_write_p2m_entry(d, gfn,
                               p2m_entry, *table_mfn, new_entry, 2);
    }

    *table_mfn = _mfn(l1e_get_pfn(*p2m_entry));
    next = map_domain_page(mfn_x(*table_mfn));
    unmap_domain_page(*table);
    *table = next;

    return 1;
}

// Returns 0 on error (out of memory)
static int
p2m_set_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
              unsigned int page_order, p2m_type_t p2mt)
{
    // XXX -- this might be able to be faster iff current->domain == d
    mfn_t table_mfn = pagetable_get_mfn(d->arch.phys_table);
    void *table =map_domain_page(mfn_x(table_mfn));
    unsigned long i, gfn_remainder = gfn;
    l1_pgentry_t *p2m_entry;
    l1_pgentry_t entry_content;
    l2_pgentry_t l2e_content;
    int rv=0;

#if CONFIG_PAGING_LEVELS >= 4
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L4_PAGETABLE_SHIFT - PAGE_SHIFT,
                         L4_PAGETABLE_ENTRIES, PGT_l3_page_table) )
        goto out;
#endif
    /*
     * When using PAE Xen, we only allow 33 bits of pseudo-physical
     * address in translated guests (i.e. 8 GBytes).  This restriction
     * comes from wanting to map the P2M table into the 16MB RO_MPT hole
     * in Xen's address space for translated PV guests.
     * When using AMD's NPT on PAE Xen, we are restricted to 4GB.
     */
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                         ((CONFIG_PAGING_LEVELS == 3)
                          ? (d->arch.hvm_domain.hap_enabled ? 4 : 8)
                          : L3_PAGETABLE_ENTRIES),
                         PGT_l2_page_table) )
        goto out;

    if ( page_order == 0 )
    {
        if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                             L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                             L2_PAGETABLE_ENTRIES, PGT_l1_page_table) )
            goto out;

        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   0, L1_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        
        if ( mfn_valid(mfn) || (p2mt == p2m_mmio_direct) )
            entry_content = l1e_from_pfn(mfn_x(mfn), p2m_type_to_flags(p2mt));
        else
            entry_content = l1e_empty();
        
        /* level 1 entry */
        paging_write_p2m_entry(d, gfn, p2m_entry, table_mfn, entry_content, 1);
    }
    else 
    {
        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                                   L2_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        
        if ( (l1e_get_flags(*p2m_entry) & _PAGE_PRESENT) &&
             !(l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
        {
            P2M_ERROR("configure P2M table 4KB L2 entry with large page\n");
            domain_crash(d);
            goto out;
        }
        
        if ( mfn_valid(mfn) )
            l2e_content = l2e_from_pfn(mfn_x(mfn),
                                       p2m_type_to_flags(p2mt) | _PAGE_PSE);
        else
            l2e_content = l2e_empty();
        
        entry_content.l1 = l2e_content.l2;
        paging_write_p2m_entry(d, gfn, p2m_entry, table_mfn, entry_content, 2);
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_valid(mfn) && (gfn > d->arch.p2m->max_mapped_pfn) )
        d->arch.p2m->max_mapped_pfn = gfn + (1UL << page_order) - 1;

    if ( iommu_enabled && (is_hvm_domain(d) || need_iommu(d)) )
    {
        if ( p2mt == p2m_ram_rw )
            for ( i = 0; i < (1UL << page_order); i++ )
                iommu_map_page(d, gfn+i, mfn_x(mfn)+i );
        else
            for ( int i = 0; i < (1UL << page_order); i++ )
                iommu_unmap_page(d, gfn+i);
    }

    /* Success */
    rv = 1;

 out:
    unmap_domain_page(table);
    return rv;
}

static mfn_t
p2m_gfn_to_mfn(struct domain *d, unsigned long gfn, p2m_type_t *t)
{
    mfn_t mfn;
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;

    ASSERT(paging_mode_translate(d));

    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */
    *t = p2m_mmio_dm;

    mfn = pagetable_get_mfn(d->arch.phys_table);

    if ( gfn > d->arch.p2m->max_mapped_pfn )
        /* This pfn is higher than the highest the p2m map currently holds */
        return _mfn(INVALID_MFN);

#if CONFIG_PAGING_LEVELS >= 4
    {
        l4_pgentry_t *l4e = map_domain_page(mfn_x(mfn));
        l4e += l4_table_offset(addr);
        if ( (l4e_get_flags(*l4e) & _PAGE_PRESENT) == 0 )
        {
            unmap_domain_page(l4e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l4e_get_pfn(*l4e));
        unmap_domain_page(l4e);
    }
#endif
    {
        l3_pgentry_t *l3e = map_domain_page(mfn_x(mfn));
#if CONFIG_PAGING_LEVELS == 3
        /* On PAE hosts the p2m has eight l3 entries, not four (see
         * shadow_set_p2m_entry()) so we can't use l3_table_offset.
         * Instead, just count the number of l3es from zero.  It's safe
         * to do this because we already checked that the gfn is within
         * the bounds of the p2m. */
        l3e += (addr >> L3_PAGETABLE_SHIFT);
#else
        l3e += l3_table_offset(addr);
#endif
        if ( (l3e_get_flags(*l3e) & _PAGE_PRESENT) == 0 )
        {
            unmap_domain_page(l3e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l3e_get_pfn(*l3e));
        unmap_domain_page(l3e);
    }

    l2e = map_domain_page(mfn_x(mfn));
    l2e += l2_table_offset(addr);
    if ( (l2e_get_flags(*l2e) & _PAGE_PRESENT) == 0 )
    {
        unmap_domain_page(l2e);
        return _mfn(INVALID_MFN);
    }
    else if ( (l2e_get_flags(*l2e) & _PAGE_PSE) )
    {
        mfn = _mfn(l2e_get_pfn(*l2e) + l1_table_offset(addr));
        *t = p2m_flags_to_type(l2e_get_flags(*l2e));
        unmap_domain_page(l2e);
        
        ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
        return (p2m_is_valid(*t)) ? mfn : _mfn(INVALID_MFN);
    }

    mfn = _mfn(l2e_get_pfn(*l2e));
    unmap_domain_page(l2e);

    l1e = map_domain_page(mfn_x(mfn));
    l1e += l1_table_offset(addr);
    if ( (l1e_get_flags(*l1e) & _PAGE_PRESENT) == 0 )
    {
        unmap_domain_page(l1e);
        return _mfn(INVALID_MFN);
    }
    mfn = _mfn(l1e_get_pfn(*l1e));
    *t = p2m_flags_to_type(l1e_get_flags(*l1e));
    unmap_domain_page(l1e);

    ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
    return (p2m_is_valid(*t)) ? mfn : _mfn(INVALID_MFN);
}

/* Read the current domain's p2m table (through the linear mapping). */
static mfn_t p2m_gfn_to_mfn_current(unsigned long gfn, p2m_type_t *t)
{
    mfn_t mfn = _mfn(INVALID_MFN);
    p2m_type_t p2mt = p2m_mmio_dm;
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */

    if ( gfn <= current->domain->arch.p2m->max_mapped_pfn )
    {
        l1_pgentry_t l1e = l1e_empty();
        l2_pgentry_t l2e = l2e_empty();
        int ret;

        ASSERT(gfn < (RO_MPT_VIRT_END - RO_MPT_VIRT_START) 
               / sizeof(l1_pgentry_t));

        ret = __copy_from_user(&l2e,
                               &__linear_l1_table[l1_linear_offset(RO_MPT_VIRT_START) + l2_linear_offset(addr)],
                               sizeof(l2e));
        
        if ( (ret == 0) && (l2e_get_flags(l2e) & _PAGE_PRESENT) && 
             (l2e_get_flags(l2e) & _PAGE_PSE) ) 
        {
            p2mt = p2m_flags_to_type(l2e_get_flags(l2e));
            ASSERT(l2e_get_pfn(l2e) != INVALID_MFN || !p2m_is_ram(p2mt));
            if ( p2m_is_valid(p2mt) )
                mfn = _mfn(l2e_get_pfn(l2e) + l1_table_offset(addr));
            else
                p2mt = p2m_mmio_dm;
        }
        else
        {
        
            /* Need to __copy_from_user because the p2m is sparse and this
             * part might not exist */
            ret = __copy_from_user(&l1e,
                                   &phys_to_machine_mapping[gfn],
                                   sizeof(l1e));
            
            if ( ret == 0 ) {
                p2mt = p2m_flags_to_type(l1e_get_flags(l1e));
                ASSERT(l1e_get_pfn(l1e) != INVALID_MFN || !p2m_is_ram(p2mt));
                if ( p2m_is_valid(p2mt) )
                    mfn = _mfn(l1e_get_pfn(l1e));
                else 
                    /* XXX see above */
                    p2mt = p2m_mmio_dm;
            }
        }
    }

    *t = p2mt;
    return mfn;
}

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m;

    p2m = xmalloc(struct p2m_domain);
    if ( p2m == NULL )
        return -ENOMEM;

    d->arch.p2m = p2m;

    memset(p2m, 0, sizeof(*p2m));
    p2m_lock_init(p2m);
    INIT_LIST_HEAD(&p2m->pages);

    p2m->set_entry = p2m_set_entry;
    p2m->get_entry = p2m_gfn_to_mfn;
    p2m->get_entry_current = p2m_gfn_to_mfn_current;
    p2m->change_entry_type_global = p2m_change_type_global;

    if ( is_hvm_domain(d) && d->arch.hvm_domain.hap_enabled &&
         (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) )
        ept_p2m_init(d);

    return 0;
}

void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt)
{
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);
    p2m->change_entry_type_global(d, ot, nt);
    p2m_unlock(p2m);
}

static
int set_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
                    unsigned int page_order, p2m_type_t p2mt)
{
    unsigned long todo = 1ul << page_order;
    unsigned int order;
    int rc = 0;

    while ( todo )
    {
        order = (((gfn | mfn_x(mfn) | todo) & ((1ul << 9) - 1)) == 0) ? 9 : 0;
        rc = d->arch.p2m->set_entry(d, gfn, mfn, order, p2mt);
        gfn += 1ul << order;
        if ( mfn_x(mfn) != INVALID_MFN )
            mfn = _mfn(mfn_x(mfn) + (1ul << order));
        todo -= 1ul << order;
    }

    return rc;
}

// Allocate a new p2m table for a domain.
//
// The structure of the p2m table is that of a pagetable for xen (i.e. it is
// controlled by CONFIG_PAGING_LEVELS).
//
// The alloc_page and free_page functions will be used to get memory to
// build the p2m, and to release it again at the end of day.
//
// Returns 0 for success or -errno.
//
int p2m_alloc_table(struct domain *d,
                    struct page_info * (*alloc_page)(struct domain *d),
                    void (*free_page)(struct domain *d, struct page_info *pg))

{
    mfn_t mfn = _mfn(INVALID_MFN);
    struct list_head *entry;
    struct page_info *page, *p2m_top;
    unsigned int page_count = 0;
    unsigned long gfn = -1UL;
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);

    if ( pagetable_get_pfn(d->arch.phys_table) != 0 )
    {
        P2M_ERROR("p2m already allocated for this domain\n");
        p2m_unlock(p2m);
        return -EINVAL;
    }

    P2M_PRINTK("allocating p2m table\n");

    p2m->alloc_page = alloc_page;
    p2m->free_page = free_page;

    p2m_top = p2m->alloc_page(d);
    if ( p2m_top == NULL )
    {
        p2m_unlock(p2m);
        return -ENOMEM;
    }
    list_add_tail(&p2m_top->list, &p2m->pages);

    p2m_top->count_info = 1;
    p2m_top->u.inuse.type_info =
#if CONFIG_PAGING_LEVELS == 4
        PGT_l4_page_table
#else
        PGT_l3_page_table
#endif
        | 1 | PGT_validated;

    d->arch.phys_table = pagetable_from_mfn(page_to_mfn(p2m_top));

    P2M_PRINTK("populating p2m table\n");

    /* Initialise physmap tables for slot zero. Other code assumes this. */
    if ( !set_p2m_entry(d, 0, _mfn(INVALID_MFN), 0,
                        p2m_invalid) )
        goto error;

    /* Copy all existing mappings from the page list and m2p */
    for ( entry = d->page_list.next;
          entry != &d->page_list;
          entry = entry->next )
    {
        page = list_entry(entry, struct page_info, list);
        mfn = page_to_mfn(page);
        gfn = get_gpfn_from_mfn(mfn_x(mfn));
        page_count++;
        if (
#ifdef __x86_64__
            (gfn != 0x5555555555555555L)
#else
            (gfn != 0x55555555L)
#endif
             && gfn != INVALID_M2P_ENTRY
            && !set_p2m_entry(d, gfn, mfn, 0, p2m_ram_rw) )
            goto error;
    }

    P2M_PRINTK("p2m table initialised (%u pages)\n", page_count);
    p2m_unlock(p2m);
    return 0;

 error:
    P2M_PRINTK("failed to initialize p2m table, gfn=%05lx, mfn=%"
               PRI_mfn "\n", gfn, mfn_x(mfn));
    p2m_unlock(p2m);
    return -ENOMEM;
}

void p2m_teardown(struct domain *d)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct list_head *entry, *n;
    struct page_info *pg;
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);
    d->arch.phys_table = pagetable_null();

    list_for_each_safe(entry, n, &p2m->pages)
    {
        pg = list_entry(entry, struct page_info, list);
        list_del(entry);
        p2m->free_page(d, pg);
    }
    p2m_unlock(p2m);
}

void p2m_final_teardown(struct domain *d)
{
    xfree(d->arch.p2m);
    d->arch.p2m = NULL;
}

#if P2M_AUDIT
static void audit_p2m(struct domain *d)
{
    struct list_head *entry;
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn, m2pfn, lp2mfn = 0;
    mfn_t p2mfn;
    unsigned long orphans_d = 0, orphans_i = 0, mpbad = 0, pmbad = 0;
    int test_linear;
    p2m_type_t type;

    if ( !paging_mode_translate(d) )
        return;

    //P2M_PRINTK("p2m audit starts\n");

    test_linear = ( (d == current->domain)
                    && !pagetable_is_null(current->arch.monitor_table) );
    if ( test_linear )
        flush_tlb_local();

    /* Audit part one: walk the domain's page allocation list, checking
     * the m2p entries. */
    for ( entry = d->page_list.next;
          entry != &d->page_list;
          entry = entry->next )
    {
        page = list_entry(entry, struct page_info, list);
        mfn = mfn_x(page_to_mfn(page));

        // P2M_PRINTK("auditing guest page, mfn=%#lx\n", mfn);

        od = page_get_owner(page);

        if ( od != d )
        {
            P2M_PRINTK("wrong owner %#lx -> %p(%u) != %p(%u)\n",
                       mfn, od, (od?od->domain_id:-1), d, d->domain_id);
            continue;
        }

        gfn = get_gpfn_from_mfn(mfn);
        if ( gfn == INVALID_M2P_ENTRY )
        {
            orphans_i++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
            //               mfn);
            continue;
        }

        if ( gfn == 0x55555555 )
        {
            orphans_d++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has debug gfn\n",
            //               mfn);
            continue;
        }

        p2mfn = gfn_to_mfn_foreign(d, gfn, &type);
        if ( mfn_x(p2mfn) != mfn )
        {
            mpbad++;
            P2M_PRINTK("map mismatch mfn %#lx -> gfn %#lx -> mfn %#lx"
                       " (-> gfn %#lx)\n",
                       mfn, gfn, mfn_x(p2mfn),
                       (mfn_valid(p2mfn)
                        ? get_gpfn_from_mfn(mfn_x(p2mfn))
                        : -1u));
            /* This m2p entry is stale: the domain has another frame in
             * this physical slot.  No great disaster, but for neatness,
             * blow away the m2p entry. */
            set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        }

        if ( test_linear && (gfn <= d->arch.p2m->max_mapped_pfn) )
        {
            lp2mfn = mfn_x(gfn_to_mfn_current(gfn, &type));
            if ( lp2mfn != mfn_x(p2mfn) )
            {
                P2M_PRINTK("linear mismatch gfn %#lx -> mfn %#lx "
                           "(!= mfn %#lx)\n", gfn, lp2mfn, mfn_x(p2mfn));
            }
        }

        // P2M_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx, lp2mfn=%#lx\n",
        //                mfn, gfn, p2mfn, lp2mfn);
    }

    /* Audit part two: walk the domain's p2m table, checking the entries. */
    if ( pagetable_get_pfn(d->arch.phys_table) != 0 )
    {
        l2_pgentry_t *l2e;
        l1_pgentry_t *l1e;
        int i1, i2;

#if CONFIG_PAGING_LEVELS == 4
        l4_pgentry_t *l4e;
        l3_pgentry_t *l3e;
        int i3, i4;
        l4e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#else /* CONFIG_PAGING_LEVELS == 3 */
        l3_pgentry_t *l3e;
        int i3;
        l3e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#endif

        gfn = 0;
#if CONFIG_PAGING_LEVELS >= 4
        for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
        {
            if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
            {
                gfn += 1 << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
                continue;
            }
            l3e = map_domain_page(mfn_x(_mfn(l4e_get_pfn(l4e[i4]))));
#endif
            for ( i3 = 0;
                  i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
                  i3++ )
            {
                if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
                {
                    gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                    continue;
                }
                l2e = map_domain_page(mfn_x(_mfn(l3e_get_pfn(l3e[i3]))));
                for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
                {
                    if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                    {
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                    
                    /* check for super page */
                    if ( l2e_get_flags(l2e[i2]) & _PAGE_PSE )
                    {
                        mfn = l2e_get_pfn(l2e[i2]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++)
                        {
                            m2pfn = get_gpfn_from_mfn(mfn+i1);
                            if ( m2pfn != (gfn + i) )
                            {
                                pmbad++;
                                P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                           " -> gfn %#lx\n", gfn+i, mfn+i,
                                           m2pfn);
                                BUG();
                            }
                        }
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }

                    l1e = map_domain_page(mfn_x(_mfn(l2e_get_pfn(l2e[i2]))));

                    for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                    {
                        if ( !(l1e_get_flags(l1e[i1]) & _PAGE_PRESENT) )
                            continue;
                        mfn = l1e_get_pfn(l1e[i1]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        m2pfn = get_gpfn_from_mfn(mfn);
                        if ( m2pfn != gfn )
                        {
                            pmbad++;
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            BUG();
                        }
                    }
                    unmap_domain_page(l1e);
                }
                unmap_domain_page(l2e);
            }
#if CONFIG_PAGING_LEVELS >= 4
            unmap_domain_page(l3e);
        }
#endif

#if CONFIG_PAGING_LEVELS == 4
        unmap_domain_page(l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
        unmap_domain_page(l3e);
#endif

    }

    //P2M_PRINTK("p2m audit complete\n");
    //if ( orphans_i | orphans_d | mpbad | pmbad )
    //    P2M_PRINTK("p2m audit found %lu orphans (%lu inval %lu debug)\n",
    //                   orphans_i + orphans_d, orphans_i, orphans_d,
    if ( mpbad | pmbad )
        P2M_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                   pmbad, mpbad);
}
#else
#define audit_p2m(_d) do { (void)(_d); } while(0)
#endif /* P2M_AUDIT */



static void
p2m_remove_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                unsigned int page_order)
{
    unsigned long i;

    if ( !paging_mode_translate(d) )
    {
        if ( need_iommu(d) )
            for ( i = 0; i < (1 << page_order); i++ )
                iommu_unmap_page(d, mfn + i);
        return;
    }

    P2M_DEBUG("removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    set_p2m_entry(d, gfn, _mfn(INVALID_MFN), page_order, p2m_invalid);
    for ( i = 0; i < (1UL << page_order); i++ )
        set_gpfn_from_mfn(mfn+i, INVALID_M2P_ENTRY);
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn, unsigned int page_order)
{
    p2m_lock(d->arch.p2m);
    audit_p2m(d);
    p2m_remove_page(d, gfn, mfn, page_order);
    audit_p2m(d);
    p2m_unlock(d->arch.p2m);
}

int
guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                        unsigned long mfn, unsigned int page_order, 
                        p2m_type_t t)
{
    unsigned long i, ogfn;
    p2m_type_t ot;
    mfn_t omfn;
    int rc = 0;

    if ( !paging_mode_translate(d) )
    {
        if ( need_iommu(d) && t == p2m_ram_rw )
        {
            for ( i = 0; i < (1 << page_order); i++ )
                if ( (rc = iommu_map_page(d, mfn + i, mfn + i)) != 0 )
                {
                    while ( i-- > 0 )
                        iommu_unmap_page(d, mfn + i);
                    return rc;
                }
        }
        return 0;
    }

#if CONFIG_PAGING_LEVELS == 3
    /*
     * 32bit PAE nested paging does not support over 4GB guest due to 
     * hardware translation limit. This limitation is checked by comparing
     * gfn with 0xfffffUL.
     */
    if ( paging_mode_hap(d) && (gfn > 0xfffffUL) )
    {
        if ( !test_and_set_bool(d->arch.hvm_domain.svm.npt_4gb_warning) )
            dprintk(XENLOG_WARNING, "Dom%d failed to populate memory beyond"
                    " 4GB: specify 'hap=0' domain config option.\n",
                    d->domain_id);
        return -EINVAL;
    }
#endif

    p2m_lock(d->arch.p2m);
    audit_p2m(d);

    P2M_DEBUG("adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    /* First, remove m->p mappings for existing p->m mappings */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        omfn = gfn_to_mfn(d, gfn, &ot);
        if ( p2m_is_ram(ot) )
        {
            ASSERT(mfn_valid(omfn));
            set_gpfn_from_mfn(mfn_x(omfn)+i, INVALID_M2P_ENTRY);
        }
    }

    /* Then, look for m->p mappings for this range and deal with them */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        ogfn = mfn_to_gfn(d, _mfn(mfn));
        if (
#ifdef __x86_64__
            (ogfn != 0x5555555555555555L)
#else
            (ogfn != 0x55555555L)
#endif
            && (ogfn != INVALID_M2P_ENTRY)
            && (ogfn != gfn) )
        {
            /* This machine frame is already mapped at another physical
             * address */
            P2M_DEBUG("aliased! mfn=%#lx, old gfn=%#lx, new gfn=%#lx\n",
                      mfn, ogfn, gfn);
            omfn = gfn_to_mfn(d, ogfn, &ot);
            if ( p2m_is_ram(ot) )
            {
                ASSERT(mfn_valid(omfn));
                P2M_DEBUG("old gfn=%#lx -> mfn %#lx\n",
                          ogfn , mfn_x(omfn));
                if ( mfn_x(omfn) == mfn )
                    p2m_remove_page(d, ogfn, mfn, 0);
            }
        }
    }

    /* Now, actually do the two-way mapping */
    if ( mfn_valid(_mfn(mfn)) ) 
    {
        if ( !set_p2m_entry(d, gfn, _mfn(mfn), page_order, t) )
            rc = -EINVAL;
        for ( i = 0; i < (1UL << page_order); i++ )
            set_gpfn_from_mfn(mfn+i, gfn+i);
    }
    else
    {
        gdprintk(XENLOG_WARNING, "Adding bad mfn to p2m map (%#lx -> %#lx)\n",
                 gfn, mfn);
        if ( !set_p2m_entry(d, gfn, _mfn(INVALID_MFN), page_order, 
                            p2m_invalid) )
            rc = -EINVAL;
    }

    audit_p2m(d);
    p2m_unlock(d->arch.p2m);

    return rc;
}

/* Walk the whole p2m table, changing any entries of the old type
 * to the new type.  This is used in hardware-assisted paging to 
 * quickly enable or diable log-dirty tracking */
void p2m_change_type_global(struct domain *d, p2m_type_t ot, p2m_type_t nt)
{
    unsigned long mfn, gfn, flags;
    l1_pgentry_t l1e_content;
    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
    mfn_t l1mfn, l2mfn;
    int i1, i2;
    l3_pgentry_t *l3e;
    int i3;
#if CONFIG_PAGING_LEVELS == 4
    l4_pgentry_t *l4e;
    int i4;
#endif /* CONFIG_PAGING_LEVELS == 4 */

    if ( !paging_mode_translate(d) )
        return;

    if ( pagetable_get_pfn(d->arch.phys_table) == 0 )
        return;

    ASSERT(p2m_locked_by_me(d->arch.p2m));

#if CONFIG_PAGING_LEVELS == 4
    l4e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#else /* CONFIG_PAGING_LEVELS == 3 */
    l3e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#endif

#if CONFIG_PAGING_LEVELS >= 4
    for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
    {
        if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
        {
            continue;
        }
        l3e = map_domain_page(l4e_get_pfn(l4e[i4]));
#endif
        for ( i3 = 0;
              i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
              i3++ )
        {
            if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
            {
                continue;
            }
            l2mfn = _mfn(l3e_get_pfn(l3e[i3]));
            l2e = map_domain_page(l3e_get_pfn(l3e[i3]));
            for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
            {
                if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                {
                    continue;
                }

                if ( (l2e_get_flags(l2e[i2]) & _PAGE_PSE) )
                {
                    flags = l2e_get_flags(l2e[i2]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l2e_get_pfn(l2e[i2]);
                    gfn = get_gpfn_from_mfn(mfn);
                    flags = p2m_type_to_flags(nt);
                    l1e_content = l1e_from_pfn(mfn, flags | _PAGE_PSE);
                    paging_write_p2m_entry(d, gfn, (l1_pgentry_t *)&l2e[i2],
                                           l2mfn, l1e_content, 2);
                    continue;
                }

                l1mfn = _mfn(l2e_get_pfn(l2e[i2]));
                l1e = map_domain_page(mfn_x(l1mfn));

                for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                {
                    flags = l1e_get_flags(l1e[i1]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l1e_get_pfn(l1e[i1]);
                    gfn = get_gpfn_from_mfn(mfn);
                    /* create a new 1le entry with the new type */
                    flags = p2m_type_to_flags(nt);
                    l1e_content = l1e_from_pfn(mfn, flags);
                    paging_write_p2m_entry(d, gfn, &l1e[i1],
                                           l1mfn, l1e_content, 1);
                }
                unmap_domain_page(l1e);
            }
            unmap_domain_page(l2e);
        }
#if CONFIG_PAGING_LEVELS >= 4
        unmap_domain_page(l3e);
    }
#endif

#if CONFIG_PAGING_LEVELS == 4
    unmap_domain_page(l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
    unmap_domain_page(l3e);
#endif

}

/* Modify the p2m type of a single gfn from ot to nt, returning the 
 * entry's previous type */
p2m_type_t p2m_change_type(struct domain *d, unsigned long gfn, 
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_type_t pt;
    mfn_t mfn;

    p2m_lock(d->arch.p2m);

    mfn = gfn_to_mfn(d, gfn, &pt);
    if ( pt == ot )
        set_p2m_entry(d, gfn, mfn, 0, nt);

    p2m_unlock(d->arch.p2m);

    return pt;
}

int
set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = 0;
    p2m_type_t ot;
    mfn_t omfn;

    if ( !paging_mode_translate(d) )
        return 0;

    omfn = gfn_to_mfn(d, gfn, &ot);
    if ( p2m_is_ram(ot) )
    {
        ASSERT(mfn_valid(omfn));
        set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
    }

    rc = set_p2m_entry(d, gfn, mfn, 0, p2m_mmio_direct);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_mmio_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            gmfn_to_mfn(d, gfn));
    return rc;
}

int
clear_mmio_p2m_entry(struct domain *d, unsigned long gfn)
{
    int rc = 0;
    unsigned long mfn;

    if ( !paging_mode_translate(d) )
        return 0;

    mfn = gmfn_to_mfn(d, gfn);
    if ( INVALID_MFN == mfn )
    {
        gdprintk(XENLOG_ERR,
            "clear_mmio_p2m_entry: gfn_to_mfn failed! gfn=%08lx\n", gfn);
        return 0;
    }
    rc = set_p2m_entry(d, gfn, _mfn(INVALID_MFN), 0, 0);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
