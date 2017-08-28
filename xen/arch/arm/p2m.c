#include <xen/config.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <xen/bitops.h>
#include <xen/vm_event.h>
#include <xen/monitor.h>
#include <xen/iocap.h>
#include <public/vm_event.h>
#include <asm/flushtlb.h>
#include <asm/gic.h>
#include <asm/event.h>
#include <asm/hardirq.h>
#include <asm/page.h>

#ifdef CONFIG_ARM_64
static unsigned int __read_mostly p2m_root_order;
static unsigned int __read_mostly p2m_root_level;
#define P2M_ROOT_ORDER    p2m_root_order
#define P2M_ROOT_LEVEL p2m_root_level
#else
/* First level P2M is alway 2 consecutive pages */
#define P2M_ROOT_LEVEL 1
#define P2M_ROOT_ORDER    1
#endif

#define P2M_ROOT_PAGES    (1<<P2M_ROOT_ORDER)

unsigned int __read_mostly p2m_ipa_bits;

/* Helpers to lookup the properties of each level */
static const paddr_t level_masks[] =
    { ZEROETH_MASK, FIRST_MASK, SECOND_MASK, THIRD_MASK };
static const uint8_t level_orders[] =
    { ZEROETH_ORDER, FIRST_ORDER, SECOND_ORDER, THIRD_ORDER };

static inline bool_t p2m_valid(lpae_t pte)
{
    return pte.p2m.valid;
}
/*
 * These two can only be used on L0..L2 ptes because L3 mappings set
 * the table bit and therefore these would return the opposite to what
 * you would expect.
 */
static inline bool_t p2m_table(lpae_t pte)
{
    return p2m_valid(pte) && pte.p2m.table;
}
static inline bool_t p2m_mapping(lpae_t pte)
{
    return p2m_valid(pte) && !pte.p2m.table;
}

static inline bool p2m_is_superpage(lpae_t pte, unsigned int level)
{
    return (level < 3) && p2m_mapping(pte);
}

/*
 * Return the start of the next mapping based on the order of the
 * current one.
 */
static inline gfn_t gfn_next_boundary(gfn_t gfn, unsigned int order)
{
    /*
     * The order corresponds to the order of the mapping (or invalid
     * range) in the page table. So we need to align the GFN before
     * incrementing.
     */
    gfn = _gfn(gfn_x(gfn) & ~((1UL << order) - 1));

    return gfn_add(gfn, 1UL << order);
}

static void p2m_flush_tlb(struct p2m_domain *p2m);

/* Unlock the flush and do a P2M TLB flush if necessary */
void p2m_write_unlock(struct p2m_domain *p2m)
{
    if ( p2m->need_flush )
    {
        p2m->need_flush = false;
        /*
         * The final flush is done with the P2M write lock taken to
         * to avoid someone else modify the P2M before the TLB
         * invalidation has completed.
         */
        p2m_flush_tlb(p2m);
    }

    write_unlock(&p2m->lock);
}

void p2m_dump_info(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    p2m_read_lock(p2m);
    printk("p2m mappings for domain %d (vmid %d):\n",
           d->domain_id, p2m->vmid);
    BUG_ON(p2m->stats.mappings[0] || p2m->stats.shattered[0]);
    printk("  1G mappings: %ld (shattered %ld)\n",
           p2m->stats.mappings[1], p2m->stats.shattered[1]);
    printk("  2M mappings: %ld (shattered %ld)\n",
           p2m->stats.mappings[2], p2m->stats.shattered[2]);
    printk("  4K mappings: %ld\n", p2m->stats.mappings[3]);
    p2m_read_unlock(p2m);
}

void memory_type_changed(struct domain *d)
{
}

void dump_p2m_lookup(struct domain *d, paddr_t addr)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    printk("dom%d IPA 0x%"PRIpaddr"\n", d->domain_id, addr);

    printk("P2M @ %p mfn:0x%lx\n",
           p2m->root, page_to_mfn(p2m->root));

    dump_pt_walk(page_to_maddr(p2m->root), addr,
                 P2M_ROOT_LEVEL, P2M_ROOT_PAGES);
}

void p2m_save_state(struct vcpu *p)
{
    p->arch.sctlr = READ_SYSREG(SCTLR_EL1);
}

void p2m_restore_state(struct vcpu *n)
{
    register_t hcr;
    struct p2m_domain *p2m = &n->domain->arch.p2m;
    uint8_t *last_vcpu_ran;

    if ( is_idle_vcpu(n) )
        return;

    hcr = READ_SYSREG(HCR_EL2);

    WRITE_SYSREG64(p2m->vttbr, VTTBR_EL2);
    isb();

    if ( is_32bit_domain(n->domain) )
        hcr &= ~HCR_RW;
    else
        hcr |= HCR_RW;

    WRITE_SYSREG(n->arch.sctlr, SCTLR_EL1);
    isb();

    WRITE_SYSREG(hcr, HCR_EL2);
    isb();

    last_vcpu_ran = &p2m->last_vcpu_ran[smp_processor_id()];

    /*
     * Flush local TLB for the domain to prevent wrong TLB translation
     * when running multiple vCPU of the same domain on a single pCPU.
     */
    if ( *last_vcpu_ran != INVALID_VCPU_ID && *last_vcpu_ran != n->vcpu_id )
        flush_tlb_local();

    *last_vcpu_ran = n->vcpu_id;
}

static void p2m_flush_tlb(struct p2m_domain *p2m)
{
    unsigned long flags = 0;
    uint64_t ovttbr;

    /*
     * ARM only provides an instruction to flush TLBs for the current
     * VMID. So switch to the VTTBR of a given P2M if different.
     */
    ovttbr = READ_SYSREG64(VTTBR_EL2);
    if ( ovttbr != p2m->vttbr )
    {
        local_irq_save(flags);
        WRITE_SYSREG64(p2m->vttbr, VTTBR_EL2);
        isb();
    }

    flush_tlb();

    if ( ovttbr != READ_SYSREG64(VTTBR_EL2) )
    {
        WRITE_SYSREG64(ovttbr, VTTBR_EL2);
        isb();
        local_irq_restore(flags);
    }
}

/*
 * Force a synchronous P2M TLB flush.
 *
 * Must be called with the p2m lock held.
 */
static void p2m_flush_tlb_sync(struct p2m_domain *p2m)
{
    ASSERT(p2m_is_write_locked(p2m));

    p2m_flush_tlb(p2m);
    p2m->need_flush = false;
}

/*
 * Find and map the root page table. The caller is responsible for
 * unmapping the table.
 *
 * The function will return NULL if the offset of the root table is
 * invalid.
 */
static lpae_t *p2m_get_root_pointer(struct p2m_domain *p2m,
                                    gfn_t gfn)
{
    unsigned int root_table;

    if ( P2M_ROOT_PAGES == 1 )
        return __map_domain_page(p2m->root);

    /*
     * Concatenated root-level tables. The table number will be the
     * offset at the previous level. It is not possible to
     * concatenate a level-0 root.
     */
    ASSERT(P2M_ROOT_LEVEL > 0);

    root_table = gfn_x(gfn) >> (level_orders[P2M_ROOT_LEVEL - 1]);
    root_table &= LPAE_ENTRY_MASK;

    if ( root_table >= P2M_ROOT_PAGES )
        return NULL;

    return __map_domain_page(p2m->root + root_table);
}

/*
 * Lookup the MFN corresponding to a domain's GFN.
 * Lookup mem access in the ratrix tree.
 * The entries associated to the GFN is considered valid.
 */
static p2m_access_t p2m_mem_access_radix_get(struct p2m_domain *p2m, gfn_t gfn)
{
    void *ptr;

    if ( !p2m->mem_access_enabled )
        return p2m->default_access;

    ptr = radix_tree_lookup(&p2m->mem_access_settings, gfn_x(gfn));
    if ( !ptr )
        return p2m_access_rwx;
    else
        return radix_tree_ptr_to_int(ptr);
}

#define GUEST_TABLE_MAP_FAILED 0
#define GUEST_TABLE_SUPER_PAGE 1
#define GUEST_TABLE_NORMAL_PAGE 2

static int p2m_create_table(struct p2m_domain *p2m, lpae_t *entry);

/*
 * Take the currently mapped table, find the corresponding GFN entry,
 * and map the next table, if available. The previous table will be
 * unmapped if the next level was mapped (e.g GUEST_TABLE_NORMAL_PAGE
 * returned).
 *
 * The read_only parameters indicates whether intermediate tables should
 * be allocated when not present.
 *
 * Return values:
 *  GUEST_TABLE_MAP_FAILED: Either read_only was set and the entry
 *  was empty, or allocating a new page failed.
 *  GUEST_TABLE_NORMAL_PAGE: next level mapped normally
 *  GUEST_TABLE_SUPER_PAGE: The next entry points to a superpage.
 */
static int p2m_next_level(struct p2m_domain *p2m, bool read_only,
                          lpae_t **table, unsigned int offset)
{
    lpae_t *entry;
    int ret;
    mfn_t mfn;

    entry = *table + offset;

    if ( !p2m_valid(*entry) )
    {
        if ( read_only )
            return GUEST_TABLE_MAP_FAILED;

        ret = p2m_create_table(p2m, entry);
        if ( ret )
            return GUEST_TABLE_MAP_FAILED;
    }

    /* The function p2m_next_level is never called at the 3rd level */
    if ( p2m_mapping(*entry) )
        return GUEST_TABLE_SUPER_PAGE;

    mfn = _mfn(entry->p2m.base);

    unmap_domain_page(*table);
    *table = map_domain_page(mfn);

    return GUEST_TABLE_NORMAL_PAGE;
}

/*
 * Get the details of a given gfn.
 *
 * If the entry is present, the associated MFN will be returned and the
 * access and type filled up. The page_order will correspond to the
 * order of the mapping in the page table (i.e it could be a superpage).
 *
 * If the entry is not present, INVALID_MFN will be returned and the
 * page_order will be set according to the order of the invalid range.
 */
mfn_t p2m_get_entry(struct p2m_domain *p2m, gfn_t gfn,
                    p2m_type_t *t, p2m_access_t *a,
                    unsigned int *page_order)
{
    paddr_t addr = pfn_to_paddr(gfn_x(gfn));
    unsigned int level = 0;
    lpae_t entry, *table;
    int rc;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t _t;

    /* Convenience aliases */
    const unsigned int offsets[4] = {
        zeroeth_table_offset(addr),
        first_table_offset(addr),
        second_table_offset(addr),
        third_table_offset(addr)
    };

    ASSERT(p2m_is_locked(p2m));
    BUILD_BUG_ON(THIRD_MASK != PAGE_MASK);

    /* Allow t to be NULL */
    t = t ?: &_t;

    *t = p2m_invalid;

    /* XXX: Check if the mapping is lower than the mapped gfn */

    /* This gfn is higher than the highest the p2m map currently holds */
    if ( gfn_x(gfn) > gfn_x(p2m->max_mapped_gfn) )
    {
        for ( level = P2M_ROOT_LEVEL; level < 3; level++ )
            if ( (gfn_x(gfn) & (level_masks[level] >> PAGE_SHIFT)) >
                 gfn_x(p2m->max_mapped_gfn) )
                break;

        goto out;
    }

    table = p2m_get_root_pointer(p2m, gfn);

    /*
     * the table should always be non-NULL because the gfn is below
     * p2m->max_mapped_gfn and the root table pages are always present.
     */
    BUG_ON(table == NULL);

    for ( level = P2M_ROOT_LEVEL; level < 3; level++ )
    {
        rc = p2m_next_level(p2m, true, &table, offsets[level]);
        if ( rc == GUEST_TABLE_MAP_FAILED )
            goto out_unmap;
        else if ( rc != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    entry = table[offsets[level]];

    if ( p2m_valid(entry) )
    {
        *t = entry.p2m.type;

        if ( a )
            *a = p2m_mem_access_radix_get(p2m, gfn);

        mfn = _mfn(entry.p2m.base);
        /*
         * The entry may point to a superpage. Find the MFN associated
         * to the GFN.
         */
        mfn = mfn_add(mfn, gfn_x(gfn) & ((1UL << level_orders[level]) - 1));
    }

out_unmap:
    unmap_domain_page(table);

out:
    if ( page_order )
        *page_order = level_orders[level];

    return mfn;
}

mfn_t p2m_lookup(struct domain *d, gfn_t gfn, p2m_type_t *t)
{
    mfn_t ret;
    struct p2m_domain *p2m = &d->arch.p2m;

    p2m_read_lock(p2m);
    ret = p2m_get_entry(p2m, gfn, t, NULL, NULL);
    p2m_read_unlock(p2m);

    return ret;
}

int guest_physmap_mark_populate_on_demand(struct domain *d,
                                          unsigned long gfn,
                                          unsigned int order)
{
    return -ENOSYS;
}

int p2m_pod_decrease_reservation(struct domain *d,
                                 xen_pfn_t gpfn,
                                 unsigned int order)
{
    return -ENOSYS;
}

static void p2m_set_permission(lpae_t *e, p2m_type_t t, p2m_access_t a)
{
    /* First apply type permissions */
    switch ( t )
    {
    case p2m_ram_rw:
        e->p2m.xn = 0;
        e->p2m.write = 1;
        break;

    case p2m_ram_ro:
        e->p2m.xn = 0;
        e->p2m.write = 0;
        break;

    case p2m_iommu_map_rw:
    case p2m_map_foreign:
    case p2m_grant_map_rw:
    case p2m_mmio_direct_dev:
    case p2m_mmio_direct_nc:
    case p2m_mmio_direct_c:
        e->p2m.xn = 1;
        e->p2m.write = 1;
        break;

    case p2m_iommu_map_ro:
    case p2m_grant_map_ro:
    case p2m_invalid:
        e->p2m.xn = 1;
        e->p2m.write = 0;
        break;

    case p2m_max_real_type:
        BUG();
        break;
    }

    /* Then restrict with access permissions */
    switch ( a )
    {
    case p2m_access_rwx:
        break;
    case p2m_access_wx:
        e->p2m.read = 0;
        break;
    case p2m_access_rw:
        e->p2m.xn = 1;
        break;
    case p2m_access_w:
        e->p2m.read = 0;
        e->p2m.xn = 1;
        break;
    case p2m_access_rx:
    case p2m_access_rx2rw:
        e->p2m.write = 0;
        break;
    case p2m_access_x:
        e->p2m.write = 0;
        e->p2m.read = 0;
        break;
    case p2m_access_r:
        e->p2m.write = 0;
        e->p2m.xn = 1;
        break;
    case p2m_access_n:
    case p2m_access_n2rwx:
        e->p2m.read = e->p2m.write = 0;
        e->p2m.xn = 1;
        break;
    }
}

static lpae_t mfn_to_p2m_entry(mfn_t mfn, p2m_type_t t, p2m_access_t a)
{
    /*
     * sh, xn and write bit will be defined in the following switches
     * based on mattr and t.
     */
    lpae_t e = (lpae_t) {
        .p2m.af = 1,
        .p2m.read = 1,
        .p2m.table = 1,
        .p2m.valid = 1,
        .p2m.type = t,
    };

    BUILD_BUG_ON(p2m_max_real_type > (1 << 4));

    switch ( t )
    {
    case p2m_mmio_direct_dev:
        e.p2m.mattr = MATTR_DEV;
        e.p2m.sh = LPAE_SH_OUTER;
        break;

    case p2m_mmio_direct_c:
        e.p2m.mattr = MATTR_MEM;
        e.p2m.sh = LPAE_SH_OUTER;
        break;

    /*
     * ARM ARM: Overlaying the shareability attribute (DDI
     * 0406C.b B3-1376 to 1377)
     *
     * A memory region with a resultant memory type attribute of Normal,
     * and a resultant cacheability attribute of Inner Non-cacheable,
     * Outer Non-cacheable, must have a resultant shareability attribute
     * of Outer Shareable, otherwise shareability is UNPREDICTABLE.
     *
     * On ARMv8 shareability is ignored and explicitly treated as Outer
     * Shareable for Normal Inner Non_cacheable, Outer Non-cacheable.
     * See the note for table D4-40, in page 1788 of the ARM DDI 0487A.j.
     */
    case p2m_mmio_direct_nc:
        e.p2m.mattr = MATTR_MEM_NC;
        e.p2m.sh = LPAE_SH_OUTER;
        break;

    default:
        e.p2m.mattr = MATTR_MEM;
        e.p2m.sh = LPAE_SH_INNER;
    }

    p2m_set_permission(&e, t, a);

    ASSERT(!(pfn_to_paddr(mfn_x(mfn)) & ~PADDR_MASK));

    e.p2m.base = mfn_x(mfn);

    return e;
}

static inline void p2m_write_pte(lpae_t *p, lpae_t pte, bool clean_pte)
{
    write_pte(p, pte);
    if ( clean_pte )
        clean_dcache(*p);
}

static inline void p2m_remove_pte(lpae_t *p, bool clean_pte)
{
    lpae_t pte;

    memset(&pte, 0x00, sizeof(pte));
    p2m_write_pte(p, pte, clean_pte);
}

/* Allocate a new page table page and hook it in via the given entry. */
static int p2m_create_table(struct p2m_domain *p2m, lpae_t *entry)
{
    struct page_info *page;
    lpae_t *p;
    lpae_t pte;

    ASSERT(!p2m_valid(*entry));

    page = alloc_domheap_page(NULL, 0);
    if ( page == NULL )
        return -ENOMEM;

    page_list_add(page, &p2m->pages);

    p = __map_domain_page(page);
    clear_page(p);

    if ( p2m->clean_pte )
        clean_dcache_va_range(p, PAGE_SIZE);

    unmap_domain_page(p);

    /*
     * The access value does not matter because the hardware will ignore
     * the permission fields for table entry.
     */
    pte = mfn_to_p2m_entry(_mfn(page_to_mfn(page)), p2m_invalid,
                           p2m->default_access);

    p2m_write_pte(entry, pte, p2m->clean_pte);

    return 0;
}

static int __p2m_get_mem_access(struct domain *d, gfn_t gfn,
                                xenmem_access_t *access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    void *i;
    unsigned int index;

    static const xenmem_access_t memaccess[] = {
#define ACCESS(ac) [p2m_access_##ac] = XENMEM_access_##ac
            ACCESS(n),
            ACCESS(r),
            ACCESS(w),
            ACCESS(rw),
            ACCESS(x),
            ACCESS(rx),
            ACCESS(wx),
            ACCESS(rwx),
            ACCESS(rx2rw),
            ACCESS(n2rwx),
#undef ACCESS
    };

    ASSERT(p2m_is_locked(p2m));

    /* If no setting was ever set, just return rwx. */
    if ( !p2m->mem_access_enabled )
    {
        *access = XENMEM_access_rwx;
        return 0;
    }

    /* If request to get default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    i = radix_tree_lookup(&p2m->mem_access_settings, gfn_x(gfn));

    if ( !i )
    {
        /*
         * No setting was found in the Radix tree. Check if the
         * entry exists in the page-tables.
         */
        mfn_t mfn = p2m_get_entry(p2m, gfn, NULL, NULL, NULL);

        if ( mfn_eq(mfn, INVALID_MFN) )
            return -ESRCH;

        /* If entry exists then its rwx. */
        *access = XENMEM_access_rwx;
    }
    else
    {
        /* Setting was found in the Radix tree. */
        index = radix_tree_ptr_to_int(i);
        if ( index >= ARRAY_SIZE(memaccess) )
            return -ERANGE;

        *access = memaccess[index];
    }

    return 0;
}

static int p2m_mem_access_radix_set(struct p2m_domain *p2m, gfn_t gfn,
                                    p2m_access_t a)
{
    int rc;

    if ( !p2m->mem_access_enabled )
        return 0;

    if ( p2m_access_rwx == a )
    {
        radix_tree_delete(&p2m->mem_access_settings, gfn_x(gfn));
        return 0;
    }

    rc = radix_tree_insert(&p2m->mem_access_settings, gfn_x(gfn),
                           radix_tree_int_to_ptr(a));
    if ( rc == -EEXIST )
    {
        /* If a setting already exists, change it to the new one */
        radix_tree_replace_slot(
            radix_tree_lookup_slot(
                &p2m->mem_access_settings, gfn_x(gfn)),
            radix_tree_int_to_ptr(a));
        rc = 0;
    }

    return rc;
}

enum p2m_operation {
    MEMACCESS,
};

/*
 * Put any references on the single 4K page referenced by pte.
 * TODO: Handle superpages, for now we only take special references for leaf
 * pages (specifically foreign ones, which can't be super mapped today).
 */
static void p2m_put_l3_page(const lpae_t pte)
{
    ASSERT(p2m_valid(pte));

    /*
     * TODO: Handle other p2m types
     *
     * It's safe to do the put_page here because page_alloc will
     * flush the TLBs if the page is reallocated before the end of
     * this loop.
     */
    if ( p2m_is_foreign(pte.p2m.type) )
    {
        unsigned long mfn = pte.p2m.base;

        ASSERT(mfn_valid(mfn));
        put_page(mfn_to_page(mfn));
    }
}

/* Free lpae sub-tree behind an entry */
static void p2m_free_entry(struct p2m_domain *p2m,
                           lpae_t entry, unsigned int level)
{
    unsigned int i;
    lpae_t *table;
    mfn_t mfn;
    struct page_info *pg;

    /* Nothing to do if the entry is invalid. */
    if ( !p2m_valid(entry) )
        return;

    /* Nothing to do but updating the stats if the entry is a super-page. */
    if ( p2m_is_superpage(entry, level) )
    {
        p2m->stats.mappings[level]--;
        return;
    }

    if ( level == 3 )
    {
        p2m->stats.mappings[level]--;
        p2m_put_l3_page(entry);
        return;
    }

    table = map_domain_page(_mfn(entry.p2m.base));
    for ( i = 0; i < LPAE_ENTRIES; i++ )
        p2m_free_entry(p2m, *(table + i), level + 1);

    unmap_domain_page(table);

    /*
     * Make sure all the references in the TLB have been removed before
     * freing the intermediate page table.
     * XXX: Should we defer the free of the page table to avoid the
     * flush?
     */
    if ( p2m->need_flush )
        p2m_flush_tlb_sync(p2m);

    mfn = _mfn(entry.p2m.base);
    ASSERT(mfn_valid(mfn_x(mfn)));

    pg = mfn_to_page(mfn_x(mfn));

    page_list_del(pg, &p2m->pages);
    free_domheap_page(pg);
}

static bool p2m_split_superpage(struct p2m_domain *p2m, lpae_t *entry,
                                unsigned int level, unsigned int target,
                                const unsigned int *offsets)
{
    struct page_info *page;
    unsigned int i;
    lpae_t pte, *table;
    bool rv = true;

    /* Convenience aliases */
    mfn_t mfn = _mfn(entry->p2m.base);
    unsigned int next_level = level + 1;
    unsigned int level_order = level_orders[next_level];

    /*
     * This should only be called with target != level and the entry is
     * a superpage.
     */
    ASSERT(level < target);
    ASSERT(p2m_is_superpage(*entry, level));

    page = alloc_domheap_page(NULL, 0);
    if ( !page )
        return false;

    page_list_add(page, &p2m->pages);
    table = __map_domain_page(page);

    /*
     * We are either splitting a first level 1G page into 512 second level
     * 2M pages, or a second level 2M page into 512 third level 4K pages.
     */
    for ( i = 0; i < LPAE_ENTRIES; i++ )
    {
        lpae_t *new_entry = table + i;

        /*
         * Use the content of the superpage entry and override
         * the necessary fields. So the correct permission are kept.
         */
        pte = *entry;
        pte.p2m.base = mfn_x(mfn_add(mfn, i << level_order));

        /*
         * First and second level pages set p2m.table = 0, but third
         * level entries set p2m.table = 1.
         */
        pte.p2m.table = (next_level == 3);

        write_pte(new_entry, pte);
    }

    /* Update stats */
    p2m->stats.shattered[level]++;
    p2m->stats.mappings[level]--;
    p2m->stats.mappings[next_level] += LPAE_ENTRIES;

    /*
     * Shatter superpage in the page to the level we want to make the
     * changes.
     * This is done outside the loop to avoid checking the offset to
     * know whether the entry should be shattered for every entry.
     */
    if ( next_level != target )
        rv = p2m_split_superpage(p2m, table + offsets[next_level],
                                 level + 1, target, offsets);

    if ( p2m->clean_pte )
        clean_dcache_va_range(table, PAGE_SIZE);

    unmap_domain_page(table);

    pte = mfn_to_p2m_entry(_mfn(page_to_mfn(page)), p2m_invalid,
                           p2m->default_access);

    /*
     * Even if we failed, we should install the newly allocated LPAE
     * entry. The caller will be in charge to free the sub-tree.
     */
    p2m_write_pte(entry, pte, p2m->clean_pte);

    return rv;
}

/*
 * Insert an entry in the p2m. This should be called with a mapping
 * equal to a page/superpage (4K, 2M, 1G).
 */
static int __p2m_set_entry(struct p2m_domain *p2m,
                           gfn_t sgfn,
                           unsigned int page_order,
                           mfn_t smfn,
                           p2m_type_t t,
                           p2m_access_t a)
{
    paddr_t addr = pfn_to_paddr(gfn_x(sgfn));
    unsigned int level = 0;
    unsigned int target = 3 - (page_order / LPAE_SHIFT);
    lpae_t *entry, *table, orig_pte;
    int rc;

    /* Convenience aliases */
    const unsigned int offsets[4] = {
        zeroeth_table_offset(addr),
        first_table_offset(addr),
        second_table_offset(addr),
        third_table_offset(addr)
    };

    ASSERT(p2m_is_write_locked(p2m));

    /*
     * Check if the level target is valid: we only support
     * 4K - 2M - 1G mapping.
     */
    ASSERT(target > 0 && target <= 3);

    table = p2m_get_root_pointer(p2m, sgfn);
    if ( !table )
        return -EINVAL;

    for ( level = P2M_ROOT_LEVEL; level < target; level++ )
    {
        /*
         * Don't try to allocate intermediate page table if the mapping
         * is about to be removed (i.e mfn == INVALID_MFN).
         */
        rc = p2m_next_level(p2m, mfn_eq(smfn, INVALID_MFN),
                            &table, offsets[level]);
        if ( rc == GUEST_TABLE_MAP_FAILED )
        {
            /*
             * We are here because p2m_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and they p2m tree is read-only). It is a valid case
             * when removing a mapping as it may not exist in the
             * page table. In this case, just ignore it.
             */
            rc = mfn_eq(smfn, INVALID_MFN) ? 0 : -ENOENT;
            goto out;
        }
        else if ( rc != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    entry = table + offsets[level];

    /*
     * If we are here with level < target, we must be at a leaf node,
     * and we need to break up the superpage.
     */
    if ( level < target )
    {
        /* We need to split the original page. */
        lpae_t split_pte = *entry;

        ASSERT(p2m_is_superpage(*entry, level));

        if ( !p2m_split_superpage(p2m, &split_pte, level, target, offsets) )
        {
            /*
             * The current super-page is still in-place, so re-increment
             * the stats.
             */
            p2m->stats.mappings[level]++;

            /* Free the allocated sub-tree */
            p2m_free_entry(p2m, split_pte, level);

            rc = -ENOMEM;
            goto out;
        }

        /*
         * Follow the break-before-sequence to update the entry.
         * For more details see (D4.7.1 in ARM DDI 0487A.j).
         */
        p2m_remove_pte(entry, p2m->clean_pte);
        p2m_flush_tlb_sync(p2m);

        p2m_write_pte(entry, split_pte, p2m->clean_pte);

        /* then move to the level we want to make real changes */
        for ( ; level < target; level++ )
        {
            rc = p2m_next_level(p2m, true, &table, offsets[level]);

            /*
             * The entry should be found and either be a table
             * or a superpage if level 3 is not targeted
             */
            ASSERT(rc == GUEST_TABLE_NORMAL_PAGE ||
                   (rc == GUEST_TABLE_SUPER_PAGE && target < 3));
        }

        entry = table + offsets[level];
    }

    /*
     * We should always be there with the correct level because
     * all the intermediate tables have been installed if necessary.
     */
    ASSERT(level == target);

    orig_pte = *entry;

    /*
     * The radix-tree can only work on 4KB. This is only used when
     * memaccess is enabled and during shutdown.
     */
    ASSERT(!p2m->mem_access_enabled || page_order == 0 ||
           p2m->domain->is_dying);
    /*
     * The access type should always be p2m_access_rwx when the mapping
     * is removed.
     */
    ASSERT(!mfn_eq(INVALID_MFN, smfn) || (a == p2m_access_rwx));
    /*
     * Update the mem access permission before update the P2M. So we
     * don't have to revert the mapping if it has failed.
     */
    rc = p2m_mem_access_radix_set(p2m, sgfn, a);
    if ( rc )
        goto out;

    /*
     * Always remove the entry in order to follow the break-before-make
     * sequence when updating the translation table (D4.7.1 in ARM DDI
     * 0487A.j).
     */
    if ( p2m_valid(orig_pte) )
        p2m_remove_pte(entry, p2m->clean_pte);

    if ( mfn_eq(smfn, INVALID_MFN) )
        /* Flush can be deferred if the entry is removed */
        p2m->need_flush |= !!p2m_valid(orig_pte);
    else
    {
        lpae_t pte = mfn_to_p2m_entry(smfn, t, a);

        if ( level < 3 )
            pte.p2m.table = 0; /* Superpage entry */

        /*
         * It is necessary to flush the TLB before writing the new entry
         * to keep coherency when the previous entry was valid.
         *
         * Although, it could be defered when only the permissions are
         * changed (e.g in case of memaccess).
         */
        if ( p2m_valid(orig_pte) )
        {
            if ( likely(!p2m->mem_access_enabled) ||
                 P2M_CLEAR_PERM(pte) != P2M_CLEAR_PERM(orig_pte) )
                p2m_flush_tlb_sync(p2m);
            else
                p2m->need_flush = true;
        }
        else /* new mapping */
            p2m->stats.mappings[level]++;

        p2m_write_pte(entry, pte, p2m->clean_pte);

        p2m->max_mapped_gfn = gfn_max(p2m->max_mapped_gfn,
                                      gfn_add(sgfn, 1 << page_order));
        p2m->lowest_mapped_gfn = gfn_min(p2m->lowest_mapped_gfn, sgfn);
    }

    /*
     * Free the entry only if the original pte was valid and the base
     * is different (to avoid freeing when permission is changed).
     */
    if ( p2m_valid(orig_pte) && entry->p2m.base != orig_pte.p2m.base )
        p2m_free_entry(p2m, orig_pte, level);

    if ( need_iommu(p2m->domain) && (p2m_valid(orig_pte) || p2m_valid(*entry)) )
        rc = iommu_iotlb_flush(p2m->domain, gfn_x(sgfn), 1UL << page_order);
    else
        rc = 0;

out:
    unmap_domain_page(table);

    return rc;
}

int p2m_set_entry(struct p2m_domain *p2m,
                  gfn_t sgfn,
                  unsigned long nr,
                  mfn_t smfn,
                  p2m_type_t t,
                  p2m_access_t a)
{
    int rc = 0;

    while ( nr )
    {
        unsigned long mask;
        unsigned long order;

        /*
         * Don't take into account the MFN when removing mapping (i.e
         * MFN_INVALID) to calculate the correct target order.
         *
         * XXX: Support superpage mappings if nr is not aligned to a
         * superpage size.
         */
        mask = !mfn_eq(smfn, INVALID_MFN) ? mfn_x(smfn) : 0;
        mask |= gfn_x(sgfn) | nr;

        /* Always map 4k by 4k when memaccess is enabled */
        if ( unlikely(p2m->mem_access_enabled) )
            order = THIRD_ORDER;
        else if ( !(mask & ((1UL << FIRST_ORDER) - 1)) )
            order = FIRST_ORDER;
        else if ( !(mask & ((1UL << SECOND_ORDER) - 1)) )
            order = SECOND_ORDER;
        else
            order = THIRD_ORDER;

        rc = __p2m_set_entry(p2m, sgfn, order, smfn, t, a);
        if ( rc )
            break;

        sgfn = gfn_add(sgfn, (1 << order));
        if ( !mfn_eq(smfn, INVALID_MFN) )
           smfn = mfn_add(smfn, (1 << order));

        nr -= (1 << order);
    }

    return rc;
}

static inline int p2m_insert_mapping(struct domain *d,
                                     gfn_t start_gfn,
                                     unsigned long nr,
                                     mfn_t mfn,
                                     p2m_type_t t)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    int rc;

    p2m_write_lock(p2m);
    rc = p2m_set_entry(p2m, start_gfn, nr, mfn, t, p2m->default_access);
    p2m_write_unlock(p2m);

    return rc;
}

static inline int p2m_remove_mapping(struct domain *d,
                                     gfn_t start_gfn,
                                     unsigned long nr,
                                     mfn_t mfn)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    int rc;

    p2m_write_lock(p2m);
    rc = p2m_set_entry(p2m, start_gfn, nr, INVALID_MFN,
                       p2m_invalid, p2m_access_rwx);
    p2m_write_unlock(p2m);

    return rc;
}

int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt)
{
    return p2m_insert_mapping(d, gfn, nr, mfn, p2mt);
}

int unmap_regions_p2mt(struct domain *d,
                       gfn_t gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return p2m_remove_mapping(d, gfn, nr, mfn);
}

int map_mmio_regions(struct domain *d,
                     gfn_t start_gfn,
                     unsigned long nr,
                     mfn_t mfn)
{
    return p2m_insert_mapping(d, start_gfn, nr, mfn, p2m_mmio_direct_dev);
}

int unmap_mmio_regions(struct domain *d,
                       gfn_t start_gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return p2m_remove_mapping(d, start_gfn, nr, mfn);
}

int map_dev_mmio_region(struct domain *d,
                        gfn_t gfn,
                        unsigned long nr,
                        mfn_t mfn)
{
    int res;

    if ( !(nr && iomem_access_permitted(d, mfn_x(mfn), mfn_x(mfn) + nr - 1)) )
        return 0;

    res = p2m_insert_mapping(d, gfn, nr, mfn, p2m_mmio_direct_c);
    if ( res < 0 )
    {
        printk(XENLOG_G_ERR "Unable to map MFNs [%#"PRI_mfn" - %#"PRI_mfn" in Dom%d\n",
               mfn_x(mfn), mfn_x(mfn) + nr - 1, d->domain_id);
        return res;
    }

    return 0;
}

int guest_physmap_add_entry(struct domain *d,
                            gfn_t gfn,
                            mfn_t mfn,
                            unsigned long page_order,
                            p2m_type_t t)
{
    return p2m_insert_mapping(d, gfn, (1 << page_order), mfn, t);
}

int guest_physmap_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                              unsigned int page_order)
{
    return p2m_remove_mapping(d, gfn, (1 << page_order), mfn);
}

static int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    unsigned int i;

    page = alloc_domheap_pages(NULL, P2M_ROOT_ORDER, 0);
    if ( page == NULL )
        return -ENOMEM;

    /* Clear both first level pages */
    for ( i = 0; i < P2M_ROOT_PAGES; i++ )
        clear_and_clean_page(page + i);

    p2m->root = page;

    p2m->vttbr = page_to_maddr(p2m->root) | ((uint64_t)p2m->vmid & 0xff) << 48;

    /*
     * Make sure that all TLBs corresponding to the new VMID are flushed
     * before using it
     */
    p2m_flush_tlb(p2m);

    return 0;
}

#define MAX_VMID 256
#define INVALID_VMID 0 /* VMID 0 is reserved */

static spinlock_t vmid_alloc_lock = SPIN_LOCK_UNLOCKED;

/*
 * VTTBR_EL2 VMID field is 8 bits. Using a bitmap here limits us to
 * 256 concurrent domains.
 */
static DECLARE_BITMAP(vmid_mask, MAX_VMID);

void p2m_vmid_allocator_init(void)
{
    set_bit(INVALID_VMID, vmid_mask);
}

static int p2m_alloc_vmid(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    int rc, nr;

    spin_lock(&vmid_alloc_lock);

    nr = find_first_zero_bit(vmid_mask, MAX_VMID);

    ASSERT(nr != INVALID_VMID);

    if ( nr == MAX_VMID )
    {
        rc = -EBUSY;
        printk(XENLOG_ERR "p2m.c: dom%d: VMID pool exhausted\n", d->domain_id);
        goto out;
    }

    set_bit(nr, vmid_mask);

    p2m->vmid = nr;

    rc = 0;

out:
    spin_unlock(&vmid_alloc_lock);
    return rc;
}

static void p2m_free_vmid(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    spin_lock(&vmid_alloc_lock);
    if ( p2m->vmid != INVALID_VMID )
        clear_bit(p2m->vmid, vmid_mask);

    spin_unlock(&vmid_alloc_lock);
}

void p2m_teardown(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *pg;

    /* p2m not actually initialized */
    if ( !p2m->domain )
        return;

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        free_domheap_page(pg);

    if ( p2m->root )
        free_domheap_pages(p2m->root, P2M_ROOT_ORDER);

    p2m->root = NULL;

    p2m_free_vmid(d);

    radix_tree_destroy(&p2m->mem_access_settings, NULL);

    p2m->domain = NULL;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    int rc = 0;
    unsigned int cpu;

    rwlock_init(&p2m->lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    p2m->vmid = INVALID_VMID;

    rc = p2m_alloc_vmid(d);
    if ( rc != 0 )
        return rc;

    p2m->max_mapped_gfn = _gfn(0);
    p2m->lowest_mapped_gfn = _gfn(ULONG_MAX);

    p2m->default_access = p2m_access_rwx;
    p2m->mem_access_enabled = false;
    radix_tree_init(&p2m->mem_access_settings);

    /*
     * Some IOMMUs don't support coherent PT walk. When the p2m is
     * shared with the CPU, Xen has to make sure that the PT changes have
     * reached the memory
     */
    p2m->clean_pte = iommu_enabled &&
        !iommu_has_feature(d, IOMMU_FEAT_COHERENT_WALK);

    rc = p2m_alloc_table(d);

    /*
     * Make sure that the type chosen to is able to store the an vCPU ID
     * between 0 and the maximum of virtual CPUS supported as long as
     * the INVALID_VCPU_ID.
     */
    BUILD_BUG_ON((1 << (sizeof(p2m->last_vcpu_ran[0]) * 8)) < MAX_VIRT_CPUS);
    BUILD_BUG_ON((1 << (sizeof(p2m->last_vcpu_ran[0])* 8)) < INVALID_VCPU_ID);

    for_each_possible_cpu(cpu)
       p2m->last_vcpu_ran[cpu] = INVALID_VCPU_ID;

    /*
     * Besides getting a domain when we only have the p2m in hand,
     * the back pointer to domain is also used in p2m_teardown()
     * as an end-of-initialization indicator.
     */
    p2m->domain = d;

    return rc;
}

/*
 * The function will go through the p2m and remove page reference when it
 * is required. The mapping will be removed from the p2m.
 *
 * XXX: See whether the mapping can be left intact in the p2m.
 */
int relinquish_p2m_mapping(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    unsigned long count = 0;
    p2m_type_t t;
    int rc = 0;
    unsigned int order;
    gfn_t start, end;

    p2m_write_lock(p2m);

    start = p2m->lowest_mapped_gfn;
    end = p2m->max_mapped_gfn;

    for ( ; gfn_x(start) < gfn_x(end);
          start = gfn_next_boundary(start, order) )
    {
        mfn_t mfn = p2m_get_entry(p2m, start, &t, NULL, &order);

        count++;
        /*
         * Arbitrarily preempt every 512 iterations.
         */
        if ( !(count % 512) && hypercall_preempt_check() )
        {
            rc = -ERESTART;
            break;
        }

        /*
         * p2m_set_entry will take care of removing reference on page
         * when it is necessary and removing the mapping in the p2m.
         */
        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            /*
             * For valid mapping, the start will always be aligned as
             * entry will be removed whilst relinquishing.
             */
            rc = __p2m_set_entry(p2m, start, order, INVALID_MFN,
                                 p2m_invalid, p2m_access_rwx);
            if ( unlikely(rc) )
            {
                printk(XENLOG_G_ERR "Unable to remove mapping gfn=%#"PRI_gfn" order=%u from the p2m of domain %d\n", gfn_x(start), order, d->domain_id);
                break;
            }
        }
    }

    /*
     * Update lowest_mapped_gfn so on the next call we still start where
     * we stopped.
     */
    p2m->lowest_mapped_gfn = start;

    p2m_write_unlock(p2m);

    return rc;
}

int p2m_cache_flush(struct domain *d, gfn_t start, unsigned long nr)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    gfn_t end = gfn_add(start, nr);
    gfn_t next_gfn;
    p2m_type_t t;
    unsigned int order;

    /*
     * The operation cache flush will invalidate the RAM assigned to the
     * guest in a given range. It will not modify the page table and
     * flushing the cache whilst the page is used by another CPU is
     * fine. So using read-lock is fine here.
     */
    p2m_read_lock(p2m);

    start = gfn_max(start, p2m->lowest_mapped_gfn);
    end = gfn_min(end, p2m->max_mapped_gfn);

    for ( ; gfn_x(start) < gfn_x(end); start = next_gfn )
    {
        mfn_t mfn = p2m_get_entry(p2m, start, &t, NULL, &order);

        next_gfn = gfn_next_boundary(start, order);

        /* Skip hole and non-RAM page */
        if ( mfn_eq(mfn, INVALID_MFN) || !p2m_is_ram(t) )
            continue;

        /* XXX: Implement preemption */
        while ( gfn_x(start) < gfn_x(next_gfn) )
        {
            flush_page_to_ram(mfn_x(mfn), false);

            start = gfn_add(start, 1);
            mfn = mfn_add(mfn, 1);
        }
    }

    invalidate_icache();

    p2m_read_unlock(p2m);

    return 0;
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    return p2m_lookup(d, gfn, NULL);
}

/*
 * If mem_access is in use it might have been the reason why get_page_from_gva
 * failed to fetch the page, as it uses the MMU for the permission checking.
 * Only in these cases we do a software-based type check and fetch the page if
 * we indeed found a conflicting mem_access setting.
 */
static struct page_info*
p2m_mem_access_check_and_get_page(vaddr_t gva, unsigned long flag)
{
    long rc;
    paddr_t ipa;
    gfn_t gfn;
    mfn_t mfn;
    xenmem_access_t xma;
    p2m_type_t t;
    struct page_info *page = NULL;
    struct p2m_domain *p2m = &current->domain->arch.p2m;

    rc = gva_to_ipa(gva, &ipa, flag);
    if ( rc < 0 )
        goto err;

    gfn = _gfn(paddr_to_pfn(ipa));

    /*
     * We do this first as this is faster in the default case when no
     * permission is set on the page.
     */
    rc = __p2m_get_mem_access(current->domain, gfn, &xma);
    if ( rc < 0 )
        goto err;

    /* Let's check if mem_access limited the access. */
    switch ( xma )
    {
    default:
    case XENMEM_access_rwx:
    case XENMEM_access_rw:
        /*
         * If mem_access contains no rw perm restrictions at all then the original
         * fault was correct.
         */
        goto err;
    case XENMEM_access_n2rwx:
    case XENMEM_access_n:
    case XENMEM_access_x:
        /*
         * If no r/w is permitted by mem_access, this was a fault caused by mem_access.
         */
        break;
    case XENMEM_access_wx:
    case XENMEM_access_w:
        /*
         * If this was a read then it was because of mem_access, but if it was
         * a write then the original get_page_from_gva fault was correct.
         */
        if ( flag == GV2M_READ )
            break;
        else
            goto err;
    case XENMEM_access_rx2rw:
    case XENMEM_access_rx:
    case XENMEM_access_r:
        /*
         * If this was a write then it was because of mem_access, but if it was
         * a read then the original get_page_from_gva fault was correct.
         */
        if ( flag == GV2M_WRITE )
            break;
        else
            goto err;
    }

    /*
     * We had a mem_access permission limiting the access, but the page type
     * could also be limiting, so we need to check that as well.
     */
    mfn = p2m_get_entry(p2m, gfn, &t, NULL, NULL);
    if ( mfn_eq(mfn, INVALID_MFN) )
        goto err;

    if ( !mfn_valid(mfn_x(mfn)) )
        goto err;

    /*
     * Base type doesn't allow r/w
     */
    if ( t != p2m_ram_rw )
        goto err;

    page = mfn_to_page(mfn_x(mfn));

    if ( unlikely(!get_page(page, current->domain)) )
        page = NULL;

err:
    return page;
}

struct page_info *get_page_from_gva(struct vcpu *v, vaddr_t va,
                                    unsigned long flags)
{
    struct domain *d = v->domain;
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page = NULL;
    paddr_t maddr = 0;
    int rc;

    /*
     * XXX: To support a different vCPU, we would need to load the
     * VTTBR_EL2, TTBR0_EL1, TTBR1_EL1 and SCTLR_EL1
     */
    if ( v != current )
        return NULL;

    p2m_read_lock(p2m);

    rc = gvirt_to_maddr(va, &maddr, flags);

    if ( rc )
        goto err;

    if ( !mfn_valid(maddr >> PAGE_SHIFT) )
        goto err;

    page = mfn_to_page(maddr >> PAGE_SHIFT);
    ASSERT(page);

    if ( unlikely(!get_page(page, d)) )
        page = NULL;

err:
    if ( !page && p2m->mem_access_enabled )
        page = p2m_mem_access_check_and_get_page(va, flags);

    p2m_read_unlock(p2m);

    return page;
}

static void __init setup_virt_paging_one(void *data)
{
    unsigned long val = (unsigned long)data;
    WRITE_SYSREG32(val, VTCR_EL2);
    isb();
}

void __init setup_virt_paging(void)
{
    /* Setup Stage 2 address translation */
    unsigned long val = VTCR_RES1|VTCR_SH0_IS|VTCR_ORGN0_WBWA|VTCR_IRGN0_WBWA;

#ifdef CONFIG_ARM_32
    printk("P2M: 40-bit IPA\n");
    p2m_ipa_bits = 40;
    val |= VTCR_T0SZ(0x18); /* 40 bit IPA */
    val |= VTCR_SL0(0x1); /* P2M starts at first level */
#else /* CONFIG_ARM_64 */
    const struct {
        unsigned int pabits; /* Physical Address Size */
        unsigned int t0sz;   /* Desired T0SZ, minimum in comment */
        unsigned int root_order; /* Page order of the root of the p2m */
        unsigned int sl0;    /* Desired SL0, maximum in comment */
    } pa_range_info[] = {
        /* T0SZ minimum and SL0 maximum from ARM DDI 0487A.b Table D4-5 */
        /*      PA size, t0sz(min), root-order, sl0(max) */
        [0] = { 32,      32/*32*/,  0,          1 },
        [1] = { 36,      28/*28*/,  0,          1 },
        [2] = { 40,      24/*24*/,  1,          1 },
        [3] = { 42,      24/*22*/,  1,          1 },
        [4] = { 44,      20/*20*/,  0,          2 },
        [5] = { 48,      16/*16*/,  0,          2 },
        [6] = { 0 }, /* Invalid */
        [7] = { 0 }  /* Invalid */
    };

    unsigned int cpu;
    unsigned int pa_range = 0x10; /* Larger than any possible value */

    for_each_online_cpu ( cpu )
    {
        const struct cpuinfo_arm *info = &cpu_data[cpu];
        if ( info->mm64.pa_range < pa_range )
            pa_range = info->mm64.pa_range;
    }

    /* pa_range is 4 bits, but the defined encodings are only 3 bits */
    if ( pa_range&0x8 || !pa_range_info[pa_range].pabits )
        panic("Unknown encoding of ID_AA64MMFR0_EL1.PARange %x\n", pa_range);

    val |= VTCR_PS(pa_range);
    val |= VTCR_TG0_4K;
    val |= VTCR_SL0(pa_range_info[pa_range].sl0);
    val |= VTCR_T0SZ(pa_range_info[pa_range].t0sz);

    p2m_root_order = pa_range_info[pa_range].root_order;
    p2m_root_level = 2 - pa_range_info[pa_range].sl0;
    p2m_ipa_bits = 64 - pa_range_info[pa_range].t0sz;

    printk("P2M: %d-bit IPA with %d-bit PA\n",
           p2m_ipa_bits,
           pa_range_info[pa_range].pabits);
#endif
    printk("P2M: %d levels with order-%d root, VTCR 0x%lx\n",
           4 - P2M_ROOT_LEVEL, P2M_ROOT_ORDER, val);
    /* It is not allowed to concatenate a level zero root */
    BUG_ON( P2M_ROOT_LEVEL == 0 && P2M_ROOT_ORDER > 0 );
    setup_virt_paging_one((void *)val);
    smp_call_function(setup_virt_paging_one, (void *)val, 1);
}

bool_t p2m_mem_access_check(paddr_t gpa, vaddr_t gla, const struct npfec npfec)
{
    int rc;
    bool_t violation;
    xenmem_access_t xma;
    vm_event_request_t *req;
    struct vcpu *v = current;
    struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);

    /* Mem_access is not in use. */
    if ( !p2m->mem_access_enabled )
        return true;

    rc = p2m_get_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), &xma);
    if ( rc )
        return true;

    /* Now check for mem_access violation. */
    switch ( xma )
    {
    case XENMEM_access_rwx:
        violation = false;
        break;
    case XENMEM_access_rw:
        violation = npfec.insn_fetch;
        break;
    case XENMEM_access_wx:
        violation = npfec.read_access;
        break;
    case XENMEM_access_rx:
    case XENMEM_access_rx2rw:
        violation = npfec.write_access;
        break;
    case XENMEM_access_x:
        violation = npfec.read_access || npfec.write_access;
        break;
    case XENMEM_access_w:
        violation = npfec.read_access || npfec.insn_fetch;
        break;
    case XENMEM_access_r:
        violation = npfec.write_access || npfec.insn_fetch;
        break;
    default:
    case XENMEM_access_n:
    case XENMEM_access_n2rwx:
        violation = true;
        break;
    }

    if ( !violation )
        return true;

    /* First, handle rx2rw and n2rwx conversion automatically. */
    if ( npfec.write_access && xma == XENMEM_access_rx2rw )
    {
        rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                0, ~0, XENMEM_access_rw, 0);
        return false;
    }
    else if ( xma == XENMEM_access_n2rwx )
    {
        rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                0, ~0, XENMEM_access_rwx, 0);
    }

    /* Otherwise, check if there is a vm_event monitor subscriber */
    if ( !vm_event_check_ring(&v->domain->vm_event->monitor) )
    {
        /* No listener */
        if ( p2m->access_required )
        {
            gdprintk(XENLOG_INFO, "Memory access permissions failure, "
                                  "no vm_event listener VCPU %d, dom %d\n",
                                  v->vcpu_id, v->domain->domain_id);
            domain_crash(v->domain);
        }
        else
        {
            /* n2rwx was already handled */
            if ( xma != XENMEM_access_n2rwx )
            {
                /* A listener is not required, so clear the access
                 * restrictions. */
                rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                        0, ~0, XENMEM_access_rwx, 0);
            }
        }

        /* No need to reinject */
        return false;
    }

    req = xzalloc(vm_event_request_t);
    if ( req )
    {
        req->reason = VM_EVENT_REASON_MEM_ACCESS;

        /* Send request to mem access subscriber */
        req->u.mem_access.gfn = gpa >> PAGE_SHIFT;
        req->u.mem_access.offset =  gpa & ((1 << PAGE_SHIFT) - 1);
        if ( npfec.gla_valid )
        {
            req->u.mem_access.flags |= MEM_ACCESS_GLA_VALID;
            req->u.mem_access.gla = gla;

            if ( npfec.kind == npfec_kind_with_gla )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_WITH_GLA;
            else if ( npfec.kind == npfec_kind_in_gpt )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_IN_GPT;
        }
        req->u.mem_access.flags |= npfec.read_access    ? MEM_ACCESS_R : 0;
        req->u.mem_access.flags |= npfec.write_access   ? MEM_ACCESS_W : 0;
        req->u.mem_access.flags |= npfec.insn_fetch     ? MEM_ACCESS_X : 0;

        if ( monitor_traps(v, (xma != XENMEM_access_n2rwx), req) < 0 )
            domain_crash(v->domain);

        xfree(req);
    }

    return false;
}

/*
 * Set access type for a region of pfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access,
                        unsigned int altp2m_idx)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_access_t a;
    unsigned int order;
    long rc = 0;

    static const p2m_access_t memaccess[] = {
#define ACCESS(ac) [XENMEM_access_##ac] = p2m_access_##ac
        ACCESS(n),
        ACCESS(r),
        ACCESS(w),
        ACCESS(rw),
        ACCESS(x),
        ACCESS(rx),
        ACCESS(wx),
        ACCESS(rwx),
        ACCESS(rx2rw),
        ACCESS(n2rwx),
#undef ACCESS
    };

    switch ( access )
    {
    case 0 ... ARRAY_SIZE(memaccess) - 1:
        a = memaccess[access];
        break;
    case XENMEM_access_default:
        a = p2m->default_access;
        break;
    default:
        return -EINVAL;
    }

    /*
     * Flip mem_access_enabled to true when a permission is set, as to prevent
     * allocating or inserting super-pages.
     */
    p2m->mem_access_enabled = true;

    /* If request to set default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_write_lock(p2m);

    for ( gfn = gfn_add(gfn, start); nr > start;
          gfn = gfn_next_boundary(gfn, order) )
    {
        p2m_type_t t;
        mfn_t mfn = p2m_get_entry(p2m, gfn, &t, NULL, &order);


        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            order = 0;
            rc = __p2m_set_entry(p2m, gfn, 0, mfn, t, a);
            if ( rc )
                break;
        }

        start += gfn_x(gfn_next_boundary(gfn, order)) - gfn_x(gfn);
        /* Check for continuation if it is not the last iteration */
        if ( nr > start && !(start & mask) && hypercall_preempt_check() )
        {
            rc = start;
            break;
        }
    }

    p2m_write_unlock(p2m);

    return rc;
}

long p2m_set_mem_access_multi(struct domain *d,
                              const XEN_GUEST_HANDLE(const_uint64) pfn_list,
                              const XEN_GUEST_HANDLE(const_uint8) access_list,
                              uint32_t nr, uint32_t start, uint32_t mask,
                              unsigned int altp2m_idx)
{
    /* Not yet implemented on ARM. */
    return -EOPNOTSUPP;
}

int p2m_get_mem_access(struct domain *d, gfn_t gfn,
                       xenmem_access_t *access)
{
    int ret;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_read_lock(p2m);
    ret = __p2m_get_mem_access(d, gfn, access);
    p2m_read_unlock(p2m);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
