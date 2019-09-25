#include <xen/cpu.h>
#include <xen/domain_page.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/alternative.h>
#include <asm/event.h>
#include <asm/flushtlb.h>
#include <asm/guest_walk.h>
#include <asm/page.h>

#define MAX_VMID_8_BIT  (1UL << 8)
#define MAX_VMID_16_BIT (1UL << 16)

#define INVALID_VMID 0 /* VMID 0 is reserved */

#ifdef CONFIG_ARM_64
static unsigned int __read_mostly p2m_root_order;
static unsigned int __read_mostly p2m_root_level;
#define P2M_ROOT_ORDER    p2m_root_order
#define P2M_ROOT_LEVEL p2m_root_level
static unsigned int __read_mostly max_vmid = MAX_VMID_8_BIT;
/* VMID is by default 8 bit width on AArch64 */
#define MAX_VMID       max_vmid
#else
/* First level P2M is alway 2 consecutive pages */
#define P2M_ROOT_LEVEL 1
#define P2M_ROOT_ORDER    1
/* VMID is always 8 bit width on AArch32 */
#define MAX_VMID        MAX_VMID_8_BIT
#endif

#define P2M_ROOT_PAGES    (1<<P2M_ROOT_ORDER)

unsigned int __read_mostly p2m_ipa_bits;

/* Helpers to lookup the properties of each level */
static const paddr_t level_masks[] =
    { ZEROETH_MASK, FIRST_MASK, SECOND_MASK, THIRD_MASK };
static const uint8_t level_orders[] =
    { ZEROETH_ORDER, FIRST_ORDER, SECOND_ORDER, THIRD_ORDER };

static mfn_t __read_mostly empty_root_mfn;

static uint64_t generate_vttbr(uint16_t vmid, mfn_t root_mfn)
{
    return (mfn_to_maddr(root_mfn) | ((uint64_t)vmid << 48));
}

/* Unlock the flush and do a P2M TLB flush if necessary */
void p2m_write_unlock(struct p2m_domain *p2m)
{
    /*
     * The final flush is done with the P2M write lock taken to avoid
     * someone else modifying the P2M wbefore the TLB invalidation has
     * completed.
     */
    p2m_tlb_flush_sync(p2m);

    write_unlock(&p2m->lock);
}

void p2m_dump_info(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    printk("dom%d IPA 0x%"PRIpaddr"\n", d->domain_id, addr);

    printk("P2M @ %p mfn:%#"PRI_mfn"\n",
           p2m->root, mfn_x(page_to_mfn(p2m->root)));

    dump_pt_walk(page_to_maddr(p2m->root), addr,
                 P2M_ROOT_LEVEL, P2M_ROOT_PAGES);
}

/*
 * p2m_save_state and p2m_restore_state work in pair to workaround
 * ARM64_WORKAROUND_AT_SPECULATE. p2m_save_state will set-up VTTBR to
 * point to the empty page-tables to stop allocating TLB entries.
 */
void p2m_save_state(struct vcpu *p)
{
    p->arch.sctlr = READ_SYSREG(SCTLR_EL1);

    if ( cpus_have_const_cap(ARM64_WORKAROUND_AT_SPECULATE) )
    {
        WRITE_SYSREG64(generate_vttbr(INVALID_VMID, empty_root_mfn), VTTBR_EL2);
        /*
         * Ensure VTTBR_EL2 is correctly synchronized so we can restore
         * the next vCPU context without worrying about AT instruction
         * speculation.
         */
        isb();
    }
}

void p2m_restore_state(struct vcpu *n)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(n->domain);
    uint8_t *last_vcpu_ran;

    if ( is_idle_vcpu(n) )
        return;

    WRITE_SYSREG(n->arch.sctlr, SCTLR_EL1);
    WRITE_SYSREG(n->arch.hcr_el2, HCR_EL2);

    /*
     * ARM64_WORKAROUND_AT_SPECULATE: VTTBR_EL2 should be restored after all
     * registers associated to EL1/EL0 translations regime have been
     * synchronized.
     */
    asm volatile(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_AT_SPECULATE));
    WRITE_SYSREG64(p2m->vttbr, VTTBR_EL2);

    last_vcpu_ran = &p2m->last_vcpu_ran[smp_processor_id()];

    /*
     * While we are restoring an out-of-context translation regime
     * we still need to ensure:
     *  - VTTBR_EL2 is synchronized before flushing the TLBs
     *  - All registers for EL1 are synchronized before executing an AT
     *  instructions targeting S1/S2.
     */
    isb();

    /*
     * Flush local TLB for the domain to prevent wrong TLB translation
     * when running multiple vCPU of the same domain on a single pCPU.
     */
    if ( *last_vcpu_ran != INVALID_VCPU_ID && *last_vcpu_ran != n->vcpu_id )
        flush_guest_tlb_local();

    *last_vcpu_ran = n->vcpu_id;
}

/*
 * Force a synchronous P2M TLB flush.
 *
 * Must be called with the p2m lock held.
 */
static void p2m_force_tlb_flush_sync(struct p2m_domain *p2m)
{
    unsigned long flags = 0;
    uint64_t ovttbr;

    ASSERT(p2m_is_write_locked(p2m));

    /*
     * ARM only provides an instruction to flush TLBs for the current
     * VMID. So switch to the VTTBR of a given P2M if different.
     */
    ovttbr = READ_SYSREG64(VTTBR_EL2);
    if ( ovttbr != p2m->vttbr )
    {
        uint64_t vttbr;

        local_irq_save(flags);

        /*
         * ARM64_WORKAROUND_AT_SPECULATE: We need to stop AT to allocate
         * TLBs entries because the context is partially modified. We
         * only need the VMID for flushing the TLBs, so we can generate
         * a new VTTBR with the VMID to flush and the empty root table.
         */
        if ( !cpus_have_const_cap(ARM64_WORKAROUND_AT_SPECULATE) )
            vttbr = p2m->vttbr;
        else
            vttbr = generate_vttbr(p2m->vmid, empty_root_mfn);

        WRITE_SYSREG64(vttbr, VTTBR_EL2);

        /* Ensure VTTBR_EL2 is synchronized before flushing the TLBs */
        isb();
    }

    flush_guest_tlb();

    if ( ovttbr != READ_SYSREG64(VTTBR_EL2) )
    {
        WRITE_SYSREG64(ovttbr, VTTBR_EL2);
        /* Ensure VTTBR_EL2 is back in place before continuing. */
        isb();
        local_irq_restore(flags);
    }

    p2m->need_flush = false;
}

void p2m_tlb_flush_sync(struct p2m_domain *p2m)
{
    if ( p2m->need_flush )
        p2m_force_tlb_flush_sync(p2m);
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

/*
 * In the case of the P2M, the valid bit is used for other purpose. Use
 * the type to check whether an entry is valid.
 */
static inline bool p2m_is_valid(lpae_t pte)
{
    return pte.p2m.type != p2m_invalid;
}

/*
 * lpae_is_* helpers don't check whether the valid bit is set in the
 * PTE. Provide our own overlay to check the valid bit.
 */
static inline bool p2m_is_mapping(lpae_t pte, unsigned int level)
{
    return p2m_is_valid(pte) && lpae_is_mapping(pte, level);
}

static inline bool p2m_is_superpage(lpae_t pte, unsigned int level)
{
    return p2m_is_valid(pte) && lpae_is_superpage(pte, level);
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
                          unsigned int level, lpae_t **table,
                          unsigned int offset)
{
    lpae_t *entry;
    int ret;
    mfn_t mfn;

    entry = *table + offset;

    if ( !p2m_is_valid(*entry) )
    {
        if ( read_only )
            return GUEST_TABLE_MAP_FAILED;

        ret = p2m_create_table(p2m, entry);
        if ( ret )
            return GUEST_TABLE_MAP_FAILED;
    }

    /* The function p2m_next_level is never called at the 3rd level */
    ASSERT(level < 3);
    if ( p2m_is_mapping(*entry, level) )
        return GUEST_TABLE_SUPER_PAGE;

    mfn = lpae_get_mfn(*entry);

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
 *
 * valid will contain the value of bit[0] (e.g valid bit) of the
 * entry.
 */
mfn_t p2m_get_entry(struct p2m_domain *p2m, gfn_t gfn,
                    p2m_type_t *t, p2m_access_t *a,
                    unsigned int *page_order,
                    bool *valid)
{
    paddr_t addr = gfn_to_gaddr(gfn);
    unsigned int level = 0;
    lpae_t entry, *table;
    int rc;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t _t;
    DECLARE_OFFSETS(offsets, addr);

    ASSERT(p2m_is_locked(p2m));
    BUILD_BUG_ON(THIRD_MASK != PAGE_MASK);

    /* Allow t to be NULL */
    t = t ?: &_t;

    *t = p2m_invalid;

    if ( valid )
        *valid = false;

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
        rc = p2m_next_level(p2m, true, level, &table, offsets[level]);
        if ( rc == GUEST_TABLE_MAP_FAILED )
            goto out_unmap;
        else if ( rc != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    entry = table[offsets[level]];

    if ( p2m_is_valid(entry) )
    {
        *t = entry.p2m.type;

        if ( a )
            *a = p2m_mem_access_radix_get(p2m, gfn);

        mfn = lpae_get_mfn(entry);
        /*
         * The entry may point to a superpage. Find the MFN associated
         * to the GFN.
         */
        mfn = mfn_add(mfn, gfn_x(gfn) & ((1UL << level_orders[level]) - 1));

        if ( valid )
            *valid = lpae_is_valid(entry);
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
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_read_lock(p2m);
    mfn = p2m_get_entry(p2m, gfn, t, NULL, NULL, NULL);
    p2m_read_unlock(p2m);

    return mfn;
}

struct page_info *p2m_get_page_from_gfn(struct domain *d, gfn_t gfn,
                                        p2m_type_t *t)
{
    struct page_info *page;
    p2m_type_t p2mt;
    mfn_t mfn = p2m_lookup(d, gfn, &p2mt);

    if ( t )
        *t = p2mt;

    if ( !p2m_is_any_ram(p2mt) )
        return NULL;

    if ( !mfn_valid(mfn) )
        return NULL;

    page = mfn_to_page(mfn);

    /*
     * get_page won't work on foreign mapping because the page doesn't
     * belong to the current domain.
     */
    if ( p2m_is_foreign(p2mt) )
    {
        struct domain *fdom = page_get_owner_and_reference(page);
        ASSERT(fdom != NULL);
        ASSERT(fdom != d);
        return page;
    }

    return get_page(page, d) ? page : NULL;
}

int guest_physmap_mark_populate_on_demand(struct domain *d,
                                          unsigned long gfn,
                                          unsigned int order)
{
    return -ENOSYS;
}

unsigned long p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn,
                                           unsigned int order)
{
    return 0;
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
    case p2m_map_foreign_rw:
    case p2m_grant_map_rw:
    case p2m_mmio_direct_dev:
    case p2m_mmio_direct_nc:
    case p2m_mmio_direct_c:
        e->p2m.xn = 1;
        e->p2m.write = 1;
        break;

    case p2m_iommu_map_ro:
    case p2m_map_foreign_ro:
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

    ASSERT(!(mfn_to_maddr(mfn) & ~PADDR_MASK));

    lpae_set_mfn(e, mfn);

    return e;
}

/* Generate table entry with correct attributes. */
static lpae_t page_to_p2m_table(struct page_info *page)
{
    /*
     * The access value does not matter because the hardware will ignore
     * the permission fields for table entry.
     *
     * We use p2m_ram_rw so the entry has a valid type. This is important
     * for p2m_is_valid() to return valid on table entries.
     */
    return mfn_to_p2m_entry(page_to_mfn(page), p2m_ram_rw, p2m_access_rwx);
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

    ASSERT(!p2m_is_valid(*entry));

    page = alloc_domheap_page(NULL, 0);
    if ( page == NULL )
        return -ENOMEM;

    page_list_add(page, &p2m->pages);

    p = __map_domain_page(page);
    clear_page(p);

    if ( p2m->clean_pte )
        clean_dcache_va_range(p, PAGE_SIZE);

    unmap_domain_page(p);

    p2m_write_pte(entry, page_to_p2m_table(page), p2m->clean_pte);

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

/*
 * Put any references on the single 4K page referenced by pte.
 * TODO: Handle superpages, for now we only take special references for leaf
 * pages (specifically foreign ones, which can't be super mapped today).
 */
static void p2m_put_l3_page(const lpae_t pte)
{
    ASSERT(p2m_is_valid(pte));

    /*
     * TODO: Handle other p2m types
     *
     * It's safe to do the put_page here because page_alloc will
     * flush the TLBs if the page is reallocated before the end of
     * this loop.
     */
    if ( p2m_is_foreign(pte.p2m.type) )
    {
        mfn_t mfn = lpae_get_mfn(pte);

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
    if ( !p2m_is_valid(entry) )
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

    table = map_domain_page(lpae_get_mfn(entry));
    for ( i = 0; i < LPAE_ENTRIES; i++ )
        p2m_free_entry(p2m, *(table + i), level + 1);

    unmap_domain_page(table);

    /*
     * Make sure all the references in the TLB have been removed before
     * freing the intermediate page table.
     * XXX: Should we defer the free of the page table to avoid the
     * flush?
     */
    p2m_tlb_flush_sync(p2m);

    mfn = lpae_get_mfn(entry);
    ASSERT(mfn_valid(mfn));

    pg = mfn_to_page(mfn);

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
    mfn_t mfn = lpae_get_mfn(*entry);
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
        lpae_set_mfn(pte, mfn_add(mfn, i << level_order));

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

    /*
     * Even if we failed, we should install the newly allocated LPAE
     * entry. The caller will be in charge to free the sub-tree.
     */
    p2m_write_pte(entry, page_to_p2m_table(page), p2m->clean_pte);

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
    unsigned int level = 0;
    unsigned int target = 3 - (page_order / LPAE_SHIFT);
    lpae_t *entry, *table, orig_pte;
    int rc;
    /* A mapping is removed if the MFN is invalid. */
    bool removing_mapping = mfn_eq(smfn, INVALID_MFN);
    DECLARE_OFFSETS(offsets, gfn_to_gaddr(sgfn));

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
         * is about to be removed.
         */
        rc = p2m_next_level(p2m, removing_mapping,
                            level, &table, offsets[level]);
        if ( rc == GUEST_TABLE_MAP_FAILED )
        {
            /*
             * We are here because p2m_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and they p2m tree is read-only). It is a valid case
             * when removing a mapping as it may not exist in the
             * page table. In this case, just ignore it.
             */
            rc = removing_mapping ?  0 : -ENOENT;
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
        p2m_force_tlb_flush_sync(p2m);

        p2m_write_pte(entry, split_pte, p2m->clean_pte);

        /* then move to the level we want to make real changes */
        for ( ; level < target; level++ )
        {
            rc = p2m_next_level(p2m, true, level, &table, offsets[level]);

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
    if ( lpae_is_valid(orig_pte) )
        p2m_remove_pte(entry, p2m->clean_pte);

    if ( removing_mapping )
        /* Flush can be deferred if the entry is removed */
        p2m->need_flush |= !!lpae_is_valid(orig_pte);
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
        if ( lpae_is_valid(orig_pte) )
        {
            if ( likely(!p2m->mem_access_enabled) ||
                 P2M_CLEAR_PERM(pte) != P2M_CLEAR_PERM(orig_pte) )
                p2m_force_tlb_flush_sync(p2m);
            else
                p2m->need_flush = true;
        }
        else if ( !p2m_is_valid(orig_pte) ) /* new mapping */
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
    if ( p2m_is_valid(orig_pte) &&
         !mfn_eq(lpae_get_mfn(*entry), lpae_get_mfn(orig_pte)) )
        p2m_free_entry(p2m, orig_pte, level);

    if ( is_iommu_enabled(p2m->domain) &&
         (lpae_is_valid(orig_pte) || lpae_is_valid(*entry)) )
    {
        unsigned int flush_flags = 0;

        if ( lpae_is_valid(orig_pte) )
            flush_flags |= IOMMU_FLUSHF_modified;
        if ( lpae_is_valid(*entry) )
            flush_flags |= IOMMU_FLUSHF_added;

        rc = iommu_iotlb_flush(p2m->domain, _dfn(gfn_x(sgfn)),
                               1UL << page_order, flush_flags);
    }
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

/* Invalidate all entries in the table. The p2m should be write locked. */
static void p2m_invalidate_table(struct p2m_domain *p2m, mfn_t mfn)
{
    lpae_t *table;
    unsigned int i;

    ASSERT(p2m_is_write_locked(p2m));

    table = map_domain_page(mfn);

    for ( i = 0; i < LPAE_ENTRIES; i++ )
    {
        lpae_t pte = table[i];

        /*
         * Writing an entry can be expensive because it may involve
         * cleaning the cache. So avoid updating the entry if the valid
         * bit is already cleared.
         */
        if ( !pte.p2m.valid )
            continue;

        pte.p2m.valid = 0;

        p2m_write_pte(&table[i], pte, p2m->clean_pte);
    }

    unmap_domain_page(table);

    p2m->need_flush = true;
}

/*
 * Invalidate all entries in the root page-tables. This is
 * useful to get fault on entry and do an action.
 */
void p2m_invalidate_root(struct p2m_domain *p2m)
{
    unsigned int i;

    p2m_write_lock(p2m);

    for ( i = 0; i < P2M_ROOT_LEVEL; i++ )
        p2m_invalidate_table(p2m, page_to_mfn(p2m->root + i));

    p2m_write_unlock(p2m);
}

/*
 * Resolve any translation fault due to change in the p2m. This
 * includes break-before-make and valid bit cleared.
 */
bool p2m_resolve_translation_fault(struct domain *d, gfn_t gfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned int level = 0;
    bool resolved = false;
    lpae_t entry, *table;

    /* Convenience aliases */
    DECLARE_OFFSETS(offsets, gfn_to_gaddr(gfn));

    p2m_write_lock(p2m);

    /* This gfn is higher than the highest the p2m map currently holds */
    if ( gfn_x(gfn) > gfn_x(p2m->max_mapped_gfn) )
        goto out;

    table = p2m_get_root_pointer(p2m, gfn);
    /*
     * The table should always be non-NULL because the gfn is below
     * p2m->max_mapped_gfn and the root table pages are always present.
     */
    BUG_ON(table == NULL);

    /*
     * Go down the page-tables until an entry has the valid bit unset or
     * a block/page entry has been hit.
     */
    for ( level = P2M_ROOT_LEVEL; level <= 3; level++ )
    {
        int rc;

        entry = table[offsets[level]];

        if ( level == 3 )
            break;

        /* Stop as soon as we hit an entry with the valid bit unset. */
        if ( !lpae_is_valid(entry) )
            break;

        rc = p2m_next_level(p2m, true, level, &table, offsets[level]);
        if ( rc == GUEST_TABLE_MAP_FAILED )
            goto out_unmap;
        else if ( rc != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    /*
     * If the valid bit of the entry is set, it means someone was playing with
     * the Stage-2 page table. Nothing to do and mark the fault as resolved.
     */
    if ( lpae_is_valid(entry) )
    {
        resolved = true;
        goto out_unmap;
    }

    /*
     * The valid bit is unset. If the entry is still not valid then the fault
     * cannot be resolved, exit and report it.
     */
    if ( !p2m_is_valid(entry) )
        goto out_unmap;

    /*
     * Now we have an entry with valid bit unset, but still valid from
     * the P2M point of view.
     *
     * If an entry is pointing to a table, each entry of the table will
     * have there valid bit cleared. This allows a function to clear the
     * full p2m with just a couple of write. The valid bit will then be
     * propagated on the fault.
     * If an entry is pointing to a block/page, no work to do for now.
     */
    if ( lpae_is_table(entry, level) )
        p2m_invalidate_table(p2m, lpae_get_mfn(entry));

    /*
     * Now that the work on the entry is done, set the valid bit to prevent
     * another fault on that entry.
     */
    resolved = true;
    entry.p2m.valid = 1;

    p2m_write_pte(table + offsets[level], entry, p2m->clean_pte);

    /*
     * No need to flush the TLBs as the modified entry had the valid bit
     * unset.
     */

out_unmap:
    unmap_domain_page(table);

out:
    p2m_write_unlock(p2m);

    return resolved;
}

static inline int p2m_insert_mapping(struct domain *d,
                                     gfn_t start_gfn,
                                     unsigned long nr,
                                     mfn_t mfn,
                                     p2m_type_t t)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
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

static struct page_info *p2m_allocate_root(void)
{
    struct page_info *page;
    unsigned int i;

    page = alloc_domheap_pages(NULL, P2M_ROOT_ORDER, 0);
    if ( page == NULL )
        return NULL;

    /* Clear both first level pages */
    for ( i = 0; i < P2M_ROOT_PAGES; i++ )
        clear_and_clean_page(page + i);

    return page;
}

static int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m->root = p2m_allocate_root();
    if ( !p2m->root )
        return -ENOMEM;

    p2m->vttbr = generate_vttbr(p2m->vmid, page_to_mfn(p2m->root));

    /*
     * Make sure that all TLBs corresponding to the new VMID are flushed
     * before using it
     */
    p2m_write_lock(p2m);
    p2m_force_tlb_flush_sync(p2m);
    p2m_write_unlock(p2m);

    return 0;
}


static spinlock_t vmid_alloc_lock = SPIN_LOCK_UNLOCKED;

/*
 * VTTBR_EL2 VMID field is 8 or 16 bits. AArch64 may support 16-bit VMID.
 * Using a bitmap here limits us to 256 or 65536 (for AArch64) concurrent
 * domains. The bitmap space will be allocated dynamically based on
 * whether 8 or 16 bit VMIDs are supported.
 */
static unsigned long *vmid_mask;

static void p2m_vmid_allocator_init(void)
{
    /*
     * allocate space for vmid_mask based on MAX_VMID
     */
    vmid_mask = xzalloc_array(unsigned long, BITS_TO_LONGS(MAX_VMID));

    if ( !vmid_mask )
        panic("Could not allocate VMID bitmap space\n");

    set_bit(INVALID_VMID, vmid_mask);
}

static int p2m_alloc_vmid(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    spin_lock(&vmid_alloc_lock);
    if ( p2m->vmid != INVALID_VMID )
        clear_bit(p2m->vmid, vmid_mask);

    spin_unlock(&vmid_alloc_lock);
}

void p2m_teardown(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
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
    p2m->clean_pte = is_iommu_enabled(d) &&
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
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
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
        mfn_t mfn = p2m_get_entry(p2m, start, &t, NULL, &order, NULL);

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

int p2m_cache_flush_range(struct domain *d, gfn_t *pstart, gfn_t end)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    gfn_t next_block_gfn;
    gfn_t start = *pstart;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t t;
    unsigned int order;
    int rc = 0;
    /* Counter for preemption */
    unsigned short count = 0;

    /*
     * The operation cache flush will invalidate the RAM assigned to the
     * guest in a given range. It will not modify the page table and
     * flushing the cache whilst the page is used by another CPU is
     * fine. So using read-lock is fine here.
     */
    p2m_read_lock(p2m);

    start = gfn_max(start, p2m->lowest_mapped_gfn);
    end = gfn_min(end, p2m->max_mapped_gfn);

    next_block_gfn = start;

    while ( gfn_x(start) < gfn_x(end) )
    {
       /*
         * Cleaning the cache for the P2M may take a long time. So we
         * need to be able to preempt. We will arbitrarily preempt every
         * time count reach 512 or above.
         *
         * The count will be incremented by:
         *  - 1 on region skipped
         *  - 10 for each page requiring a flush
         */
        if ( count >= 512 )
        {
            if ( softirq_pending(smp_processor_id()) )
            {
                rc = -ERESTART;
                break;
            }
            count = 0;
        }

        /*
         * We want to flush page by page as:
         *  - it may not be possible to map the full block (can be up to 1GB)
         *    in Xen memory
         *  - we may want to do fine grain preemption as flushing multiple
         *    page in one go may take a long time
         *
         * As p2m_get_entry is able to return the size of the mapping
         * in the p2m, it is pointless to execute it for each page.
         *
         * We can optimize it by tracking the gfn of the next
         * block. So we will only call p2m_get_entry for each block (can
         * be up to 1GB).
         */
        if ( gfn_eq(start, next_block_gfn) )
        {
            bool valid;

            mfn = p2m_get_entry(p2m, start, &t, NULL, &order, &valid);
            next_block_gfn = gfn_next_boundary(start, order);

            if ( mfn_eq(mfn, INVALID_MFN) || !p2m_is_any_ram(t) || !valid )
            {
                count++;
                start = next_block_gfn;
                continue;
            }
        }

        count += 10;

        flush_page_to_ram(mfn_x(mfn), false);

        start = gfn_add(start, 1);
        mfn = mfn_add(mfn, 1);
    }

    if ( rc != -ERESTART )
        invalidate_icache();

    p2m_read_unlock(p2m);

    *pstart = start;

    return rc;
}

/*
 * Clean & invalidate RAM associated to the guest vCPU.
 *
 * The function can only work with the current vCPU and should be called
 * with IRQ enabled as the vCPU could get preempted.
 */
void p2m_flush_vm(struct vcpu *v)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);
    int rc;
    gfn_t start = _gfn(0);

    ASSERT(v == current);
    ASSERT(local_irq_is_enabled());
    ASSERT(v->arch.need_flush_to_ram);

    do
    {
        rc = p2m_cache_flush_range(v->domain, &start, _gfn(ULONG_MAX));
        if ( rc == -ERESTART )
            do_softirq();
    } while ( rc == -ERESTART );

    if ( rc != 0 )
        gprintk(XENLOG_WARNING,
                "P2M has not been correctly cleaned (rc = %d)\n",
                rc);

    /*
     * Invalidate the p2m to track which page was modified by the guest
     * between call of p2m_flush_vm().
     */
    p2m_invalidate_root(p2m);

    v->arch.need_flush_to_ram = false;
}

/*
 * See note at ARMv7 ARM B1.14.4 (DDI 0406C.c) (TL;DR: S/W ops are not
 * easily virtualized).
 *
 * Main problems:
 *  - S/W ops are local to a CPU (not broadcast)
 *  - We have line migration behind our back (speculation)
 *  - System caches don't support S/W at all (damn!)
 *
 * In the face of the above, the best we can do is to try and convert
 * S/W ops to VA ops. Because the guest is not allowed to infer the S/W
 * to PA mapping, it can only use S/W to nuke the whole cache, which is
 * rather a good thing for us.
 *
 * Also, it is only used when turning caches on/off ("The expected
 * usage of the cache maintenance instructions that operate by set/way
 * is associated with the powerdown and powerup of caches, if this is
 * required by the implementation.").
 *
 * We use the following policy:
 *  - If we trap a S/W operation, we enabled VM trapping to detect
 *  caches being turned on/off, and do a full clean.
 *
 *  - We flush the caches on both caches being turned on and off.
 *
 *  - Once the caches are enabled, we stop trapping VM ops.
 */
void p2m_set_way_flush(struct vcpu *v)
{
    /* This function can only work with the current vCPU. */
    ASSERT(v == current);

    if ( !(v->arch.hcr_el2 & HCR_TVM) )
    {
        v->arch.need_flush_to_ram = true;
        vcpu_hcr_set_flags(v, HCR_TVM);
    }
}

void p2m_toggle_cache(struct vcpu *v, bool was_enabled)
{
    bool now_enabled = vcpu_has_cache_enabled(v);

    /* This function can only work with the current vCPU. */
    ASSERT(v == current);

    /*
     * If switching the MMU+caches on, need to invalidate the caches.
     * If switching it off, need to clean the caches.
     * Clean + invalidate does the trick always.
     */
    if ( was_enabled != now_enabled )
        v->arch.need_flush_to_ram = true;

    /* Caches are now on, stop trapping VM ops (until a S/W op) */
    if ( now_enabled )
        vcpu_hcr_clear_flags(v, HCR_TVM);
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    return p2m_lookup(d, gfn, NULL);
}

struct page_info *get_page_from_gva(struct vcpu *v, vaddr_t va,
                                    unsigned long flags)
{
    struct domain *d = v->domain;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *page = NULL;
    paddr_t maddr = 0;
    uint64_t par;
    mfn_t mfn;
    p2m_type_t t;

    /*
     * XXX: To support a different vCPU, we would need to load the
     * VTTBR_EL2, TTBR0_EL1, TTBR1_EL1 and SCTLR_EL1
     */
    if ( v != current )
        return NULL;

    /*
     * The lock is here to protect us against the break-before-make
     * sequence used when updating the entry.
     */
    p2m_read_lock(p2m);
    par = gvirt_to_maddr(va, &maddr, flags);
    p2m_read_unlock(p2m);

    /*
     * gvirt_to_maddr may fail if the entry does not have the valid bit
     * set. Fallback to the second method:
     *  1) Translate the VA to IPA using software lookup -> Stage-1 page-table
     *  may not be accessible because the stage-2 entries may have valid
     *  bit unset.
     *  2) Software lookup of the MFN
     *
     * Note that when memaccess is enabled, we instead call directly
     * p2m_mem_access_check_and_get_page(...). Because the function is a
     * a variant of the methods described above, it will be able to
     * handle entries with valid bit unset.
     *
     * TODO: Integrate more nicely memaccess with the rest of the
     * function.
     * TODO: Use the fault error in PAR_EL1 to avoid pointless
     *  translation.
     */
    if ( par )
    {
        paddr_t ipa;
        unsigned int s1_perms;

        /*
         * When memaccess is enabled, the translation GVA to MADDR may
         * have failed because of a permission fault.
         */
        if ( p2m->mem_access_enabled )
            return p2m_mem_access_check_and_get_page(va, flags, v);

        /*
         * The software stage-1 table walk can still fail, e.g, if the
         * GVA is not mapped.
         */
        if ( !guest_walk_tables(v, va, &ipa, &s1_perms) )
        {
            dprintk(XENLOG_G_DEBUG,
                    "%pv: Failed to walk page-table va %#"PRIvaddr"\n", v, va);
            return NULL;
        }

        mfn = p2m_lookup(d, gaddr_to_gfn(ipa), &t);
        if ( mfn_eq(INVALID_MFN, mfn) || !p2m_is_ram(t) )
            return NULL;

        /*
         * Check permission that are assumed by the caller. For instance
         * in case of guestcopy, the caller assumes that the translated
         * page can be accessed with the requested permissions. If this
         * is not the case, we should fail.
         *
         * Please note that we do not check for the GV2M_EXEC
         * permission. This is fine because the hardware-based translation
         * instruction does not test for execute permissions.
         */
        if ( (flags & GV2M_WRITE) && !(s1_perms & GV2M_WRITE) )
            return NULL;

        if ( (flags & GV2M_WRITE) && t != p2m_ram_rw )
            return NULL;
    }
    else
        mfn = maddr_to_mfn(maddr);

    if ( !mfn_valid(mfn) )
    {
        dprintk(XENLOG_G_DEBUG, "%pv: Invalid MFN %#"PRI_mfn"\n",
                v, mfn_x(mfn));
        return NULL;
    }

    page = mfn_to_page(mfn);
    ASSERT(page);

    if ( unlikely(!get_page(page, d)) )
    {
        dprintk(XENLOG_G_DEBUG, "%pv: Failing to acquire the MFN %#"PRI_mfn"\n",
                v, mfn_x(maddr_to_mfn(maddr)));
        return NULL;
    }

    return page;
}

/* VTCR value to be configured by all CPUs. Set only once by the boot CPU */
static uint32_t __read_mostly vtcr;

static void setup_virt_paging_one(void *data)
{
    WRITE_SYSREG32(vtcr, VTCR_EL2);

    /*
     * ARM64_WORKAROUND_AT_SPECULATE: We want to keep the TLBs free from
     * entries related to EL1/EL0 translation regime until a guest vCPU
     * is running. For that, we need to set-up VTTBR to point to an empty
     * page-table and turn on stage-2 translation. The TLB entries
     * associated with EL1/EL0 translation regime will also be flushed in case
     * an AT instruction was speculated before hand.
     */
    if ( cpus_have_cap(ARM64_WORKAROUND_AT_SPECULATE) )
    {
        WRITE_SYSREG64(generate_vttbr(INVALID_VMID, empty_root_mfn), VTTBR_EL2);
        WRITE_SYSREG(READ_SYSREG(HCR_EL2) | HCR_VM, HCR_EL2);
        isb();

        flush_all_guests_tlb_local();
    }
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
        [3] = { 42,      22/*22*/,  3,          1 },
        [4] = { 44,      20/*20*/,  0,          2 },
        [5] = { 48,      16/*16*/,  0,          2 },
        [6] = { 0 }, /* Invalid */
        [7] = { 0 }  /* Invalid */
    };

    unsigned int cpu;
    unsigned int pa_range = 0x10; /* Larger than any possible value */
    bool vmid_8_bit = false;

    for_each_online_cpu ( cpu )
    {
        const struct cpuinfo_arm *info = &cpu_data[cpu];
        if ( info->mm64.pa_range < pa_range )
            pa_range = info->mm64.pa_range;

        /* Set a flag if the current cpu does not support 16 bit VMIDs. */
        if ( info->mm64.vmid_bits != MM64_VMID_16_BITS_SUPPORT )
            vmid_8_bit = true;
    }

    /*
     * If the flag is not set then it means all CPUs support 16-bit
     * VMIDs.
     */
    if ( !vmid_8_bit )
        max_vmid = MAX_VMID_16_BIT;

    /* pa_range is 4 bits, but the defined encodings are only 3 bits */
    if ( pa_range >= ARRAY_SIZE(pa_range_info) || !pa_range_info[pa_range].pabits )
        panic("Unknown encoding of ID_AA64MMFR0_EL1.PARange %x\n", pa_range);

    val |= VTCR_PS(pa_range);
    val |= VTCR_TG0_4K;

    /* Set the VS bit only if 16 bit VMID is supported. */
    if ( MAX_VMID == MAX_VMID_16_BIT )
        val |= VTCR_VS;
    val |= VTCR_SL0(pa_range_info[pa_range].sl0);
    val |= VTCR_T0SZ(pa_range_info[pa_range].t0sz);

    p2m_root_order = pa_range_info[pa_range].root_order;
    p2m_root_level = 2 - pa_range_info[pa_range].sl0;
    p2m_ipa_bits = 64 - pa_range_info[pa_range].t0sz;

    printk("P2M: %d-bit IPA with %d-bit PA and %d-bit VMID\n",
           p2m_ipa_bits,
           pa_range_info[pa_range].pabits,
           ( MAX_VMID == MAX_VMID_16_BIT ) ? 16 : 8);
#endif
    printk("P2M: %d levels with order-%d root, VTCR 0x%lx\n",
           4 - P2M_ROOT_LEVEL, P2M_ROOT_ORDER, val);

    p2m_vmid_allocator_init();

    /* It is not allowed to concatenate a level zero root */
    BUG_ON( P2M_ROOT_LEVEL == 0 && P2M_ROOT_ORDER > 0 );
    vtcr = val;

    /*
     * ARM64_WORKAROUND_AT_SPECULATE requires to allocate root table
     * with all entries zeroed.
     */
    if ( cpus_have_cap(ARM64_WORKAROUND_AT_SPECULATE) )
    {
        struct page_info *root;

        root = p2m_allocate_root();
        if ( !root )
            panic("Unable to allocate root table for ARM64_WORKAROUND_AT_SPECULATE\n");

        empty_root_mfn = page_to_mfn(root);
    }

    setup_virt_paging_one(NULL);
    smp_call_function(setup_virt_paging_one, NULL, 1);
}

static int cpu_virt_paging_callback(struct notifier_block *nfb,
                                    unsigned long action,
                                    void *hcpu)
{
    switch ( action )
    {
    case CPU_STARTING:
        ASSERT(system_state != SYS_STATE_boot);
        setup_virt_paging_one(NULL);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_virt_paging_nfb = {
    .notifier_call = cpu_virt_paging_callback,
};

static int __init cpu_virt_paging_init(void)
{
    register_cpu_notifier(&cpu_virt_paging_nfb);

    return 0;
}
/*
 * Initialization of the notifier has to be done at init rather than presmp_init
 * phase because: the registered notifier is used to setup virtual paging for
 * non-boot CPUs after the initial virtual paging for all CPUs is already setup,
 * i.e. when a non-boot CPU is hotplugged after the system has booted. In other
 * words, the notifier should be registered after the virtual paging is
 * initially setup (setup_virt_paging() is called from start_xen()). This is
 * required because vtcr config value has to be set before a notifier can fire.
 */
__initcall(cpu_virt_paging_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
