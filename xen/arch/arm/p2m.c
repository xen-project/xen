#include <xen/config.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/stdbool.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <xen/bitops.h>
#include <asm/flushtlb.h>
#include <asm/gic.h>
#include <asm/event.h>
#include <asm/hardirq.h>
#include <asm/page.h>

/* First level P2M is 2 consecutive pages */
#define P2M_FIRST_ORDER 1
#define P2M_FIRST_ENTRIES (LPAE_ENTRIES<<P2M_FIRST_ORDER)

static bool_t p2m_valid(lpae_t pte)
{
    return pte.p2m.valid;
}
/* These two can only be used on L0..L2 ptes because L3 mappings set
 * the table bit and therefore these would return the opposite to what
 * you would expect. */
static bool_t p2m_table(lpae_t pte)
{
    return p2m_valid(pte) && pte.p2m.table;
}
static bool_t p2m_mapping(lpae_t pte)
{
    return p2m_valid(pte) && !pte.p2m.table;
}

void p2m_dump_info(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    spin_lock(&p2m->lock);
    printk("p2m mappings for domain %d (vmid %d):\n",
           d->domain_id, p2m->vmid);
    BUG_ON(p2m->stats.mappings[0] || p2m->stats.shattered[0]);
    printk("  1G mappings: %ld (shattered %ld)\n",
           p2m->stats.mappings[1], p2m->stats.shattered[1]);
    printk("  2M mappings: %ld (shattered %ld)\n",
           p2m->stats.mappings[2], p2m->stats.shattered[2]);
    printk("  4K mappings: %ld\n", p2m->stats.mappings[3]);
    spin_unlock(&p2m->lock);
}

void memory_type_changed(struct domain *d)
{
}

void dump_p2m_lookup(struct domain *d, paddr_t addr)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t *first;

    printk("dom%d IPA 0x%"PRIpaddr"\n", d->domain_id, addr);

    if ( first_linear_offset(addr) > LPAE_ENTRIES )
    {
        printk("Cannot dump addresses in second of first level pages...\n");
        return;
    }

    printk("P2M @ %p mfn:0x%lx\n",
           p2m->first_level, page_to_mfn(p2m->first_level));

    first = __map_domain_page(p2m->first_level);
    dump_pt_walk(first, addr);
    unmap_domain_page(first);
}

static void p2m_load_VTTBR(struct domain *d)
{
    if ( is_idle_domain(d) )
        return;
    BUG_ON(!d->arch.vttbr);
    WRITE_SYSREG64(d->arch.vttbr, VTTBR_EL2);
    isb(); /* Ensure update is visible */
}

void p2m_save_state(struct vcpu *p)
{
    p->arch.sctlr = READ_SYSREG(SCTLR_EL1);
}

void p2m_restore_state(struct vcpu *n)
{
    register_t hcr;

    hcr = READ_SYSREG(HCR_EL2);
    WRITE_SYSREG(hcr & ~HCR_VM, HCR_EL2);
    isb();

    p2m_load_VTTBR(n->domain);
    isb();

    if ( is_32bit_domain(n->domain) )
        hcr &= ~HCR_RW;
    else
        hcr |= HCR_RW;

    WRITE_SYSREG(n->arch.sctlr, SCTLR_EL1);
    isb();

    WRITE_SYSREG(hcr, HCR_EL2);
    isb();
}

void flush_tlb_domain(struct domain *d)
{
    /* Update the VTTBR if necessary with the domain d. In this case,
     * it's only necessary to flush TLBs on every CPUs with the current VMID
     * (our domain).
     */
    if ( d != current->domain )
        p2m_load_VTTBR(d);

    flush_tlb();

    if ( d != current->domain )
        p2m_load_VTTBR(current->domain);
}

static int p2m_first_level_index(paddr_t addr)
{
    /*
     * 1st pages are concatenated so zeroeth offset gives us the
     * index of the 1st page
     */
    return zeroeth_table_offset(addr);
}

/*
 * Map whichever of the first pages contain addr. The caller should
 * then use first_table_offset as an index.
 */
static lpae_t *p2m_map_first(struct p2m_domain *p2m, paddr_t addr)
{
    struct page_info *page;

    if ( first_linear_offset(addr) >= P2M_FIRST_ENTRIES )
        return NULL;

    page = p2m->first_level + p2m_first_level_index(addr);

    return __map_domain_page(page);
}

/*
 * Lookup the MFN corresponding to a domain's PFN.
 *
 * There are no processor functions to do a stage 2 only lookup therefore we
 * do a a software walk.
 */
paddr_t p2m_lookup(struct domain *d, paddr_t paddr, p2m_type_t *t)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t pte, *first = NULL, *second = NULL, *third = NULL;
    paddr_t maddr = INVALID_PADDR;
    paddr_t mask;
    p2m_type_t _t;

    /* Allow t to be NULL */
    t = t ?: &_t;

    *t = p2m_invalid;

    spin_lock(&p2m->lock);

    first = p2m_map_first(p2m, paddr);
    if ( !first )
        goto err;

    mask = FIRST_MASK;
    pte = first[first_table_offset(paddr)];
    if ( !p2m_table(pte) )
        goto done;

    mask = SECOND_MASK;
    second = map_domain_page(pte.p2m.base);
    pte = second[second_table_offset(paddr)];
    if ( !p2m_table(pte) )
        goto done;

    mask = THIRD_MASK;

    BUILD_BUG_ON(THIRD_MASK != PAGE_MASK);

    third = map_domain_page(pte.p2m.base);
    pte = third[third_table_offset(paddr)];

    /* This bit must be one in the level 3 entry */
    if ( !p2m_table(pte) )
        pte.bits = 0;

done:
    if ( p2m_valid(pte) )
    {
        ASSERT(pte.p2m.type != p2m_invalid);
        maddr = (pte.bits & PADDR_MASK & mask) | (paddr & ~mask);
        *t = pte.p2m.type;
    }

    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);

err:
    spin_unlock(&p2m->lock);

    return maddr;
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

static lpae_t mfn_to_p2m_entry(unsigned long mfn, unsigned int mattr,
                               p2m_type_t t)
{
    paddr_t pa = ((paddr_t) mfn) << PAGE_SHIFT;
    /* sh, xn and write bit will be defined in the following switches
     * based on mattr and t. */
    lpae_t e = (lpae_t) {
        .p2m.af = 1,
        .p2m.read = 1,
        .p2m.mattr = mattr,
        .p2m.table = 1,
        .p2m.valid = 1,
        .p2m.type = t,
    };

    BUILD_BUG_ON(p2m_max_real_type > (1 << 4));

    switch (mattr)
    {
    case MATTR_MEM:
        e.p2m.sh = LPAE_SH_INNER;
        break;

    case MATTR_DEV:
        e.p2m.sh = LPAE_SH_OUTER;
        break;
    default:
        BUG();
        break;
    }

    switch (t)
    {
    case p2m_ram_rw:
        e.p2m.xn = 0;
        e.p2m.write = 1;
        break;

    case p2m_ram_ro:
        e.p2m.xn = 0;
        e.p2m.write = 0;
        break;

    case p2m_iommu_map_rw:
    case p2m_map_foreign:
    case p2m_grant_map_rw:
    case p2m_mmio_direct:
        e.p2m.xn = 1;
        e.p2m.write = 1;
        break;

    case p2m_iommu_map_ro:
    case p2m_grant_map_ro:
    case p2m_invalid:
        e.p2m.xn = 1;
        e.p2m.write = 0;
        break;

    case p2m_max_real_type:
        BUG();
        break;
    }

    ASSERT(!(pa & ~PAGE_MASK));
    ASSERT(!(pa & ~PADDR_MASK));

    e.bits |= pa;

    return e;
}

static inline void p2m_write_pte(lpae_t *p, lpae_t pte, bool_t flush_cache)
{
    write_pte(p, pte);
    if ( flush_cache )
        clean_xen_dcache(*p);
}

/*
 * Allocate a new page table page and hook it in via the given entry.
 * apply_one_level relies on this returning 0 on success
 * and -ve on failure.
 *
 * If the existing entry is present then it must be a mapping and not
 * a table and it will be shattered into the next level down.
 *
 * level_shift is the number of bits at the level we want to create.
 */
static int p2m_create_table(struct domain *d, lpae_t *entry,
                            int level_shift, bool_t flush_cache)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    lpae_t *p;
    lpae_t pte;
    int splitting = p2m_valid(*entry);

    BUG_ON(p2m_table(*entry));

    page = alloc_domheap_page(NULL, 0);
    if ( page == NULL )
        return -ENOMEM;

    page_list_add(page, &p2m->pages);

    p = __map_domain_page(page);
    if ( splitting )
    {
        p2m_type_t t = entry->p2m.type;
        unsigned long base_pfn = entry->p2m.base;
        int i;

        /*
         * We are either splitting a first level 1G page into 512 second level
         * 2M pages, or a second level 2M page into 512 third level 4K pages.
         */
         for ( i=0 ; i < LPAE_ENTRIES; i++ )
         {
             pte = mfn_to_p2m_entry(base_pfn + (i<<(level_shift-LPAE_SHIFT)),
                                    MATTR_MEM, t);

             /*
              * First and second level super pages set p2m.table = 0, but
              * third level entries set table = 1.
              */
             if ( level_shift - LPAE_SHIFT )
                 pte.p2m.table = 0;

             write_pte(&p[i], pte);
         }
    }
    else
        clear_page(p);

    if ( flush_cache )
        clean_xen_dcache_va_range(p, PAGE_SIZE);

    unmap_domain_page(p);

    pte = mfn_to_p2m_entry(page_to_mfn(page), MATTR_MEM, p2m_invalid);

    p2m_write_pte(entry, pte, flush_cache);

    return 0;
}

enum p2m_operation {
    INSERT,
    ALLOCATE,
    REMOVE,
    RELINQUISH,
    CACHEFLUSH,
};

/* Put any references on the single 4K page referenced by pte.  TODO:
 * Handle superpages, for now we only take special references for leaf
 * pages (specifically foreign ones, which can't be super mapped today).
 */
static void p2m_put_l3_page(const lpae_t pte)
{
    ASSERT(p2m_valid(pte));

    /* TODO: Handle other p2m types
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

/*
 * Returns true if start_gpaddr..end_gpaddr contains at least one
 * suitably aligned level_size mappping of maddr.
 *
 * So long as the range is large enough the end_gpaddr need not be
 * aligned (callers should create one superpage mapping based on this
 * result and then call this again on the new range, eventually the
 * slop at the end will cause this function to return false).
 */
static bool_t is_mapping_aligned(const paddr_t start_gpaddr,
                                 const paddr_t end_gpaddr,
                                 const paddr_t maddr,
                                 const paddr_t level_size)
{
    const paddr_t level_mask = level_size - 1;

    /* No hardware superpages at level 0 */
    if ( level_size == ZEROETH_SIZE )
        return false;

    /*
     * A range smaller than the size of a superpage at this level
     * cannot be superpage aligned.
     */
    if ( ( end_gpaddr - start_gpaddr ) < level_size - 1 )
        return false;

    /* Both the gpaddr and maddr must be aligned */
    if ( start_gpaddr & level_mask )
        return false;
    if ( maddr & level_mask )
        return false;
    return true;
}

#define P2M_ONE_DESCEND        0
#define P2M_ONE_PROGRESS_NOP   0x1
#define P2M_ONE_PROGRESS       0x10

/* Helpers to lookup the properties of each level */
static const paddr_t level_sizes[] =
    { ZEROETH_SIZE, FIRST_SIZE, SECOND_SIZE, THIRD_SIZE };
static const paddr_t level_masks[] =
    { ZEROETH_MASK, FIRST_MASK, SECOND_MASK, THIRD_MASK };
static const paddr_t level_shifts[] =
    { ZEROETH_SHIFT, FIRST_SHIFT, SECOND_SHIFT, THIRD_SHIFT };

/*
 * 0   == (P2M_ONE_DESCEND) continue to descend the tree
 * +ve == (P2M_ONE_PROGRESS_*) handled at this level, continue, flush,
 *        entry, addr and maddr updated.  Return value is an
 *        indication of the amount of work done (for preemption).
 * -ve == (-Exxx) error.
 */
static int apply_one_level(struct domain *d,
                           lpae_t *entry,
                           unsigned int level,
                           bool_t flush_cache,
                           enum p2m_operation op,
                           paddr_t start_gpaddr,
                           paddr_t end_gpaddr,
                           paddr_t *addr,
                           paddr_t *maddr,
                           bool_t *flush,
                           int mattr,
                           p2m_type_t t)
{
    const paddr_t level_size = level_sizes[level];
    const paddr_t level_mask = level_masks[level];
    const paddr_t level_shift = level_shifts[level];

    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t pte;
    const lpae_t orig_pte = *entry;
    int rc;

    BUG_ON(level > 3);

    switch ( op )
    {
    case ALLOCATE:
        ASSERT(level < 3 || !p2m_valid(orig_pte));
        ASSERT(*maddr == 0);

        if ( p2m_valid(orig_pte) )
            return P2M_ONE_DESCEND;

        if ( is_mapping_aligned(*addr, end_gpaddr, 0, level_size) )
        {
            struct page_info *page;

            page = alloc_domheap_pages(d, level_shift - PAGE_SHIFT, 0);
            if ( page )
            {
                pte = mfn_to_p2m_entry(page_to_mfn(page), mattr, t);
                if ( level < 3 )
                    pte.p2m.table = 0;
                p2m_write_pte(entry, pte, flush_cache);
                p2m->stats.mappings[level]++;

                *addr += level_size;

                return P2M_ONE_PROGRESS;
            }
            else if ( level == 3 )
                return -ENOMEM;
        }

        /* L3 is always suitably aligned for mapping (handled, above) */
        BUG_ON(level == 3);

        /*
         * If we get here then we failed to allocate a sufficiently
         * large contiguous region for this level (which can't be
         * L3). Create a page table and continue to descend so we try
         * smaller allocations.
         */
        rc = p2m_create_table(d, entry, 0, flush_cache);
        if ( rc < 0 )
            return rc;

        return P2M_ONE_DESCEND;

    case INSERT:
        if ( is_mapping_aligned(*addr, end_gpaddr, *maddr, level_size) &&
           /* We do not handle replacing an existing table with a superpage */
             (level == 3 || !p2m_table(orig_pte)) )
        {
            /* New mapping is superpage aligned, make it */
            pte = mfn_to_p2m_entry(*maddr >> PAGE_SHIFT, mattr, t);
            if ( level < 3 )
                pte.p2m.table = 0; /* Superpage entry */

            p2m_write_pte(entry, pte, flush_cache);

            *flush |= p2m_valid(orig_pte);

            *addr += level_size;
            *maddr += level_size;

            if ( p2m_valid(orig_pte) )
            {
                /*
                 * We can't currently get here for an existing table
                 * mapping, since we don't handle replacing an
                 * existing table with a superpage. If we did we would
                 * need to handle freeing (and accounting) for the bit
                 * of the p2m tree which we would be about to lop off.
                 */
                BUG_ON(level < 3 && p2m_table(orig_pte));
                if ( level == 3 )
                    p2m_put_l3_page(orig_pte);
            }
            else /* New mapping */
                p2m->stats.mappings[level]++;

            return P2M_ONE_PROGRESS;
        }
        else
        {
            /* New mapping is not superpage aligned, create a new table entry */

            /* L3 is always suitably aligned for mapping (handled, above) */
            BUG_ON(level == 3);

            /* Not present -> create table entry and descend */
            if ( !p2m_valid(orig_pte) )
            {
                rc = p2m_create_table(d, entry, 0, flush_cache);
                if ( rc < 0 )
                    return rc;
                return P2M_ONE_DESCEND;
            }

            /* Existing superpage mapping -> shatter and descend */
            if ( p2m_mapping(orig_pte) )
            {
                *flush = true;
                rc = p2m_create_table(d, entry,
                                      level_shift - PAGE_SHIFT, flush_cache);
                if ( rc < 0 )
                    return rc;

                p2m->stats.shattered[level]++;
                p2m->stats.mappings[level]--;
                p2m->stats.mappings[level+1] += LPAE_ENTRIES;
            } /* else: an existing table mapping -> descend */

            BUG_ON(!p2m_table(*entry));

            return P2M_ONE_DESCEND;
        }

        break;

    case RELINQUISH:
    case REMOVE:
        if ( !p2m_valid(orig_pte) )
        {
            /* Progress up to next boundary */
            *addr = (*addr + level_size) & level_mask;
            *maddr = (*maddr + level_size) & level_mask;
            return P2M_ONE_PROGRESS_NOP;
        }

        if ( level < 3 )
        {
            if ( p2m_table(orig_pte) )
                return P2M_ONE_DESCEND;

            if ( op == REMOVE &&
                 !is_mapping_aligned(*addr, end_gpaddr,
                                     0, /* maddr doesn't matter for remove */
                                     level_size) )
            {
                /*
                 * Removing a mapping from the middle of a superpage. Shatter
                 * and descend.
                 */
                *flush = true;
                rc = p2m_create_table(d, entry,
                                      level_shift - PAGE_SHIFT, flush_cache);
                if ( rc < 0 )
                    return rc;

                p2m->stats.shattered[level]++;
                p2m->stats.mappings[level]--;
                p2m->stats.mappings[level+1] += LPAE_ENTRIES;

                return P2M_ONE_DESCEND;
            }
        }

        /*
         * Ensure that the guest address addr currently being
         * handled (that is in the range given as argument to
         * this function) is actually mapped to the corresponding
         * machine address in the specified range. maddr here is
         * the machine address given to the function, while
         * orig_pte.p2m.base is the machine frame number actually
         * mapped to the guest address: check if the two correspond.
         */
         if ( op == REMOVE &&
              pfn_to_paddr(orig_pte.p2m.base) != *maddr )
             printk(XENLOG_G_WARNING
                    "p2m_remove dom%d: mapping at %"PRIpaddr" is of maddr %"PRIpaddr" not %"PRIpaddr" as expected\n",
                    d->domain_id, *addr, pfn_to_paddr(orig_pte.p2m.base),
                    *maddr);

        *flush = true;

        memset(&pte, 0x00, sizeof(pte));
        p2m_write_pte(entry, pte, flush_cache);

        *addr += level_size;
        *maddr += level_size;

        p2m->stats.mappings[level]--;

        if ( level == 3 )
            p2m_put_l3_page(orig_pte);

        /*
         * This is still a single pte write, no matter the level, so no need to
         * scale.
         */
        return P2M_ONE_PROGRESS;

    case CACHEFLUSH:
        if ( !p2m_valid(orig_pte) )
        {
            *addr = (*addr + level_size) & level_mask;
            return P2M_ONE_PROGRESS_NOP;
        }

        if ( level < 3 && p2m_table(orig_pte) )
            return P2M_ONE_DESCEND;

        /*
         * could flush up to the next superpage boundary, but would
         * need to be careful about preemption, so just do one 4K page
         * now and return P2M_ONE_PROGRESS{,_NOP} so that the caller will
         * continue to loop over the rest of the range.
         */
        if ( p2m_is_ram(orig_pte.p2m.type) )
        {
            unsigned long offset = paddr_to_pfn(*addr & ~level_mask);
            flush_page_to_ram(orig_pte.p2m.base + offset);

            *addr += PAGE_SIZE;
            return P2M_ONE_PROGRESS;
        }
        else
        {
            *addr += PAGE_SIZE;
            return P2M_ONE_PROGRESS_NOP;
        }
    }

    BUG(); /* Should never get here */
}

static int apply_p2m_changes(struct domain *d,
                     enum p2m_operation op,
                     paddr_t start_gpaddr,
                     paddr_t end_gpaddr,
                     paddr_t maddr,
                     int mattr,
                     p2m_type_t t)
{
    int rc, ret;
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t *first = NULL, *second = NULL, *third = NULL;
    paddr_t addr, orig_maddr = maddr;
    unsigned int level = 0;
    unsigned long cur_first_page = ~0,
                  cur_first_offset = ~0,
                  cur_second_offset = ~0;
    unsigned long count = 0;
    bool_t flush = false;
    bool_t flush_pt;

    /* Some IOMMU don't support coherent PT walk. When the p2m is
     * shared with the CPU, Xen has to make sure that the PT changes have
     * reached the memory
     */
    flush_pt = iommu_enabled && !iommu_has_feature(d, IOMMU_FEAT_COHERENT_WALK);

    spin_lock(&p2m->lock);

    addr = start_gpaddr;
    while ( addr < end_gpaddr )
    {
        /*
         * Arbitrarily, preempt every 512 operations or 8192 nops.
         * 512*P2M_ONE_PROGRESS == 8192*P2M_ONE_PROGRESS_NOP == 0x2000
         *
         * count is initialised to 0 above, so we are guaranteed to
         * always make at least one pass.
         */

        if ( op == RELINQUISH && count >= 0x2000 )
        {
            if ( hypercall_preempt_check() )
            {
                p2m->lowest_mapped_gfn = addr >> PAGE_SHIFT;
                rc = -ERESTART;
                goto out;
            }
            count = 0;
        }

        if ( cur_first_page != p2m_first_level_index(addr) )
        {
            if ( first ) unmap_domain_page(first);
            first = p2m_map_first(p2m, addr);
            if ( !first )
            {
                rc = -EINVAL;
                goto out;
            }
            cur_first_page = p2m_first_level_index(addr);
            /* Any mapping further down is now invalid */
            cur_first_offset = cur_second_offset = ~0;
        }

        /* We only use a 3 level p2m at the moment, so no level 0,
         * current hardware doesn't support super page mappings at
         * level 0 anyway */

        level = 1;
        ret = apply_one_level(d, &first[first_table_offset(addr)],
                              level, flush_pt, op,
                              start_gpaddr, end_gpaddr,
                              &addr, &maddr, &flush,
                              mattr, t);
        if ( ret < 0 ) { rc = ret ; goto out; }
        count += ret;
        if ( ret != P2M_ONE_DESCEND ) continue;

        BUG_ON(!p2m_valid(first[first_table_offset(addr)]));

        if ( cur_first_offset != first_table_offset(addr) )
        {
            if (second) unmap_domain_page(second);
            second = map_domain_page(first[first_table_offset(addr)].p2m.base);
            cur_first_offset = first_table_offset(addr);
            /* Any mapping further down is now invalid */
            cur_second_offset = ~0;
        }
        /* else: second already valid */

        level = 2;
        ret = apply_one_level(d,&second[second_table_offset(addr)],
                              level, flush_pt, op,
                              start_gpaddr, end_gpaddr,
                              &addr, &maddr, &flush,
                              mattr, t);
        if ( ret < 0 ) { rc = ret ; goto out; }
        count += ret;
        if ( ret != P2M_ONE_DESCEND ) continue;

        BUG_ON(!p2m_valid(second[second_table_offset(addr)]));

        if ( cur_second_offset != second_table_offset(addr) )
        {
            /* map third level */
            if (third) unmap_domain_page(third);
            third = map_domain_page(second[second_table_offset(addr)].p2m.base);
            cur_second_offset = second_table_offset(addr);
        }

        level = 3;
        ret = apply_one_level(d, &third[third_table_offset(addr)],
                              level, flush_pt, op,
                              start_gpaddr, end_gpaddr,
                              &addr, &maddr, &flush,
                              mattr, t);
        if ( ret < 0 ) { rc = ret ; goto out; }
        /* L3 had better have done something! We cannot descend any further */
        BUG_ON(ret == P2M_ONE_DESCEND);
        count += ret;
    }

    if ( flush )
    {
        unsigned long sgfn = paddr_to_pfn(start_gpaddr);
        unsigned long egfn = paddr_to_pfn(end_gpaddr);

        flush_tlb_domain(d);
        iommu_iotlb_flush(d, sgfn, egfn - sgfn);
    }

    if ( op == ALLOCATE || op == INSERT )
    {
        unsigned long sgfn = paddr_to_pfn(start_gpaddr);
        unsigned long egfn = paddr_to_pfn(end_gpaddr);

        p2m->max_mapped_gfn = max(p2m->max_mapped_gfn, egfn);
        p2m->lowest_mapped_gfn = min(p2m->lowest_mapped_gfn, sgfn);
    }

    rc = 0;

out:
    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);
    if ( rc < 0 && ( op == INSERT || op == ALLOCATE ) &&
         addr != start_gpaddr )
    {
        BUG_ON(addr == end_gpaddr);
        /*
         * addr keeps the address of the last successfully-inserted mapping,
         * while apply_p2m_changes() considers an address range which is
         * exclusive of end_gpaddr: add level_size to addr to obtain the
         * right end of the range
         */
        apply_p2m_changes(d, REMOVE,
                          start_gpaddr, addr + level_sizes[level], orig_maddr,
                          mattr, p2m_invalid);
    }

    spin_unlock(&p2m->lock);

    return rc;
}

int p2m_populate_ram(struct domain *d,
                     paddr_t start,
                     paddr_t end)
{
    return apply_p2m_changes(d, ALLOCATE, start, end,
                             0, MATTR_MEM, p2m_ram_rw);
}

int map_mmio_regions(struct domain *d,
                     unsigned long start_gfn,
                     unsigned long nr,
                     unsigned long mfn)
{
    return apply_p2m_changes(d, INSERT,
                             pfn_to_paddr(start_gfn),
                             pfn_to_paddr(start_gfn + nr),
                             pfn_to_paddr(mfn),
                             MATTR_DEV, p2m_mmio_direct);
}

int unmap_mmio_regions(struct domain *d,
                       unsigned long start_gfn,
                       unsigned long nr,
                       unsigned long mfn)
{
    return apply_p2m_changes(d, REMOVE,
                             pfn_to_paddr(start_gfn),
                             pfn_to_paddr(start_gfn + nr),
                             pfn_to_paddr(mfn),
                             MATTR_DEV, p2m_invalid);
}

int guest_physmap_add_entry(struct domain *d,
                            unsigned long gpfn,
                            unsigned long mfn,
                            unsigned long page_order,
                            p2m_type_t t)
{
    return apply_p2m_changes(d, INSERT,
                             pfn_to_paddr(gpfn),
                             pfn_to_paddr(gpfn + (1 << page_order)),
                             pfn_to_paddr(mfn), MATTR_MEM, t);
}

void guest_physmap_remove_page(struct domain *d,
                               unsigned long gpfn,
                               unsigned long mfn, unsigned int page_order)
{
    apply_p2m_changes(d, REMOVE,
                      pfn_to_paddr(gpfn),
                      pfn_to_paddr(gpfn + (1<<page_order)),
                      pfn_to_paddr(mfn), MATTR_MEM, p2m_invalid);
}

int arch_grant_map_page_identity(struct domain *d, unsigned long frame,
                                 bool_t writeable)
{
    p2m_type_t t;

    ASSERT(is_domain_direct_mapped(d));

    /* This is not an IOMMU mapping but it is not a regular RAM p2m type
     * either. We are using IOMMU p2m types here to prevent the pages
     * from being used as grants. */
    if ( writeable )
        t = p2m_iommu_map_rw;
    else
        t = p2m_iommu_map_ro;

    return guest_physmap_add_entry(d, frame, frame, 0, t);
}

int arch_grant_unmap_page_identity(struct domain *d, unsigned long frame)
{
    ASSERT(is_domain_direct_mapped(d));

    guest_physmap_remove_page(d, frame, frame, 0);
    return 0;
}

int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;

    page = alloc_domheap_pages(NULL, P2M_FIRST_ORDER, 0);
    if ( page == NULL )
        return -ENOMEM;

    spin_lock(&p2m->lock);

    /* Clear both first level pages */
    clear_and_clean_page(page);
    clear_and_clean_page(page + 1);

    p2m->first_level = page;

    d->arch.vttbr = page_to_maddr(p2m->first_level)
        | ((uint64_t)p2m->vmid&0xff)<<48;

    /* Make sure that all TLBs corresponding to the new VMID are flushed
     * before using it
     */
    flush_tlb_domain(d);

    spin_unlock(&p2m->lock);

    return 0;
}

#define MAX_VMID 256
#define INVALID_VMID 0 /* VMID 0 is reserved */

static spinlock_t vmid_alloc_lock = SPIN_LOCK_UNLOCKED;

/* VTTBR_EL2 VMID field is 8 bits. Using a bitmap here limits us to
 * 256 concurrent domains. */
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

    spin_lock(&p2m->lock);

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        free_domheap_page(pg);

    free_domheap_pages(p2m->first_level, P2M_FIRST_ORDER);

    p2m->first_level = NULL;

    p2m_free_vmid(d);

    spin_unlock(&p2m->lock);
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    int rc = 0;

    spin_lock_init(&p2m->lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    spin_lock(&p2m->lock);
    p2m->vmid = INVALID_VMID;

    rc = p2m_alloc_vmid(d);
    if ( rc != 0 )
        goto err;

    d->arch.vttbr = 0;

    p2m->first_level = NULL;

    p2m->max_mapped_gfn = 0;
    p2m->lowest_mapped_gfn = ULONG_MAX;

err:
    spin_unlock(&p2m->lock);

    return rc;
}

int relinquish_p2m_mapping(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    return apply_p2m_changes(d, RELINQUISH,
                              pfn_to_paddr(p2m->lowest_mapped_gfn),
                              pfn_to_paddr(p2m->max_mapped_gfn),
                              pfn_to_paddr(INVALID_MFN),
                              MATTR_MEM, p2m_invalid);
}

int p2m_cache_flush(struct domain *d, xen_pfn_t start_mfn, xen_pfn_t end_mfn)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    start_mfn = MAX(start_mfn, p2m->lowest_mapped_gfn);
    end_mfn = MIN(end_mfn, p2m->max_mapped_gfn);

    return apply_p2m_changes(d, CACHEFLUSH,
                             pfn_to_paddr(start_mfn),
                             pfn_to_paddr(end_mfn),
                             pfn_to_paddr(INVALID_MFN),
                             MATTR_MEM, p2m_invalid);
}

unsigned long gmfn_to_mfn(struct domain *d, unsigned long gpfn)
{
    paddr_t p = p2m_lookup(d, pfn_to_paddr(gpfn), NULL);
    return p >> PAGE_SHIFT;
}

struct page_info *get_page_from_gva(struct domain *d, vaddr_t va,
                                    unsigned long flags)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page = NULL;
    paddr_t maddr;

    ASSERT(d == current->domain);

    spin_lock(&p2m->lock);

    if ( gvirt_to_maddr(va, &maddr, flags) )
        goto err;

    if ( !mfn_valid(maddr >> PAGE_SHIFT) )
        goto err;

    page = mfn_to_page(maddr >> PAGE_SHIFT);
    ASSERT(page);

    if ( unlikely(!get_page(page, d)) )
        page = NULL;

err:
    spin_unlock(&p2m->lock);
    return page;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
