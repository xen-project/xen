#include <xen/config.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <xen/bitops.h>
#include <asm/flushtlb.h>
#include <asm/gic.h>

/* First level P2M is 2 consecutive pages */
#define P2M_FIRST_ORDER 1
#define P2M_FIRST_ENTRIES (LPAE_ENTRIES<<P2M_FIRST_ORDER)

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

void p2m_load_VTTBR(struct domain *d)
{
    if ( is_idle_domain(d) )
        return;
    BUG_ON(!d->arch.vttbr);
    WRITE_SYSREG64(d->arch.vttbr, VTTBR_EL2);
    isb(); /* Ensure update is visible */
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

    BUG_ON(first_linear_offset(addr) > P2M_FIRST_ENTRIES);

    page = p2m->first_level + p2m_first_level_index(addr);

    return __map_domain_page(page);
}

/*
 * Lookup the MFN corresponding to a domain's PFN.
 *
 * There are no processor functions to do a stage 2 only lookup therefore we
 * do a a software walk.
 */
paddr_t p2m_lookup(struct domain *d, paddr_t paddr)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t pte, *first = NULL, *second = NULL, *third = NULL;
    paddr_t maddr = INVALID_PADDR;

    spin_lock(&p2m->lock);

    first = p2m_map_first(p2m, paddr);

    pte = first[first_table_offset(paddr)];
    if ( !pte.p2m.valid || !pte.p2m.table )
        goto done;

    second = map_domain_page(pte.p2m.base);
    pte = second[second_table_offset(paddr)];
    if ( !pte.p2m.valid || !pte.p2m.table )
        goto done;

    third = map_domain_page(pte.p2m.base);
    pte = third[third_table_offset(paddr)];

    /* This bit must be one in the level 3 entry */
    if ( !pte.p2m.table )
        pte.bits = 0;

done:
    if ( pte.p2m.valid )
        maddr = (pte.bits & PADDR_MASK & PAGE_MASK) | (paddr & ~PAGE_MASK);

    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);

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

/* Allocate a new page table page and hook it in via the given entry */
static int p2m_create_table(struct domain *d,
                            lpae_t *entry)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    void *p;
    lpae_t pte;

    BUG_ON(entry->p2m.valid);

    page = alloc_domheap_page(NULL, 0);
    if ( page == NULL )
        return -ENOMEM;

    page_list_add(page, &p2m->pages);

    p = __map_domain_page(page);
    clear_page(p);
    unmap_domain_page(p);

    pte = mfn_to_p2m_entry(page_to_mfn(page), MATTR_MEM);

    write_pte(entry, pte);

    return 0;
}

enum p2m_operation {
    INSERT,
    ALLOCATE,
    REMOVE
};

static int create_p2m_entries(struct domain *d,
                     enum p2m_operation op,
                     paddr_t start_gpaddr,
                     paddr_t end_gpaddr,
                     paddr_t maddr,
                     int mattr)
{
    int rc, flush;
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t *first = NULL, *second = NULL, *third = NULL;
    paddr_t addr;
    unsigned long cur_first_page = ~0,
                  cur_first_offset = ~0,
                  cur_second_offset = ~0;

    spin_lock(&p2m->lock);

    for(addr = start_gpaddr; addr < end_gpaddr; addr += PAGE_SIZE)
    {
        if ( cur_first_page != p2m_first_level_index(addr) )
        {
            if ( first ) unmap_domain_page(first);
            first = p2m_map_first(p2m, addr);
            cur_first_page = p2m_first_level_index(addr);
        }

        if ( !first[first_table_offset(addr)].p2m.valid )
        {
            rc = p2m_create_table(d, &first[first_table_offset(addr)]);
            if ( rc < 0 ) {
                printk("p2m_populate_ram: L1 failed\n");
                goto out;
            }
        }

        BUG_ON(!first[first_table_offset(addr)].p2m.valid);

        if ( cur_first_offset != first_table_offset(addr) )
        {
            if (second) unmap_domain_page(second);
            second = map_domain_page(first[first_table_offset(addr)].p2m.base);
            cur_first_offset = first_table_offset(addr);
        }
        /* else: second already valid */

        if ( !second[second_table_offset(addr)].p2m.valid )
        {
            rc = p2m_create_table(d, &second[second_table_offset(addr)]);
            if ( rc < 0 ) {
                printk("p2m_populate_ram: L2 failed\n");
                goto out;
            }
        }

        BUG_ON(!second[second_table_offset(addr)].p2m.valid);

        if ( cur_second_offset != second_table_offset(addr) )
        {
            /* map third level */
            if (third) unmap_domain_page(third);
            third = map_domain_page(second[second_table_offset(addr)].p2m.base);
            cur_second_offset = second_table_offset(addr);
        }

        flush = third[third_table_offset(addr)].p2m.valid;

        /* Allocate a new RAM page and attach */
        switch (op) {
            case ALLOCATE:
                {
                    struct page_info *page;
                    lpae_t pte;

                    rc = -ENOMEM;
                    page = alloc_domheap_page(d, 0);
                    if ( page == NULL ) {
                        printk("p2m_populate_ram: failed to allocate page\n");
                        goto out;
                    }

                    pte = mfn_to_p2m_entry(page_to_mfn(page), mattr);

                    write_pte(&third[third_table_offset(addr)], pte);
                }
                break;
            case INSERT:
                {
                    lpae_t pte = mfn_to_p2m_entry(maddr >> PAGE_SHIFT, mattr);
                    write_pte(&third[third_table_offset(addr)], pte);
                    maddr += PAGE_SIZE;
                }
                break;
            case REMOVE:
                {
                    lpae_t pte;
                    memset(&pte, 0x00, sizeof(pte));
                    write_pte(&third[third_table_offset(addr)], pte);
                    maddr += PAGE_SIZE;
                }
                break;
        }

        if ( flush )
            flush_tlb_all_local();
    }

    rc = 0;

out:
    if (third) unmap_domain_page(third);
    if (second) unmap_domain_page(second);
    if (first) unmap_domain_page(first);

    spin_unlock(&p2m->lock);

    return rc;
}

int p2m_populate_ram(struct domain *d,
                     paddr_t start,
                     paddr_t end)
{
    return create_p2m_entries(d, ALLOCATE, start, end, 0, MATTR_MEM);
}

int map_mmio_regions(struct domain *d,
                     paddr_t start_gaddr,
                     paddr_t end_gaddr,
                     paddr_t maddr)
{
    return create_p2m_entries(d, INSERT, start_gaddr, end_gaddr, maddr, MATTR_DEV);
}

int guest_physmap_add_page(struct domain *d,
                           unsigned long gpfn,
                           unsigned long mfn,
                           unsigned int page_order)
{
    return create_p2m_entries(d, INSERT,
                              pfn_to_paddr(gpfn),
                              pfn_to_paddr(gpfn + (1<<page_order)),
                              pfn_to_paddr(mfn), MATTR_MEM);
}

void guest_physmap_remove_page(struct domain *d,
                               unsigned long gpfn,
                               unsigned long mfn, unsigned int page_order)
{
    create_p2m_entries(d, REMOVE,
                       pfn_to_paddr(gpfn),
                       pfn_to_paddr(gpfn + (1<<page_order)),
                       pfn_to_paddr(mfn), MATTR_MEM);
}

int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    void *p;

    page = alloc_domheap_pages(NULL, P2M_FIRST_ORDER, 0);
    if ( page == NULL )
        return -ENOMEM;

    spin_lock(&p2m->lock);

    /* Clear both first level pages */
    p = __map_domain_page(page);
    clear_page(p);
    unmap_domain_page(p);

    p = __map_domain_page(page + 1);
    clear_page(p);
    unmap_domain_page(p);

    p2m->first_level = page;

    d->arch.vttbr = page_to_maddr(p2m->first_level)
        | ((uint64_t)p2m->vmid&0xff)<<48;

    p2m_load_VTTBR(d);

    /* Make sure that all TLBs corresponding to the new VMID are flushed
     * before using it
     */
    flush_tlb();

    p2m_load_VTTBR(current->domain);

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

err:
    spin_unlock(&p2m->lock);

    return rc;
}

unsigned long gmfn_to_mfn(struct domain *d, unsigned long gpfn)
{
    paddr_t p = p2m_lookup(d, pfn_to_paddr(gpfn));
    return p >> PAGE_SHIFT;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
