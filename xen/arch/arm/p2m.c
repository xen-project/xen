#include <xen/config.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>

void p2m_load_VTTBR(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    paddr_t maddr = page_to_maddr(p2m->first_level);
    uint64_t vttbr = maddr;

    vttbr |= ((uint64_t)p2m->vmid&0xff)<<48;

    printk("VTTBR dom%d = %"PRIx64"\n", d->domain_id, vttbr);

    WRITE_CP64(vttbr, VTTBR);
    isb(); /* Ensure update is visible */
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

static int p2m_create_entry(struct domain *d,
                            lpae_t *entry)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    void *p;
    lpae_t pte;

    BUG_ON(entry->p2m.valid);

    page = alloc_domheap_page(d, 0);
    if ( page == NULL )
        return -ENOMEM;

    page_list_add(page, &p2m->pages);

    p = __map_domain_page(page);
    clear_page(p);
    unmap_domain_page(p);

    pte = mfn_to_p2m_entry(page_to_mfn(page));

    write_pte(entry, pte);

    return 0;
}

static int create_p2m_entries(struct domain *d,
                     int alloc,
                     paddr_t start_gpaddr,
                     paddr_t end_gpaddr,
                     paddr_t maddr)
{
    int rc;
    struct p2m_domain *p2m = &d->arch.p2m;
    lpae_t *first = NULL, *second = NULL, *third = NULL;
    paddr_t addr;
    unsigned long cur_first_offset = ~0, cur_second_offset = ~0;

    /* XXX Don't actually handle 40 bit guest physical addresses */
    BUG_ON(start_gpaddr & 0x8000000000ULL);
    BUG_ON(end_gpaddr   & 0x8000000000ULL);

    first = __map_domain_page(p2m->first_level);

    for(addr = start_gpaddr; addr < end_gpaddr; addr += PAGE_SIZE)
    {
        if ( !first[first_table_offset(addr)].p2m.valid )
        {
            rc = p2m_create_entry(d, &first[first_table_offset(addr)]);
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
            rc = p2m_create_entry(d, &second[second_table_offset(addr)]);
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
        /* else: third already valid */

        BUG_ON(third[third_table_offset(addr)].p2m.valid);

        /* Allocate a new RAM page and attach */
        if (alloc)
        {
            struct page_info *page;
            lpae_t pte;

            rc = -ENOMEM;
            page = alloc_domheap_page(d, 0);
            if ( page == NULL ) {
                printk("p2m_populate_ram: failed to allocate page\n");
                goto out;
            }

            pte = mfn_to_p2m_entry(page_to_mfn(page));

            write_pte(&third[third_table_offset(addr)], pte);
        } else {
            lpae_t pte = mfn_to_p2m_entry(maddr >> PAGE_SHIFT);
            write_pte(&third[third_table_offset(addr)], pte);
            maddr += PAGE_SIZE;
        }
    }

    rc = 0;

out:
    spin_lock(&p2m->lock);

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
    return create_p2m_entries(d, 1, start, end, 0);
}

int map_mmio_regions(struct domain *d,
                     paddr_t start_gaddr,
                     paddr_t end_gaddr,
                     paddr_t maddr)
{
    return create_p2m_entries(d, 0, start_gaddr, end_gaddr, maddr);
}

int p2m_alloc_table(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;
    struct page_info *page;
    void *p;

    /* First level P2M is 2 consecutive pages */
    page = alloc_domheap_pages(d, 1, 0);
    if ( page == NULL )
        return -ENOMEM;

    spin_lock(&p2m->lock);

    page_list_add(page, &p2m->pages);

    /* Clear both first level pages */
    p = __map_domain_page(page);
    clear_page(p);
    unmap_domain_page(p);

    p = __map_domain_page(page + 1);
    clear_page(p);
    unmap_domain_page(p);

    p2m->first_level = page;

    spin_unlock(&p2m->lock);

    return 0;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m = &d->arch.p2m;

    spin_lock_init(&p2m->lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    /* XXX allocate properly */
    /* Zero is reserved */
    p2m->vmid = d->domain_id + 1;

    p2m->first_level = NULL;

    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
