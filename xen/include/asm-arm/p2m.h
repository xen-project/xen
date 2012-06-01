#ifndef _XEN_P2M_H
#define _XEN_P2M_H

#include <xen/mm.h>

struct domain;

/* Per-p2m-table state */
struct p2m_domain {
    /* Lock that protects updates to the p2m */
    spinlock_t lock;

    /* Pages used to construct the p2m */
    struct page_list_head pages;

    /* Root of p2m page tables, 2 contiguous pages */
    struct page_info *first_level;

    /* Current VMID in use */
    uint8_t vmid;
};

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d);

/* Allocate a new p2m table for a domain.
 *
 * Returns 0 for success or -errno.
 */
int p2m_alloc_table(struct domain *d);

/* */
void p2m_load_VTTBR(struct domain *d);

/* Setup p2m RAM mapping for domain d from start-end. */
int p2m_populate_ram(struct domain *d, paddr_t start, paddr_t end);
/* Map MMIO regions in the p2m: start_gaddr and end_gaddr is the range
 * in the guest physical address space to map, starting from the machine
 * address maddr. */
int map_mmio_regions(struct domain *d, paddr_t start_gaddr,
                     paddr_t end_gaddr, paddr_t maddr);

/* Untyped version for RAM only, for compatibility */
int guest_physmap_add_page(struct domain *d,
                           unsigned long gfn,
                           unsigned long mfn,
                           unsigned int page_order);
void guest_physmap_remove_page(struct domain *d,
                               unsigned long gpfn,
                               unsigned long mfn, unsigned int page_order);

unsigned long gmfn_to_mfn(struct domain *d, unsigned long gpfn);

/*
 * Populate-on-demand
 */

/* Call when decreasing memory reservation to handle PoD entries properly.
 * Will return '1' if all entries were handled and nothing more need be done.*/
int
p2m_pod_decrease_reservation(struct domain *d,
                             xen_pfn_t gpfn,
                             unsigned int order);

/* Look up a GFN and take a reference count on the backing page. */
typedef int p2m_type_t;
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

static inline struct page_info *get_page_from_gfn(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    struct page_info *page;
    unsigned long mfn = gmfn_to_mfn(d, gfn);

    ASSERT(t == NULL);

    if (!mfn_valid(mfn))
        return NULL;
    page = mfn_to_page(mfn);
    if ( !get_page(page, d) )
        return NULL;
    return page;
}

int get_page_type(struct page_info *page, unsigned long type);
int is_iomem_page(unsigned long mfn);
static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    int rc = get_page(page, domain);

    if ( likely(rc) && unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        rc = 0;
    }

    return rc;
}

#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
