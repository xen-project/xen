#ifndef _XEN_P2M_H
#define _XEN_P2M_H

#include <xen/mm.h>
#include <xen/radix-tree.h>
#include <public/vm_event.h> /* for vm_event_response_t */
#include <public/memory.h>
#include <xen/p2m-common.h>
#include <public/memory.h>

#define paddr_bits PADDR_BITS

/* Holds the bit size of IPAs in p2m tables.  */
extern unsigned int p2m_ipa_bits;

struct domain;

extern void memory_type_changed(struct domain *);

/* Per-p2m-table state */
struct p2m_domain {
    /* Lock that protects updates to the p2m */
    spinlock_t lock;

    /* Pages used to construct the p2m */
    struct page_list_head pages;

    /* The root of the p2m tree. May be concatenated */
    struct page_info *root;

    /* Current VMID in use */
    uint8_t vmid;

    /* Highest guest frame that's ever been mapped in the p2m
     * Only takes into account ram and foreign mapping
     */
    unsigned long max_mapped_gfn;

    /* Lowest mapped gfn in the p2m. When releasing mapped gfn's in a
     * preemptible manner this is update to track recall where to
     * resume the search. Apart from during teardown this can only
     * decrease. */
    unsigned long lowest_mapped_gfn;

    /* Gather some statistics for information purposes only */
    struct {
        /* Number of mappings at each p2m tree level */
        unsigned long mappings[4];
        /* Number of times we have shattered a mapping
         * at each p2m tree level. */
        unsigned long shattered[4];
    } stats;

    /* If true, and an access fault comes in and there is no vm_event listener,
     * pause domain. Otherwise, remove access restrictions. */
    bool_t access_required;

    /* Defines if mem_access is in use for the domain. */
    bool_t mem_access_enabled;

    /* Default P2M access type for each page in the the domain: new pages,
     * swapped in pages, cleared pages, and pages that are ambiguously
     * retyped get this access type. See definition of p2m_access_t. */
    p2m_access_t default_access;

    /* Radix tree to store the p2m_access_t settings as the pte's don't have
     * enough available bits to store this information. */
    struct radix_tree_root mem_access_settings;
};

/* List of possible type for each page in the p2m entry.
 * The number of available bit per page in the pte for this purpose is 4 bits.
 * So it's possible to only have 16 fields. If we run out of value in the
 * future, it's possible to use higher value for pseudo-type and don't store
 * them in the p2m entry.
 */
typedef enum {
    p2m_invalid = 0,    /* Nothing mapped here */
    p2m_ram_rw,         /* Normal read/write guest RAM */
    p2m_ram_ro,         /* Read-only; writes are silently dropped */
    p2m_mmio_direct,    /* Read/write mapping of genuine MMIO area */
    p2m_map_foreign,    /* Ram pages from foreign domain */
    p2m_grant_map_rw,   /* Read/write grant mapping */
    p2m_grant_map_ro,   /* Read-only grant mapping */
    /* The types below are only used to decide the page attribute in the P2M */
    p2m_iommu_map_rw,   /* Read/write iommu mapping */
    p2m_iommu_map_ro,   /* Read-only iommu mapping */
    p2m_max_real_type,  /* Types after this won't be store in the p2m */
} p2m_type_t;

static inline
int p2m_mem_access_enable_emulate(struct domain *d)
{
    /* Not supported on ARM */
    return -ENOSYS;
}

static inline
int p2m_mem_access_disable_emulate(struct domain *d)
{
    /* Not supported on ARM */
    return -ENOSYS;
}

static inline
void p2m_mem_access_emulate_check(struct vcpu *v,
                                  const vm_event_response_t *rsp)
{
    /* Not supported on ARM. */
}

static inline
void p2m_altp2m_check(struct vcpu *v, uint16_t idx)
{
    /* Not supported on ARM. */
}

#define p2m_is_foreign(_t)  ((_t) == p2m_map_foreign)
#define p2m_is_ram(_t)      ((_t) == p2m_ram_rw || (_t) == p2m_ram_ro)

/* Initialise vmid allocator */
void p2m_vmid_allocator_init(void);

/* Second stage paging setup, to be called on all CPUs */
void __cpuinit setup_virt_paging(void);

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d);

/* Return all the p2m resources to Xen. */
void p2m_teardown(struct domain *d);

/* Remove mapping refcount on each mapping page in the p2m
 *
 * TODO: For the moment only foreign mappings are handled
 */
int relinquish_p2m_mapping(struct domain *d);

/* Allocate a new p2m table for a domain.
 *
 * Returns 0 for success or -errno.
 */
int p2m_alloc_table(struct domain *d);

/* Context switch */
void p2m_save_state(struct vcpu *p);
void p2m_restore_state(struct vcpu *n);

/* Print debugging/statistial info about a domain's p2m */
void p2m_dump_info(struct domain *d);

/* Look up the MFN corresponding to a domain's PFN. */
paddr_t p2m_lookup(struct domain *d, paddr_t gpfn, p2m_type_t *t);

/* Clean & invalidate caches corresponding to a region of guest address space */
int p2m_cache_flush(struct domain *d, xen_pfn_t start_mfn, xen_pfn_t end_mfn);

/* Setup p2m RAM mapping for domain d from start-end. */
int p2m_populate_ram(struct domain *d, paddr_t start, paddr_t end);

int guest_physmap_add_entry(struct domain *d,
                            unsigned long gfn,
                            unsigned long mfn,
                            unsigned long page_order,
                            p2m_type_t t);

/* Untyped version for RAM only, for compatibility */
static inline int guest_physmap_add_page(struct domain *d,
                                         unsigned long gfn,
                                         unsigned long mfn,
                                         unsigned int page_order)
{
    return guest_physmap_add_entry(d, gfn, mfn, page_order, p2m_ram_rw);
}

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
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

static inline struct page_info *get_page_from_gfn(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    struct page_info *page;
    p2m_type_t p2mt;
    paddr_t maddr = p2m_lookup(d, pfn_to_paddr(gfn), &p2mt);
    unsigned long mfn = maddr >> PAGE_SHIFT;

    if (t)
        *t = p2mt;

    if ( p2mt == p2m_invalid || p2mt == p2m_mmio_direct )
        return NULL;

    if ( !mfn_valid(mfn) )
        return NULL;
    page = mfn_to_page(mfn);

    /* get_page won't work on foreign mapping because the page doesn't
     * belong to the current domain.
     */
    if ( p2mt == p2m_map_foreign )
    {
        struct domain *fdom = page_get_owner_and_reference(page);
        ASSERT(fdom != NULL);
        ASSERT(fdom != d);
        return page;
    }

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

/* get host p2m table */
#define p2m_get_hostp2m(d) (&(d)->arch.p2m)

/* vm_event and mem_access are supported on any ARM guest */
static inline bool_t p2m_mem_access_sanity_check(struct domain *d)
{
    return 1;
}

static inline bool_t p2m_vm_event_sanity_check(struct domain *d)
{
    return 1;
}

/* Send mem event based on the access. Boolean return value indicates if trap
 * needs to be injected into guest. */
bool_t p2m_mem_access_check(paddr_t gpa, vaddr_t gla, const struct npfec npfec);

#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
