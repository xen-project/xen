#ifndef _XEN_P2M_H
#define _XEN_P2M_H

#include <xen/mm.h>
#include <xen/radix-tree.h>
#include <xen/rwlock.h>
#include <xen/mem_access.h>
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
    /*
     * Lock that protects updates to the p2m.
     */
    rwlock_t lock;

    /* Pages used to construct the p2m */
    struct page_list_head pages;

    /* The root of the p2m tree. May be concatenated */
    struct page_info *root;

    /* Current VMID in use */
    uint16_t vmid;

    /* Current Translation Table Base Register for the p2m */
    uint64_t vttbr;

    /*
     * Highest guest frame that's ever been mapped in the p2m
     * Only takes into account ram and foreign mapping
     */
    gfn_t max_mapped_gfn;

    /*
     * Lowest mapped gfn in the p2m. When releasing mapped gfn's in a
     * preemptible manner this is update to track recall where to
     * resume the search. Apart from during teardown this can only
     * decrease. */
    gfn_t lowest_mapped_gfn;

    /* Indicate if it is required to clean the cache when writing an entry */
    bool clean_pte;

    /*
     * P2M updates may required TLBs to be flushed (invalidated).
     *
     * Flushes may be deferred by setting 'need_flush' and then flushing
     * when the p2m write lock is released.
     *
     * If an immediate flush is required (e.g, if a super page is
     * shattered), call p2m_tlb_flush_sync().
     */
    bool need_flush;

    /* Gather some statistics for information purposes only */
    struct {
        /* Number of mappings at each p2m tree level */
        unsigned long mappings[4];
        /* Number of times we have shattered a mapping
         * at each p2m tree level. */
        unsigned long shattered[4];
    } stats;

    /*
     * If true, and an access fault comes in and there is no vm_event listener,
     * pause domain. Otherwise, remove access restrictions.
     */
    bool access_required;

    /* Defines if mem_access is in use for the domain. */
    bool mem_access_enabled;

    /*
     * Default P2M access type for each page in the the domain: new pages,
     * swapped in pages, cleared pages, and pages that are ambiguously
     * retyped get this access type. See definition of p2m_access_t.
     */
    p2m_access_t default_access;

    /*
     * Radix tree to store the p2m_access_t settings as the pte's don't have
     * enough available bits to store this information.
     */
    struct radix_tree_root mem_access_settings;

    /* back pointer to domain */
    struct domain *domain;

    /* Keeping track on which CPU this p2m was used and for which vCPU */
    uint8_t last_vcpu_ran[NR_CPUS];
};

/*
 * List of possible type for each page in the p2m entry.
 * The number of available bit per page in the pte for this purpose is 4 bits.
 * So it's possible to only have 16 fields. If we run out of value in the
 * future, it's possible to use higher value for pseudo-type and don't store
 * them in the p2m entry.
 */
typedef enum {
    p2m_invalid = 0,    /* Nothing mapped here */
    p2m_ram_rw,         /* Normal read/write guest RAM */
    p2m_ram_ro,         /* Read-only; writes are silently dropped */
    p2m_mmio_direct_dev,/* Read/write mapping of genuine Device MMIO area */
    p2m_mmio_direct_nc, /* Read/write mapping of genuine MMIO area non-cacheable */
    p2m_mmio_direct_c,  /* Read/write mapping of genuine MMIO area cacheable */
    p2m_map_foreign,    /* Ram pages from foreign domain */
    p2m_grant_map_rw,   /* Read/write grant mapping */
    p2m_grant_map_ro,   /* Read-only grant mapping */
    /* The types below are only used to decide the page attribute in the P2M */
    p2m_iommu_map_rw,   /* Read/write iommu mapping */
    p2m_iommu_map_ro,   /* Read-only iommu mapping */
    p2m_max_real_type,  /* Types after this won't be store in the p2m */
} p2m_type_t;

/* We use bitmaps and mask to handle groups of types */
#define p2m_to_mask(_t) (1UL << (_t))

/* RAM types, which map to real machine frames */
#define P2M_RAM_TYPES (p2m_to_mask(p2m_ram_rw) |        \
                       p2m_to_mask(p2m_ram_ro))

/* Grant mapping types, which map to a real frame in another VM */
#define P2M_GRANT_TYPES (p2m_to_mask(p2m_grant_map_rw) |  \
                         p2m_to_mask(p2m_grant_map_ro))

/* Useful predicates */
#define p2m_is_ram(_t) (p2m_to_mask(_t) & P2M_RAM_TYPES)
#define p2m_is_foreign(_t) (p2m_to_mask(_t) & p2m_to_mask(p2m_map_foreign))
#define p2m_is_any_ram(_t) (p2m_to_mask(_t) &                   \
                            (P2M_RAM_TYPES | P2M_GRANT_TYPES |  \
                             p2m_to_mask(p2m_map_foreign)))

static inline
void p2m_altp2m_check(struct vcpu *v, uint16_t idx)
{
    /* Not supported on ARM. */
}

/* Second stage paging setup, to be called on all CPUs */
void setup_virt_paging(void);

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d);

/* Return all the p2m resources to Xen. */
void p2m_teardown(struct domain *d);

/*
 * Remove mapping refcount on each mapping page in the p2m
 *
 * TODO: For the moment only foreign mappings are handled
 */
int relinquish_p2m_mapping(struct domain *d);

/* Context switch */
void p2m_save_state(struct vcpu *p);
void p2m_restore_state(struct vcpu *n);

/* Print debugging/statistial info about a domain's p2m */
void p2m_dump_info(struct domain *d);

static inline void p2m_write_lock(struct p2m_domain *p2m)
{
    write_lock(&p2m->lock);
}

void p2m_write_unlock(struct p2m_domain *p2m);

static inline void p2m_read_lock(struct p2m_domain *p2m)
{
    read_lock(&p2m->lock);
}

static inline void p2m_read_unlock(struct p2m_domain *p2m)
{
    read_unlock(&p2m->lock);
}

static inline int p2m_is_locked(struct p2m_domain *p2m)
{
    return rw_is_locked(&p2m->lock);
}

static inline int p2m_is_write_locked(struct p2m_domain *p2m)
{
    return rw_is_write_locked(&p2m->lock);
}

void p2m_tlb_flush_sync(struct p2m_domain *p2m);

/* Look up the MFN corresponding to a domain's GFN. */
mfn_t p2m_lookup(struct domain *d, gfn_t gfn, p2m_type_t *t);

/*
 * Get details of a given gfn.
 * The P2M lock should be taken by the caller.
 */
mfn_t p2m_get_entry(struct p2m_domain *p2m, gfn_t gfn,
                    p2m_type_t *t, p2m_access_t *a,
                    unsigned int *page_order);

/*
 * Direct set a p2m entry: only for use by the P2M code.
 * The P2M write lock should be taken.
 */
int p2m_set_entry(struct p2m_domain *p2m,
                  gfn_t sgfn,
                  unsigned long nr,
                  mfn_t smfn,
                  p2m_type_t t,
                  p2m_access_t a);

/* Clean & invalidate caches corresponding to a region of guest address space */
int p2m_cache_flush(struct domain *d, gfn_t start, unsigned long nr);

/*
 * Map a region in the guest p2m with a specific p2m type.
 * The memory attributes will be derived from the p2m type.
 */
int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt);

int unmap_regions_p2mt(struct domain *d,
                       gfn_t gfn,
                       unsigned long nr,
                       mfn_t mfn);

int map_dev_mmio_region(struct domain *d,
                        gfn_t gfn,
                        unsigned long nr,
                        mfn_t mfn);

int guest_physmap_add_entry(struct domain *d,
                            gfn_t gfn,
                            mfn_t mfn,
                            unsigned long page_order,
                            p2m_type_t t);

/* Untyped version for RAM only, for compatibility */
static inline int guest_physmap_add_page(struct domain *d,
                                         gfn_t gfn,
                                         mfn_t mfn,
                                         unsigned int page_order)
{
    return guest_physmap_add_entry(d, gfn, mfn, page_order, p2m_ram_rw);
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn);

/* Look up a GFN and take a reference count on the backing page. */
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

static inline struct page_info *get_page_from_gfn(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    struct page_info *page;
    p2m_type_t p2mt;
    unsigned long mfn = mfn_x(p2m_lookup(d, _gfn(gfn), &p2mt));

    if (t)
        *t = p2mt;

    if ( !p2m_is_any_ram(p2mt) )
        return NULL;

    if ( !mfn_valid(_mfn(mfn)) )
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

    if ( !get_page(page, d) )
        return NULL;
    return page;
}

int get_page_type(struct page_info *page, unsigned long type);
bool is_iomem_page(mfn_t mfn);
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

static inline bool p2m_vm_event_sanity_check(struct domain *d)
{
    return true;
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

#endif /* _XEN_P2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
