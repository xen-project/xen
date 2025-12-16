/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__P2M_H
#define ASM__RISCV__P2M_H

#include <xen/bitops.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/rwlock.h>
#include <xen/types.h>

#include <asm/page-bits.h>

#define P2M_ROOT_ORDER  (ilog2(GSTAGE_ROOT_PAGE_TABLE_SIZE) - PAGE_SHIFT)
#define P2M_ROOT_PAGES  BIT(P2M_ROOT_ORDER, U)

#define paddr_bits PADDR_BITS

/* Get host p2m table */
#define p2m_get_hostp2m(d) (&(d)->arch.p2m)

struct gstage_mode_desc {
    unsigned char mode;
    unsigned int paging_levels;
    char name[8];
};

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

    struct gstage_mode_desc mode;

    /* Back pointer to domain */
    struct domain *domain;

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

    /*
     * Indicate if it is required to clean the cache when writing an entry or
     * when a page is needed to be fully cleared and cleaned.
     */
    bool clean_dcache;
};

/*
 * List of possible type for each page in the p2m entry.
 * The number of available bit per page in the pte for this purpose is 2 bits.
 * So it's possible to only have 4 fields. If we run out of value in the
 * future, it's possible to use higher value for pseudo-type and don't store
 * them in the p2m entry.
 */
typedef enum {
    p2m_invalid = 0,    /* Nothing mapped here */
    p2m_ram_rw,         /* Normal read/write domain RAM */
} p2m_type_t;

#include <xen/p2m-common.h>

static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

/* Look up a GFN and take a reference count on the backing page. */
typedef unsigned int p2m_query_t;
#define P2M_ALLOC    (1u<<0)   /* Populate PoD and paged-out entries */
#define P2M_UNSHARE  (1u<<1)   /* Break CoW sharing */

static inline struct page_info *get_page_from_gfn(
    struct domain *d, unsigned long gfn, p2m_type_t *t, p2m_query_t q)
{
    BUG_ON("unimplemented");
    return NULL;
}

static inline void memory_type_changed(struct domain *d)
{
    BUG_ON("unimplemented");
}


static inline int guest_physmap_mark_populate_on_demand(struct domain *d,
                                                        unsigned long gfn,
                                                        unsigned int order)
{
    return -EOPNOTSUPP;
}

static inline int guest_physmap_add_entry(struct domain *d,
                                          gfn_t gfn, mfn_t mfn,
                                          unsigned long page_order,
                                          p2m_type_t t)
{
    BUG_ON("unimplemented");
    return -EINVAL;
}

/* Untyped version for RAM only, for compatibility */
static inline int __must_check
guest_physmap_add_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int page_order)
{
    return guest_physmap_add_entry(d, gfn, mfn, page_order, p2m_ram_rw);
}

static inline mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    BUG_ON("unimplemented");
    return INVALID_MFN;
}

static inline bool arch_acquire_resource_check(struct domain *d)
{
    /*
     * Requires refcounting the foreign mappings and walking the p2m on
     * teardown in order to remove foreign pages from the p2m and drop the
     * extra reference counts.
     */
    return false;
}

void guest_mm_init(void);
unsigned char get_max_supported_mode(void);

int p2m_init(struct domain *d);

unsigned long construct_hgatp(const struct p2m_domain *p2m, uint16_t vmid);

#endif /* ASM__RISCV__P2M_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
