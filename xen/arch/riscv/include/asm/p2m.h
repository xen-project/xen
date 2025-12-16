/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__P2M_H
#define ASM__RISCV__P2M_H

#include <xen/bitops.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/rwlock.h>
#include <xen/types.h>

#include <asm/page.h>
#include <asm/page-bits.h>

#define P2M_ROOT_ORDER  (ilog2(GSTAGE_ROOT_PAGE_TABLE_SIZE) - PAGE_SHIFT)
#define P2M_ROOT_PAGES  BIT(P2M_ROOT_ORDER, U)
#define P2M_ROOT_LEVEL(p2m) ((p2m)->mode.paging_levels)

/*
 * According to the RISC-V spec:
 *   When hgatp.MODE specifies a translation scheme of Sv32x4, Sv39x4, Sv48x4,
 *   or Sv57x4, G-stage address translation is a variation on the usual
 *   page-based virtual address translation scheme of Sv32, Sv39, Sv48, or
 *   Sv57, respectively. In each case, the size of the incoming address is
 *   widened by 2 bits (to 34, 41, 50, or 59 bits).
 *
 * P2M_LEVEL_ORDER(lvl) defines the bit position in the GFN from which
 * the index for this level of the P2M page table starts. The extra 2
 * bits added by the "x4" schemes only affect the root page table width.
 *
 * Therefore, this macro can safely reuse XEN_PT_LEVEL_ORDER() for all
 * levels: the extra 2 bits do not change the indices of lower levels.
 */
#define P2M_LEVEL_ORDER(lvl) XEN_PT_LEVEL_ORDER(lvl)

#define P2M_ROOT_EXTRA_BITS(p2m, lvl) (2 * ((lvl) == P2M_ROOT_LEVEL(p2m)))

#define P2M_PAGETABLE_ENTRIES(p2m, lvl) \
    (BIT(PAGETABLE_ORDER + P2M_ROOT_EXTRA_BITS(p2m, lvl), UL))

#define P2M_TABLE_OFFSET(p2m, lvl) (P2M_PAGETABLE_ENTRIES(p2m, lvl) - 1UL)

#define P2M_GFN_LEVEL_SHIFT(lvl) (P2M_LEVEL_ORDER(lvl) + PAGE_SHIFT)

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

    /* Highest guest frame that's ever been mapped in the p2m */
    gfn_t max_mapped_gfn;

    /*
     * Lowest mapped gfn in the p2m. When releasing mapped gfn's in a
     * preemptible manner this is updated to track where to resume
     * the search. Apart from during teardown this can only decrease.
     */
    gfn_t lowest_mapped_gfn;
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
    p2m_mmio_direct_io, /* Read/write mapping of genuine Device MMIO area,
                           PTE_PBMT_IO will be used for such mappings */
    p2m_ext_storage,    /* Following types'll be stored outsude PTE bits: */
    p2m_map_foreign_rw, /* Read/write RAM pages from foreign domain */
    p2m_map_foreign_ro, /* Read-only RAM pages from foreign domain */

    /* Sentinel — not a real type, just a marker for comparison */
    p2m_first_external = p2m_ext_storage,
} p2m_type_t;

static inline p2m_type_t arch_dt_passthrough_p2m_type(void)
{
    return p2m_mmio_direct_io;
}

/*
 * Bits 8 and 9 are reserved for use by supervisor software;
 * the implementation shall ignore this field.
 * We are going to use to save in these bits frequently used types to avoid
 * get/set of a type from radix tree.
 */
#define P2M_TYPE_PTE_BITS_MASK PTE_RSW

/* We use bitmaps and mask to handle groups of types */
#define p2m_to_mask(t) BIT(t, UL)

/* RAM types, which map to real machine frames */
#define P2M_RAM_TYPES (p2m_to_mask(p2m_ram_rw))

/* Foreign mappings types */
#define P2M_FOREIGN_TYPES (p2m_to_mask(p2m_map_foreign_rw) | \
                           p2m_to_mask(p2m_map_foreign_ro))

/* Useful predicates */
#define p2m_is_ram(t) (p2m_to_mask(t) & P2M_RAM_TYPES)
#define p2m_is_any_ram(t) (p2m_to_mask(t) & P2M_RAM_TYPES)
#define p2m_is_foreign(t) (p2m_to_mask(t) & P2M_FOREIGN_TYPES)

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

/*
 * Map a region in the guest's hostp2m p2m with a specific p2m type.
 * The memory attributes will be derived from the p2m type.
 */
int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt);

/* Untyped version for RAM only, for compatibility */
static inline int __must_check
guest_physmap_add_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int page_order)
{
    return map_regions_p2mt(d, gfn, BIT(page_order, UL), mfn, p2m_ram_rw);
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

static inline void p2m_write_lock(struct p2m_domain *p2m)
{
    write_lock(&p2m->lock);
}

void p2m_write_unlock(struct p2m_domain *p2m);

static inline bool p2m_is_write_locked(struct p2m_domain *p2m)
{
    return rw_is_write_locked(&p2m->lock);
}

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
