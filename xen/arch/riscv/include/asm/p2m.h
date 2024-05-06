/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_RISCV_P2M_H__
#define __ASM_RISCV_P2M_H__

#include <asm/page-bits.h>

#define paddr_bits PADDR_BITS

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

static inline void p2m_altp2m_check(struct vcpu *v, uint16_t idx)
{
    /* Not supported on RISCV. */
}

#endif /* __ASM_RISCV_P2M_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
