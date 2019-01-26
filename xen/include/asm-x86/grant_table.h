/******************************************************************************
 * include/asm-x86/grant_table.h
 *
 * Copyright (c) 2004-2005 K A Fraser
 */

#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#include <asm/paging.h>

#include <asm/hvm/grant_table.h>
#include <asm/pv/grant_table.h>

#define INITIAL_NR_GRANT_FRAMES 1U

struct grant_table_arch {
};

static inline int create_grant_host_mapping(uint64_t addr, mfn_t frame,
                                            unsigned int flags,
                                            unsigned int cache_flags)
{
    if ( paging_mode_external(current->domain) )
        return create_grant_p2m_mapping(addr, frame, flags, cache_flags);
    return create_grant_pv_mapping(addr, frame, flags, cache_flags);
}

static inline int replace_grant_host_mapping(uint64_t addr, mfn_t frame,
                                             uint64_t new_addr,
                                             unsigned int flags)
{
    if ( paging_mode_external(current->domain) )
        return replace_grant_p2m_mapping(addr, frame, new_addr, flags);
    return replace_grant_pv_mapping(addr, frame, new_addr, flags);
}

#define gnttab_init_arch(gt) 0
#define gnttab_destroy_arch(gt) do {} while ( 0 )
#define gnttab_set_frame_gfn(gt, st, idx, gfn) do {} while ( 0 )
#define gnttab_get_frame_gfn(gt, st, idx) ({                             \
    mfn_t mfn_ = (st) ? gnttab_status_mfn(gt, idx)                       \
                      : gnttab_shared_mfn(gt, idx);                      \
    unsigned long gpfn_ = get_gpfn_from_mfn(mfn_x(mfn_));                \
    VALID_M2P(gpfn_) ? _gfn(gpfn_) : INVALID_GFN;                        \
})

#define gnttab_shared_mfn(t, i) _mfn(__virt_to_mfn((t)->shared_raw[i]))

#define gnttab_shared_gfn(d, t, i) mfn_to_gfn(d, gnttab_shared_mfn(t, i))

#define gnttab_status_mfn(t, i) _mfn(__virt_to_mfn((t)->status[i]))

#define gnttab_status_gfn(d, t, i) mfn_to_gfn(d, gnttab_status_mfn(t, i))

#define gnttab_mark_dirty(d, f) paging_mark_dirty(d, f)

static inline void gnttab_clear_flags(struct domain *d,
                                      unsigned int mask, uint16_t *addr)
{
    /* Access must be confined to the specified 2 bytes. */
    asm volatile ("lock andw %1,%0" : "+m" (*addr) : "ir" ((uint16_t)~mask));
}

/* Foreign mappings of HVM-guest pages do not modify the type count. */
#define gnttab_host_mapping_get_page_type(ro, ld, rd)   \
    (!(ro) && (((ld) == (rd)) || !paging_mode_external(rd)))

/* Done implicitly when page tables are destroyed. */
#define gnttab_release_host_mappings(domain) ( paging_mode_external(domain) )

#define gnttab_need_iommu_mapping(d)                \
    (!paging_mode_translate(d) && need_iommu_pt_sync(d))

#endif /* __ASM_GRANT_TABLE_H__ */
