#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#include <xen/grant_table.h>
#include <xen/kernel.h>
#include <xen/pfn.h>
#include <xen/sched.h>

#include <asm/guest_atomics.h>

#define INITIAL_NR_GRANT_FRAMES 1U
#define GNTTAB_MAX_VERSION 1

static inline void gnttab_clear_flags(struct domain *d,
                                      unsigned int mask, uint16_t *addr)
{
    guest_clear_mask16(d, mask, addr);
}

static inline void gnttab_mark_dirty(struct domain *d, mfn_t mfn)
{
#ifndef NDEBUG
    printk_once(XENLOG_G_WARNING "gnttab_mark_dirty not implemented yet\n");
#endif
}

static inline bool gnttab_host_mapping_get_page_type(bool ro,
                                                     const struct domain *ld,
                                                     const struct domain *rd)
{
    return false;
}

static inline bool gnttab_release_host_mappings(const struct domain *d)
{
    return true;
}

int create_grant_host_mapping(uint64_t gpaddr, mfn_t frame,
                              unsigned int flags, unsigned int cache_flags);
int replace_grant_host_mapping(uint64_t gpaddr, mfn_t frame,
                               uint64_t new_gpaddr, unsigned int flags);

/*
 * The region used by Xen on the memory will never be mapped in DOM0
 * memory layout. Therefore it can be used for the grant table.
 *
 * Only use the text section as it's always present and will contain
 * enough space for a large grant table
 */
#define gnttab_dom0_frames()                                             \
    min_t(unsigned int, opt_max_grant_frames, PFN_DOWN(_etext - _stext))

#define gnttab_set_frame_gfn(gt, st, idx, gfn, mfn)                      \
    (gfn_eq(gfn, INVALID_GFN)                                            \
     ? guest_physmap_remove_page((gt)->domain,                           \
                                 gnttab_get_frame_gfn(gt, st, idx),      \
                                 mfn, 0)                                 \
     : 0)

#define gnttab_get_frame_gfn(gt, st, idx) ({                             \
   (st) ? gnttab_status_gfn(NULL, gt, idx)                               \
        : gnttab_shared_gfn(NULL, gt, idx);                              \
})

#define gnttab_shared_page(t, i)   virt_to_page((t)->shared_raw[i])

#define gnttab_status_page(t, i)   virt_to_page((t)->status[i])

#define gnttab_shared_gfn(d, t, i)                                       \
    page_get_xenheap_gfn(gnttab_shared_page(t, i))

#define gnttab_status_gfn(d, t, i)                                       \
    page_get_xenheap_gfn(gnttab_status_page(t, i))

#define gnttab_need_iommu_mapping(d)                    \
    (is_domain_direct_mapped(d) && is_iommu_enabled(d))

#endif /* __ASM_GRANT_TABLE_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
