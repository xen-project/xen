#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#include <xen/grant_table.h>
#include <xen/kernel.h>
#include <xen/pfn.h>
#include <xen/sched.h>

#include <asm/guest_atomics.h>

#define INITIAL_NR_GRANT_FRAMES 1U
#define GNTTAB_MAX_VERSION 1

struct grant_table_arch {
    gfn_t *shared_gfn;
    gfn_t *status_gfn;
};

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

int create_grant_host_mapping(unsigned long gpaddr, mfn_t mfn,
                              unsigned int flags, unsigned int cache_flags);
#define gnttab_host_mapping_get_page_type(ro, ld, rd) (0)
int replace_grant_host_mapping(unsigned long gpaddr, mfn_t mfn,
                               unsigned long new_gpaddr, unsigned int flags);
#define gnttab_release_host_mappings(domain) 1

/*
 * The region used by Xen on the memory will never be mapped in DOM0
 * memory layout. Therefore it can be used for the grant table.
 *
 * Only use the text section as it's always present and will contain
 * enough space for a large grant table
 */
#define gnttab_dom0_frames()                                             \
    min_t(unsigned int, opt_max_grant_frames, PFN_DOWN(_etext - _stext))

#define gnttab_init_arch(gt)                                             \
({                                                                       \
    unsigned int ngf_ = (gt)->max_grant_frames;                          \
    unsigned int nsf_ = grant_to_status_frames(ngf_);                    \
                                                                         \
    (gt)->arch.shared_gfn = xmalloc_array(gfn_t, ngf_);                  \
    (gt)->arch.status_gfn = xmalloc_array(gfn_t, nsf_);                  \
    if ( (gt)->arch.shared_gfn && (gt)->arch.status_gfn )                \
    {                                                                    \
        while ( ngf_-- )                                                 \
            (gt)->arch.shared_gfn[ngf_] = INVALID_GFN;                   \
        while ( nsf_-- )                                                 \
            (gt)->arch.status_gfn[nsf_] = INVALID_GFN;                   \
    }                                                                    \
    else                                                                 \
        gnttab_destroy_arch(gt);                                         \
    (gt)->arch.shared_gfn ? 0 : -ENOMEM;                                 \
})

#define gnttab_destroy_arch(gt)                                          \
    do {                                                                 \
        XFREE((gt)->arch.shared_gfn);                                    \
        XFREE((gt)->arch.status_gfn);                                    \
    } while ( 0 )

#define gnttab_set_frame_gfn(gt, st, idx, gfn)                           \
    do {                                                                 \
        ((st) ? (gt)->arch.status_gfn : (gt)->arch.shared_gfn)[idx] =    \
            (gfn);                                                       \
    } while ( 0 )

#define gnttab_get_frame_gfn(gt, st, idx) ({                             \
   (st) ? gnttab_status_gfn(NULL, gt, idx)                               \
        : gnttab_shared_gfn(NULL, gt, idx);                              \
})

#define gnttab_shared_gfn(d, t, i)                                       \
    (((i) >= nr_grant_frames(t)) ? INVALID_GFN : (t)->arch.shared_gfn[i])

#define gnttab_status_gfn(d, t, i)                                       \
    (((i) >= nr_status_frames(t)) ? INVALID_GFN : (t)->arch.status_gfn[i])

#define gnttab_need_iommu_mapping(d)                    \
    (is_domain_direct_mapped(d) && need_iommu_pt_sync(d))

#endif /* __ASM_GRANT_TABLE_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
