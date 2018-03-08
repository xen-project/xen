#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#include <xen/grant_table.h>
#include <xen/kernel.h>
#include <xen/pfn.h>
#include <xen/sched.h>

#define INITIAL_NR_GRANT_FRAMES 1U

struct grant_table_arch {
    gfn_t *shared_gfn;
    gfn_t *status_gfn;
};

void gnttab_clear_flag(unsigned long nr, uint16_t *addr);
int create_grant_host_mapping(unsigned long gpaddr,
        unsigned long mfn, unsigned int flags, unsigned int
        cache_flags);
#define gnttab_host_mapping_get_page_type(ro, ld, rd) (0)
int replace_grant_host_mapping(unsigned long gpaddr, unsigned long mfn,
        unsigned long new_gpaddr, unsigned int flags);
void gnttab_mark_dirty(struct domain *d, unsigned long l);
#define gnttab_create_status_page(d, t, i) do {} while (0)
#define gnttab_release_host_mappings(domain) 1
static inline int replace_grant_supported(void)
{
    return 1;
}

/*
 * The region used by Xen on the memory will never be mapped in DOM0
 * memory layout. Therefore it can be used for the grant table.
 *
 * Only use the text section as it's always present and will contain
 * enough space for a large grant table
 */
static inline unsigned int gnttab_dom0_max(void)
{
    return PFN_DOWN(_etext - _stext);
}

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
        xfree((gt)->arch.shared_gfn);                                    \
        (gt)->arch.shared_gfn = NULL;                                    \
        xfree((gt)->arch.status_gfn);                                    \
        (gt)->arch.status_gfn = NULL;                                    \
    } while ( 0 )

#define gnttab_set_frame_gfn(gt, st, idx, gfn)                           \
    do {                                                                 \
        ((st) ? (gt)->arch.status_gfn : (gt)->arch.shared_gfn)[idx] =    \
            (gfn);                                                       \
    } while ( 0 )

#define gnttab_get_frame_gfn(gt, st, idx) ({                             \
   _gfn((st) ? gnttab_status_gmfn(NULL, gt, idx)                         \
             : gnttab_shared_gmfn(NULL, gt, idx));                       \
})

#define gnttab_create_shared_page(d, t, i)                               \
    do {                                                                 \
        share_xen_page_with_guest(                                       \
            virt_to_page((char *)(t)->shared_raw[i]), d, SHARE_rw);      \
    } while ( 0 )

#define gnttab_shared_gmfn(d, t, i)                                      \
    gfn_x(((i) >= nr_grant_frames(t)) ? INVALID_GFN : (t)->arch.shared_gfn[i])

#define gnttab_status_gmfn(d, t, i)                                      \
    gfn_x(((i) >= nr_status_frames(t)) ? INVALID_GFN : (t)->arch.status_gfn[i])

#define gnttab_need_iommu_mapping(d)                    \
    (is_domain_direct_mapped(d) && need_iommu(d))

#endif /* __ASM_GRANT_TABLE_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
