#ifndef __XEN_KIMAGE_H__
#define __XEN_KIMAGE_H__

#define IND_DESTINATION  0x1
#define IND_INDIRECTION  0x2
#define IND_DONE         0x4
#define IND_SOURCE       0x8
#define IND_ZERO        0x10

#ifndef __ASSEMBLY__

#include <xen/list.h>
#include <xen/mm.h>
#include <public/kexec.h>

#define KEXEC_SEGMENT_MAX 16

typedef paddr_t kimage_entry_t;

struct kexec_image {
    uint8_t type;
    uint16_t arch;
    uint64_t entry_maddr;
    uint32_t nr_segments;
    xen_kexec_segment_t *segments;

    kimage_entry_t head;
    struct page_info *entry_page;
    unsigned next_entry;

    struct page_info *control_code_page;
    struct page_info *aux_page;

    struct page_list_head control_pages;
    struct page_list_head dest_pages;
    struct page_list_head unusable_pages;

    /* Address of next control page to allocate for crash kernels. */
    paddr_t next_crash_page;
};

int kimage_alloc(struct kexec_image **rimage, uint8_t type, uint16_t arch,
                 uint64_t entry_maddr,
                 uint32_t nr_segments, xen_kexec_segment_t *segment);
void kimage_free(struct kexec_image *image);
int kimage_load_segments(struct kexec_image *image);
struct page_info *kimage_alloc_control_page(struct kexec_image *image,
                                            unsigned memflags);

kimage_entry_t *kimage_entry_next(kimage_entry_t *entry, bool_t compat);
mfn_t kimage_entry_mfn(kimage_entry_t *entry, bool_t compat);
unsigned long kimage_entry_ind(kimage_entry_t *entry, bool_t compat);
int kimage_build_ind(struct kexec_image *image, mfn_t ind_mfn,
                     bool_t compat);

#endif /* __ASSEMBLY__ */

#endif /* __XEN_KIMAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
