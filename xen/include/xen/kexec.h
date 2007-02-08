#ifndef __XEN_KEXEC_H__
#define __XEN_KEXEC_H__

#include <public/kexec.h>
#include <asm/percpu.h>
#include <xen/elfcore.h>

typedef struct xen_kexec_reserve {
    unsigned long size;
    unsigned long start;
} xen_kexec_reserve_t;

extern xen_kexec_reserve_t kexec_crash_area;

/* We have space for 4 images to support atomic update
 * of images. This is important for CRASH images since
 * a panic can happen at any time...
 */

#define KEXEC_IMAGE_DEFAULT_BASE 0
#define KEXEC_IMAGE_CRASH_BASE   2
#define KEXEC_IMAGE_NR           4

int machine_kexec_load(int type, int slot, xen_kexec_image_t *image);
void machine_kexec_unload(int type, int slot, xen_kexec_image_t *image);
void machine_kexec_reserved(xen_kexec_reserve_t *reservation);
void machine_reboot_kexec(xen_kexec_image_t *image);
void machine_kexec(xen_kexec_image_t *image);
void kexec_crash(void);
void kexec_crash_save_cpu(void);
crash_xen_info_t *kexec_crash_save_info(void);
void machine_crash_shutdown(void);

#endif /* __XEN_KEXEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
