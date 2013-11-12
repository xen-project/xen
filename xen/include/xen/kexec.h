#ifndef __XEN_KEXEC_H__
#define __XEN_KEXEC_H__

#ifdef CONFIG_KEXEC

#include <public/kexec.h>
#include <asm/percpu.h>
#include <xen/elfcore.h>
#include <xen/kimage.h>

typedef struct xen_kexec_reserve {
    unsigned long size;
    unsigned long start;
} xen_kexec_reserve_t;

extern xen_kexec_reserve_t kexec_crash_area;

extern bool_t kexecing;

void set_kexec_crash_area_size(u64 system_ram);

/* We have space for 4 images to support atomic update
 * of images. This is important for CRASH images since
 * a panic can happen at any time...
 */

#define KEXEC_IMAGE_DEFAULT_BASE 0
#define KEXEC_IMAGE_CRASH_BASE   2
#define KEXEC_IMAGE_NR           4

enum low_crashinfo {
    LOW_CRASHINFO_INVALID = 0,
    LOW_CRASHINFO_NONE = 1,
    LOW_CRASHINFO_MIN = 2,
    LOW_CRASHINFO_ALL = 3
};

/* Low crashinfo mode.  Start as INVALID so serveral codepaths can set up
 * defaults without needing to know the state of the others. */
extern enum low_crashinfo low_crashinfo_mode;
extern paddr_t crashinfo_maxaddr_bits;
void kexec_early_calculations(void);

int machine_kexec_add_page(struct kexec_image *image, unsigned long vaddr,
                           unsigned long maddr);
int machine_kexec_load(struct kexec_image *image);
void machine_kexec_unload(struct kexec_image *image);
void machine_kexec_reserved(xen_kexec_reserve_t *reservation);
void machine_reboot_kexec(struct kexec_image *image);
void machine_kexec(struct kexec_image *image);
void kexec_crash(void);
void kexec_crash_save_cpu(void);
crash_xen_info_t *kexec_crash_save_info(void);
void machine_crash_shutdown(void);
int machine_kexec_get(xen_kexec_range_t *range);
int machine_kexec_get_xen(xen_kexec_range_t *range);

/* vmcoreinfo stuff */
#define VMCOREINFO_BYTES           (4096)
#define VMCOREINFO_NOTE_NAME       "VMCOREINFO_XEN"
void arch_crash_save_vmcoreinfo(void);
void vmcoreinfo_append_str(const char *fmt, ...)
       __attribute__ ((format (printf, 1, 2)));
#define VMCOREINFO_PAGESIZE(value) \
       vmcoreinfo_append_str("PAGESIZE=%ld\n", value)
#define VMCOREINFO_SYMBOL(name) \
       vmcoreinfo_append_str("SYMBOL(%s)=%lx\n", #name, (unsigned long)&name)
#define VMCOREINFO_SYMBOL_ALIAS(alias, name) \
       vmcoreinfo_append_str("SYMBOL(%s)=%lx\n", #alias, (unsigned long)&name)
#define VMCOREINFO_STRUCT_SIZE(name) \
       vmcoreinfo_append_str("SIZE(%s)=%zu\n", #name, sizeof(struct name))
#define VMCOREINFO_OFFSET(name, field) \
       vmcoreinfo_append_str("OFFSET(%s.%s)=%lu\n", #name, #field, \
                             (unsigned long)offsetof(struct name, field))
#define VMCOREINFO_OFFSET_SUB(name, sub, field) \
       vmcoreinfo_append_str("OFFSET(%s.%s)=%lu\n", #name, #field, \
                             (unsigned long)offsetof(struct name, sub.field))

#else /* !CONFIG_KEXEC */

#define crashinfo_maxaddr_bits 0

#endif

#endif /* __XEN_KEXEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
