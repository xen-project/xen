/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#ifndef __ARCH_ARM_KERNEL_H__
#define __ARCH_ARM_KERNEL_H__

#include <xen/device_tree.h>
#include <asm/domain.h>
#include <asm/setup.h>

/*
 * List of possible features for dom0less domUs
 *
 * DOM0LESS_ENHANCED_NO_XS: Notify the OS it is running on top of Xen. All the
 *                          default features (excluding Xenstore) will be
 *                          available. Note that an OS *must* not rely on the
 *                          availability of Xen features if this is not set.
 * DOM0LESS_XENSTORE:       Xenstore will be enabled for the VM. This feature
 *                          can't be enabled without the
 *                          DOM0LESS_ENHANCED_NO_XS.
 * DOM0LESS_ENHANCED:       Notify the OS it is running on top of Xen. All the
 *                          default features (including Xenstore) will be
 *                          available. Note that an OS *must* not rely on the
 *                          availability of Xen features if this is not set.
 */
#define DOM0LESS_ENHANCED_NO_XS  BIT(0, U)
#define DOM0LESS_XENSTORE        BIT(1, U)
#define DOM0LESS_ENHANCED        (DOM0LESS_ENHANCED_NO_XS | DOM0LESS_XENSTORE)

struct kernel_info {
#ifdef CONFIG_ARM_64
    enum domain_type type;
#endif

    struct domain *d;

    void *fdt; /* flat device tree */
    paddr_t unassigned_mem; /* RAM not (yet) assigned to a bank */
    struct meminfo mem;
#ifdef CONFIG_STATIC_SHM
    struct shared_meminfo shm_mem;
#endif

    /* kernel entry point */
    paddr_t entry;

    /* grant table region */
    paddr_t gnttab_start;
    paddr_t gnttab_size;

    /* boot blob load addresses */
    const struct bootmodule *kernel_bootmodule, *initrd_bootmodule, *dtb_bootmodule;
    const char* cmdline;
    paddr_t dtb_paddr;
    paddr_t initrd_paddr;

    /* Enable pl011 emulation */
    bool vpl011;

    /* Enable/Disable PV drivers interfaces */
    uint16_t dom0less_feature;

    /* GIC phandle */
    uint32_t phandle_gic;

    /* loader to use for this kernel */
    void (*load)(struct kernel_info *info);
    /* loader specific state */
    union {
        struct {
            paddr_t kernel_addr;
            paddr_t len;
#ifdef CONFIG_ARM_64
            paddr_t text_offset; /* 64-bit Image only */
#endif
            paddr_t start; /* Must be 0 for 64-bit Image */
        } zimage;
    };
};

static inline struct membanks *kernel_info_get_mem(struct kernel_info *kinfo)
{
    return container_of(&kinfo->mem.common, struct membanks, common);
}

static inline const struct membanks *
kernel_info_get_mem_const(const struct kernel_info *kinfo)
{
    return container_of(&kinfo->mem.common, const struct membanks, common);
}

#ifdef CONFIG_STATIC_SHM
#define KERNEL_INFO_SHM_MEM_INIT                \
    .shm_mem.common.max_banks = NR_SHMEM_BANKS, \
    .shm_mem.common.type = STATIC_SHARED_MEMORY,
#else
#define KERNEL_INFO_SHM_MEM_INIT
#endif

#define KERNEL_INFO_INIT                        \
{                                               \
    .mem.common.max_banks = NR_MEM_BANKS,       \
    .mem.common.type = MEMORY,                  \
    KERNEL_INFO_SHM_MEM_INIT                    \
}

/*
 * Probe the kernel to detemine its type and select a loader.
 *
 * Sets in info:
 *  ->type
 *  ->load hook, and sets loader specific variables ->zimage
 */
int kernel_probe(struct kernel_info *info, const struct dt_device_node *domain);

/*
 * Loads the kernel into guest RAM.
 *
 * Expects to be set in info when called:
 *  ->mem
 *  ->fdt
 *
 * Sets in info:
 *  ->entry
 *  ->dtb_paddr
 *  ->initrd_paddr
 */
void kernel_load(struct kernel_info *info);

#endif /* #ifdef __ARCH_ARM_KERNEL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
