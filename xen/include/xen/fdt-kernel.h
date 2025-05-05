/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * For Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#ifndef __XEN_FDT_KERNEL_H__
#define __XEN_FDT_KERNEL_H__

#include <xen/bootfdt.h>
#include <xen/device_tree.h>
#include <xen/types.h>

#if __has_include(<asm/kernel.h>)
#   include <asm/kernel.h>
#endif

struct kernel_info {
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

    /* Enable/Disable PV drivers interfaces */
    uint16_t dom0less_feature;

    /* Interrupt controller phandle */
    uint32_t phandle_intc;

    /* loader to use for this kernel */
    void (*load)(struct kernel_info *info);

    /* loader specific state */
    union {
        struct {
            paddr_t kernel_addr;
            paddr_t len;
#if defined(CONFIG_ARM_64) || defined(CONFIG_RISCV_64)
            paddr_t text_offset; /* 64-bit Image only */
#endif
            paddr_t start; /* Must be 0 for 64-bit Image */
        } zimage;
    };

#if __has_include(<asm/kernel.h>)
    struct arch_kernel_info arch;
#endif
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

#ifndef KERNEL_INFO_SHM_MEM_INIT

#ifdef CONFIG_STATIC_SHM
#define KERNEL_INFO_SHM_MEM_INIT                \
    .shm_mem.common.max_banks = NR_SHMEM_BANKS, \
    .shm_mem.common.type = STATIC_SHARED_MEMORY,
#else
#define KERNEL_INFO_SHM_MEM_INIT
#endif

#endif /* KERNEL_INFO_SHM_MEM_INIT */

#ifndef KERNEL_INFO_INIT

#define KERNEL_INFO_INIT                        \
{                                               \
    .mem.common.max_banks = NR_MEM_BANKS,       \
    .mem.common.type = MEMORY,                  \
    KERNEL_INFO_SHM_MEM_INIT                    \
}

#endif /* KERNEL_INFO_INIT */

/*
 * Probe the kernel to detemine its type and select a loader.
 *
 * Sets in info:
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

#endif /* __XEN_FDT_KERNEL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
