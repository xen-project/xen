/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#ifndef __ARCH_ARM_KERNEL_H__
#define __ARCH_ARM_KERNEL_H__

#include <xen/libelf.h>

struct kernel_info {
    paddr_t entry;
    paddr_t ram_start;
    paddr_t ram_end;

    void *kernel_img;
    unsigned kernel_order;

    union {
        struct {
            paddr_t load_addr;
            paddr_t len;
        } zimage;

        struct {
            struct elf_binary elf;
            struct elf_dom_parms parms;
        } elf;
    };

    void (*load)(struct kernel_info *info);
};

int kernel_prepare(struct kernel_info *info);
void kernel_load(struct kernel_info *info);

#endif /* #ifdef __ARCH_ARM_KERNEL_H__ */
