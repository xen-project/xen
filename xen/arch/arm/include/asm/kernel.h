/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#ifndef __ARCH_ARM_KERNEL_H__
#define __ARCH_ARM_KERNEL_H__

#include <asm/domain.h>

#include <xen/types.h>

struct kernel_info;

struct arch_kernel_info
{
    /* Enable pl011 emulation */
    bool vpl011;
};

#define arch_hwdom_first_bank_can_fit_modules \
        arch_hwdom_first_bank_can_fit_modules
bool arch_hwdom_first_bank_can_fit_modules(const struct kernel_info *info,
                                           paddr_t bank_start,
                                           paddr_t bank_size);

#endif /* #ifdef __ARCH_ARM_KERNEL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
