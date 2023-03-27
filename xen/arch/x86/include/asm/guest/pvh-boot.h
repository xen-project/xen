/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/pvh-boot.h
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#ifndef __X86_PVH_BOOT_H__
#define __X86_PVH_BOOT_H__

#include <xen/multiboot.h>

#ifdef CONFIG_PVH_GUEST

extern bool pvh_boot;

void pvh_init(multiboot_info_t **mbi, module_t **mod);
void pvh_print_info(void);

#else

#include <xen/lib.h>

#define pvh_boot 0

static inline void pvh_init(multiboot_info_t **mbi, module_t **mod)
{
    ASSERT_UNREACHABLE();
}

static inline void pvh_print_info(void)
{
    ASSERT_UNREACHABLE();
}

#endif /* CONFIG_PVH_GUEST */
#endif /* __X86_PVH_BOOT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
