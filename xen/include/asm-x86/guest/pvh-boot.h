/******************************************************************************
 * asm-x86/guest/pvh-boot.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
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
