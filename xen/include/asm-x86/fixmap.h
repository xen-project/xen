/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Modifications for Xen are copyright (c) 2002-2004, K A Fraser
 */

#ifndef _ASM_FIXMAP_H
#define _ASM_FIXMAP_H

#include <xen/config.h>
#include <asm/acpi.h>
#include <asm/apicdef.h>
#include <asm/page.h>

/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process. We allocate these special addresses
 * from the end of virtual memory backwards.
 */
enum fixed_addresses {
#ifdef CONFIG_X86_LOCAL_APIC
    FIX_APIC_BASE,	/* local (CPU) APIC -- required for SMP or not */
#endif
#ifdef CONFIG_X86_IO_APIC
    FIX_IO_APIC_BASE_0,
    FIX_IO_APIC_BASE_END = FIX_IO_APIC_BASE_0 + MAX_IO_APICS-1,
#endif
#ifdef CONFIG_ACPI_BOOT
    FIX_ACPI_BEGIN,
    FIX_ACPI_END = FIX_ACPI_BEGIN + FIX_ACPI_PAGES - 1,
#endif
    __end_of_fixed_addresses
};

#define FIXADDR_TOP   (0xffffe000UL)
#define FIXADDR_SIZE  (__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START (FIXADDR_TOP - FIXADDR_SIZE)

extern void __set_fixmap(enum fixed_addresses idx,
                         l1_pgentry_t entry);

#define set_fixmap(idx, phys) \
    __set_fixmap(idx, mk_l1_pgentry(phys|PAGE_HYPERVISOR))

#define set_fixmap_nocache(idx, phys) \
    __set_fixmap(idx, mk_l1_pgentry(phys|PAGE_HYPERVISOR_NOCACHE))

#define fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))

#endif
