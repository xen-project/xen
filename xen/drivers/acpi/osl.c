/*
 *  acpi_osl.c - OS-dependent functions ($Revision: 83 $)
 *
 *  Copyright (C) 2000       Andrew Henroid
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 */
#include <asm/io.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/pfn.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/acpi.h>
#include <xen/numa.h>
#include <acpi/acmacros.h>
#include <acpi/acpiosxf.h>
#include <acpi/platform/aclinux.h>
#include <xen/spinlock.h>
#include <xen/domain_page.h>
#include <xen/efi.h>
#include <xen/vmap.h>
#include <xen/kconfig.h>

#define _COMPONENT		ACPI_OS_SERVICES
ACPI_MODULE_NAME("osl")

#ifdef CONFIG_ACPI_CUSTOM_DSDT
#include CONFIG_ACPI_CUSTOM_DSDT_FILE
#endif

void __init acpi_os_printf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	acpi_os_vprintf(fmt, args);
	va_end(args);
}

void __init acpi_os_vprintf(const char *fmt, va_list args)
{
	static char buffer[512];

	vsnprintf(buffer, sizeof(buffer), fmt, args);

	printk("%s", buffer);
}

acpi_physical_address __init acpi_os_get_root_pointer(void)
{
	if (efi_enabled) {
		if (efi.acpi20 != EFI_INVALID_TABLE_ADDR)
			return efi.acpi20;
		else if (efi.acpi != EFI_INVALID_TABLE_ADDR)
			return efi.acpi;
		else {
			printk(KERN_ERR PREFIX
			       "System description tables not found\n");
			return 0;
		}
	} else if (IS_ENABLED(CONFIG_ACPI_LEGACY_TABLES_LOOKUP)) {
		acpi_physical_address pa = 0;

		acpi_find_root_pointer(&pa);
		return pa;
	}

	return 0;
}

void __iomem *
acpi_os_map_memory(acpi_physical_address phys, acpi_size size)
{
	if (system_state >= SYS_STATE_active) {
		mfn_t mfn = _mfn(PFN_DOWN(phys));
		unsigned int offs = phys & (PAGE_SIZE - 1);

		/* The low first Mb is always mapped on x86. */
		if (IS_ENABLED(CONFIG_X86) && !((phys + size - 1) >> 20))
			return __va(phys);
		return __vmap(&mfn, PFN_UP(offs + size), 1, 1,
			      ACPI_MAP_MEM_ATTR, VMAP_DEFAULT) + offs;
	}
	return __acpi_map_table(phys, size);
}

void acpi_os_unmap_memory(void __iomem * virt, acpi_size size)
{
	if (system_state >= SYS_STATE_active)
		vunmap((void *)((unsigned long)virt & PAGE_MASK));
}

acpi_status acpi_os_read_port(acpi_io_address port, u32 * value, u32 width)
{
	u32 dummy;

	if (!value)
		value = &dummy;

	*value = 0;
	if (width <= 8) {
		*(u8 *) value = inb(port);
	} else if (width <= 16) {
		*(u16 *) value = inw(port);
	} else if (width <= 32) {
		*(u32 *) value = inl(port);
	} else {
		BUG();
	}

	return AE_OK;
}

acpi_status acpi_os_write_port(acpi_io_address port, u32 value, u32 width)
{
	if (width <= 8) {
		outb(value, port);
	} else if (width <= 16) {
		outw(value, port);
	} else if (width <= 32) {
		outl(value, port);
	} else {
		BUG();
	}

	return AE_OK;
}

acpi_status
acpi_os_read_memory(acpi_physical_address phys_addr, u32 * value, u32 width)
{
	u32 dummy;
	void __iomem *virt_addr = acpi_os_map_memory(phys_addr, width >> 3);

	if (!value)
		value = &dummy;

	switch (width) {
	case 8:
		*(u8 *) value = readb(virt_addr);
		break;
	case 16:
		*(u16 *) value = readw(virt_addr);
		break;
	case 32:
		*(u32 *) value = readl(virt_addr);
		break;
	default:
		BUG();
	}

	acpi_os_unmap_memory(virt_addr, width >> 3);

	return AE_OK;
}

acpi_status
acpi_os_write_memory(acpi_physical_address phys_addr, u32 value, u32 width)
{
	void __iomem *virt_addr = acpi_os_map_memory(phys_addr, width >> 3);

	switch (width) {
	case 8:
		writeb(value, virt_addr);
		break;
	case 16:
		writew(value, virt_addr);
		break;
	case 32:
		writel(value, virt_addr);
		break;
	default:
		BUG();
	}

	acpi_os_unmap_memory(virt_addr, width >> 3);

	return AE_OK;
}

#define is_xmalloc_memory(ptr) ((unsigned long)(ptr) & (PAGE_SIZE - 1))

void *__init acpi_os_alloc_memory(size_t sz)
{
	void *ptr;

	if (system_state == SYS_STATE_early_boot)
		return mfn_to_virt(alloc_boot_pages(PFN_UP(sz), 1));

	ptr = xmalloc_bytes(sz);
	ASSERT(!ptr || is_xmalloc_memory(ptr));
	return ptr;
}

void *__init acpi_os_zalloc_memory(size_t sz)
{
	void *ptr;

	if (system_state != SYS_STATE_early_boot) {
		ptr = xzalloc_bytes(sz);
		ASSERT(!ptr || is_xmalloc_memory(ptr));
		return ptr;
	}
	ptr = acpi_os_alloc_memory(sz);
	return ptr ? memset(ptr, 0, sz) : NULL;
}

void __init acpi_os_free_memory(void *ptr)
{
	if (is_xmalloc_memory(ptr))
		xfree(ptr);
	else if (ptr && system_state == SYS_STATE_early_boot)
		init_boot_pages(__pa(ptr), __pa(ptr) + PAGE_SIZE);
}
