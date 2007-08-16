/******************************************************************************
 * support.c
 * Xen module support functions.
 * Copyright (C) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <xen/evtchn.h>
#include <xen/interface/xen.h>
#include <asm/hypervisor.h>
#include "platform-pci.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#if defined (__ia64__)
unsigned long __hypercall(unsigned long a1, unsigned long a2,
			  unsigned long a3, unsigned long a4,
			  unsigned long a5, unsigned long cmd)
{
	unsigned long __res;
	__asm__ __volatile__ (";;\n"
		"mov r2=%1\n"
		"break 0x1000 ;;\n"
		"mov %0=r8 ;;\n"
		: "=r"(__res) : "r"(cmd) : "r2", "r8", "memory");

	return __res;
}
EXPORT_SYMBOL(__hypercall);

int HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count)
{
	return xencomm_hypercall_grant_table_op(cmd, uop, count);
}
EXPORT_SYMBOL(HYPERVISOR_grant_table_op);

/* without using balloon driver on PV-on-HVM for ia64 */
void balloon_update_driver_allowance(long delta)
{
	/* nothing */
}
EXPORT_SYMBOL_GPL(balloon_update_driver_allowance);

void balloon_release_driver_page(struct page *page)
{
	/* nothing */
}
EXPORT_SYMBOL_GPL(balloon_release_driver_page);
#endif /* __ia64__ */

void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
	BUG();
}
EXPORT_SYMBOL(xen_machphys_update);

