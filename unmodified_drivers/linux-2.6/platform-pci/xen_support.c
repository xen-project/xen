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

EXPORT_SYMBOL(xen_machphys_update);
void xen_machphys_update(unsigned long mfn, unsigned long pfn)
{
	BUG();
}

void balloon_update_driver_allowance(long delta)
{
}

EXPORT_SYMBOL(balloon_update_driver_allowance);
