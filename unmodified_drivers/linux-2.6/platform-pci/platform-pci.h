/******************************************************************************
 * evtchn-pci.h
 * module driver support in unmodified Linux
 * Copyright (C) 2004, Intel Corporation. <xiaofeng.ling@intel.com>
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

#ifndef __XEN_SUPPORT_H
#define __XEN_SUPPORT_H
#include <linux/version.h>
#include <linux/interrupt.h>
#include <xen/interface/hvm/params.h>

static inline int set_callback_via(uint64_t via)
{
	struct xen_hvm_param a;

	a.domid = DOMID_SELF;
	a.index = HVM_PARAM_CALLBACK_IRQ;
	a.value = via;
	return HYPERVISOR_hvm_op(HVMOP_set_param, &a);
}

unsigned long alloc_xen_mmio(unsigned long len);

int gnttab_init(void);

void setup_xen_features(void);

irqreturn_t evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs);

#endif
