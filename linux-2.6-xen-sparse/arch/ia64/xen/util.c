/******************************************************************************
 * arch/ia64/xen/util.c
 * This file is the ia64 counterpart of drivers/xen/util.c
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <xen/driver_util.h>
#include <xen/interface/memory.h>
#include <asm/hypercall.h>

struct vm_struct *alloc_vm_area(unsigned long size)
{
	int order;
	unsigned long virt;
	unsigned long nr_pages;
	struct vm_struct* area;
	
	order = get_order(size);
	virt = __get_free_pages(GFP_KERNEL, order);
	if (virt == 0) {
		goto err0;
	}
	nr_pages = 1 << order;
	scrub_pages(virt, nr_pages);
	
	area = kmalloc(sizeof(*area), GFP_KERNEL);
	if (area == NULL) {
		goto err1;
	}
	
        area->flags = VM_IOREMAP;//XXX
        area->addr = (void*)virt;
        area->size = size;
        area->pages = NULL; //XXX
        area->nr_pages = nr_pages;
        area->phys_addr = 0; 	/* xenbus_map_ring_valloc uses this field!  */

	return area;

err1:
	free_pages(virt, order);
err0:
	return NULL;
	
}
EXPORT_SYMBOL_GPL(alloc_vm_area);

void free_vm_area(struct vm_struct *area)
{
	unsigned int order = get_order(area->size);
	unsigned long i;
	unsigned long phys_addr = __pa(area->addr);

	// This area is used for foreign page mappping.
	// So underlying machine page may not be assigned.
	for (i = 0; i < (1 << order); i++) {
		unsigned long ret;
		unsigned long gpfn = (phys_addr >> PAGE_SHIFT) + i;
		struct xen_memory_reservation reservation = {
			.nr_extents   = 1,
			.address_bits = 0,
			.extent_order = 0,
			.domid        = DOMID_SELF
		};
		set_xen_guest_handle(reservation.extent_start, &gpfn);
		ret = HYPERVISOR_memory_op(XENMEM_populate_physmap,
					   &reservation);
		BUG_ON(ret != 1);
	}
	free_pages((unsigned long)area->addr, order);
	kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
