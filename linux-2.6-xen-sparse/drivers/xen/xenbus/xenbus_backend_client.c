/******************************************************************************
 * Backend-client-facing interface for the Xenbus driver.  In other words, the
 * interface between the Xenbus and the device-specific code in the backend
 * driver.
 *
 * Copyright (C) 2005-2006 XenSource Ltd
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include <xen/driver_util.h>

/* Based on Rusty Russell's skeleton driver's map_page */
int xenbus_map_ring_valloc(struct xenbus_device *dev, int gnt_ref, void **vaddr)
{
	struct gnttab_map_grant_ref op = {
		.flags = GNTMAP_host_map,
		.ref   = gnt_ref,
		.dom   = dev->otherend_id,
	};
	struct vm_struct *area;

	*vaddr = NULL;

	area = alloc_vm_area(PAGE_SIZE);
	if (!area)
		return -ENOMEM;

	op.host_addr = (unsigned long)area->addr;

	lock_vm_area(area);
	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1));
	unlock_vm_area(area);

	if (op.status != GNTST_okay) {
		free_vm_area(area);
		xenbus_dev_fatal(dev, op.status,
				 "mapping in shared page %d from domain %d",
				 gnt_ref, dev->otherend_id);
		return op.status;
	}

	/* Stuff the handle in an unused field */
	area->phys_addr = (unsigned long)op.handle;

	*vaddr = area->addr;
	return 0;
}
EXPORT_SYMBOL_GPL(xenbus_map_ring_valloc);


int xenbus_map_ring(struct xenbus_device *dev, int gnt_ref,
		   grant_handle_t *handle, void *vaddr)
{
	struct gnttab_map_grant_ref op = {
		.host_addr = (unsigned long)vaddr,
		.flags     = GNTMAP_host_map,
		.ref       = gnt_ref,
		.dom       = dev->otherend_id,
	};

	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1));

	if (op.status != GNTST_okay) {
		xenbus_dev_fatal(dev, op.status,
				 "mapping in shared page %d from domain %d",
				 gnt_ref, dev->otherend_id);
	} else
		*handle = op.handle;

	return op.status;
}
EXPORT_SYMBOL_GPL(xenbus_map_ring);


/* Based on Rusty Russell's skeleton driver's unmap_page */
int xenbus_unmap_ring_vfree(struct xenbus_device *dev, void *vaddr)
{
	struct vm_struct *area;
	struct gnttab_unmap_grant_ref op = {
		.host_addr = (unsigned long)vaddr,
	};

	/* It'd be nice if linux/vmalloc.h provided a find_vm_area(void *addr)
	 * method so that we don't have to muck with vmalloc internals here.
	 * We could force the user to hang on to their struct vm_struct from
	 * xenbus_map_ring_valloc, but these 6 lines considerably simplify
	 * this API.
	 */
	read_lock(&vmlist_lock);
	for (area = vmlist; area != NULL; area = area->next) {
		if (area->addr == vaddr)
			break;
	}
	read_unlock(&vmlist_lock);

	if (!area) {
		xenbus_dev_error(dev, -ENOENT,
				 "can't find mapped virtual address %p", vaddr);
		return GNTST_bad_virt_addr;
	}

	op.handle = (grant_handle_t)area->phys_addr;

	lock_vm_area(area);
	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));
	unlock_vm_area(area);

	if (op.status == GNTST_okay)
		free_vm_area(area);
	else
		xenbus_dev_error(dev, op.status,
				 "unmapping page at handle %d error %d",
				 (int16_t)area->phys_addr, op.status);

	return op.status;
}
EXPORT_SYMBOL_GPL(xenbus_unmap_ring_vfree);


int xenbus_unmap_ring(struct xenbus_device *dev,
		     grant_handle_t handle, void *vaddr)
{
	struct gnttab_unmap_grant_ref op = {
		.host_addr = (unsigned long)vaddr,
		.handle    = handle,
	};

	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));

	if (op.status != GNTST_okay)
		xenbus_dev_error(dev, op.status,
				 "unmapping page at handle %d error %d",
				 handle, op.status);

	return op.status;
}
EXPORT_SYMBOL_GPL(xenbus_unmap_ring);


/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
