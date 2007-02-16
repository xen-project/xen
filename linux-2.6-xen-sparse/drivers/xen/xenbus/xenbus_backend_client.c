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

#include <linux/err.h>
#include <xen/gnttab.h>
#include <xen/xenbus.h>
#include <xen/driver_util.h>

/* Based on Rusty Russell's skeleton driver's map_page */
struct vm_struct *xenbus_map_ring_valloc(struct xenbus_device *dev, int gnt_ref)
{
	struct gnttab_map_grant_ref op;
	struct vm_struct *area;

	area = alloc_vm_area(PAGE_SIZE);
	if (!area)
		return ERR_PTR(-ENOMEM);

	gnttab_set_map_op(&op, (unsigned long)area->addr, GNTMAP_host_map,
			  gnt_ref, dev->otherend_id);
	
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1))
		BUG();

	if (op.status != GNTST_okay) {
		free_vm_area(area);
		xenbus_dev_fatal(dev, op.status,
				 "mapping in shared page %d from domain %d",
				 gnt_ref, dev->otherend_id);
		BUG_ON(!IS_ERR(ERR_PTR(op.status)));
		return ERR_PTR(op.status);
	}

	/* Stuff the handle in an unused field */
	area->phys_addr = (unsigned long)op.handle;

	return area;
}
EXPORT_SYMBOL_GPL(xenbus_map_ring_valloc);


int xenbus_map_ring(struct xenbus_device *dev, int gnt_ref,
		   grant_handle_t *handle, void *vaddr)
{
	struct gnttab_map_grant_ref op;
	
	gnttab_set_map_op(&op, (unsigned long)vaddr, GNTMAP_host_map,
			  gnt_ref, dev->otherend_id);
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1))
		BUG();

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
int xenbus_unmap_ring_vfree(struct xenbus_device *dev, struct vm_struct *area)
{
	struct gnttab_unmap_grant_ref op;

	gnttab_set_unmap_op(&op, (unsigned long)area->addr, GNTMAP_host_map,
			    (grant_handle_t)area->phys_addr);

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1))
		BUG();

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
	struct gnttab_unmap_grant_ref op;

	gnttab_set_unmap_op(&op, (unsigned long)vaddr, GNTMAP_host_map,
			    handle);
	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1))
		BUG();

	if (op.status != GNTST_okay)
		xenbus_dev_error(dev, op.status,
				 "unmapping page at handle %d error %d",
				 handle, op.status);

	return op.status;
}
EXPORT_SYMBOL_GPL(xenbus_unmap_ring);

int xenbus_dev_is_online(struct xenbus_device *dev)
{
	int rc, val;

	rc = xenbus_scanf(XBT_NIL, dev->nodename, "online", "%d", &val);
	if (rc != 1)
		val = 0; /* no online node present */

	return val;
}
EXPORT_SYMBOL_GPL(xenbus_dev_is_online);

MODULE_LICENSE("Dual BSD/GPL");
