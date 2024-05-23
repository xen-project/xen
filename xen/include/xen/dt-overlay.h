 /* SPDX-License-Identifier: GPL-2.0-only */
 /*
 * xen/dt-overlay.h
 *
 * Device tree overlay support in Xen.
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc. All Rights Reserved.
 * Written by Vikram Garhwal <vikram.garhwal@amd.com>
 *
 */
#ifndef __XEN_DT_OVERLAY_H__
#define __XEN_DT_OVERLAY_H__

#include <xen/device_tree.h>
#include <xen/list.h>
#include <xen/rangeset.h>

/*
 * overlay_track describes information about added nodes through dtbo.
 * @entry: List pointer.
 * @dt_host_new: Pointer to the updated dt_host_new which is unflattened from
    the 'updated fdt'.
 * @fdt: Stores the fdt.
 * @overlay_fdt: Stores a copy of input overlay_fdt.
 * @nodes_address: Stores each overlay_node's address.
 * @num_nodes: Total number of nodes in overlay dtb.
 * @iomem_ranges: Range set to keep track of all IOMEMs.
 * @irq_ranges: Range set to keep track of all added IRQs.
 */
struct overlay_track {
    struct list_head entry;
    struct dt_device_node *dt_host_new;
    void *fdt;
    void *overlay_fdt;
    unsigned long *nodes_address;
    unsigned int num_nodes;
    struct rangeset *iomem_ranges;
    struct rangeset *irq_ranges;
};

struct xen_sysctl_dt_overlay;
struct xen_domctl_dt_overlay;

#ifdef CONFIG_OVERLAY_DTB
long dt_overlay_sysctl(struct xen_sysctl_dt_overlay *op);
long dt_overlay_domctl(struct domain *d, struct xen_domctl_dt_overlay *op);
#else
#include <xen/errno.h>
static inline long dt_overlay_sysctl(struct xen_sysctl_dt_overlay *op)
{
    return -EOPNOTSUPP;
}

static inline long dt_overlay_domctl(struct domain *d,
                                     struct xen_domctl_dt_overlay *op)
{
    return -EOPNOTSUPP;
}
#endif

#endif /* __XEN_DT_OVERLAY_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
