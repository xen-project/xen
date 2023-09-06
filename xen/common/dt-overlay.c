/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/common/dt-overlay.c
 *
 * Device tree overlay support in Xen.
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc. All Rights Reserved.
 * Written by Vikram Garhwal <vikram.garhwal@amd.com>
 *
 */
#include <asm/domain_build.h>
#include <xen/dt-overlay.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <xen/libfdt/libfdt.h>
#include <xen/xmalloc.h>

static LIST_HEAD(overlay_tracker);
static DEFINE_SPINLOCK(overlay_lock);

/* Find last descendants of the device_node. */
static struct dt_device_node *
find_last_descendants_node(const struct dt_device_node *device_node)
{
    struct dt_device_node *child_node;

    for ( child_node = device_node->child; child_node->sibling != NULL;
          child_node = child_node->sibling );

    /* If last child_node also have children. */
    if ( child_node->child )
        child_node = find_last_descendants_node(child_node);

    return child_node;
}

static int dt_overlay_remove_node(struct dt_device_node *device_node)
{
    struct dt_device_node *np;
    struct dt_device_node *parent_node;
    struct dt_device_node *last_descendant = device_node->child;

    parent_node = device_node->parent;

    /* Check if we are trying to remove "/" i.e. root node. */
    if ( parent_node == NULL )
    {
        dt_dprintk("%s's parent node not found\n", device_node->name);
        return -EFAULT;
    }

    /* Sanity check for linking between parent and child node. */
    np = parent_node->child;
    if ( np == NULL )
    {
        dt_dprintk("parent node %s's not found\n", parent_node->name);
        return -EFAULT;
    }

    /* If node to be removed is only child node or first child. */
    if ( !dt_node_cmp(np->full_name, device_node->full_name) )
    {
        parent_node->child = np->sibling;

        /*
         * Iterate over all child nodes of device_node. Given that we are
         * removing a node, we need to remove all it's descendants too.
         * Reason behind finding last_descendant:
         * If device_node has multiple children, device_node->allnext will point
         * to first_child and first_child->allnext will be a sibling. When the
         * device_node and it's all children are removed, parent_node->allnext
         * should point to node next to last children.
         */
        if ( last_descendant )
        {
            last_descendant = find_last_descendants_node(device_node);
            parent_node->allnext = last_descendant->allnext;
        }
        else
            parent_node->allnext = np->allnext;

        return 0;
    }

    for ( np = parent_node->child; np->sibling != NULL; np = np->sibling )
    {
        if ( !dt_node_cmp(np->sibling->full_name, device_node->full_name) )
        {
            /* Found the node. Now we remove it. */
            np->sibling = np->sibling->sibling;

            if ( np->child )
                np = find_last_descendants_node(np);

            /*
             * Iterate over all child nodes of device_node. Given that we are
             * removing parent node, we need to remove all it's descendants too.
             */
            if ( last_descendant )
                last_descendant = find_last_descendants_node(device_node);

            if ( last_descendant )
                np->allnext = last_descendant->allnext;
            else
                np->allnext = np->allnext->allnext;

            break;
        }
    }

    return 0;
}

/* Basic sanity check for the dtbo tool stack provided to Xen. */
static int check_overlay_fdt(const void *overlay_fdt, uint32_t overlay_fdt_size)
{
    if ( (fdt_totalsize(overlay_fdt) != overlay_fdt_size) ||
          fdt_check_header(overlay_fdt) )
    {
        printk(XENLOG_ERR "The overlay FDT is not a valid Flat Device Tree\n");
        return -EINVAL;
    }

    return 0;
}

static int irq_remove_cb(unsigned long s, unsigned long e, void *dom,
                         unsigned long *c)
{
    int rc;
    struct domain *d = dom;

    /*
     * TODO: We don't handle shared IRQs for now. So, it is assumed that
     * the IRQs was not shared with another devices.
     * TODO: Undo the IRQ routing.
     */
    rc = irq_deny_access(d, s);
    if ( rc )
    {
        printk(XENLOG_ERR "unable to revoke access for irq %lu\n", s);
    }
    else
        *c += e - s + 1;

    return rc;

}

static int iomem_remove_cb(unsigned long s, unsigned long e, void *dom,
                           unsigned long *c)
{
    int rc;
    struct domain *d = dom;

    /*
    * Remove mmio access.
    * TODO: Support for remove/add the mapping in P2M.
    */
    rc = iomem_deny_access(d, s, e);
    if ( rc )
    {
        printk(XENLOG_ERR "Unable to remove dom%d access to"
               " 0x%"PRIx64" - 0x%"PRIx64"\n",
               d->domain_id,
               s & PAGE_MASK, PAGE_ALIGN(e) - 1);
    }
    else
        *c += e - s + 1;

    return rc;
}

/* Check if node itself can be removed and remove node from IOMMU. */
static int remove_node_resources(struct dt_device_node *device_node)
{
    int rc = 0;
    unsigned int len;
    domid_t domid;

    domid = dt_device_used_by(device_node);

    dt_dprintk("Checking if node %s is used by any domain\n",
               device_node->full_name);

    /* Remove the node if only it's assigned to hardware domain or domain io. */
    if ( domid != hardware_domain->domain_id && domid != DOMID_IO )
    {
        printk(XENLOG_ERR "Device %s is being used by domain %u. Removing nodes failed\n",
               device_node->full_name, domid);
        return -EINVAL;
    }

    /* Check if iommu property exists. */
    if ( dt_get_property(device_node, "iommus", &len) )
    {
        if ( dt_device_is_protected(device_node) )
        {
            rc = iommu_remove_dt_device(device_node);
            if ( rc < 0 )
                return rc;
        }
    }

    return rc;
}

/* Remove all descendants from IOMMU. */
static int
remove_descendant_nodes_resources(const struct dt_device_node *device_node)
{
    int rc = 0;
    struct dt_device_node *child_node;

    for ( child_node = device_node->child; child_node != NULL;
         child_node = child_node->sibling )
    {
        if ( child_node->child )
        {
            rc = remove_descendant_nodes_resources(child_node);
            if ( rc )
                return rc;
        }

        rc = remove_node_resources(child_node);
        if ( rc )
            return rc;
    }

    return rc;
}

/* Remove nodes from dt_host. */
static int remove_nodes(const struct overlay_track *tracker)
{
    int rc = 0;
    struct dt_device_node *overlay_node;
    unsigned int j;
    struct domain *d = hardware_domain;

    for ( j = 0; j < tracker->num_nodes; j++ )
    {
        overlay_node = (struct dt_device_node *)tracker->nodes_address[j];
        if ( overlay_node == NULL )
        {
            printk(XENLOG_ERR "Device %s is not present in the tree. Removing nodes failed\n",
                   overlay_node->full_name);
            return -EINVAL;
        }

        rc = remove_descendant_nodes_resources(overlay_node);
        if ( rc )
            return rc;

        rc = remove_node_resources(overlay_node);
        if ( rc )
            return rc;

        dt_dprintk("Removing node: %s\n", overlay_node->full_name);

        write_lock(&dt_host_lock);

        rc = dt_overlay_remove_node(overlay_node);
        if ( rc )
        {
            write_unlock(&dt_host_lock);
            return rc;
        }

        write_unlock(&dt_host_lock);
    }

    /* Remove IRQ access. */
    if ( tracker->irq_ranges )
    {
        rc = rangeset_consume_ranges(tracker->irq_ranges, irq_remove_cb, d);
        if ( rc )
            return rc;
    }

   /* Remove mmio access. */
    if ( tracker->iomem_ranges )
    {
        rc = rangeset_consume_ranges(tracker->iomem_ranges, iomem_remove_cb, d);
        if ( rc )
            return rc;
    }

    return rc;
}

/*
 * First finds the device node to remove. Check if the device is being used by
 * any dom and finally remove it from dt_host. IOMMU is already being taken care
 * while destroying the domain.
 */
static long handle_remove_overlay_nodes(const void *overlay_fdt,
                                        uint32_t overlay_fdt_size)
{
    int rc;
    struct overlay_track *entry, *temp, *track;
    bool found_entry = false;

    rc = check_overlay_fdt(overlay_fdt, overlay_fdt_size);
    if ( rc )
        return rc;

    spin_lock(&overlay_lock);

    /*
     * First check if dtbo is correct i.e. it should one of the dtbo which was
     * used when dynamically adding the node.
     * Limitation: Cases with same node names but different property are not
     * supported currently. We are relying on user to provide the same dtbo
     * as it was used when adding the nodes.
     */
    list_for_each_entry_safe( entry, temp, &overlay_tracker, entry )
    {
        if ( memcmp(entry->overlay_fdt, overlay_fdt, overlay_fdt_size) == 0 )
        {
            track = entry;
            found_entry = true;
            break;
        }
    }

    if ( !found_entry )
    {
        rc = -EINVAL;

        printk(XENLOG_ERR "Cannot find any matching tracker with input dtbo."
               " Removing nodes is supported only for prior added dtbo.\n");
        goto out;

    }

    rc = remove_nodes(entry);
    if ( rc )
    {
        printk(XENLOG_ERR "Removing node failed\n");
        goto out;
    }

    list_del(&entry->entry);

    xfree(entry->dt_host_new);
    xfree(entry->fdt);
    xfree(entry->overlay_fdt);

    xfree(entry->nodes_address);

    rangeset_destroy(entry->irq_ranges);
    rangeset_destroy(entry->iomem_ranges);

    xfree(entry);

 out:
    spin_unlock(&overlay_lock);
    return rc;
}

long dt_overlay_sysctl(struct xen_sysctl_dt_overlay *op)
{
    long ret;
    void *overlay_fdt;

    if ( op->overlay_op != XEN_SYSCTL_DT_OVERLAY_ADD &&
         op->overlay_op != XEN_SYSCTL_DT_OVERLAY_REMOVE )
        return -EOPNOTSUPP;

    if ( op->overlay_fdt_size == 0 || op->overlay_fdt_size > KB(500) )
        return -EINVAL;

    if ( op->pad[0] || op->pad[1] || op->pad[2] )
        return -EINVAL;

    overlay_fdt = xmalloc_bytes(op->overlay_fdt_size);

    if ( overlay_fdt == NULL )
        return -ENOMEM;

    ret = copy_from_guest(overlay_fdt, op->overlay_fdt, op->overlay_fdt_size);
    if ( ret )
    {
        gprintk(XENLOG_ERR, "copy from guest failed\n");
        xfree(overlay_fdt);

        return -EFAULT;
    }

    if ( op->overlay_op == XEN_SYSCTL_DT_OVERLAY_REMOVE )
        ret = handle_remove_overlay_nodes(overlay_fdt, op->overlay_fdt_size);

    xfree(overlay_fdt);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
