/* SPDX-License-Identifier: GPL-2.0-only */
/*
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

#define DT_OVERLAY_MAX_SIZE KB(500)

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

/*
 * Returns next node to the input node. If node has children then return
 * last descendant's next node.
*/
static struct dt_device_node *
dt_find_next_node(struct dt_device_node *dt, const struct dt_device_node *node)
{
    struct dt_device_node *np;

    dt_for_each_device_node(dt, np)
        if ( np == node )
            break;

    if ( np->child )
        np = find_last_descendants_node(np);

    return np->allnext;
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

static int dt_overlay_add_node(struct dt_device_node *device_node,
                               const char *parent_node_path)
{
    struct dt_device_node *parent_node;
    struct dt_device_node *next_node;

    parent_node = dt_find_node_by_path(parent_node_path);

    if ( parent_node == NULL )
    {
        dt_dprintk("Parent node %s not found. Overlay node will not be added\n",
                   parent_node_path);
        return -EINVAL;
    }

    /* If parent has no child. */
    if ( parent_node->child == NULL )
    {
        next_node = parent_node->allnext;
        device_node->parent = parent_node;
        parent_node->allnext = device_node;
        parent_node->child = device_node;
    }
    else
    {
        struct dt_device_node *np;
        /*
         * If parent has at least one child node.
         * Iterate to the last child node of parent.
         */
        for ( np = parent_node->child; np->sibling != NULL; np = np->sibling );

        /* Iterate over all child nodes of np node. */
        if ( np->child )
        {
            struct dt_device_node *np_last_descendant;

            np_last_descendant = find_last_descendants_node(np);

            next_node = np_last_descendant->allnext;
            np_last_descendant->allnext = device_node;
        }
        else
        {
            next_node = np->allnext;
            np->allnext = device_node;
        }

        device_node->parent = parent_node;
        np->sibling = device_node;
        np->sibling->sibling = NULL;
    }

    /* Iterate over all child nodes of device_node to add children too. */
    if ( device_node->child )
    {
        struct dt_device_node *device_node_last_descendant;

        device_node_last_descendant = find_last_descendants_node(device_node);

        /* Plug next_node at the end of last children of device_node. */
        device_node_last_descendant->allnext = next_node;
    }
    else
    {
        /* Now plug next_node at the end of device_node. */
        device_node->allnext = next_node;
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
        printk(XENLOG_ERR "Unable to remove %pd access to %#lx - %#lx\n",
               d, s, e);
    }
    else
        *c += e - s + 1;

    return rc;
}

/* Count number of nodes till one level of __overlay__ tag. */
static unsigned int overlay_node_count(const void *overlay_fdt)
{
    unsigned int num_overlay_nodes = 0;
    int fragment;

    fdt_for_each_subnode(fragment, overlay_fdt, 0)
    {
        int subnode;
        int overlay;

        overlay = fdt_subnode_offset(overlay_fdt, fragment, "__overlay__");
        if ( overlay < 0 )
            continue;

        fdt_for_each_subnode(subnode, overlay_fdt, overlay)
        {
            num_overlay_nodes++;
        }
    }

    return num_overlay_nodes;
}

/*
 * overlay_get_nodes_info gets full name with path for all the nodes which
 * are in one level of __overlay__ tag. This is useful when checking node for
 * duplication i.e. dtbo tries to add nodes which already exists in device tree.
 */
static int overlay_get_nodes_info(const void *fdto, char **nodes_full_path)
{
    int fragment;
    unsigned int node_num = 0;

    fdt_for_each_subnode(fragment, fdto, 0)
    {
        int target;
        int overlay;
        int subnode;
        const char *target_path;

        overlay = fdt_subnode_offset(fdto, fragment, "__overlay__");
        if ( overlay < 0 )
            continue;

        target = fdt_overlay_target_offset(device_tree_flattened, fdto,
                                           fragment, &target_path);
        if ( target < 0 )
            return target;

        if ( target_path == NULL )
            return -EINVAL;

        fdt_for_each_subnode(subnode, fdto, overlay)
        {
            const char *node_name = NULL;
            int node_name_len;
            unsigned int target_path_len = strlen(target_path);
            unsigned int node_full_name_len;
            unsigned int extra_len;

            node_name = fdt_get_name(fdto, subnode, &node_name_len);

            if ( node_name == NULL )
                return node_name_len;

            /*
             * Extra length is for adding '/' and '\0' unless the target path is
             * root in which case we don't add the '/' at the beginning. This is
             * done to keep the node_full_path in the correct full node name
             * format.
             */
            extra_len = (target_path_len > 1) ? 2 : 1;
            node_full_name_len = target_path_len + node_name_len + extra_len;

            nodes_full_path[node_num] = xmalloc_bytes(node_full_name_len);

            if ( nodes_full_path[node_num] == NULL )
                return -ENOMEM;

            memcpy(nodes_full_path[node_num], target_path, target_path_len);

            /* Target is not root - add separator */
            if ( target_path_len > 1 )
                nodes_full_path[node_num][target_path_len++] = '/';

            memcpy(nodes_full_path[node_num] + target_path_len,
                    node_name, node_name_len);

            nodes_full_path[node_num][node_full_name_len - 1] = '\0';

            node_num++;
        }
    }

    return 0;
}

/* This function should be called with the overlay_lock taken */
static struct overlay_track *
find_track_entry_from_tracker(const void *overlay_fdt,
                              uint32_t overlay_fdt_size)
{
    struct overlay_track *entry, *temp;
    bool found_entry = false;

    ASSERT(spin_is_locked(&overlay_lock));

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
            found_entry = true;
            break;
        }
    }

    if ( !found_entry )
    {
        printk(XENLOG_ERR "Cannot find any matching tracker with input dtbo."
               " Operation is supported only for prior added dtbo.\n");
        return NULL;
    }

    return entry;
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
            return -EINVAL;

        write_lock(&dt_host_lock);

        rc = remove_descendant_nodes_resources(overlay_node);
        if ( rc )
        {
            write_unlock(&dt_host_lock);
            return rc;
        }

        rc = remove_node_resources(overlay_node);
        if ( rc )
        {
            write_unlock(&dt_host_lock);
            return rc;
        }

        dt_dprintk("Removing node: %s\n", overlay_node->full_name);

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
    struct overlay_track *entry;

    rc = check_overlay_fdt(overlay_fdt, overlay_fdt_size);
    if ( rc )
        return rc;

    spin_lock(&overlay_lock);

    entry = find_track_entry_from_tracker(overlay_fdt, overlay_fdt_size);
    if ( entry == NULL )
    {
        rc = -EINVAL;
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

static void free_nodes_full_path(unsigned int num_nodes, char **nodes_full_path)
{
    unsigned int i;

    if ( nodes_full_path == NULL )
        return;

    for ( i = 0; i < num_nodes && nodes_full_path[i] != NULL; i++ )
    {
        xfree(nodes_full_path[i]);
    }

    xfree(nodes_full_path);
}

static long add_nodes(struct overlay_track *tr, char **nodes_full_path)

{
    int rc;
    unsigned int j;
    struct dt_device_node *overlay_node;

    for ( j = 0; j < tr->num_nodes; j++ )
    {
        struct dt_device_node *prev_node, *next_node;

        dt_dprintk("Adding node: %s\n", nodes_full_path[j]);

        /* Find the newly added node in tr->dt_host_new by it's full path. */
        overlay_node = dt_find_node_by_path_from(tr->dt_host_new,
                                                 nodes_full_path[j]);
        if ( overlay_node == NULL )
            return -EFAULT;

        /*
         * Find previous and next node to overlay_node in dt_host_new. We will
         * need these nodes to fix the dt_host_new mapping. When overlay_node is
         * take out of dt_host_new tree and added to dt_host, link between
         * previous node and next_node is broken. We will need to refresh
         * dt_host_new with correct linking for any other overlay nodes
         * extraction in future.
         */
        dt_for_each_device_node(tr->dt_host_new, prev_node)
            if ( prev_node->allnext == overlay_node )
                break;

        next_node = dt_find_next_node(tr->dt_host_new, overlay_node);

        write_lock(&dt_host_lock);

        /* Add the node to dt_host. */
        rc = dt_overlay_add_node(overlay_node, overlay_node->parent->full_name);
        if ( rc )
        {
            write_unlock(&dt_host_lock);

            /* Node not added in dt_host. */
            return rc;
        }

        prev_node->allnext = next_node;

        overlay_node = dt_find_node_by_path(overlay_node->full_name);
        if ( overlay_node == NULL )
        {
            /* Sanity check. But code will never come here. */
            ASSERT_UNREACHABLE();
            return -EFAULT;
        }

        write_unlock(&dt_host_lock);

        /* Keep overlay_node address in tracker. */
        tr->nodes_address[j] = (unsigned long)overlay_node;
    }

    return 0;
}
/*
 * Adds device tree nodes under target node.
 * We use tr->dt_host_new to unflatten the updated device_tree_flattened.
 */
static long handle_add_overlay_nodes(void *overlay_fdt,
                                     uint32_t overlay_fdt_size)
{
    int rc;
    unsigned int j;
    struct dt_device_node *overlay_node;
    struct overlay_track *tr = NULL;
    char **nodes_full_path = NULL;
    unsigned int new_fdt_size;

    tr = xzalloc(struct overlay_track);
    if ( tr == NULL )
        return -ENOMEM;

    new_fdt_size = fdt_totalsize(device_tree_flattened) +
                                 fdt_totalsize(overlay_fdt);

    tr->fdt = xzalloc_bytes(new_fdt_size);
    if ( tr->fdt == NULL )
    {
        xfree(tr);
        return -ENOMEM;
    }

    tr->num_nodes = overlay_node_count(overlay_fdt);
    if ( tr->num_nodes == 0 )
    {
        xfree(tr->fdt);
        xfree(tr);
        return -ENOMEM;
    }

    tr->nodes_address = xzalloc_bytes(tr->num_nodes * sizeof(unsigned long));
    if ( tr->nodes_address == NULL )
    {
        xfree(tr->fdt);
        xfree(tr);
        return -ENOMEM;
    }

    rc = check_overlay_fdt(overlay_fdt, overlay_fdt_size);
    if ( rc )
    {
        xfree(tr->nodes_address);
        xfree(tr->fdt);
        xfree(tr);
        return rc;
    }

    /*
     * Keep a copy of overlay_fdt as fdt_overlay_apply will change the input
     * overlay's content(magic) when applying overlay.
     */
    tr->overlay_fdt = xzalloc_bytes(overlay_fdt_size);
    if ( tr->overlay_fdt == NULL )
    {
        xfree(tr->nodes_address);
        xfree(tr->fdt);
        xfree(tr);
        return -ENOMEM;
    }

    memcpy(tr->overlay_fdt, overlay_fdt, overlay_fdt_size);

    spin_lock(&overlay_lock);

    memcpy(tr->fdt, device_tree_flattened,
           fdt_totalsize(device_tree_flattened));

    /* Open tr->fdt with more space to accommodate the overlay_fdt. */
    rc = fdt_open_into(tr->fdt, tr->fdt, new_fdt_size);
    if ( rc )
    {
        printk(XENLOG_ERR "Increasing fdt size to accommodate overlay_fdt failed with error %d\n",
               rc);
        goto err;
    }

    nodes_full_path = xzalloc_bytes(tr->num_nodes * sizeof(char *));
    if ( nodes_full_path == NULL )
    {
        rc = -ENOMEM;
        goto err;
    }

    /*
     * overlay_get_nodes_info is called to get the node information from dtbo.
     * This is done before fdt_overlay_apply() because the overlay apply will
     * erase the magic of overlay_fdt.
     */
    rc = overlay_get_nodes_info(overlay_fdt, nodes_full_path);
    if ( rc )
    {
        printk(XENLOG_ERR "Getting nodes information failed with error %d\n",
               rc);
        goto err;
    }

    rc = fdt_overlay_apply(tr->fdt, overlay_fdt);
    if ( rc )
    {
        printk(XENLOG_ERR "Adding overlay node failed with error %d\n", rc);
        goto err;
    }

    /*
     * Check if any of the node already exists in dt_host. If node already exits
     * we can return here as this overlay_fdt is not suitable for overlay ops.
     */
    for ( j = 0; j < tr->num_nodes; j++ )
    {
        overlay_node = dt_find_node_by_path(nodes_full_path[j]);
        if ( overlay_node != NULL )
        {
            printk(XENLOG_ERR "node %s exists in device tree\n",
                   nodes_full_path[j]);
            rc = -EINVAL;
            goto err;
        }
    }

    /*
     * Unflatten the tr->fdt into a new dt_host.
     * TODO: Check and add alias_scan() if it's needed for overlay in future.
     */
    rc = unflatten_device_tree(tr->fdt, &tr->dt_host_new);
    if ( rc )
    {
        printk(XENLOG_ERR "unflatten_device_tree failed with error %d\n", rc);
        goto err;
    }

    rc = add_nodes(tr, nodes_full_path);
    if ( rc )
    {
        printk(XENLOG_ERR "Adding nodes failed. Removing the partially added nodes.\n");
        goto remove_node;
    }

    INIT_LIST_HEAD(&tr->entry);
    list_add_tail(&tr->entry, &overlay_tracker);

    spin_unlock(&overlay_lock);

    free_nodes_full_path(tr->num_nodes, nodes_full_path);

    return rc;

/*
 * Failure case. We need to remove the nodes, free tracker(if tr exists) and
 * tr->dt_host_new.
 */
 remove_node:
    tr->num_nodes = j;
    rc = remove_nodes(tr);

    if ( rc )
    {
        /*
         * User needs to provide right overlay. Incorrect node information
         * example parent node doesn't exist in dt_host etc can cause memory
         * leaks as removing_nodes() will fail and this means nodes memory is
         * not freed from tracker. Which may cause memory leaks. Ideally, these
         * device tree related mistakes will be caught by fdt_overlay_apply()
         * but given that we don't manage that code keeping this warning message
         * is better here.
         */
        printk(XENLOG_ERR "Removing node failed.\n");
        spin_unlock(&overlay_lock);

        free_nodes_full_path(tr->num_nodes, nodes_full_path);

        return rc;
    }

 err:
    spin_unlock(&overlay_lock);

    if ( tr->dt_host_new )
        xfree(tr->dt_host_new);

    free_nodes_full_path(tr->num_nodes, nodes_full_path);

    xfree(tr->overlay_fdt);
    xfree(tr->nodes_address);
    xfree(tr->fdt);

    xfree(tr);

    return rc;
}

static long handle_attach_overlay_nodes(struct domain *d,
                                        const void *overlay_fdt,
                                        uint32_t overlay_fdt_size)
{
    int rc;
    unsigned int j;
    struct overlay_track *entry;

    rc = check_overlay_fdt(overlay_fdt, overlay_fdt_size);
    if ( rc )
        return rc;

    spin_lock(&overlay_lock);

    entry = find_track_entry_from_tracker(overlay_fdt, overlay_fdt_size);
    if ( entry == NULL )
    {
        rc = -EINVAL;
        goto out;
    }

    entry->irq_ranges = rangeset_new(d, "Overlays: Interrupts", 0);
    if (entry->irq_ranges == NULL)
    {
        rc = -ENOMEM;
        printk(XENLOG_ERR "Creating IRQ rangeset failed");
        goto out;
    }

    entry->iomem_ranges = rangeset_new(d, "Overlay: I/O Memory",
                                       RANGESETF_prettyprint_hex);
    if (entry->iomem_ranges == NULL)
    {
        rc = -ENOMEM;
        printk(XENLOG_ERR "Creating IOMMU rangeset failed");
        goto out;
    }

    for ( j = 0; j < entry->num_nodes; j++ )
    {
        struct dt_device_node *overlay_node;

        overlay_node = (struct dt_device_node *)entry->nodes_address[j];
        if ( overlay_node == NULL )
        {
            rc = -EINVAL;
            goto out;
        }

        write_lock(&dt_host_lock);
        rc = handle_device(d, overlay_node, p2m_mmio_direct_c,
                           entry->iomem_ranges, entry->irq_ranges);
        write_unlock(&dt_host_lock);
        if ( rc )
        {
            printk(XENLOG_ERR "Adding IRQ and IOMMU failed\n");
            goto out;
        }
    }

    spin_unlock(&overlay_lock);

    return 0;

 out:
    spin_unlock(&overlay_lock);

    if ( entry )
    {
        rangeset_destroy(entry->irq_ranges);
        rangeset_destroy(entry->iomem_ranges);
    }

    return rc;
}

long dt_overlay_sysctl(struct xen_sysctl_dt_overlay *op)
{
    long ret;
    void *overlay_fdt;

    if ( op->overlay_op != XEN_SYSCTL_DT_OVERLAY_ADD &&
         op->overlay_op != XEN_SYSCTL_DT_OVERLAY_REMOVE )
        return -EOPNOTSUPP;

    if ( op->overlay_fdt_size == 0 ||
         op->overlay_fdt_size > DT_OVERLAY_MAX_SIZE )
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
    else
        ret = handle_add_overlay_nodes(overlay_fdt, op->overlay_fdt_size);

    xfree(overlay_fdt);

    return ret;
}

long dt_overlay_domctl(struct domain *d, struct xen_domctl_dt_overlay *op)
{
    long ret;
    void *overlay_fdt;

    if ( op->overlay_op != XEN_DOMCTL_DT_OVERLAY_ATTACH )
        return -EOPNOTSUPP;

    if ( op->overlay_fdt_size == 0 ||
         op->overlay_fdt_size > DT_OVERLAY_MAX_SIZE )
        return -EINVAL;

    if ( op->pad[0] || op->pad[1] || op->pad[2] )
        return -EINVAL;

    /* TODO: add support for non-1:1 domains using xen,reg */
    if ( !is_domain_direct_mapped(d) )
        return -EOPNOTSUPP;

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

    if ( op->overlay_op == XEN_DOMCTL_DT_OVERLAY_ATTACH )
        ret = handle_attach_overlay_nodes(d, overlay_fdt, op->overlay_fdt_size);
    else
        ret = -EOPNOTSUPP;

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
