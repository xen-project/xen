/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/event.h>

#include <asm/static-evtchn.h>

#define STATIC_EVTCHN_NODE_SIZE_CELLS 2

static int __init get_evtchn_dt_property(const struct dt_device_node *np,
                                         uint32_t *port, uint32_t *phandle)
{
    const __be32 *prop = NULL;
    uint32_t len;

    prop = dt_get_property(np, "xen,evtchn", &len);
    if ( !prop )
    {
        printk(XENLOG_ERR "xen,evtchn property should not be empty.\n");
        return -EINVAL;
    }

    if ( !len || len < dt_cells_to_size(STATIC_EVTCHN_NODE_SIZE_CELLS) )
    {
        printk(XENLOG_ERR "xen,evtchn property value is not valid.\n");
        return -EINVAL;
    }

    *port = dt_next_cell(1, &prop);
    *phandle = dt_next_cell(1, &prop);

    return 0;
}

static int __init alloc_domain_evtchn(struct dt_device_node *node)
{
    int rc;
    uint32_t domU1_port, domU2_port, remote_phandle;
    struct dt_device_node *remote_node;
    const struct dt_device_node *p1_node, *p2_node;
    struct evtchn_alloc_unbound alloc_unbound;
    struct evtchn_bind_interdomain bind_interdomain;
    struct domain *d1 = NULL, *d2 = NULL;

    if ( !dt_device_is_compatible(node, "xen,evtchn-v1") )
        return 0;

    /*
     * Event channel is already created while parsing the other side of
     * evtchn node.
     */
    if ( dt_device_static_evtchn_created(node) )
        return 0;

    rc = get_evtchn_dt_property(node, &domU1_port, &remote_phandle);
    if ( rc )
        return rc;

    remote_node = dt_find_node_by_phandle(remote_phandle);
    if ( !remote_node )
    {
        printk(XENLOG_ERR
                "evtchn: could not find remote evtchn phandle\n");
        return -EINVAL;
    }

    rc = get_evtchn_dt_property(remote_node, &domU2_port, &remote_phandle);
    if ( rc )
        return rc;

    if ( node->phandle != remote_phandle )
    {
        printk(XENLOG_ERR "xen,evtchn property is not setup correctly.\n");
        return -EINVAL;
    }

    p1_node = dt_get_parent(node);
    if ( !p1_node )
    {
        printk(XENLOG_ERR "evtchn: evtchn parent node is NULL\n" );
        return -EINVAL;
    }

    p2_node = dt_get_parent(remote_node);
    if ( !p2_node )
    {
        printk(XENLOG_ERR "evtchn: remote parent node is NULL\n" );
        return -EINVAL;
    }

    d1 = get_domain_by_id(p1_node->used_by);
    d2 = get_domain_by_id(p2_node->used_by);

    if ( !d1 || !d2 )
    {
        printk(XENLOG_ERR "evtchn: could not find domains\n" );
        return -EINVAL;
    }

    alloc_unbound.dom = d1->domain_id;
    alloc_unbound.remote_dom = d2->domain_id;

    rc = evtchn_alloc_unbound(&alloc_unbound, domU1_port);
    if ( rc < 0 )
    {
        printk(XENLOG_ERR
                "evtchn_alloc_unbound() failure (Error %d) \n", rc);
        return rc;
    }

    bind_interdomain.remote_dom  = d1->domain_id;
    bind_interdomain.remote_port = domU1_port;

    rc = evtchn_bind_interdomain(&bind_interdomain, d2, domU2_port);
    if ( rc < 0 )
    {
        printk(XENLOG_ERR
                "evtchn_bind_interdomain() failure (Error %d) \n", rc);
        return rc;
    }

    dt_device_set_static_evtchn_created(node);
    dt_device_set_static_evtchn_created(remote_node);

    return 0;
}

void __init alloc_static_evtchn(void)
{
    struct dt_device_node *node, *evtchn_node;
    struct dt_device_node *chosen = dt_find_node_by_path("/chosen");

    BUG_ON(chosen == NULL);

    if ( hardware_domain )
        dt_device_set_used_by(chosen, hardware_domain->domain_id);

    dt_for_each_child_node(chosen, node)
    {
        if ( hardware_domain )
        {
            if ( alloc_domain_evtchn(node) != 0 )
                panic("Could not set up domains evtchn\n");
        }

        dt_for_each_child_node(node, evtchn_node)
        {
            if ( alloc_domain_evtchn(evtchn_node) != 0 )
                panic("Could not set up domains evtchn\n");
        }
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
