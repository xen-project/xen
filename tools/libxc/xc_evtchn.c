/******************************************************************************
 * xc_evtchn.c
 *
 * API for manipulating and accessing inter-domain event channels.
 *
 * Copyright (c) 2004, K A Fraser.
 */

#include "xc_private.h"


static int do_evtchn_op(int xc_handle, evtchn_op_t *op)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_event_channel_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("do_evtchn_op: op mlock failed");
        goto out;
    }

    if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0)
        ERROR("do_evtchn_op: HYPERVISOR_event_channel_op failed: %d", ret);

    safe_munlock(op, sizeof(*op));
 out:
    return ret;
}


int xc_evtchn_alloc_unbound(int xc_handle,
                            uint32_t dom,
                            uint32_t remote_dom)
{
    int         rc;
    evtchn_op_t op = {
        .cmd = EVTCHNOP_alloc_unbound,
        .u.alloc_unbound.dom = (domid_t)dom,
        .u.alloc_unbound.remote_dom = (domid_t)remote_dom };

    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
        rc = op.u.alloc_unbound.port;

    return rc;
}


int xc_evtchn_status(int xc_handle,
                     uint32_t dom,
                     evtchn_port_t port,
                     xc_evtchn_status_t *status)
{
    int         rc;
    evtchn_op_t op = {
        .cmd           = EVTCHNOP_status,
        .u.status.dom  = (domid_t)dom,
        .u.status.port = port };

    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
        memcpy(status, &op.u.status, sizeof(*status));

    return rc;
}
