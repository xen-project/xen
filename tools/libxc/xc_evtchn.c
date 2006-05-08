/******************************************************************************
 * xc_evtchn.c
 *
 * API for manipulating and accessing inter-domain event channels.
 *
 * Copyright (c) 2004, K A Fraser.
 */

#include "xc_private.h"


static int do_evtchn_op(int xc_handle, int cmd, void *arg, size_t arg_size)
{
    int ret = -1;
    DECLARE_HYPERCALL;

    hypercall.op     = __HYPERVISOR_event_channel_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = (unsigned long)arg;

    if ( mlock(arg, arg_size) != 0 )
    {
        PERROR("do_evtchn_op: arg mlock failed");
        goto out;
    }

    if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0)
        ERROR("do_evtchn_op: HYPERVISOR_event_channel_op failed: %d", ret);

    safe_munlock(arg, arg_size);
 out:
    return ret;
}


int xc_evtchn_alloc_unbound(int xc_handle,
                            uint32_t dom,
                            uint32_t remote_dom)
{
    int         rc;
    struct evtchn_alloc_unbound arg = {
        .dom = (domid_t)dom,
        .remote_dom = (domid_t)remote_dom
    };

    rc = do_evtchn_op(xc_handle, EVTCHNOP_alloc_unbound, &arg, sizeof(arg));
    if ( rc == 0 )
        rc = arg.port;

    return rc;
}


int xc_evtchn_status(int xc_handle,
                     uint32_t dom,
                     evtchn_port_t port,
                     xc_evtchn_status_t *status)
{
    status->dom  = (domid_t)dom;
    status->port = port;
    return do_evtchn_op(xc_handle, EVTCHNOP_status, status, sizeof(*status));
}
