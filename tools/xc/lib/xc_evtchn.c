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
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_event_channel_op;
    hypercall.arg[0] = (unsigned long)op;

    if ( mlock(op, sizeof(*op)) != 0 )
    {
        PERROR("Could not lock memory for Xen hypercall");
        goto out1;
    }

    if ( (ret = do_xen_hypercall(xc_handle, &hypercall)) < 0 )
        goto out2;

 out2: (void)munlock(op, sizeof(*op));
 out1: return ret;
}

int xc_evtchn_open(int xc_handle,
                   u64 dom1,
                   u64 dom2,
                   int *port1,
                   int *port2)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_open;
    op.u.open.dom1 = (domid_t)dom1;
    op.u.open.dom2 = (domid_t)dom2;
   
    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
    {
        if ( port1 != NULL )
            *port1 = op.u.open.port1;
        if ( port2 != NULL )
            *port2 = op.u.open.port2;
    }
    
    return rc;
}


int xc_evtchn_close(int xc_handle,
                    u64 dom,
                    int port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_close;
    op.u.close.dom  = (domid_t)dom;
    op.u.close.port = port;
    return do_evtchn_op(xc_handle, &op);
}


int xc_evtchn_send(int xc_handle,
                   int local_port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.local_port = local_port;
    return do_evtchn_op(xc_handle, &op);
}


int xc_evtchn_status(int xc_handle,
                     u64 dom1,
                     int port1,
                     u64 *dom2,
                     int *port2,
                     int *chn_status)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_status;
    op.u.status.dom1  = (domid_t)dom1;
    op.u.status.port1 = port1;
   
    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
    {
        if ( dom2 != NULL )
            *dom2 = (u64)op.u.status.dom2;
        if ( port2 != NULL )
            *port2 = op.u.status.port2;
        if ( chn_status != NULL )
            *chn_status = op.u.status.status;
    }
    
    return rc;
}
