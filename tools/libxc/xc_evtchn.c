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


int xc_evtchn_alloc_unbound(int xc_handle,
                            u32 dom,
                            int *port)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_alloc_unbound;
    op.u.alloc_unbound.dom = (domid_t)dom;
   
    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
    {
        if ( port != NULL )
            *port = op.u.alloc_unbound.port;
    }
    
    return rc;
}


int xc_evtchn_bind_interdomain(int xc_handle,
                               u32 dom1,
                               u32 dom2,
                               int *port1,
                               int *port2)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_bind_interdomain;
    op.u.bind_interdomain.dom1  = (domid_t)dom1;
    op.u.bind_interdomain.dom2  = (domid_t)dom2;
    op.u.bind_interdomain.port1 = (port1 != NULL) ? *port1 : 0;
    op.u.bind_interdomain.port2 = (port2 != NULL) ? *port2 : 0;


    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
    {
        if ( port1 != NULL )
            *port1 = op.u.bind_interdomain.port1;
        if ( port2 != NULL )
            *port2 = op.u.bind_interdomain.port2;
    }
    
    return rc;
}


int xc_evtchn_bind_virq(int xc_handle,
                        int virq,
                        int *port)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_bind_virq;
    op.u.bind_virq.virq = (u32)virq;
   
    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
    {
        if ( port != NULL )
            *port = op.u.bind_virq.port;
    }
    
    return rc;
}


int xc_evtchn_close(int xc_handle,
                    u32 dom,
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
                     u32 dom,
                     int port,
                     xc_evtchn_status_t *status)
{
    evtchn_op_t op;
    int         rc;

    op.cmd = EVTCHNOP_status;
    op.u.status.dom  = (domid_t)dom;
    op.u.status.port = port;
   
    if ( (rc = do_evtchn_op(xc_handle, &op)) == 0 )
        memcpy(status, &op.u.status, sizeof(*status));
    
    return rc;
}
