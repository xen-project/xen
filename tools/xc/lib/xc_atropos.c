/******************************************************************************
 * xc_atropos.c
 * 
 * API for manipulating parameters of the Atropos scheduler.
 * 
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge.
 */

#include "xc_private.h"

int xc_atropos_domain_set(int xc_handle,
			  u64 domid, u64 period, u64 slice, u64 latency,
                          int xtratime)
{
    dom0_op_t op;
    struct atropos_adjdom *p = &op.u.adjustdom.u.atropos;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_ATROPOS;
    op.u.adjustdom.direction = SCHED_INFO_PUT;

    p->period   = period;
    p->slice    = slice;
    p->latency  = latency;
    p->xtratime = xtratime;

    return do_dom0_op(xc_handle, &op);
}

int xc_atropos_domain_get(int xc_handle, u64 domid, u64 *period,
                          u64 *slice, u64 *latency, int *xtratime)
{
    dom0_op_t op;
    int ret;
    struct atropos_adjdom *p = &op.u.adjustdom.u.atropos;

    op.cmd = DOM0_ADJUSTDOM;    
    op.u.adjustdom.domain = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_ATROPOS;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *period   = p->period;
    *slice    = p->slice;
    *latency  = p->latency;
    *xtratime = p->xtratime;

    return ret;
}
