/******************************************************************************
 * xc_sedf.c
 * 
 * API for manipulating parameters of the Simple EDF scheduler.
 * 
 * changes by Stephan Diestelhorst
 * based on code
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge.
 */

#include "xc_private.h"

int xc_sedf_domain_set(int xc_handle,
                          u32 domid, u64 period, u64 slice)
{
    dom0_op_t op;
    struct sedf_adjdom *p = &op.u.adjustdom.u.sedf;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_SEDF;
    op.u.adjustdom.direction = SCHED_INFO_PUT;

    p->period   = period;
    p->slice    = slice;
    return do_dom0_op(xc_handle, &op);
}

int xc_sedf_domain_get(int xc_handle, u32 domid, u64 *period, u64 *slice)
{
    dom0_op_t op;
    int ret;
    struct sedf_adjdom *p = &op.u.adjustdom.u.sedf;

    op.cmd = DOM0_ADJUSTDOM;    
    op.u.adjustdom.domain = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_SEDF;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *period   = p->period;
    *slice    = p->slice;
    return ret;
}
