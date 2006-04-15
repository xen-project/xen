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
                          uint32_t domid, uint64_t period, uint64_t slice,uint64_t latency, uint16_t extratime,uint16_t weight)
{
    DECLARE_DOM0_OP;
    struct sedf_adjdom *p = &op.u.adjustdom.u.sedf;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_SEDF;
    op.u.adjustdom.direction = SCHED_INFO_PUT;

    p->period    = period;
    p->slice     = slice;
    p->latency   = latency;
    p->extratime = extratime;
    p->weight    = weight;
    return do_dom0_op(xc_handle, &op);
}

int xc_sedf_domain_get(int xc_handle, uint32_t domid, uint64_t *period, uint64_t *slice, uint64_t* latency, uint16_t* extratime, uint16_t* weight)
{
    DECLARE_DOM0_OP;
    int ret;
    struct sedf_adjdom *p = &op.u.adjustdom.u.sedf;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_SEDF;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *period    = p->period;
    *slice     = p->slice;
    *latency   = p->latency;
    *extratime = p->extratime;
    *weight    = p->weight;
    return ret;
}
