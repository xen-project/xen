/******************************************************************************
 * xc_atropos.c
 * 
 * API for manipulating parameters of the Atropos scheduler.
 * 
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge.
 */

#include "xc_private.h"

int xc_atropos_global_set(int xc_handle,
			  unsigned long ctx_allow)
{
    dom0_op_t op;
    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.if_ver = SCHED_CTL_IF_VER;
    op.u.schedctl.sched_id = SCHED_BVT;

    op.u.schedctl.u.bvt.ctx_allow = ctx_allow;
    return do_dom0_op(xc_handle, &op);
}

int xc_atropos_domain_set(int xc_handle,
			  u64 domid, int xtratime)
{
    dom0_op_t op;
    op.cmd = DOM0_ADJUSTDOM;

    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.if_ver = SCHED_CTL_IF_VER;
    op.u.adjustdom.sched_id = SCHED_ATROPOS;

    op.u.adjustdom.u.atropos.xtratime = xtratime;

    printf("Doing dom0 op!\n");

    return do_dom0_op(xc_handle, &op);
}
