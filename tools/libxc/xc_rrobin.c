/******************************************************************************
 * xc_rrobin.c
 * 
 * API for manipulating parameters of the Round Robin scheduler
 * 
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge.
 */

#include "xc_private.h"

int xc_rrobin_global_set(int xc_handle, u64 slice)
{
    dom0_op_t op;
    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_RROBIN;
    op.u.schedctl.direction = SCHED_INFO_PUT;

    op.u.schedctl.u.rrobin.slice = slice;
    return do_dom0_op(xc_handle, &op);
}


int xc_rrobin_global_get(int xc_handle, u64 *slice)
{
    dom0_op_t op;
    int ret;

    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_RROBIN;
    op.u.schedctl.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *slice = op.u.schedctl.u.rrobin.slice;

    return ret;
}
