/******************************************************************************
 * xc_bvtsched.c
 * 
 * API for manipulating parameters of the Borrowed Virtual Time scheduler.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"

int xc_bvtsched_global_set(int xc_handle,
                           unsigned long ctx_allow)
{
    dom0_op_t op;
    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_BVT;
    op.u.schedctl.if_ver = SCHED_CTL_IF_VER;
    op.u.schedctl.u.bvt.ctx_allow = ctx_allow;
    return do_dom0_op(xc_handle, &op);
}

int xc_bvtsched_domain_set(int xc_handle,
                           u64 domid,
                           unsigned long mcuadv,
                           unsigned long warp,
                           unsigned long warpl,
                           unsigned long warpu)
{
    dom0_op_t op;
    struct bvt_adjdom *adjptr = &op.u.adjustdom.u.bvt;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.sched_id = SCHED_BVT;
    op.u.adjustdom.if_ver   = SCHED_CTL_IF_VER;
    op.u.adjustdom.domain  = (domid_t)domid;

    adjptr->mcu_adv = mcuadv;
    adjptr->warp    = warp;
    adjptr->warpl   = warpl;
    adjptr->warpu   = warpu;
    return do_dom0_op(xc_handle, &op);
}
