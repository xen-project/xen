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
    DECLARE_DOM0_OP;

    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_BVT;
    op.u.schedctl.direction = SCHED_INFO_PUT;
    op.u.schedctl.u.bvt.ctx_allow = ctx_allow;

    return do_dom0_op(xc_handle, &op);
}

int xc_bvtsched_global_get(int xc_handle,
                           unsigned long *ctx_allow)
{
    DECLARE_DOM0_OP;
    int ret;

    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_BVT;
    op.u.schedctl.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *ctx_allow = op.u.schedctl.u.bvt.ctx_allow;

    return ret;
}

int xc_bvtsched_domain_set(int xc_handle,
                           uint32_t domid,
                           uint32_t mcuadv,
                           int warpback,
                           int32_t warpvalue,
                           long long warpl,
                           long long warpu)
{
    DECLARE_DOM0_OP;
    struct bvt_adjdom *bvtadj = &op.u.adjustdom.u.bvt;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_BVT;
    op.u.adjustdom.direction = SCHED_INFO_PUT;

    bvtadj->mcu_adv     = mcuadv;
    bvtadj->warpback    = warpback;
    bvtadj->warpvalue   = warpvalue;
    bvtadj->warpl       = warpl;
    bvtadj->warpu       = warpu;
    return do_dom0_op(xc_handle, &op);
}


int xc_bvtsched_domain_get(int xc_handle,
                           uint32_t domid,
                           uint32_t *mcuadv,
                           int *warpback,
                           int32_t *warpvalue,
                           long long *warpl,
                           long long *warpu)
{

    DECLARE_DOM0_OP;
    int ret;
    struct bvt_adjdom *adjptr = &op.u.adjustdom.u.bvt;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_BVT;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *mcuadv     = adjptr->mcu_adv;
    *warpback   = adjptr->warpback;
    *warpvalue  = adjptr->warpvalue;
    *warpl      = adjptr->warpl;
    *warpu      = adjptr->warpu;
    return ret;
}
