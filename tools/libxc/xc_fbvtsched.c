/******************************************************************************
 * xc_fbvtsched.c
 * 
 * API for manipulating parameters of the Fair Borrowed Virtual Time scheduler.
 * 
 * Copyright (c) 2004, G. Milos
 * Based on K. Fraiser's xc_bvtsched.c
 */

#include "xc_private.h"

int xc_fbvtsched_global_set(int xc_handle,
                           unsigned long ctx_allow)
{
    dom0_op_t op;

    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_FBVT;
    op.u.schedctl.direction = SCHED_INFO_PUT;
    op.u.schedctl.u.fbvt.ctx_allow = ctx_allow;

    return do_dom0_op(xc_handle, &op);
}

int xc_fbvtsched_global_get(int xc_handle,
                           unsigned long *ctx_allow)
{
    dom0_op_t op;
    int ret;
    
    op.cmd = DOM0_SCHEDCTL;
    op.u.schedctl.sched_id = SCHED_FBVT;
    op.u.schedctl.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *ctx_allow = op.u.schedctl.u.fbvt.ctx_allow;

    return ret;
}

int xc_fbvtsched_domain_set(int xc_handle,
                           u32 domid,
                           unsigned long mcuadv,
                           unsigned long warp,
                           unsigned long warpl,
                           unsigned long warpu)
{
    dom0_op_t op;
    struct fbvt_adjdom *fbvtadj = &op.u.adjustdom.u.fbvt;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_FBVT;
    op.u.adjustdom.direction = SCHED_INFO_PUT;

    fbvtadj->mcu_adv = mcuadv;
    fbvtadj->warp    = warp;
    fbvtadj->warpl   = warpl;
    fbvtadj->warpu   = warpu;
    return do_dom0_op(xc_handle, &op);
}


int xc_fbvtsched_domain_get(int xc_handle,
                           u32 domid,
                           unsigned long *mcuadv,
                           unsigned long *warp,
                           unsigned long *warpl,
                           unsigned long *warpu)
{
    
    dom0_op_t op;
    int ret;
    struct fbvt_adjdom *adjptr = &op.u.adjustdom.u.fbvt;

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = (domid_t)domid;
    op.u.adjustdom.sched_id = SCHED_FBVT;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    ret = do_dom0_op(xc_handle, &op);

    *mcuadv = adjptr->mcu_adv;
    *warp   = adjptr->warp;
    *warpl  = adjptr->warpl;
    *warpu  = adjptr->warpu;
    return ret;
}
