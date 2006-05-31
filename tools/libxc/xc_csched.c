/****************************************************************************
 * (C) 2006 - Emmanuel Ackaouy - XenSource Inc.
 ****************************************************************************
 *
 *        File: xc_csched.c
 *      Author: Emmanuel Ackaouy
 *
 * Description: XC Interface to the credit scheduler
 *
 */
#include "xc_private.h"


int
xc_sched_credit_domain_set(
    int xc_handle,
    uint32_t domid,
    struct sched_credit_adjdom *sdom)
{
    DECLARE_DOM0_OP;

    op.cmd = DOM0_ADJUSTDOM;    
    op.u.adjustdom.domain = (domid_t) domid;
    op.u.adjustdom.sched_id = SCHED_CREDIT;
    op.u.adjustdom.direction = SCHED_INFO_PUT;
    op.u.adjustdom.u.credit = *sdom;

    return do_dom0_op(xc_handle, &op);
}

int
xc_sched_credit_domain_get(
    int xc_handle,
    uint32_t domid,
    struct sched_credit_adjdom *sdom)
{
    DECLARE_DOM0_OP;
    int err;

    op.cmd = DOM0_ADJUSTDOM;    
    op.u.adjustdom.domain = (domid_t) domid;
    op.u.adjustdom.sched_id = SCHED_CREDIT;
    op.u.adjustdom.direction = SCHED_INFO_GET;

    err = do_dom0_op(xc_handle, &op);
    if ( err == 0 )
        *sdom = op.u.adjustdom.u.credit;

    return err;
}
