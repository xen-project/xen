/****************************************************************************
 * (C) 2006 - Emmanuel Ackaouy - XenSource Inc.
 ****************************************************************************
 *
 *        File: xc_csched.c
 *      Author: Emmanuel Ackaouy
 *
 * Description: XC Interface to the credit scheduler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

int
xc_sched_credit_domain_set(
    xc_interface *xch,
    uint32_t domid,
    struct xen_domctl_sched_credit *sdom)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;
    domctl.u.scheduler_op.u.credit = *sdom;

    return do_domctl(xch, &domctl);
}

int
xc_sched_credit_domain_get(
    xc_interface *xch,
    uint32_t domid,
    struct xen_domctl_sched_credit *sdom)
{
    DECLARE_DOMCTL;
    int err;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

    err = do_domctl(xch, &domctl);
    if ( err == 0 )
        *sdom = domctl.u.scheduler_op.u.credit;

    return err;
}

int
xc_sched_credit_params_set(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_credit_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_putinfo;

    sysctl.u.scheduler_op.u.sched_credit = *schedule;

    rc = do_sysctl(xch, &sysctl);

    *schedule = sysctl.u.scheduler_op.u.sched_credit;

    return rc;
}

int
xc_sched_credit_params_get(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_credit_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_getinfo;

    rc = do_sysctl(xch, &sysctl);

    *schedule = sysctl.u.scheduler_op.u.sched_credit;

    return rc;
}
