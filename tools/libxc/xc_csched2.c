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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

int
xc_sched_credit2_domain_set(
    xc_interface *xch,
    uint32_t domid,
    struct xen_domctl_sched_credit2 *sdom)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT2;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;
    domctl.u.scheduler_op.u.credit2 = *sdom;

    if ( do_domctl(xch, &domctl) )
        return -1;

    return 0;
}

int
xc_sched_credit2_domain_get(
    xc_interface *xch,
    uint32_t domid,
    struct xen_domctl_sched_credit2 *sdom)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT2;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

    if ( do_domctl(xch, &domctl) )
        return -1;

    *sdom = domctl.u.scheduler_op.u.credit2;

    return 0;
}

int
xc_sched_credit2_params_set(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_credit2_schedule *schedule)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT2;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_putinfo;

    sysctl.u.scheduler_op.u.sched_credit2 = *schedule;

    if ( do_sysctl(xch, &sysctl) )
        return -1;

    *schedule = sysctl.u.scheduler_op.u.sched_credit2;

    return 0;
}

int
xc_sched_credit2_params_get(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_credit2_schedule *schedule)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT2;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_getinfo;

    if ( do_sysctl(xch, &sysctl) )
        return -1;

    *schedule = sysctl.u.scheduler_op.u.sched_credit2;

    return 0;
}
