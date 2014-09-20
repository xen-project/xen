/****************************************************************************
 *
 *        File: xc_rt.c
 *      Author: Sisu Xi
 *              Meng Xu
 *
 * Description: XC Interface to the rtds scheduler
 * Note: VCPU's parameter (period, budget) is in microsecond (us).
 *       All VCPUs of the same domain have same period and budget.
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

int xc_sched_rtds_domain_set(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_sched_rtds *sdom)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_RTDS;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;
    domctl.u.scheduler_op.u.rtds.period = sdom->period;
    domctl.u.scheduler_op.u.rtds.budget = sdom->budget;

    rc = do_domctl(xch, &domctl);

    return rc;
}

int xc_sched_rtds_domain_get(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_sched_rtds *sdom)
{
    int rc;
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_RTDS;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

    rc = do_domctl(xch, &domctl);

    if ( rc == 0 )
        *sdom = domctl.u.scheduler_op.u.rtds;

    return rc;
}
