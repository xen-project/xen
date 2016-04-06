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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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

int xc_sched_rtds_vcpu_set(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_schedparam_vcpu *vcpus,
                           uint32_t num_vcpus)
{
    int rc = 0;
    unsigned processed = 0;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(vcpus, sizeof(*vcpus) * num_vcpus,
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, vcpus) )
        return -1;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_RTDS;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putvcpuinfo;

    while ( processed < num_vcpus )
    {
        domctl.u.scheduler_op.u.v.nr_vcpus = num_vcpus - processed;
        set_xen_guest_handle_offset(domctl.u.scheduler_op.u.v.vcpus, vcpus,
                                    processed);
        if ( (rc = do_domctl(xch, &domctl)) != 0 )
            break;
        processed += domctl.u.scheduler_op.u.v.nr_vcpus;
    }

    xc_hypercall_bounce_post(xch, vcpus);

    return rc;
}

int xc_sched_rtds_vcpu_get(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_schedparam_vcpu *vcpus,
                           uint32_t num_vcpus)
{
    int rc = 0;
    unsigned processed = 0;
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(vcpus, sizeof(*vcpus) * num_vcpus,
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, vcpus) )
        return -1;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t) domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_RTDS;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getvcpuinfo;

    while ( processed < num_vcpus )
    {
        domctl.u.scheduler_op.u.v.nr_vcpus = num_vcpus - processed;
        set_xen_guest_handle_offset(domctl.u.scheduler_op.u.v.vcpus, vcpus,
                                    processed);
        if ( (rc = do_domctl(xch, &domctl)) != 0 )
            break;
        processed += domctl.u.scheduler_op.u.v.nr_vcpus;
    }

    xc_hypercall_bounce_post(xch, vcpus);

    return rc;
}
