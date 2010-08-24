/******************************************************************************
 * xc_sedf.c
 *
 * API for manipulating parameters of the Simple EDF scheduler.
 *
 * changes by Stephan Diestelhorst
 * based on code
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge.
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

int xc_sedf_domain_set(
    xc_interface *xch,
    uint32_t domid,
    uint64_t period,
    uint64_t slice,
    uint64_t latency,
    uint16_t extratime,
    uint16_t weight)
{
    DECLARE_DOMCTL;
    struct xen_domctl_sched_sedf *p = &domctl.u.scheduler_op.u.sedf;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain  = (domid_t)domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_SEDF;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;

    p->period    = period;
    p->slice     = slice;
    p->latency   = latency;
    p->extratime = extratime;
    p->weight    = weight;
    return do_domctl(xch, &domctl);
}

int xc_sedf_domain_get(
    xc_interface *xch,
    uint32_t domid,
    uint64_t *period,
    uint64_t *slice,
    uint64_t *latency,
    uint16_t *extratime,
    uint16_t *weight)
{
    DECLARE_DOMCTL;
    int ret;
    struct xen_domctl_sched_sedf *p = &domctl.u.scheduler_op.u.sedf;

    domctl.cmd = XEN_DOMCTL_scheduler_op;
    domctl.domain = (domid_t)domid;
    domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_SEDF;
    domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

    ret = do_domctl(xch, &domctl);

    *period    = p->period;
    *slice     = p->slice;
    *latency   = p->latency;
    *extratime = p->extratime;
    *weight    = p->weight;
    return ret;
}
