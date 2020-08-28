/******************************************************************************
 * xc_arinc653.c
 * 
 * XC interface to the ARINC653 scheduler
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2010 DornerWorks, Ltd. <DornerWorks.com>
 */

#include "xc_private.h"

int
xc_sched_arinc653_schedule_set(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(
        schedule,
        sizeof(*schedule),
        XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, schedule) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_ARINC653;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_putinfo;
    set_xen_guest_handle(sysctl.u.scheduler_op.u.sched_arinc653.schedule,
            schedule);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, schedule);

    return rc;
}

int
xc_sched_arinc653_schedule_get(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(
        schedule,
        sizeof(*schedule),
        XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, schedule) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_ARINC653;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_getinfo;
    set_xen_guest_handle(sysctl.u.scheduler_op.u.sched_arinc653.schedule,
            schedule);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, schedule);

    return rc;
}
