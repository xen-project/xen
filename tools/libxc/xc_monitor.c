/******************************************************************************
 *
 * xc_monitor.c
 *
 * Interface to VM event monitor
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

int xc_monitor_mov_to_cr0(xc_interface *xch, domid_t domain_id, bool enable,
                          bool sync, bool onchangeonly)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_MOV_TO_CR0;
    domctl.u.monitor_op.u.mov_to_cr.sync = sync;
    domctl.u.monitor_op.u.mov_to_cr.onchangeonly = onchangeonly;

    return do_domctl(xch, &domctl);
}

int xc_monitor_mov_to_cr3(xc_interface *xch, domid_t domain_id, bool enable,
                          bool sync, bool onchangeonly)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_MOV_TO_CR3;
    domctl.u.monitor_op.u.mov_to_cr.sync = sync;
    domctl.u.monitor_op.u.mov_to_cr.onchangeonly = onchangeonly;

    return do_domctl(xch, &domctl);
}

int xc_monitor_mov_to_cr4(xc_interface *xch, domid_t domain_id, bool enable,
                          bool sync, bool onchangeonly)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_MOV_TO_CR4;
    domctl.u.monitor_op.u.mov_to_cr.sync = sync;
    domctl.u.monitor_op.u.mov_to_cr.onchangeonly = onchangeonly;

    return do_domctl(xch, &domctl);
}

int xc_monitor_mov_to_msr(xc_interface *xch, domid_t domain_id, bool enable,
                          bool extended_capture)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR;
    domctl.u.monitor_op.u.mov_to_msr.extended_capture = extended_capture;

    return do_domctl(xch, &domctl);
}

int xc_monitor_software_breakpoint(xc_interface *xch, domid_t domain_id,
                                   bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT;

    return do_domctl(xch, &domctl);
}

int xc_monitor_singlestep(xc_interface *xch, domid_t domain_id,
                          bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP;

    return do_domctl(xch, &domctl);
}
