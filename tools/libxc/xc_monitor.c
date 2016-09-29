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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"

void *xc_monitor_enable(xc_interface *xch, domid_t domain_id, uint32_t *port)
{
    return xc_vm_event_enable(xch, domain_id, HVM_PARAM_MONITOR_RING_PFN,
                              port);
}

int xc_monitor_disable(xc_interface *xch, domid_t domain_id)
{
    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_DISABLE,
                               XEN_DOMCTL_VM_EVENT_OP_MONITOR,
                               NULL);
}

int xc_monitor_resume(xc_interface *xch, domid_t domain_id)
{
    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_RESUME,
                               XEN_DOMCTL_VM_EVENT_OP_MONITOR,
                               NULL);
}

int xc_monitor_get_capabilities(xc_interface *xch, domid_t domain_id,
                                uint32_t *capabilities)
{
    int rc;
    DECLARE_DOMCTL;

    if ( !capabilities )
    {
        errno = EINVAL;
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = XEN_DOMCTL_MONITOR_OP_GET_CAPABILITIES;

    rc = do_domctl(xch, &domctl);
    if ( rc )
        return rc;

    *capabilities = domctl.u.monitor_op.event;
    return 0;
}

int xc_monitor_write_ctrlreg(xc_interface *xch, domid_t domain_id,
                             uint16_t index, bool enable, bool sync,
                             bool onchangeonly)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG;
    domctl.u.monitor_op.u.mov_to_cr.index = index;
    domctl.u.monitor_op.u.mov_to_cr.sync = sync;
    domctl.u.monitor_op.u.mov_to_cr.onchangeonly = onchangeonly;

    return do_domctl(xch, &domctl);
}

int xc_monitor_mov_to_msr(xc_interface *xch, domid_t domain_id, uint32_t msr,
                          bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR;
    domctl.u.monitor_op.u.mov_to_msr.msr = msr;

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

int xc_monitor_guest_request(xc_interface *xch, domid_t domain_id, bool enable,
                             bool sync)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST;
    domctl.u.monitor_op.u.guest_request.sync = sync;

    return do_domctl(xch, &domctl);
}

int xc_monitor_emulate_each_rep(xc_interface *xch, domid_t domain_id,
                                bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = XEN_DOMCTL_MONITOR_OP_EMULATE_EACH_REP;
    domctl.u.monitor_op.event = enable;

    return do_domctl(xch, &domctl);
}

int xc_monitor_debug_exceptions(xc_interface *xch, domid_t domain_id,
                                bool enable, bool sync)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_DEBUG_EXCEPTION;
    domctl.u.monitor_op.u.debug_exception.sync = sync;

    return do_domctl(xch, &domctl);
}

int xc_monitor_cpuid(xc_interface *xch, domid_t domain_id, bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_CPUID;

    return do_domctl(xch, &domctl);
}

int xc_monitor_privileged_call(xc_interface *xch, domid_t domain_id,
                               bool enable)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_monitor_op;
    domctl.domain = domain_id;
    domctl.u.monitor_op.op = enable ? XEN_DOMCTL_MONITOR_OP_ENABLE
                                    : XEN_DOMCTL_MONITOR_OP_DISABLE;
    domctl.u.monitor_op.event = XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL;

    return do_domctl(xch, &domctl);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
