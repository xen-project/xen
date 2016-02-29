/*
 * vm_event.h: architecture specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_X86_VM_EVENT_H__
#define __ASM_X86_VM_EVENT_H__

#include <xen/sched.h>
#include <xen/vm_event.h>

/*
 * Should we emulate the next matching instruction on VCPU resume
 * after a vm_event?
 */
struct arch_vm_event {
    uint32_t emulate_flags;
    struct vm_event_emul_read_data emul_read_data;
    struct monitor_write_data write_data;
};

int vm_event_init_domain(struct domain *d);

void vm_event_cleanup_domain(struct domain *d);

void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v);

void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_fill_regs(vm_event_request_t *req);

static inline uint32_t vm_event_monitor_get_capabilities(struct domain *d)
{
    uint32_t capabilities = 0;

    /*
     * At the moment only Intel HVM domains are supported. However, event
     * delivery could be extended to AMD and PV domains.
     */
    if ( !is_hvm_domain(d) || !cpu_has_vmx )
        return capabilities;

    capabilities = (1U << XEN_DOMCTL_MONITOR_EVENT_WRITE_CTRLREG) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_MOV_TO_MSR) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_SOFTWARE_BREAKPOINT) |
                   (1U << XEN_DOMCTL_MONITOR_EVENT_GUEST_REQUEST);

    /* Since we know this is on VMX, we can just call the hvm func */
    if ( hvm_is_singlestep_supported() )
        capabilities |= (1U << XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP);

    return capabilities;
}

#endif /* __ASM_X86_VM_EVENT_H__ */
