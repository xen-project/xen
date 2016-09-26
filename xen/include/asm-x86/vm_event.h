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

/*
 * Should we emulate the next matching instruction on VCPU resume
 * after a vm_event?
 */
struct arch_vm_event {
    uint32_t emulate_flags;
    union {
        struct vm_event_emul_read_data read;
        struct vm_event_emul_insn_data insn;
    } emul;
    struct monitor_write_data write_data;
};

int vm_event_init_domain(struct domain *d);

void vm_event_cleanup_domain(struct domain *d);

void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v,
                                vm_event_response_t *rsp);

void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_emulate_check(struct vcpu *v, vm_event_response_t *rsp);

#endif /* __ASM_X86_VM_EVENT_H__ */
