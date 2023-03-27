/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vm_event.h: architecture specific vm_event handling routines
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 */

#ifndef __ASM_X86_VM_EVENT_H__
#define __ASM_X86_VM_EVENT_H__

#include <xen/sched.h>
#include <public/vm_event.h>

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
    struct vm_event_regs_x86 gprs;
    bool set_gprs;
    /* A sync vm_event has been sent and we're not done handling it. */
    bool sync_event;
    /* Send mem access events from emulator */
    bool send_event;
};

int vm_event_init_domain(struct domain *d);

void vm_event_cleanup_domain(struct domain *d);

void vm_event_toggle_singlestep(struct domain *d, struct vcpu *v,
                                vm_event_response_t *rsp);

void vm_event_register_write_resume(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_emulate_check(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_sync_event(struct vcpu *v, bool value);

void vm_event_reset_vmtrace(struct vcpu *v);

#endif /* __ASM_X86_VM_EVENT_H__ */
