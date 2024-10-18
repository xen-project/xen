/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/arm/vm_event.c
 *
 * Architecture-specific vm_event handling routines
 *
 * Copyright (c) 2016 Tamas K Lengyel (tamas.lengyel@zentific.com)
 */

#include <xen/sched.h>
#include <xen/vm_event.h>

void vm_event_fill_regs(vm_event_request_t *req)
{
    const struct cpu_user_regs *regs = guest_cpu_user_regs();

    req->data.regs.arm.cpsr = regs->cpsr;
    req->data.regs.arm.pc = regs->pc;
    req->data.regs.arm.ttbcr = READ_SYSREG(TCR_EL1);
    req->data.regs.arm.ttbr0 = READ_SYSREG64(TTBR0_EL1);
    req->data.regs.arm.ttbr1 = READ_SYSREG64(TTBR1_EL1);
}

void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp)
{
    struct cpu_user_regs *regs = &v->arch.cpu_info->guest_cpu_user_regs;

    /* vCPU should be paused */
    ASSERT(atomic_read(&v->vm_event_pause_count));

    regs->pc = rsp->data.regs.arm.pc;
}

void vm_event_monitor_next_interrupt(struct vcpu *v)
{
    /* Not supported on ARM. */
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
