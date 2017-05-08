/*
 * arch/x86/hvm/vm_event.c
 *
 * HVM vm_event handling routines
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/vm_event.h>
#include <asm/hvm/support.h>
#include <asm/vm_event.h>

static void hvm_vm_event_set_registers(const struct vcpu *v)
{
    ASSERT(v == current);

    if ( unlikely(v->arch.vm_event->set_gprs) )
    {
        struct cpu_user_regs *regs = guest_cpu_user_regs();

        regs->rax = v->arch.vm_event->gprs.rax;
        regs->rbx = v->arch.vm_event->gprs.rbx;
        regs->rcx = v->arch.vm_event->gprs.rcx;
        regs->rdx = v->arch.vm_event->gprs.rdx;
        regs->rsp = v->arch.vm_event->gprs.rsp;
        regs->rbp = v->arch.vm_event->gprs.rbp;
        regs->rsi = v->arch.vm_event->gprs.rsi;
        regs->rdi = v->arch.vm_event->gprs.rdi;

        regs->r8 = v->arch.vm_event->gprs.r8;
        regs->r9 = v->arch.vm_event->gprs.r9;
        regs->r10 = v->arch.vm_event->gprs.r10;
        regs->r11 = v->arch.vm_event->gprs.r11;
        regs->r12 = v->arch.vm_event->gprs.r12;
        regs->r13 = v->arch.vm_event->gprs.r13;
        regs->r14 = v->arch.vm_event->gprs.r14;
        regs->r15 = v->arch.vm_event->gprs.r15;

        regs->rflags = v->arch.vm_event->gprs.rflags;
        regs->rip = v->arch.vm_event->gprs.rip;

        v->arch.vm_event->set_gprs = false;
    }
}

void hvm_vm_event_do_resume(struct vcpu *v)
{
    struct monitor_write_data *w;

    ASSERT(v->arch.vm_event);

    hvm_vm_event_set_registers(v);

    w = &v->arch.vm_event->write_data;

    if ( unlikely(v->arch.vm_event->emulate_flags) )
    {
        enum emul_kind kind = EMUL_KIND_NORMAL;

        /*
         * Please observe the order here to match the flag descriptions
         * provided in public/vm_event.h
         */
        if ( v->arch.vm_event->emulate_flags &
             VM_EVENT_FLAG_SET_EMUL_READ_DATA )
            kind = EMUL_KIND_SET_CONTEXT_DATA;
        else if ( v->arch.vm_event->emulate_flags &
                  VM_EVENT_FLAG_EMULATE_NOWRITE )
            kind = EMUL_KIND_NOWRITE;
        else if ( v->arch.vm_event->emulate_flags &
                  VM_EVENT_FLAG_SET_EMUL_INSN_DATA )
            kind = EMUL_KIND_SET_CONTEXT_INSN;

        hvm_emulate_one_vm_event(kind, TRAP_invalid_op,
                                 X86_EVENT_NO_EC);

        v->arch.vm_event->emulate_flags = 0;
    }

    if ( unlikely(w->do_write.cr0) )
    {
        if ( hvm_set_cr0(w->cr0, 0) == X86EMUL_EXCEPTION )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);

        w->do_write.cr0 = 0;
    }

    if ( unlikely(w->do_write.cr4) )
    {
        if ( hvm_set_cr4(w->cr4, 0) == X86EMUL_EXCEPTION )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);

        w->do_write.cr4 = 0;
    }

    if ( unlikely(w->do_write.cr3) )
    {
        if ( hvm_set_cr3(w->cr3, 0) == X86EMUL_EXCEPTION )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);

        w->do_write.cr3 = 0;
    }

    if ( unlikely(w->do_write.msr) )
    {
        if ( hvm_msr_write_intercept(w->msr, w->value, 0) ==
             X86EMUL_EXCEPTION )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);

        w->do_write.msr = 0;
    }
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
