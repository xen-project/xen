/******************************************************************************
 * arch/x86/pv/traps.c
 *
 * PV low level entry points.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/event.h>
#include <xen/hypercall.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/softirq.h>

#include <asm/apic.h>
#include <asm/shared.h>
#include <asm/traps.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(mfn) __mfn_to_page(mfn_x(mfn))
#undef page_to_mfn
#define page_to_mfn(pg) _mfn(__page_to_mfn(pg))

void do_entry_int82(struct cpu_user_regs *regs)
{
    if ( unlikely(untrusted_msi) )
        check_for_unexpected_msi((uint8_t)regs->entry_vector);

    pv_hypercall(regs);
}

void pv_inject_event(const struct x86_event *event)
{
    struct vcpu *curr = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct trap_bounce *tb;
    const struct trap_info *ti;
    const uint8_t vector = event->vector;
    unsigned int error_code = event->error_code;
    bool use_error_code;

    ASSERT(vector == event->vector); /* Confirm no truncation. */
    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION )
    {
        ASSERT(vector < 32);
        use_error_code = TRAP_HAVE_EC & (1u << vector);
    }
    else
    {
        ASSERT(event->type == X86_EVENTTYPE_SW_INTERRUPT);
        use_error_code = false;
    }
    if ( use_error_code )
        ASSERT(error_code != X86_EVENT_NO_EC);
    else
        ASSERT(error_code == X86_EVENT_NO_EC);

    tb = &curr->arch.pv_vcpu.trap_bounce;
    ti = &curr->arch.pv_vcpu.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( event->type == X86_EVENTTYPE_HW_EXCEPTION &&
         vector == TRAP_page_fault )
    {
        curr->arch.pv_vcpu.ctrlreg[2] = event->cr2;
        arch_set_cr2(curr, event->cr2);

        /* Re-set error_code.user flag appropriately for the guest. */
        error_code &= ~PFEC_user_mode;
        if ( !guest_kernel_mode(curr, regs) )
            error_code |= PFEC_user_mode;

        trace_pv_page_fault(event->cr2, error_code);
    }
    else
        trace_pv_trap(vector, regs->rip, use_error_code, error_code);

    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = error_code;
    }

    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;

    if ( unlikely(null_trap_bounce(curr, tb)) )
    {
        gprintk(XENLOG_WARNING,
                "Unhandled %s fault/trap [#%d, ec=%04x]\n",
                trapstr(vector), vector, error_code);

        if ( vector == TRAP_page_fault )
            show_page_walk(event->cr2);
    }
}

/*
 * Called from asm to set up the MCE trapbounce info.
 * Returns false no callback is set up, else true.
 */
bool set_guest_machinecheck_trapbounce(void)
{
    struct vcpu *curr = current;
    struct trap_bounce *tb = &curr->arch.pv_vcpu.trap_bounce;

    pv_inject_hw_exception(TRAP_machine_check, X86_EVENT_NO_EC);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for MCE delivery path */

    return !null_trap_bounce(curr, tb);
}

/*
 * Called from asm to set up the NMI trapbounce info.
 * Returns false if no callback is set up, else true.
 */
bool set_guest_nmi_trapbounce(void)
{
    struct vcpu *curr = current;
    struct trap_bounce *tb = &curr->arch.pv_vcpu.trap_bounce;

    pv_inject_hw_exception(TRAP_nmi, X86_EVENT_NO_EC);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */

    return !null_trap_bounce(curr, tb);
}

struct softirq_trap {
    struct domain *domain;   /* domain to inject trap */
    struct vcpu *vcpu;       /* vcpu to inject trap */
    unsigned int processor;  /* physical cpu to inject trap */
};

static DEFINE_PER_CPU(struct softirq_trap, softirq_trap);

static void nmi_mce_softirq(void)
{
    unsigned int cpu = smp_processor_id();
    struct softirq_trap *st = &per_cpu(softirq_trap, cpu);

    BUG_ON(st->vcpu == NULL);

    /*
     * Set the tmp value unconditionally, so that the check in the iret
     * hypercall works.
     */
    cpumask_copy(st->vcpu->cpu_hard_affinity_tmp,
                 st->vcpu->cpu_hard_affinity);

    if ( (cpu != st->processor) ||
         (st->processor != st->vcpu->processor) )
    {

        /*
         * We are on a different physical cpu.  Make sure to wakeup the vcpu on
         * the specified processor.
         */
        vcpu_set_hard_affinity(st->vcpu, cpumask_of(st->processor));

        /* Affinity is restored in the iret hypercall. */
    }

    /*
     * Only used to defer wakeup of domain/vcpu to a safe (non-NMI/MCE)
     * context.
     */
    vcpu_kick(st->vcpu);
    st->vcpu = NULL;
}

void __init pv_trap_init(void)
{
    /* The 32-on-64 hypercall vector is only accessible from ring 1. */
    _set_gate(idt_table + HYPERCALL_VECTOR,
              SYS_DESC_trap_gate, 1, entry_int82);

    /* Fast trap for int80 (faster than taking the #GP-fixup path). */
    _set_gate(idt_table + LEGACY_SYSCALL_VECTOR, SYS_DESC_trap_gate, 3,
              &int80_direct_trap);

    open_softirq(NMI_MCE_SOFTIRQ, nmi_mce_softirq);
}

int pv_raise_interrupt(struct vcpu *v, uint8_t vector)
{
    struct softirq_trap *st = &per_cpu(softirq_trap, smp_processor_id());

    switch ( vector )
    {
    case TRAP_nmi:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;
        if ( !test_and_set_bool(v->nmi_pending) )
        {
            st->domain = v->domain;
            st->processor = v->processor;

            /* Not safe to wake up a vcpu here */
            raise_softirq(NMI_MCE_SOFTIRQ);
            return 0;
        }
        st->vcpu = NULL;
        break;

    case TRAP_machine_check:
        if ( cmpxchgptr(&st->vcpu, NULL, v) )
            return -EBUSY;

        /*
         * We are called by the machine check (exception or polling) handlers
         * on the physical CPU that reported a machine check error.
         */
        if ( !test_and_set_bool(v->mce_pending) )
        {
            st->domain = v->domain;
            st->processor = v->processor;

            /* not safe to wake up a vcpu here */
            raise_softirq(NMI_MCE_SOFTIRQ);
            return 0;
        }
        st->vcpu = NULL;
        break;
    }

    /* Delivery failed */
    return -EIO;
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
