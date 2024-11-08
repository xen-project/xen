/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/traps.c
 *
 * PV low level entry points.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/event.h>
#include <xen/hypercall.h>
#include <xen/lib.h>
#include <xen/softirq.h>

#include <asm/debugreg.h>
#include <asm/irq-vectors.h>
#include <asm/pv/trace.h>
#include <asm/shared.h>
#include <asm/traps.h>

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
    if ( event->type == X86_ET_HW_EXC )
    {
        ASSERT(vector < 32);
        use_error_code = X86_EXC_HAVE_EC & (1u << vector);
    }
    else
    {
        ASSERT(event->type == X86_ET_SW_INT);
        use_error_code = false;
    }
    if ( use_error_code )
        ASSERT(error_code != X86_EVENT_NO_EC);
    else
        ASSERT(error_code == X86_EVENT_NO_EC);

    tb = &curr->arch.pv.trap_bounce;
    ti = &curr->arch.pv.trap_ctxt[vector];

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    switch ( vector | -(event->type == X86_ET_SW_INT) )
    {
    case X86_EXC_PF:
        curr->arch.pv.ctrlreg[2] = event->cr2;
        arch_set_cr2(curr, event->cr2);

        /* Re-set error_code.user flag appropriately for the guest. */
        error_code &= ~PFEC_user_mode;
        if ( !guest_kernel_mode(curr, regs) )
            error_code |= PFEC_user_mode;

        trace_pv_page_fault(event->cr2, error_code);
        break;

    case X86_EXC_DB:
        curr->arch.dr6 = x86_merge_dr6(curr->domain->arch.cpu_policy,
                                       curr->arch.dr6, event->pending_dbg);
        fallthrough;
    default:
        trace_pv_trap(vector, regs->rip, use_error_code, error_code);
        break;
    }

    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = error_code;
    }

    if ( TI_GET_IF(ti) )
        tb->flags |= TBF_INTERRUPT;

    if ( unlikely(null_trap_bounce(curr, tb)) )
    {
        gprintk(XENLOG_ERR,
                "Unhandled: vec %u, %s[%04x]\n",
                vector, vector_name(vector), error_code);

        if ( vector == X86_EXC_PF )
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
    struct trap_bounce *tb = &curr->arch.pv.trap_bounce;

    pv_inject_hw_exception(X86_EXC_MC, X86_EVENT_NO_EC);
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
    struct trap_bounce *tb = &curr->arch.pv.trap_bounce;

    pv_inject_hw_exception(X86_EXC_NMI, X86_EVENT_NO_EC);
    tb->flags &= ~TBF_EXCEPTION; /* not needed for NMI delivery path */

    return !null_trap_bounce(curr, tb);
}

static DEFINE_PER_CPU(struct vcpu *, softirq_nmi_vcpu);

static void cf_check nmi_softirq(void)
{
    struct vcpu **v_ptr = &this_cpu(softirq_nmi_vcpu);

    BUG_ON(*v_ptr == NULL);

    /*
     * Only used to defer wakeup of domain/vcpu to a safe (non-NMI)
     * context.
     */
    vcpu_kick(*v_ptr);
    *v_ptr = NULL;
}

void nocall entry_int80(void);
void nocall entry_int82(void);

void __init pv_trap_init(void)
{
#ifdef CONFIG_PV32
    /* The 32-on-64 hypercall vector is only accessible from ring 1. */
    _set_gate(idt_table + HYPERCALL_VECTOR,
              SYS_DESC_irq_gate, 1, entry_int82);
#endif

    /* Fast trap for int80 (faster than taking the #GP-fixup path). */
    _set_gate(idt_table + LEGACY_SYSCALL_VECTOR, SYS_DESC_irq_gate, 3,
              &entry_int80);

    open_softirq(NMI_SOFTIRQ, nmi_softirq);
}

/*
 * Deliver NMI to PV guest. Return 0 on success.
 * Called in NMI context, so no use of printk().
 */
int pv_raise_nmi(struct vcpu *v)
{
    struct vcpu **v_ptr = &per_cpu(softirq_nmi_vcpu, smp_processor_id());

    if ( cmpxchgptr(v_ptr, NULL, v) )
        return -EBUSY;
    if ( !test_and_set_bool(v->arch.nmi_pending) )
    {
        /* Not safe to wake up a vcpu here */
        raise_softirq(NMI_SOFTIRQ);
        return 0;
    }
    *v_ptr = NULL;

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
