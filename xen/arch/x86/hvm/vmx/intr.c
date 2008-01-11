/*
 * intr.c: handling I/O, interrupts related VMX entry/exit
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2004-2007, XenSource Inc.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/trace.h>

/*
 * A few notes on virtual NMI and INTR delivery, and interactions with
 * interruptibility states:
 * 
 * We can only inject an ExtInt if EFLAGS.IF = 1 and no blocking by
 * STI nor MOV SS. Otherwise the VM entry fails. The 'virtual interrupt
 * pending' control causes a VM exit when all these checks succeed. It will
 * exit immediately after VM entry if the checks succeed at that point.
 * 
 * We can only inject an NMI if no blocking by MOV SS (also, depending on
 * implementation, if no blocking by STI). If pin-based 'virtual NMIs'
 * control is specified then the NMI-blocking interruptibility flag is
 * also checked. The 'virtual NMI pending' control (available only in
 * conjunction with 'virtual NMIs') causes a VM exit when all these checks
 * succeed. It will exit immediately after VM entry if the checks succeed
 * at that point.
 * 
 * Because a processor may or may not check blocking-by-STI when injecting
 * a virtual NMI, it will be necessary to convert that to block-by-MOV-SS
 * before specifying the 'virtual NMI pending' control. Otherwise we could
 * enter an infinite loop where we check blocking-by-STI in software and
 * thus delay delivery of a virtual NMI, but the processor causes immediate
 * VM exit because it does not check blocking-by-STI.
 * 
 * Injecting a virtual NMI sets the NMI-blocking interruptibility flag only
 * if the 'virtual NMIs' control is set. Injecting *any* kind of event clears
 * the STI- and MOV-SS-blocking interruptibility-state flags.
 * 
 * If MOV/POP SS is executed while MOV-SS-blocking is in effect, the effect
 * is cleared. If STI is executed while MOV-SS- or STI-blocking is in effect,
 * the effect is cleared. (i.e., MOV-SS-blocking 'dominates' STI-blocking).
 */

static void enable_intr_window(struct vcpu *v, struct hvm_intack intack)
{
    u32 *cpu_exec_control = &v->arch.hvm_vmx.exec_control;
    u32 ctl = CPU_BASED_VIRTUAL_INTR_PENDING;

    ASSERT(intack.source != hvm_intsrc_none);

    if ( (intack.source == hvm_intsrc_nmi) && cpu_has_vmx_vnmi )
    {
        /*
         * We set MOV-SS blocking in lieu of STI blocking when delivering an
         * NMI. This is because it is processor-specific whether STI-blocking
         * blocks NMIs. Hence we *must* check for STI-blocking on NMI delivery
         * (otherwise vmentry will fail on processors that check for STI-
         * blocking) but if the processor does not check for STI-blocking then
         * we may immediately vmexit and hance make no progress!
         * (see SDM 3B 21.3, "Other Causes of VM Exits").
         */
        u32 intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);
        if ( intr_shadow & VMX_INTR_SHADOW_STI )
        {
            /* Having both STI-blocking and MOV-SS-blocking fails vmentry. */
            intr_shadow &= ~VMX_INTR_SHADOW_STI;
            intr_shadow |= VMX_INTR_SHADOW_MOV_SS;
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
        }
        ctl = CPU_BASED_VIRTUAL_NMI_PENDING;
    }

    if ( !(*cpu_exec_control & ctl) )
    {
        *cpu_exec_control |= ctl;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, *cpu_exec_control);
    }
}

static void vmx_dirq_assist(struct vcpu *v)
{
    unsigned int irq;
    uint32_t device, intx;
    struct domain *d = v->domain;
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    struct dev_intx_gsi_link *digl;

    if ( !vtd_enabled || (v->vcpu_id != 0) || (hvm_irq_dpci == NULL) )
        return;

    for ( irq = find_first_bit(hvm_irq_dpci->dirq_mask, NR_IRQS);
          irq < NR_IRQS;
          irq = find_next_bit(hvm_irq_dpci->dirq_mask, NR_IRQS, irq + 1) )
    {
        stop_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(irq)]);
        clear_bit(irq, &hvm_irq_dpci->dirq_mask);

        list_for_each_entry ( digl, &hvm_irq_dpci->mirq[irq].digl_list, list )
        {
            device = digl->device;
            intx = digl->intx;
            hvm_pci_intx_assert(d, device, intx);
            spin_lock(&hvm_irq_dpci->dirq_lock);
            hvm_irq_dpci->mirq[irq].pending++;
            spin_unlock(&hvm_irq_dpci->dirq_lock);
        }

        /*
         * Set a timer to see if the guest can finish the interrupt or not. For
         * example, the guest OS may unmask the PIC during boot, before the
         * guest driver is loaded. hvm_pci_intx_assert() may succeed, but the
         * guest will never deal with the irq, then the physical interrupt line
         * will never be deasserted.
         */
        set_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(irq)],
                  NOW() + PT_IRQ_TIME_OUT);
    }
}

asmlinkage void vmx_intr_assist(void)
{
    struct hvm_intack intack;
    struct vcpu *v = current;
    unsigned int tpr_threshold = 0;
    enum hvm_intblk intblk;

    /* Crank the handle on interrupt state. */
    pt_update_irq(v);
    vmx_dirq_assist(v);

    do {
        intack = hvm_vcpu_has_pending_irq(v);
        if ( likely(intack.source == hvm_intsrc_none) )
            goto out;

        intblk = hvm_interrupt_blocked(v, intack);
        if ( intblk == hvm_intblk_tpr )
        {
            ASSERT(vlapic_enabled(vcpu_vlapic(v)));
            ASSERT(intack.source == hvm_intsrc_lapic);
            tpr_threshold = intack.vector >> 4;
            goto out;
        }

        if ( (intblk != hvm_intblk_none) ||
             (__vmread(VM_ENTRY_INTR_INFO) & INTR_INFO_VALID_MASK) )
        {
            enable_intr_window(v, intack);
            goto out;
        }

        intack = hvm_vcpu_ack_pending_irq(v, intack);
    } while ( intack.source == hvm_intsrc_none );

    if ( intack.source == hvm_intsrc_nmi )
    {
        vmx_inject_nmi(v);
    }
    else
    {
        HVMTRACE_2D(INJ_VIRQ, v, intack.vector, /*fake=*/ 0);
        vmx_inject_extint(v, intack.vector);
        pt_intr_post(v, intack);
    }

    /* Is there another IRQ to queue up behind this one? */
    intack = hvm_vcpu_has_pending_irq(v);
    if ( unlikely(intack.source != hvm_intsrc_none) )
        enable_intr_window(v, intack);

 out:
    if ( cpu_has_vmx_tpr_shadow )
        __vmwrite(TPR_THRESHOLD, tpr_threshold);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
