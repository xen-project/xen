/*
 * intr.c: Interrupt handling for SVM.
 * Copyright (c) 2005, AMD Inc. 
 * Copyright (c) 2004, Intel Corporation.
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
#include <xen/trace.h>
#include <xen/errno.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/paging.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <public/hvm/ioreq.h>
#include <xen/domain_page.h>
#include <asm/hvm/trace.h>

static void svm_inject_nmi(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    eventinj_t event;

    event.bytes = 0;
    event.fields.v = 1;
    event.fields.type = X86_EVENTTYPE_NMI;
    event.fields.vector = 2;

    ASSERT(vmcb->eventinj.fields.v == 0);
    vmcb->eventinj = event;
}
    
static void svm_inject_extint(struct vcpu *v, int vector)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    eventinj_t event;

    event.bytes = 0;
    event.fields.v = 1;
    event.fields.type = X86_EVENTTYPE_EXT_INTR;
    event.fields.vector = vector;

    ASSERT(vmcb->eventinj.fields.v == 0);
    vmcb->eventinj = event;
}
    
static void enable_intr_window(struct vcpu *v, struct hvm_intack intack)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    vintr_t intr;

    ASSERT(intack.source != hvm_intsrc_none);

    HVMTRACE_2D(INJ_VIRQ, v, 0x0, /*fake=*/ 1);

    /*
     * Create a dummy virtual interrupt to intercept as soon as the
     * guest can accept the real interrupt.
     *
     * TODO: Better NMI handling. We need a way to skip a MOV SS interrupt
     * shadow. This is hard to do without hardware support. We should also
     * track 'NMI blocking' from NMI injection until IRET. This can be done
     * quite easily in software by intercepting the unblocking IRET.
     */
    intr = vmcb->vintr;
    intr.fields.irq     = 1;
    intr.fields.vector  = 0;
    intr.fields.prio    = intack.vector >> 4;
    intr.fields.ign_tpr = (intack.source != hvm_intsrc_lapic);
    vmcb->vintr = intr;
    vmcb->general1_intercepts |= GENERAL1_INTERCEPT_VINTR;
}

static void svm_dirq_assist(struct vcpu *v)
{
    unsigned int irq;
    uint32_t device, intx;
    struct domain *d = v->domain;
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    struct dev_intx_gsi_link *digl;

    if ( !amd_iommu_enabled || (v->vcpu_id != 0) || (hvm_irq_dpci == NULL) )
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

asmlinkage void svm_intr_assist(void) 
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct hvm_intack intack;

    /* Crank the handle on interrupt state. */
    pt_update_irq(v);
    svm_dirq_assist(v);

    do {
        intack = hvm_vcpu_has_pending_irq(v);
        if ( likely(intack.source == hvm_intsrc_none) )
            return;

        /*
         * Pending IRQs must be delayed if:
         * 1. An event is already pending. This is despite the fact that SVM
         *    provides a VINTR delivery method quite separate from the EVENTINJ
         *    mechanism. The event delivery can arbitrarily delay the injection
         *    of the vintr (for example, if the exception is handled via an
         *    interrupt gate, hence zeroing RFLAGS.IF). In the meantime:
         *    - the vTPR could be modified upwards, so we need to wait until
         *      the exception is delivered before we can safely decide that an
         *      interrupt is deliverable; and
         *    - the guest might look at the APIC/PIC state, so we ought not to
         *      have cleared the interrupt out of the IRR.
         * 2. The IRQ is masked.
         */
        if ( unlikely(vmcb->eventinj.fields.v) ||
             hvm_interrupt_blocked(v, intack) )
        {
            enable_intr_window(v, intack);
            return;
        }

        intack = hvm_vcpu_ack_pending_irq(v, intack);
    } while ( intack.source == hvm_intsrc_none );

    if ( intack.source == hvm_intsrc_nmi )
    {
        svm_inject_nmi(v);
    }
    else
    {
        HVMTRACE_2D(INJ_VIRQ, v, intack.vector, /*fake=*/ 0);
        svm_inject_extint(v, intack.vector);
        pt_intr_post(v, intack);
    }

    /* Is there another IRQ to queue up behind this one? */
    intack = hvm_vcpu_has_pending_irq(v);
    if ( unlikely(intack.source != hvm_intsrc_none) )
        enable_intr_window(v, intack);
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
