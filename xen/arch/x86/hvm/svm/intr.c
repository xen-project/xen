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

static void svm_inject_dummy_vintr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    vintr_t intr = vmcb->vintr;

    intr.fields.irq = 1;
    intr.fields.intr_masking = 1;
    intr.fields.vector = 0;
    intr.fields.prio = 0xF;
    intr.fields.ign_tpr = 1;
    vmcb->vintr = intr;
}
    
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
    
static void enable_intr_window(struct vcpu *v, enum hvm_intack intr_source)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;

    ASSERT(intr_source != hvm_intack_none);

    /*
     * Create a dummy virtual interrupt to intercept as soon as the
     * guest can accept the real interrupt.
     *
     * TODO: Better NMI handling. We need a way to skip a MOV SS interrupt
     * shadow. This is hard to do without hardware support. We should also
     * track 'NMI blocking' from NMI injection until IRET. This can be done
     * quite easily in software by intercepting the unblocking IRET.
     */
    vmcb->general1_intercepts |= GENERAL1_INTERCEPT_VINTR;
    HVMTRACE_2D(INJ_VIRQ, v, 0x0, /*fake=*/ 1);
    svm_inject_dummy_vintr(v);
}

static void update_cr8_intercept(
    struct vcpu *v, enum hvm_intack masked_intr_source)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct vlapic *vlapic = vcpu_vlapic(v);
    int max_irr;

    vmcb->cr_intercepts &= ~CR_INTERCEPT_CR8_WRITE;

    /*
     * If ExtInts are masked then that dominates the TPR --- the 'interrupt
     * window' has already been enabled in this case.
     */
    if ( (masked_intr_source == hvm_intack_lapic) ||
         (masked_intr_source == hvm_intack_pic) )
        return;

    /* Is there an interrupt pending at the LAPIC? Nothing to do if not. */
    if ( !vlapic_enabled(vlapic) || 
         ((max_irr = vlapic_find_highest_irr(vlapic)) == -1) )
        return;

    /* Highest-priority pending interrupt is masked by the TPR? */
    if ( (vmcb->vintr.fields.tpr & 0xf) >= (max_irr >> 4) )
        vmcb->cr_intercepts |= CR_INTERCEPT_CR8_WRITE;
}

asmlinkage void svm_intr_assist(void) 
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    enum hvm_intack intr_source;
    int intr_vector;

    /* Crank the handle on interrupt state. */
    pt_update_irq(v);
    hvm_set_callback_irq_level();

    do {
        intr_source = hvm_vcpu_has_pending_irq(v);
        if ( likely(intr_source == hvm_intack_none) )
            goto out;

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
             !hvm_interrupts_enabled(v, intr_source) )
        {
            enable_intr_window(v, intr_source);
            goto out;
        }
    } while ( !hvm_vcpu_ack_pending_irq(v, intr_source, &intr_vector) );

    if ( intr_source == hvm_intack_nmi )
    {
        svm_inject_nmi(v);
    }
    else
    {
        HVMTRACE_2D(INJ_VIRQ, v, intr_vector, /*fake=*/ 0);
        svm_inject_extint(v, intr_vector);
        pt_intr_post(v, intr_vector, intr_source);
    }

    /* Is there another IRQ to queue up behind this one? */
    intr_source = hvm_vcpu_has_pending_irq(v);
    if ( unlikely(intr_source != hvm_intack_none) )
        enable_intr_window(v, intr_source);

 out:
    update_cr8_intercept(v, intr_source);
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
