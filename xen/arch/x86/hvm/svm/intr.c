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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <asm/hvm/nestedhvm.h> /* for nestedhvm_vcpu_in_guestmode */
#include <xen/event.h>
#include <xen/kernel.h>
#include <public/hvm/ioreq.h>
#include <xen/domain_page.h>
#include <asm/hvm/trace.h>

static void svm_inject_nmi(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    eventinj_t event;

    event.bytes = 0;
    event.fields.v = 1;
    event.fields.type = X86_EVENTTYPE_NMI;
    event.fields.vector = 2;

    ASSERT(vmcb->eventinj.fields.v == 0);
    vmcb->eventinj = event;

    /*
     * SVM does not virtualise the NMI mask, so we emulate it by intercepting
     * the next IRET and blocking NMI injection until the intercept triggers.
     */
    vmcb_set_general1_intercepts(
        vmcb, general1_intercepts | GENERAL1_INTERCEPT_IRET);
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
    uint32_t general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    vintr_t intr;

    ASSERT(intack.source != hvm_intsrc_none);

    if ( nestedhvm_enabled(v->domain) ) {
        struct nestedvcpu *nv = &vcpu_nestedhvm(v);
        if ( nv->nv_vmentry_pending ) {
            struct vmcb_struct *gvmcb = nv->nv_vvmcx;

            /* check if l1 guest injects interrupt into l2 guest via vintr.
             * return here or l2 guest looses interrupts, otherwise.
             */
            ASSERT(gvmcb != NULL);
            intr = vmcb_get_vintr(gvmcb);
            if ( intr.fields.irq )
                return;
        }
    }

    HVMTRACE_3D(INTR_WINDOW, intack.vector, intack.source,
                vmcb->eventinj.fields.v?vmcb->eventinj.fields.vector:-1);

    /*
     * Create a dummy virtual interrupt to intercept as soon as the
     * guest can accept the real interrupt.
     *
     * TODO: Better NMI handling. We need a way to skip a MOV SS interrupt
     * shadow. This is hard to do without hardware support. Also we should
     * not be waiting for EFLAGS.IF to become 1.
     */

    /*
     * NMI-blocking window is handled by IRET interception. We should not
     * inject a VINTR in this case as VINTR is unaware of NMI-blocking and
     * hence we can enter an endless loop (VINTR intercept fires, yet
     * hvm_interrupt_blocked() still indicates NMI-blocking is active, so
     * we inject a VINTR, ...).
     */
    if ( (intack.source == hvm_intsrc_nmi) &&
         (general1_intercepts & GENERAL1_INTERCEPT_IRET) )
        return;

    intr = vmcb_get_vintr(vmcb);
    intr.fields.irq     = 1;
    intr.fields.vector  = 0;
    intr.fields.prio    = intack.vector >> 4;
    intr.fields.ign_tpr = (intack.source != hvm_intsrc_lapic);
    vmcb_set_vintr(vmcb, intr);
    vmcb_set_general1_intercepts(
        vmcb, general1_intercepts | GENERAL1_INTERCEPT_VINTR);
}

void svm_intr_assist(void) 
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct hvm_intack intack;
    enum hvm_intblk intblk;

    /* Crank the handle on interrupt state. */
    pt_update_irq(v);

    do {
        intack = hvm_vcpu_has_pending_irq(v);
        if ( likely(intack.source == hvm_intsrc_none) )
            return;

        intblk = hvm_interrupt_blocked(v, intack);
        if ( intblk == hvm_intblk_svm_gif ) {
            ASSERT(nestedhvm_enabled(v->domain));
            return;
        }

        /* Interrupts for the nested guest are already
         * in the vmcb.
         */
        if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
        {
            int rc;

            /* l2 guest was running when an interrupt for
             * the l1 guest occured.
             */
            rc = nestedsvm_vcpu_interrupt(v, intack);
            switch (rc) {
            case NSVM_INTR_NOTINTERCEPTED:
                /* Inject interrupt into 2nd level guest directly. */
                break;	
            case NSVM_INTR_NOTHANDLED:
            case NSVM_INTR_FORCEVMEXIT:
                return;
            case NSVM_INTR_MASKED:
                /* Guest already enabled an interrupt window. */
                return;
            default:
                panic("%s: nestedsvm_vcpu_interrupt can't handle value %#x",
                    __func__, rc);
            }
        }

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
        if ( unlikely(vmcb->eventinj.fields.v) || intblk )
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
        HVMTRACE_2D(INJ_VIRQ, intack.vector, /*fake=*/ 0);
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
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
