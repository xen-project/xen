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
 *
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
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <public/hvm/ioreq.h>
#include <xen/domain_page.h>
#include <asm/hvm/trace.h>

/*
 * Most of this code is copied from vmx_io.c and modified 
 * to be suitable for SVM.
 */

static inline int svm_inject_extint(struct vcpu *v, int trap)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    vintr_t intr = vmcb->vintr;

    /* Update only relevant fields */    
    intr.fields.irq = 1;
    intr.fields.intr_masking = 1;
    intr.fields.vector = trap;
    intr.fields.prio = 0xF;
    intr.fields.ign_tpr = 1;
    vmcb->vintr = intr;

    return 0;
}
    
asmlinkage void svm_intr_assist(void) 
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int intr_type = APIC_DM_EXTINT;
    int intr_vector = -1;

    /*
     * Do not deliver a virtual interrupt (vintr) if an exception is pending.
     * This is because the delivery of the exception can arbitrarily delay
     * the injection of the vintr (for example, if the exception is handled
     * via an interrupt gate, hence zeroing RFLAGS.IF). In the meantime the
     * vTPR can be modified upwards and we can end up delivering the vintr
     * when it is not in fact valid to do so (because we do not re-check the
     * vTPR value). Moreover, the guest will be able to see the updated
     * APIC/PIC state (as if the interrupt had been acknowledged) yet will not
     * have actually received the interrupt. This could confuse the guest!
     */
    if ( vmcb->eventinj.fields.v )
        return;

    /*
     * Previous Interrupt delivery caused this intercept?
     * This will happen if the injection is latched by the processor (hence
     * clearing vintr.fields.irq) but then subsequently a fault occurs (e.g.,
     * due to lack of shadow mapping of guest IDT or guest-kernel stack).
     * 
     * NB. Exceptions that fault during delivery are lost. This needs to be
     * fixed but we'll usually get away with it since faults are usually
     * idempotent. But this isn't the case for e.g. software interrupts!
     */
    if ( vmcb->exitintinfo.fields.v && (vmcb->exitintinfo.fields.type == 0) )
    {
        intr_vector = vmcb->exitintinfo.fields.vector;
        vmcb->exitintinfo.bytes = 0;
        HVMTRACE_1D(REINJ_VIRQ, v, intr_vector);
        svm_inject_extint(v, intr_vector);
        return;
    }

    /*
     * Previous interrupt still pending? This occurs if we return from VMRUN
     * very early in the entry-to-guest process. Usually this is because an
     * external physical interrupt was pending when we executed VMRUN.
     */
    if ( vmcb->vintr.fields.irq )
        return;

    /* Crank the handle on interrupt state and check for new interrrupts. */
    pt_update_irq(v);
    hvm_set_callback_irq_level();
    if ( !cpu_has_pending_irq(v) )
        return;

    /*
     * Create a 'fake' virtual interrupt on to intercept as soon as the
     * guest _can_ take interrupts.  Do not obtain the next interrupt from
     * the vlapic/pic if unable to inject.
     */
    if ( irq_masked(vmcb->rflags) || vmcb->interrupt_shadow )  
    {
        vmcb->general1_intercepts |= GENERAL1_INTERCEPT_VINTR;
        HVMTRACE_2D(INJ_VIRQ, v, 0x0, /*fake=*/ 1);
        svm_inject_extint(v, 0x0); /* actual vector doesn't matter */
        return;
    }

    /* Okay, we can deliver the interrupt: grab it and update PIC state. */
    intr_vector = cpu_get_interrupt(v, &intr_type);
    BUG_ON(intr_vector < 0);

    HVMTRACE_2D(INJ_VIRQ, v, intr_vector, /*fake=*/ 0);
    svm_inject_extint(v, intr_vector);

    pt_intr_post(v, intr_vector, intr_type);
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
