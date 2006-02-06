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
#include <xen/shadow.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <public/hvm/ioreq.h>
#include <xen/domain_page.h>

/*
 * Most of this code is copied from vmx_io.c and modified 
 * to be suitable for SVM.
 */
#define BSP_CPU(v)    (!(v->vcpu_id))

static inline int svm_inject_extint(struct vcpu *v, int trap, int error_code)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    vintr_t intr;

    ASSERT(vmcb);

    /* Save all fields */
    intr = vmcb->vintr;
    /* Update only relevant fields */    
    intr.fields.irq = 1;
    intr.fields.intr_masking = 1;
    intr.fields.vector = trap;
    intr.fields.prio = 0xF;
    vmcb->vintr = intr;
//  printf( "IRQ = %d\n", trap );
    return 0;
}

void svm_set_tsc_shift(struct vcpu *v, struct hvm_virpit *vpit)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u64    drift;

    if ( vpit->first_injected )
        drift = vpit->period_cycles * vpit->pending_intr_nr;
    else
        drift = 0;
    vmcb->tsc_offset = ( 0 - drift );
}

static inline void
interrupt_post_injection(struct vcpu * v, int vector, int type)
{
    struct hvm_virpit *vpit = &(v->domain->arch.hvm_domain.vpit);

    switch(type)
    {
    case VLAPIC_DELIV_MODE_EXT:
    case VLAPIC_DELIV_MODE_FIXED:
    case VLAPIC_DELIV_MODE_LPRI:
        if ( is_pit_irq(v, vector, type) ) {
            if ( !vpit->first_injected ) {
                vpit->first_injected = 1;
                vpit->pending_intr_nr = 0;
            }
            else if (vpit->pending_intr_nr) {
                --vpit->pending_intr_nr;
            }
            vpit->inject_point = NOW();
            svm_set_tsc_shift (v, vpit);
        }
        break;

    default:
        printk("Not support interrupt type: %d\n", type);
        break;
    }
}

asmlinkage void svm_intr_assist(void) 
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct hvm_domain *plat=&v->domain->arch.hvm_domain; 
    struct hvm_virpit *vpit = &plat->vpit;
    struct hvm_virpic *pic= &plat->vpic;
    int intr_type = VLAPIC_DELIV_MODE_EXT;
    int intr_vector = -1;
    int re_injecting = 0;
    unsigned long rflags;

    ASSERT(vmcb);

    /* Check if an Injection is active */
    if (v->arch.hvm_svm.injecting_event) {
       /* Previous Interrupt delivery caused this Intercept? */
       if (vmcb->exitintinfo.fields.v && (vmcb->exitintinfo.fields.type == 0)) {
           v->arch.hvm_svm.saved_irq_vector = vmcb->exitintinfo.fields.vector;
//           printk("Injecting PF#: saving IRQ from ExitInfo\n");
           vmcb->exitintinfo.bytes = 0;

           /* bail out, we won't be injecting an interrupt this time */
           return;
       }
    }

    /* Guest's interrputs masked? */
    rflags = vmcb->rflags;
    if (irq_masked(rflags)) {
        HVM_DBG_LOG(DBG_LEVEL_1, "Guest IRQs masked: rflags: %lx", rflags);
       /* bail out, we won't be injecting an interrupt this time */
       return;
    }

    /* Interrupt delivery caused an Intercept? */
    if (vmcb->exitintinfo.fields.v && (vmcb->exitintinfo.fields.type == 0)) {
//        printk("Re-injecting IRQ from ExitInfo\n");
        intr_vector = vmcb->exitintinfo.fields.vector;
        vmcb->exitintinfo.bytes = 0;
        re_injecting = 1;
    }
    /* Previous interrupt still pending? */
    else if (vmcb->vintr.fields.irq) {
//        printk("Re-injecting IRQ from Vintr\n");
        intr_vector = vmcb->vintr.fields.vector;
        vmcb->vintr.bytes = 0;
        re_injecting = 1;
    }
    /* Pending IRQ saved at last VMExit? */
    else if ( v->arch.hvm_svm.saved_irq_vector >= 0) {
//        printk("Re-Injecting saved IRQ\n");
        intr_vector = v->arch.hvm_svm.saved_irq_vector;
        v->arch.hvm_svm.saved_irq_vector = -1;
        re_injecting = 1;
    }
    /* Now let's check for newer interrrupts  */
    else {
        /* Interrput pending at the PIC? */
        hvm_pic_assist(v);

        if (vpit->pending_intr_nr) {
            pic_set_irq(pic, 0, 0);
            pic_set_irq(pic, 0, 1);
        }

        if (plat->interrupt_request) {
            intr_vector = cpu_get_interrupt(v, &intr_type);
            plat->interrupt_request = 0;
        }
    }

    /* have we got an interrupt to inject? */
    if (intr_vector >= 0) {
        switch (intr_type) {
        case VLAPIC_DELIV_MODE_EXT:
        case VLAPIC_DELIV_MODE_FIXED:
        case VLAPIC_DELIV_MODE_LPRI:
            /* Re-injecting a PIT interruptt? */
            if (re_injecting && 
                is_pit_irq(v, intr_vector, intr_type)) {
                    ++vpit->pending_intr_nr;
            }
            /* let's inject this interrupt */
            TRACE_3D(TRC_VMX_INT, v->domain->domain_id, intr_vector, 0);
            svm_inject_extint(v, intr_vector, VMX_INVALID_ERROR_CODE);
            interrupt_post_injection(v, intr_vector, intr_type);
            break;
        case VLAPIC_DELIV_MODE_SMI:
        case VLAPIC_DELIV_MODE_NMI:
        case VLAPIC_DELIV_MODE_INIT:
        case VLAPIC_DELIV_MODE_STARTUP:
        default:
            printk("Unsupported interrupt type: %d\n", intr_type);
            BUG();
            break;
        }
    }
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
