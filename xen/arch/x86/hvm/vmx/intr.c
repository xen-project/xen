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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <asm/apicdef.h>
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
#include <asm/hvm/nestedhvm.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/trace.h>
#include <asm/vm_event.h>

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
 */

static void vmx_enable_intr_window(struct vcpu *v, struct hvm_intack intack)
{
    u32 ctl = CPU_BASED_VIRTUAL_INTR_PENDING;

    ASSERT(intack.source != hvm_intsrc_none);

    if ( unlikely(tb_init_done) )
    {
        unsigned long intr;

        __vmread(VM_ENTRY_INTR_INFO, &intr);
        HVMTRACE_3D(INTR_WINDOW, intack.vector, intack.source,
                    (intr & INTR_INFO_VALID_MASK) ? intr & 0xff : -1);
    }

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
        unsigned long intr_shadow;

        __vmread(GUEST_INTERRUPTIBILITY_INFO, &intr_shadow);
        if ( intr_shadow & VMX_INTR_SHADOW_STI )
        {
            /* Having both STI-blocking and MOV-SS-blocking fails vmentry. */
            intr_shadow &= ~VMX_INTR_SHADOW_STI;
            intr_shadow |= VMX_INTR_SHADOW_MOV_SS;
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
        }
        ctl = CPU_BASED_VIRTUAL_NMI_PENDING;
    }

    if ( !(v->arch.hvm.vmx.exec_control & ctl) )
    {
        v->arch.hvm.vmx.exec_control |= ctl;
        vmx_update_cpu_exec_control(v);
    }
}

/*
 * Injecting interrupts for nested virtualization
 *
 *  When injecting virtual interrupts (originated from L0), there are
 *  two major possibilities, within L1 context and within L2 context
 *   1. L1 context (in_nesting == 0)
 *     Everything is the same as without nested, check RFLAGS.IF to
 *     see if the injection can be done, using VMCS to inject the
 *     interrupt
 *
 *   2. L2 context (in_nesting == 1)
 *     Causes a virtual VMExit, RFLAGS.IF is ignored, whether to ack
 *     irq according to intr_ack_on_exit, shouldn't block normally,
 *     except for:
 *    a. context transition
 *     interrupt needs to be blocked at virtual VMEntry time
 *    b. L2 idtv reinjection
 *     if L2 idtv is handled within L0 (e.g. L0 shadow page fault),
 *     it needs to be reinjected without exiting to L1, interrupt
 *     injection should be blocked as well at this point.
 *
 *  Unfortunately, interrupt blocking in L2 won't work with simple
 *  intr_window_open (which depends on L2's IF). To solve this,
 *  the following algorithm can be used:
 *   v->arch.hvm.vmx.exec_control.VIRTUAL_INTR_PENDING now denotes
 *   only L0 control, physical control may be different from it.
 *       - if in L1, it behaves normally, intr window is written
 *         to physical control as it is
 *       - if in L2, replace it to MTF (or NMI window) if possible
 *       - if MTF/NMI window is not used, intr window can still be
 *         used but may have negative impact on interrupt performance.
 */

enum hvm_intblk nvmx_intr_blocked(struct vcpu *v)
{
    int r = hvm_intblk_none;
    struct nestedvcpu *nvcpu = &vcpu_nestedhvm(v);

    if ( nestedhvm_vcpu_in_guestmode(v) )
    {
        if ( nvcpu->nv_vmexit_pending ||
             nvcpu->nv_vmswitch_in_progress )
            r = hvm_intblk_rflags_ie;
        else
        {
            unsigned long intr_info;

            __vmread(VM_ENTRY_INTR_INFO, &intr_info);
            if ( intr_info & INTR_INFO_VALID_MASK )
                r = hvm_intblk_rflags_ie;
        }
    }
    else if ( nvcpu->nv_vmentry_pending )
        r = hvm_intblk_rflags_ie;

    return r;
}

static int nvmx_intr_intercept(struct vcpu *v, struct hvm_intack intack)
{
    u32 ctrl;

    /* If blocked by L1's tpr, then nothing to do. */
    if ( nestedhvm_vcpu_in_guestmode(v) &&
         hvm_interrupt_blocked(v, intack) == hvm_intblk_tpr )
        return 1;

    if ( nvmx_intr_blocked(v) != hvm_intblk_none )
    {
        vmx_enable_intr_window(v, intack);
        return 1;
    }

    if ( nestedhvm_vcpu_in_guestmode(v) )
    {
        ctrl = get_vvmcs(v, PIN_BASED_VM_EXEC_CONTROL);
        if ( !(ctrl & PIN_BASED_EXT_INTR_MASK) )
            return 0;

        if ( intack.source == hvm_intsrc_pic ||
                 intack.source == hvm_intsrc_lapic )
        {
            vmx_inject_extint(intack.vector, intack.source);

            ctrl = get_vvmcs(v, VM_EXIT_CONTROLS);
            if ( ctrl & VM_EXIT_ACK_INTR_ON_EXIT )
            {
                /* for now, duplicate the ack path in vmx_intr_assist */
                hvm_vcpu_ack_pending_irq(v, intack);
                pt_intr_post(v, intack);

                intack = hvm_vcpu_has_pending_irq(v);
                if ( unlikely(intack.source != hvm_intsrc_none) )
                    vmx_enable_intr_window(v, intack);
            }
            else if ( !cpu_has_vmx_virtual_intr_delivery )
                vmx_enable_intr_window(v, intack);

            return 1;
        }
        else if ( intack.source == hvm_intsrc_vector )
        {
            vmx_inject_extint(intack.vector, intack.source);
            return 1;
        }
    }

    return 0;
}

void vmx_intr_assist(void)
{
    struct hvm_intack intack;
    struct vcpu *v = current;
    unsigned int tpr_threshold = 0;
    enum hvm_intblk intblk;
    int pt_vector;

    /* Block event injection when single step with MTF. */
    if ( unlikely(v->arch.hvm.single_step) )
    {
        v->arch.hvm.vmx.exec_control |= CPU_BASED_MONITOR_TRAP_FLAG;
        vmx_update_cpu_exec_control(v);
        return;
    }

    /* Block event injection while handling a sync vm_event. */
    if ( unlikely(v->arch.vm_event) && v->arch.vm_event->sync_event )
        return;

    /* Crank the handle on interrupt state. */
    pt_vector = pt_update_irq(v);

    do {
        unsigned long intr_info;

        intack = hvm_vcpu_has_pending_irq(v);
        if ( likely(intack.source == hvm_intsrc_none) )
            goto out;

        if ( unlikely(nvmx_intr_intercept(v, intack)) )
            goto out;

        intblk = hvm_interrupt_blocked(v, intack);
        if ( cpu_has_vmx_virtual_intr_delivery )
        {
            /* Set "Interrupt-window exiting" for ExtINT and NMI. */
            if ( (intblk != hvm_intblk_none) &&
                 (intack.source == hvm_intsrc_pic ||
                  intack.source == hvm_intsrc_vector ||
                  intack.source == hvm_intsrc_nmi) )
            {
                vmx_enable_intr_window(v, intack);
                goto out;
            }

            __vmread(VM_ENTRY_INTR_INFO, &intr_info);
            if ( intr_info & INTR_INFO_VALID_MASK )
            {
                if ( (intack.source == hvm_intsrc_pic) ||
                     (intack.source == hvm_intsrc_nmi) ||
                     (intack.source == hvm_intsrc_mce) )
                    vmx_enable_intr_window(v, intack);

                goto out;
            }
        } else if ( intblk == hvm_intblk_tpr )
        {
            ASSERT(vlapic_enabled(vcpu_vlapic(v)));
            ASSERT(intack.source == hvm_intsrc_lapic);
            tpr_threshold = intack.vector >> 4;
            goto out;
        }
        else if ( intblk != hvm_intblk_none )
        {
            vmx_enable_intr_window(v, intack);
            goto out;
        }
        else
        {
            __vmread(VM_ENTRY_INTR_INFO, &intr_info);
            if ( intr_info & INTR_INFO_VALID_MASK )
            {
                vmx_enable_intr_window(v, intack);
                goto out;
            }
        }

        intack = hvm_vcpu_ack_pending_irq(v, intack);
    } while ( intack.source == hvm_intsrc_none );

    if ( intack.source == hvm_intsrc_nmi )
    {
        vmx_inject_nmi();
    }
    else if ( intack.source == hvm_intsrc_mce )
    {
        hvm_inject_hw_exception(TRAP_machine_check, X86_EVENT_NO_EC);
    }
    else if ( cpu_has_vmx_virtual_intr_delivery &&
              intack.source != hvm_intsrc_pic &&
              intack.source != hvm_intsrc_vector )
    {
        unsigned long status;
        unsigned int i, n;

       /*
        * intack.vector is the highest priority vector. So we set eoi_exit_bitmap
        * for intack.vector - give a chance to post periodic time interrupts when
        * periodic time interrupts become the highest one
        */
        if ( pt_vector != -1 )
        {
#ifndef NDEBUG
            /*
             * We assert that intack.vector is the highest priority vector for
             * only an interrupt from vlapic can reach this point and the
             * highest vector is chosen in hvm_vcpu_has_pending_irq().
             * But, in fact, the assertion failed sometimes. It is suspected
             * that PIR is not synced to vIRR which makes pt_vector is left in
             * PIR. In order to verify this suspicion, dump some information
             * when the assertion fails.
             */
            if ( unlikely(intack.vector < pt_vector) )
            {
                const struct vlapic *vlapic;
                const struct pi_desc *pi_desc;
                const uint32_t *word;
                unsigned int i;

                printk(XENLOG_ERR "%pv: intack: %u:%02x pt: %02x\n",
                       current, intack.source, intack.vector, pt_vector);

                vlapic = vcpu_vlapic(v);
                if ( vlapic && vlapic->regs )
                {
                    word = (const void *)&vlapic->regs->data[APIC_IRR];
                    printk(XENLOG_ERR "vIRR:");
                    for ( i = X86_NR_VECTORS / 32; i-- ; )
                        printk(" %08x", word[i*4]);
                    printk("\n");
                }

                pi_desc = &v->arch.hvm.vmx.pi_desc;
                if ( pi_desc )
                {
                    word = (const void *)&pi_desc->pir;
                    printk(XENLOG_ERR " PIR:");
                    for ( i = X86_NR_VECTORS / 32; i-- ; )
                        printk(" %08x", word[i]);
                    printk("\n");
                }
            }
#endif
            ASSERT(intack.vector >= pt_vector);
            vmx_set_eoi_exit_bitmap(v, intack.vector);
        }

        /* we need update the RVI field */
        __vmread(GUEST_INTR_STATUS, &status);
        status &= ~VMX_GUEST_INTR_STATUS_SUBFIELD_BITMASK;
        status |= VMX_GUEST_INTR_STATUS_SUBFIELD_BITMASK &
                    intack.vector;
        __vmwrite(GUEST_INTR_STATUS, status);

        n = ARRAY_SIZE(v->arch.hvm.vmx.eoi_exit_bitmap);
        while ( (i = find_first_bit(&v->arch.hvm.vmx.eoi_exitmap_changed,
                                    n)) < n )
        {
            clear_bit(i, &v->arch.hvm.vmx.eoi_exitmap_changed);
            __vmwrite(EOI_EXIT_BITMAP(i), v->arch.hvm.vmx.eoi_exit_bitmap[i]);
        }

        pt_intr_post(v, intack);
    }
    else
    {
        HVMTRACE_2D(INJ_VIRQ, intack.vector, /*fake=*/ 0);
        vmx_inject_extint(intack.vector, intack.source);
        pt_intr_post(v, intack);
    }

    /* Is there another IRQ to queue up behind this one? */
    intack = hvm_vcpu_has_pending_irq(v);
    if ( !cpu_has_vmx_virtual_intr_delivery ||
         intack.source == hvm_intsrc_pic ||
         intack.source == hvm_intsrc_vector )
    {
        if ( unlikely(intack.source != hvm_intsrc_none) )
            vmx_enable_intr_window(v, intack);
    }

 out:
    if ( !nestedhvm_vcpu_in_guestmode(v) &&
         !cpu_has_vmx_virtual_intr_delivery &&
         cpu_has_vmx_tpr_shadow )
        __vmwrite(TPR_THRESHOLD, tpr_threshold);
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
