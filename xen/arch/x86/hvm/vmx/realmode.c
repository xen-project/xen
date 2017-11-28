/******************************************************************************
 * arch/x86/hvm/vmx/realmode.c
 * 
 * Real-mode emulation for VMX.
 * 
 * Copyright (c) 2007-2008 Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/softirq.h>
#include <asm/event.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

static void realmode_deliver_exception(
    unsigned int vector,
    unsigned int insn_len,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct segment_register *idtr, *csr;
    struct cpu_user_regs *regs = hvmemul_ctxt->ctxt.regs;
    uint32_t cs_eip, pstk;
    uint16_t frame[3];
    unsigned int last_byte;

    idtr = hvmemul_get_seg_reg(x86_seg_idtr, hvmemul_ctxt);
    csr  = hvmemul_get_seg_reg(x86_seg_cs,   hvmemul_ctxt);
    __set_bit(x86_seg_cs, &hvmemul_ctxt->seg_reg_dirty);

 again:
    last_byte = (vector * 4) + 3;
    if ( idtr->limit < last_byte ||
         hvm_copy_from_guest_phys(&cs_eip, idtr->base + vector * 4, 4) !=
         HVMTRANS_okay )
    {
        /* Software interrupt? */
        if ( insn_len != 0 )
        {
            insn_len = 0;
            vector = TRAP_gp_fault;
            goto again;
        }

        /* Exception or hardware interrupt. */
        switch ( vector )
        {
        case TRAP_double_fault:
            hvm_triple_fault();
            return;
        case TRAP_gp_fault:
            vector = TRAP_double_fault;
            goto again;
        default:
            vector = TRAP_gp_fault;
            goto again;
        }
    }

    frame[0] = regs->ip + insn_len;
    frame[1] = csr->sel;
    frame[2] = regs->flags & ~X86_EFLAGS_RF;

    /* We can't test hvmemul_ctxt->ctxt.sp_size: it may not be initialised. */
    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].db )
        pstk = regs->esp -= 6;
    else
        pstk = regs->sp -= 6;

    pstk += hvmemul_get_seg_reg(x86_seg_ss, hvmemul_ctxt)->base;
    (void)hvm_copy_to_guest_phys(pstk, frame, sizeof(frame), current);

    csr->sel  = cs_eip >> 16;
    csr->base = (uint32_t)csr->sel << 4;
    regs->ip = (uint16_t)cs_eip;
    regs->eflags &= ~(X86_EFLAGS_TF | X86_EFLAGS_IF | X86_EFLAGS_RF);

    /* Exception delivery clears STI and MOV-SS blocking. */
    if ( hvmemul_ctxt->intr_shadow &
         (VMX_INTR_SHADOW_STI|VMX_INTR_SHADOW_MOV_SS) )
    {
        hvmemul_ctxt->intr_shadow &=
            ~(VMX_INTR_SHADOW_STI|VMX_INTR_SHADOW_MOV_SS);
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, hvmemul_ctxt->intr_shadow);
    }
}

void vmx_realmode_emulate_one(struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    perfc_incr(realmode_emulations);

    rc = hvm_emulate_one(hvmemul_ctxt);

    if ( hvm_vcpu_io_need_completion(vio) )
        vio->io_completion = HVMIO_realmode_completion;

    if ( rc == X86EMUL_UNHANDLEABLE )
    {
        gdprintk(XENLOG_ERR, "Failed to emulate insn.\n");
        goto fail;
    }

    if ( rc == X86EMUL_UNRECOGNIZED )
    {
        gdprintk(XENLOG_ERR, "Unrecognized insn.\n");
        if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
            goto fail;

        realmode_deliver_exception(TRAP_invalid_op, 0, hvmemul_ctxt);
    }

    if ( rc == X86EMUL_EXCEPTION )
    {
        if ( unlikely(curr->domain->debugger_attached) &&
             ((hvmemul_ctxt->ctxt.event.vector == TRAP_debug) ||
              (hvmemul_ctxt->ctxt.event.vector == TRAP_int3)) )
        {
            domain_pause_for_debugger();
        }
        else if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        {
            gdprintk(XENLOG_ERR, "Exception %02x in protected mode.\n",
                     hvmemul_ctxt->ctxt.event.vector);
            goto fail;
        }
        else
        {
            realmode_deliver_exception(
                hvmemul_ctxt->ctxt.event.vector,
                hvmemul_ctxt->ctxt.event.insn_len,
                hvmemul_ctxt);
        }
    }

    return;

 fail:
    hvm_dump_emulation_state(XENLOG_G_ERR, "Real-mode", hvmemul_ctxt, rc);
    domain_crash(curr->domain);
}

void vmx_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct hvm_emulate_ctxt hvmemul_ctxt;
    struct segment_register *sreg;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    unsigned long intr_info;
    unsigned int emulations = 0;

    /* Get-and-clear VM_ENTRY_INTR_INFO. */
    __vmread(VM_ENTRY_INTR_INFO, &intr_info);
    if ( intr_info & INTR_INFO_VALID_MASK )
        __vmwrite(VM_ENTRY_INTR_INFO, 0);

    hvm_emulate_init_once(&hvmemul_ctxt, NULL, regs);

    /* Only deliver interrupts into emulated real mode. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) &&
         (intr_info & INTR_INFO_VALID_MASK) )
    {
        realmode_deliver_exception((uint8_t)intr_info, 0, &hvmemul_ctxt);
        intr_info = 0;
    }

    curr->arch.hvm_vmx.vmx_emulate = 1;
    while ( curr->arch.hvm_vmx.vmx_emulate &&
            !softirq_pending(smp_processor_id()) )
    {
        /*
         * Check for pending interrupts only every 16 instructions, because
         * hvm_local_events_need_delivery() is moderately expensive, and only
         * in real mode, because we don't emulate protected-mode IDT vectoring.
         */
        if ( unlikely(!(++emulations & 15)) &&
             curr->arch.hvm_vmx.vmx_realmode && 
             hvm_local_events_need_delivery(curr) )
            break;

        vmx_realmode_emulate_one(&hvmemul_ctxt);

        if ( vio->io_req.state != STATE_IOREQ_NONE || vio->mmio_retry )
            break;

        /* Stop emulating unless our segment state is not safe */
        if ( curr->arch.hvm_vmx.vmx_realmode )
            curr->arch.hvm_vmx.vmx_emulate = 
                (curr->arch.hvm_vmx.vm86_segment_mask != 0);
        else
            curr->arch.hvm_vmx.vmx_emulate = 
                 ((hvmemul_ctxt.seg_reg[x86_seg_cs].sel & 3)
                  || (hvmemul_ctxt.seg_reg[x86_seg_ss].sel & 3));
    }

    /* Need to emulate next time if we've started an IO operation */
    if ( vio->io_req.state != STATE_IOREQ_NONE )
        curr->arch.hvm_vmx.vmx_emulate = 1;

    if ( !curr->arch.hvm_vmx.vmx_emulate && !curr->arch.hvm_vmx.vmx_realmode )
    {
        /*
         * Cannot enter protected mode with bogus selector RPLs and DPLs.
         * At this point CS.RPL == SS.RPL == CS.DPL == SS.DPL == 0. For
         * DS, ES, FS and GS the most uninvasive trick is to set DPL == RPL.
         */
        sreg = hvmemul_get_seg_reg(x86_seg_ds, &hvmemul_ctxt);
        sreg->dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_es, &hvmemul_ctxt);
        sreg->dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_fs, &hvmemul_ctxt);
        sreg->dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_gs, &hvmemul_ctxt);
        sreg->dpl = sreg->sel & 3;
        hvmemul_ctxt.seg_reg_dirty |=
            (1ul << x86_seg_ds) | (1ul << x86_seg_es) |
            (1ul << x86_seg_fs) | (1ul << x86_seg_gs);
    }

    hvm_emulate_writeback(&hvmemul_ctxt);

    /* Re-instate VM_ENTRY_INTR_INFO if we did not discharge it. */
    if ( intr_info & INTR_INFO_VALID_MASK )
        __vmwrite(VM_ENTRY_INTR_INFO, intr_info);
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
