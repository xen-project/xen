/******************************************************************************
 * arch/x86/hvm/vmx/realmode.c
 * 
 * Real-mode emulation for VMX.
 * 
 * Copyright (c) 2007-2008 Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <asm/event.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

struct realmode_emulate_ctxt {
    struct hvm_emulate_ctxt hvm;
    uint32_t intr_shadow;
};

static void realmode_deliver_exception(
    unsigned int vector,
    unsigned int insn_len,
    struct realmode_emulate_ctxt *rm_ctxt)
{
    struct segment_register *idtr, *csr;
    struct cpu_user_regs *regs = rm_ctxt->hvm.ctxt.regs;
    uint32_t cs_eip, pstk;
    uint16_t frame[3];
    unsigned int last_byte;

    idtr = hvmemul_get_seg_reg(x86_seg_idtr, &rm_ctxt->hvm);
    csr  = hvmemul_get_seg_reg(x86_seg_cs,   &rm_ctxt->hvm);
    __set_bit(x86_seg_cs, &rm_ctxt->hvm.seg_reg_dirty);

 again:
    last_byte = (vector * 4) + 3;
    if ( idtr->limit < last_byte )
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

    (void)hvm_copy_from_guest_phys(&cs_eip, idtr->base + vector * 4, 4);

    frame[0] = regs->eip + insn_len;
    frame[1] = csr->sel;
    frame[2] = regs->eflags & ~X86_EFLAGS_RF;

    if ( rm_ctxt->hvm.ctxt.addr_size == 32 )
    {
        regs->esp -= 6;
        pstk = regs->esp;
    }
    else
    {
        pstk = (uint16_t)(regs->esp - 6);
        regs->esp &= ~0xffff;
        regs->esp |= pstk;
    }

    pstk += hvmemul_get_seg_reg(x86_seg_ss, &rm_ctxt->hvm)->base;
    (void)hvm_copy_to_guest_phys(pstk, frame, sizeof(frame));

    csr->sel  = cs_eip >> 16;
    csr->base = (uint32_t)csr->sel << 4;
    regs->eip = (uint16_t)cs_eip;
    regs->eflags &= ~(X86_EFLAGS_TF | X86_EFLAGS_IF | X86_EFLAGS_RF);

    /* Exception delivery clears STI and MOV-SS blocking. */
    if ( rm_ctxt->intr_shadow & (VMX_INTR_SHADOW_STI|VMX_INTR_SHADOW_MOV_SS) )
    {
        rm_ctxt->intr_shadow &= ~(VMX_INTR_SHADOW_STI|VMX_INTR_SHADOW_MOV_SS);
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, rm_ctxt->intr_shadow);
    }
}

static void realmode_emulate_one(struct realmode_emulate_ctxt *rm_ctxt)
{
    struct cpu_user_regs *regs = rm_ctxt->hvm.ctxt.regs;
    struct vcpu *curr = current;
    unsigned long seg_reg_dirty;
    uint32_t new_intr_shadow, intr_info;
    int rc;

    seg_reg_dirty = rm_ctxt->hvm.seg_reg_dirty;
    rm_ctxt->hvm.seg_reg_dirty = 0;

    rc = hvm_emulate_one(&rm_ctxt->hvm);

    if ( test_bit(x86_seg_cs, &rm_ctxt->hvm.seg_reg_dirty) )
    {
        curr->arch.hvm_vmx.vmxemul &= ~VMXEMUL_BAD_CS;
        if ( hvmemul_get_seg_reg(x86_seg_cs, &rm_ctxt->hvm)->sel & 3 )
            curr->arch.hvm_vmx.vmxemul |= VMXEMUL_BAD_CS;
    }

    if ( test_bit(x86_seg_ss, &rm_ctxt->hvm.seg_reg_dirty) )
    {
        curr->arch.hvm_vmx.vmxemul &= ~VMXEMUL_BAD_SS;
        if ( hvmemul_get_seg_reg(x86_seg_ss, &rm_ctxt->hvm)->sel & 3 )
            curr->arch.hvm_vmx.vmxemul |= VMXEMUL_BAD_SS;
    }

    rm_ctxt->hvm.seg_reg_dirty |= seg_reg_dirty;

    if ( rc == X86EMUL_UNHANDLEABLE )
    {
        gdprintk(XENLOG_ERR, "Failed to emulate insn.\n");
        goto fail;
    }

    if ( rc == X86EMUL_RETRY )
        return;

    new_intr_shadow = rm_ctxt->intr_shadow;

    /* MOV-SS instruction toggles MOV-SS shadow, else we just clear it. */
    if ( rm_ctxt->hvm.flags.mov_ss )
        new_intr_shadow ^= VMX_INTR_SHADOW_MOV_SS;
    else
        new_intr_shadow &= ~VMX_INTR_SHADOW_MOV_SS;

    /* STI instruction toggles STI shadow, else we just clear it. */
    if ( rm_ctxt->hvm.flags.sti )
        new_intr_shadow ^= VMX_INTR_SHADOW_STI;
    else
        new_intr_shadow &= ~VMX_INTR_SHADOW_STI;

    /* Update interrupt shadow information in VMCS only if it changes. */
    if ( rm_ctxt->intr_shadow != new_intr_shadow )
    {
        rm_ctxt->intr_shadow = new_intr_shadow;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, rm_ctxt->intr_shadow);
    }

    if ( rc == X86EMUL_EXCEPTION )
    {
        if ( !rm_ctxt->hvm.flags.exn_pending )
        {
            intr_info = __vmread(VM_ENTRY_INTR_INFO);
            __vmwrite(VM_ENTRY_INTR_INFO, 0);
            if ( !(intr_info & INTR_INFO_VALID_MASK) )
            {
                gdprintk(XENLOG_ERR, "Exception pending but no info.\n");
                goto fail;
            }
            rm_ctxt->hvm.exn_vector = (uint8_t)intr_info;
            rm_ctxt->hvm.exn_insn_len = 0;
        }

        if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        {
            gdprintk(XENLOG_ERR, "Exception %02x in protected mode.\n",
                     rm_ctxt->hvm.exn_vector);
            goto fail;
        }

        realmode_deliver_exception(
            rm_ctxt->hvm.exn_vector, rm_ctxt->hvm.exn_insn_len, rm_ctxt);
    }
    else if ( rm_ctxt->hvm.flags.hlt && !hvm_local_events_need_delivery(curr) )
    {
        hvm_hlt(regs->eflags);
    }

    return;

 fail:
    gdprintk(XENLOG_ERR,
             "Real-mode emulation failed @ %04x:%08lx: "
             "%02x %02x %02x %02x %02x %02x\n",
             hvmemul_get_seg_reg(x86_seg_cs, &rm_ctxt->hvm)->sel,
             rm_ctxt->hvm.insn_buf_eip,
             rm_ctxt->hvm.insn_buf[0], rm_ctxt->hvm.insn_buf[1],
             rm_ctxt->hvm.insn_buf[2], rm_ctxt->hvm.insn_buf[3],
             rm_ctxt->hvm.insn_buf[4], rm_ctxt->hvm.insn_buf[5]);
    domain_crash_synchronous();
}

void vmx_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct realmode_emulate_ctxt rm_ctxt;
    struct segment_register *sreg;
    unsigned long intr_info;
    unsigned int emulations = 0;

    /* Get-and-clear VM_ENTRY_INTR_INFO. */
    intr_info = __vmread(VM_ENTRY_INTR_INFO);
    if ( intr_info & INTR_INFO_VALID_MASK )
        __vmwrite(VM_ENTRY_INTR_INFO, 0);

    hvm_emulate_prepare(&rm_ctxt.hvm, regs);
    rm_ctxt.intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);

    if ( curr->arch.hvm_vcpu.io_in_progress ||
         curr->arch.hvm_vcpu.io_completed )
        realmode_emulate_one(&rm_ctxt);

    /* Only deliver interrupts into emulated real mode. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) &&
         (intr_info & INTR_INFO_VALID_MASK) )
    {
        realmode_deliver_exception((uint8_t)intr_info, 0, &rm_ctxt);
        intr_info = 0;
    }

    while ( curr->arch.hvm_vmx.vmxemul &&
            !softirq_pending(smp_processor_id()) &&
            !curr->arch.hvm_vcpu.io_in_progress )
    {
        /*
         * Check for pending interrupts only every 16 instructions, because
         * hvm_local_events_need_delivery() is moderately expensive, and only
         * in real mode, because we don't emulate protected-mode IDT vectoring.
         */
        if ( unlikely(!(++emulations & 15)) &&
             !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) &&
             hvm_local_events_need_delivery(curr) )
            break;
        realmode_emulate_one(&rm_ctxt);
    }

    if ( !curr->arch.hvm_vmx.vmxemul )
    {
        /*
         * Cannot enter protected mode with bogus selector RPLs and DPLs.
         * At this point CS.RPL == SS.RPL == CS.DPL == SS.DPL == 0. For
         * DS, ES, FS and GS the most uninvasive trick is to set DPL == RPL.
         */
        sreg = hvmemul_get_seg_reg(x86_seg_ds, &rm_ctxt.hvm);
        sreg->attr.fields.dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_es, &rm_ctxt.hvm);
        sreg->attr.fields.dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_fs, &rm_ctxt.hvm);
        sreg->attr.fields.dpl = sreg->sel & 3;
        sreg = hvmemul_get_seg_reg(x86_seg_gs, &rm_ctxt.hvm);
        sreg->attr.fields.dpl = sreg->sel & 3;
        rm_ctxt.hvm.seg_reg_dirty |=
            (1ul << x86_seg_ds) | (1ul << x86_seg_es) |
            (1ul << x86_seg_fs) | (1ul << x86_seg_gs);
    }

    hvm_emulate_writeback(&rm_ctxt.hvm);

    /* Re-instate VM_ENTRY_INTR_INFO if we did not discharge it. */
    if ( intr_info & INTR_INFO_VALID_MASK )
        __vmwrite(VM_ENTRY_INTR_INFO, intr_info);
}
