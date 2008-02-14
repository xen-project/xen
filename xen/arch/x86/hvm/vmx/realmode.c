/******************************************************************************
 * arch/x86/hvm/vmx/realmode.c
 * 
 * Real-mode emulation for VMX.
 * 
 * Copyright (c) 2007 Citrix Systems, Inc.
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
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/x86_emulate.h>

struct realmode_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;

    /* Cache of 16 bytes of instruction. */
    uint8_t insn_buf[16];
    unsigned long insn_buf_eip;

    struct segment_register seg_reg[10];

    union {
        struct {
            unsigned int hlt:1;
            unsigned int mov_ss:1;
            unsigned int sti:1;
        } flags;
        unsigned int flag_word;
    };

    uint8_t exn_vector;
    uint8_t exn_insn_len;

    uint32_t intr_shadow;
};

static void realmode_deliver_exception(
    unsigned int vector,
    unsigned int insn_len,
    struct realmode_emulate_ctxt *rm_ctxt)
{
    struct segment_register *idtr = &rm_ctxt->seg_reg[x86_seg_idtr];
    struct segment_register *csr = &rm_ctxt->seg_reg[x86_seg_cs];
    struct cpu_user_regs *regs = rm_ctxt->ctxt.regs;
    uint32_t cs_eip, pstk;
    uint16_t frame[3];
    unsigned int last_byte;

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

    if ( rm_ctxt->ctxt.addr_size == 32 )
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

    pstk += rm_ctxt->seg_reg[x86_seg_ss].base;
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

static uint32_t virtual_to_linear(
    enum x86_segment seg,
    uint32_t offset,
    struct realmode_emulate_ctxt *rm_ctxt)
{
    uint32_t addr = offset;
    if ( seg == x86_seg_none )
        return addr;
    ASSERT(is_x86_user_segment(seg));
    return addr + rm_ctxt->seg_reg[seg].base;
}

static int
realmode_read(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long *val,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct realmode_emulate_ctxt *rm_ctxt)
{
    uint32_t addr = virtual_to_linear(seg, offset, rm_ctxt);

    *val = 0;

    if ( hvm_copy_from_guest_virt_nofault(val, addr, bytes) )
    {
        struct vcpu *curr = current;

        if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
            return X86EMUL_UNHANDLEABLE;

        if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
            return X86EMUL_UNHANDLEABLE;

        if ( !curr->arch.hvm_vmx.real_mode_io_completed )
        {
            curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
            send_mmio_req(IOREQ_TYPE_COPY, addr, 1, bytes,
                          0, IOREQ_READ, 0, 0);
        }

        if ( !curr->arch.hvm_vmx.real_mode_io_completed )
            return X86EMUL_RETRY;

        *val = curr->arch.hvm_vmx.real_mode_io_data;
        curr->arch.hvm_vmx.real_mode_io_completed = 0;
    }

    return X86EMUL_OKAY;
}

static int
realmode_emulate_read(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long *val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return realmode_read(
        seg, offset, val, bytes, hvm_access_read,
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt));
}

static int
realmode_emulate_insn_fetch(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long *val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    unsigned int insn_off = offset - rm_ctxt->insn_buf_eip;

    /* Fall back if requested bytes are not in the prefetch cache. */
    if ( unlikely((insn_off + bytes) > sizeof(rm_ctxt->insn_buf)) )
        return realmode_read(
            seg, offset, val, bytes,
            hvm_access_insn_fetch, rm_ctxt);

    /* Hit the cache. Simple memcpy. */
    *val = 0;
    memcpy(val, &rm_ctxt->insn_buf[insn_off], bytes);
    return X86EMUL_OKAY;
}

static int
realmode_emulate_write(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    uint32_t addr = virtual_to_linear(seg, offset, rm_ctxt);

    if ( hvm_copy_to_guest_virt_nofault(addr, &val, bytes) )
    {
        struct vcpu *curr = current;

        if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
            return X86EMUL_UNHANDLEABLE;

        if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
            return X86EMUL_UNHANDLEABLE;

        curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
        send_mmio_req(IOREQ_TYPE_COPY, addr, 1, bytes,
                      val, IOREQ_WRITE, 0, 0);
    }

    return X86EMUL_OKAY;
}

static int 
realmode_emulate_cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    unsigned long old,
    unsigned long new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    /* Fix this in case the guest is really relying on r-m-w atomicity. */
    return realmode_emulate_write(seg, offset, new, bytes, ctxt);
}

static int 
realmode_rep_ins(
    uint16_t src_port,
    enum x86_segment dst_seg,
    unsigned long dst_offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    struct vcpu *curr = current;
    uint32_t paddr = virtual_to_linear(dst_seg, dst_offset, rm_ctxt);

    if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        return X86EMUL_UNHANDLEABLE;

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
        return X86EMUL_UNHANDLEABLE;

    if ( !curr->arch.hvm_vmx.real_mode_io_completed )
    {
        curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
        send_pio_req(src_port, *reps, bytes_per_rep,
                     paddr, IOREQ_READ,
                     !!(ctxt->regs->eflags & X86_EFLAGS_DF), 1);
    }

    if ( !curr->arch.hvm_vmx.real_mode_io_completed )
        return X86EMUL_RETRY;

    curr->arch.hvm_vmx.real_mode_io_completed = 0;

    return X86EMUL_OKAY;
}

static int 
realmode_rep_outs(
    enum x86_segment src_seg,
    unsigned long src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    struct vcpu *curr = current;
    uint32_t paddr = virtual_to_linear(src_seg, src_offset, rm_ctxt);

    if ( curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        return X86EMUL_UNHANDLEABLE;

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
        return X86EMUL_UNHANDLEABLE;

    curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
    send_pio_req(dst_port, *reps, bytes_per_rep,
                 paddr, IOREQ_WRITE,
                 !!(ctxt->regs->eflags & X86_EFLAGS_DF), 1);

    return X86EMUL_OKAY;
}

static int 
realmode_rep_movs(
   enum x86_segment src_seg,
   unsigned long src_offset,
   enum x86_segment dst_seg,
   unsigned long dst_offset,
   unsigned int bytes_per_rep,
   unsigned long *reps,
   struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    struct vcpu *curr = current;
    uint32_t saddr = virtual_to_linear(src_seg, src_offset, rm_ctxt);
    uint32_t daddr = virtual_to_linear(dst_seg, dst_offset, rm_ctxt);
    p2m_type_t p2mt;

    if ( (curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) ||
         curr->arch.hvm_vmx.real_mode_io_in_progress )
        return X86EMUL_UNHANDLEABLE;

    mfn_x(gfn_to_mfn_current(saddr >> PAGE_SHIFT, &p2mt));
    if ( !p2m_is_ram(p2mt) )
    {
        if ( !curr->arch.hvm_vmx.real_mode_io_completed )
        {
            curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
            send_mmio_req(IOREQ_TYPE_COPY, saddr, *reps, bytes_per_rep,
                      daddr, IOREQ_READ,
                      !!(ctxt->regs->eflags & X86_EFLAGS_DF), 1);
        }

        if ( !curr->arch.hvm_vmx.real_mode_io_completed )
            return X86EMUL_RETRY;

        curr->arch.hvm_vmx.real_mode_io_completed = 0;
    }
    else
    {
        mfn_x(gfn_to_mfn_current(daddr >> PAGE_SHIFT, &p2mt));
        if ( p2m_is_ram(p2mt) )
            return X86EMUL_UNHANDLEABLE;
        curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
        send_mmio_req(IOREQ_TYPE_COPY, daddr, *reps, bytes_per_rep,
                      saddr, IOREQ_WRITE,
                      !!(ctxt->regs->eflags & X86_EFLAGS_DF), 1);
    }

    return X86EMUL_OKAY;
}

static int
realmode_read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    memcpy(reg, &rm_ctxt->seg_reg[seg], sizeof(struct segment_register));
    return X86EMUL_OKAY;
}

static int
realmode_write_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    struct vcpu *curr = current;

    if ( seg == x86_seg_cs )
    {
        if ( reg->attr.fields.dpl != 0 )
            return X86EMUL_UNHANDLEABLE;
        curr->arch.hvm_vmx.vmxemul &= ~VMXEMUL_BAD_CS;
        if ( reg->sel & 3 )
            curr->arch.hvm_vmx.vmxemul |= VMXEMUL_BAD_CS;
    }

    if ( seg == x86_seg_ss )
    {
        if ( reg->attr.fields.dpl != 0 )
            return X86EMUL_UNHANDLEABLE;
        curr->arch.hvm_vmx.vmxemul &= ~VMXEMUL_BAD_SS;
        if ( reg->sel & 3 )
            curr->arch.hvm_vmx.vmxemul |= VMXEMUL_BAD_SS;
        rm_ctxt->flags.mov_ss = 1;
    }

    memcpy(&rm_ctxt->seg_reg[seg], reg, sizeof(struct segment_register));

    return X86EMUL_OKAY;
}

static int
realmode_read_io(
    unsigned int port,
    unsigned int bytes,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
        return X86EMUL_UNHANDLEABLE;

    if ( !curr->arch.hvm_vmx.real_mode_io_completed )
    {
        curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
        send_pio_req(port, 1, bytes, 0, IOREQ_READ, 0, 0);
    }

    if ( !curr->arch.hvm_vmx.real_mode_io_completed )
        return X86EMUL_RETRY;

    *val = curr->arch.hvm_vmx.real_mode_io_data;
    curr->arch.hvm_vmx.real_mode_io_completed = 0;

    return X86EMUL_OKAY;
}

static int realmode_write_io(
    unsigned int port,
    unsigned int bytes,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    if ( port == 0xe9 )
    {
        hvm_print_line(curr, val);
        return X86EMUL_OKAY;
    }

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
        return X86EMUL_UNHANDLEABLE;

    curr->arch.hvm_vmx.real_mode_io_in_progress = 1;
    send_pio_req(port, 1, bytes, val, IOREQ_WRITE, 0, 0);

    return X86EMUL_OKAY;
}

static int
realmode_read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        *val = current->arch.hvm_vcpu.guest_cr[reg];
        break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static int
realmode_write_cr(
    unsigned int reg,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
        if ( !hvm_set_cr0(val) )
            return X86EMUL_UNHANDLEABLE;
        break;
    case 2:
        current->arch.hvm_vcpu.guest_cr[2] = val;
        break;
    case 3:
        if ( !hvm_set_cr3(val) )
            return X86EMUL_UNHANDLEABLE;
        break;
    case 4:
        if ( !hvm_set_cr4(val) )
            return X86EMUL_UNHANDLEABLE;
        break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static int
realmode_read_msr(
    unsigned long reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    struct cpu_user_regs _regs;

    _regs.ecx = (uint32_t)reg;

    if ( !vmx_msr_read_intercept(&_regs) )
    {
        struct realmode_emulate_ctxt *rm_ctxt =
            container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
        rm_ctxt->exn_vector = (uint8_t)__vmread(VM_ENTRY_INTR_INFO);
        rm_ctxt->exn_insn_len = 0;
        __vmwrite(VM_ENTRY_INTR_INFO, 0);
        return X86EMUL_EXCEPTION;
    }

    *val = ((uint64_t)(uint32_t)_regs.edx << 32) || (uint32_t)_regs.eax;
    return X86EMUL_OKAY;
}

static int
realmode_write_msr(
    unsigned long reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    struct cpu_user_regs _regs;

    _regs.edx = (uint32_t)(val >> 32);
    _regs.eax = (uint32_t)val;
    _regs.ecx = (uint32_t)reg;

    if ( !vmx_msr_write_intercept(&_regs) )
    {
        struct realmode_emulate_ctxt *rm_ctxt =
            container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
        rm_ctxt->exn_vector = (uint8_t)__vmread(VM_ENTRY_INTR_INFO);
        rm_ctxt->exn_insn_len = 0;
        __vmwrite(VM_ENTRY_INTR_INFO, 0);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

static int realmode_write_rflags(
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    if ( (val & X86_EFLAGS_IF) && !(ctxt->regs->eflags & X86_EFLAGS_IF) )
        rm_ctxt->flags.sti = 1;
    return X86EMUL_OKAY;
}

static int realmode_wbinvd(
    struct x86_emulate_ctxt *ctxt)
{
    vmx_wbinvd_intercept();
    return X86EMUL_OKAY;
}

static int realmode_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    vmx_cpuid_intercept(eax, ebx, ecx, edx);
    return X86EMUL_OKAY;
}

static int realmode_hlt(
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);
    rm_ctxt->flags.hlt = 1;
    return X86EMUL_OKAY;
}

static int realmode_inject_hw_exception(
    uint8_t vector,
    uint16_t error_code,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);

    /* We don't emulate protected-mode exception delivery. */
    if ( current->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        return X86EMUL_UNHANDLEABLE;

    if ( error_code != 0 )
        return X86EMUL_UNHANDLEABLE;

    rm_ctxt->exn_vector = vector;
    rm_ctxt->exn_insn_len = 0;

    return X86EMUL_OKAY;
}

static int realmode_inject_sw_interrupt(
    uint8_t vector,
    uint8_t insn_len,
    struct x86_emulate_ctxt *ctxt)
{
    struct realmode_emulate_ctxt *rm_ctxt =
        container_of(ctxt, struct realmode_emulate_ctxt, ctxt);

    /* We don't emulate protected-mode exception delivery. */
    if ( current->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE )
        return X86EMUL_UNHANDLEABLE;

    rm_ctxt->exn_vector = vector;
    rm_ctxt->exn_insn_len = insn_len;

    return X86EMUL_OKAY;
}

static void realmode_load_fpu_ctxt(
    struct x86_emulate_ctxt *ctxt)
{
    if ( !current->fpu_dirtied )
        vmx_do_no_device_fault();
}

static struct x86_emulate_ops realmode_emulator_ops = {
    .read          = realmode_emulate_read,
    .insn_fetch    = realmode_emulate_insn_fetch,
    .write         = realmode_emulate_write,
    .cmpxchg       = realmode_emulate_cmpxchg,
    .rep_ins       = realmode_rep_ins,
    .rep_outs      = realmode_rep_outs,
    .rep_movs      = realmode_rep_movs,
    .read_segment  = realmode_read_segment,
    .write_segment = realmode_write_segment,
    .read_io       = realmode_read_io,
    .write_io      = realmode_write_io,
    .read_cr       = realmode_read_cr,
    .write_cr      = realmode_write_cr,
    .read_msr      = realmode_read_msr,
    .write_msr     = realmode_write_msr,
    .write_rflags  = realmode_write_rflags,
    .wbinvd        = realmode_wbinvd,
    .cpuid         = realmode_cpuid,
    .hlt           = realmode_hlt,
    .inject_hw_exception = realmode_inject_hw_exception,
    .inject_sw_interrupt = realmode_inject_sw_interrupt,
    .load_fpu_ctxt = realmode_load_fpu_ctxt
};

static void realmode_emulate_one(struct realmode_emulate_ctxt *rm_ctxt)
{
    struct cpu_user_regs *regs = rm_ctxt->ctxt.regs;
    struct vcpu *curr = current;
    u32 new_intr_shadow;
    int rc, io_completed;
    unsigned long addr;

    rm_ctxt->ctxt.addr_size =
        rm_ctxt->seg_reg[x86_seg_cs].attr.fields.db ? 32 : 16;
    rm_ctxt->ctxt.sp_size =
        rm_ctxt->seg_reg[x86_seg_ss].attr.fields.db ? 32 : 16;

    rm_ctxt->insn_buf_eip = (uint32_t)regs->eip;
    addr = virtual_to_linear(x86_seg_cs, regs->eip, rm_ctxt);
    if ( hvm_fetch_from_guest_virt_nofault(rm_ctxt->insn_buf, addr,
                                           sizeof(rm_ctxt->insn_buf))
         != HVMCOPY_okay )
    {
        gdprintk(XENLOG_ERR, "Failed to pre-fetch instruction bytes.\n");
        goto fail;
    }

    rm_ctxt->flag_word = 0;

    io_completed = curr->arch.hvm_vmx.real_mode_io_completed;
    if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
    {
        gdprintk(XENLOG_ERR, "I/O in progress before insn is emulated.\n");
        goto fail;
    }

    rc = x86_emulate(&rm_ctxt->ctxt, &realmode_emulator_ops);

    if ( curr->arch.hvm_vmx.real_mode_io_completed )
    {
        gdprintk(XENLOG_ERR, "I/O completion after insn is emulated.\n");
        goto fail;
    }

    if ( rc == X86EMUL_UNHANDLEABLE )
    {
        gdprintk(XENLOG_ERR, "Failed to emulate insn.\n");
        goto fail;
    }

    if ( rc == X86EMUL_RETRY )
    {
        BUG_ON(!curr->arch.hvm_vmx.real_mode_io_in_progress);
        if ( !io_completed )
            return;
        gdprintk(XENLOG_ERR, "Multiple I/O reads in a single insn.\n");
        goto fail;
    }

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress &&
         (get_ioreq(curr)->vp_ioreq.dir == IOREQ_READ) )
    {
        gdprintk(XENLOG_ERR, "I/O read in progress but insn is retired.\n");
        goto fail;
    }

    new_intr_shadow = rm_ctxt->intr_shadow;

    /* MOV-SS instruction toggles MOV-SS shadow, else we just clear it. */
    if ( rm_ctxt->flags.mov_ss )
        new_intr_shadow ^= VMX_INTR_SHADOW_MOV_SS;
    else
        new_intr_shadow &= ~VMX_INTR_SHADOW_MOV_SS;

    /* STI instruction toggles STI shadow, else we just clear it. */
    if ( rm_ctxt->flags.sti )
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
        realmode_deliver_exception(
            rm_ctxt->exn_vector, rm_ctxt->exn_insn_len, rm_ctxt);
    }
    else if ( rm_ctxt->flags.hlt && !hvm_local_events_need_delivery(curr) )
    {
        hvm_hlt(regs->eflags);
    }

    return;

 fail:
    gdprintk(XENLOG_ERR,
             "Real-mode emulation failed @ %04x:%08lx: "
             "%02x %02x %02x %02x %02x %02x\n",
             rm_ctxt->seg_reg[x86_seg_cs].sel, rm_ctxt->insn_buf_eip,
             rm_ctxt->insn_buf[0], rm_ctxt->insn_buf[1],
             rm_ctxt->insn_buf[2], rm_ctxt->insn_buf[3],
             rm_ctxt->insn_buf[4], rm_ctxt->insn_buf[5]);
    domain_crash_synchronous();
}

void vmx_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct realmode_emulate_ctxt rm_ctxt;
    unsigned long intr_info = __vmread(VM_ENTRY_INTR_INFO);
    unsigned int i, emulations = 0;

    rm_ctxt.ctxt.regs = regs;

    for ( i = 0; i < 10; i++ )
        hvm_get_segment_register(curr, i, &rm_ctxt.seg_reg[i]);

    rm_ctxt.intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);

    if ( curr->arch.hvm_vmx.real_mode_io_in_progress ||
         curr->arch.hvm_vmx.real_mode_io_completed )
        realmode_emulate_one(&rm_ctxt);

    /* Only deliver interrupts into emulated real mode. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) &&
         (intr_info & INTR_INFO_VALID_MASK) )
    {
        realmode_deliver_exception((uint8_t)intr_info, 0, &rm_ctxt);
        __vmwrite(VM_ENTRY_INTR_INFO, 0);
    }

    while ( curr->arch.hvm_vmx.vmxemul &&
            !softirq_pending(smp_processor_id()) &&
            !curr->arch.hvm_vmx.real_mode_io_in_progress )
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
        rm_ctxt.seg_reg[x86_seg_ds].attr.fields.dpl =
            rm_ctxt.seg_reg[x86_seg_ds].sel & 3;
        rm_ctxt.seg_reg[x86_seg_es].attr.fields.dpl =
            rm_ctxt.seg_reg[x86_seg_es].sel & 3;
        rm_ctxt.seg_reg[x86_seg_fs].attr.fields.dpl =
            rm_ctxt.seg_reg[x86_seg_fs].sel & 3;
        rm_ctxt.seg_reg[x86_seg_gs].attr.fields.dpl =
            rm_ctxt.seg_reg[x86_seg_gs].sel & 3;
    }

    for ( i = 0; i < 10; i++ )
        hvm_set_segment_register(curr, i, &rm_ctxt.seg_reg[i]);
}

int vmx_realmode_io_complete(void)
{
    struct vcpu *curr = current;
    ioreq_t *p = &get_ioreq(curr)->vp_ioreq;

    if ( !curr->arch.hvm_vmx.real_mode_io_in_progress )
        return 0;

    curr->arch.hvm_vmx.real_mode_io_in_progress = 0;
    if ( p->dir == IOREQ_READ )
    {
        curr->arch.hvm_vmx.real_mode_io_completed = 1;
        curr->arch.hvm_vmx.real_mode_io_data = p->data;
    }

    return 1;
}
