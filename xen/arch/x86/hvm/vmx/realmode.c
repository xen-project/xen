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
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vmx/cpu.h>
#include <asm/x86_emulate.h>

struct realmode_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;

    /* Cache of up to 31 bytes of instruction. */
    uint8_t insn_buf[31];
    uint8_t insn_buf_bytes;
    unsigned long insn_buf_eip;

    struct segment_register seg_reg[10];
};

static int realmode_translate_linear_addr(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct realmode_emulate_ctxt *rm_ctxt,
    unsigned long *paddr)
{
    struct segment_register *reg = &rm_ctxt->seg_reg[seg];
    int okay;

    okay = hvm_virtual_to_linear_addr(
        seg, reg, offset, bytes, access_type, rm_ctxt->ctxt.addr_size, paddr);

    if ( !okay )
    {
        hvm_inject_exception(TRAP_gp_fault, 0, 0);
        return X86EMUL_EXCEPTION;
    }

    return 0;
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
    unsigned long addr;
    int rc;

    rc = realmode_translate_linear_addr(
        seg, offset, bytes, access_type, rm_ctxt, &addr);
    if ( rc )
        return rc;

    *val = 0;
    (void)hvm_copy_from_guest_phys(val, addr, bytes);
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
    if ( unlikely((insn_off + bytes) > rm_ctxt->insn_buf_bytes) )
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
    unsigned long addr;
    int rc;

    rc = realmode_translate_linear_addr(
        seg, offset, bytes, hvm_access_write, rm_ctxt, &addr);
    if ( rc )
        return rc;

    (void)hvm_copy_to_guest_phys(addr, &val, bytes);
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
    return X86EMUL_UNHANDLEABLE;
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
    memcpy(&rm_ctxt->seg_reg[seg], reg, sizeof(struct segment_register));

    if ( seg == x86_seg_ss )
    {
        u32 intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);
        intr_shadow ^= VMX_INTR_SHADOW_MOV_SS;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
    }

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
        return X86EMUL_UNHANDLEABLE;
    
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

static int realmode_write_rflags(
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    if ( (val & X86_EFLAGS_IF) && !(ctxt->regs->eflags & X86_EFLAGS_IF) )
    {
        u32 intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);
        intr_shadow ^= VMX_INTR_SHADOW_STI;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
    }

    return X86EMUL_OKAY;
}

static struct x86_emulate_ops realmode_emulator_ops = {
    .read          = realmode_emulate_read,
    .insn_fetch    = realmode_emulate_insn_fetch,
    .write         = realmode_emulate_write,
    .cmpxchg       = realmode_emulate_cmpxchg,
    .read_segment  = realmode_read_segment,
    .write_segment = realmode_write_segment,
    .read_io       = realmode_read_io,
    .write_io      = realmode_write_io,
    .read_cr       = realmode_read_cr,
    .write_rflags  = realmode_write_rflags
};

int vmx_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct realmode_emulate_ctxt rm_ctxt;
    unsigned long addr;
    int i, rc = 0;

    for ( i = 0; i < 10; i++ )
        hvm_get_segment_register(curr, i, &rm_ctxt.seg_reg[i]);

    while ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) &&
            !softirq_pending(smp_processor_id()) )
    {
        rm_ctxt.ctxt.regs = regs;
        rm_ctxt.ctxt.addr_size =
            rm_ctxt.seg_reg[x86_seg_cs].attr.fields.db ? 32 : 16;
        rm_ctxt.ctxt.sp_size =
            rm_ctxt.seg_reg[x86_seg_ss].attr.fields.db ? 32 : 16;

        rm_ctxt.insn_buf_eip = regs->eip;
        rm_ctxt.insn_buf_bytes =
            (hvm_virtual_to_linear_addr(
                x86_seg_cs, &rm_ctxt.seg_reg[x86_seg_cs],
                regs->eip, sizeof(rm_ctxt.insn_buf),
                hvm_access_insn_fetch, rm_ctxt.ctxt.addr_size, &addr) &&
             !hvm_copy_from_guest_virt(
                 rm_ctxt.insn_buf, addr, sizeof(rm_ctxt.insn_buf)))
            ? sizeof(rm_ctxt.insn_buf) : 0;

        rc = x86_emulate(&rm_ctxt.ctxt, &realmode_emulator_ops);

        if ( curr->arch.hvm_vmx.real_mode_io_in_progress )
        {
            rc = 0;
            break;
        }

        if ( rc )
        {
            gdprintk(XENLOG_DEBUG,
                     "RM %04x:%08lx: %02x %02x %02x %02x %02x %02x\n",
                     rm_ctxt.seg_reg[x86_seg_cs].sel, rm_ctxt.insn_buf_eip,
                     rm_ctxt.insn_buf[0], rm_ctxt.insn_buf[1],
                     rm_ctxt.insn_buf[2], rm_ctxt.insn_buf[3],
                     rm_ctxt.insn_buf[4], rm_ctxt.insn_buf[5]);
            gdprintk(XENLOG_ERR, "Emulation failed\n");
            rc = -EINVAL;
            break;
        }
    }

    for ( i = 0; i < 10; i++ )
        hvm_set_segment_register(curr, i, &rm_ctxt.seg_reg[i]);

    return rc;
}

int vmx_realmode_io_complete(void)
{
    struct vcpu *curr = current;
    ioreq_t *p = &get_ioreq(curr)->vp_ioreq;

    if ( !curr->arch.hvm_vmx.real_mode_io_in_progress )
        return 0;

#if 0
    gdprintk(XENLOG_DEBUG, "RM I/O %d %c bytes=%d addr=%lx data=%lx\n",
             p->type, p->dir ? 'R' : 'W',
             (int)p->size, (long)p->addr, (long)p->data);
#endif

    curr->arch.hvm_vmx.real_mode_io_in_progress = 0;
    if ( p->dir == IOREQ_READ )
    {
        curr->arch.hvm_vmx.real_mode_io_completed = 1;
        curr->arch.hvm_vmx.real_mode_io_data = p->data;
    }

    return 1;
}
