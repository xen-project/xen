/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * util-xen.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator hypervisor-
 * only utility functions.
 */

#include "private.h"

#include <xen/nospec.h>
#include <xen/sched.h>
#include <asm/debugreg.h>
#include <asm/xstate.h>

#ifndef NDEBUG
void x86_emulate_free_state(struct x86_emulate_state *s)
{
    check_state(s);
    s->caller = NULL;
}
#endif

unsigned int x86_insn_opsize(const struct x86_emulate_state *s)
{
    check_state(s);

    return s->op_bytes << 3;
}

int x86_insn_modrm(const struct x86_emulate_state *s,
                   unsigned int *rm, unsigned int *reg)
{
    check_state(s);

    if ( unlikely(s->modrm_mod > 3) )
    {
        if ( rm )
            *rm = ~0U;
        if ( reg )
            *reg = ~0U;
        return -EINVAL;
    }

    if ( rm )
        *rm = s->modrm_rm;
    if ( reg )
        *reg = s->modrm_reg;

    return s->modrm_mod;
}

unsigned long x86_insn_operand_ea(const struct x86_emulate_state *s,
                                  enum x86_segment *seg)
{
    *seg = s->ea.type == OP_MEM ? s->ea.mem.seg : x86_seg_none;

    check_state(s);

    return s->ea.mem.off;
}

bool cf_check x86_insn_is_portio(const struct x86_emulate_state *s,
                                 const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
    case 0x6c ... 0x6f: /* INS / OUTS */
    case 0xe4 ... 0xe7: /* IN / OUT imm8 */
    case 0xec ... 0xef: /* IN / OUT %dx */
        return true;
    }

    return false;
}

bool cf_check x86_insn_is_cr_access(const struct x86_emulate_state *s,
                                    const struct x86_emulate_ctxt *ctxt)
{
    switch ( ctxt->opcode )
    {
        unsigned int ext;

    case X86EMUL_OPC(0x0f, 0x01):
        if ( x86_insn_modrm(s, NULL, &ext) >= 0
             && (ext & 5) == 4 ) /* SMSW / LMSW */
            return true;
        break;

    case X86EMUL_OPC(0x0f, 0x06): /* CLTS */
    case X86EMUL_OPC(0x0f, 0x20): /* MOV from CRn */
    case X86EMUL_OPC(0x0f, 0x22): /* MOV to CRn */
        return true;
    }

    return false;
}

unsigned long x86_insn_immediate(const struct x86_emulate_state *s,
                                 unsigned int nr)
{
    check_state(s);

    switch ( nr )
    {
    case 0:
        return s->imm1;
    case 1:
        return s->imm2;
    }

    return 0;
}

int cf_check x86emul_read_xcr(unsigned int reg, uint64_t *val,
                              struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
        *val = current->arch.xcr0;
        return X86EMUL_OKAY;

    case 1:
        if ( current->domain->arch.cpuid->xstate.xgetbv1 )
            break;
        /* fall through */
    default:
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    *val = xgetbv(reg);

    return X86EMUL_OKAY;
}

/* Note: May be called with ctxt=NULL. */
int cf_check x86emul_write_xcr(unsigned int reg, uint64_t val,
                               struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
        break;

    default:
    gp_fault:
        if ( ctxt )
            x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }

    if ( unlikely(handle_xsetbv(reg, val) != 0) )
        goto gp_fault;

    return X86EMUL_OKAY;
}

#ifdef CONFIG_PV

/* Called with NULL ctxt in hypercall context. */
int cf_check x86emul_read_dr(unsigned int reg, unsigned long *val,
                             struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( reg )
    {
    case 0 ... 3:
        *val = array_access_nospec(curr->arch.dr, reg);
        break;

    case 4:
        if ( curr->arch.pv.ctrlreg[4] & X86_CR4_DE )
            goto ud_fault;

        /* Fallthrough */
    case 6:
        *val = curr->arch.dr6;
        break;

    case 5:
        if ( curr->arch.pv.ctrlreg[4] & X86_CR4_DE )
            goto ud_fault;

        /* Fallthrough */
    case 7:
        *val = curr->arch.dr7 | curr->arch.pv.dr7_emul;
        break;

    ud_fault:
    default:
        if ( ctxt )
            x86_emul_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC, ctxt);

        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int cf_check x86emul_write_dr(unsigned int reg, unsigned long val,
                              struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( set_debugreg(curr, reg, val) )
    {
    case 0:
        return X86EMUL_OKAY;

    case -ENODEV:
        x86_emul_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC, ctxt);
        return X86EMUL_EXCEPTION;

    default:
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);
        return X86EMUL_EXCEPTION;
    }
}

#endif /* CONFIG_PV */

int cf_check x86emul_cpuid(uint32_t leaf, uint32_t subleaf,
                           struct cpuid_leaf *res,
                           struct x86_emulate_ctxt *ctxt)
{
    guest_cpuid(current, leaf, subleaf, res);

    return X86EMUL_OKAY;
}
