/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/emul-inv-op.c
 *
 * Emulate invalid op for PV guests
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 */

#include <asm/pv/trace.h>

#include "emulate.h"

static int emulate_forced_invalid_op(struct cpu_user_regs *regs)
{
    char sig[5], instr[2];
    unsigned long eip, rc;
    struct cpuid_leaf res;
    const struct vcpu_msrs *msrs = current->arch.msrs;

    eip = regs->rip;

    /* Check for forced emulation signature: ud2 ; .ascii "xen". */
    if ( (rc = copy_from_guest_pv(sig, (char __user *)eip, sizeof(sig))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(sig) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(sig, "\xf\xbxen", sizeof(sig)) )
        return 0;
    eip += sizeof(sig);

    /* We only emulate CPUID. */
    if ( (rc = copy_from_guest_pv(instr, (char __user *)eip,
                                  sizeof(instr))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(instr) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(instr, "\xf\xa2", sizeof(instr)) )
        return 0;

    /* If cpuid faulting is enabled and CPL>0 inject a #GP in place of #UD. */
    if ( msrs->misc_features_enables.cpuid_faulting &&
         !guest_kernel_mode(current, regs) )
    {
        regs->rip = eip;
        pv_inject_hw_exception(X86_EXC_GP, regs->error_code);
        return EXCRET_fault_fixed;
    }

    eip += sizeof(instr);

    guest_cpuid(current, regs->eax, regs->ecx, &res);

    regs->rax = res.a;
    regs->rbx = res.b;
    regs->rcx = res.c;
    regs->rdx = res.d;

    pv_emul_instruction_done(regs, eip);

    trace_trap_one_addr(TRC_PV_FORCED_INVALID_OP, regs->rip);

    return EXCRET_fault_fixed;
}

bool pv_emulate_invalid_op(struct cpu_user_regs *regs)
{
    return !emulate_forced_invalid_op(regs);
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
