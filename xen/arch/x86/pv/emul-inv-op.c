/******************************************************************************
 * arch/x86/pv/emul-inv-op.c
 *
 * Emulate invalid op for PV guests
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/trace.h>

#include "emulate.h"

static int emulate_forced_invalid_op(struct cpu_user_regs *regs)
{
    char sig[5], instr[2];
    unsigned long eip, rc;
    struct cpuid_leaf res;
    const struct vcpu_msrs *msrs = current->arch.msrs;

    eip = regs->rip;

    /* Check for forced emulation signature: ud2 ; .ascii "xen". */
    if ( (rc = copy_from_user(sig, (char *)eip, sizeof(sig))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(sig) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(sig, "\xf\xbxen", sizeof(sig)) )
        return 0;
    eip += sizeof(sig);

    /* We only emulate CPUID. */
    if ( ( rc = copy_from_user(instr, (char *)eip, sizeof(instr))) != 0 )
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
        pv_inject_hw_exception(TRAP_gp_fault, regs->error_code);
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
