/******************************************************************************
 * arch/x86/pv/emulate.c
 *
 * Common PV emulation code
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

#include <xen/guest_access.h>

#include <asm/debugreg.h>

#include "emulate.h"

int pv_emul_read_descriptor(unsigned int sel, const struct vcpu *v,
                            unsigned long *base, unsigned long *limit,
                            unsigned int *ar, bool insn_fetch)
{
    struct desc_struct desc;

    if ( sel < 4)
        desc.b = desc.a = 0;
    else if ( __get_user(desc, gdt_ldt_desc_ptr(sel)) )
        return 0;
    if ( !insn_fetch )
        desc.b &= ~_SEGMENT_L;

    *ar = desc.b & 0x00f0ff00;
    if ( !(desc.b & _SEGMENT_L) )
    {
        *base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                 (desc.b & 0xff000000));
        *limit = (desc.a & 0xffff) | (desc.b & 0x000f0000);
        if ( desc.b & _SEGMENT_G )
            *limit = ((*limit + 1) << 12) - 1;
#ifndef NDEBUG
        if ( sel > 3 )
        {
            unsigned int a, l;
            unsigned char valid;

            asm volatile (
                "larl %2,%0 ; setz %1"
                : "=r" (a), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && ((a & 0x00f0ff00) != *ar));
            asm volatile (
                "lsll %2,%0 ; setz %1"
                : "=r" (l), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && (l != *limit));
        }
#endif
    }
    else
    {
        *base = 0UL;
        *limit = ~0UL;
    }

    return 1;
}

void pv_emul_instruction_done(struct cpu_user_regs *regs, unsigned long rip)
{
    regs->rip = rip;
    regs->eflags &= ~X86_EFLAGS_RF;
    if ( regs->eflags & X86_EFLAGS_TF )
    {
        current->arch.debugreg[6] |= DR_STEP | DR_STATUS_RESERVED_ONE;
        pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);
    }
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
