/******************************************************************************
 * arch/x86/pv/misc-hypercalls.c
 *
 * Misc hypercall handlers
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

#include <xen/hypercall.h>

#include <asm/debugreg.h>

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0 ... 3:
    case 6:
        return curr->arch.debugreg[reg];
    case 7:
        return (curr->arch.debugreg[7] |
                curr->arch.debugreg[5]);
    case 4 ... 5:
        return ((curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) ?
                curr->arch.debugreg[reg + 2] : 0);
    }

    return -EINVAL;
}

long do_fpu_taskswitch(int set)
{
    struct vcpu *v = current;

    if ( set )
    {
        v->arch.pv_vcpu.ctrlreg[0] |= X86_CR0_TS;
        stts();
    }
    else
    {
        v->arch.pv_vcpu.ctrlreg[0] &= ~X86_CR0_TS;
        if ( v->fpu_dirtied )
            clts();
    }

    return 0;
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
