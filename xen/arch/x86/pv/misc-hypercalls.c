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
    unsigned long val;
    int res = x86emul_read_dr(reg, &val, NULL);

    return res == X86EMUL_OKAY ? val : -ENODEV;
}

long do_fpu_taskswitch(int set)
{
    struct vcpu *v = current;

    if ( set )
    {
        v->arch.pv.ctrlreg[0] |= X86_CR0_TS;
        stts();
    }
    else
    {
        v->arch.pv.ctrlreg[0] &= ~X86_CR0_TS;
        if ( v->fpu_dirtied )
            clts();
    }

    return 0;
}

/*
 * Used by hypercalls and the emulator.
 *  -ENODEV => #UD
 *  -EINVAL => #GP Invalid bit
 *  -EPERM  => #GP Valid bit, but not permitted to use
 */
long set_debugreg(struct vcpu *v, unsigned int reg, unsigned long value)
{
    struct vcpu *curr = current;

    switch ( reg )
    {
    case 0 ... 3:
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;

        v->arch.dr[reg] = value;
        if ( v == curr )
        {
            switch ( reg )
            {
            case 0: write_debugreg(0, value); break;
            case 1: write_debugreg(1, value); break;
            case 2: write_debugreg(2, value); break;
            case 3: write_debugreg(3, value); break;
            }
        }
        break;

    case 4:
        if ( v->arch.pv.ctrlreg[4] & X86_CR4_DE )
            return -ENODEV;

        /* Fallthrough */
    case 6:
        /* The upper 32 bits are strictly reserved. */
        if ( value != (uint32_t)value )
            return -EINVAL;

        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= ~DR_STATUS_RESERVED_ZERO; /* reserved bits => 0 */
        value |=  DR_STATUS_RESERVED_ONE;  /* reserved bits => 1 */

        v->arch.dr6 = value;
        if ( v == curr )
            write_debugreg(6, value);
        break;

    case 5:
        if ( v->arch.pv.ctrlreg[4] & X86_CR4_DE )
            return -ENODEV;

        /* Fallthrough */
    case 7:
        /* The upper 32 bits are strictly reserved. */
        if ( value != (uint32_t)value )
            return -EINVAL;

        /*
         * DR7: Bit 10 reserved (set to 1).
         *      Bits 11-12,14-15 reserved (set to 0).
         */
        value &= ~DR_CONTROL_RESERVED_ZERO; /* reserved bits => 0 */
        value |=  DR_CONTROL_RESERVED_ONE;  /* reserved bits => 1 */
        /*
         * Privileged bits:
         *      GD (bit 13): must be 0.
         */
        if ( value & DR_GENERAL_DETECT )
            return -EPERM;

        /* DR7.{G,L}E = 0 => debugging disabled for this domain. */
        if ( value & DR7_ACTIVE_MASK )
        {
            unsigned int i, io_enable = 0;

            for ( i = DR_CONTROL_SHIFT; i < 32; i += DR_CONTROL_SIZE )
            {
                if ( ((value >> i) & 3) == DR_IO )
                {
                    if ( !(v->arch.pv.ctrlreg[4] & X86_CR4_DE) )
                        return -EPERM;
                    io_enable |= value & (3 << ((i - 16) >> 1));
                }
            }

            v->arch.pv.dr7_emul = io_enable;
            value &= ~io_enable;

            /*
             * If DR7 was previously clear then we need to load all other
             * debug registers at this point as they were not restored during
             * context switch.  Updating DR7 itself happens later.
             */
            if ( (v == curr) && !(v->arch.dr7 & DR7_ACTIVE_MASK) )
                activate_debugregs(v);
        }
        else
            /* Zero the emulated controls if %dr7 isn't active. */
            v->arch.pv.dr7_emul = 0;

        v->arch.dr7 = value;
        if ( v == curr )
            write_debugreg(7, value);
        break;

    default:
        return -ENODEV;
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
