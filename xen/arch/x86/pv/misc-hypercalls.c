/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/misc-hypercalls.c
 *
 * Misc hypercall handlers
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 */

#include <xen/hypercall.h>

#include <asm/debugreg.h>

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

long do_get_debugreg(int reg)
{
    /* Avoid implementation defined behavior casting unsigned long to long. */
    union {
        unsigned long val;
        long ret;
    } u;
    int res = x86emul_read_dr(reg, &u.val, NULL);

    return res == X86EMUL_OKAY ? u.ret : -ENODEV;
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
    const struct cpu_policy *p = curr->domain->arch.cpu_policy;

    switch ( reg )
    {
    case 0 ... 3:
        if ( !breakpoint_addr_ok(value) )
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

        value = x86_adj_dr6_rsvd(p, value);

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

        value = x86_adj_dr7_rsvd(p, value);

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

long do_stack_switch(unsigned long ss, unsigned long esp)
{
    fixup_guest_stack_selector(current->domain, ss);
    current->arch.pv.kernel_ss = ss;
    current->arch.pv.kernel_sp = esp;

    return 0;
}

long do_set_segment_base(unsigned int which, unsigned long base)
{
    struct vcpu *v = current;
    long ret = 0;

    if ( is_pv_32bit_vcpu(v) )
        return -ENOSYS; /* x86/64 only. */

    switch ( which )
    {
    case SEGBASE_FS:
        if ( is_canonical_address(base) )
            write_fs_base(base);
        else
            ret = -EINVAL;
        break;

    case SEGBASE_GS_USER:
        if ( is_canonical_address(base) )
        {
            write_gs_shadow(base);
            v->arch.pv.gs_base_user = base;
        }
        else
            ret = -EINVAL;
        break;

    case SEGBASE_GS_KERNEL:
        if ( is_canonical_address(base) )
            write_gs_base(base);
        else
            ret = -EINVAL;
        break;

    case SEGBASE_GS_USER_SEL:
    {
        unsigned int sel = (uint16_t)base;

        /*
         * We wish to update the user %gs from the GDT/LDT.  Currently, the
         * guest kernel's GS_BASE is in context.
         */
        asm volatile ( "swapgs" );

        if ( sel > 3 )
            /* Fix up RPL for non-NUL selectors. */
            sel |= 3;
        else if ( cpu_bug_null_seg )
            /* Work around NUL segment behaviour on AMD hardware. */
            asm volatile ( "mov %[sel], %%gs"
                           :: [sel] "r" (FLAT_USER_DS32) );

        /*
         * Load the chosen selector, with fault handling.
         *
         * Errors ought to fail the hypercall, but that was never built in
         * originally, and Linux will BUG() if this call fails.
         *
         * NUL the selector in the case of an error.  This too needs to deal
         * with the AMD NUL segment behaviour, but it is already a slowpath in
         * #GP context so perform the flat load unconditionally to avoid
         * complicated logic.
         *
         * Anyone wanting to check for errors from this hypercall should
         * re-read %gs and compare against the input.
         */
        asm volatile ( "1: mov %[sel], %%gs\n\t"
                       ".section .fixup, \"ax\", @progbits\n\t"
                       "2: mov %k[flat], %%gs\n\t"
                       "   xor %[sel], %[sel]\n\t"
                       "   jmp 1b\n\t"
                       ".previous\n\t"
                       _ASM_EXTABLE(1b, 2b)
                       : [sel] "+r" (sel)
                       : [flat] "r" (FLAT_USER_DS32) );

        /* Update the cache of the inactive base, as read from the GDT/LDT. */
        v->arch.pv.gs_base_user = read_gs_base();

        asm volatile ( safe_swapgs );
        break;
    }

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
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
