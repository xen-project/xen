/******************************************************************************
 * arch/x86/spec_ctrl.c
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
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>

#include <asm/microcode.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/spec_ctrl.h>
#include <asm/spec_ctrl_asm.h>

static enum ind_thunk {
    THUNK_DEFAULT, /* Decide which thunk to use at boot time. */
    THUNK_NONE,    /* Missing compiler support for thunks. */

    THUNK_RETPOLINE,
    THUNK_LFENCE,
    THUNK_JMP,
} opt_thunk __initdata = THUNK_DEFAULT;
static int8_t __initdata opt_ibrs = -1;
static bool __initdata opt_rsb_native = true;
static bool __initdata opt_rsb_vmexit = true;
bool __read_mostly opt_ibpb = true;
uint8_t __read_mostly default_bti_ist_info;

static int __init parse_bti(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        val = parse_bool(s, ss);
        if ( !val )
        {
            opt_thunk = THUNK_JMP;
            opt_ibrs = 0;
            opt_ibpb = false;
            opt_rsb_native = false;
            opt_rsb_vmexit = false;
        }
        else if ( val > 0 )
            rc = -EINVAL;
        else if ( !strncmp(s, "thunk=", 6) )
        {
            s += 6;

            if ( !strncmp(s, "retpoline", ss - s) )
                opt_thunk = THUNK_RETPOLINE;
            else if ( !strncmp(s, "lfence", ss - s) )
                opt_thunk = THUNK_LFENCE;
            else if ( !strncmp(s, "jmp", ss - s) )
                opt_thunk = THUNK_JMP;
            else
                rc = -EINVAL;
        }
        else if ( (val = parse_boolean("ibrs", s, ss)) >= 0 )
            opt_ibrs = val;
        else if ( (val = parse_boolean("ibpb", s, ss)) >= 0 )
            opt_ibpb = val;
        else if ( (val = parse_boolean("rsb_native", s, ss)) >= 0 )
            opt_rsb_native = val;
        else if ( (val = parse_boolean("rsb_vmexit", s, ss)) >= 0 )
            opt_rsb_vmexit = val;
        else if ( (val = parse_boolean("rsb", s, ss)) >= 0 )
        {
            opt_rsb_native = val;
            opt_rsb_vmexit = val;
        }
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("bti", parse_bti);

static void __init print_details(enum ind_thunk thunk)
{
    unsigned int _7d0 = 0, e8b = 0, tmp;

    /* Collect diagnostics about available mitigations. */
    if ( boot_cpu_data.cpuid_level >= 7 )
        cpuid_count(7, 0, &tmp, &tmp, &tmp, &_7d0);
    if ( boot_cpu_data.extended_cpuid_level >= 0x80000008 )
        cpuid(0x80000008, &tmp, &e8b, &tmp, &tmp);

    printk(XENLOG_DEBUG "Speculative mitigation facilities:\n");

    /* Hardware features which pertain to speculative mitigations. */
    if ( (_7d0 & (cpufeat_mask(X86_FEATURE_IBRSB) |
                  cpufeat_mask(X86_FEATURE_STIBP))) ||
         (e8b & cpufeat_mask(X86_FEATURE_IBPB)) )
        printk(XENLOG_DEBUG "  Hardware features:%s%s%s\n",
               (_7d0 & cpufeat_mask(X86_FEATURE_IBRSB)) ? " IBRS/IBPB" : "",
               (_7d0 & cpufeat_mask(X86_FEATURE_STIBP)) ? " STIBP"     : "",
               (e8b  & cpufeat_mask(X86_FEATURE_IBPB))  ? " IBPB"      : "");

    /* Compiled-in support which pertains to BTI mitigations. */
    if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        printk(XENLOG_DEBUG "  Compiled-in support: INDIRECT_THUNK\n");

    printk(XENLOG_INFO
           "BTI mitigations: Thunk %s, Others:%s%s%s%s\n",
           thunk == THUNK_NONE      ? "N/A" :
           thunk == THUNK_RETPOLINE ? "RETPOLINE" :
           thunk == THUNK_LFENCE    ? "LFENCE" :
           thunk == THUNK_JMP       ? "JMP" : "?",
           boot_cpu_has(X86_FEATURE_XEN_IBRS_SET)    ? " IBRS+" :
           boot_cpu_has(X86_FEATURE_XEN_IBRS_CLEAR)  ? " IBRS-"      : "",
           opt_ibpb                                  ? " IBPB"       : "",
           boot_cpu_has(X86_FEATURE_RSB_NATIVE)      ? " RSB_NATIVE" : "",
           boot_cpu_has(X86_FEATURE_RSB_VMEXIT)      ? " RSB_VMEXIT" : "");
}

/* Calculate whether Retpoline is known-safe on this CPU. */
static bool __init retpoline_safe(void)
{
    unsigned int ucode_rev = this_cpu(ucode_cpu_info).cpu_sig.rev;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        return true;

    if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL ||
         boot_cpu_data.x86 != 6 )
        return false;

    switch ( boot_cpu_data.x86_model )
    {
    case 0x17: /* Penryn */
    case 0x1d: /* Dunnington */
    case 0x1e: /* Nehalem */
    case 0x1f: /* Auburndale / Havendale */
    case 0x1a: /* Nehalem EP */
    case 0x2e: /* Nehalem EX */
    case 0x25: /* Westmere */
    case 0x2c: /* Westmere EP */
    case 0x2f: /* Westmere EX */
    case 0x2a: /* SandyBridge */
    case 0x2d: /* SandyBridge EP/EX */
    case 0x3a: /* IvyBridge */
    case 0x3e: /* IvyBridge EP/EX */
    case 0x3c: /* Haswell */
    case 0x3f: /* Haswell EX/EP */
    case 0x45: /* Haswell D */
    case 0x46: /* Haswell H */
        return true;

        /*
         * Broadwell processors are retpoline-safe after specific microcode
         * versions.
         */
    case 0x3d: /* Broadwell */
        return ucode_rev >= 0x28;
    case 0x47: /* Broadwell H */
        return ucode_rev >= 0x1b;
    case 0x4f: /* Broadwell EP/EX */
        return ucode_rev >= 0xb000025;
    case 0x56: /* Broadwell D */
        return false; /* TBD. */

        /*
         * Skylake and later processors are not retpoline-safe.
         */
    default:
        return false;
    }
}

void __init init_speculation_mitigations(void)
{
    enum ind_thunk thunk = THUNK_DEFAULT;
    bool ibrs = false;

    /*
     * Has the user specified any custom BTI mitigations?  If so, follow their
     * instructions exactly and disable all heuristics.
     */
    if ( opt_thunk != THUNK_DEFAULT || opt_ibrs != -1 )
    {
        thunk = opt_thunk;
        ibrs  = !!opt_ibrs;
    }
    else
    {
        /*
         * Evaluate the safest Branch Target Injection mitigations to use.
         * First, begin with compiler-aided mitigations.
         */
        if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        {
            /*
             * AMD's recommended mitigation is to set lfence as being dispatch
             * serialising, and to use IND_THUNK_LFENCE.
             */
            if ( cpu_has_lfence_dispatch )
                thunk = THUNK_LFENCE;
            /*
             * On Intel hardware, we'd like to use retpoline in preference to
             * IBRS, but only if it is safe on this hardware.
             */
            else if ( retpoline_safe() )
                thunk = THUNK_RETPOLINE;
            else if ( boot_cpu_has(X86_FEATURE_IBRSB) )
                ibrs = true;
        }
        /* Without compiler thunk support, use IBRS if available. */
        else if ( boot_cpu_has(X86_FEATURE_IBRSB) )
            ibrs = true;
    }

    /*
     * Supplimentary minor adjustments.  Without compiler support, there are
     * no thunks.
     */
    if ( !IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        thunk = THUNK_NONE;

    /*
     * If IBRS is in use and thunks are compiled in, there is no point
     * suffering extra overhead.  Switch to the least-overhead thunk.
     */
    if ( ibrs && thunk == THUNK_DEFAULT )
        thunk = THUNK_JMP;

    /*
     * If there are still no thunk preferences, the compiled default is
     * actually retpoline, and it is better than nothing.
     */
    if ( thunk == THUNK_DEFAULT )
        thunk = THUNK_RETPOLINE;

    /* Apply the chosen settings. */
    if ( thunk == THUNK_LFENCE )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_LFENCE);
    else if ( thunk == THUNK_JMP )
        setup_force_cpu_cap(X86_FEATURE_IND_THUNK_JMP);

    if ( boot_cpu_has(X86_FEATURE_IBRSB) )
    {
        /*
         * Even if we've chosen to not have IBRS set in Xen context, we still
         * need the IBRS entry/exit logic to virtualise IBRS support for
         * guests.
         */
        if ( ibrs )
            setup_force_cpu_cap(X86_FEATURE_XEN_IBRS_SET);
        else
            setup_force_cpu_cap(X86_FEATURE_XEN_IBRS_CLEAR);

        default_bti_ist_info |= BTI_IST_WRMSR | ibrs;
    }

    /*
     * PV guests can poison the RSB to any virtual address from which
     * they can execute a call instruction.  This is necessarily outside
     * of the Xen supervisor mappings.
     *
     * With SMEP enabled, the processor won't speculate into user mappings.
     * Therefore, in this case, we don't need to worry about poisoned entries
     * from 64bit PV guests.
     *
     * 32bit PV guest kernels run in ring 1, so use supervisor mappings.
     * If a processors speculates to 32bit PV guest kernel mappings, it is
     * speculating in 64bit supervisor mode, and can leak data.
     */
    if ( opt_rsb_native )
    {
        setup_force_cpu_cap(X86_FEATURE_RSB_NATIVE);
        default_bti_ist_info |= BTI_IST_RSB;
    }

    /*
     * HVM guests can always poison the RSB to point at Xen supervisor
     * mappings.
     */
    if ( opt_rsb_vmexit )
        setup_force_cpu_cap(X86_FEATURE_RSB_VMEXIT);

    /* Check we have hardware IBPB support before using it... */
    if ( !boot_cpu_has(X86_FEATURE_IBRSB) && !boot_cpu_has(X86_FEATURE_IBPB) )
        opt_ibpb = false;

    /* (Re)init BSP state now that default_bti_ist_info has been calculated. */
    init_shadow_spec_ctrl_state();

    print_details(thunk);
}

static void __init __maybe_unused build_assertions(void)
{
    /* The optimised assembly relies on this alias. */
    BUILD_BUG_ON(BTI_IST_IBRS != SPEC_CTRL_IBRS);
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
