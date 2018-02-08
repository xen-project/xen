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

#include <asm/processor.h>
#include <asm/spec_ctrl.h>

static enum ind_thunk {
    THUNK_DEFAULT, /* Decide which thunk to use at boot time. */
    THUNK_NONE,    /* Missing compiler support for thunks. */

    THUNK_RETPOLINE,
    THUNK_LFENCE,
    THUNK_JMP,
} opt_thunk __initdata = THUNK_DEFAULT;

static int __init parse_bti(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !strncmp(s, "thunk=", 6) )
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
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("bti", parse_bti);

static void __init print_details(enum ind_thunk thunk)
{
    printk(XENLOG_DEBUG "Speculative mitigation facilities:\n");

    /* Compiled-in support which pertains to BTI mitigations. */
    if ( IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        printk(XENLOG_DEBUG "  Compiled-in support: INDIRECT_THUNK\n");

    printk(XENLOG_INFO
           "BTI mitigations: Thunk %s\n",
           thunk == THUNK_NONE      ? "N/A" :
           thunk == THUNK_RETPOLINE ? "RETPOLINE" :
           thunk == THUNK_LFENCE    ? "LFENCE" :
           thunk == THUNK_JMP       ? "JMP" : "?");
}

void __init init_speculation_mitigations(void)
{
    enum ind_thunk thunk = THUNK_DEFAULT;

    /*
     * Has the user specified any custom BTI mitigations?  If so, follow their
     * instructions exactly and disable all heuristics.
     */
    if ( opt_thunk != THUNK_DEFAULT )
    {
        thunk = opt_thunk;
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
        }
    }

    /*
     * Supplimentary minor adjustments.  Without compiler support, there are
     * no thunks.
     */
    if ( !IS_ENABLED(CONFIG_INDIRECT_THUNK) )
        thunk = THUNK_NONE;

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

    print_details(thunk);
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
