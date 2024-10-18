/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 XenServer.
 */
#include <xen/bug.h>
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/debugreg.h>

/*
 * Merge new bits into dr6.  'new' is always given in positive polarity,
 * matching the Intel VMCS PENDING_DBG semantics.
 *
 * At the time of writing (August 2024), on the subject of %dr6 updates the
 * manuals are either vague (Intel "certain exceptions may clear bits 0-3"),
 * or disputed (AMD makes statements which don't match observed behaviour).
 *
 * The only debug exception I can find which doesn't clear the breakpoint bits
 * is ICEBP(/INT1) on AMD systems.  This is also the one source of #DB that
 * doesn't have an explicit status bit, meaning we can't easily identify this
 * case either (AMD systems don't virtualise PENDING_DBG and only provide a
 * post-merge %dr6 value).
 *
 * Treat %dr6 merging as unconditionally writing the breakpoint bits.
 *
 * We can't really manage any better, and guest kernels handling #DB as
 * instructed by the SDM/APM (i.e. reading %dr6 then resetting it back to
 * default) wont notice.
 */
unsigned int x86_merge_dr6(const struct cpu_policy *p, unsigned int dr6,
                           unsigned int new)
{
    /* Flip dr6 to have positive polarity. */
    dr6 ^= X86_DR6_DEFAULT;

    /* Sanity check that only known values are passed in. */
    ASSERT(!(dr6 & ~X86_DR6_KNOWN_MASK));
    ASSERT(!(new & ~X86_DR6_KNOWN_MASK));

    /* Breakpoint bits overridden.  All others accumulate. */
    dr6 = (dr6 & ~X86_DR6_BP_MASK) | new;

    /* Flip dr6 back to having default polarity. */
    dr6 ^= X86_DR6_DEFAULT;

    return x86_adj_dr6_rsvd(p, dr6);
}

unsigned int x86_adj_dr6_rsvd(const struct cpu_policy *p, unsigned int dr6)
{
    unsigned int ones = X86_DR6_DEFAULT;

    /*
     * The i586 and later processors had most but not all reserved bits read
     * as 1s.  New features allocated in this space have inverted polarity,
     * and don't force their respective bit to 1.
     */
    if ( p->feat.rtm )
        ones &= ~X86_DR6_RTM;
    if ( p->feat.bld )
        ones &= ~X86_DR6_BLD;

    dr6 |= ones;
    dr6 &= ~X86_DR6_ZEROS;

    return dr6;
}

unsigned int x86_adj_dr7_rsvd(const struct cpu_policy *p, unsigned int dr7)
{
    unsigned int zeros = X86_DR7_ZEROS;

    /*
     * Most but not all reserved bits force to zero.  Hardware lacking
     * optional features force more bits to zero.
     */
    if ( !p->feat.rtm )
        zeros |= X86_DR7_RTM;

    dr7 &= ~zeros;
    dr7 |= X86_DR7_DEFAULT;

    return dr7;
}
