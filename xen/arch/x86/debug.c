/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 XenServer.
 */
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/debugreg.h>

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
