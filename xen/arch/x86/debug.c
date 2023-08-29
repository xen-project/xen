/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 XenServer.
 */
#include <xen/kernel.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/debugreg.h>

unsigned int x86_adj_dr6_rsvd(const struct cpu_policy *p, unsigned int dr6)
{
    return dr6;
}

unsigned int x86_adj_dr7_rsvd(const struct cpu_policy *p, unsigned int dr7)
{
    return dr7;
}
