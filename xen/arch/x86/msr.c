/******************************************************************************
 * arch/x86/msr.c
 *
 * Policy objects for Model-Specific Registers.
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
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/msr.h>

struct msr_domain_policy __read_mostly hvm_max_msr_domain_policy,
                         __read_mostly  pv_max_msr_domain_policy;

static void __init calculate_hvm_max_policy(void)
{
    struct msr_domain_policy *dp = &hvm_max_msr_domain_policy;

    if ( !hvm_enabled )
        return;

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
    {
        dp->plaform_info.available = true;
        dp->plaform_info.cpuid_faulting = true;
    }
}

static void __init calculate_pv_max_policy(void)
{
    struct msr_domain_policy *dp = &pv_max_msr_domain_policy;

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    if ( cpu_has_cpuid_faulting )
    {
        dp->plaform_info.available = true;
        dp->plaform_info.cpuid_faulting = true;
    }
}

void __init init_guest_msr_policy(void)
{
    calculate_hvm_max_policy();
    calculate_pv_max_policy();
}

int init_domain_msr_policy(struct domain *d)
{
    struct msr_domain_policy *dp;

    dp = xmalloc(struct msr_domain_policy);

    if ( !dp )
        return -ENOMEM;

    *dp = is_pv_domain(d) ? pv_max_msr_domain_policy :
                            hvm_max_msr_domain_policy;

    /* See comment in intel_ctxt_switch_levelling() */
    if ( is_control_domain(d) )
    {
        dp->plaform_info.available = false;
        dp->plaform_info.cpuid_faulting = false;
    }

    d->arch.msr = dp;

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
