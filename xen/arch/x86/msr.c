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

struct msr_vcpu_policy __read_mostly hvm_max_msr_vcpu_policy,
                       __read_mostly  pv_max_msr_vcpu_policy;

static void __init calculate_hvm_max_policy(void)
{
    struct msr_domain_policy *dp = &hvm_max_msr_domain_policy;
    struct msr_vcpu_policy *vp = &hvm_max_msr_vcpu_policy;

    if ( !hvm_enabled )
        return;

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
         boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
    {
        dp->plaform_info.available = true;
        dp->plaform_info.cpuid_faulting = true;
    }

    /* 0x00000140  MSR_INTEL_MISC_FEATURES_ENABLES */
    vp->misc_features_enables.available = dp->plaform_info.available;
}

static void __init calculate_pv_max_policy(void)
{
    struct msr_domain_policy *dp = &pv_max_msr_domain_policy;
    struct msr_vcpu_policy *vp = &pv_max_msr_vcpu_policy;

    /* 0x000000ce  MSR_INTEL_PLATFORM_INFO */
    if ( cpu_has_cpuid_faulting )
    {
        dp->plaform_info.available = true;
        dp->plaform_info.cpuid_faulting = true;
    }

    /* 0x00000140  MSR_INTEL_MISC_FEATURES_ENABLES */
    vp->misc_features_enables.available = dp->plaform_info.available;
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

int init_vcpu_msr_policy(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct msr_vcpu_policy *vp;

    vp = xmalloc(struct msr_vcpu_policy);

    if ( !vp )
        return -ENOMEM;

    *vp = is_pv_domain(d) ? pv_max_msr_vcpu_policy :
                            hvm_max_msr_vcpu_policy;

    /* See comment in intel_ctxt_switch_levelling() */
    if ( is_control_domain(d) )
        vp->misc_features_enables.available = false;

    v->arch.msr = vp;

    return 0;
}

int guest_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    const struct msr_domain_policy *dp = v->domain->arch.msr;
    const struct msr_vcpu_policy *vp = v->arch.msr;

    switch ( msr )
    {
    case MSR_INTEL_PLATFORM_INFO:
        if ( !dp->plaform_info.available )
            goto gp_fault;
        *val = (uint64_t)dp->plaform_info.cpuid_faulting <<
               _MSR_PLATFORM_INFO_CPUID_FAULTING;
        break;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
        if ( !vp->misc_features_enables.available )
            goto gp_fault;
        *val = (uint64_t)vp->misc_features_enables.cpuid_faulting <<
               _MSR_MISC_FEATURES_CPUID_FAULTING;
        break;

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;

 gp_fault:
    return X86EMUL_EXCEPTION;
}

int guest_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    const struct vcpu *curr = current;
    struct domain *d = v->domain;
    struct msr_domain_policy *dp = d->arch.msr;
    struct msr_vcpu_policy *vp = v->arch.msr;

    switch ( msr )
    {
    case MSR_INTEL_PLATFORM_INFO:
        goto gp_fault;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
    {
        uint64_t rsvd = ~0ull;
        bool old_cpuid_faulting = vp->misc_features_enables.cpuid_faulting;

        if ( !vp->misc_features_enables.available )
            goto gp_fault;

        if ( dp->plaform_info.cpuid_faulting )
            rsvd &= ~MSR_MISC_FEATURES_CPUID_FAULTING;

        if ( val & rsvd )
            goto gp_fault;

        vp->misc_features_enables.cpuid_faulting =
            val & MSR_MISC_FEATURES_CPUID_FAULTING;

        if ( v == curr && is_hvm_domain(d) && cpu_has_cpuid_faulting &&
             (old_cpuid_faulting ^ vp->misc_features_enables.cpuid_faulting) )
            ctxt_switch_levelling(v);
        break;
    }

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;

 gp_fault:
    return X86EMUL_EXCEPTION;
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
