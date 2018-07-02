/* Common data structures and functions consumed by hypervisor and toolstack */
#ifndef XEN_LIB_X86_POLICIES_H
#define XEN_LIB_X86_POLICIES_H

#include <xen/lib/x86/cpuid.h>
#include <xen/lib/x86/msr.h>

struct cpu_policy
{
    struct cpuid_policy *cpuid;
    struct msr_policy *msr;
};

#endif /* !XEN_LIB_X86_POLICIES_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
