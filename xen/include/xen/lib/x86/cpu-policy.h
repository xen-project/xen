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

struct cpu_policy_errors
{
    uint32_t leaf, subleaf;
    uint32_t msr;
};

#define INIT_CPU_POLICY_ERRORS { -1, -1, -1 }

/*
 * Calculate whether two policies are compatible.
 *
 * i.e. Can a VM configured with @guest run on a CPU supporting @host.
 *
 * @param host     A cpu_policy describing the hardware capabilities.
 * @param guest    A cpu_policy describing the intended VM configuration.
 * @param err      Optional hint for error diagnostics.
 * @returns -errno
 *
 * For typical usage, @host should be a system policy.  In the case that an
 * incompatibility is detected, the optional err pointer may identify the
 * problematic leaf/subleaf and/or MSR.
 */
int x86_cpu_policies_are_compatible(const struct cpu_policy *host,
                                    const struct cpu_policy *guest,
                                    struct cpu_policy_errors *err);

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
