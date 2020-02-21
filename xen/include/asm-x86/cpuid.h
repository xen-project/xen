#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>

#ifndef __ASSEMBLY__
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/percpu.h>

#include <xen/lib/x86/cpu-policy.h>
#include <xen/lib/x86/cpuid.h>

#include <public/sysctl.h>

extern const uint32_t known_features[FSCAPINTS];
extern const uint32_t special_features[FSCAPINTS];

void init_guest_cpuid(void);

/*
 * Expected levelling capabilities (given cpuid vendor/family information),
 * and levelling capabilities actually available (given MSR probing).
 */
#define LCAP_faulting XEN_SYSCTL_CPU_LEVELCAP_faulting
#define LCAP_1cd      (XEN_SYSCTL_CPU_LEVELCAP_ecx |        \
                       XEN_SYSCTL_CPU_LEVELCAP_edx)
#define LCAP_e1cd     (XEN_SYSCTL_CPU_LEVELCAP_extd_ecx |   \
                       XEN_SYSCTL_CPU_LEVELCAP_extd_edx)
#define LCAP_Da1      XEN_SYSCTL_CPU_LEVELCAP_xsave_eax
#define LCAP_6c       XEN_SYSCTL_CPU_LEVELCAP_thermal_ecx
#define LCAP_7ab0     (XEN_SYSCTL_CPU_LEVELCAP_l7s0_eax |   \
                       XEN_SYSCTL_CPU_LEVELCAP_l7s0_ebx)
extern unsigned int expected_levelling_cap, levelling_caps;

struct cpuidmasks
{
    uint64_t _1cd;
    uint64_t e1cd;
    uint64_t Da1;
    uint64_t _6c;
    uint64_t _7ab0;
};

/* Per CPU shadows of masking MSR values, for lazy context switching. */
DECLARE_PER_CPU(struct cpuidmasks, cpuidmasks);

/* Default masking MSR values, calculated at boot. */
extern struct cpuidmasks cpuidmask_defaults;

extern struct cpuid_policy raw_cpuid_policy, host_cpuid_policy,
    pv_max_cpuid_policy, pv_def_cpuid_policy,
    hvm_max_cpuid_policy, hvm_def_cpuid_policy;

extern const struct cpu_policy system_policies[];

/* Check that all previously present features are still available. */
bool recheck_cpu_features(unsigned int cpu);

/* Allocate and initialise a CPUID policy suitable for the domain. */
int init_domain_cpuid_policy(struct domain *d);

/* Clamp the CPUID policy to reality. */
void recalculate_cpuid_policy(struct domain *d);

struct vcpu;
void guest_cpuid(const struct vcpu *v, uint32_t leaf,
                 uint32_t subleaf, struct cpuid_leaf *res);

#endif /* __ASSEMBLY__ */
#endif /* !__X86_CPUID_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
