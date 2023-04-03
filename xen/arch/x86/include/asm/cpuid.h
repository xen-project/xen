#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>

#ifndef __ASSEMBLY__
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/percpu.h>

#include <public/sysctl.h>

extern const uint32_t known_features[FSCAPINTS];

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

/* Check that all previously present features are still available. */
bool recheck_cpu_features(unsigned int cpu);

struct vcpu;
struct cpuid_leaf;
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
