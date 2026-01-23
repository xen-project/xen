#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>

#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/percpu.h>

#include <public/sysctl.h>

extern const uint32_t known_features[FSCAPINTS];

/*
 * Expected levelling capabilities (given cpuid vendor/family information),
 * and levelling capabilities actually available (given MSR probing).
 */
#define LCAP_faulting (1U <<  0) /* CPUID Faulting       */
#define LCAP_1cd      (1U <<  1) /* 0x00000001.ecx/edx   */
#define LCAP_e1cd     (1U <<  2) /* 0x80000001.ecx/edx   */
#define LCAP_Da1      (1U <<  3) /* 0x0000000D:1.eax     */
#define LCAP_6c       (1U <<  4) /* 0x00000006.ecx       */
#define LCAP_7ab0     (1U <<  5) /* 0x00000007:0.eax/ebx */
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
