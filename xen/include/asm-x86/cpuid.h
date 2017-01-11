#ifndef __X86_CPUID_H__
#define __X86_CPUID_H__

#include <asm/cpufeatureset.h>
#include <asm/percpu.h>

#define FEATURESET_1d     0 /* 0x00000001.edx      */
#define FEATURESET_1c     1 /* 0x00000001.ecx      */
#define FEATURESET_e1d    2 /* 0x80000001.edx      */
#define FEATURESET_e1c    3 /* 0x80000001.ecx      */
#define FEATURESET_Da1    4 /* 0x0000000d:1.eax    */
#define FEATURESET_7b0    5 /* 0x00000007:0.ebx    */
#define FEATURESET_7c0    6 /* 0x00000007:0.ecx    */
#define FEATURESET_e7d    7 /* 0x80000007.edx      */
#define FEATURESET_e8b    8 /* 0x80000008.ebx      */
#define FEATURESET_7d0    9 /* 0x00000007:0.edx    */

#ifndef __ASSEMBLY__
#include <xen/types.h>
#include <xen/kernel.h>
#include <asm/x86_emulate.h>
#include <public/sysctl.h>

extern const uint32_t known_features[FSCAPINTS];
extern const uint32_t special_features[FSCAPINTS];

extern uint32_t raw_featureset[FSCAPINTS];
#define host_featureset boot_cpu_data.x86_capability
extern uint32_t pv_featureset[FSCAPINTS];
extern uint32_t hvm_featureset[FSCAPINTS];

void init_guest_cpuid(void);

const uint32_t *lookup_deep_deps(uint32_t feature);

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

/* Whether or not cpuid faulting is available for the current domain. */
DECLARE_PER_CPU(bool, cpuid_faulting_enabled);

#define CPUID_GUEST_NR_BASIC      (0xdu + 1)
#define CPUID_GUEST_NR_FEAT       (0u + 1)
#define CPUID_GUEST_NR_XSTATE     (62u + 1)
#define CPUID_GUEST_NR_EXTD_INTEL (0x8u + 1)
#define CPUID_GUEST_NR_EXTD_AMD   (0x1cu + 1)
#define CPUID_GUEST_NR_EXTD       MAX(CPUID_GUEST_NR_EXTD_INTEL, \
                                      CPUID_GUEST_NR_EXTD_AMD)

struct cpuid_policy
{
    /*
     * WARNING: During the CPUID transition period, not all information here
     * is accurate.  The following items are accurate, and can be relied upon.
     *
     * Global *_policy objects:
     *
     * - Host accurate:
     *   - max_{,sub}leaf
     *   - {xcr0,xss}_{high,low}
     *
     * - Guest accurate:
     *   - Nothing
     *
     * Everything else should be considered inaccurate, and not necesserily 0.
     */

    /* Basic leaves: 0x000000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_BASIC];
        struct {
            /* Leaf 0x0 - Max and vendor. */
            uint32_t max_leaf, /* b */:32, /* c */:32, /* d */:32;
        };
    } basic;

    /* Structured feature leaf: 0x00000007[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_FEAT];
        struct {
            /* Subleaf 0. */
            uint32_t max_subleaf, /* b */:32, /* c */:32, /* d */:32;
        };
    } feat;

    /* Xstate feature leaf: 0x0000000D[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_XSTATE];
        struct {
            /* Subleaf 0. */
            uint32_t xcr0_low, /* b */:32, /* c */:32, xcr0_high;

            /* Subleaf 1. */
            uint32_t /* a */:32, /* b */:32, xss_low, xss_high;
        };
    } xstate;

    /* Extended leaves: 0x800000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_EXTD];
        struct {
            /* Leaf 0x80000000 - Max and vendor. */
            uint32_t max_leaf, /* b */:32, /* c */:32, /* d */:32;
        };
    } extd;
};

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
