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

#define CPUID_GUEST_NR_BASIC      (0xdu + 1)
#define CPUID_GUEST_NR_FEAT       (0u + 1)
#define CPUID_GUEST_NR_CACHE      (5u + 1)
#define CPUID_GUEST_NR_XSTATE     (62u + 1)
#define CPUID_GUEST_NR_EXTD_INTEL (0x8u + 1)
#define CPUID_GUEST_NR_EXTD_AMD   (0x1cu + 1)
#define CPUID_GUEST_NR_EXTD       MAX(CPUID_GUEST_NR_EXTD_INTEL, \
                                      CPUID_GUEST_NR_EXTD_AMD)

struct cpuid_policy
{
#define DECL_BITFIELD(word) _DECL_BITFIELD(FEATURESET_ ## word)
#define _DECL_BITFIELD(x)   __DECL_BITFIELD(x)
#define __DECL_BITFIELD(x)  CPUID_BITFIELD_ ## x

    /* Basic leaves: 0x000000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_BASIC];
        struct {
            /* Leaf 0x0 - Max and vendor. */
            uint32_t max_leaf, vendor_ebx, vendor_ecx, vendor_edx;

            /* Leaf 0x1 - Family/model/stepping and features. */
            uint32_t raw_fms;
            uint8_t :8,       /* Brand ID. */
                clflush_size, /* Number of 8-byte blocks per cache line. */
                lppp,         /* Logical processors per package. */
                apic_id;      /* Initial APIC ID. */
            union {
                uint32_t _1c;
                struct { DECL_BITFIELD(1c); };
            };
            union {
                uint32_t _1d;
                struct { DECL_BITFIELD(1d); };
            };

            /* Leaf 0x2 - TLB/Cache/Prefetch. */
            uint8_t l2_nr_queries; /* Documented as fixed to 1. */
            uint8_t l2_desc[15];

            uint64_t :64, :64; /* Leaf 0x3 - PSN. */
            uint64_t :64, :64; /* Leaf 0x4 - Structured Cache. */
            uint64_t :64, :64; /* Leaf 0x5 - MONITOR. */
            uint64_t :64, :64; /* Leaf 0x6 - Therm/Perf. */
            uint64_t :64, :64; /* Leaf 0x7 - Structured Features. */
            uint64_t :64, :64; /* Leaf 0x8 - rsvd */
            uint64_t :64, :64; /* Leaf 0x9 - DCA */

            /* Leaf 0xa - Intel PMU. */
            uint8_t pmu_version;
        };
    } basic;

    /* Structured cache leaf: 0x00000004[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_CACHE];
        struct cpuid_cache_leaf {
            uint32_t type:5,
                :27, :32, :32, :32;
        } subleaf[CPUID_GUEST_NR_CACHE];
    } cache;

    /* Structured feature leaf: 0x00000007[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_FEAT];
        struct {
            /* Subleaf 0. */
            uint32_t max_subleaf;
            union {
                uint32_t _7b0;
                struct { DECL_BITFIELD(7b0); };
            };
            union {
                uint32_t _7c0;
                struct { DECL_BITFIELD(7c0); };
            };
            union {
                uint32_t _7d0;
                struct { DECL_BITFIELD(7d0); };
            };
        };
    } feat;

    /* Xstate feature leaf: 0x0000000D[xx] */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_XSTATE];

        struct {
            /* Subleaf 0. */
            uint32_t xcr0_low, /* b */:32, max_size, xcr0_high;

            /* Subleaf 1. */
            union {
                uint32_t Da1;
                struct { DECL_BITFIELD(Da1); };
            };
            uint32_t /* b */:32, xss_low, xss_high;
        };

        /* Per-component common state.  Valid for i >= 2. */
        struct {
            uint32_t size, offset;
            bool xss:1, align:1;
            uint32_t _res_d;
        } comp[CPUID_GUEST_NR_XSTATE];
    } xstate;

    /* Extended leaves: 0x800000xx */
    union {
        struct cpuid_leaf raw[CPUID_GUEST_NR_EXTD];
        struct {
            /* Leaf 0x80000000 - Max and vendor. */
            uint32_t max_leaf, vendor_ebx, vendor_ecx, vendor_edx;

            /* Leaf 0x80000001 - Family/model/stepping and features. */
            uint32_t raw_fms, /* b */:32;
            union {
                uint32_t e1c;
                struct { DECL_BITFIELD(e1c); };
            };
            union {
                uint32_t e1d;
                struct { DECL_BITFIELD(e1d); };
            };

            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* Brand string. */
            uint64_t :64, :64; /* L1 cache/TLB. */
            uint64_t :64, :64; /* L2/3 cache/TLB. */

            /* Leaf 0x80000007 - Advanced Power Management. */
            uint32_t /* a */:32, /* b */:32, /* c */:32;
            union {
                uint32_t e7d;
                struct { DECL_BITFIELD(e7d); };
            };

            /* Leaf 0x80000008 - Misc addr/feature info. */
            uint8_t maxphysaddr, maxlinaddr, :8, :8;
            union {
                uint32_t e8b;
                struct { DECL_BITFIELD(e8b); };
            };
            uint32_t /* c */:32, /* d */:32;
        };
    } extd;

#undef __DECL_BITFIELD
#undef _DECL_BITFIELD
#undef DECL_BITFIELD

    /* Toolstack selected Hypervisor max_leaf (if non-zero). */
    uint8_t hv_limit, hv2_limit;

    /* Value calculated from raw data above. */
    uint8_t x86_vendor;
};

/* Fill in a featureset bitmap from a CPUID policy. */
static inline void cpuid_policy_to_featureset(
    const struct cpuid_policy *p, uint32_t fs[FSCAPINTS])
{
    fs[FEATURESET_1d]  = p->basic._1d;
    fs[FEATURESET_1c]  = p->basic._1c;
    fs[FEATURESET_e1d] = p->extd.e1d;
    fs[FEATURESET_e1c] = p->extd.e1c;
    fs[FEATURESET_Da1] = p->xstate.Da1;
    fs[FEATURESET_7b0] = p->feat._7b0;
    fs[FEATURESET_7c0] = p->feat._7c0;
    fs[FEATURESET_e7d] = p->extd.e7d;
    fs[FEATURESET_e8b] = p->extd.e8b;
    fs[FEATURESET_7d0] = p->feat._7d0;
}

/* Fill in a CPUID policy from a featureset bitmap. */
static inline void cpuid_featureset_to_policy(
    const uint32_t fs[FSCAPINTS], struct cpuid_policy *p)
{
    p->basic._1d  = fs[FEATURESET_1d];
    p->basic._1c  = fs[FEATURESET_1c];
    p->extd.e1d   = fs[FEATURESET_e1d];
    p->extd.e1c   = fs[FEATURESET_e1c];
    p->xstate.Da1 = fs[FEATURESET_Da1];
    p->feat._7b0  = fs[FEATURESET_7b0];
    p->feat._7c0  = fs[FEATURESET_7c0];
    p->extd.e7d   = fs[FEATURESET_e7d];
    p->extd.e8b   = fs[FEATURESET_e8b];
    p->feat._7d0  = fs[FEATURESET_7d0];
}

extern struct cpuid_policy raw_cpuid_policy, host_cpuid_policy,
    pv_max_cpuid_policy, hvm_max_cpuid_policy;

/* Allocate and initialise a CPUID policy suitable for the domain. */
int init_domain_cpuid_policy(struct domain *d);

/* Clamp the CPUID policy to reality. */
void recalculate_cpuid_policy(struct domain *d);

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
