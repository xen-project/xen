#ifndef __ASM_ARM_CPUFEATURE_H
#define __ASM_ARM_CPUFEATURE_H

#ifdef CONFIG_ARM_64
#define cpu_feature64(c, feat)         ((c)->pfr64.feat)
#define boot_cpu_feature64(feat)       (system_cpuinfo.pfr64.feat)
#define boot_dbg_feature64(feat)       (system_cpuinfo.dbg64.feat)

#define cpu_feature64_has_el0_32(c)    (cpu_feature64(c, el0) == 2)

#define cpu_has_el0_32    (boot_cpu_feature64(el0) == 2)
#define cpu_has_el0_64    (boot_cpu_feature64(el0) >= 1)
#define cpu_has_el1_32    (boot_cpu_feature64(el1) == 2)
#define cpu_has_el1_64    (boot_cpu_feature64(el1) >= 1)
#define cpu_has_el2_32    (boot_cpu_feature64(el2) == 2)
#define cpu_has_el2_64    (boot_cpu_feature64(el2) >= 1)
#define cpu_has_el3_32    (boot_cpu_feature64(el3) == 2)
#define cpu_has_el3_64    (boot_cpu_feature64(el3) >= 1)
#define cpu_has_fp        (boot_cpu_feature64(fp) < 8)
#define cpu_has_simd      (boot_cpu_feature64(simd) < 8)
#define cpu_has_gicv3     (boot_cpu_feature64(gic) >= 1)
#endif

#define cpu_feature32(c, feat)         ((c)->pfr32.feat)
#define boot_cpu_feature32(feat)       (system_cpuinfo.pfr32.feat)
#define boot_dbg_feature32(feat)       (system_cpuinfo.dbg32.feat)

#define cpu_has_arm       (boot_cpu_feature32(arm) == 1)
#define cpu_has_thumb     (boot_cpu_feature32(thumb) >= 1)
#define cpu_has_thumb2    (boot_cpu_feature32(thumb) >= 3)
#define cpu_has_jazelle   (boot_cpu_feature32(jazelle) > 0)
#define cpu_has_thumbee   (boot_cpu_feature32(thumbee) == 1)
#define cpu_has_aarch32   (cpu_has_arm || cpu_has_thumb)

#ifdef CONFIG_ARM64_SVE
#define cpu_has_sve       (boot_cpu_feature64(sve) == 1)
#else
#define cpu_has_sve       0
#endif

#ifdef CONFIG_ARM_32
#define cpu_has_gicv3     (boot_cpu_feature32(gic) >= 1)
#define cpu_has_gentimer  (boot_cpu_feature32(gentimer) == 1)
/*
 * On Armv7, the value 0 is used to indicate that PMUv2 is not
 * supported. IOW this doesn't tell us whether the PMU is not supported
 * (a processor may implement PMUv1).
 *
 * For convenience, we treat 0 as not supported which matches the
 * meaning on Armv8
 */
#define cpu_has_pmu       ((boot_dbg_feature32(perfmon) >= 1) && \
                           (boot_dbg_feature32(perfmon) < 15))
#else
#define cpu_has_gentimer  (1)
#define cpu_has_pmu       ((boot_dbg_feature64(pmu_ver) >= 1) && \
                           (boot_dbg_feature64(pmu_ver) < 15))
#endif
#define cpu_has_security  (boot_cpu_feature32(security) > 0)

#define ARM64_WORKAROUND_CLEAN_CACHE    0
#define ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE    1
#define ARM32_WORKAROUND_766422 2
#define ARM64_WORKAROUND_834220 3
#define LIVEPATCH_FEATURE   4
#define SKIP_SYNCHRONIZE_SERROR_ENTRY_EXIT 5
#define ARM_HARDEN_BRANCH_PREDICTOR 6
#define ARM_SSBD 7
#define ARM_SMCCC_1_1 8
#define ARM64_WORKAROUND_AT_SPECULATE 9
#define ARM_WORKAROUND_858921 10
#define ARM64_WORKAROUND_REPEAT_TLBI 11
#define ARM_WORKAROUND_BHB_LOOP_8 12
#define ARM_WORKAROUND_BHB_LOOP_24 13
#define ARM_WORKAROUND_BHB_LOOP_32 14
#define ARM_WORKAROUND_BHB_SMCC_3 15
#define ARM_HAS_SB 16
#define ARM64_WORKAROUND_1508412 17

#define ARM_NCAPS           18

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/bitops.h>

extern DECLARE_BITMAP(cpu_hwcaps, ARM_NCAPS);

void check_local_cpu_features(void);
void enable_cpu_features(void);

static inline bool cpus_have_cap(unsigned int num)
{
    if ( num >= ARM_NCAPS )
        return false;

    return test_bit(num, cpu_hwcaps);
}

/* System capability check for constant cap */
#define cpus_have_const_cap(num) ({                 \
        register_t __ret;                           \
                                                    \
        asm volatile (ALTERNATIVE("mov %0, #0",     \
                                  "mov %0, #1",     \
                                  num)              \
                      : "=r" (__ret));              \
                                                    \
        unlikely(__ret);                            \
        })

static inline void cpus_set_cap(unsigned int num)
{
    if (num >= ARM_NCAPS)
        printk(XENLOG_WARNING "Attempt to set an illegal CPU capability (%d >= %d)\n",
               num, ARM_NCAPS);
    else
        __set_bit(num, cpu_hwcaps);
}

struct arm_cpu_capabilities {
    const char *desc;
    u16 capability;
    bool (*matches)(const struct arm_cpu_capabilities *entry);
    int (*enable)(void *data); /* Called on every active CPUs */
    union {
        struct {    /* To be used for eratum handling only */
            u32 midr_model;
            u32 midr_range_min, midr_range_max;
        };
    };
};

void update_cpu_capabilities(const struct arm_cpu_capabilities *caps,
                             const char *info);

void enable_cpu_capabilities(const struct arm_cpu_capabilities *caps);
int enable_nonboot_cpu_caps(const struct arm_cpu_capabilities *caps);

/*
 * capabilities of CPUs
 */
struct cpuinfo_arm {
    union {
        register_t bits;
        struct {
            unsigned long revision:4;
            unsigned long part_number:12;
            unsigned long architecture:4;
            unsigned long variant:4;
            unsigned long implementer:8;
#ifdef CONFIG_ARM_64
            unsigned long _res0:32;
#endif
        };
    } midr;
    union {
        register_t bits;
        struct {
            unsigned long aff0:8;
            unsigned long aff1:8;
            unsigned long aff2:8;
            unsigned long mt:1; /* Multi-thread, iff MP == 1 */
            unsigned long __res0:5;
            unsigned long up:1; /* UP system, iff MP == 1 */
            unsigned long mp:1; /* MP extensions */

#ifdef CONFIG_ARM_64
            unsigned long aff3:8;
            unsigned long __res1:24;
#endif
        };
    } mpidr;

#ifdef CONFIG_ARM_64
    /* 64-bit CPUID registers. */
    union {
        register_t bits[2];
        struct {
            /* PFR0 */
            unsigned long el0:4;
            unsigned long el1:4;
            unsigned long el2:4;
            unsigned long el3:4;
            unsigned long fp:4;   /* Floating Point */
            unsigned long simd:4; /* Advanced SIMD */
            unsigned long gic:4;  /* GIC support */
            unsigned long ras:4;
            unsigned long sve:4;
            unsigned long sel2:4;
            unsigned long mpam:4;
            unsigned long amu:4;
            unsigned long dit:4;
            unsigned long __res0:4;
            unsigned long csv2:4;
            unsigned long cvs3:4;

            /* PFR1 */
            unsigned long bt:4;
            unsigned long ssbs:4;
            unsigned long mte:4;
            unsigned long ras_frac:4;
            unsigned long mpam_frac:4;
            unsigned long __res1:4;
            unsigned long sme:4;
            unsigned long __res2:36;
        };
    } pfr64;

    union {
        register_t bits[2];
        struct {
            /* DFR0 */
            unsigned long debug_ver:4;
            unsigned long trace_ver:4;
            unsigned long pmu_ver:4;
            unsigned long brps:4;
            unsigned long __res0:4;
            unsigned long wrps:4;
            unsigned long __res1:4;
            unsigned long ctx_cmps:4;
            unsigned long pms_ver:4;
            unsigned long double_lock:4;
            unsigned long trace_filt:4;
            unsigned long __res2:4;
            unsigned long mtpmu:4;
            unsigned long __res3:12;

            /* DFR1 */
            unsigned long __res4:64;
        };
    } dbg64;

    struct {
        register_t bits[2];
    } aux64;

    union {
        register_t bits[3];
        struct {
            /* MMFR0 */
            unsigned long pa_range:4;
            unsigned long asid_bits:4;
            unsigned long bigend:4;
            unsigned long secure_ns:4;
            unsigned long bigend_el0:4;
            unsigned long tgranule_16K:4;
            unsigned long tgranule_64K:4;
            unsigned long tgranule_4K:4;
            unsigned long tgranule_16k_2:4;
            unsigned long tgranule_64k_2:4;
            unsigned long tgranule_4k_2:4;
            unsigned long exs:4;
            unsigned long __res0:8;
            unsigned long fgt:4;
            unsigned long ecv:4;

            /* MMFR1 */
            unsigned long hafdbs:4;
            unsigned long vmid_bits:4;
            unsigned long vh:4;
            unsigned long hpds:4;
            unsigned long lo:4;
            unsigned long pan:4;
            unsigned long specsei:4;
            unsigned long xnx:4;
            unsigned long twed:4;
            unsigned long ets:4;
            unsigned long __res1:4;
            unsigned long afp:4;
            unsigned long __res2:12;
            unsigned long ecbhb:4;

            /* MMFR2 */
            unsigned long __res3:64;
        };
    } mm64;

    union {
        register_t bits[3];
        struct {
            /* ISAR0 */
            unsigned long __res0:4;
            unsigned long aes:4;
            unsigned long sha1:4;
            unsigned long sha2:4;
            unsigned long crc32:4;
            unsigned long atomic:4;
            unsigned long __res1:4;
            unsigned long rdm:4;
            unsigned long sha3:4;
            unsigned long sm3:4;
            unsigned long sm4:4;
            unsigned long dp:4;
            unsigned long fhm:4;
            unsigned long ts:4;
            unsigned long tlb:4;
            unsigned long rndr:4;

            /* ISAR1 */
            unsigned long dpb:4;
            unsigned long apa:4;
            unsigned long api:4;
            unsigned long jscvt:4;
            unsigned long fcma:4;
            unsigned long lrcpc:4;
            unsigned long gpa:4;
            unsigned long gpi:4;
            unsigned long frintts:4;
            unsigned long sb:4;
            unsigned long specres:4;
            unsigned long bf16:4;
            unsigned long dgh:4;
            unsigned long i8mm:4;
            unsigned long __res2:8;

            /* ISAR2 */
            unsigned long wfxt:4;
            unsigned long rpres:4;
            unsigned long gpa3:4;
            unsigned long apa3:4;
            unsigned long __res3:12;
            unsigned long clearbhb:4;

            unsigned long __res4:32;
        };
    } isa64;

    union {
        register_t bits[1];
        struct {
            unsigned long len:4;
            unsigned long __res0:60;
        };
    } zcr64;

    struct {
        register_t bits[1];
    } zfr64;

    /*
     * DCZID is only used to check for incoherent values between cores
     * and taint Xen in this case
     */
    struct {
        register_t bits[1];
    } dczid;

    /*
     * CTR is only used to check for different cache types or policies and
     * taint Xen in this case
     */
    struct {
        register_t bits[1];
    } ctr;

#endif

    /*
     * 32-bit CPUID registers. On ARMv8 these describe the properties
     * when running in 32-bit mode.
     */
    union {
        register_t bits[3];
        struct {
            /* PFR0 */
            unsigned long arm:4;
            unsigned long thumb:4;
            unsigned long jazelle:4;
            unsigned long thumbee:4;
            unsigned long csv2:4;
            unsigned long amu:4;
            unsigned long dit:4;
            unsigned long ras:4;
#ifdef CONFIG_ARM_64
            unsigned long __res0:32;
#endif

            /* PFR1 */
            unsigned long progmodel:4;
            unsigned long security:4;
            unsigned long mprofile:4;
            unsigned long virt:4;
            unsigned long gentimer:4;
            unsigned long sec_frac:4;
            unsigned long virt_frac:4;
            unsigned long gic:4;
#ifdef CONFIG_ARM_64
            unsigned long __res1:32;
#endif

            /* PFR2 */
            unsigned long csv3:4;
            unsigned long ssbs:4;
            unsigned long ras_frac:4;
            unsigned long __res2:20;
#ifdef CONFIG_ARM_64
            unsigned long __res3:32;
#endif
        };
    } pfr32;

    union {
        register_t bits[2];
        struct {
            /* DFR0 */
            unsigned long copdbg:4;
            unsigned long copsdbg:4;
            unsigned long mmapdbg:4;
            unsigned long coptrc:4;
            unsigned long mmaptrc:4;
            unsigned long mprofdbg:4;
            unsigned long perfmon:4;
            unsigned long tracefilt:4;
#ifdef CONFIG_ARM_64
            unsigned long __res0:32;
#endif

            /* DFR1 */
            unsigned long mtpmu:4;
            unsigned long __res1:28;
#ifdef CONFIG_ARM_64
            unsigned long __res2:32;
#endif
        };
    } dbg32;

    struct {
        register_t bits[1];
    } aux32;

    struct {
        register_t bits[6];
    } mm32;

    struct {
        register_t bits[7];
    } isa32;

    struct {
        register_t bits[3];
    } mvfr;
};

extern struct cpuinfo_arm system_cpuinfo;

extern void identify_cpu(struct cpuinfo_arm *c);

#ifdef CONFIG_ARM_64
extern void update_system_features(const struct cpuinfo_arm *new);
#else
static inline void update_system_features(const struct cpuinfo_arm *cpuinfo)
{
    /* Not supported on arm32 */
}
#endif

extern struct cpuinfo_arm cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]

extern struct cpuinfo_arm domain_cpuinfo;

#endif /* __ASSEMBLY__ */

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
