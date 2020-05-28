#ifndef __ASM_ARM_CPUFEATURE_H
#define __ASM_ARM_CPUFEATURE_H

#ifdef CONFIG_ARM_64
#define cpu_feature64(c, feat)         ((c)->pfr64.feat)
#define boot_cpu_feature64(feat)       (boot_cpu_data.pfr64.feat)

#define cpu_has_el0_32    (boot_cpu_feature64(el0) == 2)
#define cpu_has_el0_64    (boot_cpu_feature64(el0) >= 1)
#define cpu_has_el1_32    (boot_cpu_feature64(el1) == 2)
#define cpu_has_el1_64    (boot_cpu_feature64(el1) >= 1)
#define cpu_has_el2_32    (boot_cpu_feature64(el2) == 2)
#define cpu_has_el2_64    (boot_cpu_feature64(el2) >= 1)
#define cpu_has_el3_32    (boot_cpu_feature64(el3) == 2)
#define cpu_has_el3_64    (boot_cpu_feature64(el3) >= 1)
#define cpu_has_fp        (boot_cpu_feature64(fp) == 0)
#define cpu_has_simd      (boot_cpu_feature64(simd) == 0)
#define cpu_has_gicv3     (boot_cpu_feature64(gic) == 1)
#endif

#define cpu_feature32(c, feat)         ((c)->pfr32.feat)
#define boot_cpu_feature32(feat)       (boot_cpu_data.pfr32.feat)

#define cpu_has_arm       (boot_cpu_feature32(arm) == 1)
#define cpu_has_thumb     (boot_cpu_feature32(thumb) >= 1)
#define cpu_has_thumb2    (boot_cpu_feature32(thumb) >= 3)
#define cpu_has_jazelle   (boot_cpu_feature32(jazelle) > 0)
#define cpu_has_thumbee   (boot_cpu_feature32(thumbee) == 1)
#define cpu_has_aarch32   (cpu_has_arm || cpu_has_thumb)

#ifdef CONFIG_ARM_32
#define cpu_has_gentimer  (boot_cpu_feature32(gentimer) == 1)
#else
#define cpu_has_gentimer  (1)
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

#define ARM_NCAPS           10

#ifndef __ASSEMBLY__

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/bitops.h>

extern DECLARE_BITMAP(cpu_hwcaps, ARM_NCAPS);

static inline bool cpus_have_cap(unsigned int num)
{
    if ( num >= ARM_NCAPS )
        return false;

    return test_bit(num, cpu_hwcaps);
}

static inline cpu_nr_siblings(unsigned int)
{
    return 1;
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
    bool (*matches)(const struct arm_cpu_capabilities *);
    int (*enable)(void *); /* Called on every active CPUs */
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
        uint32_t bits;
        struct {
            unsigned long revision:4;
            unsigned long part_number:12;
            unsigned long architecture:4;
            unsigned long variant:4;
            unsigned long implementer:8;
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
        uint64_t bits[2];
        struct {
            unsigned long el0:4;
            unsigned long el1:4;
            unsigned long el2:4;
            unsigned long el3:4;
            unsigned long fp:4;   /* Floating Point */
            unsigned long simd:4; /* Advanced SIMD */
            unsigned long gic:4;  /* GIC support */
            unsigned long __res0:28;
            unsigned long csv2:4;
            unsigned long __res1:4;
        };
    } pfr64;

    struct {
        uint64_t bits[2];
    } dbg64;

    struct {
        uint64_t bits[2];
    } aux64;

    union {
        uint64_t bits[2];
        struct {
            unsigned long pa_range:4;
            unsigned long asid_bits:4;
            unsigned long bigend:4;
            unsigned long secure_ns:4;
            unsigned long bigend_el0:4;
            unsigned long tgranule_16K:4;
            unsigned long tgranule_64K:4;
            unsigned long tgranule_4K:4;
            unsigned long __res0:32;

            unsigned long hafdbs:4;
            unsigned long vmid_bits:4;
            unsigned long vh:4;
            unsigned long hpds:4;
            unsigned long lo:4;
            unsigned long pan:4;
            unsigned long __res1:8;
            unsigned long __res2:32;
        };
    } mm64;

    struct {
        uint64_t bits[2];
    } isa64;

#endif

    /*
     * 32-bit CPUID registers. On ARMv8 these describe the properties
     * when running in 32-bit mode.
     */
    union {
        uint32_t bits[2];
        struct {
            unsigned long arm:4;
            unsigned long thumb:4;
            unsigned long jazelle:4;
            unsigned long thumbee:4;
            unsigned long __res0:16;

            unsigned long progmodel:4;
            unsigned long security:4;
            unsigned long mprofile:4;
            unsigned long virt:4;
            unsigned long gentimer:4;
            unsigned long __res1:12;
        };
    } pfr32;

    struct {
        uint32_t bits[1];
    } dbg32;

    struct {
        uint32_t bits[1];
    } aux32;

    struct {
        uint32_t bits[4];
    } mm32;

    struct {
        uint32_t bits[6];
    } isa32;
};

extern struct cpuinfo_arm boot_cpu_data;

extern void identify_cpu(struct cpuinfo_arm *);

extern struct cpuinfo_arm cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]

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
