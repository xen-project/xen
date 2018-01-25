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
#define SKIP_CTXT_SWITCH_SERROR_SYNC 6
#define ARM_HARDEN_BRANCH_PREDICTOR 7

#define ARM_NCAPS           8

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
