/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mpu.h: Arm Memory Protection Unit definitions.
 */

#ifndef __ARM_MPU_H__
#define __ARM_MPU_H__

#if defined(CONFIG_ARM_64)
# include <asm/arm64/mpu.h>
#elif defined(CONFIG_ARM_32)
# include <asm/arm32/mpu.h>
#else
# error "unknown ARM variant"
#endif

#define MPU_REGION_SHIFT  6
#define MPU_REGION_ALIGN  (_AC(1, UL) << MPU_REGION_SHIFT)
#define MPU_REGION_MASK   (~(MPU_REGION_ALIGN - 1))

#define NUM_MPU_REGIONS_SHIFT   8
#define NUM_MPU_REGIONS         (_AC(1, UL) << NUM_MPU_REGIONS_SHIFT)
#define NUM_MPU_REGIONS_MASK    (NUM_MPU_REGIONS - 1)
#define MAX_MPU_REGION_NR       NUM_MPU_REGIONS_MASK

#define PRENR_MASK  GENMASK(31, 0)

#ifndef __ASSEMBLY__

/*
 * Set base address of MPU protection region.
 *
 * @pr: pointer to the protection region structure.
 * @base: base address as base of the protection region.
 */
static inline void pr_set_base(pr_t *pr, paddr_t base)
{
    pr->prbar.reg.base = ((base & ~MPU_REGION_RES0) >> MPU_REGION_SHIFT);
}

/*
 * Set limit address of MPU protection region.
 *
 * @pr: pointer to the protection region structure.
 * @limit: exclusive address as limit of the protection region.
 */
static inline void pr_set_limit(pr_t *pr, paddr_t limit)
{
    /* PRLAR_ELx.LIMIT expects inclusive limit */
    pr->prlar.reg.limit = (((limit - 1) & ~MPU_REGION_RES0)
                           >> MPU_REGION_SHIFT);
}

/*
 * Access to get base address of MPU protection region.
 * The base address shall be zero extended.
 *
 * @pr: pointer to the protection region structure.
 * @return: Base address configured for the passed protection region.
 */
static inline paddr_t pr_get_base(const pr_t *pr)
{
    return (paddr_t)(pr->prbar.reg.base << MPU_REGION_SHIFT);
}

/*
 * Access to get limit address of MPU protection region.
 * The limit address shall be concatenated with 0x3f.
 *
 * @pr: pointer to the protection region structure.
 * @return: Inclusive limit address configured for the passed protection region.
 */
static inline paddr_t pr_get_limit(const pr_t *pr)
{
    return (paddr_t)((pr->prlar.reg.limit << MPU_REGION_SHIFT)
                     | ~MPU_REGION_MASK);
}

/*
 * Check if the protection region is valid (enabled).
 *
 * @pr: pointer to the protection region structure.
 * @return: True if the region is valid (enabled), false otherwise.
 */
static inline bool region_is_valid(const pr_t *pr)
{
    return pr->prlar.reg.en;
}

#endif /* __ASSEMBLY__ */

#endif /* __ARM_MPU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
