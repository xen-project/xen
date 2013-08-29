#ifndef __ASM_ARM_PLATFORMS_EXYNOS5_H
#define __ASM_ASM_PLATFORMS_EXYSNO5_H

#define EXYNOS5_MCT_BASE            0x101c0000
#define EXYNOS5_MCT_G_TCON          0x240       /* Relative to MCT_BASE */
#define EXYNOS5_MCT_G_TCON_START    (1 << 8)

#define EXYNOS5_PA_CHIPID           0x10000000
#define EXYNOS5_PA_TIMER            0x12dd0000
/* Base address of system controller */
#define EXYNOS5_PA_PMU              0x10040000

#define EXYNOS5_SWRESET             0x0400      /* Relative to PA_PMU */

#define S5P_PA_SYSRAM   0x02020000

#endif /* __ASM_ARM_PLATFORMS_EXYNOS5_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
