/*
 * xen/arch/arm/platforms/exynos5.c
 *
 * Exynos5 specific settings
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/p2m.h>
#include <xen/config.h>
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/platforms/exynos5.h>
#include <asm/platform.h>

static int exynos5_init_time(void)
{
    uint32_t reg;
    void __iomem *mct;

    BUILD_BUG_ON(EXYNOS5_MCT_G_TCON >= PAGE_SIZE);

    mct = ioremap_attr(EXYNOS5_MCT_BASE, PAGE_SIZE, PAGE_HYPERVISOR_NOCACHE);
    if ( !mct )
    {
        dprintk(XENLOG_ERR, "Unable to map MCT\n");
        return -ENOMEM;
    }

    /* Enable timer on Exynos 5250 should probably be done by u-boot */
    reg = ioreadl(mct + EXYNOS5_MCT_G_TCON);
    iowritel(mct + EXYNOS5_MCT_G_TCON, reg | EXYNOS5_MCT_G_TCON_START);

    iounmap(mct);

    return 0;
}

/* Additional mappings for dom0 (Not in the DTS) */
static int exynos5_specific_mapping(struct domain *d)
{
    /* Map the chip ID */
    map_mmio_regions(d, EXYNOS5_PA_CHIPID, EXYNOS5_PA_CHIPID + PAGE_SIZE - 1,
                     EXYNOS5_PA_CHIPID);

    /* Map the PWM region */
    map_mmio_regions(d, EXYNOS5_PA_TIMER,
                     EXYNOS5_PA_TIMER + (PAGE_SIZE * 2) - 1,
                     EXYNOS5_PA_TIMER);

    return 0;
}

static void exynos5_reset(void)
{
    void __iomem *pmu;

    BUILD_BUG_ON(EXYNOS5_SWRESET >= PAGE_SIZE);

    pmu = ioremap_nocache(EXYNOS5_PA_PMU, PAGE_SIZE);
    if ( !pmu )
    {
        dprintk(XENLOG_ERR, "Unable to map PMU\n");
        return;
    }

    iowritel(pmu + EXYNOS5_SWRESET, 1);
    iounmap(pmu);
}

static uint32_t exynos5_quirks(void)
{
    return PLATFORM_QUIRK_DOM0_MAPPING_11;
}

static const char const *exynos5_dt_compat[] __initdata =
{
    "samsung,exynos5250",
    NULL
};

PLATFORM_START(exynos5, "SAMSUNG EXYNOS5")
    .compatible = exynos5_dt_compat,
    .init_time = exynos5_init_time,
    .specific_mapping = exynos5_specific_mapping,
    .reset = exynos5_reset,
    .quirks = exynos5_quirks,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
