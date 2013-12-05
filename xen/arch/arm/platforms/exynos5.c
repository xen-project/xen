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
#include <asm/io.h>

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
    reg = readl(mct + EXYNOS5_MCT_G_TCON);
    writel(reg | EXYNOS5_MCT_G_TCON_START, mct + EXYNOS5_MCT_G_TCON);

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

static int __init exynos5_smp_init(void)
{
    void __iomem *sysram;

    sysram = ioremap_nocache(S5P_PA_SYSRAM, PAGE_SIZE);
    if ( !sysram )
    {
        dprintk(XENLOG_ERR, "Unable to map exynos5 MMIO\n");
        return -EFAULT;
    }

    printk("Set SYSRAM to %"PRIpaddr" (%p)\n",
           __pa(init_secondary), init_secondary);
    writel(__pa(init_secondary), sysram);

    iounmap(sysram);

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

    writel(1, pmu + EXYNOS5_SWRESET);
    iounmap(pmu);
}

static const char * const exynos5_dt_compat[] __initconst =
{
    "samsung,exynos5250",
    NULL
};

static const struct dt_device_match exynos5_blacklist_dev[] __initconst =
{
    /* Multi core Timer
     * TODO: this device set up IRQ to CPU 1 which is not yet handled by Xen.
     * This is result to random freeze.
     */
    DT_MATCH_COMPATIBLE("samsung,exynos4210-mct"),
    { /* sentinel */ },
};

PLATFORM_START(exynos5, "SAMSUNG EXYNOS5")
    .compatible = exynos5_dt_compat,
    .init_time = exynos5_init_time,
    .specific_mapping = exynos5_specific_mapping,
    .smp_init = exynos5_smp_init,
    .cpu_up = cpu_up_send_sgi,
    .reset = exynos5_reset,
    .blacklist_dev = exynos5_blacklist_dev,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
