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
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/delay.h>
#include <asm/platforms/exynos5.h>
#include <asm/platform.h>
#include <asm/io.h>

static bool secure_firmware;

#define EXYNOS_ARM_CORE0_CONFIG     0x2000
#define EXYNOS_ARM_CORE_CONFIG(_nr) (EXYNOS_ARM_CORE0_CONFIG + (0x80 * (_nr)))
#define EXYNOS_ARM_CORE_STATUS(_nr) (EXYNOS_ARM_CORE_CONFIG(_nr) + 0x4)
#define S5P_CORE_LOCAL_PWR_EN       0x3

#define SMC_CMD_CPU1BOOT            (-4)

static int exynos5_init_time(void)
{
    uint32_t reg;
    void __iomem *mct;
    int rc;
    struct dt_device_node *node;
    u64 mct_base_addr;
    u64 size;

    node = dt_find_compatible_node(NULL, NULL, "samsung,exynos4210-mct");
    if ( !node )
    {
        dprintk(XENLOG_ERR, "samsung,exynos4210-mct missing in DT\n");
        return -ENXIO;
    }

    rc = dt_device_get_address(node, 0, &mct_base_addr, &size);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "Error in \"samsung,exynos4210-mct\"\n");
        return -ENXIO;
    }

    dprintk(XENLOG_INFO, "mct_base_addr: %016llx size: %016llx\n",
            mct_base_addr, size);

    mct = ioremap_nocache(mct_base_addr, size);
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
static int exynos5250_specific_mapping(struct domain *d)
{
    /* Map the chip ID */
    map_mmio_regions(d, gaddr_to_gfn(EXYNOS5_PA_CHIPID), 1,
                     maddr_to_mfn(EXYNOS5_PA_CHIPID));

    /* Map the PWM region */
    map_mmio_regions(d, gaddr_to_gfn(EXYNOS5_PA_TIMER), 2,
                     maddr_to_mfn(EXYNOS5_PA_TIMER));

    return 0;
}

static int __init exynos5_smp_init(void)
{
    struct dt_device_node *node;
    void __iomem *sysram;
    char *compatible;
    u64 sysram_addr;
    u64 size;
    u64 sysram_offset;
    int rc;

    node = dt_find_compatible_node(NULL, NULL, "samsung,secure-firmware");
    if ( node )
    {
        /* Have to use sysram_ns_base_addr + 0x1c for boot address */
        compatible = "samsung,exynos4210-sysram-ns";
        sysram_offset = 0x1c;
        secure_firmware = true;
        printk("Running under secure firmware.\n");
    }
    else
    {
        /* Have to use sysram_base_addr + offset 0 for boot address */
        compatible = "samsung,exynos4210-sysram";
        sysram_offset = 0;
    }

    node = dt_find_compatible_node(NULL, NULL, compatible);
    if ( !node )
    {
        dprintk(XENLOG_ERR, "%s missing in DT\n", compatible);
        return -ENXIO;
    }

    rc = dt_device_get_address(node, 0, &sysram_addr, &size);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "Error in %s\n", compatible);
        return -ENXIO;
    }
    dprintk(XENLOG_INFO, "sysram_addr: %016llx size: %016llx offset: %016llx\n",
            sysram_addr, size, sysram_offset);

    sysram = ioremap_nocache(sysram_addr, size);
    if ( !sysram )
    {
        dprintk(XENLOG_ERR, "Unable to map exynos5 MMIO\n");
        return -EFAULT;
    }

    printk("Set SYSRAM to %"PRIpaddr" (%p)\n",
           __pa(init_secondary), init_secondary);
    writel(__pa(init_secondary), sysram + sysram_offset);

    iounmap(sysram);

    return 0;
}

static int exynos_cpu_power_state(void __iomem *power, int cpu)
{
    return __raw_readl(power + EXYNOS_ARM_CORE_STATUS(cpu)) &
           S5P_CORE_LOCAL_PWR_EN;
}

static void exynos_cpu_power_up(void __iomem *power, int cpu)
{
    __raw_writel(S5P_CORE_LOCAL_PWR_EN,
                 power + EXYNOS_ARM_CORE_CONFIG(cpu));
}

static int exynos5_cpu_power_up(void __iomem *power, int cpu)
{
    unsigned int timeout;

    if ( !exynos_cpu_power_state(power, cpu) )
    {
        exynos_cpu_power_up(power, cpu);
        timeout = 10;

        /* wait max 10 ms until cpu is on */
        while ( exynos_cpu_power_state(power, cpu) != S5P_CORE_LOCAL_PWR_EN )
        {
            mdelay(1);

            if ( --timeout == 0 )
                break;
        }

        if ( timeout == 0 )
        {
            dprintk(XENLOG_ERR, "CPU%d power enable failed\n", cpu);
            return -ETIMEDOUT;
        }
    }
    return 0;
}

static int exynos5_get_pmu_baseandsize(u64 *power_base_addr, u64 *size)
{
    struct dt_device_node *node;
    int rc;
    static const struct dt_device_match exynos_dt_pmu_matches[] =
    {
        DT_MATCH_COMPATIBLE("samsung,exynos5250-pmu"),
        DT_MATCH_COMPATIBLE("samsung,exynos5410-pmu"),
        DT_MATCH_COMPATIBLE("samsung,exynos5420-pmu"),
        { /*sentinel*/ },
    };

    node = dt_find_matching_node(NULL, exynos_dt_pmu_matches);
    if ( !node )
    {
        dprintk(XENLOG_ERR, "samsung,exynos5XXX-pmu missing in DT\n");
        return -ENXIO;
    }

    rc = dt_device_get_address(node, 0, power_base_addr, size);
    if ( rc )
    {
        dprintk(XENLOG_ERR, "Error in \"samsung,exynos5XXX-pmu\"\n");
        return -ENXIO;
    }

    dprintk(XENLOG_DEBUG, "power_base_addr: %016llx size: %016llx\n",
            *power_base_addr, *size);

    return 0;
}

static int exynos5_cpu_up(int cpu)
{
    u64 power_base_addr;
    u64 size;
    void __iomem *power;
    int rc;

    rc = exynos5_get_pmu_baseandsize(&power_base_addr, &size);
    if ( rc )
        return rc;

    power = ioremap_nocache(power_base_addr, size);
    if ( !power )
    {
        dprintk(XENLOG_ERR, "Unable to map power MMIO\n");
        return -EFAULT;
    }

    rc = exynos5_cpu_power_up(power, cpu);
    if ( rc )
    {
        iounmap(power);
        return -ETIMEDOUT;
    }

    iounmap(power);

    if ( secure_firmware )
        call_smc(SMC_CMD_CPU1BOOT, cpu, 0, 0);

    return cpu_up_send_sgi(cpu);
}

static void exynos5_reset(void)
{
    u64 power_base_addr;
    u64 size;
    void __iomem *pmu;
    int rc;

    rc = exynos5_get_pmu_baseandsize(&power_base_addr, &size);
    if ( rc )
        return;

    pmu = ioremap_nocache(power_base_addr, size);
    if ( !pmu )
    {
        dprintk(XENLOG_ERR, "Unable to map PMU\n");
        return;
    }

    writel(1, pmu + EXYNOS5_SWRESET);

    iounmap(pmu);
}

static const struct dt_device_match exynos5_blacklist_dev[] __initconst =
{
    /* Multi core Timer
     * TODO: this device set up IRQ to CPU 1 which is not yet handled by Xen.
     * This is result to random freeze.
     */
    DT_MATCH_COMPATIBLE("samsung,exynos4210-mct"),
    DT_MATCH_COMPATIBLE("samsung,secure-firmware"),
    { /* sentinel */ },
};

static const char * const exynos5250_dt_compat[] __initconst =
{
    "samsung,exynos5250",
    NULL
};

static const char * const exynos5_dt_compat[] __initconst =
{
    "samsung,exynos5410",
    NULL
};

PLATFORM_START(exynos5250, "SAMSUNG EXYNOS5250")
    .compatible = exynos5250_dt_compat,
    .init_time = exynos5_init_time,
    .specific_mapping = exynos5250_specific_mapping,
    .smp_init = exynos5_smp_init,
    .cpu_up = cpu_up_send_sgi,
    .reset = exynos5_reset,
    .blacklist_dev = exynos5_blacklist_dev,
PLATFORM_END

PLATFORM_START(exynos5, "SAMSUNG EXYNOS5")
    .compatible = exynos5_dt_compat,
    .init_time = exynos5_init_time,
    .smp_init = exynos5_smp_init,
    .cpu_up = exynos5_cpu_up,
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
