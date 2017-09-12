/*
 * xen/arch/arm/platforms/omap5.c
 *
 * OMAP5 specific settings
 *
 * Chen Baozi <baozich@gmail.com>
 * Copyright (c) 2013
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
#include <asm/platform.h>
#include <asm/platforms/omap5.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/io.h>

static uint16_t num_den[8][2] = {
    {         0,          0 },  /* not used */
    {  26 *  64,  26 *  125 },  /* 12.0 Mhz */
    {   2 * 768,   2 * 1625 },  /* 13.0 Mhz */
    {         0,          0 },  /* not used */
    { 130 *   8, 130 *   25 },  /* 19.2 Mhz */
    {   2 * 384,   2 * 1625 },  /* 26.0 Mhz */
    {   3 * 256,   3 * 1125 },  /* 27.0 Mhz */
    { 130 *   4, 130 *   25 },  /* 38.4 Mhz */
};

/*
 * The realtime counter also called master counter, is a free-running
 * counter, which is related to real time. It produces the count used
 * by the CPU local timer peripherals in the MPU cluster. The timer counts
 * at a rate of 6.144 MHz. Because the device operates on different clocks
 * in different power modes, the master counter shifts operation between
 * clocks, adjusting the increment per clock in hardware accordingly to
 * maintain a constant count rate.
 */
static int omap5_init_time(void)
{
    void __iomem *ckgen_prm_base;
    void __iomem *rt_ct_base;
    unsigned int sys_clksel;
    unsigned int num, den, frac1, frac2;

    ckgen_prm_base = ioremap_nocache(OMAP5_CKGEN_PRM_BASE, 0x20);
    if ( !ckgen_prm_base )
    {
        dprintk(XENLOG_ERR, "%s: PRM_BASE ioremap failed\n", __func__);
        return -ENOMEM;
    }

    sys_clksel = readl(ckgen_prm_base + OMAP5_CM_CLKSEL_SYS) &
        ~SYS_CLKSEL_MASK;

    iounmap(ckgen_prm_base);

    rt_ct_base = ioremap_nocache(REALTIME_COUNTER_BASE, 0x20);
    if ( !rt_ct_base )
    {
        dprintk(XENLOG_ERR, "%s: REALTIME_COUNTER_BASE ioremap failed\n", __func__);
        return -ENOMEM;
    }

    frac1 = readl(rt_ct_base + INCREMENTER_NUMERATOR_OFFSET);
    num = frac1 & ~NUMERATOR_DENUMERATOR_MASK;
    if ( num_den[sys_clksel][0] != num )
    {
        frac1 &= NUMERATOR_DENUMERATOR_MASK;
        frac1 |= num_den[sys_clksel][0];
    }

    frac2 = readl(rt_ct_base + INCREMENTER_DENUMERATOR_RELOAD_OFFSET);
    den = frac2 & ~NUMERATOR_DENUMERATOR_MASK;
    if ( num_den[sys_clksel][1] != num )
    {
        frac2 &= NUMERATOR_DENUMERATOR_MASK;
        frac2 |= num_den[sys_clksel][1];
    }

    writel(frac1, rt_ct_base + INCREMENTER_NUMERATOR_OFFSET);
    writel(frac2 | PRM_FRAC_INCREMENTER_DENUMERATOR_RELOAD,
           rt_ct_base + INCREMENTER_DENUMERATOR_RELOAD_OFFSET);

    iounmap(rt_ct_base);

    return 0;
}

/* Additional mappings for dom0 (not in the DTS) */
static int omap5_specific_mapping(struct domain *d)
{
    /* Map the PRM module */
    map_mmio_regions(d, gaddr_to_gfn(OMAP5_PRM_BASE), 2,
                     maddr_to_mfn(OMAP5_PRM_BASE));

    /* Map the PRM_MPU */
    map_mmio_regions(d, gaddr_to_gfn(OMAP5_PRCM_MPU_BASE), 1,
                     maddr_to_mfn(OMAP5_PRCM_MPU_BASE));

    /* Map the Wakeup Gen */
    map_mmio_regions(d, gaddr_to_gfn(OMAP5_WKUPGEN_BASE), 1,
                     maddr_to_mfn(OMAP5_WKUPGEN_BASE));

    /* Map the on-chip SRAM */
    map_mmio_regions(d, gaddr_to_gfn(OMAP5_SRAM_PA), 32,
                     maddr_to_mfn(OMAP5_SRAM_PA));

    return 0;
}

static int __init omap5_smp_init(void)
{
    void __iomem *wugen_base;

    wugen_base = ioremap_nocache(OMAP5_WKUPGEN_BASE, PAGE_SIZE);
    if ( !wugen_base )
    {
        dprintk(XENLOG_ERR, "Unable to map omap5 MMIO\n");
        return -EFAULT;
    }

    printk("Set AuxCoreBoot1 to %"PRIpaddr" (%p)\n",
           __pa(init_secondary), init_secondary);
    writel(__pa(init_secondary), wugen_base + OMAP_AUX_CORE_BOOT_1_OFFSET);

    printk("Set AuxCoreBoot0 to 0x20\n");
    writel(0x20, wugen_base + OMAP_AUX_CORE_BOOT_0_OFFSET);

    iounmap(wugen_base);

    return 0;
}

static const char * const omap5_dt_compat[] __initconst =
{
    "ti,omap5",
    NULL
};

static const char * const dra7_dt_compat[] __initconst =
{
    "ti,dra7",
    NULL
};

PLATFORM_START(omap5, "TI OMAP5")
    .compatible = omap5_dt_compat,
    .init_time = omap5_init_time,
    .specific_mapping = omap5_specific_mapping,
    .smp_init = omap5_smp_init,
    .cpu_up = cpu_up_send_sgi,
PLATFORM_END

PLATFORM_START(dra7, "TI DRA7")
    .compatible = dra7_dt_compat,
    .init_time = omap5_init_time,
    .cpu_up = cpu_up_send_sgi,
    .smp_init = omap5_smp_init,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
