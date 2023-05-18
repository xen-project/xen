/*
 * xen/arch/arm/platforms/brcm-raspberry-pi.c
 *
 * Raspberry Pi 4 Platform specific settings.
 *
 * Stewart Hildebrand <stewart.hildebrand@dornerworks.com>
 * Copyright (c) 2019 DornerWorks, Ltd
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

#include <xen/delay.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/platform.h>

static const char *const rpi4_dt_compat[] __initconst =
{
    "brcm,bcm2711",
    NULL
};

static const struct dt_device_match rpi4_blacklist_dev[] __initconst =
{
    /*
     * The aux SPIs share an IRQ and a page with the aux UART.
     * If the same page gets mapped to dom0 and Xen, there is risk of
     * dom0 writing to the UART that Xen controls.
     */
    DT_MATCH_COMPATIBLE("brcm,bcm2835-aux-spi"),
    /*
     * The aux peripheral also shares a page with the aux UART.
     */
    DT_MATCH_COMPATIBLE("brcm,bcm2835-aux"),
    /* Special device used for rebooting */
    DT_MATCH_COMPATIBLE("brcm,bcm2835-pm"),
    { /* sentinel */ },
};


#define PM_PASSWORD                 0x5a000000
#define PM_RSTC                     0x1c
#define PM_WDOG                     0x24
#define PM_RSTC_WRCFG_FULL_RESET    0x00000020
#define PM_RSTC_WRCFG_CLR           0xffffffcf

static void __iomem *rpi4_map_watchdog(void)
{
    void __iomem *base;
    struct dt_device_node *node;
    paddr_t start, len;
    int ret;

    node = dt_find_compatible_node(NULL, NULL, "brcm,bcm2835-pm");
    if ( !node )
        return NULL;

    ret = dt_device_get_paddr(node, 0, &start, &len);
    if ( ret )
    {
        printk("Cannot read watchdog register address\n");
        return NULL;
    }

    base = ioremap_nocache(start & PAGE_MASK, PAGE_SIZE);
    if ( !base )
    {
        printk("Unable to map watchdog register!\n");
        return NULL;
    }

    return base;
}

static void rpi4_reset(void)
{
    uint32_t val;
    void __iomem *base = rpi4_map_watchdog();

    if ( !base )
        return;

    /* use a timeout of 10 ticks (~150us) */
    writel(10 | PM_PASSWORD, base + PM_WDOG);
    val = readl(base + PM_RSTC);
    val &= PM_RSTC_WRCFG_CLR;
    val |= PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET;
    writel(val, base + PM_RSTC);

    /* No sleeping, possibly atomic. */
    mdelay(1);
}

PLATFORM_START(rpi4, "Raspberry Pi 4")
    .compatible     = rpi4_dt_compat,
    .blacklist_dev  = rpi4_blacklist_dev,
    .reset = rpi4_reset,
    .dma_bitsize    = 30,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
