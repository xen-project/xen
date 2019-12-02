/*
 * xen/arch/arm/platforms/sunxi.c
 *
 * SUNXI (Allwinner ARM SoCs) specific settings
 *
 * Copyright (c) 2013 Citrix Systems.
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

#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/platform.h>
#include <asm/io.h>

/* Watchdog constants: */
#define SUNXI_WDT_MODE_REG        0x04
#define SUNXI_WDT_MODE_EN         (1 << 0)
#define SUNXI_WDT_MODE_RST_EN     (1 << 1)

#define SUNXI_WDT_CONFIG_SYSTEM_RESET   (1 << 0)
#define SUNXI_WDOG0_CFG_REG             0x14
#define SUNXI_WDOG0_MODE_REG            0x18

static void __iomem *sunxi_map_watchdog(bool *new_wdt)
{
    void __iomem *wdt;
    struct dt_device_node *node;
    paddr_t wdt_start, wdt_len;
    bool _new_wdt = false;
    int ret;

    node = dt_find_compatible_node(NULL, NULL, "allwinner,sun6i-a31-wdt");
    if ( node )
       _new_wdt = true;
    else
        node = dt_find_compatible_node(NULL, NULL, "allwinner,sun4i-a10-wdt");

    if ( !node )
    {
        dprintk(XENLOG_ERR, "Cannot find matching watchdog node in DT\n");
        return NULL;
    }

    ret = dt_device_get_address(node, 0, &wdt_start, &wdt_len);
    if ( ret )
    {
        dprintk(XENLOG_ERR, "Cannot read watchdog register address\n");
        return NULL;
    }

    wdt = ioremap_nocache(wdt_start & PAGE_MASK, PAGE_SIZE);
    if ( !wdt )
    {
        dprintk(XENLOG_ERR, "Unable to map watchdog register!\n");
        return NULL;
    }

    if ( new_wdt )
        *new_wdt = _new_wdt;

    return wdt + (wdt_start & ~PAGE_MASK);
}

/* Enable watchdog to trigger a reset after 500 ms */
static void sunxi_old_wdt_reset(void __iomem *wdt)
{
    writel(SUNXI_WDT_MODE_EN | SUNXI_WDT_MODE_RST_EN,
           wdt + SUNXI_WDT_MODE_REG);
}

static void sunxi_new_wdt_reset(void __iomem *wdt)
{
    writel(SUNXI_WDT_CONFIG_SYSTEM_RESET, wdt + SUNXI_WDOG0_CFG_REG);
    writel(SUNXI_WDT_MODE_EN, wdt + SUNXI_WDOG0_MODE_REG);
}

static void sunxi_reset(void)
{
    void __iomem *wdt;
    bool is_new_wdt;

    wdt = sunxi_map_watchdog(&is_new_wdt);
    if ( !wdt )
        return;

    if ( is_new_wdt )
        sunxi_new_wdt_reset(wdt);
    else
        sunxi_old_wdt_reset(wdt);

    iounmap(wdt);

    for (;;)
        wfi();
}

static const char * const sunxi_v7_dt_compat[] __initconst =
{
    "allwinner,sun6i-a31",
    "allwinner,sun6i-a31s",
    "allwinner,sun7i-a20",
    "allwinner,sun8i-a23",
    "allwinner,sun8i-a33",
    "allwinner,sun8i-h2-plus",
    "allwinner,sun8i-h3",
    NULL
};

static const char * const sunxi_v8_dt_compat[] __initconst =
{
    "allwinner,sun50i-a64",
    "allwinner,sun50i-h5",
    "allwinner,sun50i-h6",
    NULL
};

static const struct dt_device_match sunxi_blacklist_dev[] __initconst =
{
    /*
     * The UARTs share a page which runs the risk of mapping the Xen console
     * UART to dom0, so don't map any of them.
     */
    DT_MATCH_COMPATIBLE("snps,dw-apb-uart"),
    { /* sentinel */ },
};

PLATFORM_START(sunxi_v7, "Allwinner ARMv7")
    .compatible = sunxi_v7_dt_compat,
    .blacklist_dev = sunxi_blacklist_dev,
    .reset = sunxi_reset,
PLATFORM_END

PLATFORM_START(sunxi_v8, "Allwinner ARMv8")
    .compatible = sunxi_v8_dt_compat,
    .blacklist_dev = sunxi_blacklist_dev,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
