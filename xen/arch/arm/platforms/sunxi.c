/*
 * xen/arch/arm/platforms/sunxi.c
 *
 * SUNXI (AllWinner A20/A31) specific settings
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
#define SUNXI_WDT_BASE            0x01c20c90
#define SUNXI_WDT_MODE            0x04
#define SUNXI_WDT_MODEADDR        (SUNXI_WDT_BASE + SUNXI_WDT_MODE)
#define SUNXI_WDT_MODE_EN         (1 << 0)
#define SUNXI_WDT_MODE_RST_EN     (1 << 1)


static void sunxi_reset(void)
{
    void __iomem *wdt;

    wdt = ioremap_nocache(SUNXI_WDT_MODEADDR & PAGE_MASK, PAGE_SIZE);
    if ( !wdt )
    {
        dprintk(XENLOG_ERR, "Unable to map watchdog register!\n");
        return;
    }

    /* Enable watchdog to trigger a reset after 500 ms: */
    writel(SUNXI_WDT_MODE_EN | SUNXI_WDT_MODE_RST_EN,
      wdt + (SUNXI_WDT_MODEADDR & ~PAGE_MASK));
    iounmap(wdt);

    for (;;)
        wfi();
}

static const char * const sunxi_dt_compat[] __initconst =
{
    "allwinner,sun7i-a20",
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

PLATFORM_START(sunxi, "Allwinner A20")
    .compatible = sunxi_dt_compat,
    .blacklist_dev = sunxi_blacklist_dev,
    .reset = sunxi_reset,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
