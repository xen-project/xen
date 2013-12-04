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

#include <asm/platform.h>

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

    .dom0_gnttab_start = 0x01d00000,
    .dom0_gnttab_size = 0x20000,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
