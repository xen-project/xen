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

#include <asm/platform.h>

static const char *const brcm_bcm2838_dt_compat[] __initconst =
{
    "brcm,bcm2838",
    NULL
};

static const struct dt_device_match brcm_bcm2838_blacklist_dev[] __initconst =
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
    { /* sentinel */ },
};

PLATFORM_START(brcm_bcm2838, "Raspberry Pi 4")
    .compatible     = brcm_bcm2838_dt_compat,
    .blacklist_dev  = brcm_bcm2838_blacklist_dev,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
