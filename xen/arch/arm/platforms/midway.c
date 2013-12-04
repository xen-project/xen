/*
 * xen/arch/arm/platforms/midway.c
 *
 * Calxeda Midway specific settings
 *
 * Andre Przywara <andre.przywara@linaro.org>
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

#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/platforms/midway.h>
#include <asm/platform.h>
#include <asm/io.h>

static void midway_reset(void)
{
    void __iomem *pmu;

    BUILD_BUG_ON((MW_SREG_PWR_REQ & PAGE_MASK) !=
                 (MW_SREG_A15_PWR_CTRL & PAGE_MASK));

    pmu = ioremap_nocache(MW_SREG_PWR_REQ & PAGE_MASK, PAGE_SIZE);
    if ( !pmu )
    {
        dprintk(XENLOG_ERR, "Unable to map PMU\n");
        return;
    }

    writel(MW_PWR_HARD_RESET, pmu + (MW_SREG_PWR_REQ & ~PAGE_MASK));
    writel(1, pmu + (MW_SREG_A15_PWR_CTRL & ~PAGE_MASK));
    iounmap(pmu);
}

static const char * const midway_dt_compat[] __initconst =
{
    "calxeda,ecx-2000",
    NULL
};

PLATFORM_START(midway, "CALXEDA MIDWAY")
    .compatible = midway_dt_compat,
    .reset = midway_reset,

    .dom0_gnttab_start = 0xff800000,
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
