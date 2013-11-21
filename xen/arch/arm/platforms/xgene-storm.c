/*
 * xen/arch/arm/platforms/xgene-storm.c
 *
 * Applied Micro's X-Gene specific settings
 *
 * Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
 * Anup Patel <apatel@apm.com>
 * Copyright (c) 2013 Applied Micro.
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

#include <xen/config.h>
#include <asm/platform.h>

static uint32_t xgene_storm_quirks(void)
{
    return PLATFORM_QUIRK_DOM0_MAPPING_11|PLATFORM_QUIRK_GIC_64K_STRIDE;
}


static const char * const xgene_storm_dt_compat[] __initconst =
{
    "apm,xgene-storm",
    NULL
};

PLATFORM_START(xgene_storm, "APM X-GENE STORM")
    .compatible = xgene_storm_dt_compat,
    .quirks = xgene_storm_quirks,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
