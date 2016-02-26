/*
 * xen/arch/arm/platforms/xilinx-zynqmp.c
 *
 * Xilinx ZynqMP setup
 *
 * Copyright (c) 2016 Xilinx Inc.
 * Written by Edgar E. Iglesias <edgar.iglesias@xilinx.com>
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

static const char * const zynqmp_dt_compat[] __initconst =
{
    "xlnx,zynqmp",
    NULL
};

static const struct dt_device_match zynqmp_blacklist_dev[] __initconst =
{
    /* Power management is not yet supported.  */
    DT_MATCH_COMPATIBLE("xlnx,zynqmp-pm"),
    { /* sentinel */ },
};

PLATFORM_START(xgene_storm, "Xilinx ZynqMP")
    .compatible = zynqmp_dt_compat,
    .blacklist_dev = zynqmp_blacklist_dev,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
