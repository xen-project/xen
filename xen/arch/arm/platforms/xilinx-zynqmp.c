/*
 * xen/arch/arm/platforms/xilinx-zynqmp.c
 *
 * Xilinx ZynqMP setup
 *
 * Copyright (c) 2015 Xilinx Inc.
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

PLATFORM_START(xgene_storm, "Xilinx ZynqMP")
    .compatible = zynqmp_dt_compat,
    .dom0_gnttab_start = 0xf0000000,
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
