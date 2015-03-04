/*
 * xen/arch/arm/platforms/thunderx.c
 *
 * Cavium Thunder specific settings
 *
 * Vijaya Kumar K <Vijaya.Kumar@caviumnetworks.com>
 * Copyright (c) 2015 Cavium Inc.
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

static const char * const thunderx_dt_compat[] __initconst =
{
    "cavium,thunder-88xx",
    NULL
};

PLATFORM_START(thunderx, "THUNDERX")
    .compatible = thunderx_dt_compat,
    .dom0_gnttab_start = 0x40000000000,
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
