/*
 * xen/arch/arm/platforms/thunderx.c
 *
 * Cavium Thunder-X specific settings
 *
 * Copyright (c) 2018 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/platform.h>

static const char * const thunderx_dt_compat[] __initconst =
{
    "cavium,thunder-88xx",
    NULL
};

static const struct dt_device_match thunderx_blacklist_dev[] __initconst =
{
    /* Cavium has its own SMMU which is not yet supported. */
    DT_MATCH_COMPATIBLE("cavium,smmu-v2"),
    { /* sentinel */ },
};

PLATFORM_START(thunderx, "THUNDERX")
    .compatible = thunderx_dt_compat,
    .blacklist_dev = thunderx_blacklist_dev,
PLATFORM_END
