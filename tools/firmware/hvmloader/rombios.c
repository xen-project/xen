/*
 * HVM ROMBIOS support.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
 * Copyright (c) 2011, Citrix Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include "config.h"

#include "../rombios/config.h"

#define ROM_INCLUDE_ROMBIOS
#include "roms.inc"

//BUILD_BUG_ON(sizeof(rombios) > (0x00100000U - ROMBIOS_PHYSICAL_ADDRESS));

struct bios_config rombios_config =  {
    .name = "ROMBIOS",

    .image = rombios,
    .image_size = sizeof(rombios),

    .bios_address = ROMBIOS_PHYSICAL_ADDRESS,

    .smbios_start = SMBIOS_PHYSICAL_ADDRESS,
    .smbios_end = SMBIOS_PHYSICAL_END,

    .optionrom_start = OPTIONROM_PHYSICAL_ADDRESS,
    .optionrom_end = OPTIONROM_PHYSICAL_END,

    .acpi_start = ACPI_PHYSICAL_ADDRESS,

};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
