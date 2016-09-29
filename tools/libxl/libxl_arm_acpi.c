/*
 * ARM DomU ACPI generation
 *
 * Copyright (C) 2016      Linaro Ltd.
 *
 * Author: Shannon Zhao <shannon.zhao@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_arm.h"

#include <stdint.h>

/* Below typedefs are useful for the headers under acpi/ */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#include <acpi/acconfig.h>
#include <acpi/actbl.h>

int libxl__prepare_acpi(libxl__gc *gc, libxl_domain_build_info *info,
                        struct xc_dom_image *dom)
{
    const libxl_version_info *vers;
    int rc = 0;

    vers = libxl_get_version_info(CTX);
    if (vers == NULL) {
        rc = ERROR_FAIL;
        goto out;
    }

    LOG(DEBUG, "constructing ACPI tables for Xen version %d.%d guest",
        vers->xen_version_major, vers->xen_version_minor);

    dom->acpi_modules[0].data = NULL;
    dom->acpi_modules[0].length = 0;
    dom->acpi_modules[0].guest_addr_out = GUEST_ACPI_BASE;

out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
