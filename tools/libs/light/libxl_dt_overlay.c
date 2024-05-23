/*
 * Copyright (C) 2021 Xilinx Inc.
 * Author Vikram Garhwal <fnu.vikram@xilinx.com>
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

#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxl_internal.h"
#include <libfdt.h>
#include <xenctrl.h>

static int check_overlay_fdt(libxl__gc *gc, void *fdt, size_t size)
{
    int r;

    if (fdt_magic(fdt) != FDT_MAGIC) {
        LOG(ERROR, "Overlay FDT is not a valid Flat Device Tree");
        return ERROR_FAIL;
    }

    r = fdt_check_header(fdt);
    if (r) {
        LOG(ERROR, "Failed to check the overlay FDT (%d)", r);
        return ERROR_FAIL;
    }

    if (fdt_totalsize(fdt) > size) {
        LOG(ERROR, "Overlay FDT totalsize is too big");
        return ERROR_FAIL;
    }

    return 0;
}

int libxl_dt_overlay(libxl_ctx *ctx, void *overlay_dt, uint32_t overlay_dt_size,
                     uint8_t overlay_op)
{
    int rc;
    int r;
    GC_INIT(ctx);

    if (check_overlay_fdt(gc, overlay_dt, overlay_dt_size)) {
        LOG(ERROR, "Overlay DTB check failed");
        rc = ERROR_FAIL;
        goto out;
    } else {
        LOG(DEBUG, "Overlay DTB check passed");
        rc = 0;
    }

    r = xc_dt_overlay(ctx->xch, overlay_dt, overlay_dt_size, overlay_op);

    if (r) {
        LOG(ERROR, "%s: Adding/Removing overlay dtb failed.", __func__);
        rc = ERROR_FAIL;
    }

out:
    GC_FREE;
    return rc;
}

int libxl_dt_overlay_domain(libxl_ctx *ctx, uint32_t domain_id,
                            void *overlay_dt, uint32_t overlay_dt_size,
                            uint8_t overlay_op)
{
    int rc;
    int r;
    GC_INIT(ctx);

    if (check_overlay_fdt(gc, overlay_dt, overlay_dt_size)) {
        LOG(ERROR, "Overlay DTB check failed");
        rc = ERROR_FAIL;
        goto out;
    } else {
        LOG(DEBUG, "Overlay DTB check passed");
        rc = 0;
    }

    r = xc_dt_overlay_domain(ctx->xch, overlay_dt, overlay_dt_size, overlay_op,
                             domain_id);
    if (r) {
        LOG(ERROR, "%s: Attaching/Detaching overlay dtb failed.", __func__);
        rc = ERROR_FAIL;
    }

out:
    GC_FREE;
    return rc;
}
