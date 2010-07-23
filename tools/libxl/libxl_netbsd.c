/*
 * Copyright (C) 2010      Advanced Micro Devices
 * Author Christoph Egger <Christoph.Egger@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl.h"
#include "libxl_osdeps.h"

int libxl_blktap_enabled(struct libxl_ctx *ctx)
{
    return 0;
}

const char *libxl_blktap_devpath(struct libxl_ctx *ctx,
                                 const char *disk,
                                 libxl_disk_phystype phystype)
{
    return NULL;
}
