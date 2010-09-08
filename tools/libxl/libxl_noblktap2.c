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
#include "libxl_internal.h"

int libxl__blktap_enabled(libxl__gc *gc)
{
    return 0;
}

const char *libxl__blktap_devpath(libxl__gc *gc,
                                 const char *disk,
                                 libxl_disk_phystype phystype)
{
    return NULL;
}
