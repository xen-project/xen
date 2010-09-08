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

#include "tap-ctl.h"

int libxl__blktap_enabled(libxl_gc *gc)
{
    const char *msg;
    return !tap_ctl_check(&msg);
}

const char *libxl__blktap_devpath(libxl_gc *gc,
                                 const char *disk,
                                 libxl_disk_phystype phystype)
{
    const char *type;
    char *params, *devname = NULL;
    int minor, err;

    type = libxl__device_disk_string_of_phystype(phystype);
    minor = tap_ctl_find_minor(type, disk);
    if (minor >= 0) {
        devname = libxl__sprintf(gc, "/dev/xen/blktap-2/tapdev%d", minor);
        if (devname)
            return devname;
    }

    params = libxl__sprintf(gc, "%s:%s", type, disk);
    err = tap_ctl_create(params, &devname);
    if (!err) {
        libxl__ptr_add(gc, devname);
        return devname;
    }

    return NULL;
}
