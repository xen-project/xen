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

#include <string.h>

int libxl__blktap_enabled(libxl__gc *gc)
{
    const char *msg;
    return !tap_ctl_check(&msg);
}

char *libxl__blktap_devpath(libxl__gc *gc,
                            const char *disk,
                            libxl_disk_format format)
{
    const char *type;
    char *params, *devname = NULL;
    tap_list_t tap;
    int err;

    type = libxl__device_disk_string_of_format(format);
    err = tap_ctl_find(type, disk, &tap);
    if (err == 0) {
        devname = libxl__sprintf(gc, "/dev/xen/blktap-2/tapdev%d", tap.minor);
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


void libxl__device_destroy_tapdisk(libxl__gc *gc, char *be_path)
{
    char *path, *params, *type, *disk;
    int err;
    tap_list_t tap;

    path = libxl__sprintf(gc, "%s/tapdisk-params", be_path);
    if (!path) return;

    params = libxl__xs_read(gc, XBT_NULL, path);
    if (!params) return;

    type = params;
    disk = strchr(params, ':');
    if (!disk) return;

    *disk++ = '\0';

    err = tap_ctl_find(type, disk, &tap);
    if (err < 0) return;

    tap_ctl_destroy(tap.id, tap.minor);
}
