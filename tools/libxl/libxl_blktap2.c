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

#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxl_internal.h"

#include "tap-ctl.h"

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
        devname = GCSPRINTF("/dev/xen/blktap-2/tapdev%d", tap.minor);
        if (devname)
            return devname;
    }

    params = GCSPRINTF("%s:%s", type, disk);
    err = tap_ctl_create(params, &devname);
    if (!err) {
        libxl__ptr_add(gc, devname);
        return devname;
    }

    free(devname);
    return NULL;
}


int libxl__device_destroy_tapdisk(libxl__gc *gc, const char *params)
{
    char *type, *disk;
    int err;
    tap_list_t tap;

    type = libxl__strdup(gc, params);

    disk = strchr(type, ':');
    if (!disk) {
        LOG(ERROR, "Unable to parse params %s", params);
        return ERROR_INVAL;
    }

    *disk++ = '\0';

    err = tap_ctl_find(type, disk, &tap);
    if (err < 0) {
        /* returns -errno */
        LOGEV(ERROR, -err, "Unable to find type %s disk %s", type, disk);
        return ERROR_FAIL;
    }

    err = tap_ctl_destroy(tap.id, tap.minor);
    if (err < 0) {
        LOGEV(ERROR, -err, "Failed to destroy tap device id %d minor %d",
              tap.id, tap.minor);
        return ERROR_FAIL;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
