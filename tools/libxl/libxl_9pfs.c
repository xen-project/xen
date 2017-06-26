/*
 * Copyright (C) 2017      Aporeto
 * Author Stefano Stabellini <stefano@aporeto.com>
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

#include "libxl_osdeps.h"

#include "libxl_internal.h"

int libxl__device_p9_setdefault(libxl__gc *gc, libxl_device_p9 *p9)
{
    int rc;

    rc = libxl__resolve_domid(gc, p9->backend_domname, &p9->backend_domid);
    return rc;
}

static int libxl__device_from_p9(libxl__gc *gc, uint32_t domid,
                                 libxl_device_p9 *p9,
                                 libxl__device *device)
{
   device->backend_devid   = p9->devid;
   device->backend_domid   = p9->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_9PFS;
   device->devid           = p9->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_9PFS;

   return 0;
}

static LIBXL_DEFINE_UPDATE_DEVID(p9, "9pfs")

int libxl__device_p9_add(libxl__gc *gc, uint32_t domid,
                         libxl_device_p9 *p9)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_p9_setdefault(gc, p9);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    rc = libxl__device_p9_update_devid(gc, domid, p9);
    if (rc) goto out;

    rc = libxl__device_from_p9(gc, domid, p9, &device);
    if (rc != 0) goto out;

    flexarray_append_pair(back, "frontend-id", libxl__sprintf(gc, "%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(front, "backend-id",
                          libxl__sprintf(gc, "%d", p9->backend_domid));
    flexarray_append_pair(front, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(front, "tag", p9->tag);
    flexarray_append_pair(back, "path", p9->path);
    flexarray_append_pair(back, "security_model", p9->security_model);

    libxl__device_generic_add(gc, XBT_NULL, &device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              NULL);
    rc = 0;
out:
    return rc;
}

LIBXL_DEFINE_DEVICE_REMOVE(p9)

