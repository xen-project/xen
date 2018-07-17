/*
 * Copyright (C) 2016 EPAM Systems Inc.
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

#include "libxl_internal.h"

#include <xen/io/kbdif.h>

static int libxl__device_vkb_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_vkb *vkb, bool hotplug)
{
    if (vkb->backend_type == LIBXL_VKB_BACKEND_UNKNOWN) {
        vkb->backend_type = LIBXL_VKB_BACKEND_QEMU;
    }

    return libxl__resolve_domid(gc, vkb->backend_domname, &vkb->backend_domid);
}

static int libxl__device_vkb_dm_needed(libxl_device_vkb *vkb, uint32_t domid)
{
    return vkb->backend_type == LIBXL_VKB_BACKEND_QEMU;
}

static int libxl__set_xenstore_vkb(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vkb *vkb,
                                   flexarray_t *back, flexarray_t *front,
                                   flexarray_t *ro_front)
{
    flexarray_append_pair(back, "backend-type",
                          (char *)libxl_vkb_backend_to_string(vkb->backend_type));

    if (vkb->unique_id) {
        flexarray_append_pair(back, XENKBD_FIELD_UNIQUE_ID, vkb->unique_id);
    }

    return 0;
}

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_add(gc, domid, &libxl__vkb_devtype, vkb);
    if (rc) {
        LOGD(ERROR, domid, "Unable to add vkb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

static LIBXL_DEFINE_DEVICE_FROM_TYPE(vkb)
static LIBXL_DEFINE_UPDATE_DEVID(vkb)

#define libxl__add_vkbs NULL
#define libxl_device_vkb_list NULL
#define libxl_device_vkb_compare NULL

LIBXL_DEFINE_DEVICE_REMOVE(vkb)

DEFINE_DEVICE_TYPE_STRUCT(vkb, VKBD,
    .skip_attach = 1,
    .dm_needed = (device_dm_needed_fn_t)libxl__device_vkb_dm_needed,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vkb
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
