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

static int libxl__device_vkb_dm_needed(void *e, uint32_t domid)
{
    libxl_device_vkb *elem = e;

    return elem->backend_type == LIBXL_VKB_BACKEND_QEMU;
}

static int libxl__set_xenstore_vkb(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vkb *vkb,
                                   flexarray_t *back, flexarray_t *front,
                                   flexarray_t *ro_front)
{
    if (vkb->unique_id) {
        flexarray_append_pair(back, XENKBD_FIELD_UNIQUE_ID, vkb->unique_id);
    }

    if (vkb->feature_disable_keyboard) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_DSBL_KEYBRD,
                              GCSPRINTF("%u", vkb->feature_disable_keyboard));
    }

    if (vkb->feature_disable_pointer) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_DSBL_POINTER,
                              GCSPRINTF("%u", vkb->feature_disable_pointer));
    }

    if (vkb->feature_abs_pointer) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_ABS_POINTER,
                              GCSPRINTF("%u", vkb->feature_abs_pointer));
    }

    if (vkb->feature_raw_pointer) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_RAW_POINTER,
                              GCSPRINTF("%u", vkb->feature_raw_pointer));
    }

    if (vkb->feature_multi_touch) {
        flexarray_append_pair(back, XENKBD_FIELD_FEAT_MTOUCH,
                              GCSPRINTF("%u", vkb->feature_multi_touch));
        flexarray_append_pair(back, XENKBD_FIELD_MT_WIDTH,
                              GCSPRINTF("%u", vkb->multi_touch_width));
        flexarray_append_pair(back, XENKBD_FIELD_MT_HEIGHT,
                              GCSPRINTF("%u", vkb->multi_touch_height));
        flexarray_append_pair(back, XENKBD_FIELD_MT_NUM_CONTACTS,
                              GCSPRINTF("%u", vkb->multi_touch_num_contacts));
    }

    if (vkb->width) {
        flexarray_append_pair(back, XENKBD_FIELD_WIDTH,
                              GCSPRINTF("%u", vkb->width));
    }

    if (vkb->height) {
        flexarray_append_pair(back, XENKBD_FIELD_HEIGHT,
                              GCSPRINTF("%u", vkb->height));
    }

    return 0;
}

static int libxl__vkb_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                    libxl_devid devid,
                                    libxl_device_vkb *vkb)
{
    const char *be_path, *fe_path, *tmp;
    libxl__device dev;
    int rc;

    vkb->devid = devid;

    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) goto out;

    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/frontend", libxl_path),
                                  &fe_path);
    if (rc) goto out;

    rc = libxl__backendpath_parse_domid(gc, be_path, &vkb->backend_domid);
    if (rc) goto out;

    rc = libxl__parse_backend_path(gc, be_path, &dev);
    if (rc) goto out;

    vkb->backend_type = dev.backend_kind == LIBXL__DEVICE_KIND_VINPUT ?
                                            LIBXL_VKB_BACKEND_LINUX : LIBXL_VKB_BACKEND_QEMU;

    vkb->unique_id = xs_read(CTX->xsh, XBT_NULL, GCSPRINTF("%s/"XENKBD_FIELD_UNIQUE_ID, be_path), NULL);

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_DSBL_KEYBRD,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->feature_disable_keyboard = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_DSBL_POINTER,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->feature_disable_pointer = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_ABS_POINTER,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->feature_abs_pointer = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_RAW_POINTER,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->feature_raw_pointer = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_FEAT_MTOUCH,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->feature_multi_touch = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_WIDTH,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->multi_touch_width = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_HEIGHT,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->multi_touch_height = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_MT_NUM_CONTACTS,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->multi_touch_num_contacts = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_WIDTH,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->width = strtoul(tmp, NULL, 0);
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/"XENKBD_FIELD_HEIGHT,
                                be_path), &tmp);
    if (rc) goto out;

    if (tmp) {
        vkb->height = strtoul(tmp, NULL, 0);
    }

    rc = 0;

out:

    return rc;
}

static int libxl__device_from_vkb(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vkb *type, libxl__device *device)
{
    device->backend_devid   = type->devid;
    device->backend_domid   = type->backend_domid;
    device->backend_kind    = type->backend_type == LIBXL_VKB_BACKEND_LINUX ?
                              LIBXL__DEVICE_KIND_VINPUT : LIBXL__DEVICE_KIND_VKBD;
    device->devid           = type->devid;
    device->domid           = domid;
    device->kind            = LIBXL__DEVICE_KIND_VKBD;

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

int libxl_devid_to_device_vkb(libxl_ctx *ctx, uint32_t domid,
                              int devid, libxl_device_vkb *vkb)
{
    GC_INIT(ctx);

    libxl_device_vkb *vkbs = NULL;
    int n, i;
    int rc;

    libxl_device_vkb_init(vkb);

    vkbs = libxl__device_list(gc, &libxl__vkb_devtype, domid, &n);

    if (!vkbs) { rc = ERROR_NOTFOUND; goto out; }

    for (i = 0; i < n; ++i) {
        if (devid == vkbs[i].devid) {
            libxl_device_vkb_copy(ctx, vkb, &vkbs[i]);
            rc = 0;
            goto out;
        }
    }

    rc = ERROR_NOTFOUND;

out:

    if (vkbs)
        libxl__device_list_free(&libxl__vkb_devtype, vkbs, n);

    GC_FREE;
    return rc;
}

int libxl_device_vkb_getinfo(libxl_ctx *ctx, uint32_t domid,
                             const libxl_device_vkb *vkb,
                             libxl_vkbinfo *info)
{
    GC_INIT(ctx);
    char *libxl_path, *dompath, *devpath;
    char *val;
    int rc;

    libxl_vkbinfo_init(info);
    dompath = libxl__xs_get_dompath(gc, domid);
    info->devid = vkb->devid;

    devpath = libxl__domain_device_frontend_path(gc, domid, info->devid,
                                                 LIBXL__DEVICE_KIND_VKBD);
    libxl_path = libxl__domain_device_libxl_path(gc, domid, info->devid,
                                                 LIBXL__DEVICE_KIND_VKBD);

    info->backend = xs_read(ctx->xsh, XBT_NULL,
                            GCSPRINTF("%s/backend", libxl_path),
                            NULL);
    if (!info->backend) { rc = ERROR_FAIL; goto out; }

    rc = libxl__backendpath_parse_domid(gc, info->backend, &info->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", devpath));
    info->state = val ? strtoul(val, NULL, 10) : -1;

    info->frontend = xs_read(ctx->xsh, XBT_NULL,
                             GCSPRINTF("%s/frontend", libxl_path),
                             NULL);
    info->frontend_id = domid;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/"XENKBD_FIELD_EVT_CHANNEL, devpath));
    info->evtch = val ? strtoul(val, NULL, 10) : -1;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/"XENKBD_FIELD_RING_GREF, devpath));
    info->rref = val ? strtoul(val, NULL, 10) : -1;

    rc = 0;

out:
     GC_FREE;
     return rc;
}

static LIBXL_DEFINE_UPDATE_DEVID(vkb)

#define libxl__add_vkbs NULL
#define libxl_device_vkb_compare NULL

LIBXL_DEFINE_DEVICE_LIST(vkb)
LIBXL_DEFINE_DEVICE_REMOVE(vkb)

DEFINE_DEVICE_TYPE_STRUCT(vkb, VKBD,
    .skip_attach = 1,
    .dm_needed = libxl__device_vkb_dm_needed,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vkb,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__vkb_from_xenstore
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
