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

static int libxl__device_vdispl_setdefault(libxl__gc *gc, uint32_t domid,
                                           libxl_device_vdispl *vdispl,
                                           bool hotplug)
{
    return libxl__resolve_domid(gc, vdispl->backend_domname,
                                &vdispl->backend_domid);
}

static int libxl__device_from_vdispl(libxl__gc *gc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__device *device)
{
   device->backend_devid   = vdispl->devid;
   device->backend_domid   = vdispl->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_VDISPL;
   device->devid           = vdispl->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_VDISPL;

   return 0;
}

static int libxl__vdispl_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                       libxl_devid devid,
                                       libxl_device_vdispl *vdispl)
{
    const char *be_path;
    int rc;

    vdispl->devid = devid;
    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) return rc;

    return libxl__backendpath_parse_domid(gc, be_path, &vdispl->backend_domid);
}

static void libxl__update_config_vdispl(libxl__gc *gc,
                                        libxl_device_vdispl *dst,
                                        libxl_device_vdispl *src)
{
    dst->devid = src->devid;
    dst->be_alloc = src->be_alloc;
}

static int libxl_device_vdispl_compare(libxl_device_vdispl *d1,
                                       libxl_device_vdispl *d2)
{
    return COMPARE_DEVID(d1, d2);
}

static void libxl__device_vdispl_add(libxl__egc *egc, uint32_t domid,
                                     libxl_device_vdispl *vdispl,
                                     libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vdispl_devtype, vdispl, aodev);
}

static int libxl__set_xenstore_vdispl(libxl__gc *gc, uint32_t domid,
                                      libxl_device_vdispl *vdispl,
                                      flexarray_t *back, flexarray_t *front,
                                      flexarray_t *ro_front)
{
    int i;

    flexarray_append_pair(ro_front, "be-alloc",
                          GCSPRINTF("%d", vdispl->be_alloc));

    for (i = 0; i < vdispl->num_connectors; i++) {
        flexarray_append_pair(ro_front, GCSPRINTF("%d/resolution", i),
                              GCSPRINTF("%dx%d", vdispl->connectors[i].width,
                                                 vdispl->connectors[i].height));
        flexarray_append_pair(ro_front, GCSPRINTF("%d/id", i),
                              vdispl->connectors[i].id);
    }

    return 0;
}

static int libxl__device_vdispl_getconnectors(libxl_ctx *ctx,
                                              const char *path,
                                              libxl_vdisplinfo *info)
{
    GC_INIT(ctx);
    char *connector = NULL;
    char *connector_path;
    int i, rc;

    info->num_connectors = 0;

    connector_path = GCSPRINTF("%s/%d", path, info->num_connectors);

    while ((connector = xs_read(ctx->xsh, XBT_NULL, connector_path, NULL)) !=
           NULL) {
        free(connector);
        connector_path = GCSPRINTF("%s/%d", path, ++info->num_connectors);
    }

    info->connectors = libxl__calloc(NOGC, info->num_connectors,
                                     sizeof(*info->connectors));

    for (i = 0; i < info->num_connectors; i++) {
        char *value;
        char *value_path;

        value_path = GCSPRINTF("%s/%d/id", path, i);
        info->connectors[i].id = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        if (info->connectors[i].id == NULL) { rc = ERROR_FAIL; goto out; }

        value_path = GCSPRINTF("%s/%d/resolution", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        if (value == NULL) { rc = ERROR_FAIL; goto out; }

        rc = sscanf(value, "%ux%u", &info->connectors[i].width,
                    &info->connectors[i].height);
        free(value);

        if (rc != 2) {
            rc = ERROR_FAIL; goto out;
        }

        value_path = GCSPRINTF("%s/%d/req-ring-ref", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].req_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/req-event-channel", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].req_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/evt-ring-ref", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].evt_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/evt-event-channel", path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].evt_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);
    }

    rc = 0;

out:
    return rc;
}

int libxl_device_vdispl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                libxl_device_vdispl *vdispl,
                                libxl_vdisplinfo *info)
{
    GC_INIT(ctx);
    char *libxl_path, *dompath, *devpath;
    char *val;
    int rc;

    libxl_vdisplinfo_init(info);
    dompath = libxl__xs_get_dompath(gc, domid);
    info->devid = vdispl->devid;

    devpath = GCSPRINTF("%s/device/vdispl/%d", dompath, info->devid);
    libxl_path = GCSPRINTF("%s/device/vdispl/%d",
                           libxl__xs_libxl_path(gc, domid),
                           info->devid);
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

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/be-alloc", devpath));
    info->be_alloc = val ? strtoul(val, NULL, 10) : 0;

    rc = libxl__device_vdispl_getconnectors(ctx, devpath, info);
    if (rc) goto out;

    rc = 0;

out:
     GC_FREE;
     return rc;
}

int libxl_devid_to_device_vdispl(libxl_ctx *ctx, uint32_t domid,
                                 int devid, libxl_device_vdispl *vdispl)
{
    GC_INIT(ctx);

    libxl_device_vdispl *vdispls = NULL;
    int n, i;
    int rc;

    libxl_device_vdispl_init(vdispl);

    vdispls = libxl__device_list(gc, &libxl__vdispl_devtype, domid, &n);

    if (!vdispls) { rc = ERROR_NOTFOUND; goto out; }

    for (i = 0; i < n; ++i) {
        if (devid == vdispls[i].devid) {
            libxl_device_vdispl_copy(ctx, vdispl, &vdispls[i]);
            rc = 0;
            goto out;
        }
    }

    rc = ERROR_NOTFOUND;

out:

    if (vdispls)
        libxl__device_list_free(&libxl__vdispl_devtype, vdispls, n);

    GC_FREE;
    return rc;
}

LIBXL_DEFINE_DEVICE_ADD(vdispl)
static LIBXL_DEFINE_DEVICES_ADD(vdispl)
LIBXL_DEFINE_DEVICE_REMOVE(vdispl)
static LIBXL_DEFINE_UPDATE_DEVID(vdispl, "vdispl")
LIBXL_DEFINE_DEVICE_LIST(vdispl)

DEFINE_DEVICE_TYPE_STRUCT(vdispl,
    .update_config = (device_update_config_fn_t)libxl__update_config_vdispl,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__vdispl_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vdispl
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
