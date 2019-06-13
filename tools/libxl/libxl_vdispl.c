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

#include <xen/io/displif.h>

static int libxl__device_vdispl_setdefault(libxl__gc *gc, uint32_t domid,
                                           libxl_device_vdispl *vdispl,
                                           bool hotplug)
{
    return libxl__resolve_domid(gc, vdispl->backend_domname,
                                &vdispl->backend_domid);
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

static int libxl_device_vdispl_compare(const libxl_device_vdispl *d1,
                                       const libxl_device_vdispl *d2)
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

    flexarray_append_pair(ro_front, XENDISPL_FIELD_BE_ALLOC,
                          GCSPRINTF("%d", vdispl->be_alloc));

    for (i = 0; i < vdispl->num_connectors; i++) {
        flexarray_append_pair(ro_front, GCSPRINTF("%d/"XENDISPL_FIELD_RESOLUTION, i),
                              GCSPRINTF("%d"XENDISPL_RESOLUTION_SEPARATOR"%d", vdispl->connectors[i].width,
                                                 vdispl->connectors[i].height));
        flexarray_append_pair(ro_front, GCSPRINTF("%d/"XENDISPL_FIELD_UNIQUE_ID, i),
                              vdispl->connectors[i].unique_id);
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

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_UNIQUE_ID, path, i);
        info->connectors[i].unique_id = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        if (info->connectors[i].unique_id == NULL) { rc = ERROR_FAIL; goto out; }

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_RESOLUTION, path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        if (value == NULL) { rc = ERROR_FAIL; goto out; }

        rc = sscanf(value, "%u"XENDISPL_RESOLUTION_SEPARATOR"%u", &info->connectors[i].width,
                    &info->connectors[i].height);
        free(value);

        if (rc != 2) {
            rc = ERROR_FAIL; goto out;
        }

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_REQ_RING_REF, path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].req_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_REQ_CHANNEL, path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].req_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_EVT_RING_REF, path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].evt_rref = value ? strtoul(value, NULL, 10) : -1;
        free(value);

        value_path = GCSPRINTF("%s/%d/"XENDISPL_FIELD_EVT_CHANNEL, path, i);
        value = xs_read(ctx->xsh, XBT_NULL, value_path, NULL);
        info->connectors[i].evt_evtch = value ? strtoul(value, NULL, 10) : -1;
        free(value);
    }

    rc = 0;

out:
    return rc;
}

int libxl_device_vdispl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                const libxl_device_vdispl *vdispl,
                                libxl_vdisplinfo *info)
{
    GC_INIT(ctx);
    char *libxl_path, *devpath;
    char *val;
    int rc;

    libxl_vdisplinfo_init(info);
    info->devid = vdispl->devid;

    devpath = libxl__domain_device_frontend_path(gc, domid, info->devid,
                                                 LIBXL__DEVICE_KIND_VDISPL);
    libxl_path = libxl__domain_device_libxl_path(gc, domid, info->devid,
                                                 LIBXL__DEVICE_KIND_VDISPL);

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

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/"XENDISPL_FIELD_BE_ALLOC, devpath));
    info->be_alloc = val ? strtoul(val, NULL, 10) : 0;

    rc = libxl__device_vdispl_getconnectors(ctx, devpath, info);
    if (rc) goto out;

    rc = 0;

out:
     GC_FREE;
     return rc;
}

static LIBXL_DEFINE_DEVICE_FROM_TYPE(vdispl)
static LIBXL_DEFINE_UPDATE_DEVID(vdispl)
static LIBXL_DEFINE_DEVICES_ADD(vdispl)

LIBXL_DEFINE_DEVID_TO_DEVICE(vdispl)
LIBXL_DEFINE_DEVICE_ADD(vdispl)
LIBXL_DEFINE_DEVICE_REMOVE(vdispl)
LIBXL_DEFINE_DEVICE_LIST(vdispl)

DEFINE_DEVICE_TYPE_STRUCT(vdispl, VDISPL,
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
