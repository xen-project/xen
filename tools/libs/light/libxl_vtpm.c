/*
 * Copyright (C) 2016      SUSE Linux GmbH
 * Author Juergen Gross <jgross@suse.com>
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

static int libxl__device_vtpm_setdefault(libxl__gc *gc, uint32_t domid,
                                         libxl_device_vtpm *vtpm, bool hotplug)
{
    int rc;
    if (libxl_uuid_is_nil(&vtpm->uuid)) {
        libxl_uuid_generate(&vtpm->uuid);
    }
    rc = libxl__resolve_domid(gc, vtpm->backend_domname, &vtpm->backend_domid);
    return rc;
}

static void libxl__update_config_vtpm(libxl__gc *gc, libxl_device_vtpm *dst,
                                      libxl_device_vtpm *src)
{
    dst->devid = src->devid;
    libxl_uuid_copy(CTX, &dst->uuid, &src->uuid);
}

static int libxl__set_xenstore_vtpm(libxl__gc *gc, uint32_t domid,
                                    libxl_device_vtpm *vtpm,
                                    flexarray_t *back, flexarray_t *front,
                                    flexarray_t *ro_front)
{
    flexarray_append_pair(back, "handle", GCSPRINTF("%d", vtpm->devid));
    flexarray_append_pair(back, "uuid",
                          GCSPRINTF(LIBXL_UUID_FMT,
                                    LIBXL_UUID_BYTES(vtpm->uuid)));
    flexarray_append_pair(back, "resume", "False");

    flexarray_append_pair(front, "handle", GCSPRINTF("%d", vtpm->devid));

    return 0;
}

static void libxl__device_vtpm_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vtpm *vtpm,
                                   libxl__ao_device *aodev)
{
    libxl__device_add_async(egc, domid, &libxl__vtpm_devtype, vtpm, aodev);
}

static int libxl__vtpm_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                     libxl_devid devid,
                                     libxl_device_vtpm *vtpm)
{
    int rc;
    const char *be_path;
    char *uuid;

    vtpm->devid = devid;

    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/backend", libxl_path),
                                  &be_path);
    if (rc) return rc;

    rc = libxl__backendpath_parse_domid(gc, be_path, &vtpm->backend_domid);
    if (rc) return rc;

    uuid = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/uuid", be_path));
    if (uuid) {
        if(libxl_uuid_from_string(&(vtpm->uuid), uuid)) {
            LOGD(ERROR, vtpm->backend_domid, "%s/uuid is a malformed uuid?? "
                               "(%s) Probably a bug!!\n", be_path, uuid);
            return ERROR_FAIL;
        }
    }

    return 0;
}

int libxl_device_vtpm_getinfo(libxl_ctx *ctx,
                              uint32_t domid,
                              const libxl_device_vtpm *vtpm,
                              libxl_vtpminfo *vtpminfo)
{
    GC_INIT(ctx);
    char *libxl_path, *vtpmpath;
    char *val;
    int rc = 0;

    libxl_vtpminfo_init(vtpminfo);
    vtpminfo->devid = vtpm->devid;

    vtpmpath = libxl__domain_device_frontend_path(gc, domid, vtpminfo->devid,
                                                  LIBXL__DEVICE_KIND_VTPM);
    libxl_path = libxl__domain_device_libxl_path(gc, domid, vtpminfo->devid,
                                                 LIBXL__DEVICE_KIND_VTPM);
    vtpminfo->backend = xs_read(ctx->xsh, XBT_NULL,
          GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!vtpminfo->backend) {
        goto err;
    }

    rc = libxl__backendpath_parse_domid(gc, vtpminfo->backend,
                                        &vtpminfo->backend_id);
    if (rc) goto exit;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/state", vtpmpath));
    vtpminfo->state = val ? strtoul(val, NULL, 10) : -1;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/event-channel", vtpmpath));
    vtpminfo->evtch = val ? strtoul(val, NULL, 10) : -1;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/ring-ref", vtpmpath));
    vtpminfo->rref = val ? strtoul(val, NULL, 10) : -1;

    vtpminfo->frontend = xs_read(ctx->xsh, XBT_NULL,
          GCSPRINTF("%s/frontend", libxl_path), NULL);
    vtpminfo->frontend_id = domid;

    val = libxl__xs_read(gc, XBT_NULL,
          GCSPRINTF("%s/uuid", libxl_path));
    if(val == NULL) {
       LOGD(ERROR, domid, "%s/uuid does not exist!", vtpminfo->backend);
       goto err;
    }
    if(libxl_uuid_from_string(&(vtpminfo->uuid), val)) {
       LOGD(ERROR, domid,
             "%s/uuid is a malformed uuid?? (%s) Probably a bug!\n",
             vtpminfo->backend, val);
       goto err;
    }

    goto exit;
err:
    rc = ERROR_FAIL;
exit:
    GC_FREE;
    return rc;
}

int libxl_devid_to_device_vtpm(libxl_ctx *ctx,
                               uint32_t domid,
                               int devid,
                               libxl_device_vtpm *vtpm)
{
    GC_INIT(ctx);
    libxl_device_vtpm *vtpms;
    int nb, i;
    int rc;

    vtpms = libxl__device_list(gc, &libxl__vtpm_devtype, domid, &nb);
    if (!vtpms)
        return ERROR_FAIL;

    libxl_device_vtpm_init(vtpm);
    rc = 1;
    for (i = 0; i < nb; ++i) {
        if(devid == vtpms[i].devid) {
            vtpm->backend_domid = vtpms[i].backend_domid;
            vtpm->devid = vtpms[i].devid;
            libxl_uuid_copy(ctx, &vtpm->uuid, &vtpms[i].uuid);
            rc = 0;
            break;
        }
    }

    libxl__device_list_free(&libxl__vtpm_devtype, vtpms, nb);
    GC_FREE;
    return rc;
}

static int libxl_device_vtpm_compare(const libxl_device_vtpm *d1,
                                     const libxl_device_vtpm *d2)
{
    return COMPARE_DEVID(d1, d2);
}

int libxl_uuid_to_device_vtpm(libxl_ctx *ctx, uint32_t domid,
                            libxl_uuid* uuid, libxl_device_vtpm *vtpm)
{
    GC_INIT(ctx);
    libxl_device_vtpm *vtpms;
    int nb, i;
    int rc;

    vtpms = libxl__device_list(gc, &libxl__vtpm_devtype, domid, &nb);
    if (!vtpms)
        return ERROR_FAIL;

    memset(vtpm, 0, sizeof (libxl_device_vtpm));
    rc = 1;
    for (i = 0; i < nb; ++i) {
        if(!libxl_uuid_compare(uuid, &vtpms[i].uuid)) {
            vtpm->backend_domid = vtpms[i].backend_domid;
            vtpm->devid = vtpms[i].devid;
            libxl_uuid_copy(ctx, &vtpm->uuid, &vtpms[i].uuid);
            rc = 0;
            break;
        }
    }

    libxl__device_list_free(&libxl__vtpm_devtype, vtpms, nb);
    GC_FREE;
    return rc;
}

static void libxl_device_vtpm_update_config(libxl__gc *gc, void *d, void *s)
{
    libxl__update_config_vtpm(gc, d, s);
}

static LIBXL_DEFINE_UPDATE_DEVID(vtpm)
static LIBXL_DEFINE_DEVICE_FROM_TYPE(vtpm)
static LIBXL_DEFINE_DEVICES_ADD(vtpm)

LIBXL_DEFINE_DEVICE_ADD(vtpm)
LIBXL_DEFINE_DEVICE_REMOVE(vtpm)
LIBXL_DEFINE_DEVICE_LIST(vtpm)

DEFINE_DEVICE_TYPE_STRUCT(vtpm, VTPM,
    .update_config = libxl_device_vtpm_update_config,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__vtpm_from_xenstore,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_vtpm,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

