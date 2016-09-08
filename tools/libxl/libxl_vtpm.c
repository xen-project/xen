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

static int libxl__device_vtpm_setdefault(libxl__gc *gc, libxl_device_vtpm *vtpm)
{
    int rc;
    if (libxl_uuid_is_nil(&vtpm->uuid)) {
        libxl_uuid_generate(&vtpm->uuid);
    }
    rc = libxl__resolve_domid(gc, vtpm->backend_domname, &vtpm->backend_domid);
    return rc;
}

static int libxl__device_from_vtpm(libxl__gc *gc, uint32_t domid,
                                   libxl_device_vtpm *vtpm,
                                   libxl__device *device)
{
   device->backend_devid   = vtpm->devid;
   device->backend_domid   = vtpm->backend_domid;
   device->backend_kind    = LIBXL__DEVICE_KIND_VTPM;
   device->devid           = vtpm->devid;
   device->domid           = domid;
   device->kind            = LIBXL__DEVICE_KIND_VTPM;

   return 0;
}

static void libxl__update_config_vtpm(libxl__gc *gc, libxl_device_vtpm *dst,
                                      libxl_device_vtpm *src)
{
    dst->devid = src->devid;
    libxl_uuid_copy(CTX, &dst->uuid, &src->uuid);
}

static void libxl__device_vtpm_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vtpm *vtpm,
                                   libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    flexarray_t *front;
    flexarray_t *back;
    libxl__device *device;
    int rc;
    xs_transaction_t t = XBT_NULL;
    libxl_domain_config d_config;
    libxl_device_vtpm vtpm_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_vtpm_init(&vtpm_saved);
    libxl_device_vtpm_copy(CTX, &vtpm_saved, vtpm);

    rc = libxl__device_vtpm_setdefault(gc, vtpm);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (vtpm->devid == -1) {
        if ((vtpm->devid = libxl__device_nextid(gc, domid, "vtpm")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    libxl__update_config_vtpm(gc, &vtpm_saved, vtpm);

    GCNEW(device);
    rc = libxl__device_from_vtpm(gc, domid, vtpm, device);
    if ( rc != 0 ) goto out;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "handle");
    flexarray_append(back, GCSPRINTF("%d", vtpm->devid));

    flexarray_append(back, "uuid");
    flexarray_append(back, GCSPRINTF(LIBXL_UUID_FMT, LIBXL_UUID_BYTES(vtpm->uuid)));
    flexarray_append(back, "resume");
    flexarray_append(back, "False");

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vtpm->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(front, "handle");
    flexarray_append(front, GCSPRINTF("%d", vtpm->devid));

    if (aodev->update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        DEVICE_ADD(vtpm, vtpms, domid, &vtpm_saved, COMPARE_DEVID, &d_config);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__device_exists(gc, t, device);
        if (rc < 0) goto out;
        if (rc == 1) {              /* already exists in xenstore */
            LOG(ERROR, "device already exists in xenstore");
            aodev->action = LIBXL__DEVICE_ACTION_ADD; /* for error message */
            rc = ERROR_DEVICE_EXISTS;
            goto out;
        }

        if (aodev->update_json) {
            rc = libxl__set_domain_configuration(gc, domid, &d_config);
            if (rc) goto out;
        }

        libxl__device_generic_add(gc, t, device,
                                  libxl__xs_kvs_of_flexarray(gc, back),
                                  libxl__xs_kvs_of_flexarray(gc, front),
                                  NULL);

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    aodev->dev = device;
    aodev->action = LIBXL__DEVICE_ACTION_ADD;
    libxl__wait_device_connection(egc, aodev);

    rc = 0;
out:
    libxl__xs_transaction_abort(gc, &t);
    if (lock) libxl__unlock_domain_userdata(lock);
    libxl_device_vtpm_dispose(&vtpm_saved);
    libxl_domain_config_dispose(&d_config);
    aodev->rc = rc;
    if(rc) aodev->callback(egc, aodev);
    return;
}

libxl_device_vtpm *libxl_device_vtpm_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);

    libxl_device_vtpm* vtpms = NULL;
    char *libxl_path;
    char** dir = NULL;
    unsigned int ndirs = 0;
    int rc;

    *num = 0;

    libxl_path = GCSPRINTF("%s/device/vtpm", libxl__xs_libxl_path(gc, domid));
    dir = libxl__xs_directory(gc, XBT_NULL, libxl_path, &ndirs);
    if (dir && ndirs) {
       vtpms = malloc(sizeof(*vtpms) * ndirs);
       libxl_device_vtpm* vtpm;
       libxl_device_vtpm* end = vtpms + ndirs;
       for(vtpm = vtpms; vtpm < end; ++vtpm, ++dir) {
          char* tmp;
          const char* be_path = libxl__xs_read(gc, XBT_NULL,
                GCSPRINTF("%s/%s/backend",
                   libxl_path, *dir));

          libxl_device_vtpm_init(vtpm);

          vtpm->devid = atoi(*dir);

          rc = libxl__backendpath_parse_domid(gc, be_path,
                                              &vtpm->backend_domid);
          if (rc) return NULL;

          tmp = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/uuid", libxl_path));
          if (tmp) {
              if(libxl_uuid_from_string(&(vtpm->uuid), tmp)) {
                  LOG(ERROR, "%s/uuid is a malformed uuid?? (%s) Probably a bug!!\n", be_path, tmp);
                  free(vtpms);
                  return NULL;
              }
          }
       }
    }
    *num = ndirs;

    GC_FREE;
    return vtpms;
}

int libxl_device_vtpm_getinfo(libxl_ctx *ctx,
                              uint32_t domid,
                              libxl_device_vtpm *vtpm,
                              libxl_vtpminfo *vtpminfo)
{
    GC_INIT(ctx);
    char *libxl_path, *dompath, *vtpmpath;
    char *val;
    int rc = 0;

    libxl_vtpminfo_init(vtpminfo);
    dompath = libxl__xs_get_dompath(gc, domid);
    vtpminfo->devid = vtpm->devid;

    vtpmpath = GCSPRINTF("%s/device/vtpm/%d", dompath, vtpminfo->devid);
    libxl_path = GCSPRINTF("%s/device/vtpm/%d",
                           libxl__xs_libxl_path(gc, domid), vtpminfo->devid);
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
       LOG(ERROR, "%s/uuid does not exist!", vtpminfo->backend);
       goto err;
    }
    if(libxl_uuid_from_string(&(vtpminfo->uuid), val)) {
       LOG(ERROR,
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
    libxl_device_vtpm *vtpms;
    int nb, i;
    int rc;

    vtpms = libxl_device_vtpm_list(ctx, domid, &nb);
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

    libxl_device_vtpm_list_free(vtpms, nb);
    return rc;
}

static int libxl_device_vtpm_compare(libxl_device_vtpm *d1,
                                     libxl_device_vtpm *d2)
{
    return COMPARE_DEVID(d1, d2);
}

int libxl_uuid_to_device_vtpm(libxl_ctx *ctx, uint32_t domid,
                            libxl_uuid* uuid, libxl_device_vtpm *vtpm)
{
    libxl_device_vtpm *vtpms;
    int nb, i;
    int rc;

    vtpms = libxl_device_vtpm_list(ctx, domid, &nb);
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

    libxl_device_vtpm_list_free(vtpms, nb);
    return rc;
}

void libxl_vtpminfo_list_free(libxl_vtpminfo* list, int nr)
{
   int i;
   for (i = 0; i < nr; i++)
      libxl_vtpminfo_dispose(&list[i]);
   free(list);
}

void libxl_device_vtpm_list_free(libxl_device_vtpm* list, int nr)
{
   int i;
   for (i = 0; i < nr; i++)
      libxl_device_vtpm_dispose(&list[i]);
   free(list);
}

static void libxl_device_vtpm_update_config(libxl__gc *gc, void *d, void *s)
{
    libxl__update_config_vtpm(gc, d, s);
}

LIBXL_DEFINE_DEVICE_ADD(vtpm)
static LIBXL_DEFINE_DEVICES_ADD(vtpm)
LIBXL_DEFINE_DEVICE_REMOVE(vtpm)

DEFINE_DEVICE_TYPE_STRUCT(vtpm,
    .update_config = libxl_device_vtpm_update_config
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

