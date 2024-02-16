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

static int libxl__device_p9_setdefault(libxl__gc *gc, uint32_t domid,
                                       libxl_device_p9 *p9, bool hotplug)
{
    if (p9->type == LIBXL_P9_TYPE_UNKNOWN) {
        p9->type = LIBXL_P9_TYPE_QEMU;
    }
    if (p9->type == LIBXL_P9_TYPE_QEMU &&
        (p9->max_files || p9->max_open_files || p9->max_space ||
         p9->auto_delete)) {
        LOGD(ERROR, domid, "Illegal 9pfs parameter combination");
        return ERROR_INVAL;
    }
    if (p9->type == LIBXL_P9_TYPE_XEN_9PFSD && !p9->tag) {
        p9->tag = libxl__strdup(NOGC, "Xen");
    }

    if (!p9->path || !p9->security_model || !p9->tag) {
        LOGD(ERROR, domid, "9pfs spec missing required field!");
        return ERROR_INVAL;
    }

    return libxl__resolve_domid(gc, p9->backend_domname, &p9->backend_domid);
}

static int libxl__set_xenstore_p9(libxl__gc *gc, uint32_t domid,
                                  libxl_device_p9 *p9,
                                  flexarray_t *back, flexarray_t *front,
                                  flexarray_t *ro_front)
{
    flexarray_append_pair(back, "path", p9->path);
    flexarray_append_pair(back, "security_model", p9->security_model);

    flexarray_append_pair(front, "tag", p9->tag);

    if (p9->type == LIBXL_P9_TYPE_XEN_9PFSD) {
        flexarray_append_pair(back, "max-space",
                              GCSPRINTF("%u", p9->max_space));
        flexarray_append_pair(back, "max-files",
                              GCSPRINTF("%u", p9->max_files));
        flexarray_append_pair(back, "max-open-files",
                              GCSPRINTF("%u", p9->max_open_files));
        flexarray_append_pair(back, "auto-delete",
                              p9->auto_delete ? "1" : "0");
    }

    return 0;
}

static int libxl__device_from_p9(libxl__gc *gc, uint32_t domid,
                                 libxl_device_p9 *type, libxl__device *device)
{
    device->backend_devid   = type->devid;
    device->backend_domid   = type->backend_domid;
    device->backend_kind    = type->type == LIBXL_P9_TYPE_QEMU
                              ? LIBXL__DEVICE_KIND_9PFS
                              : LIBXL__DEVICE_KIND_XEN_9PFS;
    device->devid           = type->devid;
    device->domid           = domid;
    device->kind            = LIBXL__DEVICE_KIND_9PFS;

    return 0;
}

static int libxl__device_p9_dm_needed(void *e, unsigned domid)
{
    libxl_device_p9 *elem = e;

    return elem->type == LIBXL_P9_TYPE_QEMU && elem->backend_domid == domid;
}

typedef struct libxl__aop9_state libxl__aop9_state;

struct libxl__aop9_state {
    libxl__spawn_state spawn;
    libxl__ao_device *aodev;
    libxl_device_p9 p9;
    uint32_t domid;
};

static void xen9pfsd_confirm(libxl__egc *egc, libxl__spawn_state *spawn,
                             const char *xsdata);
static void xen9pfsd_failed(libxl__egc *egc, libxl__spawn_state *spawn, int rc);
static void xen9pfsd_detached(libxl__egc *egc, libxl__spawn_state *spawn);
static void xen9pfsd_spawn_outcome(libxl__egc *egc, libxl__aop9_state *aop9,
                                   int rc);

/*
 * Spawn the xen-9pfsd daemon if needed.
 * returns:
 * < 0 if error
 * 0 if no daemon needs to be spawned
 * 1 if daemon was spawned
 */
static int xen9pfsd_spawn(libxl__egc *egc, uint32_t domid, libxl_device_p9 *p9,
                         libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    struct libxl__aop9_state *aop9;
    int rc;
    char *args[] = { "xen-9pfsd", NULL };
    char *path = GCSPRINTF("/local/domain/%u/libxl/xen-9pfs",
                           p9->backend_domid);

    if (p9->type != LIBXL_P9_TYPE_XEN_9PFSD ||
        libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", path)))
        return 0;

    GCNEW(aop9);
    aop9->aodev = aodev;
    libxl_device_p9_copy(CTX, &aop9->p9, p9);
    aop9->domid = domid;

    aop9->spawn.ao = aodev->ao;
    aop9->spawn.what = "xen-9pfs daemon";
    aop9->spawn.xspath = GCSPRINTF("%s/state", path);
    aop9->spawn.timeout_ms = LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000;
    aop9->spawn.pidpath = GCSPRINTF("%s/pid", path);
    aop9->spawn.midproc_cb = libxl__spawn_record_pid;
    aop9->spawn.confirm_cb = xen9pfsd_confirm;
    aop9->spawn.failure_cb = xen9pfsd_failed;
    aop9->spawn.detached_cb = xen9pfsd_detached;
    rc = libxl__spawn_spawn(egc, &aop9->spawn);
    if (rc < 0)
        return rc;
    if (!rc) {
        setsid();
        libxl__exec(gc, -1, -1, -1, LIBEXEC_BIN "/xen-9pfsd", args, NULL);
    }

    return 1;
}

static void xen9pfsd_confirm(libxl__egc *egc, libxl__spawn_state *spawn,
                             const char *xsdata)
{
    STATE_AO_GC(spawn->ao);

    if (!xsdata)
        return;

    if (strcmp(xsdata, "running"))
        return;

    libxl__spawn_initiate_detach(gc, spawn);
}

static void xen9pfsd_failed(libxl__egc *egc, libxl__spawn_state *spawn, int rc)
{
    libxl__aop9_state *aop9 = CONTAINER_OF(spawn, *aop9, spawn);

    xen9pfsd_spawn_outcome(egc, aop9, rc);
}

static void xen9pfsd_detached(libxl__egc *egc, libxl__spawn_state *spawn)
{
    libxl__aop9_state *aop9 = CONTAINER_OF(spawn, *aop9, spawn);

    xen9pfsd_spawn_outcome(egc, aop9, 0);
}

static void xen9pfsd_spawn_outcome(libxl__egc *egc, libxl__aop9_state *aop9,
                                   int rc)
{
    aop9->aodev->rc = rc;
    if (rc)
        aop9->aodev->callback(egc, aop9->aodev);
    else
        libxl__device_add_async(egc, aop9->domid, &libxl__p9_devtype,
                                &aop9->p9, aop9->aodev);
}

static void libxl__device_p9_add(libxl__egc *egc, uint32_t domid,
                                 libxl_device_p9 *p9,
                                 libxl__ao_device *aodev)
{
    int rc;

    rc = xen9pfsd_spawn(egc, domid, p9, aodev);
    if (rc == 1)
        return;

    if (rc == 0)
        libxl__device_add_async(egc, domid, &libxl__p9_devtype, p9, aodev);

    aodev->rc = rc;
    if (rc)
        aodev->callback(egc, aodev);
}

int libxl_device_9pfs_add(libxl_ctx *ctx, uint32_t domid, libxl_device_p9 *p9,
                          const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    libxl__prepare_ao_device(ao, aodev);
    aodev->action = LIBXL__DEVICE_ACTION_ADD;
    aodev->callback = device_addrm_aocomplete;

    libxl__device_p9_add(egc, domid, p9, aodev);

    return AO_INPROGRESS;
}

#define libxl_device_p9_list NULL
#define libxl_device_p9_compare NULL

static LIBXL_DEFINE_UPDATE_DEVID(p9)
static LIBXL_DEFINE_DEVICES_ADD(p9)

LIBXL_DEFINE_DEVICE_REMOVE(p9)

DEFINE_DEVICE_TYPE_STRUCT(p9, 9PFS, p9s,
    .set_xenstore_config = (device_set_xenstore_config_fn_t)
                           libxl__set_xenstore_p9,
    .dm_needed = libxl__device_p9_dm_needed,
);
