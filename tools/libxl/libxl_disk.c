/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#define BACKEND_STRING_SIZE 5

static void disk_eject_xswatch_callback(libxl__egc *egc, libxl__ev_xswatch *w,
                                        const char *wpath, const char *epath) {
    EGC_GC;
    libxl_evgen_disk_eject *evg = (void*)w;
    const char *backend;
    char *value;
    char backend_type[BACKEND_STRING_SIZE+1];
    int rc;

    value = libxl__xs_read(gc, XBT_NULL, wpath);

    if (!value || strcmp(value,  "eject"))
        return;

    if (libxl__xs_printf(gc, XBT_NULL, wpath, "")) {
        LIBXL__EVENT_DISASTER(egc, "xs_write failed acknowledging eject",
                              errno, LIBXL_EVENT_TYPE_DISK_EJECT);
        return;
    }

    libxl_event *ev = NEW_EVENT(egc, DISK_EJECT, evg->domid, evg->user);
    libxl_device_disk *disk = &ev->u.disk_eject.disk;

    rc = libxl__xs_read_checked(gc, XBT_NULL, evg->be_ptr_path, &backend);
    if (rc) {
        LIBXL__EVENT_DISASTER(egc, "xs_read failed reading be_ptr_path",
                              errno, LIBXL_EVENT_TYPE_DISK_EJECT);
        return;
    }
    if (!backend) {
        /* device has been removed, not simply ejected */
        return;
    }

    sscanf(backend,
            "/local/domain/%d/backend/%" TOSTRING(BACKEND_STRING_SIZE)
           "[a-z]/%*d/%*d",
           &disk->backend_domid, backend_type);
    if (!strcmp(backend_type, "tap") || !strcmp(backend_type, "vbd")) {
        disk->backend = LIBXL_DISK_BACKEND_TAP;
    } else if (!strcmp(backend_type, "qdisk")) {
        disk->backend = LIBXL_DISK_BACKEND_QDISK;
    } else {
        disk->backend = LIBXL_DISK_BACKEND_UNKNOWN;
    }

    disk->pdev_path = strdup(""); /* xxx fixme malloc failure */
    disk->format = LIBXL_DISK_FORMAT_EMPTY;
    /* this value is returned to the user: do not free right away */
    disk->vdev = libxl__strdup(NOGC, evg->vdev);
    disk->removable = 1;
    disk->readwrite = 0;
    disk->is_cdrom = 1;

    libxl__event_occurred(egc, ev);
}

int libxl_evenable_disk_eject(libxl_ctx *ctx, uint32_t guest_domid,
                              const char *vdev, libxl_ev_user user,
                              libxl_evgen_disk_eject **evgen_out) {
    GC_INIT(ctx);
    CTX_LOCK;
    int rc;
    char *path;
    libxl_evgen_disk_eject *evg = NULL;

    evg = malloc(sizeof(*evg));  if (!evg) { rc = ERROR_NOMEM; goto out; }
    memset(evg, 0, sizeof(*evg));
    evg->user = user;
    evg->domid = guest_domid;
    LIBXL_LIST_INSERT_HEAD(&CTX->disk_eject_evgens, evg, entry);

    uint32_t domid = libxl_get_stubdom_id(ctx, guest_domid);

    if (!domid)
        domid = guest_domid;

    int devid = libxl__device_disk_dev_number(vdev, NULL, NULL);

    path = GCSPRINTF("%s/eject",
                    libxl__domain_device_frontend_path(gc, domid, devid,
                    LIBXL__DEVICE_KIND_VBD));
    if (!path) { rc = ERROR_NOMEM; goto out; }

    const char *libxl_path = libxl__domain_device_frontend_path(gc, domid, devid,
                                                                LIBXL__DEVICE_KIND_VBD);
    evg->be_ptr_path = libxl__sprintf(NOGC, "%s/backend", libxl_path);

    const char *configured_vdev;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
            GCSPRINTF("%s/dev", libxl_path), &configured_vdev);
    if (rc) goto out;

    evg->vdev = libxl__strdup(NOGC, configured_vdev);

    rc = libxl__ev_xswatch_register(gc, &evg->watch,
                                    disk_eject_xswatch_callback, path);
    if (rc) goto out;

    *evgen_out = evg;
    CTX_UNLOCK;
    GC_FREE;
    return 0;

 out:
    if (evg)
        libxl__evdisable_disk_eject(gc, evg);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

void libxl__evdisable_disk_eject(libxl__gc *gc, libxl_evgen_disk_eject *evg) {
    CTX_LOCK;

    LIBXL_LIST_REMOVE(evg, entry);

    if (libxl__ev_xswatch_isregistered(&evg->watch))
        libxl__ev_xswatch_deregister(gc, &evg->watch);

    free(evg->vdev);
    free(evg->be_ptr_path);
    free(evg);

    CTX_UNLOCK;
}

void libxl_evdisable_disk_eject(libxl_ctx *ctx, libxl_evgen_disk_eject *evg) {
    GC_INIT(ctx);
    libxl__evdisable_disk_eject(gc, evg);
    GC_FREE;
}

static int libxl__device_disk_setdefault(libxl__gc *gc, uint32_t domid,
                                         libxl_device_disk *disk, bool hotplug)
{
    int rc;

    libxl_defbool_setdefault(&disk->discard_enable, !!disk->readwrite);
    libxl_defbool_setdefault(&disk->colo_enable, false);
    libxl_defbool_setdefault(&disk->colo_restore_enable, false);

    rc = libxl__resolve_domid(gc, disk->backend_domname, &disk->backend_domid);
    if (rc < 0) return rc;

    /* Force Qdisk backend for CDROM devices of guests with a device model. */
    if (disk->is_cdrom != 0 &&
        libxl__domain_type(gc, domid) == LIBXL_DOMAIN_TYPE_HVM) {
        if (!(disk->backend == LIBXL_DISK_BACKEND_QDISK ||
              disk->backend == LIBXL_DISK_BACKEND_UNKNOWN)) {
            LOGD(ERROR, domid, "Backend for CD devices on HVM guests must be Qdisk");
            return ERROR_FAIL;
        }
        disk->backend = LIBXL_DISK_BACKEND_QDISK;
    }

    rc = libxl__device_disk_set_backend(gc, disk);
    return rc;
}

static int libxl__device_from_disk(libxl__gc *gc, uint32_t domid,
                                   const libxl_device_disk *disk,
                                   libxl__device *device)
{
    int devid;

    devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);
    if (devid==-1) {
        LOGD(ERROR, domid, "Invalid or unsupported"" virtual disk identifier %s",
             disk->vdev);
        return ERROR_INVAL;
    }

    device->backend_domid = disk->backend_domid;
    device->backend_devid = devid;

    switch (disk->backend) {
        case LIBXL_DISK_BACKEND_PHY:
            device->backend_kind = LIBXL__DEVICE_KIND_VBD;
            break;
        case LIBXL_DISK_BACKEND_TAP:
            device->backend_kind = LIBXL__DEVICE_KIND_VBD;
            break;
        case LIBXL_DISK_BACKEND_QDISK:
            device->backend_kind = LIBXL__DEVICE_KIND_QDISK;
            break;
        default:
            LOGD(ERROR, domid, "Unrecognized disk backend type: %d",
                 disk->backend);
            return ERROR_INVAL;
    }

    device->domid = domid;
    device->devid = devid;
    device->kind  = LIBXL__DEVICE_KIND_VBD;

    return 0;
}

/* Specific function called directly only by local disk attach,
 * all other users should instead use the regular
 * libxl__device_disk_add wrapper
 *
 * The (optionally) passed function get_vdev will be used to
 * set the vdev the disk should be attached to. When it is set the caller
 * must also pass get_vdev_user, which will be passed to get_vdev.
 *
 * The passed get_vdev function is also in charge of printing
 * the corresponding error message when appropiate.
 */
static void device_disk_add(libxl__egc *egc, uint32_t domid,
                           libxl_device_disk *disk,
                           libxl__ao_device *aodev,
                           char *get_vdev(libxl__gc *, void *,
                                          xs_transaction_t),
                           void *get_vdev_user)
{
    STATE_AO_GC(aodev->ao);
    flexarray_t *front = NULL;
    flexarray_t *back = NULL;
    char *dev = NULL, *script;
    libxl__device *device;
    int rc;
    libxl_ctx *ctx = gc->owner;
    xs_transaction_t t = XBT_NULL;
    libxl_domain_config d_config;
    libxl_device_disk disk_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_disk_init(&disk_saved);
    libxl_device_disk_copy(ctx, &disk_saved, disk);

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    /*
     * get_vdev != NULL -> local attach
     * get_vdev == NULL -> block attach
     *
     * We don't care about local attach state because it's only
     * intermediate state.
     */
    if (!get_vdev && aodev->update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        device_add_domain_config(gc, &d_config, &libxl__disk_devtype,
                                 &disk_saved);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        if (get_vdev) {
            assert(get_vdev_user);
            disk->vdev = get_vdev(gc, get_vdev_user, t);
            if (disk->vdev == NULL) {
                rc = ERROR_FAIL;
                goto out;
            }
        }

        rc = libxl__device_disk_setdefault(gc, domid, disk, aodev->update_json);
        if (rc) goto out;

        front = flexarray_make(gc, 16, 1);
        back = flexarray_make(gc, 16, 1);

        GCNEW(device);
        rc = libxl__device_from_disk(gc, domid, disk, device);
        if (rc != 0) {
            LOGD(ERROR, domid, "Invalid or unsupported"" virtual disk identifier %s",
                 disk->vdev);
            goto out;
        }

        rc = libxl__device_exists(gc, t, device);
        if (rc < 0) goto out;
        if (rc == 1) {              /* already exists in xenstore */
            LOGD(ERROR, domid, "device already exists in xenstore");
            aodev->action = LIBXL__DEVICE_ACTION_ADD; /* for error message */
            rc = ERROR_DEVICE_EXISTS;
            goto out;
        }

        switch (disk->backend) {
            case LIBXL_DISK_BACKEND_PHY:
                dev = disk->pdev_path;

                flexarray_append(back, "params");
                flexarray_append(back, dev);

                script = libxl__abs_path(gc, disk->script?: "block",
                                         libxl__xen_script_dir_path());
                flexarray_append_pair(back, "script", script);

                assert(device->backend_kind == LIBXL__DEVICE_KIND_VBD);
                break;

            case LIBXL_DISK_BACKEND_TAP:
                LOG(ERROR, "blktap is not supported");
                rc = ERROR_FAIL;
                goto out;
            case LIBXL_DISK_BACKEND_QDISK:
                flexarray_append(back, "params");
                flexarray_append(back, GCSPRINTF("%s:%s",
                              libxl__device_disk_string_of_format(disk->format),
                              disk->pdev_path ? : ""));
                if (libxl_defbool_val(disk->colo_enable)) {
                    flexarray_append(back, "colo-host");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->colo_host));
                    flexarray_append(back, "colo-port");
                    flexarray_append(back, libxl__sprintf(gc, "%d", disk->colo_port));
                    flexarray_append(back, "colo-export");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->colo_export));
                    flexarray_append(back, "active-disk");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->active_disk));
                    flexarray_append(back, "hidden-disk");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->hidden_disk));
                }
                assert(device->backend_kind == LIBXL__DEVICE_KIND_QDISK);
                break;
            default:
                LOGD(ERROR, domid, "Unrecognized disk backend type: %d",
                     disk->backend);
                rc = ERROR_INVAL;
                goto out;
        }

        flexarray_append(back, "frontend-id");
        flexarray_append(back, GCSPRINTF("%d", domid));
        flexarray_append(back, "online");
        flexarray_append(back, "1");
        flexarray_append(back, "removable");
        flexarray_append(back, GCSPRINTF("%d", (disk->removable) ? 1 : 0));
        flexarray_append(back, "bootable");
        flexarray_append(back, GCSPRINTF("%d", 1));
        flexarray_append(back, "state");
        flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(back, "dev");
        flexarray_append(back, disk->vdev);
        flexarray_append(back, "type");
        flexarray_append(back, libxl__device_disk_string_of_backend(disk->backend));
        flexarray_append(back, "mode");
        flexarray_append(back, disk->readwrite ? "w" : "r");
        flexarray_append(back, "device-type");
        flexarray_append(back, disk->is_cdrom ? "cdrom" : "disk");
        if (disk->direct_io_safe) {
            flexarray_append(back, "direct-io-safe");
            flexarray_append(back, "1");
        }
        flexarray_append_pair(back, "discard-enable",
                              libxl_defbool_val(disk->discard_enable) ?
                              "1" : "0");

        flexarray_append(front, "backend-id");
        flexarray_append(front, GCSPRINTF("%d", disk->backend_domid));
        flexarray_append(front, "state");
        flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(front, "virtual-device");
        flexarray_append(front, GCSPRINTF("%d", device->devid));
        flexarray_append(front, "device-type");
        flexarray_append(front, disk->is_cdrom ? "cdrom" : "disk");

        /*
         * Old PV kernel disk frontends before 2.6.26 rely on tool stack to
         * write disk native protocol to frontend node. Xend does this, port
         * this behaviour to xl.
         *
         * New kernels write this node themselves. In that case it just
         * overwrites an existing node which is OK.
         */
        if (type == LIBXL_DOMAIN_TYPE_PV) {
            const char *protocol =
                xc_domain_get_native_protocol(ctx->xch, domid);
            if (protocol) {
                flexarray_append(front, "protocol");
                flexarray_append(front, libxl__strdup(gc, protocol));
            }
        }

        if (!get_vdev && aodev->update_json) {
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
    libxl_device_disk_dispose(&disk_saved);
    libxl_domain_config_dispose(&d_config);
    aodev->rc = rc;
    if (rc) aodev->callback(egc, aodev);
    return;
}

static void libxl__device_disk_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_disk *disk,
                                   libxl__ao_device *aodev)
{
    device_disk_add(egc, domid, disk, aodev, NULL, NULL);
}

static int libxl__disk_from_xenstore(libxl__gc *gc, const char *libxl_path,
                                     libxl_devid devid,
                                     libxl_device_disk *disk)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    unsigned int len;
    char *tmp;
    int rc;

    const char *backend_path;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path),
                                &backend_path);
    if (rc) goto out;

    if (!backend_path) {
        LOG(ERROR, "disk %s does not exist (no backend path", libxl_path);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__backendpath_parse_domid(gc, backend_path, &disk->backend_domid);
    if (rc) {
        LOG(ERROR, "Unable to fetch device backend domid from %s", backend_path);
        goto out;
    }

    /*
     * "params" may not be present; but everything else must be.
     * colo releated entries(colo-host, colo-port, colo-export,
     * active-disk and hidden-disk) are present only if colo is
     * enabled.
     */
    tmp = xs_read(ctx->xsh, XBT_NULL,
                  GCSPRINTF("%s/params", libxl_path), &len);
    if (tmp && strchr(tmp, ':')) {
        disk->pdev_path = strdup(strchr(tmp, ':') + 1);
        free(tmp);
    } else {
        disk->pdev_path = tmp;
    }

    tmp = xs_read(ctx->xsh, XBT_NULL,
                  GCSPRINTF("%s/colo-host", libxl_path), &len);
    if (tmp) {
        libxl_defbool_set(&disk->colo_enable, true);
        disk->colo_host = tmp;

        tmp = xs_read(ctx->xsh, XBT_NULL,
                      GCSPRINTF("%s/colo-port", libxl_path), &len);
        if (!tmp) {
            LOG(ERROR, "Missing xenstore node %s/colo-port", libxl_path);
            goto cleanup;
        }
        disk->colo_port = atoi(tmp);

#define XS_READ_COLO(param, item) do {                                  \
        tmp = xs_read(ctx->xsh, XBT_NULL,                               \
                      GCSPRINTF("%s/"#param"", libxl_path), &len);         \
        if (!tmp) {                                                     \
            LOG(ERROR, "Missing xenstore node %s/"#param"", libxl_path);   \
            goto cleanup;                                               \
        }                                                               \
        disk->item = tmp;                                               \
} while (0)
        XS_READ_COLO(colo-export, colo_export);
        XS_READ_COLO(active-disk, active_disk);
        XS_READ_COLO(hidden-disk, hidden_disk);
#undef XS_READ_COLO
    } else {
        libxl_defbool_set(&disk->colo_enable, false);
    }

    tmp = libxl__xs_read(gc, XBT_NULL,
                         GCSPRINTF("%s/type", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/type", libxl_path);
        goto cleanup;
    }
    libxl_string_to_backend(ctx, tmp, &(disk->backend));

    disk->vdev = xs_read(ctx->xsh, XBT_NULL,
                         GCSPRINTF("%s/dev", libxl_path), &len);
    if (!disk->vdev) {
        LOG(ERROR, "Missing xenstore node %s/dev", libxl_path);
        goto cleanup;
    }

    tmp = libxl__xs_read(gc, XBT_NULL, libxl__sprintf
                         (gc, "%s/removable", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/removable", libxl_path);
        goto cleanup;
    }
    disk->removable = atoi(tmp);

    tmp = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/mode", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/mode", libxl_path);
        goto cleanup;
    }
    if (!strcmp(tmp, "w"))
        disk->readwrite = 1;
    else
        disk->readwrite = 0;

    tmp = libxl__xs_read(gc, XBT_NULL,
                         GCSPRINTF("%s/device-type", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/device-type", libxl_path);
        goto cleanup;
    }
    disk->is_cdrom = !strcmp(tmp, "cdrom");

    disk->format = LIBXL_DISK_FORMAT_UNKNOWN;

    return 0;
cleanup:
    rc = ERROR_FAIL;
 out:
    libxl_device_disk_dispose(disk);
    return rc;
}

int libxl_vdev_to_device_disk(libxl_ctx *ctx, uint32_t domid,
                              const char *vdev, libxl_device_disk *disk)
{
    GC_INIT(ctx);
    char *libxl_path;
    int devid = libxl__device_disk_dev_number(vdev, NULL, NULL);
    int rc = ERROR_FAIL;

    if (devid < 0)
        return ERROR_INVAL;

    libxl_device_disk_init(disk);

    libxl_path = libxl__domain_device_libxl_path(gc, domid, devid,
                                                 LIBXL__DEVICE_KIND_VBD);

    rc = libxl__disk_from_xenstore(gc, libxl_path, devid, disk);

    GC_FREE;
    return rc;
}

int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              const libxl_device_disk *disk,
                              libxl_diskinfo *diskinfo)
{
    GC_INIT(ctx);
    char *fe_path, *libxl_path;
    char *val;
    int rc;

    diskinfo->backend = NULL;

    diskinfo->devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);

    /* tap devices entries in xenstore are written as vbd devices. */
    fe_path = libxl__domain_device_frontend_path(gc, domid, diskinfo->devid,
                                                 LIBXL__DEVICE_KIND_VBD);
    libxl_path = libxl__domain_device_libxl_path(gc, domid, diskinfo->devid,
                                                 LIBXL__DEVICE_KIND_VBD);
    diskinfo->backend = xs_read(ctx->xsh, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!diskinfo->backend) {
        GC_FREE;
        return ERROR_FAIL;
    }
    rc = libxl__backendpath_parse_domid(gc, diskinfo->backend,
                                        &diskinfo->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", fe_path));
    diskinfo->state = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/event-channel", fe_path));
    diskinfo->evtch = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/ring-ref", fe_path));
    diskinfo->rref = val ? strtoul(val, NULL, 10) : -1;
    diskinfo->frontend = xs_read(ctx->xsh, XBT_NULL,
                                 GCSPRINTF("%s/frontend", libxl_path), NULL);
    diskinfo->frontend_id = domid;

    GC_FREE;
    return 0;

 out:
    free(diskinfo->backend);
    return rc;
}

typedef struct {
    libxl__ao *ao;
    libxl_domid domid;
    libxl_device_disk *disk;
    libxl_device_disk disk_saved;
    libxl__ev_slowlock qmp_lock;
    int dm_ver;
    libxl__ev_time time;
    libxl__ev_qmp qmp;
} libxl__cdrom_insert_state;

static void cdrom_insert_lock_acquired(libxl__egc *, libxl__ev_slowlock *,
                                       int rc);
static void cdrom_insert_ejected(libxl__egc *egc, libxl__ev_qmp *,
                                 const libxl__json_object *, int rc);
static void cdrom_insert_addfd_cb(libxl__egc *egc, libxl__ev_qmp *,
                                  const libxl__json_object *, int rc);
static void cdrom_insert_inserted(libxl__egc *egc, libxl__ev_qmp *,
                                  const libxl__json_object *, int rc);
static void cdrom_insert_timout(libxl__egc *egc, libxl__ev_time *ev,
                                const struct timeval *requested_abs,
                                int rc);
static void cdrom_insert_done(libxl__egc *egc,
                              libxl__cdrom_insert_state *cis,
                              int rc);

int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk,
                       const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int num = 0, i;
    libxl_device_disk *disks = NULL;
    int rc;
    libxl__cdrom_insert_state *cis;

    GCNEW(cis);
    cis->ao = ao;
    cis->domid = domid;
    cis->disk = disk;
    libxl_device_disk_init(&cis->disk_saved);
    libxl_device_disk_copy(ctx, &cis->disk_saved, disk);
    libxl__ev_devlock_init(&cis->qmp_lock);
    cis->qmp_lock.ao = ao;
    cis->qmp_lock.domid = domid;
    libxl__ev_time_init(&cis->time);
    libxl__ev_qmp_init(&cis->qmp);
    cis->qmp.ao = ao;
    cis->qmp.domid = domid;
    cis->qmp.payload_fd = -1;

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (type != LIBXL_DOMAIN_TYPE_HVM) {
        LOGD(ERROR, domid, "cdrom-insert requires an HVM domain");
        rc = ERROR_INVAL;
        goto out;
    }

    if (libxl_get_stubdom_id(ctx, domid) != 0) {
        LOGD(ERROR, domid, "cdrom-insert doesn't work for stub domains");
        rc = ERROR_INVAL;
        goto out;
    }

    cis->dm_ver = libxl__device_model_version_running(gc, domid);
    if (cis->dm_ver == -1) {
        LOGD(ERROR, domid, "Cannot determine device model version");
        rc = ERROR_FAIL;
        goto out;
    }

    disks = libxl__device_list(gc, &libxl__disk_devtype, domid, &num);
    for (i = 0; i < num; i++) {
        if (disks[i].is_cdrom && !strcmp(disk->vdev, disks[i].vdev))
        {
            /* Found.  Set backend type appropriately. */
            disk->backend=disks[i].backend;
            break;
        }
    }
    if (i == num) {
        LOGD(ERROR, domid, "Virtual device not found");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__device_disk_setdefault(gc, domid, disk, false);
    if (rc) goto out;

    if (!disk->pdev_path) {
        disk->pdev_path = libxl__strdup(NOGC, "");
        disk->format = LIBXL_DISK_FORMAT_EMPTY;
    }

out:
    libxl__device_list_free(&libxl__disk_devtype, disks, num);
    if (rc) {
        cdrom_insert_done(egc, cis, rc); /* must be last */
    } else {
        cis->qmp_lock.callback = cdrom_insert_lock_acquired;
        libxl__ev_slowlock_lock(egc, &cis->qmp_lock); /* must be last */
    }
    return AO_INPROGRESS;
}

static void cdrom_insert_lock_acquired(libxl__egc *egc,
                                       libxl__ev_slowlock *lock,
                                       int rc)
{
    libxl__cdrom_insert_state *cis = CONTAINER_OF(lock, *cis, qmp_lock);
    STATE_AO_GC(cis->ao);

    if (rc) goto out;

    rc = libxl__ev_time_register_rel(ao, &cis->time,
                                     cdrom_insert_timout,
                                     LIBXL_HOTPLUG_TIMEOUT * 1000);
    if (rc) goto out;

    /* We need to eject the original image first.
     * JSON is not updated.
     */

    if (cis->dm_ver == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
        libxl__json_object *args = NULL;
        int devid = libxl__device_disk_dev_number(cis->disk->vdev,
                                                  NULL, NULL);

        QMP_PARAMETERS_SPRINTF(&args, "device", "ide-%i", devid);
        cis->qmp.callback = cdrom_insert_ejected;
        rc = libxl__ev_qmp_send(egc, &cis->qmp, "eject", args);
        if (rc) goto out;
    } else {
        cdrom_insert_ejected(egc, &cis->qmp, NULL, 0); /* must be last */
    }
    return;

out:
    cdrom_insert_done(egc, cis, rc); /* must be last */
}

static void cdrom_insert_ejected(libxl__egc *egc,
                                 libxl__ev_qmp *qmp,
                                 const libxl__json_object *response,
                                 int rc)
{
    EGC_GC;
    libxl__cdrom_insert_state *cis = CONTAINER_OF(qmp, *cis, qmp);
    libxl__domain_userdata_lock *data_lock = NULL;
    libxl__device device;
    const char *be_path, *libxl_path;
    flexarray_t *empty = NULL;
    xs_transaction_t t = XBT_NULL;
    char *tmp;
    libxl_domain_config d_config;
    bool has_callback = false;

    /* convenience aliases */
    libxl_domid domid = cis->domid;
    libxl_device_disk *disk = cis->disk;

    libxl_domain_config_init(&d_config);

    if (rc) goto out;

    rc = libxl__device_from_disk(gc, domid, disk, &device);
    if (rc) goto out;
    be_path = libxl__device_backend_path(gc, &device);
    libxl_path = libxl__device_libxl_path(gc, &device);

    data_lock = libxl__lock_domain_userdata(gc, domid);
    if (!data_lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    empty = flexarray_make(gc, 4, 1);
    flexarray_append_pair(empty, "type",
                          libxl__device_disk_string_of_backend(disk->backend));
    flexarray_append_pair(empty, "params", "");

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;
        /* Sanity check: make sure the device exists before writing here */
        tmp = libxl__xs_read(gc, t, GCSPRINTF("%s/frontend", libxl_path));
        if (!tmp)
        {
            LOGD(ERROR, domid, "Internal error: %s does not exist",
                 GCSPRINTF("%s/frontend", libxl_path));
            rc = ERROR_FAIL;
            goto out;
        }

        char **kvs = libxl__xs_kvs_of_flexarray(gc, empty);

        rc = libxl__xs_writev(gc, t, be_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_writev(gc, t, libxl_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    /*
     * Now that the drive is empty, we can insert the new media.
     */

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc) goto out;

    device_add_domain_config(gc, &d_config, &libxl__disk_devtype,
                             &cis->disk_saved);

    rc = libxl__dm_check_start(gc, &d_config, domid);
    if (rc) goto out;

    if (cis->dm_ver == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN &&
        disk->format != LIBXL_DISK_FORMAT_EMPTY) {
        libxl__json_object *args = NULL;

        assert(qmp->payload_fd == -1);
        qmp->payload_fd = open(disk->pdev_path, O_RDONLY);
        if (qmp->payload_fd < 0) {
            LOGED(ERROR, domid, "Failed to open cdrom file %s",
                  disk->pdev_path);
            rc = ERROR_FAIL;
            goto out;
        }

        /* This free form parameter is not use by QEMU or libxl. */
        QMP_PARAMETERS_SPRINTF(&args, "opaque", "%s:%s",
                               libxl_disk_format_to_string(disk->format),
                               disk->pdev_path);
        qmp->callback = cdrom_insert_addfd_cb;
        rc = libxl__ev_qmp_send(egc, qmp, "add-fd", args);
        if (rc) goto out;
        has_callback = true;
    } else {
        has_callback = false;
    }

    rc = 0;

out:
    libxl__xs_transaction_abort(gc, &t);
    libxl_domain_config_dispose(&d_config);
    if (data_lock) libxl__unlock_domain_userdata(data_lock);
    if (rc) {
        cdrom_insert_done(egc, cis, rc); /* must be last */
    } else if (!has_callback) {
        /* Only called if no asynchronous callback are set. */
        cdrom_insert_inserted(egc, qmp, NULL, 0); /* must be last */
    }
}

static void cdrom_insert_addfd_cb(libxl__egc *egc,
                                  libxl__ev_qmp *qmp,
                                  const libxl__json_object *response,
                                  int rc)
{
    EGC_GC;
    libxl__cdrom_insert_state *cis = CONTAINER_OF(qmp, *cis, qmp);
    libxl__json_object *args = NULL;
    const libxl__json_object *o;
    int devid;
    int fdset;

    /* convenience aliases */
    libxl_device_disk *disk = cis->disk;

    close(qmp->payload_fd);
    qmp->payload_fd = -1;

    if (rc) goto out;

    o = libxl__json_map_get("fdset-id", response, JSON_INTEGER);
    if (!o) {
        rc = ERROR_FAIL;
        goto out;
    }
    fdset = libxl__json_object_get_integer(o);

    devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);
    QMP_PARAMETERS_SPRINTF(&args, "device", "ide-%i", devid);
    QMP_PARAMETERS_SPRINTF(&args, "target", "/dev/fdset/%d", fdset);
    libxl__qmp_param_add_string(gc, &args, "arg",
        libxl__qemu_disk_format_string(disk->format));
    qmp->callback = cdrom_insert_inserted;
    rc = libxl__ev_qmp_send(egc, qmp, "change", args);
out:
    if (rc)
        cdrom_insert_done(egc, cis, rc); /* must be last */
}

static void cdrom_insert_inserted(libxl__egc *egc,
                                  libxl__ev_qmp *qmp,
                                  const libxl__json_object *response,
                                  int rc)
{
    EGC_GC;
    libxl__cdrom_insert_state *cis = CONTAINER_OF(qmp, *cis, qmp);
    libxl__domain_userdata_lock *data_lock = NULL;
    libxl_domain_config d_config;
    flexarray_t *insert = NULL;
    xs_transaction_t t = XBT_NULL;
    libxl__device device;
    const char *be_path, *libxl_path;
    char *tmp;

    /* convenience aliases */
    libxl_domid domid = cis->domid;
    libxl_device_disk *disk = cis->disk;

    libxl_domain_config_init(&d_config);

    if (rc) goto out;

    rc = libxl__device_from_disk(gc, domid, disk, &device);
    if (rc) goto out;
    be_path = libxl__device_backend_path(gc, &device);
    libxl_path = libxl__device_libxl_path(gc, &device);

    data_lock = libxl__lock_domain_userdata(gc, domid);
    if (!data_lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc) goto out;

    device_add_domain_config(gc, &d_config, &libxl__disk_devtype,
                             &cis->disk_saved);

    insert = flexarray_make(gc, 4, 1);
    flexarray_append_pair(insert, "type",
                      libxl__device_disk_string_of_backend(disk->backend));
    if (disk->format != LIBXL_DISK_FORMAT_EMPTY)
        flexarray_append_pair(insert, "params",
                    GCSPRINTF("%s:%s",
                        libxl__device_disk_string_of_format(disk->format),
                        disk->pdev_path));
    else
        flexarray_append_pair(insert, "params", "");

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;
        /* Sanity check: make sure the device exists before writing here */
        tmp = libxl__xs_read(gc, t, GCSPRINTF("%s/frontend", libxl_path));
        if (!tmp)
        {
            LOGD(ERROR, domid, "Internal error: %s does not exist",
                 GCSPRINTF("%s/frontend", libxl_path));
            rc = ERROR_FAIL;
            goto out;
        }

        rc = libxl__set_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        char **kvs = libxl__xs_kvs_of_flexarray(gc, insert);

        rc = libxl__xs_writev(gc, t, be_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_writev(gc, t, libxl_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    rc = 0;

out:
    libxl__xs_transaction_abort(gc, &t);
    libxl_domain_config_dispose(&d_config);
    if (data_lock) libxl__unlock_domain_userdata(data_lock);
    cdrom_insert_done(egc, cis, rc); /* must be last */
}

static void cdrom_insert_timout(libxl__egc *egc, libxl__ev_time *ev,
                                const struct timeval *requested_abs,
                                int rc)
{
    EGC_GC;
    libxl__cdrom_insert_state *cis = CONTAINER_OF(ev, *cis, time);
    LOGD(ERROR, cis->domid, "cdrom insertion timed out");
    cdrom_insert_done(egc, cis, rc);
}

static void cdrom_insert_done(libxl__egc *egc,
                              libxl__cdrom_insert_state *cis,
                              int rc)
{
    EGC_GC;

    libxl__ev_time_deregister(gc, &cis->time);
    libxl__ev_qmp_dispose(gc, &cis->qmp);
    if (cis->qmp.payload_fd >= 0) close(cis->qmp.payload_fd);
    libxl__ev_slowlock_unlock(gc, &cis->qmp_lock);
    libxl_device_disk_dispose(&cis->disk_saved);
    libxl__ao_complete(egc, cis->ao, rc);
}

/* libxl__alloc_vdev only works on the local domain, that is the domain
 * where the toolstack is running */
static char * libxl__alloc_vdev(libxl__gc *gc, void *get_vdev_user,
        xs_transaction_t t)
{
    const char *blkdev_start = (const char *) get_vdev_user;
    int devid = 0, disk = 0, part = 0;

    libxl__device_disk_dev_number(blkdev_start, &disk, &part);
    if (part != 0) {
        LOG(ERROR, "blkdev_start is invalid");
        return NULL;
    }

    do {
        devid = libxl__device_disk_dev_number(GCSPRINTF("d%dp0", disk),
                NULL, NULL);
        if (devid < 0)
            return NULL;
        if (libxl__xs_read(gc, t, GCSPRINTF("%s/backend",
                           libxl__domain_device_libxl_path(gc,
                           LIBXL_TOOLSTACK_DOMID, devid,
                           LIBXL__DEVICE_KIND_VBD))) == NULL) {
            if (errno == ENOENT)
                return libxl__devid_to_vdev(gc, devid);
            else
                return NULL;
        }
        disk++;
    } while (1);
    return NULL;
}

/* Callbacks */

char *libxl__device_disk_find_local_path(libxl__gc *gc,
                                          libxl_domid guest_domid,
                                          const libxl_device_disk *disk,
                                          bool qdisk_direct)
{
    char *path = NULL;

    /* No local paths for driver domains */
    if (disk->backend_domname != NULL) {
        LOG(DEBUG, "Non-local backend, can't access locally.\n");
        goto out;
    }

    /*
     * If this is in raw format, and we're not using a script or a
     * driver domain, we can access the target path directly.
     */
    if (disk->format == LIBXL_DISK_FORMAT_RAW
        && disk->script == NULL) {
        path = libxl__strdup(gc, disk->pdev_path);
        LOG(DEBUG, "Directly accessing local RAW disk %s", path);
        goto out;
    }

    /*
     * If we're being called for a qemu path, we can pass the target
     * string directly as well
     */
    if (qdisk_direct && disk->backend == LIBXL_DISK_BACKEND_QDISK) {
        path = libxl__strdup(gc, disk->pdev_path);
        LOG(DEBUG, "Directly accessing local QDISK target %s", path);
        goto out;
    }

    /*
     * If the format isn't raw and / or we're using a script, then see
     * if the script has written a path to the "cooked" node
     */
    if (disk->script && guest_domid != INVALID_DOMID) {
        libxl__device device;
        char *be_path, *pdpath;
        int rc;

        LOGD(DEBUG, guest_domid,
             "Run from a script; checking for physical-device-path (vdev %s)",
             disk->vdev);

        rc = libxl__device_from_disk(gc, guest_domid, disk, &device);
        if (rc < 0)
            goto out;

        be_path = libxl__device_backend_path(gc, &device);

        pdpath = libxl__sprintf(gc, "%s/physical-device-path", be_path);

        LOGD(DEBUG, guest_domid, "Attempting to read node %s", pdpath);
        path = libxl__xs_read(gc, XBT_NULL, pdpath);

        if (path)
            LOGD(DEBUG, guest_domid, "Accessing cooked block device %s", path);
        else
            LOGD(DEBUG, guest_domid, "No physical-device-path, can't access locally.");

        goto out;
    }

 out:
    return path;
}

static void local_device_attach_cb(libxl__egc *egc, libxl__ao_device *aodev);

void libxl__device_disk_local_initiate_attach(libxl__egc *egc,
                                     libxl__disk_local_state *dls)
{
    STATE_AO_GC(dls->ao);
    int rc;
    const libxl_device_disk *in_disk = dls->in_disk;
    libxl_device_disk *disk = &dls->disk;
    const char *blkdev_start = dls->blkdev_start;

    assert(in_disk->pdev_path);

    disk->vdev = NULL;

    if (dls->diskpath)
        LOG(DEBUG, "Strange, dls->diskpath already set: %s", dls->diskpath);

    LOG(DEBUG, "Trying to find local path");

    dls->diskpath = libxl__device_disk_find_local_path(gc, INVALID_DOMID,
                                                       in_disk, false);
    if (dls->diskpath) {
        LOG(DEBUG, "Local path found, executing callback.");
        dls->callback(egc, dls, 0);
    } else {
        LOG(DEBUG, "Local path not found, initiating attach.");

        memcpy(disk, in_disk, sizeof(libxl_device_disk));
        disk->pdev_path = libxl__strdup(gc, in_disk->pdev_path);
        if (in_disk->script != NULL)
            disk->script = libxl__strdup(gc, in_disk->script);
        disk->vdev = NULL;

        rc = libxl__device_disk_setdefault(gc, LIBXL_TOOLSTACK_DOMID, disk,
                                           false);
        if (rc) goto out;

        libxl__prepare_ao_device(ao, &dls->aodev);
        dls->aodev.callback = local_device_attach_cb;
        device_disk_add(egc, LIBXL_TOOLSTACK_DOMID, disk, &dls->aodev,
                        libxl__alloc_vdev, (void *) blkdev_start);
    }

    return;

 out:
    assert(rc);
    dls->rc = rc;
    libxl__device_disk_local_initiate_detach(egc, dls);
    dls->callback(egc, dls, rc);
}

static void local_device_attach_cb(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__disk_local_state *dls = CONTAINER_OF(aodev, *dls, aodev);
    char *be_path = NULL;
    int rc;
    libxl__device device;
    libxl_device_disk *disk = &dls->disk;

    rc = aodev->rc;
    if (rc) {
        LOGE(ERROR, "unable locally attach device: %s", disk->pdev_path);
        goto out;
    }

    rc = libxl__device_from_disk(gc, LIBXL_TOOLSTACK_DOMID, disk, &device);
    if (rc < 0)
        goto out;
    be_path = libxl__device_backend_path(gc, &device);
    rc = libxl__wait_for_backend(gc, be_path, GCSPRINTF("%d", XenbusStateConnected));
    if (rc < 0)
        goto out;

    dls->diskpath = GCSPRINTF("/dev/%s",
                              libxl__devid_to_localdev(gc, device.devid));
    LOG(DEBUG, "locally attached disk %s", dls->diskpath);

    dls->callback(egc, dls, 0);
    return;

 out:
    assert(rc);
    dls->rc = rc;
    libxl__device_disk_local_initiate_detach(egc, dls);
    return;
}

/* Callbacks for local detach */

static void local_device_detach_cb(libxl__egc *egc, libxl__ao_device *aodev);

void libxl__device_disk_local_initiate_detach(libxl__egc *egc,
                                     libxl__disk_local_state *dls)
{
    STATE_AO_GC(dls->ao);
    int rc = 0;
    libxl_device_disk *disk = &dls->disk;
    libxl__device *device;
    libxl__ao_device *aodev = &dls->aodev;
    libxl__prepare_ao_device(ao, aodev);

    if (!dls->diskpath) goto out;

    if (disk->vdev != NULL) {
        GCNEW(device);
        rc = libxl__device_from_disk(gc, LIBXL_TOOLSTACK_DOMID,
                                     disk, device);
        if (rc != 0) goto out;

        aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
        aodev->dev = device;
        aodev->callback = local_device_detach_cb;
        aodev->force = 0;
        libxl__initiate_device_generic_remove(egc, aodev);
        return;
    }

out:
    aodev->rc = rc;
    local_device_detach_cb(egc, aodev);
    return;
}

static void local_device_detach_cb(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__disk_local_state *dls = CONTAINER_OF(aodev, *dls, aodev);
    int rc;

    if (aodev->rc) {
        LOGED(ERROR, aodev->dev->domid, "Unable to %s %s with id %u",
                     libxl__device_action_to_string(aodev->action),
                     libxl__device_kind_to_string(aodev->dev->kind),
                     aodev->dev->devid);
        goto out;
    }

out:
    /*
     * If there was an error in dls->rc, it means we have been called from
     * a failed execution of libxl__device_disk_local_initiate_attach,
     * so return the original error.
     */
    rc = dls->rc ? dls->rc : aodev->rc;
    dls->callback(egc, dls, rc);
    return;
}

/* The following functions are defined:
 * libxl_device_disk_add
 * libxl__add_disks
 * libxl_device_disk_remove
 * libxl_device_disk_destroy
 */
LIBXL_DEFINE_DEVICE_ADD(disk)
LIBXL_DEFINE_DEVICES_ADD(disk)
LIBXL_DEFINE_DEVICE_REMOVE(disk)

static int libxl_device_disk_compare(const libxl_device_disk *d1,
                                     const libxl_device_disk *d2)
{
    return COMPARE_DISK(d1, d2);
}

/* Take care of removable device. We maintain invariant in the
 * insert / remove operation so that:
 * 1. if xenstore is "empty" while JSON is not, the result
 *    is "empty"
 * 2. if xenstore has a different media than JSON, use the
 *    one in JSON
 * 3. if xenstore and JSON have the same media, well, you
 *    know the answer :-)
 *
 * Currently there is only one removable device -- CDROM.
 * Look for libxl_cdrom_insert for reference.
 */
static void libxl_device_disk_merge(libxl_ctx *ctx, void *d1, void *d2)
{
    GC_INIT(ctx);
    libxl_device_disk *src = d1;
    libxl_device_disk *dst = d2;

    if (src->removable) {
        if (!src->pdev_path || *src->pdev_path == '\0') {
            /* 1, no media in drive */
            free(dst->pdev_path);
            dst->pdev_path = libxl__strdup(NOGC, "");
            dst->format = LIBXL_DISK_FORMAT_EMPTY;
        } else {
            /* 2 and 3, use JSON, no need to touch anything */
            ;
        }
    }
}

static int libxl_device_disk_dm_needed(void *e, unsigned domid)
{
    libxl_device_disk *elem = e;

    return elem->backend == LIBXL_DISK_BACKEND_QDISK &&
           elem->backend_domid == domid;
}

LIBXL_DEFINE_DEVICE_LIST(disk)

#define libxl__device_disk_update_devid NULL

DEFINE_DEVICE_TYPE_STRUCT(disk, VBD,
    .merge       = libxl_device_disk_merge,
    .dm_needed   = libxl_device_disk_dm_needed,
    .from_xenstore = (device_from_xenstore_fn_t)libxl__disk_from_xenstore,
    .skip_attach = 1,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
