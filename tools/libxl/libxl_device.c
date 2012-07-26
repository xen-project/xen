/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

char *libxl__device_frontend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->domid);

    /* Console 0 is a special case */
    if (device->kind == LIBXL__DEVICE_KIND_CONSOLE && device->devid == 0)
        return libxl__sprintf(gc, "%s/console", dom_path);

    return libxl__sprintf(gc, "%s/device/%s/%d", dom_path,
                          libxl__device_kind_to_string(device->kind),
                          device->devid);
}

char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->backend_domid);

    return libxl__sprintf(gc, "%s/backend/%s/%u/%d", dom_path,
                          libxl__device_kind_to_string(device->backend_kind),
                          device->domid, device->devid);
}

int libxl__parse_backend_path(libxl__gc *gc,
                              const char *path,
                              libxl__device *dev)
{
    /* /local/domain/<domid>/backend/<kind>/<domid>/<devid> */
    char strkind[16]; /* Longest is actually "console" */
    int rc = sscanf(path, "/local/domain/%d/backend/%15[^/]/%u/%d",
                    &dev->backend_domid,
                    strkind,
                    &dev->domid,
                    &dev->devid);

    if (rc != 4)
        return ERROR_FAIL;

    return libxl__device_kind_from_string(strkind, &dev->backend_kind);
}

static int libxl__num_devices(libxl__gc *gc, uint32_t domid)
{
    char *path;
    unsigned int num_kinds, num_devs;
    char **kinds = NULL, **devs = NULL;
    int i, j, rc = 0;
    libxl__device dev;
    libxl__device_kind kind;
    int numdevs = 0;

    path = GCSPRINTF("/local/domain/%d/device", domid);
    kinds = libxl__xs_directory(gc, XBT_NULL, path, &num_kinds);
    if (!kinds) {
        if (errno != ENOENT) {
            LOGE(ERROR, "unable to get xenstore device listing %s", path);
            rc = ERROR_FAIL;
            goto out;
        }
        num_kinds = 0;
    }
    for (i = 0; i < num_kinds; i++) {
        if (libxl__device_kind_from_string(kinds[i], &kind))
            continue;

        path = GCSPRINTF("/local/domain/%d/device/%s", domid, kinds[i]);
        devs = libxl__xs_directory(gc, XBT_NULL, path, &num_devs);
        if (!devs)
            continue;
        for (j = 0; j < num_devs; j++) {
            path = GCSPRINTF("/local/domain/%d/device/%s/%s/backend",
                             domid, kinds[i], devs[j]);
            path = libxl__xs_read(gc, XBT_NULL, path);
            if (path && libxl__parse_backend_path(gc, path, &dev) == 0) {
                numdevs++;
            }
        }
    }
out:
    if (rc) return rc;
    return numdevs;
}

int libxl__device_generic_add(libxl__gc *gc, xs_transaction_t t,
        libxl__device *device, char **bents, char **fents)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *frontend_path, *backend_path;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions backend_perms[2];
    int create_transaction = t == XBT_NULL;

    frontend_path = libxl__device_frontend_path(gc, device);
    backend_path = libxl__device_backend_path(gc, device);

    frontend_perms[0].id = device->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = device->backend_domid;
    frontend_perms[1].perms = XS_PERM_READ;

    backend_perms[0].id = device->backend_domid;
    backend_perms[0].perms = XS_PERM_NONE;
    backend_perms[1].id = device->domid;
    backend_perms[1].perms = XS_PERM_READ;

retry_transaction:
    if (create_transaction)
        t = xs_transaction_start(ctx->xsh);
    /* FIXME: read frontend_path and check state before removing stuff */

    if (fents) {
        xs_rm(ctx->xsh, t, frontend_path);
        xs_mkdir(ctx->xsh, t, frontend_path);
        xs_set_permissions(ctx->xsh, t, frontend_path, frontend_perms, ARRAY_SIZE(frontend_perms));
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/backend", frontend_path), backend_path, strlen(backend_path));
        libxl__xs_writev(gc, t, frontend_path, fents);
    }

    if (bents) {
        xs_rm(ctx->xsh, t, backend_path);
        xs_mkdir(ctx->xsh, t, backend_path);
        xs_set_permissions(ctx->xsh, t, backend_path, backend_perms, ARRAY_SIZE(backend_perms));
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/frontend", backend_path), frontend_path, strlen(frontend_path));
        libxl__xs_writev(gc, t, backend_path, bents);
    }

    if (!create_transaction)
        return 0;

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xs transaction failed");
            return ERROR_FAIL;
        }
    }
    return 0;
}

typedef struct {
    libxl__gc *gc;
    libxl_device_disk *disk;
    struct stat stab;
} disk_try_backend_args;

static int disk_try_backend(disk_try_backend_args *a,
                            libxl_disk_backend backend) {
    /* returns 0 (ie, DISK_BACKEND_UNKNOWN) on failure, or
     * backend on success */
    libxl_ctx *ctx = libxl__gc_owner(a->gc);
    switch (backend) {

    case LIBXL_DISK_BACKEND_PHY:
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_EMPTY)) {
            goto bad_format;
        }

        if (libxl__try_phy_backend(a->stab.st_mode))
            return backend;

        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend phy"
                   " unsuitable as phys path not a block device",
                   a->disk->vdev);
        return 0;

    case LIBXL_DISK_BACKEND_TAP:
        if (!libxl__blktap_enabled(a->gc)) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend tap"
                       " unsuitable because blktap not available",
                       a->disk->vdev);
            return 0;
        }
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_VHD)) {
            goto bad_format;
        }
        return backend;

    case LIBXL_DISK_BACKEND_QDISK:
        return backend;

    default:
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend "
                   " %d unknown", a->disk->vdev, backend);
        return 0;

    }
    abort(); /* notreached */

 bad_format:
    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend %s"
               " unsuitable due to format %s",
               a->disk->vdev,
               libxl_disk_backend_to_string(backend),
               libxl_disk_format_to_string(a->disk->format));
    return 0;
}

int libxl__device_disk_set_backend(libxl__gc *gc, libxl_device_disk *disk) {
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_disk_backend ok;
    disk_try_backend_args a;

    a.gc = gc;
    a.disk = disk;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s spec.backend=%s",
               disk->vdev,
               libxl_disk_backend_to_string(disk->backend));

    if (disk->format == LIBXL_DISK_FORMAT_EMPTY) {
        if (!disk->is_cdrom) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s is empty"
                       " but not cdrom",
                       disk->vdev);
            return ERROR_INVAL;
        }
        memset(&a.stab, 0, sizeof(a.stab));
    } else {
        if (stat(disk->pdev_path, &a.stab)) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s "
                             "failed to stat: %s",
                             disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
        if (!S_ISBLK(a.stab.st_mode) &
            !S_ISREG(a.stab.st_mode)) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s "
                             "phys path is not a block dev or file: %s",
                             disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
    }

    if (disk->backend != LIBXL_DISK_BACKEND_UNKNOWN) {
        ok= disk_try_backend(&a, disk->backend);
    } else {
        ok=
            disk_try_backend(&a, LIBXL_DISK_BACKEND_PHY) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_TAP) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_QDISK);
        if (ok)
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, using backend %s",
                       disk->vdev,
                       libxl_disk_backend_to_string(ok));
    }
    if (!ok) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "no suitable backend for disk %s",
                   disk->vdev);
        return ERROR_INVAL;
    }
    disk->backend = ok;
    return 0;
}

char *libxl__device_disk_string_of_format(libxl_disk_format format)
{
    switch (format) {
        case LIBXL_DISK_FORMAT_QCOW: return "qcow";
        case LIBXL_DISK_FORMAT_QCOW2: return "qcow2";
        case LIBXL_DISK_FORMAT_VHD: return "vhd";
        case LIBXL_DISK_FORMAT_RAW:
        case LIBXL_DISK_FORMAT_EMPTY: return "aio";
        default: return NULL;
    }
}

char *libxl__device_disk_string_of_backend(libxl_disk_backend backend)
{
    switch (backend) {
        case LIBXL_DISK_BACKEND_QDISK: return "qdisk";
        case LIBXL_DISK_BACKEND_TAP: return "phy";
        case LIBXL_DISK_BACKEND_PHY: return "phy";
        default: return NULL;
    }
}

int libxl__device_physdisk_major_minor(const char *physpath, int *major, int *minor)
{
    struct stat buf;
    if (stat(physpath, &buf) < 0)
        return -1;
    *major = major(buf.st_rdev);
    *minor = minor(buf.st_rdev);
    return 0;
}

static int device_virtdisk_matches(const char *virtpath, const char *devtype,
                                   int *index_r, int max_index,
                                   int *partition_r, int max_partition) {
    const char *p;
    char *ep;
    int tl, c;
    long pl;

    tl = strlen(devtype);
    if (memcmp(virtpath, devtype, tl))
        return 0;

    /* We decode the drive letter as if it were in base 52
     * with digits a-zA-Z, more or less */
    *index_r = -1;
    p = virtpath + tl;
    for (;;) {
        c = *p++;
        if (c >= 'a' && c <= 'z') {
            c -= 'a';
        } else {
            --p;
            break;
        }
        (*index_r)++;
        (*index_r) *= 26;
        (*index_r) += c;

        if (*index_r > max_index)
            return 0;
    }

    if (!*p) {
        *partition_r = 0;
        return 1;
    }

    if (*p=='0')
        return 0; /* leading zeroes not permitted in partition number */

    pl = strtoul(p, &ep, 10);
    if (pl > max_partition || *ep)
        return 0;

    *partition_r = pl;
    return 1;
}

int libxl__device_disk_dev_number(const char *virtpath, int *pdisk,
                                  int *ppartition)
{
    int disk, partition;
    char *ep;
    unsigned long ul;
    int chrused;

    chrused = -1;
    if ((sscanf(virtpath, "d%ip%i%n", &disk, &partition, &chrused)  >= 2
         && chrused == strlen(virtpath) && disk < (1<<20) && partition < 256)
        ||
        device_virtdisk_matches(virtpath, "xvd",
                                &disk, (1<<20)-1,
                                &partition, 255)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        if (disk <= 15 && partition <= 15)
            return (202 << 8) | (disk << 4) | partition;
        else
            return (1 << 28) | (disk << 8) | partition;
    }

    errno = 0;
    ul = strtoul(virtpath, &ep, 0);
    if (!errno && !*ep && ul <= INT_MAX) {
        /* FIXME: should parse ul to determine these. */
        if (pdisk || ppartition)
            return -1;
        return ul;
    }

    if (device_virtdisk_matches(virtpath, "hd",
                                &disk, 3,
                                &partition, 63)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        return ((disk<2 ? 3 : 22) << 8) | ((disk & 1) << 6) | partition;
    }
    if (device_virtdisk_matches(virtpath, "sd",
                                &disk, 15,
                                &partition, 15)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        return (8 << 8) | (disk << 4) | partition;
    }
    return -1;
}

/* Device AO operations */

void libxl__prepare_ao_device(libxl__ao *ao, libxl__ao_device *aodev)
{
    aodev->ao = ao;
    aodev->rc = 0;
    aodev->dev = NULL;
    /* Initialize timer for QEMU Bodge */
    libxl__ev_time_init(&aodev->timeout);
    aodev->active = 1;
}

void libxl__prepare_ao_devices(libxl__ao *ao, libxl__ao_devices *aodevs)
{
    AO_GC;

    GCNEW_ARRAY(aodevs->array, aodevs->size);
    for (int i = 0; i < aodevs->size; i++) {
        aodevs->array[i].aodevs = aodevs;
        libxl__prepare_ao_device(ao, &aodevs->array[i]);
    }
}

void libxl__ao_devices_callback(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__ao_devices *aodevs = aodev->aodevs;
    int i, error = 0;

    aodev->active = 0;
    for (i = 0; i < aodevs->size; i++) {
        if (aodevs->array[i].active)
            return;

        if (aodevs->array[i].rc)
            error = aodevs->array[i].rc;
    }

    aodevs->callback(egc, aodevs, error);
    return;
}

int libxl__device_destroy(libxl__gc *gc, libxl__device *dev)
{
    char *be_path = libxl__device_backend_path(gc, dev);
    char *fe_path = libxl__device_frontend_path(gc, dev);
    xs_transaction_t t = 0;
    int rc = 0;

    do {
        t = xs_transaction_start(CTX->xsh);
        libxl__xs_path_cleanup(gc, t, fe_path);
        libxl__xs_path_cleanup(gc, t, be_path);
        rc = !xs_transaction_end(CTX->xsh, t, 0);
    } while (rc && errno == EAGAIN);
    if (rc) {
        LOGE(ERROR, "unable to finish transaction");
        goto out;
    }

    libxl__device_destroy_tapdisk(gc, be_path);

out:
    return rc;
}

/* Callback for device destruction */

static void devices_remove_callback(libxl__egc *egc, libxl__ao_devices *aodevs,
                                    int rc);

void libxl__devices_destroy(libxl__egc *egc, libxl__devices_remove_state *drs)
{
    STATE_AO_GC(drs->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    uint32_t domid = drs->domid;
    char *path;
    unsigned int num_kinds, num_dev_xsentries;
    char **kinds = NULL, **devs = NULL;
    int i, j, numdev = 0, rc = 0;
    libxl__device *dev;
    libxl__ao_devices *aodevs = &drs->aodevs;
    libxl__ao_device *aodev;
    libxl__device_kind kind;

    aodevs->size = libxl__num_devices(gc, drs->domid);
    if (aodevs->size < 0) {
        LOG(ERROR, "unable to get number of devices for domain %u", drs->domid);
        rc = aodevs->size;
        goto out;
    }

    libxl__prepare_ao_devices(drs->ao, aodevs);
    aodevs->callback = devices_remove_callback;

    path = libxl__sprintf(gc, "/local/domain/%d/device", domid);
    kinds = libxl__xs_directory(gc, XBT_NULL, path, &num_kinds);
    if (!kinds) {
        if (errno != ENOENT) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to get xenstore"
                             " device listing %s", path);
            goto out;
        }
        num_kinds = 0;
    }
    for (i = 0; i < num_kinds; i++) {
        if (libxl__device_kind_from_string(kinds[i], &kind))
            continue;

        path = libxl__sprintf(gc, "/local/domain/%d/device/%s", domid, kinds[i]);
        devs = libxl__xs_directory(gc, XBT_NULL, path, &num_dev_xsentries);
        if (!devs)
            continue;
        for (j = 0; j < num_dev_xsentries; j++) {
            path = libxl__sprintf(gc, "/local/domain/%d/device/%s/%s/backend",
                                  domid, kinds[i], devs[j]);
            path = libxl__xs_read(gc, XBT_NULL, path);
            GCNEW(dev);
            if (path && libxl__parse_backend_path(gc, path, dev) == 0) {
                aodev = &aodevs->array[numdev];
                dev->domid = domid;
                dev->kind = kind;
                dev->devid = atoi(devs[j]);
                aodev->action = DEVICE_DISCONNECT;
                aodev->dev = dev;
                aodev->callback = libxl__ao_devices_callback;
                aodev->force = drs->force;
                libxl__initiate_device_remove(egc, aodev);
                numdev++;
            }
        }
    }

    /* console 0 frontend directory is not under /local/domain/<domid>/device */
    path = libxl__sprintf(gc, "/local/domain/%d/console/backend", domid);
    path = libxl__xs_read(gc, XBT_NULL, path);
    GCNEW(dev);
    if (path && strcmp(path, "") &&
        libxl__parse_backend_path(gc, path, dev) == 0) {
        dev->domid = domid;
        dev->kind = LIBXL__DEVICE_KIND_CONSOLE;
        dev->devid = 0;

        /* Currently console devices can be destroyed synchronously by just
         * removing xenstore entries, this is what libxl__device_destroy does.
         */
        libxl__device_destroy(gc, dev);
    }

out:
    if (!numdev) drs->callback(egc, drs, rc);
    return;
}

/* Callbacks for device related operations */

/*
 * device_backend_callback is the main callback entry point, for both device
 * addition and removal. It gets called if we reach the desired state
 * (XenbusStateClosed or XenbusStateInitWait). After that, all this
 * functions get called in the order displayed below.
 *
 * If new device types are added, they should only need to modify the
 * specific hotplug scripts call, which can be found in each OS specific
 * file. If this new devices don't need a hotplug script, no modification
 * should be needed.
 */

/* This callback is part of the Qemu devices Badge */
static void device_qemu_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                const struct timeval *requested_abs);

static void device_backend_callback(libxl__egc *egc, libxl__ev_devstate *ds,
                                   int rc);

static void device_backend_cleanup(libxl__gc *gc,
                                   libxl__ao_device *aodev);

static void device_hotplug_done(libxl__egc *egc, libxl__ao_device *aodev);

void libxl__initiate_device_remove(libxl__egc *egc,
                                   libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    xs_transaction_t t = 0;
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *state_path = libxl__sprintf(gc, "%s/state", be_path);
    char *online_path = GCSPRINTF("%s/online", be_path);
    const char *state;
    libxl_dominfo info;
    uint32_t domid = aodev->dev->domid;
    int rc = 0;

    libxl_dominfo_init(&info);
    rc = libxl_domain_info(CTX, &info, domid);
    if (rc) {
        LOG(ERROR, "unable to get info for domain %d", domid);
        goto out;
    }
    if (QEMU_BACKEND(aodev->dev) &&
        (info.paused || info.dying || info.shutdown)) {
        /*
         * TODO: 4.2 Bodge due to QEMU, see comment on top of
         * libxl__initiate_device_remove in libxl_internal.h
         */
        rc = libxl__ev_time_register_rel(gc, &aodev->timeout,
                                         device_qemu_timeout,
                                         LIBXL_QEMU_BODGE_TIMEOUT * 1000);
        if (rc) {
            LOG(ERROR, "unable to register timeout for Qemu device %s",
                       be_path);
            goto out;
        }
        return;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) {
            LOG(ERROR, "unable to start transaction");
            goto out;
        }

        if (aodev->force)
            libxl__xs_path_cleanup(gc, t,
                                   libxl__device_frontend_path(gc, aodev->dev));

        rc = libxl__xs_read_checked(gc, t, state_path, &state);
        if (rc) {
            LOG(ERROR, "unable to read device state from path %s", state_path);
            goto out;
        }

        /*
         * Check if device is already in "closed" state, in which case
         * it should not be changed.
         */
         if (state && atoi(state) != XenbusStateClosed) {
            rc = libxl__xs_write_checked(gc, t, online_path, "0");
            if (rc) {
                LOG(ERROR, "unable to write to xenstore path %s", online_path);
                goto out;
            }
            rc = libxl__xs_write_checked(gc, t, state_path, "5");
            if (rc) {
                LOG(ERROR, "unable to write to xenstore path %s", state_path);
                goto out;
            }
        }

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    libxl__device_destroy_tapdisk(gc, be_path);

    rc = libxl__ev_devstate_wait(gc, &aodev->backend_ds,
                                 device_backend_callback,
                                 state_path, XenbusStateClosed,
                                 LIBXL_DESTROY_TIMEOUT * 1000);
    if (rc) {
        LOG(ERROR, "unable to remove device %s", be_path);
        goto out;
    }

    libxl_dominfo_dispose(&info);
    return;

out:
    aodev->rc = rc;
    libxl_dominfo_dispose(&info);
    libxl__xs_transaction_abort(gc, &t);
    device_hotplug_done(egc, aodev);
    return;
}

static void device_qemu_timeout(libxl__egc *egc, libxl__ev_time *ev,
                                const struct timeval *requested_abs)
{
    libxl__ao_device *aodev = CONTAINER_OF(ev, *aodev, timeout);
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *state_path = GCSPRINTF("%s/state", be_path);
    int rc = 0;

    libxl__ev_time_deregister(gc, &aodev->timeout);

    rc = libxl__xs_write_checked(gc, XBT_NULL, state_path, "6");
    if (rc) goto out;

out:
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
}

static void device_backend_callback(libxl__egc *egc, libxl__ev_devstate *ds,
                                   int rc) {
    libxl__ao_device *aodev = CONTAINER_OF(ds, *aodev, backend_ds);
    STATE_AO_GC(aodev->ao);

    device_backend_cleanup(gc, aodev);

    if (rc == ERROR_TIMEDOUT && aodev->action == DEVICE_DISCONNECT &&
        !aodev->force) {
        aodev->force = 1;
        libxl__initiate_device_remove(egc, aodev);
        return;
    }

    if (rc) {
        LOG(ERROR, "unable to disconnect device with path %s",
                   libxl__device_backend_path(gc, aodev->dev));
        goto out;
    }

out:
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
    return;
}

static void device_backend_cleanup(libxl__gc *gc, libxl__ao_device *aodev)
{
    if (!aodev) return;
    libxl__ev_devstate_cancel(gc, &aodev->backend_ds);
}

static void device_hotplug_done(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *fe_path = libxl__device_frontend_path(gc, aodev->dev);
    xs_transaction_t t = 0;
    int rc;

    if (aodev->action == DEVICE_DISCONNECT) {
        for (;;) {
            rc = libxl__xs_transaction_start(gc, &t);
            if (rc) goto out;

            libxl__xs_path_cleanup(gc, t, fe_path);
            libxl__xs_path_cleanup(gc, t, be_path);

            rc = libxl__xs_transaction_commit(gc, &t);
            if (!rc) break;
            if (rc < 0) goto out;
        }
    }

out:
    aodev->callback(egc, aodev);
    return;
}

static void devices_remove_callback(libxl__egc *egc, libxl__ao_devices *aodevs,
                                    int rc)
{
    libxl__devices_remove_state *drs = CONTAINER_OF(aodevs, *drs, aodevs);
    STATE_AO_GC(drs->ao);

    drs->callback(egc, drs, rc);
    return;
}

int libxl__wait_for_device_model(libxl__gc *gc,
                                 uint32_t domid, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata)
{
    char *path;
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    return libxl__wait_for_offspring(gc, domid,
                                     LIBXL_DEVICE_MODEL_START_TIMEOUT,
                                     "Device Model", path, state, spawning,
                                     check_callback, check_callback_userdata);
}

int libxl__wait_for_backend(libxl__gc *gc, char *be_path, char *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int watchdog = 100;
    unsigned int len;
    char *p;
    char *path = libxl__sprintf(gc, "%s/state", be_path);
    int rc = -1;

    while (watchdog > 0) {
        p = xs_read(ctx->xsh, XBT_NULL, path, &len);
        if (p == NULL) {
            if (errno == ENOENT) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Backend %s does not exist",
                       be_path);
            } else {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to access backend %s",
                       be_path);
            }
            goto out;
        } else {
            if (!strcmp(p, state)) {
                rc = 0;
                goto out;
            } else {
                usleep(100000);
                watchdog--;
            }
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Backend %s not ready", be_path);
out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
