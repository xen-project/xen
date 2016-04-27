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
        return GCSPRINTF("%s/console", dom_path);

    return GCSPRINTF("%s/device/%s/%d", dom_path,
                     libxl__device_kind_to_string(device->kind),
                     device->devid);
}

char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->backend_domid);

    return GCSPRINTF("%s/backend/%s/%u/%d", dom_path,
                     libxl__device_kind_to_string(device->backend_kind),
                     device->domid, device->devid);
}

char *libxl__device_libxl_path(libxl__gc *gc, libxl__device *device)
{
    char *libxl_dom_path = libxl__xs_libxl_path(gc, device->domid);

    return GCSPRINTF("%s/device/%s/%d", libxl_dom_path,
                     libxl__device_kind_to_string(device->kind),
                     device->devid);
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

int libxl__nic_type(libxl__gc *gc, libxl__device *dev, libxl_nic_type *nictype)
{
    char *snictype, *be_path;
    int rc = 0;

    be_path = libxl__device_backend_path(gc, dev);
    snictype = libxl__xs_read(gc, XBT_NULL,
                              GCSPRINTF("%s/%s", be_path, "type"));
    if (!snictype) {
        LOGE(ERROR, "unable to read nictype from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl_nic_type_from_string(snictype, nictype);
    if (rc) {
        LOGE(ERROR, "unable to parse nictype from %s", be_path);
        goto out;
    }

    rc = 0;

out:
    return rc;
}

int libxl__device_generic_add(libxl__gc *gc, xs_transaction_t t,
        libxl__device *device, char **bents, char **fents, char **ro_fents)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *frontend_path, *backend_path, *libxl_path;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions ro_frontend_perms[2];
    struct xs_permissions backend_perms[2];
    int create_transaction = t == XBT_NULL;
    int rc;

    frontend_path = libxl__device_frontend_path(gc, device);
    backend_path = libxl__device_backend_path(gc, device);
    libxl_path = libxl__device_libxl_path(gc, device);

    frontend_perms[0].id = device->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = device->backend_domid;
    frontend_perms[1].perms = XS_PERM_READ;

    ro_frontend_perms[0].id = backend_perms[0].id = device->backend_domid;
    ro_frontend_perms[0].perms = backend_perms[0].perms = XS_PERM_NONE;
    ro_frontend_perms[1].id = backend_perms[1].id = device->domid;
    ro_frontend_perms[1].perms = backend_perms[1].perms = XS_PERM_READ;

retry_transaction:
    if (create_transaction)
        t = xs_transaction_start(ctx->xsh);

    /* FIXME: read frontend_path and check state before removing stuff */

    rc = libxl__xs_rm_checked(gc, t, libxl_path);
    if (rc) goto out;

    rc = libxl__xs_write_checked(gc, t, GCSPRINTF("%s/frontend",libxl_path),
                                 frontend_path);
    if (rc) goto out;

    rc = libxl__xs_write_checked(gc, t, GCSPRINTF("%s/backend",libxl_path),
                                 backend_path);
    if (rc) goto out;

    /* xxx much of this function lacks error checks! */

    if (fents || ro_fents) {
        xs_rm(ctx->xsh, t, frontend_path);
        xs_mkdir(ctx->xsh, t, frontend_path);
        /* Console 0 is a special case. It doesn't use the regular PV
         * state machine but also the frontend directory has
         * historically contained other information, such as the
         * vnc-port, which we don't want the guest fiddling with.
         */
        if (device->kind == LIBXL__DEVICE_KIND_CONSOLE && device->devid == 0)
            xs_set_permissions(ctx->xsh, t, frontend_path,
                               ro_frontend_perms, ARRAY_SIZE(ro_frontend_perms));
        else
            xs_set_permissions(ctx->xsh, t, frontend_path,
                               frontend_perms, ARRAY_SIZE(frontend_perms));
        xs_write(ctx->xsh, t, GCSPRINTF("%s/backend", frontend_path),
                 backend_path, strlen(backend_path));
        if (fents)
            libxl__xs_writev_perms(gc, t, frontend_path, fents,
                                   frontend_perms, ARRAY_SIZE(frontend_perms));
        if (ro_fents)
            libxl__xs_writev_perms(gc, t, frontend_path, ro_fents,
                                   ro_frontend_perms, ARRAY_SIZE(ro_frontend_perms));
    }

    if (bents) {
        xs_rm(ctx->xsh, t, backend_path);
        xs_mkdir(ctx->xsh, t, backend_path);
        xs_set_permissions(ctx->xsh, t, backend_path, backend_perms, ARRAY_SIZE(backend_perms));
        xs_write(ctx->xsh, t, GCSPRINTF("%s/frontend", backend_path),
                 frontend_path, strlen(frontend_path));
        libxl__xs_writev(gc, t, backend_path, bents);
    }

    if (!create_transaction)
        return 0;

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else {
            LOGE(ERROR, "xs transaction failed");
            return ERROR_FAIL;
        }
    }
    return 0;

 out:
    if (create_transaction && t)
        libxl__xs_transaction_abort(gc, &t);
    return rc;
}

typedef struct {
    libxl__gc *gc;
    libxl_device_disk *disk;
    struct stat stab;
} disk_try_backend_args;

static int disk_try_backend(disk_try_backend_args *a,
                            libxl_disk_backend backend)
 {
    libxl__gc *gc = a->gc;
    /* returns 0 (ie, DISK_BACKEND_UNKNOWN) on failure, or
     * backend on success */

    switch (backend) {
    case LIBXL_DISK_BACKEND_PHY:
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_EMPTY)) {
            goto bad_format;
        }

        if (a->disk->backend_domid != LIBXL_TOOLSTACK_DOMID) {
            LOG(DEBUG, "Disk vdev=%s, is using a storage driver domain, "
                       "skipping physical device check", a->disk->vdev);
            return backend;
        }

        if (a->disk->script) {
            LOG(DEBUG, "Disk vdev=%s, uses script=... assuming phy backend",
                a->disk->vdev);
            return backend;
        }

        if (libxl__try_phy_backend(a->stab.st_mode))
            return backend;

        LOG(DEBUG, "Disk vdev=%s, backend phy unsuitable as phys path not a "
                   "block device", a->disk->vdev);
        return 0;

    case LIBXL_DISK_BACKEND_TAP:
        if (a->disk->script) goto bad_script;

        if (a->disk->is_cdrom) {
            LOG(DEBUG, "Disk vdev=%s, backend tap unsuitable for cdroms",
                       a->disk->vdev);
            return 0;
        }
        if (!libxl__blktap_enabled(a->gc)) {
            LOG(DEBUG, "Disk vdev=%s, backend tap unsuitable because blktap "
                       "not available", a->disk->vdev);
            return 0;
        }
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_VHD)) {
            goto bad_format;
        }
        return backend;

    case LIBXL_DISK_BACKEND_QDISK:
        if (a->disk->script) goto bad_script;
        return backend;

    default:
        LOG(DEBUG, "Disk vdev=%s, backend %d unknown", a->disk->vdev, backend);
        return 0;

    }
    abort(); /* notreached */

 bad_format:
    LOG(DEBUG, "Disk vdev=%s, backend %s unsuitable due to format %s",
               a->disk->vdev,
               libxl_disk_backend_to_string(backend),
               libxl_disk_format_to_string(a->disk->format));
    return 0;

 bad_script:
    LOG(DEBUG, "Disk vdev=%s, backend %s not compatible with script=...",
        a->disk->vdev, libxl_disk_backend_to_string(backend));
    return 0;
}

int libxl__backendpath_parse_domid(libxl__gc *gc, const char *be_path,
                                   libxl_domid *domid_out) {
    int r;
    unsigned int domid_sc;
    char delim_sc;

    r = sscanf(be_path, "/local/domain/%u%c", &domid_sc, &delim_sc);
    if (!(r==2 && delim_sc=='/')) {
        LOG(ERROR, "internal error: backend path %s unparseable!", be_path);
        return ERROR_FAIL;
    }
    *domid_out = domid_sc;
    return 0;
}

int libxl__device_disk_set_backend(libxl__gc *gc, libxl_device_disk *disk) {
    libxl_disk_backend ok;
    disk_try_backend_args a;

    a.gc = gc;
    a.disk = disk;

    LOG(DEBUG, "Disk vdev=%s spec.backend=%s", disk->vdev,
               libxl_disk_backend_to_string(disk->backend));

    if (disk->format == LIBXL_DISK_FORMAT_EMPTY) {
        if (!disk->is_cdrom) {
            LOG(ERROR, "Disk vdev=%s is empty but not cdrom", disk->vdev);
            return ERROR_INVAL;
        }
        memset(&a.stab, 0, sizeof(a.stab));
    } else if ((disk->backend == LIBXL_DISK_BACKEND_UNKNOWN ||
                disk->backend == LIBXL_DISK_BACKEND_PHY) &&
               disk->backend_domid == LIBXL_TOOLSTACK_DOMID &&
               !disk->script) {
        if (stat(disk->pdev_path, &a.stab)) {
            LOGE(ERROR, "Disk vdev=%s failed to stat: %s",
                        disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
        if (!S_ISBLK(a.stab.st_mode) &
            !S_ISREG(a.stab.st_mode)) {
            LOG(ERROR, "Disk vdev=%s phys path is not a block dev or file: %s",
                       disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
    }

    if (disk->backend != LIBXL_DISK_BACKEND_UNKNOWN) {
        ok= disk_try_backend(&a, disk->backend);
    } else {
        ok=
            disk_try_backend(&a, LIBXL_DISK_BACKEND_PHY) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_QDISK) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_TAP);
        if (ok)
            LOG(DEBUG, "Disk vdev=%s, using backend %s",
                       disk->vdev,
                       libxl_disk_backend_to_string(ok));
    }
    if (!ok) {
        LOG(ERROR, "no suitable backend for disk %s", disk->vdev);
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
    aodev->num_exec = 0;
    /* Initialize timer for QEMU Bodge and hotplug execution */
    libxl__ev_time_init(&aodev->timeout);
    /*
     * Initialize xs_watch, because it's not used on all possible
     * execution paths, but it's unconditionally destroyed when finished.
     */
    libxl__ev_xswatch_init(&aodev->xs_watch);
    aodev->active = 1;
    /* We init this here because we might call device_hotplug_done
     * without actually calling any hotplug script */
    libxl__ev_child_init(&aodev->child);
}

/* multidev */

void libxl__multidev_begin(libxl__ao *ao, libxl__multidev *multidev)
{
    AO_GC;

    multidev->ao = ao;
    multidev->array = 0;
    multidev->used = multidev->allocd = 0;

    /* We allocate an aodev to represent the operation of preparing
     * all of the other operations.  This operation is completed when
     * we have started all the others (ie, when the user calls
     * _prepared).  That arranges automatically that
     *  (i) we do not think we have finished even if one of the
     *      operations completes while we are still preparing
     *  (ii) if we are starting zero operations, we do still
     *      make the callback as soon as we know this fact
     *  (iii) we have a nice consistent way to deal with any
     *      error that might occur while deciding what to initiate
     */
    multidev->preparation = libxl__multidev_prepare(multidev);
}

static void multidev_one_callback(libxl__egc *egc, libxl__ao_device *aodev);

libxl__ao_device *libxl__multidev_prepare(libxl__multidev *multidev) {
    STATE_AO_GC(multidev->ao);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    aodev->multidev = multidev;
    aodev->callback = multidev_one_callback;
    libxl__prepare_ao_device(ao, aodev);

    if (multidev->used >= multidev->allocd) {
        multidev->allocd = multidev->used * 2 + 5;
        GCREALLOC_ARRAY(multidev->array, multidev->allocd);
    }
    multidev->array[multidev->used++] = aodev;

    return aodev;
}

static void multidev_one_callback(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__multidev *multidev = aodev->multidev;
    int i, error = 0;

    aodev->active = 0;

    for (i = 0; i < multidev->used; i++) {
        if (multidev->array[i]->active)
            return;

        if (multidev->array[i]->rc)
            error = multidev->array[i]->rc;
    }

    multidev->callback(egc, multidev, error);
    return;
}

void libxl__multidev_prepared(libxl__egc *egc,
                              libxl__multidev *multidev, int rc)
{
    multidev->preparation->rc = rc;
    multidev_one_callback(egc, multidev->preparation);
}

/******************************************************************************/

/* Macro for defining the functions that will add a bunch of disks when
 * inside an async op with multidev.
 * This macro is added to prevent repetition of code.
 *
 * The following functions are defined:
 * libxl__add_disks
 * libxl__add_nics
 * libxl__add_vtpms
 */

#define DEFINE_DEVICES_ADD(type)                                        \
    void libxl__add_##type##s(libxl__egc *egc, libxl__ao *ao, uint32_t domid, \
                              libxl_domain_config *d_config,            \
                              libxl__multidev *multidev)                \
    {                                                                   \
        AO_GC;                                                          \
        int i;                                                          \
        for (i = 0; i < d_config->num_##type##s; i++) {                 \
            libxl__ao_device *aodev = libxl__multidev_prepare(multidev);  \
            libxl__device_##type##_add(egc, domid, &d_config->type##s[i], \
                                       aodev);                          \
        }                                                               \
    }

DEFINE_DEVICES_ADD(disk)
DEFINE_DEVICES_ADD(nic)
DEFINE_DEVICES_ADD(vtpm)

#undef DEFINE_DEVICES_ADD

/******************************************************************************/

int libxl__device_destroy(libxl__gc *gc, libxl__device *dev)
{
    const char *be_path = libxl__device_backend_path(gc, dev);
    const char *fe_path = libxl__device_frontend_path(gc, dev);
    const char *libxl_path = libxl__device_libxl_path(gc, dev);
    const char *tapdisk_path = GCSPRINTF("%s/%s", be_path, "tapdisk-params");
    const char *tapdisk_params;
    xs_transaction_t t = 0;
    int rc;
    uint32_t domid;

    rc = libxl__get_domid(gc, &domid);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        /* May not exist if this is not a tap device */
        rc = libxl__xs_read_checked(gc, t, tapdisk_path, &tapdisk_params);
        if (rc) goto out;

        if (domid == LIBXL_TOOLSTACK_DOMID) {
            /*
             * The toolstack domain is in charge for removing both the
             * frontend and the backend path
             */
            libxl__xs_path_cleanup(gc, t, fe_path);
            libxl__xs_path_cleanup(gc, t, be_path);
            libxl__xs_path_cleanup(gc, t, libxl_path);
        } else if (dev->backend_domid == domid) {
            /*
             * The driver domain is in charge for removing what it can
             * from the backend path
             */
            libxl__xs_path_cleanup(gc, t, be_path);
        }

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    if (tapdisk_params)
        rc = libxl__device_destroy_tapdisk(gc, tapdisk_params);

out:
    libxl__xs_transaction_abort(gc, &t);
    return rc;
}

/* Callback for device destruction */

static void devices_remove_callback(libxl__egc *egc,
                                    libxl__multidev *multidev, int rc);

void libxl__devices_destroy(libxl__egc *egc, libxl__devices_remove_state *drs)
{
    STATE_AO_GC(drs->ao);
    uint32_t domid = drs->domid;
    char *path;
    unsigned int num_kinds, num_dev_xsentries;
    char **kinds = NULL, **devs = NULL;
    int i, j, rc = 0;
    libxl__device *dev;
    libxl__multidev *multidev = &drs->multidev;
    libxl__ao_device *aodev;
    libxl__device_kind kind;

    libxl__multidev_begin(ao, multidev);
    multidev->callback = devices_remove_callback;

    path = GCSPRINTF("/local/domain/%d/device", domid);
    kinds = libxl__xs_directory(gc, XBT_NULL, path, &num_kinds);
    if (!kinds) {
        if (errno != ENOENT) {
            LOGE(ERROR, "unable to get xenstore device listing %s", path);
            goto out;
        }
        num_kinds = 0;
    }
    for (i = 0; i < num_kinds; i++) {
        if (libxl__device_kind_from_string(kinds[i], &kind))
            continue;

        path = GCSPRINTF("/local/domain/%d/device/%s", domid, kinds[i]);
        devs = libxl__xs_directory(gc, XBT_NULL, path, &num_dev_xsentries);
        if (!devs)
            continue;
        for (j = 0; j < num_dev_xsentries; j++) {
            path = GCSPRINTF("/local/domain/%d/device/%s/%s/backend",
                             domid, kinds[i], devs[j]);
            path = libxl__xs_read(gc, XBT_NULL, path);
            GCNEW(dev);
            if (path && libxl__parse_backend_path(gc, path, dev) == 0) {
                dev->domid = domid;
                dev->kind = kind;
                dev->devid = atoi(devs[j]);
                if (dev->backend_kind == LIBXL__DEVICE_KIND_CONSOLE) {
                    /* Currently console devices can be destroyed
                     * synchronously by just removing xenstore entries,
                     * this is what libxl__device_destroy does.
                     */
                    libxl__device_destroy(gc, dev);
                    continue;
                }
                aodev = libxl__multidev_prepare(multidev);
                aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
                aodev->dev = dev;
                aodev->force = drs->force;
                libxl__initiate_device_remove(egc, aodev);
            }
        }
    }

    /* console 0 frontend directory is not under /local/domain/<domid>/device */
    path = GCSPRINTF("/local/domain/%d/console/backend", domid);
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
    libxl__multidev_prepared(egc, multidev, rc);
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

static void device_hotplug(libxl__egc *egc, libxl__ao_device *aodev);

static void device_hotplug_timeout_cb(libxl__egc *egc, libxl__ev_time *ev,
                                      const struct timeval *requested_abs);

static void device_hotplug_child_death_cb(libxl__egc *egc,
                                          libxl__ev_child *child,
                                          pid_t pid, int status);

static void device_destroy_be_timeout_cb(libxl__egc *egc, libxl__ev_time *ev,
                                         const struct timeval *requested_abs);

static void device_destroy_be_watch_cb(libxl__egc *egc,
                                       libxl__ev_xswatch *watch,
                                       const char *watch_path,
                                       const char *event_path);

static void device_hotplug_done(libxl__egc *egc, libxl__ao_device *aodev);

static void device_hotplug_clean(libxl__gc *gc, libxl__ao_device *aodev);

void libxl__wait_device_connection(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *state_path = GCSPRINTF("%s/state", be_path);
    int rc = 0;

    if (QEMU_BACKEND(aodev->dev)) {
        /*
         * If Qemu is not running, there's no point in waiting for
         * it to change the state of the device.
         *
         * If Qemu is running, it will set the state of the device to
         * 4 directly, without waiting in state 2 for any hotplug execution.
         */
        device_hotplug(egc, aodev);
        return;
    }

    rc = libxl__ev_devstate_wait(gc, &aodev->backend_ds,
                                 device_backend_callback,
                                 state_path, XenbusStateInitWait,
                                 LIBXL_INIT_TIMEOUT * 1000);
    if (rc) {
        LOG(ERROR, "unable to initialize device %s", be_path);
        goto out;
    }

    return;

out:
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
    return;
}

void libxl__initiate_device_remove(libxl__egc *egc,
                                   libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    xs_transaction_t t = 0;
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *state_path = GCSPRINTF("%s/state", be_path);
    char *online_path = GCSPRINTF("%s/online", be_path);
    const char *state;
    libxl_dominfo info;
    uint32_t my_domid, domid = aodev->dev->domid;
    int rc = 0;

    libxl_dominfo_init(&info);

    rc = libxl__get_domid(gc, &my_domid);
    if (rc) {
        LOG(ERROR, "unable to get my domid");
        goto out;
    }

    if (my_domid == LIBXL_TOOLSTACK_DOMID) {
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
    const char *xs_state;
    xs_transaction_t t = 0;
    int rc = 0;

    libxl__ev_time_deregister(gc, &aodev->timeout);

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) {
            LOG(ERROR, "unable to start transaction");
            goto out;
        }

        /*
         * Check that the state path exists and is actually different than
         * 6 before unconditionally setting it. If Qemu runs on a driver
         * domain it is possible that the driver domain has already cleaned
         * the backend path if the device has reached state 6.
         */
        rc = libxl__xs_read_checked(gc, XBT_NULL, state_path, &xs_state);
        if (rc) goto out;

        if (xs_state && atoi(xs_state) != XenbusStateClosed) {
            rc = libxl__xs_write_checked(gc, XBT_NULL, state_path, "6");
            if (rc) goto out;
        }

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    device_hotplug(egc, aodev);
    return;

out:
    libxl__xs_transaction_abort(gc, &t);
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
}

static void device_backend_callback(libxl__egc *egc, libxl__ev_devstate *ds,
                                   int rc) {
    libxl__ao_device *aodev = CONTAINER_OF(ds, *aodev, backend_ds);
    STATE_AO_GC(aodev->ao);

    device_backend_cleanup(gc, aodev);

    if (rc == ERROR_TIMEDOUT &&
        aodev->action == LIBXL__DEVICE_ACTION_REMOVE &&
        !aodev->force) {
        aodev->force = 1;
        libxl__initiate_device_remove(egc, aodev);
        return;
    }

    if (rc) {
        LOG(ERROR, "unable to %s device with path %s",
                   libxl__device_action_to_string(aodev->action),
                   libxl__device_backend_path(gc, aodev->dev));
        goto out;
    }

    device_hotplug(egc, aodev);
    return;

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

static void device_hotplug(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char **args = NULL, **env = NULL;
    int rc = 0;
    int hotplug;
    pid_t pid;
    uint32_t domid;

    /*
     * If device is attached from a driver domain don't try to execute
     * hotplug scripts
     */
    rc = libxl__get_domid(gc, &domid);
    if (rc) goto out;
    if (aodev->dev->backend_domid != domid) {
        if (aodev->action != LIBXL__DEVICE_ACTION_REMOVE)
            goto out;

        rc = libxl__ev_time_register_rel(gc, &aodev->timeout,
                                         device_destroy_be_timeout_cb,
                                         LIBXL_DESTROY_TIMEOUT * 1000);
        if (rc) {
            LOG(ERROR, "setup of xs watch timeout failed");
            goto out;
        }

        rc = libxl__ev_xswatch_register(gc, &aodev->xs_watch,
                                        device_destroy_be_watch_cb,
                                        be_path);
        if (rc) {
            LOG(ERROR, "setup of xs watch for %s failed", be_path);
            libxl__ev_time_deregister(gc, &aodev->timeout);
            goto out;
        }
        return;
    }

    /* Check if we have to execute hotplug scripts for this device
     * and return the necessary args/env vars for execution */
    hotplug = libxl__get_hotplug_script_info(gc, aodev->dev, &args, &env,
                                             aodev->action,
                                             aodev->num_exec);
    switch (hotplug) {
    case 0:
        /* no hotplug script to execute */
        goto out;
    case 1:
        /* execute hotplug script */
        break;
    default:
        /* everything else is an error */
        LOG(ERROR, "unable to get args/env to execute hotplug script for "
                   "device %s", libxl__device_backend_path(gc, aodev->dev));
        rc = hotplug;
        goto out;
    }

    /* Set hotplug timeout */
    rc = libxl__ev_time_register_rel(gc, &aodev->timeout,
                                     device_hotplug_timeout_cb,
                                     LIBXL_HOTPLUG_TIMEOUT * 1000);
    if (rc) {
        LOG(ERROR, "unable to register timeout for hotplug device %s", be_path);
        goto out;
    }

    aodev->what = GCSPRINTF("%s %s", args[0], args[1]);
    LOG(DEBUG, "calling hotplug script: %s %s", args[0], args[1]);

    /* fork and execute hotplug script */
    pid = libxl__ev_child_fork(gc, &aodev->child, device_hotplug_child_death_cb);
    if (pid == -1) {
        LOG(ERROR, "unable to fork");
        rc = ERROR_FAIL;
        goto out;
    }

    if (!pid) {
        /* child */
        libxl__exec(gc, -1, -1, -1, args[0], args, env);
        /* notreached */
        abort();
    }

    assert(libxl__ev_child_inuse(&aodev->child));

    return;

out:
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
    return;
}

static void device_hotplug_timeout_cb(libxl__egc *egc, libxl__ev_time *ev,
                                      const struct timeval *requested_abs)
{
    libxl__ao_device *aodev = CONTAINER_OF(ev, *aodev, timeout);
    STATE_AO_GC(aodev->ao);

    libxl__ev_time_deregister(gc, &aodev->timeout);

    assert(libxl__ev_child_inuse(&aodev->child));
    LOG(DEBUG, "killing hotplug script %s because of timeout", aodev->what);
    if (kill(aodev->child.pid, SIGKILL)) {
        LOGEV(ERROR, errno, "unable to kill hotplug script %s [%ld]",
                            aodev->what, (unsigned long)aodev->child.pid);
    }

    return;
}

static void device_hotplug_child_death_cb(libxl__egc *egc,
                                          libxl__ev_child *child,
                                          pid_t pid, int status)
{
    libxl__ao_device *aodev = CONTAINER_OF(child, *aodev, child);
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *hotplug_error;

    device_hotplug_clean(gc, aodev);

    if (status) {
        libxl_report_child_exitstatus(CTX, LIBXL__LOG_ERROR,
                                      aodev->what, pid, status);
        hotplug_error = libxl__xs_read(gc, XBT_NULL,
                                       GCSPRINTF("%s/hotplug-error", be_path));
        if (hotplug_error)
            LOG(ERROR, "script: %s", hotplug_error);
        aodev->rc = ERROR_FAIL;
        if (aodev->action == LIBXL__DEVICE_ACTION_ADD)
            /*
             * Only fail on device connection, on disconnection
             * ignore error, and continue with the remove process
             */
             goto error;
    }

    /* Increase num_exec and call hotplug scripts again if necessary
     * If no more executions are needed, device_hotplug will call
     * device_hotplug_done breaking the loop.
     */
    aodev->num_exec++;
    device_hotplug(egc, aodev);

    return;

error:
    assert(aodev->rc);
    device_hotplug_done(egc, aodev);
}

static void device_destroy_be_timeout_cb(libxl__egc *egc, libxl__ev_time *ev,
                                         const struct timeval *requested_abs)
{
    libxl__ao_device *aodev = CONTAINER_OF(ev, *aodev, timeout);
    STATE_AO_GC(aodev->ao);

    LOG(ERROR, "timed out while waiting for %s to be removed",
               libxl__device_backend_path(gc, aodev->dev));

    aodev->rc = ERROR_TIMEDOUT;

    device_hotplug_done(egc, aodev);
    return;
}

static void device_destroy_be_watch_cb(libxl__egc *egc,
                                       libxl__ev_xswatch *watch,
                                       const char *watch_path,
                                       const char *event_path)
{
    libxl__ao_device *aodev = CONTAINER_OF(watch, *aodev, xs_watch);
    STATE_AO_GC(aodev->ao);
    const char *dir;
    int rc;

    rc = libxl__xs_read_checked(gc, XBT_NULL, watch_path, &dir);
    if (rc) {
        LOG(ERROR, "unable to read backend path: %s", watch_path);
        aodev->rc = rc;
        goto out;
    }
    if (dir) {
        /* backend path still exists, wait a little longer... */
        return;
    }

out:
    /* We are done, backend path no longer exists */
    device_hotplug_done(egc, aodev);
}

static void device_hotplug_done(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    int rc;

    device_hotplug_clean(gc, aodev);

    /* Clean xenstore if it's a disconnection */
    if (aodev->action == LIBXL__DEVICE_ACTION_REMOVE) {
        rc = libxl__device_destroy(gc, aodev->dev);
        if (!aodev->rc)
            aodev->rc = rc;
    }

    aodev->callback(egc, aodev);
    return;
}

static void device_hotplug_clean(libxl__gc *gc, libxl__ao_device *aodev)
{
    /* Clean events and check reentrancy */
    libxl__ev_time_deregister(gc, &aodev->timeout);
    libxl__ev_xswatch_deregister(gc, &aodev->xs_watch);
    assert(!libxl__ev_child_inuse(&aodev->child));
}

static void devices_remove_callback(libxl__egc *egc,
                                    libxl__multidev *multidev, int rc)
{
    libxl__devices_remove_state *drs = CONTAINER_OF(multidev, *drs, multidev);
    STATE_AO_GC(drs->ao);

    drs->callback(egc, drs, rc);
    return;
}

int libxl__wait_for_device_model_deprecated(libxl__gc *gc,
                                 uint32_t domid, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata)
{
    char *path;
    path = GCSPRINTF("/local/domain/0/device-model/%d/state", domid);
    return libxl__xenstore_child_wait_deprecated(gc, domid,
                                     LIBXL_DEVICE_MODEL_START_TIMEOUT,
                                     "Device Model", path, state, spawning,
                                     check_callback, check_callback_userdata);
}

int libxl__wait_for_backend(libxl__gc *gc, const char *be_path,
                            const char *state)
{
    int watchdog = 100;
    const char *p, *path = GCSPRINTF("%s/state", be_path);
    int rc;

    while (watchdog-- > 0) {
        rc = libxl__xs_read_checked(gc, XBT_NULL, path, &p);
        if (rc) return rc;

        if (p == NULL) {
            LOG(ERROR, "Backend %s does not exist", be_path);
            return ERROR_FAIL;
        }

        if (!strcmp(p, state))
            return 0;

        usleep(100000);
    }

    LOG(ERROR, "Backend %s not ready", be_path);
    return ERROR_FAIL;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
