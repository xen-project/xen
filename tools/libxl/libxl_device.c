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

static char *libxl__device_frontend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->domid);

    /* Console 0 is a special case */
    if (device->kind == LIBXL__DEVICE_KIND_CONSOLE && device->devid == 0)
        return GCSPRINTF("%s/%s", dom_path,
                         libxl__device_kind_to_string(device->kind));

    if (device->kind == LIBXL__DEVICE_KIND_VUART)
        return GCSPRINTF("%s/%s/%d", dom_path,
                         libxl__device_kind_to_string(device->kind),
                         device->devid);

    return GCSPRINTF("%s/device/%s/%d", dom_path,
                     libxl__device_kind_to_string(device->kind),
                     device->devid);
}

char *libxl__domain_device_frontend_path(libxl__gc *gc, uint32_t domid, uint32_t devid,
                                         libxl__device_kind device_kind)
{
    char *dom_path = libxl__xs_get_dompath(gc, domid);

    return GCSPRINTF("%s/device/%s/%d", dom_path,
                     libxl__device_kind_to_string(device_kind), devid);
}

char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->backend_domid);

    return GCSPRINTF("%s/backend/%s/%u/%d", dom_path,
                     libxl__device_kind_to_string(device->backend_kind),
                     device->domid, device->devid);
}

char *libxl__domain_device_backend_path(libxl__gc *gc, uint32_t backend_domid,
                                        uint32_t domid, uint32_t devid,
                                        libxl__device_kind backend_kind)
{
    char *dom_path = libxl__xs_get_dompath(gc, backend_domid);

    return GCSPRINTF("%s/backend/%s/%u/%d", dom_path,
                     libxl__device_kind_to_string(backend_kind),
                     domid, devid);
}

char *libxl__device_libxl_path(libxl__gc *gc, libxl__device *device)
{
    char *libxl_dom_path = libxl__xs_libxl_path(gc, device->domid);

    return GCSPRINTF("%s/device/%s/%d", libxl_dom_path,
                     libxl__device_kind_to_string(device->kind),
                     device->devid);
}

char *libxl__domain_device_libxl_path(libxl__gc *gc,  uint32_t domid, uint32_t devid,
                                      libxl__device_kind device_kind)
{
    char *libxl_dom_path = libxl__xs_libxl_path(gc, domid);

    return GCSPRINTF("%s/device/%s/%d", libxl_dom_path,
                     libxl__device_kind_to_string(device_kind), devid);
}

/* Returns 1 if device exists, 0 if not, ERROR_* (<0) on error. */
int libxl__device_exists(libxl__gc *gc, xs_transaction_t t,
                         libxl__device *device)
{
    int rc;
    char *be_path = libxl__device_libxl_path(gc, device);
    const char *dir;

    rc = libxl__xs_read_checked(gc, t, be_path, &dir);

    if (rc)
        return rc;

    if (dir)
        return 1;
    return 0;
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
        LOGED(ERROR, dev->domid, "unable to read nictype from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl_nic_type_from_string(snictype, nictype);
    if (rc) {
        LOGED(ERROR, dev->domid, "unable to parse nictype from %s", be_path);
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
    char *frontend_path = NULL, *backend_path = NULL, *libxl_path;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions ro_frontend_perms[2];
    struct xs_permissions backend_perms[2];
    int create_transaction = t == XBT_NULL;
    int libxl_only = device->backend_kind == LIBXL__DEVICE_KIND_NONE;
    int rc;

    if (libxl_only) {
        /* bents should be set as this is used to setup libxl_path content. */
        assert(!fents && !ro_fents);
    } else {
        frontend_path = libxl__device_frontend_path(gc, device);
        backend_path = libxl__device_backend_path(gc, device);
    }
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

    if (!libxl_only) {
        rc = libxl__xs_write_checked(gc, t, GCSPRINTF("%s/frontend",libxl_path),
                                     frontend_path);
        if (rc) goto out;

        rc = libxl__xs_write_checked(gc, t, GCSPRINTF("%s/backend",libxl_path),
                                     backend_path);
        if (rc) goto out;
    }

    /* xxx much of this function lacks error checks! */

    if (fents || ro_fents) {
        xs_rm(ctx->xsh, t, frontend_path);
        xs_mkdir(ctx->xsh, t, frontend_path);
        /* Console 0 is a special case. It doesn't use the regular PV
         * state machine but also the frontend directory has
         * historically contained other information, such as the
         * vnc-port, which we don't want the guest fiddling with.
         */
        if ((device->kind == LIBXL__DEVICE_KIND_CONSOLE && device->devid == 0) ||
            (device->kind == LIBXL__DEVICE_KIND_VUART))
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
        if (!libxl_only) {
            xs_rm(ctx->xsh, t, backend_path);
            xs_mkdir(ctx->xsh, t, backend_path);
            xs_set_permissions(ctx->xsh, t, backend_path, backend_perms,
                               ARRAY_SIZE(backend_perms));
            xs_write(ctx->xsh, t, GCSPRINTF("%s/frontend", backend_path),
                     frontend_path, strlen(frontend_path));
            libxl__xs_writev(gc, t, backend_path, bents);
        }

        /*
         * We make a copy of everything for the backend in the libxl
         * path as well.  This means we don't need to trust the
         * backend.  Ideally this information would not be used and we
         * would use the information from the json configuration
         * instead.  But there are still places in libxl that try to
         * reconstruct a config from xenstore.
         *
         * For devices without PV backend (e.g. USB devices emulated via qemu)
         * only the libxl path is written.
         *
         * This duplication will typically produces duplicate keys
         * which will go out of date, but that's OK because nothing
         * reads those.  For example, there is usually
         *   /libxl/$guest/device/$kind/$devid/state
         * which starts out containing XenbusStateInitialising ("1")
         * just like the copy in
         *  /local/domain/$driverdom/backend/$guest/$kind/$devid/state
         * but which won't ever be updated.
         *
         * This duplication is superfluous and messy but as discussed
         * the proper fix is more intrusive than we want to do now.
         */
        rc = libxl__xs_writev(gc, t, libxl_path, bents);
        if (rc) goto out;
    }

    if (!create_transaction)
        return 0;

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else {
            LOGED(ERROR, device->domid, "xs transaction failed");
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
        if (a->disk->format != LIBXL_DISK_FORMAT_RAW) {
            goto bad_format;
        }

        if (libxl_defbool_val(a->disk->colo_enable))
            goto bad_colo;

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
        LOG(DEBUG, "Disk vdev=%s, backend tap unsuitable because blktap "
                   "not available", a->disk->vdev);
        return 0;

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

 bad_colo:
    LOG(DEBUG, "Disk vdev=%s, backend %s not compatible with colo",
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
        if (disk->pdev_path != NULL && strcmp(disk->pdev_path, "")) {
            LOG(ERROR,
                "Disk vdev=%s is empty but an image has been provided: %s",
                disk->vdev, disk->pdev_path);
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
        case LIBXL_DISK_FORMAT_QED: return "qed";
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

const char *libxl__qemu_disk_format_string(libxl_disk_format format)
{
    switch (format) {
    case LIBXL_DISK_FORMAT_QCOW: return "qcow";
    case LIBXL_DISK_FORMAT_QCOW2: return "qcow2";
    case LIBXL_DISK_FORMAT_VHD: return "vpc";
    case LIBXL_DISK_FORMAT_RAW: return "raw";
    case LIBXL_DISK_FORMAT_EMPTY: return NULL;
    case LIBXL_DISK_FORMAT_QED: return "qed";
    default: return NULL;
    }
}

int libxl__device_physdisk_major_minor(const char *physpath, int *major, int *minor)
{
    struct stat buf;
    if (stat(physpath, &buf) < 0)
        return -1;
    if (!S_ISBLK(buf.st_mode))
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

static char *encode_disk_name(char *ptr, unsigned int n)
{
    if (n >= 26)
        ptr = encode_disk_name(ptr, n / 26 - 1);
    *ptr = 'a' + n % 26;
    return ptr + 1;
}

char *libxl__devid_to_vdev(libxl__gc *gc, int devid)
{
    unsigned int minor;
    int offset;
    int nr_parts;
    char *ptr = NULL;
/* Same as in Linux.
 * encode_disk_name might end up using up to 29 bytes (BUFFER_SIZE - 3)
 * including the trailing \0.
 *
 * The code is safe because 26 raised to the power of 28 (that is the
 * maximum offset that can be stored in the allocated buffer as a
 * string) is far greater than UINT_MAX on 64 bits so offset cannot be
 * big enough to exhaust the available bytes in ret. */
#define BUFFER_SIZE 32
    char *ret = libxl__zalloc(gc, BUFFER_SIZE);

#define EXT_SHIFT 28
#define EXTENDED (1<<EXT_SHIFT)
#define VDEV_IS_EXTENDED(dev) ((dev)&(EXTENDED))
#define BLKIF_MINOR_EXT(dev) ((dev)&(~EXTENDED))
/* the size of the buffer to store the device name is 32 bytes to match the
 * equivalent buffer in the Linux kernel code */

    if (!VDEV_IS_EXTENDED(devid)) {
        minor = devid & 0xff;
        nr_parts = 16;
    } else {
        minor = BLKIF_MINOR_EXT(devid);
        nr_parts = 256;
    }
    offset = minor / nr_parts;

    strcpy(ret, "xvd");
    ptr = encode_disk_name(ret + 3, offset);
    if (minor % nr_parts == 0)
        *ptr = 0;
    else
        /* overflow cannot happen, thanks to the upper bound */
        snprintf(ptr, ret + 32 - ptr,
                "%d", minor & (nr_parts - 1));
    return ret;
#undef BUFFER_SIZE
#undef EXT_SHIFT
#undef EXTENDED
#undef VDEV_IS_EXTENDED
#undef BLKIF_MINOR_EXT
}

/* Device AO operations */

void libxl__prepare_ao_device(libxl__ao *ao, libxl__ao_device *aodev)
{
    aodev->ao = ao;
    aodev->rc = 0;
    aodev->dev = NULL;
    aodev->num_exec = 0;
    /* Initialize timer for QEMU Bodge */
    libxl__ev_time_init(&aodev->timeout);
    /*
     * Initialize xs_watch, because it's not used on all possible
     * execution paths, but it's unconditionally destroyed when finished.
     */
    libxl__xswait_init(&aodev->xswait);
    aodev->active = 1;
    /* We init this here because we might call device_hotplug_done
     * without actually calling any hotplug script */
    libxl__async_exec_init(&aodev->aes);
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

void libxl__multidev_prepare_with_aodev(libxl__multidev *multidev,
                                        libxl__ao_device *aodev) {
    STATE_AO_GC(multidev->ao);

    aodev->multidev = multidev;
    aodev->callback = libxl__multidev_one_callback;
    libxl__prepare_ao_device(ao, aodev);

    if (multidev->used >= multidev->allocd) {
        multidev->allocd = multidev->used * 2 + 5;
        GCREALLOC_ARRAY(multidev->array, multidev->allocd);
    }
    multidev->array[multidev->used++] = aodev;
}

libxl__ao_device *libxl__multidev_prepare(libxl__multidev *multidev) {
    STATE_AO_GC(multidev->ao);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    libxl__multidev_prepare_with_aodev(multidev, aodev);

    return aodev;
}

void libxl__multidev_one_callback(libxl__egc *egc, libxl__ao_device *aodev)
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
    libxl__multidev_one_callback(egc, multidev->preparation);
}

/******************************************************************************/

int libxl__device_destroy(libxl__gc *gc, libxl__device *dev)
{
    const char *be_path = NULL;
    const char *fe_path = NULL;
    const char *libxl_path = libxl__device_libxl_path(gc, dev);
    xs_transaction_t t = 0;
    int rc;
    uint32_t domid;
    int libxl_only = dev->backend_kind == LIBXL__DEVICE_KIND_NONE;

    if (!libxl_only) {
        be_path = libxl__device_backend_path(gc, dev);
        fe_path = libxl__device_frontend_path(gc, dev);
    }

    rc = libxl__get_domid(gc, &domid);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        if (domid == LIBXL_TOOLSTACK_DOMID) {
            /*
             * The toolstack domain is in charge of removing the
             * frontend and libxl paths.
             */
            if (!libxl_only)
                libxl__xs_path_cleanup(gc, t, fe_path);
            libxl__xs_path_cleanup(gc, t, libxl_path);
        }
        if (dev->backend_domid == domid && !libxl_only) {
            /*
             * The driver domain is in charge of removing what it can
             * from the backend path.
             */
            libxl__xs_path_cleanup(gc, t, be_path);
        }

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

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

    path = GCSPRINTF("/libxl/%d/device", domid);
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

        path = GCSPRINTF("/libxl/%d/device/%s", domid, kinds[i]);
        devs = libxl__xs_directory(gc, XBT_NULL, path, &num_dev_xsentries);
        if (!devs)
            continue;
        for (j = 0; j < num_dev_xsentries; j++) {
            path = GCSPRINTF("/libxl/%d/device/%s/%s/backend",
                             domid, kinds[i], devs[j]);
            path = libxl__xs_read(gc, XBT_NULL, path);
            GCNEW(dev);
            if (path && libxl__parse_backend_path(gc, path, dev) == 0) {
                dev->domid = domid;
                dev->kind = kind;
                dev->devid = atoi(devs[j]);
                if (dev->backend_kind == LIBXL__DEVICE_KIND_CONSOLE ||
                    dev->backend_kind == LIBXL__DEVICE_KIND_VUART) {
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
                if (dev->kind == LIBXL__DEVICE_KIND_VUSB)
                    libxl__initiate_device_usbctrl_remove(egc, aodev);
                else
                    libxl__initiate_device_generic_remove(egc, aodev);
            }
        }
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
                                const struct timeval *requested_abs, int rc);

static void device_backend_callback(libxl__egc *egc, libxl__ev_devstate *ds,
                                   int rc);

static void device_backend_cleanup(libxl__gc *gc,
                                   libxl__ao_device *aodev);

static void device_hotplug(libxl__egc *egc, libxl__ao_device *aodev);

static void device_hotplug_child_death_cb(libxl__egc *egc,
                                          libxl__async_exec_state *aes,
                                          int rc, int status);

static void device_destroy_be_watch_cb(libxl__egc *egc,
                                       libxl__xswait_state *xswait,
                                       int rc, const char *data);

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

    rc = libxl__ev_devstate_wait(ao, &aodev->backend_ds,
                                 device_backend_callback,
                                 state_path, XenbusStateInitWait,
                                 LIBXL_INIT_TIMEOUT * 1000);
    if (rc) {
        LOGD(ERROR, aodev->dev->domid, "unable to initialize device %s", be_path);
        goto out;
    }

    return;

out:
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
    return;
}

void libxl__initiate_device_generic_remove(libxl__egc *egc,
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
        LOGD(ERROR, domid, "unable to get my domid");
        goto out;
    }

    if (my_domid == LIBXL_TOOLSTACK_DOMID) {
        rc = libxl_domain_info(CTX, &info, domid);
        if (rc) {
            LOGD(ERROR, domid, "unable to get info for domain %d", domid);
            goto out;
        }
        if (QEMU_BACKEND(aodev->dev) &&
            (info.paused || info.dying || info.shutdown)) {
            /*
             * TODO: 4.2 Bodge due to QEMU, see comment on top of
             * libxl__initiate_device_generic_remove in libxl_internal.h
             */
            rc = libxl__ev_time_register_rel(ao, &aodev->timeout,
                                             device_qemu_timeout,
                                             LIBXL_QEMU_BODGE_TIMEOUT * 1000);
            if (rc) {
                LOGD(ERROR, domid, "unable to register timeout for Qemu device %s",
                            be_path);
                goto out;
            }
            goto out_success;
        }
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) {
            LOGD(ERROR, domid, "unable to start transaction");
            goto out;
        }

        if (aodev->force)
            libxl__xs_path_cleanup(gc, t,
                                   libxl__device_frontend_path(gc, aodev->dev));

        rc = libxl__xs_read_checked(gc, t, state_path, &state);
        if (rc) {
            LOGD(ERROR, domid, "unable to read device state from path %s", state_path);
            goto out;
        }

        /* if state_path is empty, assume backend is gone (backend domain
         * shutdown?), cleanup frontend only; rc=0 */
        if (!state) {
            LOG(INFO, "backend %s already removed, cleanup frontend only", be_path);
            goto out;
        }

        rc = libxl__xs_write_checked(gc, t, online_path, "0");
        if (rc)
            goto out;

        /*
         * Check if device is already in "closed" state, in which case
         * it should not be changed.
         */
         if (state && atoi(state) != XenbusStateClosed) {
            rc = libxl__xs_write_checked(gc, t, state_path, GCSPRINTF("%d", XenbusStateClosing));
            if (rc) {
                LOGD(ERROR, domid, "unable to write to xenstore path %s", state_path);
                goto out;
            }
        }

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    rc = libxl__ev_devstate_wait(ao, &aodev->backend_ds,
                                 device_backend_callback,
                                 state_path, XenbusStateClosed,
                                 LIBXL_DESTROY_TIMEOUT * 1000);
    if (rc) {
        LOGD(ERROR, domid, "unable to remove device %s", be_path);
        goto out;
    }

out_success:
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
                                const struct timeval *requested_abs, int rc)
{
    libxl__ao_device *aodev = CONTAINER_OF(ev, *aodev, timeout);
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *state_path = GCSPRINTF("%s/state", be_path);
    const char *xs_state;
    xs_transaction_t t = 0;

    if (rc != ERROR_TIMEDOUT)
        goto out;

    libxl__ev_time_deregister(gc, &aodev->timeout);

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) {
            LOGD(ERROR, aodev->dev->domid, "unable to start transaction");
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
            rc = libxl__xs_write_checked(gc, XBT_NULL, state_path, GCSPRINTF("%d", XenbusStateClosed));
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

    LOGD(DEBUG, aodev->dev->domid, "calling device_backend_cleanup");
    device_backend_cleanup(gc, aodev);

    if (rc == ERROR_TIMEDOUT &&
        aodev->action == LIBXL__DEVICE_ACTION_REMOVE &&
        !aodev->force) {
        LOGD(DEBUG, aodev->dev->domid, "Timeout reached, initiating forced remove");
        aodev->force = 1;
        libxl__initiate_device_generic_remove(egc, aodev);
        return;
    }

    if (rc) {
        LOGD(ERROR, aodev->dev->domid, "unable to %s device with path %s",
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
    libxl__async_exec_state *aes = &aodev->aes;
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char **args = NULL, **env = NULL;
    int rc = 0;
    int hotplug, nullfd = -1;
    uint32_t domid;

    /*
     * If device is attached from a driver domain don't try to execute
     * hotplug scripts
     */
    rc = libxl__get_domid(gc, &domid);
    if (rc) {
        LOGD(ERROR, aodev->dev->domid, "Failed to get domid");
        goto out;
    }
    if (aodev->dev->backend_domid != domid) {
        LOGD(DEBUG, aodev->dev->domid,
             "Backend domid %d, domid %d, assuming driver domains",
             aodev->dev->backend_domid, domid);

        if (aodev->action != LIBXL__DEVICE_ACTION_REMOVE) {
            LOG(DEBUG, "Not a remove, not executing hotplug scripts");
            goto out;
        }

        aodev->xswait.ao = ao;
        aodev->xswait.what = "removal of backend path";
        aodev->xswait.path = be_path;
        aodev->xswait.timeout_ms = LIBXL_DESTROY_TIMEOUT * 1000;
        aodev->xswait.callback = device_destroy_be_watch_cb;
        rc = libxl__xswait_start(gc, &aodev->xswait);
        if (rc) {
            LOGD(ERROR, aodev->dev->domid,
                 "Setup of backend removal watch failed (path %s)", be_path);
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
        LOGD(DEBUG, aodev->dev->domid, "No hotplug script to execute");
        goto out;
    case 1:
        /* execute hotplug script */
        break;
    default:
        /* everything else is an error */
        LOGD(ERROR, aodev->dev->domid,
                    "unable to get args/env to execute hotplug script for "
                    "device %s", libxl__device_backend_path(gc, aodev->dev));
        rc = hotplug;
        goto out;
    }

    assert(args != NULL);
    LOGD(DEBUG, aodev->dev->domid, "calling hotplug script: %s %s", args[0], args[1]);
    LOGD(DEBUG, aodev->dev->domid, "extra args:");
    {
        const char *arg;
        unsigned int x;

        for (x = 2; (arg = args[x]); x++)
            LOGD(DEBUG, aodev->dev->domid, "\t%s", arg);
    }
    LOGD(DEBUG, aodev->dev->domid, "env:");
    if (env != NULL) {
        const char *k, *v;
        unsigned int x;

        for (x = 0; (k = env[x]); x += 2) {
            v = env[x+1];
            LOGD(DEBUG, aodev->dev->domid, "\t%s: %s", k, v);
        }
    }

    nullfd = open("/dev/null", O_RDONLY);
    if (nullfd < 0) {
        LOGD(ERROR, aodev->dev->domid, "unable to open /dev/null for hotplug script");
        rc = ERROR_FAIL;
        goto out;
    }

    aes->ao = ao;
    aes->what = GCSPRINTF("%s %s", args[0], args[1]);
    aes->env = env;
    aes->args = args;
    aes->callback = device_hotplug_child_death_cb;
    aes->timeout_ms = LIBXL_HOTPLUG_TIMEOUT * 1000;
    aes->stdfds[0] = nullfd;
    aes->stdfds[1] = 2;
    aes->stdfds[2] = -1;

    rc = libxl__async_exec_start(aes);
    if (rc)
        goto out;

    close(nullfd);
    assert(libxl__async_exec_inuse(&aodev->aes));

    return;

out:
    if (nullfd >= 0) close(nullfd);
    aodev->rc = rc;
    device_hotplug_done(egc, aodev);
    return;
}

static void device_hotplug_child_death_cb(libxl__egc *egc,
                                          libxl__async_exec_state *aes,
                                          int rc, int status)
{
    libxl__ao_device *aodev = CONTAINER_OF(aes, *aodev, aes);
    STATE_AO_GC(aodev->ao);
    char *be_path = libxl__device_backend_path(gc, aodev->dev);
    char *hotplug_error;

    device_hotplug_clean(gc, aodev);

    if (status && !rc) {
        hotplug_error = libxl__xs_read(gc, XBT_NULL,
                                       GCSPRINTF("%s/hotplug-error", be_path));
        if (hotplug_error)
            LOG(ERROR, "script: %s", hotplug_error);
        rc = ERROR_FAIL;
    }

    if (rc) {
        if (!aodev->rc)
            aodev->rc = rc;
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

static void device_destroy_be_watch_cb(libxl__egc *egc,
                                       libxl__xswait_state *xswait,
                                       int rc, const char *dir)
{
    libxl__ao_device *aodev = CONTAINER_OF(xswait, *aodev, xswait);
    STATE_AO_GC(aodev->ao);

    if (rc) {
        if (rc == ERROR_TIMEDOUT)
            LOGD(ERROR, aodev->dev->domid,
                 "timed out while waiting for %s to be removed",
                 xswait->path);
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
    libxl__xswait_stop(gc, &aodev->xswait);
    assert(!libxl__async_exec_inuse(&aodev->aes));
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
    uint32_t dm_domid = libxl_get_stubdom_id(CTX, domid);

    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
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

/* generic callback for devices that only need to set ao_complete */
void device_addrm_aocomplete(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);

    if (aodev->rc) {
        if (aodev->dev) {
            LOGD(ERROR, aodev->dev->domid, "Unable to %s %s with id %u",
                        libxl__device_action_to_string(aodev->action),
                        libxl__device_kind_to_string(aodev->dev->kind),
                        aodev->dev->devid);
        } else {
            LOG(ERROR, "unable to %s device",
                       libxl__device_action_to_string(aodev->action));
        }
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, aodev->rc);
    return;
}

/* common function to get next device id */
int libxl__device_nextid(libxl__gc *gc, uint32_t domid,
                         libxl__device_kind device)
{
    char *libxl_dom_path, **l;
    unsigned int nb;
    int nextid = -1;

    if (!(libxl_dom_path = libxl__xs_libxl_path(gc, domid)))
        return nextid;

    l = libxl__xs_directory(gc, XBT_NULL,
        GCSPRINTF("%s/device/%s", libxl_dom_path,
                  libxl__device_kind_to_string(device)), &nb);
    if (l == NULL || nb == 0)
        nextid = 0;
    else
        nextid = strtoul(l[nb - 1], NULL, 10) + 1;

    return nextid;
}

static void device_complete(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);

    LOG(DEBUG, "device %s %s %s",
               libxl__device_backend_path(gc, aodev->dev),
               libxl__device_action_to_string(aodev->action),
               aodev->rc ? "failed" : "succeed");

    libxl__nested_ao_free(aodev->ao);
}

static void qdisk_spawn_outcome(libxl__egc *egc, libxl__dm_spawn_state *dmss,
                                int rc)
{
    STATE_AO_GC(dmss->spawn.ao);

    LOGD(DEBUG, dmss->guest_domid, "qdisk backend spawn %s",
                rc ? "failed" : "succeed");

    libxl__nested_ao_free(dmss->spawn.ao);
}

/*
 * Data structures used to track devices handled by driver domains
 */

/*
 * Structure that describes a device handled by a driver domain
 */
typedef struct libxl__ddomain_device {
    libxl__device *dev;
    LIBXL_SLIST_ENTRY(struct libxl__ddomain_device) next;
} libxl__ddomain_device;

/*
 * Structure that describes a domain and it's associated devices
 */
typedef struct libxl__ddomain_guest {
    uint32_t domid;
    int num_vifs, num_vbds, num_qdisks;
    LIBXL_SLIST_HEAD(, struct libxl__ddomain_device) devices;
    LIBXL_SLIST_ENTRY(struct libxl__ddomain_guest) next;
} libxl__ddomain_guest;

/*
 * Main structure used by a driver domain to keep track of devices
 * currently in use
 */
typedef struct {
    libxl__ao *ao;
    libxl__ev_xswatch watch;
    LIBXL_SLIST_HEAD(, struct libxl__ddomain_guest) guests;
} libxl__ddomain;

static libxl__ddomain_guest *search_for_guest(libxl__ddomain *ddomain,
                                               uint32_t domid)
{
    libxl__ddomain_guest *dguest;

    LIBXL_SLIST_FOREACH(dguest, &ddomain->guests, next) {
        if (dguest->domid == domid)
            return dguest;
    }
    return NULL;
}

static libxl__ddomain_device *search_for_device(libxl__ddomain_guest *dguest,
                                                libxl__device *dev)
{
    libxl__ddomain_device *ddev;

    LIBXL_SLIST_FOREACH(ddev, &dguest->devices, next) {
#define LIBXL_DEVICE_CMP(dev1, dev2, entry) (dev1->entry == dev2->entry)
        if (LIBXL_DEVICE_CMP(ddev->dev, dev, backend_devid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, backend_domid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, devid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, domid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, backend_kind) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, kind))
            return ddev;
#undef LIBXL_DEVICE_CMP
    }

    return NULL;
}

static void check_and_maybe_remove_guest(libxl__gc *gc,
                                         libxl__ddomain *ddomain,
                                         libxl__ddomain_guest *dguest)
{
    assert(ddomain);

    if (dguest != NULL &&
        dguest->num_vifs + dguest->num_vbds + dguest->num_qdisks == 0) {
        LIBXL_SLIST_REMOVE(&ddomain->guests, dguest, libxl__ddomain_guest,
                           next);
        LOGD(DEBUG, dguest->domid, "Removed domain from the list of active guests");
        /* Clear any leftovers in libxl/<domid> */
        libxl__xs_rm_checked(gc, XBT_NULL,
                             GCSPRINTF("libxl/%u", dguest->domid));
        free(dguest);
    }
}

/*
 * The following comment applies to both add_device and remove_device.
 *
 * If the return value is greater than 0, it means there's no ao dispatched,
 * so the free of the nested ao should be done by the parent when it has
 * finished.
 */
static int add_device(libxl__egc *egc, libxl__ao *ao,
                      libxl__ddomain_guest *dguest,
                      libxl__device *dev)
{
    AO_GC;
    libxl__ao_device *aodev;
    libxl__ddomain_device *ddev;
    libxl__dm_spawn_state *dmss;
    int rc = 0;

    /*
     * New device addition, allocate a struct to hold it and add it
     * to the list of active devices for a given guest.
     */
    ddev = libxl__zalloc(NOGC, sizeof(*ddev));
    ddev->dev = libxl__zalloc(NOGC, sizeof(*ddev->dev));
    *ddev->dev = *dev;
    LIBXL_SLIST_INSERT_HEAD(&dguest->devices, ddev, next);
    LOGD(DEBUG, dev->domid, "Added device %s to the list of active devices",
         libxl__device_backend_path(gc, dev));

    switch(dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VBD:
    case LIBXL__DEVICE_KIND_VIF:
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VBD) dguest->num_vbds++;
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VIF) dguest->num_vifs++;

        GCNEW(aodev);
        libxl__prepare_ao_device(ao, aodev);
        /*
         * Clone the libxl__device to avoid races if remove_device is called
         * before the device addition has finished.
         */
        GCNEW(aodev->dev);
        *aodev->dev = *dev;
        aodev->action = LIBXL__DEVICE_ACTION_ADD;
        aodev->callback = device_complete;
        libxl__wait_device_connection(egc, aodev);

        break;
    case LIBXL__DEVICE_KIND_QDISK:
        if (dguest->num_qdisks == 0) {
            GCNEW(dmss);
            dmss->guest_domid = dev->domid;
            dmss->spawn.ao = ao;
            dmss->callback = qdisk_spawn_outcome;

            libxl__spawn_qdisk_backend(egc, dmss);
        }
        dguest->num_qdisks++;

        break;
    default:
        rc = 1;
        break;
    }

    return rc;
}

static int remove_device(libxl__egc *egc, libxl__ao *ao,
                         libxl__ddomain_guest *dguest,
                         libxl__ddomain_device *ddev)
{
    AO_GC;
    libxl__device *dev = ddev->dev;
    libxl__ao_device *aodev;
    int rc = 0;

    switch(ddev->dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VBD:
    case LIBXL__DEVICE_KIND_VIF:
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VBD) dguest->num_vbds--;
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VIF) dguest->num_vifs--;

        GCNEW(aodev);
        libxl__prepare_ao_device(ao, aodev);
        /*
         * Clone the libxl__device to avoid races if there's a add_device
         * running in parallel.
         */
        GCNEW(aodev->dev);
        *aodev->dev = *dev;
        aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
        aodev->callback = device_complete;
        libxl__initiate_device_generic_remove(egc, aodev);
        break;
    case LIBXL__DEVICE_KIND_QDISK:
        if (--dguest->num_qdisks == 0) {
            rc = libxl__destroy_qdisk_backend(gc, dev->domid);
            if (rc)
                goto out;
        }
        libxl__device_destroy(gc, dev);
        /* Fall through to return > 0, no ao has been dispatched */
    default:
        rc = 1;
        break;
    }

    /*
     * Removal of an active device, remove it from the list and
     * free it's data structures if they are no longer needed.
     *
     * NB: the freeing is safe because all the async ops launched
     * above or from add_device make a copy of the data they use, so
     * there's no risk of dereferencing.
     */
    LIBXL_SLIST_REMOVE(&dguest->devices, ddev, libxl__ddomain_device,
                       next);
    LOGD(DEBUG, dev->domid, "Removed device %s from the list of active devices",
         libxl__device_backend_path(gc, dev));

    free(ddev->dev);
    free(ddev);

out:
    return rc;
}

static void backend_watch_callback(libxl__egc *egc, libxl__ev_xswatch *watch,
                                   const char *watch_path,
                                   const char *event_path)
{
    libxl__ddomain *ddomain = CONTAINER_OF(watch, *ddomain, watch);
    libxl__ao *nested_ao = libxl__nested_ao_create(ddomain->ao);
    STATE_AO_GC(nested_ao);
    char *p, *path;
    const char *sstate, *sonline;
    int state, online, rc;
    libxl__device *dev;
    libxl__ddomain_device *ddev = NULL;
    libxl__ddomain_guest *dguest = NULL;
    bool free_ao = false;

    /* Check if event_path ends with "state" or "online" and truncate it. */
    path = libxl__strdup(gc, event_path);
    p = strrchr(path, '/');
    if (p == NULL)
        goto skip;
    if (strcmp(p, "/state") != 0 && strcmp(p, "/online") != 0)
        goto skip;
    /* Truncate the string so it points to the backend directory. */
    *p = '\0';

    /* Fetch the value of the state and online nodes. */
    rc = libxl__xs_read_checked(gc, XBT_NULL, GCSPRINTF("%s/state", path),
                                &sstate);
    if (rc || !sstate)
        goto skip;
    state = atoi(sstate);

    rc = libxl__xs_read_checked(gc, XBT_NULL, GCSPRINTF("%s/online", path),
                                &sonline);
    if (rc || !sonline)
        goto skip;
    online = atoi(sonline);

    GCNEW(dev);
    rc = libxl__parse_backend_path(gc, path, dev);
    if (rc)
        goto skip;

    dguest = search_for_guest(ddomain, dev->domid);
    if (dguest == NULL && state == XenbusStateClosed) {
        /*
         * Spurious state change, device has already been disconnected
         * or never attached.
         */
        goto skip;
    }
    if (dguest == NULL) {
        /* Create a new guest struct and initialize it */
        dguest = libxl__zalloc(NOGC, sizeof(*dguest));
        dguest->domid = dev->domid;
        LIBXL_SLIST_INIT(&dguest->devices);
        LIBXL_SLIST_INSERT_HEAD(&ddomain->guests, dguest, next);
        LOGD(DEBUG, dguest->domid, "Added domain to the list of active guests");
    }
    ddev = search_for_device(dguest, dev);
    if (ddev == NULL && state == XenbusStateClosed) {
        /*
         * Spurious state change, device has already been disconnected
         * or never attached.
         */
        goto skip;
    } else if (ddev == NULL) {
        rc = add_device(egc, nested_ao, dguest, dev);
        if (rc > 0)
            free_ao = true;
    } else if (state == XenbusStateClosed && online == 0) {
        rc = remove_device(egc, nested_ao, dguest, ddev);
        if (rc > 0)
            free_ao = true;
        check_and_maybe_remove_guest(gc, ddomain, dguest);
    }

    if (free_ao)
        libxl__nested_ao_free(nested_ao);

    return;

skip:
    libxl__nested_ao_free(nested_ao);
    check_and_maybe_remove_guest(gc, ddomain, dguest);
    return;
}

/* Handler of events for device driver domains */
int libxl_device_events_handler(libxl_ctx *ctx,
                                const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, 0, ao_how);
    int rc;
    uint32_t domid;
    libxl__ddomain ddomain;
    char *be_path;
    char **kinds = NULL, **domains = NULL, **devs = NULL;
    const char *sstate;
    char *state_path;
    int state;
    unsigned int nkinds, ndomains, ndevs;
    int i, j, k;

    ddomain.ao = ao;
    LIBXL_SLIST_INIT(&ddomain.guests);

    rc = libxl__get_domid(gc, &domid);
    if (rc) {
        LOG(ERROR, "unable to get domain id");
        goto out;
    }

    /*
     * We use absolute paths because we want xswatch to also return
     * absolute paths that can be parsed by libxl__parse_backend_path.
     */
    be_path = GCSPRINTF("/local/domain/%u/backend", domid);
    rc = libxl__ev_xswatch_register(gc, &ddomain.watch, backend_watch_callback,
                                    be_path);
    if (rc) goto out;

    kinds = libxl__xs_directory(gc, XBT_NULL, be_path, &nkinds);
    if (kinds) {
        for (i = 0; i < nkinds; i++) {
            domains = libxl__xs_directory(gc, XBT_NULL,
                    GCSPRINTF("%s/%s", be_path, kinds[i]), &ndomains);
            if (!domains)
                continue;
            for (j = 0; j < ndomains; j++) {
                devs = libxl__xs_directory(gc, XBT_NULL,
                        GCSPRINTF("%s/%s/%s", be_path, kinds[i], domains[j]), &ndevs);
                if (!devs)
                    continue;
                for (k = 0; k < ndevs; k++) {
                    state_path = GCSPRINTF("%s/%s/%s/%s/state",
                            be_path, kinds[i], domains[j], devs[k]);
                    rc = libxl__xs_read_checked(gc, XBT_NULL, state_path, &sstate);
                    if (rc || !sstate)
                        continue;
                    state = atoi(sstate);
                    if (state == XenbusStateInitWait)
                        backend_watch_callback(egc, &ddomain.watch,
                                               be_path, state_path);
                }
            }
        }
    }

    return AO_INPROGRESS;

out:
    return AO_CREATE_FAIL(rc);
}

void device_add_domain_config(libxl__gc *gc, libxl_domain_config *d_config,
                              const struct libxl_device_type *dt, const void *dev)
{
    int *num_dev;
    unsigned int i;
    void *item = NULL;

    num_dev = libxl__device_type_get_num(dt, d_config);

    /* Check for existing device */
    for (i = 0; i < *num_dev; i++) {
        if (dt->compare(libxl__device_type_get_elem(dt, d_config, i), dev)) {
            item = libxl__device_type_get_elem(dt, d_config, i);
        }
    }

    if (!item) {
        void **devs = libxl__device_type_get_ptr(dt, d_config);
        *devs = libxl__realloc(NOGC, *devs,
                               dt->dev_elem_size * (*num_dev + 1));
        item = libxl__device_type_get_elem(dt, d_config, *num_dev);
        (*num_dev)++;
    } else {
        dt->dispose(item);
    }

    dt->init(item);
    dt->copy(CTX, item, dev);
}

void libxl__device_add_async(libxl__egc *egc, uint32_t domid,
                             const struct libxl_device_type *dt, void *type,
                             libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    flexarray_t *back;
    flexarray_t *front, *ro_front;
    libxl__device *device;
    xs_transaction_t t = XBT_NULL;
    libxl_domain_config d_config;
    void *type_saved;
    libxl__domain_userdata_lock *lock = NULL;
    int rc;

    libxl_domain_config_init(&d_config);

    type_saved = libxl__malloc(gc, dt->dev_elem_size);

    dt->init(type_saved);
    dt->copy(CTX, type_saved, type);

    if (dt->set_default) {
        rc = dt->set_default(gc, domid, type, aodev->update_json);
        if (rc) goto out;
    }

    if (dt->update_devid) {
        rc = dt->update_devid(gc, domid, type);
        if (rc) goto out;
    }

    if (dt->update_config)
        dt->update_config(gc, type_saved, type);

    GCNEW(device);
    rc = dt->to_device(gc, domid, type, device);
    if (rc) goto out;

    if (aodev->update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        device_add_domain_config(gc, &d_config, dt, type_saved);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    back = flexarray_make(gc, 16, 1);
    front = flexarray_make(gc, 16, 1);
    ro_front = flexarray_make(gc, 16, 1);

    flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state",
                          GCSPRINTF("%d", XenbusStateInitialising));

    flexarray_append_pair(front, "backend-id",
                          GCSPRINTF("%d", device->backend_domid));
    flexarray_append_pair(front, "state",
                          GCSPRINTF("%d", XenbusStateInitialising));

    if (dt->set_xenstore_config)
        dt->set_xenstore_config(gc, domid, type, back, front, ro_front);

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__device_exists(gc, t, device);
        if (rc < 0) goto out;
        if (rc == 1) {              /* already exists in xenstore */
            LOGD(ERROR, domid, "device already exists in xenstore");
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
                                  libxl__xs_kvs_of_flexarray(gc, ro_front));

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
    dt->dispose(type_saved);
    libxl_domain_config_dispose(&d_config);
    aodev->rc = rc;
    if (rc) aodev->callback(egc, aodev);
    return;
}

int libxl__device_add(libxl__gc *gc, uint32_t domid,
                      const struct libxl_device_type *dt, void *type)
{
    flexarray_t *back;
    flexarray_t *front, *ro_front;
    libxl__device *device;
    int rc;

    if (dt->set_default) {
        rc = dt->set_default(gc, domid, type, false);
        if (rc) goto out;
    }

    if (dt->update_devid) {
        rc = dt->update_devid(gc, domid, type);
        if (rc) goto out;
    }

    GCNEW(device);
    rc = dt->to_device(gc, domid, type, device);
    if (rc) goto out;

    back = flexarray_make(gc, 16, 1);
    front = flexarray_make(gc, 16, 1);
    ro_front = flexarray_make(gc, 16, 1);

    flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state",
                          GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(front, "backend-id",
                          libxl__sprintf(gc, "%d", device->backend_domid));
    flexarray_append_pair(front, "state",
                          GCSPRINTF("%d", XenbusStateInitialising));

    if (dt->set_xenstore_config)
        dt->set_xenstore_config(gc, domid, type, back, front, ro_front);

    rc = libxl__device_generic_add(gc, XBT_NULL, device,
                                   libxl__xs_kvs_of_flexarray(gc, back),
                                   libxl__xs_kvs_of_flexarray(gc, front),
                                   libxl__xs_kvs_of_flexarray(gc, ro_front));
    if (rc) goto out;

    rc = 0;

out:
    return rc;
}

void *libxl__device_list(libxl__gc *gc, const struct libxl_device_type *dt,
                         uint32_t domid, int *num)
{
    void *r = NULL;
    void *list = NULL;
    void *item = NULL;
    char *libxl_path;
    char **dir = NULL;
    unsigned int ndirs = 0;
    unsigned int ndevs = 0;
    int rc;

    *num = 0;

    libxl_path = GCSPRINTF("%s/device/%s",
                           libxl__xs_libxl_path(gc, domid),
                           libxl__device_kind_to_string(dt->type));

    dir = libxl__xs_directory(gc, XBT_NULL, libxl_path, &ndirs);

    if (dir && ndirs) {
        if (dt->get_num) {
            if (ndirs != 1) {
                LOGD(ERROR, domid, "multiple entries in %s\n", libxl_path);
                rc = ERROR_FAIL;
                goto out;
            }
            rc = dt->get_num(gc, GCSPRINTF("%s/%s", libxl_path, *dir), &ndevs);
            if (rc) goto out;
        } else {
            ndevs = ndirs;
        }
        list = libxl__malloc(NOGC, dt->dev_elem_size * ndevs);
        item = list;

        while (*num < ndevs) {
            dt->init(item);

            if (dt->from_xenstore) {
                int nr = dt->get_num ? *num : atoi(*dir);
                char *device_libxl_path = GCSPRINTF("%s/%s", libxl_path, *dir);
                rc = dt->from_xenstore(gc, device_libxl_path, nr, item);
                if (rc) goto out;
            }

            item = (uint8_t *)item + dt->dev_elem_size;
            ++(*num);
            if (!dt->get_num)
                ++dir;
        }
    }

    r = list;
    list = NULL;

out:

    if (list) {
        libxl__device_list_free(dt, list, *num);
        *num = 0;
    }

    return r;
}

void libxl__device_list_free(const struct libxl_device_type *dt,
                             void *list, int num)
{
    int i;

    for (i = 0; i < num; i++)
        dt->dispose((uint8_t*)list + i * dt->dev_elem_size);

    free(list);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
