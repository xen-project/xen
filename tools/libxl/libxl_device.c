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

#include "libxl_osdeps.h"

#include <string.h>
#include <stdio.h>
#include <sys/time.h> /* for struct timeval */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>


#include "libxl.h"
#include "libxl_internal.h"

static const char *string_of_kinds[] = {
    [DEVICE_VIF] = "vif",
    [DEVICE_VIF2] = "vif2",
    [DEVICE_VBD] = "vbd",
    [DEVICE_TAP] = "tap",
    [DEVICE_PCI] = "pci",
    [DEVICE_VFB] = "vfb",
    [DEVICE_VKBD] = "vkbd",
    [DEVICE_CONSOLE] = "console",
};

int libxl_device_generic_add(libxl_ctx *ctx, libxl_device *device,
                             char **bents, char **fents)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dom_path_backend, *dom_path, *frontend_path, *backend_path;
    xs_transaction_t t;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions backend_perms[2];
    int rc;

    if (!is_valid_device_kind(device->backend_kind) || !is_valid_device_kind(device->kind)) {
        rc = ERROR_INVAL;
        goto out;
    }

    dom_path_backend = libxl_xs_get_dompath(&gc, device->backend_domid);
    dom_path = libxl_xs_get_dompath(&gc, device->domid);

    frontend_path = libxl_sprintf(&gc, "%s/device/%s/%d",
                                  dom_path, string_of_kinds[device->kind], device->devid);
    backend_path = libxl_sprintf(&gc, "%s/backend/%s/%u/%d",
                                 dom_path_backend, string_of_kinds[device->backend_kind], device->domid, device->devid);

    frontend_perms[0].id = device->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = device->backend_domid;
    frontend_perms[1].perms = XS_PERM_READ;

    backend_perms[0].id = device->backend_domid;
    backend_perms[0].perms = XS_PERM_NONE;
    backend_perms[1].id = device->domid;
    backend_perms[1].perms = XS_PERM_READ;

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    /* FIXME: read frontend_path and check state before removing stuff */

    if (fents) {
        xs_rm(ctx->xsh, t, frontend_path);
        xs_mkdir(ctx->xsh, t, frontend_path);
        xs_set_permissions(ctx->xsh, t, frontend_path, frontend_perms, ARRAY_SIZE(frontend_perms));
        xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/backend", frontend_path), backend_path, strlen(backend_path));
        libxl_xs_writev(&gc, t, frontend_path, fents);
    }

    if (bents) {
        xs_rm(ctx->xsh, t, backend_path);
        xs_mkdir(ctx->xsh, t, backend_path);
        xs_set_permissions(ctx->xsh, t, backend_path, backend_perms, ARRAY_SIZE(backend_perms));
        xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/frontend", backend_path), frontend_path, strlen(frontend_path));
        libxl_xs_writev(&gc, t, backend_path, bents);
    }

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs transaction failed");
    }
    rc = 0;
out:
    libxl_free_all(&gc);
    return rc;
}

char *device_disk_string_of_phystype(libxl_disk_phystype phystype)
{
    switch (phystype) {
        case PHYSTYPE_QCOW: return "qcow";
        case PHYSTYPE_QCOW2: return "qcow2";
        case PHYSTYPE_VHD: return "vhd";
        case PHYSTYPE_AIO: return "aio";
        case PHYSTYPE_FILE: return "file";
        case PHYSTYPE_PHY: return "phy";
        default: return NULL;
    }
}

char *device_disk_backend_type_of_phystype(libxl_disk_phystype phystype)
{
    switch (phystype) {
        case PHYSTYPE_QCOW: return "tap";
        case PHYSTYPE_VHD: return "tap";
        case PHYSTYPE_AIO: return "tap";
        /* let's pretend file is tap:aio */
        case PHYSTYPE_FILE: return "tap";
        case PHYSTYPE_PHY: return "phy";
        default: return NULL;
    }
}

int device_physdisk_major_minor(const char *physpath, int *major, int *minor)
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

int device_disk_dev_number(char *virtpath)
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
        if (disk <= 15 && partition <= 15)
            return (202 << 8) | (disk << 4) | partition;
        else
            return (1 << 28) | (disk << 8) | partition;
    }

    errno = 0;
    ul = strtoul(virtpath, &ep, 0);
    if (!errno && !*ep && ul <= INT_MAX)
        return ul;

    if (device_virtdisk_matches(virtpath, "hd",
                                &disk, 3,
                                &partition, 63)) {
        return ((disk<2 ? 3 : 22) << 8) | ((disk & 1) << 6) | partition;
    }
    if (device_virtdisk_matches(virtpath, "sd",
                                &disk, 15,
                                &partition, 15)) {
        return (8 << 8) | (disk << 4) | partition;
    }
    return -1;
}

int libxl_device_destroy(libxl_ctx *ctx, char *be_path, int force)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    xs_transaction_t t;
    char *state_path = libxl_sprintf(&gc, "%s/state", be_path);
    char *state = libxl_xs_read(&gc, XBT_NULL, state_path);
    int rc = 0;

    if (!state)
        goto out;
    if (atoi(state) != 4) {
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        goto out;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/online", be_path), "0", strlen("0"));
    xs_write(ctx->xsh, t, state_path, "5", strlen("5"));
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else {
            rc = -1;
            goto out;
        }
    }
    if (!force) {
        xs_watch(ctx->xsh, state_path, be_path);
        rc = 1;
    }
out:
    libxl_free_all(&gc);
    return rc;
}

static int wait_for_dev_destroy(libxl_ctx *ctx, struct timeval *tv)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int nfds, rc;
    unsigned int n;
    fd_set rfds;
    char **l1 = NULL;

    rc = 1;
    nfds = xs_fileno(ctx->xsh) + 1;
    FD_ZERO(&rfds);
    FD_SET(xs_fileno(ctx->xsh), &rfds);
    if (select(nfds, &rfds, NULL, NULL, tv) > 0) {
        l1 = xs_read_watch(ctx->xsh, &n);
        if (l1 != NULL) {
            char *state = libxl_xs_read(&gc, XBT_NULL, l1[XS_WATCH_PATH]);
            if (!state || atoi(state) == 6) {
                xs_unwatch(ctx->xsh, l1[0], l1[1]);
                xs_rm(ctx->xsh, XBT_NULL, l1[XS_WATCH_TOKEN]);
                XL_LOG(ctx, XL_LOG_DEBUG, "Destroyed device backend at %s", l1[XS_WATCH_TOKEN]);
                rc = 0;
            }
            free(l1);
        }
    }
    libxl_free_all(&gc);
    return rc;
}

int libxl_devices_destroy(libxl_ctx *ctx, uint32_t domid, int force)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *path, *be_path, *fe_path;
    unsigned int num1, num2;
    char **l1 = NULL, **l2 = NULL;
    int i, j, n = 0, n_watches = 0;
    flexarray_t *toremove;

    toremove = flexarray_make(16, 1);
    path = libxl_sprintf(&gc, "/local/domain/%d/device", domid);
    l1 = libxl_xs_directory(&gc, XBT_NULL, path, &num1);
    if (!l1) {
        XL_LOG(ctx, XL_LOG_ERROR, "%s is empty", path);
        goto out;
    }
    for (i = 0; i < num1; i++) {
        if (!strcmp("vfs", l1[i]))
            continue;
        path = libxl_sprintf(&gc, "/local/domain/%d/device/%s", domid, l1[i]);
        l2 = libxl_xs_directory(&gc, XBT_NULL, path, &num2);
        if (!l2)
            continue;
        for (j = 0; j < num2; j++) {
            fe_path = libxl_sprintf(&gc, "/local/domain/%d/device/%s/%s", domid, l1[i], l2[j]);
            be_path = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/backend", fe_path));
            if (be_path != NULL) {
                if (libxl_device_destroy(ctx, be_path, force) > 0)
                    n_watches++;
                flexarray_set(toremove, n++, libxl_dirname(&gc, be_path));
            } else {
                xs_rm(ctx->xsh, XBT_NULL, path);
            }
        }
    }
    if (!force) {
        /* Linux-ism. Most implementations leave the timeout
         * untouched after select. Linux, however, will chip
         * away the elapsed time from it, which is what we 
         * need to enforce a single time span waiting for
         * device destruction. */
        struct timeval tv;
        tv.tv_sec = LIBXL_DESTROY_TIMEOUT;
        tv.tv_usec = 0;
        while (n_watches > 0) {
            if (wait_for_dev_destroy(ctx, &tv)) {
                break;
            } else {
                n_watches--;
            }
        }
    }
    for (i = 0; i < n; i++) {
        flexarray_get(toremove, i, (void**) &path);
        xs_rm(ctx->xsh, XBT_NULL, path);
    }
out:
    flexarray_free(toremove);
    libxl_free_all(&gc);
    return 0;
}

int libxl_device_del(libxl_ctx *ctx, libxl_device *dev, int wait)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dom_path_backend, *backend_path;
    int rc;

    /* Create strings */
    dom_path_backend    = libxl_xs_get_dompath(&gc, dev->backend_domid);
    backend_path        = libxl_sprintf(&gc, "%s/backend/%s/%u/%d",
                                    dom_path_backend, 
                                    string_of_kinds[dev->backend_kind], 
                                    dev->domid, dev->devid);
    rc = libxl_device_destroy(ctx, backend_path, !wait);
    if (rc == -1) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (wait) {
        struct timeval tv;
        tv.tv_sec = LIBXL_DESTROY_TIMEOUT;
        tv.tv_usec = 0;
        (void)wait_for_dev_destroy(ctx, &tv);
    }

    rc = 0;

out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_wait_for_device_model(libxl_ctx *ctx,
                                uint32_t domid, char *state,
                                int (*check_callback)(libxl_ctx *ctx,
                                                      uint32_t domid,
                                                      const char *state,
                                                      void *userdata),
                                void *check_callback_userdata)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *path;
    char *p;
    unsigned int len;
    int rc = 0;
    struct xs_handle *xsh;
    int nfds;
    fd_set rfds;
    struct timeval tv;
    unsigned int num;
    char **l = NULL;

    xsh = xs_daemon_open();
    path = libxl_sprintf(&gc, "/local/domain/0/device-model/%d/state", domid);
    xs_watch(xsh, path, path);
    tv.tv_sec = LIBXL_DEVICE_MODEL_START_TIMEOUT;
    tv.tv_usec = 0;
    nfds = xs_fileno(xsh) + 1;
    while (rc > 0 || (!rc && tv.tv_sec > 0)) {
        p = xs_read(xsh, XBT_NULL, path, &len);
        if ( NULL == p )
            goto again;

        if ( NULL != state && strcmp(p, state) )
            goto again;

        if ( NULL != check_callback ) {
            rc = (*check_callback)(ctx, domid, p, check_callback_userdata);
            if ( rc > 0 )
                goto again;
        }

        free(p);
        xs_unwatch(xsh, path, path);
        xs_daemon_close(xsh);
        libxl_free_all(&gc);
        return rc;
again:
        free(p);
        FD_ZERO(&rfds);
        FD_SET(xs_fileno(xsh), &rfds);
        rc = select(nfds, &rfds, NULL, NULL, &tv);
        if (rc > 0) {
            l = xs_read_watch(xsh, &num);
            if (l != NULL)
                free(l);
            else
                goto again;
        }
    }
    xs_unwatch(xsh, path, path);
    xs_daemon_close(xsh);
    XL_LOG(ctx, XL_LOG_ERROR, "Device Model not ready");
    libxl_free_all(&gc);
    return -1;
}

int libxl_wait_for_backend(libxl_ctx *ctx, char *be_path, char *state)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int watchdog = 100;
    unsigned int len;
    char *p;
    char *path = libxl_sprintf(&gc, "%s/state", be_path);

    while (watchdog > 0) {
        p = xs_read(ctx->xsh, XBT_NULL, path, &len);
        if (p == NULL) {
            if (errno == ENOENT) {
                XL_LOG(ctx, XL_LOG_ERROR, "Backend %s does not exist",
                       be_path);
            } else {
                XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Failed to access backend %s",
                       be_path);
            }
            return -1;
        } else {
            if (!strcmp(p, state)) {
                return 0;
            } else {
                usleep(100000);
                watchdog--;
            }
        }
    }
    XL_LOG(ctx, XL_LOG_ERROR, "Backend %s not ready", be_path);
    libxl_free_all(&gc);
    return -1;
}

