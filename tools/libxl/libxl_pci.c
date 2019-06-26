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

#define PCI_BDF                "%04x:%02x:%02x.%01x"
#define PCI_BDF_SHORT          "%02x:%02x.%01x"
#define PCI_BDF_VDEVFN         "%04x:%02x:%02x.%01x@%02x"
#define PCI_OPTIONS            "msitranslate=%d,power_mgmt=%d"
#define PCI_BDF_XSPATH         "%04x-%02x-%02x-%01x"

static unsigned int pcidev_encode_bdf(libxl_device_pci *pcidev)
{
    unsigned int value;

    value = pcidev->domain << 16;
    value |= (pcidev->bus & 0xff) << 8;
    value |= (pcidev->dev & 0x1f) << 3;
    value |= (pcidev->func & 0x7);

    return value;
}

static void pcidev_struct_fill(libxl_device_pci *pcidev, unsigned int domain,
                               unsigned int bus, unsigned int dev,
                               unsigned int func, unsigned int vdevfn)
{
    pcidev->domain = domain;
    pcidev->bus = bus;
    pcidev->dev = dev;
    pcidev->func = func;
    pcidev->vdevfn = vdevfn;
}

static void libxl_create_pci_backend_device(libxl__gc *gc, flexarray_t *back, int num, libxl_device_pci *pcidev)
{
    flexarray_append(back, GCSPRINTF("key-%d", num));
    flexarray_append(back, GCSPRINTF(PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    flexarray_append(back, GCSPRINTF("dev-%d", num));
    flexarray_append(back, GCSPRINTF(PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    if (pcidev->vdevfn)
        flexarray_append_pair(back, GCSPRINTF("vdevfn-%d", num), GCSPRINTF("%x", pcidev->vdevfn));
    flexarray_append(back, GCSPRINTF("opts-%d", num));
    flexarray_append(back,
              GCSPRINTF("msitranslate=%d,power_mgmt=%d,permissive=%d",
                             pcidev->msitranslate, pcidev->power_mgmt,
                             pcidev->permissive));
    flexarray_append_pair(back, GCSPRINTF("state-%d", num), GCSPRINTF("%d", XenbusStateInitialising));
}

static void libxl__device_from_pcidev(libxl__gc *gc, uint32_t domid,
                                      libxl_device_pci *pcidev,
                                      libxl__device *device)
{
    device->backend_devid = 0;
    device->backend_domid = 0;
    device->backend_kind = LIBXL__DEVICE_KIND_PCI;
    device->devid = 0;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_PCI;
}

int libxl__create_pci_backend(libxl__gc *gc, uint32_t domid,
                              libxl_device_pci *pcidev, int num)
{
    flexarray_t *front = NULL;
    flexarray_t *back = NULL;
    libxl__device device;
    int i;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    LOGD(DEBUG, domid, "Creating pci backend");

    /* add pci device */
    libxl__device_from_pcidev(gc, domid, pcidev, &device);

    flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(back, "domain", libxl__domid_to_name(gc, domid));

    for (i = 0; i < num; i++, pcidev++)
        libxl_create_pci_backend_device(gc, back, i, pcidev);

    flexarray_append_pair(back, "num_devs", GCSPRINTF("%d", num));
    flexarray_append_pair(front, "backend-id", GCSPRINTF("%d", 0));
    flexarray_append_pair(front, "state", GCSPRINTF("%d", XenbusStateInitialising));

    return libxl__device_generic_add(gc, XBT_NULL, &device,
                                     libxl__xs_kvs_of_flexarray(gc, back),
                                     libxl__xs_kvs_of_flexarray(gc, front),
                                     NULL);
}

static int libxl__device_pci_add_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    flexarray_t *back;
    char *num_devs, *be_path;
    int num = 0;
    xs_transaction_t t = XBT_NULL;
    libxl__device *device;
    int rc;
    libxl_domain_config d_config;
    libxl_device_pci pcidev_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_pci_init(&pcidev_saved);
    libxl_device_pci_copy(CTX, &pcidev_saved, pcidev);

    be_path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                                LIBXL__DEVICE_KIND_PCI);
    num_devs = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/num_devs", be_path));
    if (!num_devs)
        return libxl__create_pci_backend(gc, domid, pcidev, 1);

    libxl_domain_type domtype = libxl__domain_type(gc, domid);
    if (domtype == LIBXL_DOMAIN_TYPE_INVALID)
        return ERROR_FAIL;

    if (!starting && domtype == LIBXL_DOMAIN_TYPE_PV) {
        if (libxl__wait_for_backend(gc, be_path, GCSPRINTF("%d", XenbusStateConnected)) < 0)
            return ERROR_FAIL;
    }

    back = flexarray_make(gc, 16, 1);

    LOGD(DEBUG, domid, "Adding new pci device to xenstore");
    num = atoi(num_devs);
    libxl_create_pci_backend_device(gc, back, num, pcidev);
    flexarray_append_pair(back, "num_devs", GCSPRINTF("%d", num + 1));
    if (!starting)
        flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateReconfiguring));

    GCNEW(device);
    libxl__device_from_pcidev(gc, domid, pcidev, device);

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc) goto out;

    device_add_domain_config(gc, &d_config, &libxl__pcidev_devtype,
                             &pcidev_saved);

    rc = libxl__dm_check_start(gc, &d_config, domid);
    if (rc) goto out;

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__set_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        libxl__xs_writev(gc, t, be_path, libxl__xs_kvs_of_flexarray(gc, back));

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

out:
    libxl__xs_transaction_abort(gc, &t);
    if (lock) libxl__unlock_domain_userdata(lock);
    libxl_device_pci_dispose(&pcidev_saved);
    libxl_domain_config_dispose(&d_config);
    return rc;
}

static int libxl__device_pci_remove_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *be_path, *num_devs_path, *num_devs, *xsdev, *tmp, *tmppath;
    int num, i, j;
    xs_transaction_t t;

    be_path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                                LIBXL__DEVICE_KIND_PCI);
    num_devs_path = GCSPRINTF("%s/num_devs", be_path);
    num_devs = libxl__xs_read(gc, XBT_NULL, num_devs_path);
    if (!num_devs)
        return ERROR_INVAL;
    num = atoi(num_devs);

    libxl_domain_type domtype = libxl__domain_type(gc, domid);
    if (domtype == LIBXL_DOMAIN_TYPE_INVALID)
        return ERROR_FAIL;

    if (domtype == LIBXL_DOMAIN_TYPE_PV) {
        if (libxl__wait_for_backend(gc, be_path, GCSPRINTF("%d", XenbusStateConnected)) < 0) {
            LOGD(DEBUG, domid, "pci backend at %s is not ready", be_path);
            return ERROR_FAIL;
        }
    }

    for (i = 0; i < num; i++) {
        unsigned int domain = 0, bus = 0, dev = 0, func = 0;
        xsdev = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/dev-%d", be_path, i));
        sscanf(xsdev, PCI_BDF, &domain, &bus, &dev, &func);
        if (domain == pcidev->domain && bus == pcidev->bus &&
            pcidev->dev == dev && pcidev->func == func) {
            break;
        }
    }
    if (i == num) {
        LOGD(ERROR, domid, "Couldn't find the device on xenstore");
        return ERROR_INVAL;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, GCSPRINTF("%s/state-%d", be_path, i), GCSPRINTF("%d", XenbusStateClosing), 1);
    xs_write(ctx->xsh, t, GCSPRINTF("%s/state", be_path), GCSPRINTF("%d", XenbusStateReconfiguring), 1);
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    if (domtype == LIBXL_DOMAIN_TYPE_PV) {
        if (libxl__wait_for_backend(gc, be_path, GCSPRINTF("%d", XenbusStateConnected)) < 0) {
            LOGD(DEBUG, domid, "pci backend at %s is not ready", be_path);
            return ERROR_FAIL;
        }
    }

retry_transaction2:
    t = xs_transaction_start(ctx->xsh);
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/state-%d", be_path, i));
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/key-%d", be_path, i));
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/dev-%d", be_path, i));
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/vdev-%d", be_path, i));
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/opts-%d", be_path, i));
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/vdevfn-%d", be_path, i));
    libxl__xs_printf(gc, t, num_devs_path, "%d", num - 1);
    for (j = i + 1; j < num; j++) {
        tmppath = GCSPRINTF("%s/state-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, GCSPRINTF("%s/state-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = GCSPRINTF("%s/dev-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, GCSPRINTF("%s/dev-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = GCSPRINTF("%s/key-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, GCSPRINTF("%s/key-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = GCSPRINTF("%s/vdev-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, GCSPRINTF("%s/vdev-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = GCSPRINTF("%s/opts-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, GCSPRINTF("%s/opts-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = GCSPRINTF("%s/vdevfn-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, GCSPRINTF("%s/vdevfn-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
    }
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction2;

    if (num == 1) {
        libxl__device dev;
        if (libxl__parse_backend_path(gc, be_path, &dev) != 0)
            return ERROR_FAIL;

        dev.domid = domid;
        dev.kind = LIBXL__DEVICE_KIND_PCI;
        dev.devid = 0;

        libxl__device_destroy(gc, &dev);
        return 0;
    }

    return 0;
}

static int get_all_assigned_devices(libxl__gc *gc, libxl_device_pci **list, int *num)
{
    char **domlist;
    unsigned int nd = 0, i;

    *list = NULL;
    *num = 0;

    domlist = libxl__xs_directory(gc, XBT_NULL, "/local/domain", &nd);
    for(i = 0; i < nd; i++) {
        char *path, *num_devs;

        path = GCSPRINTF("/local/domain/0/backend/%s/%s/0/num_devs",
                         libxl__device_kind_to_string(LIBXL__DEVICE_KIND_PCI),
                         domlist[i]);
        num_devs = libxl__xs_read(gc, XBT_NULL, path);
        if ( num_devs ) {
            int ndev = atoi(num_devs), j;
            char *devpath, *bdf;

            for(j = 0; j < ndev; j++) {
                devpath = GCSPRINTF("/local/domain/0/backend/%s/%s/0/dev-%u",
                                    libxl__device_kind_to_string(LIBXL__DEVICE_KIND_PCI),
                                    domlist[i], j);
                bdf = libxl__xs_read(gc, XBT_NULL, devpath);
                if ( bdf ) {
                    unsigned dom, bus, dev, func;
                    if ( sscanf(bdf, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
                        continue;

                    *list = realloc(*list, sizeof(libxl_device_pci) * ((*num) + 1));
                    if (*list == NULL)
                        return ERROR_NOMEM;
                    pcidev_struct_fill(*list + *num, dom, bus, dev, func, 0);
                    (*num)++;
                }
            }
        }
    }
    libxl__ptr_add(gc, *list);

    return 0;
}

static int is_pcidev_in_array(libxl_device_pci *assigned, int num_assigned,
                       int dom, int bus, int dev, int func)
{
    int i;

    for(i = 0; i < num_assigned; i++) {
        if ( assigned[i].domain != dom )
            continue;
        if ( assigned[i].bus != bus )
            continue;
        if ( assigned[i].dev != dev )
            continue;
        if ( assigned[i].func != func )
            continue;
        return 1;
    }

    return 0;
}

/* Write the standard BDF into the sysfs path given by sysfs_path. */
static int sysfs_write_bdf(libxl__gc *gc, const char * sysfs_path,
                           libxl_device_pci *pcidev)
{
    int rc, fd;
    char *buf;

    fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "Couldn't open %s", sysfs_path);
        return ERROR_FAIL;
    }

    buf = GCSPRINTF(PCI_BDF, pcidev->domain, pcidev->bus,
                    pcidev->dev, pcidev->func);
    rc = write(fd, buf, strlen(buf));
    /* Annoying to have two if's, but we need the errno */
    if (rc < 0)
        LOGE(ERROR, "write to %s returned %d", sysfs_path, rc);
    close(fd);

    if (rc < 0)
        return ERROR_FAIL;

    return 0;
}

libxl_device_pci *libxl_device_pci_assignable_list(libxl_ctx *ctx, int *num)
{
    GC_INIT(ctx);
    libxl_device_pci *pcidevs = NULL, *new, *assigned;
    struct dirent *de;
    DIR *dir;
    int r, num_assigned;

    *num = 0;

    r = get_all_assigned_devices(gc, &assigned, &num_assigned);
    if (r) goto out;

    dir = opendir(SYSFS_PCIBACK_DRIVER);
    if (NULL == dir) {
        if (errno == ENOENT) {
            LOG(ERROR, "Looks like pciback driver not loaded");
        } else {
            LOGE(ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER);
        }
        goto out;
    }

    while((de = readdir(dir))) {
        unsigned dom, bus, dev, func;
        if (sscanf(de->d_name, PCI_BDF, &dom, &bus, &dev, &func) != 4)
            continue;

        if (is_pcidev_in_array(assigned, num_assigned, dom, bus, dev, func))
            continue;

        new = realloc(pcidevs, ((*num) + 1) * sizeof(*new));
        if (NULL == new)
            continue;

        pcidevs = new;
        new = pcidevs + *num;

        memset(new, 0, sizeof(*new));
        pcidev_struct_fill(new, dom, bus, dev, func, 0);
        (*num)++;
    }

    closedir(dir);
out:
    GC_FREE;
    return pcidevs;
}

/* Unbind device from its current driver, if any.  If driver_path is non-NULL,
 * store the path to the original driver in it. */
static int sysfs_dev_unbind(libxl__gc *gc, libxl_device_pci *pcidev,
                            char **driver_path)
{
    char * spath, *dp = NULL;
    struct stat st;

    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/driver",
                           pcidev->domain,
                           pcidev->bus,
                           pcidev->dev,
                           pcidev->func);
    if ( !lstat(spath, &st) ) {
        /* Find the canonical path to the driver. */
        dp = libxl__zalloc(gc, PATH_MAX);
        dp = realpath(spath, dp);
        if ( !dp ) {
            LOGE(ERROR, "realpath() failed");
            return -1;
        }

        LOG(DEBUG, "Driver re-plug path: %s", dp);

        /* Unbind from the old driver */
        spath = GCSPRINTF("%s/unbind", dp);
        if ( sysfs_write_bdf(gc, spath, pcidev) < 0 ) {
            LOGE(ERROR, "Couldn't unbind device");
            return -1;
        }
    }

    if ( driver_path )
        *driver_path = dp;

    return 0;
}

static uint16_t sysfs_dev_get_vendor(libxl__gc *gc, libxl_device_pci *pcidev)
{
    char *pci_device_vendor_path =
            GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/vendor",
                      pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    uint16_t read_items;
    uint16_t pci_device_vendor;

    FILE *f = fopen(pci_device_vendor_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have vendor attribute",
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        return 0xffff;
    }
    read_items = fscanf(f, "0x%hx\n", &pci_device_vendor);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read vendor of pci device "PCI_BDF,
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        return 0xffff;
    }

    return pci_device_vendor;
}

static uint16_t sysfs_dev_get_device(libxl__gc *gc, libxl_device_pci *pcidev)
{
    char *pci_device_device_path =
            GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/device",
                      pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    uint16_t read_items;
    uint16_t pci_device_device;

    FILE *f = fopen(pci_device_device_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have device attribute",
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        return 0xffff;
    }
    read_items = fscanf(f, "0x%hx\n", &pci_device_device);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read device of pci device "PCI_BDF,
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        return 0xffff;
    }

    return pci_device_device;
}

static int sysfs_dev_get_class(libxl__gc *gc, libxl_device_pci *pcidev,
                               unsigned long *class)
{
    char *pci_device_class_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/class",
                     pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    int read_items, ret = 0;

    FILE *f = fopen(pci_device_class_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have class attribute",
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        ret = ERROR_FAIL;
        goto out;
    }
    read_items = fscanf(f, "0x%lx\n", class);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read class of pci device "PCI_BDF,
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        ret = ERROR_FAIL;
    }

out:
    return ret;
}

/*
 * Some devices may need some ways to work well. Here like IGD,
 * we have to pass a specific option to qemu.
 */
bool libxl__is_igd_vga_passthru(libxl__gc *gc,
                                const libxl_domain_config *d_config)
{
    unsigned int i;
    uint16_t pt_vendor, pt_device;
    unsigned long class;

    for (i = 0 ; i < d_config->num_pcidevs ; i++) {
        libxl_device_pci *pcidev = &d_config->pcidevs[i];
        pt_vendor = sysfs_dev_get_vendor(gc, pcidev);
        pt_device = sysfs_dev_get_device(gc, pcidev);

        if (pt_vendor == 0xffff || pt_device == 0xffff ||
            pt_vendor != 0x8086)
            continue;

        if (sysfs_dev_get_class(gc, pcidev, &class))
            continue;
        if (class == 0x030000)
            return true;
    }

    return false;
}

/*
 * A brief comment about slots.  I don't know what slots are for; however,
 * I have by experimentation determined:
 * - Before a device can be bound to pciback, its BDF must first be listed
 *   in pciback/slots
 * - The way to get the BDF listed there is to write BDF to
 *   pciback/new_slot
 * - Writing the same BDF to pciback/new_slot is not idempotent; it results
 *   in two entries of the BDF in pciback/slots
 * It's not clear whether having two entries in pciback/slots is a problem
 * or not.  Just to be safe, this code does the conservative thing, and
 * first checks to see if there is a slot, adding one only if one does not
 * already exist.
 */

/* Scan through /sys/.../pciback/slots looking for pcidev's BDF */
static int pciback_dev_has_slot(libxl__gc *gc, libxl_device_pci *pcidev)
{
    FILE *f;
    int rc = 0;
    unsigned dom, bus, dev, func;

    f = fopen(SYSFS_PCIBACK_DRIVER"/slots", "r");

    if (f == NULL) {
        LOGE(ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER"/slots");
        return ERROR_FAIL;
    }

    while(fscanf(f, "%x:%x:%x.%d\n", &dom, &bus, &dev, &func)==4) {
        if(dom == pcidev->domain
           && bus == pcidev->bus
           && dev == pcidev->dev
           && func == pcidev->func) {
            rc = 1;
            goto out;
        }
    }
out:
    fclose(f);
    return rc;
}

static int pciback_dev_is_assigned(libxl__gc *gc, libxl_device_pci *pcidev)
{
    char * spath;
    int rc;
    struct stat st;

    if ( access(SYSFS_PCIBACK_DRIVER, F_OK) < 0 ) {
        if ( errno == ENOENT ) {
            LOG(ERROR, "Looks like pciback driver is not loaded");
        } else {
            LOGE(ERROR, "Can't access "SYSFS_PCIBACK_DRIVER);
        }
        return -1;
    }

    spath = GCSPRINTF(SYSFS_PCIBACK_DRIVER"/"PCI_BDF,
                      pcidev->domain, pcidev->bus,
                      pcidev->dev, pcidev->func);
    rc = lstat(spath, &st);

    if( rc == 0 )
        return 1;
    if ( rc < 0 && errno == ENOENT )
        return 0;
    LOGE(ERROR, "Accessing %s", spath);
    return -1;
}

static int pciback_dev_assign(libxl__gc *gc, libxl_device_pci *pcidev)
{
    int rc;

    if ( (rc=pciback_dev_has_slot(gc, pcidev)) < 0 ) {
        LOGE(ERROR, "Error checking for pciback slot");
        return ERROR_FAIL;
    } else if (rc == 0) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/new_slot",
                             pcidev) < 0 ) {
            LOGE(ERROR, "Couldn't bind device to pciback!");
            return ERROR_FAIL;
        }
    }

    if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/bind", pcidev) < 0 ) {
        LOGE(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }
    return 0;
}

static int pciback_dev_unassign(libxl__gc *gc, libxl_device_pci *pcidev)
{
    /* Remove from pciback */
    if ( sysfs_dev_unbind(gc, pcidev, NULL) < 0 ) {
        LOG(ERROR, "Couldn't unbind device!");
        return ERROR_FAIL;
    }

    /* Remove slot if necessary */
    if ( pciback_dev_has_slot(gc, pcidev) > 0 ) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/remove_slot",
                             pcidev) < 0 ) {
            LOGE(ERROR, "Couldn't remove pciback slot");
            return ERROR_FAIL;
        }
    }
    return 0;
}

#define PCIBACK_INFO_PATH "/libxl/pciback"

static void pci_assignable_driver_path_write(libxl__gc *gc,
                                            libxl_device_pci *pcidev,
                                            char *driver_path)
{
    char *path;

    path = GCSPRINTF(PCIBACK_INFO_PATH"/"PCI_BDF_XSPATH"/driver_path",
                     pcidev->domain,
                     pcidev->bus,
                     pcidev->dev,
                     pcidev->func);
    if ( libxl__xs_printf(gc, XBT_NULL, path, "%s", driver_path) < 0 ) {
        LOGE(WARN, "Write of %s to node %s failed.", driver_path, path);
    }
}

static char * pci_assignable_driver_path_read(libxl__gc *gc,
                                              libxl_device_pci *pcidev)
{
    return libxl__xs_read(gc, XBT_NULL,
                          GCSPRINTF(
                           PCIBACK_INFO_PATH "/" PCI_BDF_XSPATH "/driver_path",
                           pcidev->domain,
                           pcidev->bus,
                           pcidev->dev,
                           pcidev->func));
}

static void pci_assignable_driver_path_remove(libxl__gc *gc,
                                              libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);

    /* Remove the xenstore entry */
    xs_rm(ctx->xsh, XBT_NULL,
          GCSPRINTF(PCIBACK_INFO_PATH "/" PCI_BDF_XSPATH,
                    pcidev->domain,
                    pcidev->bus,
                    pcidev->dev,
                    pcidev->func) );
}

static int libxl__device_pci_assignable_add(libxl__gc *gc,
                                            libxl_device_pci *pcidev,
                                            int rebind)
{
    unsigned dom, bus, dev, func;
    char *spath, *driver_path = NULL;
    int rc;
    struct stat st;

    /* Local copy for convenience */
    dom = pcidev->domain;
    bus = pcidev->bus;
    dev = pcidev->dev;
    func = pcidev->func;

    /* See if the device exists */
    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF, dom, bus, dev, func);
    if ( lstat(spath, &st) ) {
        LOGE(ERROR, "Couldn't lstat %s", spath);
        return ERROR_FAIL;
    }

    /* Check to see if it's already assigned to pciback */
    rc = pciback_dev_is_assigned(gc, pcidev);
    if ( rc < 0 ) {
        return ERROR_FAIL;
    }
    if ( rc ) {
        LOG(WARN, PCI_BDF" already assigned to pciback", dom, bus, dev, func);
        return 0;
    }

    /* Check to see if there's already a driver that we need to unbind from */
    if ( sysfs_dev_unbind(gc, pcidev, &driver_path ) ) {
        LOG(ERROR, "Couldn't unbind "PCI_BDF" from driver",
            dom, bus, dev, func);
        return ERROR_FAIL;
    }

    /* Store driver_path for rebinding to dom0 */
    if ( rebind ) {
        if ( driver_path ) {
            pci_assignable_driver_path_write(gc, pcidev, driver_path);
        } else if ( (driver_path =
                     pci_assignable_driver_path_read(gc, pcidev)) != NULL ) {
            LOG(INFO, PCI_BDF" not bound to a driver, will be rebound to %s",
                dom, bus, dev, func, driver_path);
        } else {
            LOG(WARN, PCI_BDF" not bound to a driver, will not be rebound.",
                dom, bus, dev, func);
        }
    } else {
        pci_assignable_driver_path_remove(gc, pcidev);
    }

    if ( pciback_dev_assign(gc, pcidev) ) {
        LOG(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }

    return 0;
}

static int libxl__device_pci_assignable_remove(libxl__gc *gc,
                                               libxl_device_pci *pcidev,
                                               int rebind)
{
    int rc;
    char *driver_path;

    /* Unbind from pciback */
    if ( (rc=pciback_dev_is_assigned(gc, pcidev)) < 0 ) {
        return ERROR_FAIL;
    } else if ( rc ) {
        pciback_dev_unassign(gc, pcidev);
    } else {
        LOG(WARN, "Not bound to pciback");
    }

    /* Rebind if necessary */
    driver_path = pci_assignable_driver_path_read(gc, pcidev);

    if ( driver_path ) {
        if ( rebind ) {
            LOG(INFO, "Rebinding to driver at %s", driver_path);

            if ( sysfs_write_bdf(gc,
                                 GCSPRINTF("%s/bind", driver_path),
                                 pcidev) < 0 ) {
                LOGE(ERROR, "Couldn't bind device to %s", driver_path);
                return -1;
            }

            pci_assignable_driver_path_remove(gc, pcidev);
        }
    } else {
        if ( rebind ) {
            LOG(WARN,
                "Couldn't find path for original driver; not rebinding");
        }
    }

    return 0;
}

int libxl_device_pci_assignable_add(libxl_ctx *ctx, libxl_device_pci *pcidev,
                                    int rebind)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_assignable_add(gc, pcidev, rebind);

    GC_FREE;
    return rc;
}


int libxl_device_pci_assignable_remove(libxl_ctx *ctx, libxl_device_pci *pcidev,
                                       int rebind)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_assignable_remove(gc, pcidev, rebind);

    GC_FREE;
    return rc;
}

/*
 * This function checks that all functions of a device are bound to pciback
 * driver. It also initialises a bit-mask of which function numbers are present
 * on that device.
*/
static int pci_multifunction_check(libxl__gc *gc, libxl_device_pci *pcidev, unsigned int *func_mask)
{
    struct dirent *de;
    DIR *dir;

    *func_mask = 0;

    dir = opendir(SYSFS_PCI_DEV);
    if ( NULL == dir ) {
        LOGE(ERROR, "Couldn't open %s", SYSFS_PCI_DEV);
        return -1;
    }

    while( (de = readdir(dir)) ) {
        unsigned dom, bus, dev, func;
        struct stat st;
        char *path;

        if ( sscanf(de->d_name, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
            continue;
        if ( pcidev->domain != dom )
            continue;
        if ( pcidev->bus != bus )
            continue;
        if ( pcidev->dev != dev )
            continue;

        path = GCSPRINTF("%s/" PCI_BDF, SYSFS_PCIBACK_DRIVER, dom, bus, dev, func);
        if ( lstat(path, &st) ) {
            if ( errno == ENOENT )
                LOG(ERROR, PCI_BDF " is not assigned to pciback driver",
                    dom, bus, dev, func);
            else
                LOGE(ERROR, "Couldn't lstat %s", path);
            closedir(dir);
            return -1;
        }
        (*func_mask) |= (1 << func);
    }

    closedir(dir);
    return 0;
}

static int pci_ins_check(libxl__gc *gc, uint32_t domid, const char *state, void *priv)
{
    char *orig_state = priv;

    if ( !strcmp(state, "pci-insert-failed") )
        return -1;
    if ( !strcmp(state, "pci-inserted") )
        return 0;
    if ( !strcmp(state, orig_state) )
        return 1;

    return 1;
}

static int qemu_pci_add_xenstore(libxl__gc *gc, uint32_t domid,
                                 libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc = 0;
    char *path;
    char *state, *vdevfn;
    uint32_t dm_domid;

    dm_domid = libxl_get_stubdom_id(CTX, domid);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    state = libxl__xs_read(gc, XBT_NULL, path);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/parameter");
    if (pcidev->vdevfn) {
        libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF_VDEVFN","PCI_OPTIONS,
                         pcidev->domain, pcidev->bus, pcidev->dev,
                         pcidev->func, pcidev->vdevfn, pcidev->msitranslate,
                         pcidev->power_mgmt);
    } else {
        libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF","PCI_OPTIONS,
                         pcidev->domain,  pcidev->bus, pcidev->dev,
                         pcidev->func, pcidev->msitranslate, pcidev->power_mgmt);
    }

    libxl__qemu_traditional_cmd(gc, domid, "pci-ins");
    rc = libxl__wait_for_device_model_deprecated(gc, domid, NULL, NULL,
                                      pci_ins_check, state);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/parameter");
    vdevfn = libxl__xs_read(gc, XBT_NULL, path);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    if ( rc < 0 )
        LOGD(ERROR, domid, "qemu refused to add device: %s", vdevfn);
    else if ( sscanf(vdevfn, "0x%x", &pcidev->vdevfn) != 1 ) {
        LOGD(ERROR, domid, "wrong format for the vdevfn: '%s'", vdevfn);
        rc = -1;
    }
    xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));

    return rc;
}

static int do_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_domain_type type = libxl__domain_type(gc, domid);
    char *sysfs_path;
    FILE *f;
    unsigned long long start, end, flags, size;
    int irq, i, rc, hvm = 0;
    uint32_t flag = XEN_DOMCTL_DEV_RDM_RELAXED;
    uint32_t domainid = domid;
    bool isstubdom = libxl_is_stubdom(ctx, domid, &domainid);

    if (type == LIBXL_DOMAIN_TYPE_INVALID)
        return ERROR_FAIL;

    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        hvm = 1;
        if (libxl__wait_for_device_model_deprecated(gc, domid, "running",
                                         NULL, NULL, NULL) < 0) {
            return ERROR_FAIL;
        }
        switch (libxl__device_model_version_running(gc, domid)) {
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
                rc = qemu_pci_add_xenstore(gc, domid, pcidev);
                break;
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
                rc = libxl__qmp_pci_add(gc, domid, pcidev);
                break;
            default:
                return ERROR_INVAL;
        }
        if ( rc )
            return ERROR_FAIL;
    }

    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func);
    f = fopen(sysfs_path, "r");
    start = end = flags = size = 0;
    irq = 0;

    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        return ERROR_FAIL;
    }
    for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
        if (fscanf(f, "0x%llx 0x%llx 0x%llx\n", &start, &end, &flags) != 3)
            continue;
        size = end - start + 1;
        if (start) {
            if (flags & PCI_BAR_IO) {
                rc = xc_domain_ioport_permission(ctx->xch, domid, start, size, 1);
                if (rc < 0) {
                    LOGED(ERROR, domainid,
                          "Error: xc_domain_ioport_permission error 0x%llx/0x%llx",
                          start,
                          size);
                    fclose(f);
                    return ERROR_FAIL;
                }
            } else {
                rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 1);
                if (rc < 0) {
                    LOGED(ERROR, domainid,
                          "Error: xc_domain_iomem_permission error 0x%llx/0x%llx",
                          start,
                          size);
                    fclose(f);
                    return ERROR_FAIL;
                }
            }
        }
    }
    fclose(f);
    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
                                pcidev->bus, pcidev->dev, pcidev->func);
    f = fopen(sysfs_path, "r");
    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        goto out;
    }
    if ((fscanf(f, "%u", &irq) == 1) && irq) {
        rc = xc_physdev_map_pirq(ctx->xch, domid, irq, &irq);
        if (rc < 0) {
            LOGED(ERROR, domainid, "Error: xc_physdev_map_pirq irq=%d", irq);
            fclose(f);
            return ERROR_FAIL;
        }
        rc = xc_domain_irq_permission(ctx->xch, domid, irq, 1);
        if (rc < 0) {
            LOGED(ERROR, domainid, "Error: xc_domain_irq_permission irq=%d", irq);
            fclose(f);
            return ERROR_FAIL;
        }
    }
    fclose(f);

    /* Don't restrict writes to the PCI config space from this VM */
    if (pcidev->permissive) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/permissive",
                             pcidev) < 0 ) {
            LOGD(ERROR, domainid, "Setting permissive for device");
            return ERROR_FAIL;
        }
    }

out:
    if (!isstubdom) {
        if (pcidev->rdm_policy == LIBXL_RDM_RESERVE_POLICY_STRICT) {
            flag &= ~XEN_DOMCTL_DEV_RDM_RELAXED;
        } else if (pcidev->rdm_policy != LIBXL_RDM_RESERVE_POLICY_RELAXED) {
            LOGED(ERROR, domainid, "unknown rdm check flag.");
            return ERROR_FAIL;
        }
        rc = xc_assign_device(ctx->xch, domid, pcidev_encode_bdf(pcidev), flag);
        if (rc < 0 && (hvm || errno != ENOSYS)) {
            LOGED(ERROR, domainid, "xc_assign_device failed");
            return ERROR_FAIL;
        }
    }

    if (!starting)
        rc = libxl__device_pci_add_xenstore(gc, domid, pcidev, starting);
    else
        rc = 0;
    return rc;
}

static int libxl__device_pci_reset(libxl__gc *gc, unsigned int domain, unsigned int bus,
                                   unsigned int dev, unsigned int func)
{
    char *reset;
    int fd, rc;

    reset = GCSPRINTF("%s/do_flr", SYSFS_PCIBACK_DRIVER);
    fd = open(reset, O_WRONLY);
    if (fd >= 0) {
        char *buf = GCSPRINTF(PCI_BDF, domain, bus, dev, func);
        rc = write(fd, buf, strlen(buf));
        if (rc < 0)
            LOGD(ERROR, domain, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno != ENOENT)
        LOGED(ERROR, domain, "Failed to access pciback path %s", reset);
    reset = GCSPRINTF("%s/"PCI_BDF"/reset", SYSFS_PCI_DEV, domain, bus, dev, func);
    fd = open(reset, O_WRONLY);
    if (fd >= 0) {
        rc = write(fd, "1", 1);
        if (rc < 0)
            LOGED(ERROR, domain, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno == ENOENT) {
        LOGD(ERROR, domain,
             "The kernel doesn't support reset from sysfs for PCI device "PCI_BDF,
             domain, bus, dev, func);
    } else {
        LOGED(ERROR, domain, "Failed to access reset path %s", reset);
    }
    return -1;
}

static int libxl__device_pci_setdefault(libxl__gc *gc, uint32_t domid,
                                        libxl_device_pci *pci, bool hotplug)
{
    /* We'd like to force reserve rdm specific to a device by default.*/
    if (pci->rdm_policy == LIBXL_RDM_RESERVE_POLICY_INVALID)
        pci->rdm_policy = LIBXL_RDM_RESERVE_POLICY_STRICT;
    return 0;
}

int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid,
                         libxl_device_pci *pcidev,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;
    rc = libxl__device_pci_add(gc, domid, pcidev, 0);
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

static int libxl_pcidev_assignable(libxl_ctx *ctx, libxl_device_pci *pcidev)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_assignable_list(ctx, &num);
    for (i = 0; i < num; i++) {
        if (pcidevs[i].domain == pcidev->domain &&
            pcidevs[i].bus == pcidev->bus &&
            pcidevs[i].dev == pcidev->dev &&
            pcidevs[i].func == pcidev->func)
            break;
    }
    free(pcidevs);
    return i != num;
}

int libxl__device_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    unsigned int orig_vdev, pfunc_mask;
    libxl_device_pci *assigned;
    int num_assigned, i, rc;
    int stubdomid = 0;

    if (libxl__domain_type(gc, domid) == LIBXL_DOMAIN_TYPE_HVM) {
        rc = xc_test_assign_device(ctx->xch, domid, pcidev_encode_bdf(pcidev));
        if (rc) {
            LOGD(ERROR, domid,
                 "PCI device %04x:%02x:%02x.%u %s?",
                 pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func,
                 errno == ENOSYS ? "cannot be assigned - no IOMMU"
                 : "already assigned to a different guest");
            goto out;
        }
    }

    rc = libxl__device_pci_setdefault(gc, domid, pcidev, false);
    if (rc) goto out;

    if (pcidev->seize && !pciback_dev_is_assigned(gc, pcidev)) {
        rc = libxl__device_pci_assignable_add(gc, pcidev, 1);
        if ( rc )
            goto out;
    }

    if (!libxl_pcidev_assignable(ctx, pcidev)) {
        LOGD(ERROR, domid, "PCI device %x:%x:%x.%x is not assignable",
             pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = get_all_assigned_devices(gc, &assigned, &num_assigned);
    if ( rc ) {
        LOGD(ERROR, domid,
             "cannot determine if device is assigned, refusing to continue");
        goto out;
    }
    if ( is_pcidev_in_array(assigned, num_assigned, pcidev->domain,
                     pcidev->bus, pcidev->dev, pcidev->func) ) {
        LOGD(ERROR, domid, "PCI device already attached to a domain");
        rc = ERROR_FAIL;
        goto out;
    }

    libxl__device_pci_reset(gc, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        /* stubdomain is always running by now, even at create time */
        rc = do_pci_add(gc, stubdomid, &pcidev_s, 0);
        if ( rc )
            goto out;
    }

    orig_vdev = pcidev->vdevfn & ~7U;

    if ( pcidev->vfunc_mask == LIBXL_PCI_FUNC_ALL ) {
        if ( !(pcidev->vdevfn >> 3) ) {
            LOGD(ERROR, domid, "Must specify a v-slot for multi-function devices");
            rc = ERROR_INVAL;
            goto out;
        }
        if ( pci_multifunction_check(gc, pcidev, &pfunc_mask) ) {
            rc = ERROR_FAIL;
            goto out;
        }
        pcidev->vfunc_mask &= pfunc_mask;
        /* so now vfunc_mask == pfunc_mask */
    }else{
        pfunc_mask = (1 << pcidev->func);
    }

    for(rc = 0, i = 7; i >= 0; --i) {
        if ( (1 << i) & pfunc_mask ) {
            if ( pcidev->vfunc_mask == pfunc_mask ) {
                pcidev->func = i;
                pcidev->vdevfn = orig_vdev | i;
            }else{
                /* if not passing through multiple devices in a block make
                 * sure that virtual function number 0 is always used otherwise
                 * guest won't see the device
                 */
                pcidev->vdevfn = orig_vdev;
            }
            if ( do_pci_add(gc, domid, pcidev, starting) )
                rc = ERROR_FAIL;
        }
    }

out:
    return rc;
}

static void libxl__add_pcidevs(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                               libxl_domain_config *d_config,
                               libxl__multidev *multidev)
{
    AO_GC;
    libxl__ao_device *aodev = libxl__multidev_prepare(multidev);
    int i, rc = 0;

    for (i = 0; i < d_config->num_pcidevs; i++) {
        rc = libxl__device_pci_add(gc, domid, &d_config->pcidevs[i], 1);
        if (rc < 0) {
            LOGD(ERROR, domid, "libxl_device_pci_add failed: %d", rc);
            goto out;
        }
    }

    if (d_config->num_pcidevs > 0) {
        rc = libxl__create_pci_backend(gc, domid, d_config->pcidevs,
            d_config->num_pcidevs);
        if (rc < 0) {
            LOGD(ERROR, domid, "libxl_create_pci_backend failed: %d", rc);
            goto out;
        }
    }

out:
    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

static int qemu_pci_remove_xenstore(libxl__gc *gc, uint32_t domid,
                                    libxl_device_pci *pcidev, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *state;
    char *path;
    uint32_t dm_domid;

    dm_domid = libxl_get_stubdom_id(CTX, domid);

    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    state = libxl__xs_read(gc, XBT_NULL, path);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/parameter");
    libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF, pcidev->domain,
                     pcidev->bus, pcidev->dev, pcidev->func);

    /* Remove all functions at once atomically by only signalling
     * device-model for function 0 */
    if ( !force && (pcidev->vdevfn & 0x7) == 0 ) {
        libxl__qemu_traditional_cmd(gc, domid, "pci-rem");
        if (libxl__wait_for_device_model_deprecated(gc, domid, "pci-removed",
                                         NULL, NULL, NULL) < 0) {
            LOGD(ERROR, domid, "Device Model didn't respond in time");
            /* This depends on guest operating system acknowledging the
             * SCI, if it doesn't respond in time then we may wish to
             * force the removal.
             */
            return ERROR_FAIL;
        }
    }
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));

    return 0;
}

static int libxl__device_pci_remove_common(libxl__gc *gc, uint32_t domid,
                                           libxl_device_pci *pcidev, int force);

static int do_pci_remove(libxl__gc *gc, uint32_t domid,
                         libxl_device_pci *pcidev, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_device_pci *assigned;
    libxl_domain_type type = libxl__domain_type(gc, domid);
    int hvm = 0, rc, num;
    int stubdomid = 0;
    uint32_t domainid = domid;
    bool isstubdom = libxl_is_stubdom(ctx, domid, &domainid);


    assigned = libxl_device_pci_list(ctx, domid, &num);
    if ( assigned == NULL )
        return ERROR_FAIL;

    rc = ERROR_INVAL;
    if ( !is_pcidev_in_array(assigned, num, pcidev->domain,
                      pcidev->bus, pcidev->dev, pcidev->func) ) {
        LOGD(ERROR, domainid, "PCI device not attached to this domain");
        goto out_fail;
    }

    rc = ERROR_FAIL;
    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        hvm = 1;
        if (libxl__wait_for_device_model_deprecated(gc, domid, "running",
                                         NULL, NULL, NULL) < 0)
            goto out_fail;

        switch (libxl__device_model_version_running(gc, domid)) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            rc = qemu_pci_remove_xenstore(gc, domid, pcidev, force);
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            rc = libxl__qmp_pci_del(gc, domid, pcidev);
            break;
        default:
            rc = ERROR_INVAL;
            goto out_fail;
        }
        if (rc && !force) {
            rc = ERROR_FAIL;
            goto out_fail;
        }
    } else {
        assert(type == LIBXL_DOMAIN_TYPE_PV);

        char *sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
                                     pcidev->bus, pcidev->dev, pcidev->func);
        FILE *f = fopen(sysfs_path, "r");
        unsigned int start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
            goto skip1;
        }
        for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
            if (fscanf(f, "0x%x 0x%x 0x%x\n", &start, &end, &flags) != 3)
                continue;
            size = end - start + 1;
            if (start) {
                if (flags & PCI_BAR_IO) {
                    rc = xc_domain_ioport_permission(ctx->xch, domid, start, size, 0);
                    if (rc < 0)
                        LOGED(ERROR, domainid,
                              "xc_domain_ioport_permission error 0x%x/0x%x",
                              start,
                              size);
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 0);
                    if (rc < 0)
                        LOGED(ERROR, domainid,
                              "xc_domain_iomem_permission error 0x%x/0x%x",
                              start,
                              size);
                }
            }
        }
        fclose(f);
skip1:
        sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
                               pcidev->bus, pcidev->dev, pcidev->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
            goto out;
        }
        if ((fscanf(f, "%u", &irq) == 1) && irq) {
            rc = xc_physdev_unmap_pirq(ctx->xch, domid, irq);
            if (rc < 0) {
                LOGED(ERROR, domainid, "xc_physdev_unmap_pirq irq=%d", irq);
            }
            rc = xc_domain_irq_permission(ctx->xch, domid, irq, 0);
            if (rc < 0) {
                LOGED(ERROR, domainid, "xc_domain_irq_permission irq=%d", irq);
            }
        }
        fclose(f);
    }
out:
    /* don't do multiple resets while some functions are still passed through */
    if ( (pcidev->vdevfn & 0x7) == 0 ) {
        libxl__device_pci_reset(gc, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    }

    if (!isstubdom) {
        rc = xc_deassign_device(ctx->xch, domid, pcidev_encode_bdf(pcidev));
        if (rc < 0 && (hvm || errno != ENOSYS))
            LOGED(ERROR, domainid, "xc_deassign_device failed");
    }

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        libxl__device_pci_remove_common(gc, stubdomid, &pcidev_s, force);
    }

    libxl__device_pci_remove_xenstore(gc, domid, pcidev);

    rc = 0;
out_fail:
    free(assigned);
    return rc;

}

static int libxl__device_pci_remove_common(libxl__gc *gc, uint32_t domid,
                                           libxl_device_pci *pcidev, int force)
{
    unsigned int orig_vdev, pfunc_mask;
    int i, rc;

    orig_vdev = pcidev->vdevfn & ~7U;

    if ( pcidev->vfunc_mask == LIBXL_PCI_FUNC_ALL ) {
        if ( pci_multifunction_check(gc, pcidev, &pfunc_mask) ) {
            rc = ERROR_FAIL;
            goto out;
        }
        pcidev->vfunc_mask &= pfunc_mask;
    }else{
        pfunc_mask = (1 << pcidev->func);
    }

    for(rc = 0, i = 7; i >= 0; --i) {
        if ( (1 << i) & pfunc_mask ) {
            if ( pcidev->vfunc_mask == pfunc_mask ) {
                pcidev->func = i;
                pcidev->vdevfn = orig_vdev | i;
            }else{
                pcidev->vdevfn = orig_vdev;
            }
            if ( do_pci_remove(gc, domid, pcidev, force) )
                rc = ERROR_FAIL;
        }
    }

out:
    return rc;
}

int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_pci *pcidev,
                            const libxl_asyncop_how *ao_how)

{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_pci_remove_common(gc, domid, pcidev, 0);

    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl_device_pci_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_pci *pcidev,
                             const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_pci_remove_common(gc, domid, pcidev, 1);

    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

static int libxl__device_pci_from_xs_be(libxl__gc *gc,
                                        const char *be_path,
                                        libxl_devid nr, void *data)
{
    char *s;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;
    libxl_device_pci *pci = data;

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/dev-%d", be_path, nr));
    sscanf(s, PCI_BDF, &domain, &bus, &dev, &func);

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/vdevfn-%d", be_path, nr));
    if (s)
        vdevfn = strtol(s, (char **) NULL, 16);

    pcidev_struct_fill(pci, domain, bus, dev, func, vdevfn);

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/opts-%d", be_path, nr));
    if (s) {
        char *saveptr;
        char *p = strtok_r(s, ",=", &saveptr);
        do {
            while (*p == ' ')
                p++;
            if (!strcmp(p, "msitranslate")) {
                p = strtok_r(NULL, ",=", &saveptr);
                pci->msitranslate = atoi(p);
            } else if (!strcmp(p, "power_mgmt")) {
                p = strtok_r(NULL, ",=", &saveptr);
                pci->power_mgmt = atoi(p);
            } else if (!strcmp(p, "permissive")) {
                p = strtok_r(NULL, ",=", &saveptr);
                pci->permissive = atoi(p);
            }
        } while ((p = strtok_r(NULL, ",=", &saveptr)) != NULL);
    }

    return 0;
}

static int libxl__device_pci_get_num(libxl__gc *gc, const char *be_path,
                                     unsigned int *num)
{
    char *num_devs;
    int rc = 0;

    num_devs = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/num_devs", be_path));
    if (!num_devs)
        rc = ERROR_FAIL;
    else
        *num = atoi(num_devs);

    return rc;
}

libxl_device_pci *libxl_device_pci_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);
    char *be_path;
    unsigned int n, i;
    libxl_device_pci *pcidevs = NULL;

    *num = 0;

    be_path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                                LIBXL__DEVICE_KIND_PCI);
    if (libxl__device_pci_get_num(gc, be_path, &n))
        goto out;

    pcidevs = calloc(n, sizeof(libxl_device_pci));

    for (i = 0; i < n; i++)
        libxl__device_pci_from_xs_be(gc, be_path, i, pcidevs + i);

    *num = n;
out:
    GC_FREE;
    return pcidevs;
}

int libxl__device_pci_destroy_all(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_device_pci *pcidevs;
    int num, i, rc = 0;

    pcidevs = libxl_device_pci_list(ctx, domid, &num);
    if ( pcidevs == NULL )
        return 0;

    for (i = 0; i < num; i++) {
        /* Force remove on shutdown since, on HVM, qemu will not always
         * respond to SCI interrupt because the guest kernel has shut down the
         * devices by the time we even get here!
         */
        if (libxl__device_pci_remove_common(gc, domid, pcidevs + i, 1) < 0)
            rc = ERROR_FAIL;
    }

    free(pcidevs);
    return rc;
}

int libxl__grant_vga_iomem_permission(libxl__gc *gc, const uint32_t domid,
                                      libxl_domain_config *const d_config)
{
    int i, ret;

    if (!libxl_defbool_val(d_config->b_info.u.hvm.gfx_passthru))
        return 0;

    for (i = 0 ; i < d_config->num_pcidevs ; i++) {
        uint64_t vga_iomem_start = 0xa0000 >> XC_PAGE_SHIFT;
        uint32_t stubdom_domid;
        libxl_device_pci *pcidev = &d_config->pcidevs[i];
        unsigned long pci_device_class;

        if (sysfs_dev_get_class(gc, pcidev, &pci_device_class))
            continue;
        if (pci_device_class != 0x030000) /* VGA class */
            continue;

        stubdom_domid = libxl_get_stubdom_id(CTX, domid);
        ret = xc_domain_iomem_permission(CTX->xch, stubdom_domid,
                                         vga_iomem_start, 0x20, 1);
        if (ret < 0) {
            LOGED(ERROR, domid,
                  "failed to give stubdom%d access to iomem range "
                  "%"PRIx64"-%"PRIx64" for VGA passthru",
                  stubdom_domid,
                  vga_iomem_start, (vga_iomem_start + 0x20 - 1));
            return ret;
        }
        ret = xc_domain_iomem_permission(CTX->xch, domid,
                                         vga_iomem_start, 0x20, 1);
        if (ret < 0) {
            LOGED(ERROR, domid,
                  "failed to give dom%d access to iomem range "
                  "%"PRIx64"-%"PRIx64" for VGA passthru",
                  domid, vga_iomem_start, (vga_iomem_start + 0x20 - 1));
            return ret;
        }
        break;
    }

    return 0;
}

static int libxl_device_pci_compare(const libxl_device_pci *d1,
                                    const libxl_device_pci *d2)
{
    return COMPARE_PCI(d1, d2);
}

#define libxl__device_pci_update_devid NULL

DEFINE_DEVICE_TYPE_STRUCT_X(pcidev, pci, PCI,
    .get_num = libxl__device_pci_get_num,
    .from_xenstore = libxl__device_pci_from_xs_be,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
