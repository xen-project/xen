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
#define PCI_PT_QDEV_ID         "pci-pt-%02x_%02x.%01x"

static unsigned int pci_encode_bdf(libxl_device_pci *pci)
{
    unsigned int value;

    value = pci->domain << 16;
    value |= (pci->bus & 0xff) << 8;
    value |= (pci->dev & 0x1f) << 3;
    value |= (pci->func & 0x7);

    return value;
}

static void pci_struct_fill(libxl_device_pci *pci, unsigned int domain,
                            unsigned int bus, unsigned int dev,
                            unsigned int func)
{
    pci->domain = domain;
    pci->bus = bus;
    pci->dev = dev;
    pci->func = func;
}

static void libxl_create_pci_backend_device(libxl__gc *gc,
                                            flexarray_t *back,
                                            int num,
                                            const libxl_device_pci *pci)
{
    flexarray_append(back, GCSPRINTF("key-%d", num));
    flexarray_append(back, GCSPRINTF(PCI_BDF, pci->domain, pci->bus, pci->dev, pci->func));
    flexarray_append(back, GCSPRINTF("dev-%d", num));
    flexarray_append(back, GCSPRINTF(PCI_BDF, pci->domain, pci->bus, pci->dev, pci->func));
    if (pci->vdevfn)
        flexarray_append_pair(back, GCSPRINTF("vdevfn-%d", num), GCSPRINTF("%x", pci->vdevfn));
    if (pci->name)
        flexarray_append_pair(back, GCSPRINTF("name-%d", num), GCSPRINTF("%s", pci->name));
    flexarray_append(back, GCSPRINTF("opts-%d", num));
    flexarray_append(back,
              GCSPRINTF("msitranslate=%d,power_mgmt=%d,permissive=%d,rdm_policy=%s",
                        pci->msitranslate, pci->power_mgmt,
                        pci->permissive, libxl_rdm_reserve_policy_to_string(pci->rdm_policy)));
    flexarray_append_pair(back, GCSPRINTF("state-%d", num), GCSPRINTF("%d", XenbusStateInitialising));
}

static void libxl__device_from_pci(libxl__gc *gc, uint32_t domid,
                                   const libxl_device_pci *pci,
                                   libxl__device *device)
{
    device->backend_devid = 0;
    device->backend_domid = 0;
    device->backend_kind = LIBXL__DEVICE_KIND_PCI;
    device->devid = 0;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_PCI;
}

static void libxl__create_pci_backend(libxl__gc *gc, xs_transaction_t t,
                                      uint32_t domid, const libxl_device_pci *pci)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    flexarray_t *front, *back;
    char *fe_path, *be_path;
    struct xs_permissions fe_perms[2], be_perms[2];

    LOGD(DEBUG, domid, "Creating pci backend");

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    fe_path = libxl__domain_device_frontend_path(gc, domid, 0,
                                                 LIBXL__DEVICE_KIND_PCI);
    be_path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                                LIBXL__DEVICE_KIND_PCI);

    flexarray_append_pair(back, "frontend", fe_path);
    flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
    flexarray_append_pair(back, "online", GCSPRINTF("%d", 1));
    flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(back, "domain", libxl__domid_to_name(gc, domid));

    be_perms[0].id = 0;
    be_perms[0].perms = XS_PERM_NONE;
    be_perms[1].id = domid;
    be_perms[1].perms = XS_PERM_READ;

    xs_rm(ctx->xsh, t, be_path);
    xs_mkdir(ctx->xsh, t, be_path);
    xs_set_permissions(ctx->xsh, t, be_path, be_perms,
                       ARRAY_SIZE(be_perms));
    libxl__xs_writev(gc, t, be_path, libxl__xs_kvs_of_flexarray(gc, back));

    flexarray_append_pair(front, "backend", be_path);
    flexarray_append_pair(front, "backend-id", GCSPRINTF("%d", 0));
    flexarray_append_pair(front, "state", GCSPRINTF("%d", XenbusStateInitialising));

    fe_perms[0].id = domid;
    fe_perms[0].perms = XS_PERM_NONE;
    fe_perms[1].id = 0;
    fe_perms[1].perms = XS_PERM_READ;

    xs_rm(ctx->xsh, t, fe_path);
    xs_mkdir(ctx->xsh, t, fe_path);
    xs_set_permissions(ctx->xsh, t, fe_path,
                       fe_perms, ARRAY_SIZE(fe_perms));
    libxl__xs_writev(gc, t, fe_path, libxl__xs_kvs_of_flexarray(gc, front));
}

static int libxl__device_pci_add_xenstore(libxl__gc *gc,
                                          uint32_t domid,
                                          const libxl_device_pci *pci,
                                          bool starting)
{
    flexarray_t *back;
    char *num_devs, *be_path;
    int num = 0;
    xs_transaction_t t = XBT_NULL;
    int rc;
    libxl_domain_config d_config;
    libxl__flock *lock = NULL;
    bool is_stubdomain = libxl_is_stubdom(CTX, domid, NULL);

    /* Stubdomain doesn't have own config. */
    if (!is_stubdomain)
        libxl_domain_config_init(&d_config);

    be_path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                                LIBXL__DEVICE_KIND_PCI);
    num_devs = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/num_devs", be_path));

    libxl_domain_type domtype = libxl__domain_type(gc, domid);
    if (domtype == LIBXL_DOMAIN_TYPE_INVALID)
        return ERROR_FAIL;

    /* Wait is only needed if the backend already exists (num_devs != NULL) */
    if (num_devs && !starting && domtype == LIBXL_DOMAIN_TYPE_PV) {
        rc = libxl__wait_for_backend(gc, be_path,
                                     GCSPRINTF("%d", XenbusStateConnected));
        if (rc) return rc;
    }

    back = flexarray_make(gc, 16, 1);

    LOGD(DEBUG, domid, "Adding new pci device to xenstore");
    num = num_devs ? atoi(num_devs) : 0;
    libxl_create_pci_backend_device(gc, back, num, pci);
    flexarray_append_pair(back, "num_devs", GCSPRINTF("%d", num + 1));
    if (num && !starting)
        flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateReconfiguring));

    /*
     * Stubdomin config is derived from its target domain, it doesn't have
     * its own file.
     */
    if (!is_stubdomain && !starting) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        LOGD(DEBUG, domid, "Adding new pci device to config");
        device_add_domain_config(gc, &d_config, &libxl__pci_devtype,
                                 pci);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        if (lock) {
            rc = libxl__set_domain_configuration(gc, domid, &d_config);
            if (rc) goto out;
        }

        /* This is the first device, so create the backend */
        if (!num_devs)
            libxl__create_pci_backend(gc, t, domid, pci);

        libxl__xs_writev(gc, t, be_path, libxl__xs_kvs_of_flexarray(gc, back));

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

out:
    libxl__xs_transaction_abort(gc, &t);
    if (lock) libxl__unlock_file(lock);
    if (!is_stubdomain)
        libxl_domain_config_dispose(&d_config);
    return rc;
}

static int libxl__device_pci_remove_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pci)
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
        if (domain == pci->domain && bus == pci->bus &&
            pci->dev == dev && pci->func == func) {
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
    xs_rm(ctx->xsh, t, GCSPRINTF("%s/name-%d", be_path, i));
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
        tmppath = GCSPRINTF("%s/name-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, GCSPRINTF("%s/name-%d", be_path, j - 1), tmp, strlen(tmp));
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

static bool is_pci_in_array(libxl_device_pci *pcis, int num,
                            libxl_device_pci *pci)
{
    int i;

    for (i = 0; i < num; i++) {
        if (COMPARE_PCI(pci, &pcis[i]))
            break;
    }

    return i < num;
}

/* Write the standard BDF into the sysfs path given by sysfs_path. */
static int sysfs_write_bdf(libxl__gc *gc, const char * sysfs_path,
                           libxl_device_pci *pci)
{
    int rc, fd;
    char *buf;

    fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "Couldn't open %s", sysfs_path);
        return ERROR_FAIL;
    }

    buf = GCSPRINTF(PCI_BDF, pci->domain, pci->bus,
                    pci->dev, pci->func);
    rc = write(fd, buf, strlen(buf));
    /* Annoying to have two if's, but we need the errno */
    if (rc < 0)
        LOGE(ERROR, "write to %s returned %d", sysfs_path, rc);
    close(fd);

    if (rc < 0)
        return ERROR_FAIL;

    return 0;
}

#define PCI_INFO_PATH "/libxl/pci"

static char *pci_info_xs_path(libxl__gc *gc, libxl_device_pci *pci,
                              const char *node)
{
    return node ?
        GCSPRINTF(PCI_INFO_PATH"/"PCI_BDF_XSPATH"/%s",
                  pci->domain, pci->bus, pci->dev, pci->func,
                  node) :
        GCSPRINTF(PCI_INFO_PATH"/"PCI_BDF_XSPATH,
                  pci->domain, pci->bus, pci->dev, pci->func);
}


static int pci_info_xs_write(libxl__gc *gc, libxl_device_pci *pci,
                              const char *node, const char *val)
{
    char *path = pci_info_xs_path(gc, pci, node);
    int rc = libxl__xs_printf(gc, XBT_NULL, path, "%s", val);

    if (rc) LOGE(WARN, "Write of %s to node %s failed.", val, path);

    return rc;
}

static char *pci_info_xs_read(libxl__gc *gc, libxl_device_pci *pci,
                              const char *node)
{
    char *path = pci_info_xs_path(gc, pci, node);

    return libxl__xs_read(gc, XBT_NULL, path);
}

static void pci_info_xs_remove(libxl__gc *gc, libxl_device_pci *pci,
                               const char *node)
{
    char *path = pci_info_xs_path(gc, pci, node);
    libxl_ctx *ctx = libxl__gc_owner(gc);

    /* Remove the xenstore entry */
    xs_rm(ctx->xsh, XBT_NULL, path);
}

libxl_device_pci *libxl_device_pci_assignable_list(libxl_ctx *ctx, int *num)
{
    GC_INIT(ctx);
    libxl_device_pci *pcis = NULL, *new;
    struct dirent *de;
    DIR *dir;

    *num = 0;

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
        unsigned int dom, bus, dev, func;
        char *name;

        if (sscanf(de->d_name, PCI_BDF, &dom, &bus, &dev, &func) != 4)
            continue;

        new = realloc(pcis, ((*num) + 1) * sizeof(*new));
        if (NULL == new)
            continue;

        pcis = new;
        new = pcis + *num;

        libxl_device_pci_init(new);
        pci_struct_fill(new, dom, bus, dev, func);

        if (pci_info_xs_read(gc, new, "domid")) /* already assigned */
            continue;

        name = pci_info_xs_read(gc, new, "name");
        if (name) new->name = strdup(name);

        (*num)++;
    }

    closedir(dir);
out:
    GC_FREE;
    return pcis;
}

void libxl_device_pci_assignable_list_free(libxl_device_pci *list, int num)
{
    int i;

    for (i = 0; i < num; i++)
        libxl_device_pci_dispose(&list[i]);

    free(list);
}

/* Unbind device from its current driver, if any.  If driver_path is non-NULL,
 * store the path to the original driver in it. */
static int sysfs_dev_unbind(libxl__gc *gc, libxl_device_pci *pci,
                            char **driver_path)
{
    char * spath, *dp = NULL;
    struct stat st;

    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/driver",
                           pci->domain,
                           pci->bus,
                           pci->dev,
                           pci->func);
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
        if ( sysfs_write_bdf(gc, spath, pci) < 0 ) {
            LOGE(ERROR, "Couldn't unbind device");
            return -1;
        }
    }

    if ( driver_path )
        *driver_path = dp;

    return 0;
}

static uint16_t sysfs_dev_get_vendor(libxl__gc *gc, libxl_device_pci *pci)
{
    char *pci_device_vendor_path =
            GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/vendor",
                      pci->domain, pci->bus, pci->dev, pci->func);
    uint16_t read_items;
    uint16_t pci_device_vendor;

    FILE *f = fopen(pci_device_vendor_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have vendor attribute",
             pci->domain, pci->bus, pci->dev, pci->func);
        return 0xffff;
    }
    read_items = fscanf(f, "0x%hx\n", &pci_device_vendor);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read vendor of pci device "PCI_BDF,
             pci->domain, pci->bus, pci->dev, pci->func);
        return 0xffff;
    }

    return pci_device_vendor;
}

static uint16_t sysfs_dev_get_device(libxl__gc *gc, libxl_device_pci *pci)
{
    char *pci_device_device_path =
            GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/device",
                      pci->domain, pci->bus, pci->dev, pci->func);
    uint16_t read_items;
    uint16_t pci_device_device;

    FILE *f = fopen(pci_device_device_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have device attribute",
             pci->domain, pci->bus, pci->dev, pci->func);
        return 0xffff;
    }
    read_items = fscanf(f, "0x%hx\n", &pci_device_device);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read device of pci device "PCI_BDF,
             pci->domain, pci->bus, pci->dev, pci->func);
        return 0xffff;
    }

    return pci_device_device;
}

static int sysfs_dev_get_class(libxl__gc *gc, libxl_device_pci *pci,
                               unsigned long *class)
{
    char *pci_device_class_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/class",
                     pci->domain, pci->bus, pci->dev, pci->func);
    int read_items, ret = 0;

    FILE *f = fopen(pci_device_class_path, "r");
    if (!f) {
        LOGE(ERROR,
             "pci device "PCI_BDF" does not have class attribute",
             pci->domain, pci->bus, pci->dev, pci->func);
        ret = ERROR_FAIL;
        goto out;
    }
    read_items = fscanf(f, "0x%lx\n", class);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR,
             "cannot read class of pci device "PCI_BDF,
             pci->domain, pci->bus, pci->dev, pci->func);
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
        libxl_device_pci *pci = &d_config->pcidevs[i];
        pt_vendor = sysfs_dev_get_vendor(gc, pci);
        pt_device = sysfs_dev_get_device(gc, pci);

        if (pt_vendor == 0xffff || pt_device == 0xffff ||
            pt_vendor != 0x8086)
            continue;

        if (sysfs_dev_get_class(gc, pci, &class))
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

/* Scan through /sys/.../pciback/slots looking for pci's BDF */
static int pciback_dev_has_slot(libxl__gc *gc, libxl_device_pci *pci)
{
    FILE *f;
    int rc = 0;
    unsigned dom, bus, dev, func;

    f = fopen(SYSFS_PCIBACK_DRIVER"/slots", "r");

    if (f == NULL) {
        LOGE(ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER"/slots");
        return ERROR_FAIL;
    }

    while (fscanf(f, "%x:%x:%x.%d\n", &dom, &bus, &dev, &func) == 4) {
        if (dom == pci->domain
            && bus == pci->bus
            && dev == pci->dev
            && func == pci->func) {
            rc = 1;
            goto out;
        }
    }
out:
    fclose(f);
    return rc;
}

static int pciback_dev_is_assigned(libxl__gc *gc, libxl_device_pci *pci)
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
                      pci->domain, pci->bus,
                      pci->dev, pci->func);
    rc = lstat(spath, &st);

    if( rc == 0 )
        return 1;
    if ( rc < 0 && errno == ENOENT )
        return 0;
    LOGE(ERROR, "Accessing %s", spath);
    return -1;
}

static int pciback_dev_assign(libxl__gc *gc, libxl_device_pci *pci)
{
    int rc;

    if ( (rc = pciback_dev_has_slot(gc, pci)) < 0 ) {
        LOGE(ERROR, "Error checking for pciback slot");
        return ERROR_FAIL;
    } else if (rc == 0) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/new_slot",
                             pci) < 0 ) {
            LOGE(ERROR, "Couldn't bind device to pciback!");
            return ERROR_FAIL;
        }
    }

    if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/bind", pci) < 0 ) {
        LOGE(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }
    return 0;
}

static int pciback_dev_unassign(libxl__gc *gc, libxl_device_pci *pci)
{
    /* Remove from pciback */
    if ( sysfs_dev_unbind(gc, pci, NULL) < 0 ) {
        LOG(ERROR, "Couldn't unbind device!");
        return ERROR_FAIL;
    }

    /* Remove slot if necessary */
    if ( pciback_dev_has_slot(gc, pci) > 0 ) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/remove_slot",
                             pci) < 0 ) {
            LOGE(ERROR, "Couldn't remove pciback slot");
            return ERROR_FAIL;
        }
    }
    return 0;
}

static int libxl__device_pci_assignable_add(libxl__gc *gc,
                                            libxl_device_pci *pci,
                                            int rebind)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    unsigned dom, bus, dev, func;
    char *spath, *driver_path = NULL;
    const char *name;
    int rc;
    struct stat st;

    /* Local copy for convenience */
    dom = pci->domain;
    bus = pci->bus;
    dev = pci->dev;
    func = pci->func;
    name = pci->name;

    /* Sanitise any name that is set */
    if (name) {
        unsigned int i, n = strlen(name);

        if (n > 64) { /* Reasonable upper bound on name length */
            LOG(ERROR, "Name too long");
            return ERROR_FAIL;
        }

        for (i = 0; i < n; i++) {
            if (!isgraph(name[i])) {
                LOG(ERROR, "Names may only include printable characters");
                return ERROR_FAIL;
            }
        }
    }

    /* See if the device exists */
    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF, dom, bus, dev, func);
    if ( lstat(spath, &st) ) {
        LOGE(ERROR, "Couldn't lstat %s", spath);
        return ERROR_FAIL;
    }

    /* Check to see if it's already assigned to pciback */
    rc = pciback_dev_is_assigned(gc, pci);
    if ( rc < 0 ) {
        return ERROR_FAIL;
    }
    if ( rc ) {
        LOG(WARN, PCI_BDF" already assigned to pciback", dom, bus, dev, func);
        goto name;
    }

    /* Check to see if there's already a driver that we need to unbind from */
    if ( sysfs_dev_unbind(gc, pci, &driver_path ) ) {
        LOG(ERROR, "Couldn't unbind "PCI_BDF" from driver",
            dom, bus, dev, func);
        return ERROR_FAIL;
    }

    /* Store driver_path for rebinding to dom0 */
    if ( rebind ) {
        if ( driver_path ) {
            pci_info_xs_write(gc, pci, "driver_path", driver_path);
        } else if ( (driver_path =
                     pci_info_xs_read(gc, pci, "driver_path")) != NULL ) {
            LOG(INFO, PCI_BDF" not bound to a driver, will be rebound to %s",
                dom, bus, dev, func, driver_path);
        } else {
            LOG(WARN, PCI_BDF" not bound to a driver, will not be rebound.",
                dom, bus, dev, func);
        }
    } else {
        pci_info_xs_remove(gc, pci, "driver_path");
    }

    if ( pciback_dev_assign(gc, pci) ) {
        LOG(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }

name:
    if (name)
        pci_info_xs_write(gc, pci, "name", name);
    else
        pci_info_xs_remove(gc, pci, "name");

    /*
     * DOMID_IO is just a sentinel domain, without any actual mappings,
     * so always pass XEN_DOMCTL_DEV_RDM_RELAXED to avoid assignment being
     * unnecessarily denied.
     */
    rc = xc_assign_device(ctx->xch, DOMID_IO, pci_encode_bdf(pci),
                          XEN_DOMCTL_DEV_RDM_RELAXED);
    if ( rc < 0 ) {
        LOG(ERROR, "failed to quarantine "PCI_BDF, dom, bus, dev, func);
        return ERROR_FAIL;
    }

    return 0;
}

static int name2bdf(libxl__gc *gc, libxl_device_pci *pci)
{
    char **bdfs;
    unsigned int i, n;
    int rc = ERROR_NOTFOUND;

    bdfs = libxl__xs_directory(gc, XBT_NULL, PCI_INFO_PATH, &n);
    if (!bdfs || !n)
        goto out;

    for (i = 0; i < n; i++) {
        unsigned dom, bus, dev, func;
        char *name;

        if (sscanf(bdfs[i], PCI_BDF_XSPATH, &dom, &bus, &dev, &func) != 4)
            continue;

        pci_struct_fill(pci, dom, bus, dev, func);

        name = pci_info_xs_read(gc, pci, "name");
        if (name && !strcmp(name, pci->name)) {
            rc = 0;
            break;
        }
    }

out:
    if (!rc)
        LOG(DETAIL, "'%s' -> " PCI_BDF, pci->name, pci->domain,
            pci->bus, pci->dev, pci->func);

    return rc;
}

static int libxl__device_pci_assignable_remove(libxl__gc *gc,
                                               libxl_device_pci *pci,
                                               int rebind)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc;
    char *driver_path;

    /* If the device is named then we need to look up the BDF */
    if (pci->name) {
        rc = name2bdf(gc, pci);
        if (rc) return rc;
    }

    /* De-quarantine */
    rc = xc_deassign_device(ctx->xch, DOMID_IO, pci_encode_bdf(pci));
    if ( rc < 0 ) {
        LOG(ERROR, "failed to de-quarantine "PCI_BDF, pci->domain, pci->bus,
            pci->dev, pci->func);
        return ERROR_FAIL;
    }

    /* Unbind from pciback */
    if ( (rc = pciback_dev_is_assigned(gc, pci)) < 0 ) {
        return ERROR_FAIL;
    } else if ( rc ) {
        pciback_dev_unassign(gc, pci);
    } else {
        LOG(WARN, "Not bound to pciback");
    }

    /* Rebind if necessary */
    driver_path = pci_info_xs_read(gc, pci, "driver_path");

    if ( driver_path ) {
        if ( rebind ) {
            LOG(INFO, "Rebinding to driver at %s", driver_path);

            if ( sysfs_write_bdf(gc,
                                 GCSPRINTF("%s/bind", driver_path),
                                 pci) < 0 ) {
                LOGE(ERROR, "Couldn't bind device to %s", driver_path);
                return -1;
            }

            pci_info_xs_remove(gc, pci, "driver_path");
        }
    } else {
        if ( rebind ) {
            LOG(WARN,
                "Couldn't find path for original driver; not rebinding");
        }
    }

    pci_info_xs_remove(gc, pci, "name");

    return 0;
}

int libxl_device_pci_assignable_add(libxl_ctx *ctx, libxl_device_pci *pci,
                                    int rebind)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_assignable_add(gc, pci, rebind);

    GC_FREE;
    return rc;
}


int libxl_device_pci_assignable_remove(libxl_ctx *ctx, libxl_device_pci *pci,
                                       int rebind)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_assignable_remove(gc, pci, rebind);

    GC_FREE;
    return rc;
}

/*
 * This function checks that all functions of a device are bound to pciback
 * driver. It also initialises a bit-mask of which function numbers are present
 * on that device.
*/
static int pci_multifunction_check(libxl__gc *gc, libxl_device_pci *pci, unsigned int *func_mask)
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
        if ( pci->domain != dom )
            continue;
        if ( pci->bus != bus )
            continue;
        if ( pci->dev != dev )
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
                                 libxl_device_pci *pci)
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
    if (pci->vdevfn) {
        libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF_VDEVFN","PCI_OPTIONS,
                         pci->domain, pci->bus, pci->dev,
                         pci->func, pci->vdevfn, pci->msitranslate,
                         pci->power_mgmt);
    } else {
        libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF","PCI_OPTIONS,
                         pci->domain,  pci->bus, pci->dev,
                         pci->func, pci->msitranslate, pci->power_mgmt);
    }

    libxl__qemu_traditional_cmd(gc, domid, "pci-ins");
    rc = libxl__wait_for_device_model_deprecated(gc, domid, NULL, NULL,
                                      pci_ins_check, state);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/parameter");
    vdevfn = libxl__xs_read(gc, XBT_NULL, path);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    if ( rc < 0 )
        LOGD(ERROR, domid, "qemu refused to add device: %s", vdevfn);
    else if ( sscanf(vdevfn, "0x%x", &pci->vdevfn) != 1 ) {
        LOGD(ERROR, domid, "wrong format for the vdevfn: '%s'", vdevfn);
        rc = -1;
    }
    xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));

    return rc;
}

static int check_qemu_running(libxl__gc *gc,
                              libxl_domid domid,
                              libxl__xswait_state *xswa,
                              int rc,
                              const char *state)
{
    if (rc) {
        if (rc == ERROR_TIMEDOUT) {
            LOGD(ERROR, domid, "%s not ready", xswa->what);
        }
        goto out;
    }

    if (!state || strcmp(state, "running"))
        return ERROR_NOT_READY;

out:
    libxl__xswait_stop(gc, xswa);
    return rc;
}

typedef struct pci_add_state {
    /* filled by user of do_pci_add */
    libxl__ao_device *aodev;
    libxl_domid domid;
    bool starting;
    void (*callback)(libxl__egc *, struct pci_add_state *, int rc);

    /* private to device_pci_add_stubdom_wait */
    libxl__ev_devstate pciback_ds;

    /* private to do_pci_add */
    libxl__xswait_state xswait;
    libxl__ev_qmp qmp;
    libxl__ev_time timeout;
    libxl__ev_time timeout_retries;
    libxl_device_pci pci;
    libxl_domid pci_domid;
    int retries;
} pci_add_state;

static void pci_add_qemu_trad_watch_state_cb(libxl__egc *egc,
    libxl__xswait_state *xswa, int rc, const char *state);
static void pci_add_qmp_device_add(libxl__egc *, pci_add_state *);
static void pci_add_qmp_device_add_cb(libxl__egc *,
    libxl__ev_qmp *, const libxl__json_object *, int rc);
static void pci_add_qmp_device_add_retry(libxl__egc *egc, libxl__ev_time *ev,
    const struct timeval *requested_abs, int rc);
static void pci_add_qmp_query_pci_cb(libxl__egc *,
    libxl__ev_qmp *, const libxl__json_object *, int rc);
static void pci_add_timeout(libxl__egc *egc, libxl__ev_time *ev,
    const struct timeval *requested_abs, int rc);
static void pci_add_dm_done(libxl__egc *,
    pci_add_state *, int rc);

static void do_pci_add(libxl__egc *egc,
                       libxl_domid domid,
                       pci_add_state *pas)
{
    STATE_AO_GC(pas->aodev->ao);
    libxl_domain_type type = libxl__domain_type(gc, domid);
    int rc;

    /* init pci_add_state */
    libxl__xswait_init(&pas->xswait);
    libxl__ev_qmp_init(&pas->qmp);
    pas->pci_domid = domid;
    pas->retries = 0;
    libxl__ev_time_init(&pas->timeout);
    libxl__ev_time_init(&pas->timeout_retries);

    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        switch (libxl__device_model_version_running(gc, domid)) {
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
                pas->xswait.ao = ao;
                pas->xswait.what = "Device Model";
                pas->xswait.path = DEVICE_MODEL_XS_PATH(gc,
                    libxl_get_stubdom_id(CTX, domid), domid, "/state");
                pas->xswait.timeout_ms = LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000;
                pas->xswait.callback = pci_add_qemu_trad_watch_state_cb;
                rc = libxl__xswait_start(gc, &pas->xswait);
                if (rc) goto out;
                return;
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
                rc = libxl__ev_time_register_rel(ao, &pas->timeout,
                                                 pci_add_timeout,
                                                 LIBXL_QMP_CMD_TIMEOUT * 1000);
                if (rc) goto out;

                pci_add_qmp_device_add(egc, pas); /* must be last */
                return;
            default:
                rc = ERROR_INVAL;
                break;
        }
    }

    rc = 0;

out:
    pci_add_dm_done(egc, pas, rc); /* must be last */
}

static void pci_add_qemu_trad_watch_state_cb(libxl__egc *egc,
                                             libxl__xswait_state *xswa,
                                             int rc,
                                             const char *state)
{
    pci_add_state *pas = CONTAINER_OF(xswa, *pas, xswait);
    STATE_AO_GC(pas->aodev->ao);

    /* Convenience aliases */
    libxl_domid domid = pas->domid;
    libxl_device_pci *pci = &pas->pci;

    rc = check_qemu_running(gc, domid, xswa, rc, state);
    if (rc == ERROR_NOT_READY)
        return;
    if (rc)
        goto out;

    rc = qemu_pci_add_xenstore(gc, domid, pci);
out:
    pci_add_dm_done(egc, pas, rc); /* must be last */
}

static void pci_add_qmp_device_add(libxl__egc *egc, pci_add_state *pas)
{
    STATE_AO_GC(pas->aodev->ao);
    libxl__json_object *args = NULL;
    int rc;

    /* Convenience aliases */
    libxl_domid domid = pas->domid;
    libxl_device_pci *pci = &pas->pci;
    libxl__ev_qmp *const qmp = &pas->qmp;

    libxl__qmp_param_add_string(gc, &args, "driver",
                                "xen-pci-passthrough");
    QMP_PARAMETERS_SPRINTF(&args, "id", PCI_PT_QDEV_ID,
                           pci->bus, pci->dev, pci->func);
    QMP_PARAMETERS_SPRINTF(&args, "hostaddr",
                           "%04x:%02x:%02x.%01x", pci->domain,
                           pci->bus, pci->dev, pci->func);
    if (pci->vdevfn) {
        QMP_PARAMETERS_SPRINTF(&args, "addr", "%x.%x",
                               PCI_SLOT(pci->vdevfn),
                               PCI_FUNC(pci->vdevfn));
    }
    /*
     * Version of QEMU prior to the XSA-131 fix did not support
     * this property and were effectively always in permissive
     * mode. The fix for XSA-131 switched the default to be
     * restricted by default and added the permissive property.
     *
     * Therefore in order to support both old and new QEMU we only
     * set the permissive flag if it is true. Users of older QEMU
     * have no reason to set the flag so this is ok.
     */
    if (pci->permissive)
        libxl__qmp_param_add_bool(gc, &args, "permissive", true);

    qmp->ao = pas->aodev->ao;
    qmp->domid = domid;
    qmp->payload_fd = -1;
    qmp->callback = pci_add_qmp_device_add_cb;
    rc = libxl__ev_qmp_send(egc, qmp, "device_add", args);
    if (rc) goto out;
    return;

out:
    pci_add_dm_done(egc, pas, rc); /* must be last */
}

static void pci_add_qmp_device_add_cb(libxl__egc *egc,
                                      libxl__ev_qmp *qmp,
                                      const libxl__json_object *response,
                                      int rc)
{
    EGC_GC;
    pci_add_state *pas = CONTAINER_OF(qmp, *pas, qmp);

    if (rc) {
        /* Retry only applicable for HVM with stubdom. */
        if (libxl_get_stubdom_id(CTX, qmp->domid) == 0)
            goto out;

        if (pas->retries++ < 10) {
            LOGD(ERROR, qmp->domid, "Retrying PCI add %d", pas->retries);
            rc = libxl__ev_time_register_rel(pas->aodev->ao,
                                             &pas->timeout_retries,
                                             pci_add_qmp_device_add_retry,
                                             1000);
            if (rc) goto out;
            return; /* Wait for the timeout to then retry. */
        } else {
            goto out;
        }
    }

    qmp->callback = pci_add_qmp_query_pci_cb;
    rc = libxl__ev_qmp_send(egc, qmp, "query-pci", NULL);
    if (rc) goto out;
    return;

out:
    pci_add_dm_done(egc, pas, rc); /* must be last */
}

static void pci_add_qmp_device_add_retry(libxl__egc *egc, libxl__ev_time *ev,
                                         const struct timeval *requested_abs,
                                         int rc)
{
    pci_add_state *pas = CONTAINER_OF(ev, *pas, timeout_retries);

    pci_add_qmp_device_add(egc, pas);
}

static void pci_add_qmp_query_pci_cb(libxl__egc *egc,
                                     libxl__ev_qmp *qmp,
                                     const libxl__json_object *response,
                                     int rc)
{
    EGC_GC;
    pci_add_state *pas = CONTAINER_OF(qmp, *pas, qmp);
    const libxl__json_object *bus = NULL;
    char *asked_id;
    int i, j;
    const libxl__json_object *devices = NULL;
    const libxl__json_object *device = NULL;
    const libxl__json_object *o = NULL;
    const char *id = NULL;
    int dev_slot, dev_func;

    /* Convenience aliases */
    libxl_device_pci *pci = &pas->pci;

    if (rc) goto out;

    /* `query-pci' returns:
     * [
     *   {'bus': 'int',
     *    'devices': [
     *       {'bus': 'int', 'slot': 'int', 'function': 'int',
     *        'class_info': 'PciDeviceClass', 'id': 'PciDeviceId',
     *        '*irq': 'int', 'qdev_id': 'str',
     *        '*pci_bridge': 'PciBridgeInfo',
     *        'regions': ['PciMemoryRegion']
     *       }
     *    ]
     *   }
     * ]
     * (See qemu.git/qapi/ for the struct that aren't detailed here)
     */

    asked_id = GCSPRINTF(PCI_PT_QDEV_ID,
                         pci->bus, pci->dev, pci->func);

    for (i = 0; (bus = libxl__json_array_get(response, i)); i++) {
        devices = libxl__json_map_get("devices", bus, JSON_ARRAY);
        if (!devices) {
            rc = ERROR_QEMU_API;
            goto out;
        }

        for (j = 0; (device = libxl__json_array_get(devices, j)); j++) {
             o = libxl__json_map_get("qdev_id", device, JSON_STRING);
             if (!o) {
                 rc = ERROR_QEMU_API;
                 goto out;
             }
             id = libxl__json_object_get_string(o);
             if (!id || strcmp(asked_id, id))
                 continue;

             o = libxl__json_map_get("slot", device, JSON_INTEGER);
             if (!o) {
                 rc = ERROR_QEMU_API;
                 goto out;
             }
             dev_slot = libxl__json_object_get_integer(o);
             o = libxl__json_map_get("function", device, JSON_INTEGER);
             if (!o) {
                 rc = ERROR_QEMU_API;
                 goto out;
             }
             dev_func = libxl__json_object_get_integer(o);

             pci->vdevfn = PCI_DEVFN(dev_slot, dev_func);

             rc = 0;
             goto out;
        }
    }

    rc = ERROR_FAIL;
    LOGD(ERROR, qmp->domid,
         "PCI device id '%s' wasn't found in QEMU's 'query-pci' response.",
         asked_id);

out:
    if (rc == ERROR_QEMU_API) {
        LOGD(ERROR, qmp->domid,
             "Unexpected response to QMP cmd 'query-pci', received:\n%s",
             JSON(response));
    }
    pci_add_dm_done(egc, pas, rc); /* must be last */
}

static void pci_add_timeout(libxl__egc *egc, libxl__ev_time *ev,
                            const struct timeval *requested_abs,
                            int rc)
{
    pci_add_state *pas = CONTAINER_OF(ev, *pas, timeout);

    pci_add_dm_done(egc, pas, rc);
}

static bool pci_supp_legacy_irq(void)
{
#ifdef CONFIG_PCI_SUPP_LEGACY_IRQ
    return true;
#else
    return false;
#endif
}

static void pci_add_dm_done(libxl__egc *egc,
                            pci_add_state *pas,
                            int rc)
{
    STATE_AO_GC(pas->aodev->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_domid domid = pas->pci_domid;
    char *sysfs_path;
    FILE *f;
    unsigned long long start, end, flags, size;
    int irq, i;
    int r;
    uint32_t flag = XEN_DOMCTL_DEV_RDM_RELAXED;
    uint32_t domainid = domid;
    bool isstubdom = libxl_is_stubdom(ctx, domid, &domainid);

    /* Convenience aliases */
    bool starting = pas->starting;
    libxl_device_pci *pci = &pas->pci;
    bool hvm = libxl__domain_type(gc, domid) == LIBXL_DOMAIN_TYPE_HVM;

    libxl__ev_qmp_dispose(gc, &pas->qmp);

    if (rc) goto out;

    /* stubdomain is always running by now, even at create time */
    if (isstubdom)
        starting = false;

    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/resource", pci->domain,
                           pci->bus, pci->dev, pci->func);
    f = fopen(sysfs_path, "r");
    start = end = flags = size = 0;
    irq = 0;

    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        rc = ERROR_FAIL;
        goto out;
    }
    for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
        if (fscanf(f, "0x%llx 0x%llx 0x%llx\n", &start, &end, &flags) != 3)
            continue;
        size = end - start + 1;
        if (start) {
            if (flags & PCI_BAR_IO) {
                r = xc_domain_ioport_permission(ctx->xch, domid, start, size, 1);
                if (r < 0) {
                    LOGED(ERROR, domainid,
                          "xc_domain_ioport_permission 0x%llx/0x%llx (error %d)",
                          start, size, r);
                    fclose(f);
                    rc = ERROR_FAIL;
                    goto out;
                }
            } else {
                r = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 1);
                if (r < 0) {
                    LOGED(ERROR, domainid,
                          "xc_domain_iomem_permission 0x%llx/0x%llx (error %d)",
                          start, size, r);
                    fclose(f);
                    rc = ERROR_FAIL;
                    goto out;
                }
            }
        }
    }
    fclose(f);
    if (!pci_supp_legacy_irq())
        goto out_no_irq;
    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/irq", pci->domain,
                                pci->bus, pci->dev, pci->func);
    f = fopen(sysfs_path, "r");
    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        goto out_no_irq;
    }
    if ((fscanf(f, "%u", &irq) == 1) && irq) {
        r = xc_physdev_map_pirq(ctx->xch, domid, irq, &irq);
        if (r < 0) {
            LOGED(ERROR, domainid, "xc_physdev_map_pirq irq=%d (error=%d)",
                  irq, r);
            fclose(f);
            rc = ERROR_FAIL;
            goto out;
        }
        r = xc_domain_irq_permission(ctx->xch, domid, irq, 1);
        if (r < 0) {
            LOGED(ERROR, domainid,
                  "xc_domain_irq_permission irq=%d (error=%d)", irq, r);
            fclose(f);
            rc = ERROR_FAIL;
            goto out;
        }
    }
    fclose(f);

    /* Don't restrict writes to the PCI config space from this VM */
    if (pci->permissive) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/permissive",
                             pci) < 0 ) {
            LOGD(ERROR, domainid, "Setting permissive for device");
            rc = ERROR_FAIL;
            goto out;
        }
    }

out_no_irq:
    if (!isstubdom) {
        if (pci->rdm_policy == LIBXL_RDM_RESERVE_POLICY_STRICT) {
            flag &= ~XEN_DOMCTL_DEV_RDM_RELAXED;
        } else if (pci->rdm_policy != LIBXL_RDM_RESERVE_POLICY_RELAXED) {
            LOGED(ERROR, domainid, "unknown rdm check flag.");
            rc = ERROR_FAIL;
            goto out;
        }
        r = xc_assign_device(ctx->xch, domid, pci_encode_bdf(pci), flag);
        if (r < 0 && (hvm || errno != ENOSYS)) {
            LOGED(ERROR, domainid, "xc_assign_device failed");
            rc = ERROR_FAIL;
            goto out;
        }
    }

    if (!libxl_get_stubdom_id(CTX, domid))
        rc = libxl__device_pci_add_xenstore(gc, domid, pci, starting);
    else
        rc = 0;
out:
    libxl__ev_time_deregister(gc, &pas->timeout);
    libxl__ev_time_deregister(gc, &pas->timeout_retries);
    pas->callback(egc, pas, rc);
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

int libxl__device_pci_setdefault(libxl__gc *gc, uint32_t domid,
                                 libxl_device_pci *pci, bool hotplug)
{
    /* We'd like to force reserve rdm specific to a device by default.*/
    if (pci->rdm_policy == LIBXL_RDM_RESERVE_POLICY_INVALID)
        pci->rdm_policy = LIBXL_RDM_RESERVE_POLICY_STRICT;
    return 0;
}

int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid,
                         libxl_device_pci *pci,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    libxl__prepare_ao_device(ao, aodev);
    aodev->action = LIBXL__DEVICE_ACTION_ADD;
    aodev->callback = device_addrm_aocomplete;
    aodev->update_json = true;
    libxl__device_pci_add(egc, domid, pci, false, aodev);
    return AO_INPROGRESS;
}

static bool libxl_pci_assignable(libxl_ctx *ctx, libxl_device_pci *pci)
{
    libxl_device_pci *pcis;
    int num;
    bool assignable;

    pcis = libxl_device_pci_assignable_list(ctx, &num);
    assignable = is_pci_in_array(pcis, num, pci);
    libxl_device_pci_assignable_list_free(pcis, num);

    return assignable;
}

static void device_pci_add_stubdom_wait(libxl__egc *egc,
    pci_add_state *pas, int rc);
static void device_pci_add_stubdom_ready(libxl__egc *egc,
    libxl__ev_devstate *ds, int rc);
static void device_pci_add_stubdom_done(libxl__egc *egc,
    pci_add_state *, int rc);
static void device_pci_add_done(libxl__egc *egc,
    pci_add_state *, int rc);

void libxl__device_pci_add(libxl__egc *egc, uint32_t domid,
                           libxl_device_pci *pci, bool starting,
                           libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc;
    int stubdomid = 0;
    pci_add_state *pas;

    GCNEW(pas);
    pas->aodev = aodev;
    pas->domid = domid;

    libxl_device_pci_copy(CTX, &pas->pci, pci);
    pci = &pas->pci;

    /* If the device is named then we need to look up the BDF */
    if (pci->name) {
        rc = name2bdf(gc, pci);
        if (rc) goto out;
    }

    pas->starting = starting;
    pas->callback = device_pci_add_stubdom_done;

    if (libxl__domain_type(gc, domid) == LIBXL_DOMAIN_TYPE_HVM) {
        rc = xc_test_assign_device(ctx->xch, domid, pci_encode_bdf(pci));
        if (rc) {
            LOGD(ERROR, domid,
                 "PCI device %04x:%02x:%02x.%u %s?",
                 pci->domain, pci->bus, pci->dev, pci->func,
                 errno == EOPNOTSUPP ? "cannot be assigned - no IOMMU"
                 : "already assigned to a different guest");
            goto out;
        }
    }

    rc = libxl__device_pci_setdefault(gc, domid, pci, !starting);
    if (rc) goto out;

    if (pci->seize && !pciback_dev_is_assigned(gc, pci)) {
        rc = libxl__device_pci_assignable_add(gc, pci, 1);
        if ( rc )
            goto out;
    }

    if (!libxl_pci_assignable(ctx, pci)) {
        LOGD(ERROR, domid, "PCI device %x:%x:%x.%x is not assignable",
             pci->domain, pci->bus, pci->dev, pci->func);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = pci_info_xs_write(gc, pci, "domid", GCSPRINTF("%u", domid));
    if (rc) goto out;

    libxl__device_pci_reset(gc, pci->domain, pci->bus, pci->dev, pci->func);

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        pas->callback = device_pci_add_stubdom_wait;

        do_pci_add(egc, stubdomid, pas); /* must be last */
        return;
    }

    device_pci_add_stubdom_done(egc, pas, 0); /* must be last */
    return;

out:
    device_pci_add_done(egc, pas, rc); /* must be last */
}

static void device_pci_add_stubdom_wait(libxl__egc *egc,
                                        pci_add_state *pas,
                                        int rc)
{
    libxl__ao_device *aodev = pas->aodev;
    STATE_AO_GC(aodev->ao);
    int stubdomid = libxl_get_stubdom_id(CTX, pas->domid);
    char *state_path;

    if (rc) goto out;

    /* Wait for the device actually being connected, otherwise device model
     * running there will fail to find the device. */
    state_path = GCSPRINTF("%s/state",
            libxl__domain_device_backend_path(gc, 0, stubdomid, 0,
                                              LIBXL__DEVICE_KIND_PCI));
    rc = libxl__ev_devstate_wait(ao, &pas->pciback_ds,
            device_pci_add_stubdom_ready,
            state_path, XenbusStateConnected,
            LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000);
    if (rc) goto out;
    return;
out:
    device_pci_add_done(egc, pas, rc); /* must be last */
}

static void device_pci_add_stubdom_ready(libxl__egc *egc,
                                         libxl__ev_devstate *ds,
                                         int rc)
{
    pci_add_state *pas = CONTAINER_OF(ds, *pas, pciback_ds);

    device_pci_add_stubdom_done(egc, pas, rc); /* must be last */
}

static void device_pci_add_stubdom_done(libxl__egc *egc,
                                        pci_add_state *pas,
                                        int rc)
{
    STATE_AO_GC(pas->aodev->ao);
    unsigned int orig_vdev, pfunc_mask;
    int i;

    /* Convenience aliases */
    libxl_domid domid = pas->domid;
    libxl_device_pci *pci = &pas->pci;

    if (rc) goto out;

    orig_vdev = pci->vdevfn & ~7U;

    if ( pci->vfunc_mask == LIBXL_PCI_FUNC_ALL ) {
        if ( !(pci->vdevfn >> 3) ) {
            LOGD(ERROR, domid, "Must specify a v-slot for multi-function devices");
            rc = ERROR_INVAL;
            goto out;
        }
        if ( pci_multifunction_check(gc, pci, &pfunc_mask) ) {
            rc = ERROR_FAIL;
            goto out;
        }
        pci->vfunc_mask &= pfunc_mask;
        /* so now vfunc_mask == pfunc_mask */
    }else{
        pfunc_mask = (1 << pci->func);
    }

    for (rc = 0, i = 7; i >= 0; --i) {
        if ( (1 << i) & pfunc_mask ) {
            if ( pci->vfunc_mask == pfunc_mask ) {
                pci->func = i;
                pci->vdevfn = orig_vdev | i;
            } else {
                /* if not passing through multiple devices in a block make
                 * sure that virtual function number 0 is always used otherwise
                 * guest won't see the device
                 */
                pci->vdevfn = orig_vdev;
            }
            pas->callback = device_pci_add_done;
            do_pci_add(egc, domid, pas); /* must be last */
            return;
        }
    }

out:
    device_pci_add_done(egc, pas, rc);
}

static void device_pci_add_done(libxl__egc *egc,
                                pci_add_state *pas,
                                int rc)
{
    EGC_GC;
    libxl__ao_device *aodev = pas->aodev;
    libxl_domid domid = pas->domid;
    libxl_device_pci *pci = &pas->pci;

    if (rc) {
        if (pci->name) {
            LOGD(ERROR, domid,
                 "libxl__device_pci_add failed for "
                 "PCI device '%s' (rc %d)",
                 pci->name,
                 rc);
        } else {
            LOGD(ERROR, domid,
                 "libxl__device_pci_add failed for "
                 "PCI device %x:%x:%x.%x (rc %d)",
                 pci->domain, pci->bus, pci->dev, pci->func,
                 rc);
        }
        pci_info_xs_remove(gc, pci, "domid");
    }
    libxl_device_pci_dispose(pci);
    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

typedef struct {
    libxl__multidev multidev;
    libxl__ao_device *outer_aodev;
    libxl_domain_config *d_config;
    libxl_domid domid;
} add_pcis_state;

static void add_pcis_done(libxl__egc *, libxl__multidev *, int rc);

static void libxl__add_pcis(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                            libxl_domain_config *d_config,
                            libxl__multidev *multidev)
{
    AO_GC;
    add_pcis_state *apds;
    int i;

    /* We need to start a new multidev in order to be able to execute
     * libxl__create_pci_backend only once. */

    GCNEW(apds);
    apds->outer_aodev = libxl__multidev_prepare(multidev);
    apds->d_config = d_config;
    apds->domid = domid;
    apds->multidev.callback = add_pcis_done;
    libxl__multidev_begin(ao, &apds->multidev);

    for (i = 0; i < d_config->num_pcidevs; i++) {
        libxl__ao_device *aodev = libxl__multidev_prepare(&apds->multidev);
        libxl__device_pci_add(egc, domid, &d_config->pcidevs[i],
                              true, aodev);
    }

    libxl__multidev_prepared(egc, &apds->multidev, 0);
}

static void add_pcis_done(libxl__egc *egc, libxl__multidev *multidev,
                          int rc)
{
    EGC_GC;
    add_pcis_state *apds = CONTAINER_OF(multidev, *apds, multidev);
    libxl__ao_device *aodev = apds->outer_aodev;

    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

static int qemu_pci_remove_xenstore(libxl__gc *gc, uint32_t domid,
                                    libxl_device_pci *pci, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *state;
    char *path;
    uint32_t dm_domid;

    dm_domid = libxl_get_stubdom_id(CTX, domid);

    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/state");
    state = libxl__xs_read(gc, XBT_NULL, path);
    path = DEVICE_MODEL_XS_PATH(gc, dm_domid, domid, "/parameter");
    libxl__xs_printf(gc, XBT_NULL, path, PCI_BDF, pci->domain,
                     pci->bus, pci->dev, pci->func);

    /* Remove all functions at once atomically by only signalling
     * device-model for function 0 */
    if ( !force && (pci->vdevfn & 0x7) == 0 ) {
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

typedef struct pci_remove_state {
    libxl__ao_device *aodev;
    libxl_domid domid;
    libxl_device_pci pci;
    bool force;
    bool hvm;
    unsigned int orig_vdev;
    unsigned int pfunc_mask;
    int next_func;
    libxl__ao_device stubdom_aodev;
    libxl__xswait_state xswait;
    libxl__ev_qmp qmp;
    libxl__ev_time timeout;
    libxl__ev_time retry_timer;
} pci_remove_state;

static void libxl__device_pci_remove_common(libxl__egc *egc,
    uint32_t domid, libxl_device_pci *pci, bool force,
    libxl__ao_device *aodev);
static void device_pci_remove_common_next(libxl__egc *egc,
    pci_remove_state *prs, int rc);

static void pci_remove_qemu_trad_watch_state_cb(libxl__egc *egc,
    libxl__xswait_state *xswa, int rc, const char *state);
static void pci_remove_qmp_device_del(libxl__egc *egc,
    pci_remove_state *prs);
static void pci_remove_qmp_device_del_cb(libxl__egc *egc,
    libxl__ev_qmp *qmp, const libxl__json_object *response, int rc);
static void pci_remove_qmp_retry_timer_cb(libxl__egc *egc,
    libxl__ev_time *ev, const struct timeval *requested_abs, int rc);
static void pci_remove_qmp_query_cb(libxl__egc *egc,
    libxl__ev_qmp *qmp, const libxl__json_object *response, int rc);
static void pci_remove_timeout(libxl__egc *egc,
    libxl__ev_time *ev, const struct timeval *requested_abs, int rc);
static void pci_remove_detached(libxl__egc *egc,
    pci_remove_state *prs, int rc);
static void pci_remove_stubdom_done(libxl__egc *egc,
    libxl__ao_device *aodev);
static void pci_remove_done(libxl__egc *egc,
    pci_remove_state *prs, int rc);

static void do_pci_remove(libxl__egc *egc, pci_remove_state *prs)
{
    STATE_AO_GC(prs->aodev->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_device_pci *pcis;
    bool attached;
    uint32_t domid = prs->domid;
    libxl_domain_type type = libxl__domain_type(gc, domid);
    libxl_device_pci *pci = &prs->pci;
    int rc, num;
    uint32_t domainid = domid;

    pcis = libxl_device_pci_list(ctx, domid, &num);
    if (!pcis) {
        rc = ERROR_FAIL;
        goto out_fail;
    }

    attached = is_pci_in_array(pcis, num, pci);
    libxl_device_pci_list_free(pcis, num);

    rc = ERROR_INVAL;
    if (!attached) {
        LOGD(ERROR, domainid, "PCI device not attached to this domain");
        goto out_fail;
    }

    rc = ERROR_FAIL;
    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        prs->hvm = true;
        switch (libxl__device_model_version_running(gc, domid)) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            prs->xswait.ao = ao;
            prs->xswait.what = "Device Model";
            prs->xswait.path = DEVICE_MODEL_XS_PATH(gc,
                libxl_get_stubdom_id(CTX, domid), domid, "/state");
            prs->xswait.timeout_ms = LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000;
            prs->xswait.callback = pci_remove_qemu_trad_watch_state_cb;
            rc = libxl__xswait_start(gc, &prs->xswait);
            if (rc) goto out_fail;
            return;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            pci_remove_qmp_device_del(egc, prs); /* must be last */
            return;
        default:
            rc = ERROR_INVAL;
            goto out_fail;
        }
    } else {
        char *sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/resource", pci->domain,
                                     pci->bus, pci->dev, pci->func);
        FILE *f = fopen(sysfs_path, "r");
        uint64_t start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
            goto skip1;
        }
        for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
            if (fscanf(f, "0x%"SCNx64" 0x%"SCNx64" 0x%"SCNx64"\n",
                       &start, &end, &flags) != 3)
                continue;
            size = end - start + 1;
            if (start) {
                if (flags & PCI_BAR_IO) {
                    rc = xc_domain_ioport_permission(ctx->xch, domid, start, size, 0);
                    if (rc < 0)
                        LOGED(ERROR, domainid,
                              "xc_domain_ioport_permission error %#"PRIx64"/%#"PRIx64,
                              start,
                              size);
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 0);
                    if (rc < 0)
                        LOGED(ERROR, domainid,
                              "xc_domain_iomem_permission error %#"PRIx64"/%#"PRIx64,
                              start,
                              size);
                }
            }
        }
        fclose(f);
skip1:
        if (!pci_supp_legacy_irq())
            goto skip_irq;
        sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/irq", pci->domain,
                               pci->bus, pci->dev, pci->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
            goto skip_irq;
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
skip_irq:
    rc = 0;
out_fail:
    pci_remove_detached(egc, prs, rc); /* must be last */
}

static void pci_remove_qemu_trad_watch_state_cb(libxl__egc *egc,
                                                libxl__xswait_state *xswa,
                                                int rc,
                                                const char *state)
{
    pci_remove_state *prs = CONTAINER_OF(xswa, *prs, xswait);
    STATE_AO_GC(prs->aodev->ao);

    /* Convenience aliases */
    libxl_domid domid = prs->domid;
    libxl_device_pci *const pci = &prs->pci;

    rc = check_qemu_running(gc, domid, xswa, rc, state);
    if (rc == ERROR_NOT_READY)
        return;
    if (rc)
        goto out;

    rc = qemu_pci_remove_xenstore(gc, domid, pci, prs->force);

out:
    pci_remove_detached(egc, prs, rc);
}

static void pci_remove_qmp_device_del(libxl__egc *egc,
                                      pci_remove_state *prs)
{
    STATE_AO_GC(prs->aodev->ao);
    libxl__json_object *args = NULL;
    int rc;

    /* Convenience aliases */
    libxl_device_pci *const pci = &prs->pci;

    rc = libxl__ev_time_register_rel(ao, &prs->timeout,
                                     pci_remove_timeout,
                                     LIBXL_QMP_CMD_TIMEOUT * 1000);
    if (rc) goto out;

    QMP_PARAMETERS_SPRINTF(&args, "id", PCI_PT_QDEV_ID,
                           pci->bus, pci->dev, pci->func);
    prs->qmp.callback = pci_remove_qmp_device_del_cb;
    rc = libxl__ev_qmp_send(egc, &prs->qmp, "device_del", args);
    if (rc) goto out;
    return;

out:
    pci_remove_detached(egc, prs, rc);
}

static void pci_remove_qmp_device_del_cb(libxl__egc *egc,
                                         libxl__ev_qmp *qmp,
                                         const libxl__json_object *response,
                                         int rc)
{
    EGC_GC;
    pci_remove_state *prs = CONTAINER_OF(qmp, *prs, qmp);

    if (rc) goto out;

    /* Now that the command is sent, we want to wait until QEMU has
     * confirmed that the device is removed. */
    /* TODO: Instead of using a poll loop { ev_timer ; query-pci }, it
     * could be possible to listen to events sent by QEMU via QMP in order
     * to wait for the passthrough pci-device to be removed from QEMU.  */
    pci_remove_qmp_retry_timer_cb(egc, &prs->retry_timer, NULL,
                                  ERROR_TIMEDOUT);
    return;

out:
    pci_remove_detached(egc, prs, rc);
}

static void pci_remove_qmp_retry_timer_cb(libxl__egc *egc, libxl__ev_time *ev,
                                          const struct timeval *requested_abs,
                                          int rc)
{
    EGC_GC;
    pci_remove_state *prs = CONTAINER_OF(ev, *prs, retry_timer);

    prs->qmp.callback = pci_remove_qmp_query_cb;
    rc = libxl__ev_qmp_send(egc, &prs->qmp, "query-pci", NULL);
    if (rc) goto out;
    return;

out:
    pci_remove_detached(egc, prs, rc);
}

static void pci_remove_qmp_query_cb(libxl__egc *egc,
                                    libxl__ev_qmp *qmp,
                                    const libxl__json_object *response,
                                    int rc)
{
    EGC_GC;
    pci_remove_state *prs = CONTAINER_OF(qmp, *prs, qmp);
    const libxl__json_object *bus = NULL;
    const char *asked_id;
    int i, j;

    /* Convenience aliases */
    libxl__ao *const ao = prs->aodev->ao;
    libxl_device_pci *const pci = &prs->pci;

    if (rc) goto out;

    libxl__ev_qmp_dispose(gc, qmp);

    asked_id = GCSPRINTF(PCI_PT_QDEV_ID,
                         pci->bus, pci->dev, pci->func);

    /* query-pci response:
     * [{ 'devices': [ 'qdev_id': 'str', ...  ], ... }]
     * */

    for (i = 0; (bus = libxl__json_array_get(response, i)); i++) {
        const libxl__json_object *devices = NULL;
        const libxl__json_object *device = NULL;
        const libxl__json_object *o = NULL;
        const char *id = NULL;

        devices = libxl__json_map_get("devices", bus, JSON_ARRAY);
        if (!devices) {
            rc = ERROR_QEMU_API;
            goto out;
        }

        for (j = 0; (device = libxl__json_array_get(devices, j)); j++) {
             o = libxl__json_map_get("qdev_id", device, JSON_STRING);
             if (!o) {
                 rc = ERROR_QEMU_API;
                 goto out;
             }
             id = libxl__json_object_get_string(o);

             if (id && !strcmp(asked_id, id)) {
                 /* Device still in QEMU, need to wait longuer. */
                 rc = libxl__ev_time_register_rel(ao, &prs->retry_timer,
                     pci_remove_qmp_retry_timer_cb, 1000);
                 if (rc) goto out;
                 return;
             }
        }
    }

out:
    pci_remove_detached(egc, prs, rc); /* must be last */
}

static void pci_remove_timeout(libxl__egc *egc, libxl__ev_time *ev,
                               const struct timeval *requested_abs,
                               int rc)
{
    EGC_GC;
    pci_remove_state *prs = CONTAINER_OF(ev, *prs, timeout);

    /* Convenience aliases */
    libxl_device_pci *const pci = &prs->pci;

    LOGD(WARN, prs->domid, "timed out waiting for DM to remove "
         PCI_PT_QDEV_ID, pci->bus, pci->dev, pci->func);

    /* If we timed out, we might still want to keep destroying the device
     * (when force==true), so let the next function decide what to do on
     * error */
    pci_remove_detached(egc, prs, rc);
}

static void pci_remove_detached(libxl__egc *egc,
                                pci_remove_state *prs,
                                int rc)
{
    STATE_AO_GC(prs->aodev->ao);
    int stubdomid = 0;
    uint32_t domainid = prs->domid;
    bool isstubdom;

    /* Convenience aliases */
    libxl_device_pci *const pci = &prs->pci;
    libxl_domid domid = prs->domid;

    /* Cleaning QMP states ASAP */
    libxl__ev_qmp_dispose(gc, &prs->qmp);
    libxl__ev_time_deregister(gc, &prs->timeout);
    libxl__ev_time_deregister(gc, &prs->retry_timer);

    if (rc && !prs->force)
        goto out;

    isstubdom = libxl_is_stubdom(CTX, domid, &domainid);

    /* don't do multiple resets while some functions are still passed through */
    if ((pci->vdevfn & 0x7) == 0) {
        libxl__device_pci_reset(gc, pci->domain, pci->bus, pci->dev, pci->func);
    }

    if (!isstubdom) {
        rc = xc_deassign_device(CTX->xch, domid, pci_encode_bdf(pci));
        if (rc < 0 && (prs->hvm || errno != ENOSYS))
            LOGED(ERROR, domainid, "xc_deassign_device failed");
    }

    stubdomid = libxl_get_stubdom_id(CTX, domid);
    if (stubdomid != 0) {
        libxl_device_pci *pci_s;
        libxl__ao_device *const stubdom_aodev = &prs->stubdom_aodev;

        GCNEW(pci_s);
        libxl_device_pci_init(pci_s);
        libxl_device_pci_copy(CTX, pci_s, pci);

        libxl__prepare_ao_device(ao, stubdom_aodev);
        stubdom_aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
        stubdom_aodev->callback = pci_remove_stubdom_done;
        stubdom_aodev->update_json = prs->aodev->update_json;
        libxl__device_pci_remove_common(egc, stubdomid, pci_s,
                                        prs->force, stubdom_aodev);
        return;
    }

    rc = 0;
out:
    pci_remove_done(egc, prs, rc);
}

static void pci_remove_stubdom_done(libxl__egc *egc,
                                    libxl__ao_device *aodev)
{
    pci_remove_state *prs = CONTAINER_OF(aodev, *prs, stubdom_aodev);

    pci_remove_done(egc, prs, 0);
}

static void pci_remove_done(libxl__egc *egc,
                            pci_remove_state *prs,
                            int rc)
{
    EGC_GC;

    if (rc) goto out;

    libxl__device_pci_remove_xenstore(gc, prs->domid, &prs->pci);
out:
    device_pci_remove_common_next(egc, prs, rc);
}

static void libxl__device_pci_remove_common(libxl__egc *egc,
                                            uint32_t domid,
                                            libxl_device_pci *pci,
                                            bool force,
                                            libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    int rc;
    pci_remove_state *prs;

    GCNEW(prs);
    prs->aodev = aodev;
    prs->domid = domid;

    libxl_device_pci_copy(CTX, &prs->pci, pci);
    pci = &prs->pci;

    /* If the device is named then we need to look up the BDF */
    if (pci->name) {
        rc = name2bdf(gc, pci);
        if (rc) goto out;
    }

    prs->force = force;
    libxl__xswait_init(&prs->xswait);
    libxl__ev_qmp_init(&prs->qmp);
    prs->qmp.ao = prs->aodev->ao;
    prs->qmp.domid = prs->domid;
    prs->qmp.payload_fd = -1;
    libxl__ev_time_init(&prs->timeout);
    libxl__ev_time_init(&prs->retry_timer);

    prs->orig_vdev = pci->vdevfn & ~7U;

    if ( pci->vfunc_mask == LIBXL_PCI_FUNC_ALL ) {
        if ( pci_multifunction_check(gc, pci, &prs->pfunc_mask) ) {
            rc = ERROR_FAIL;
            goto out;
        }
        pci->vfunc_mask &= prs->pfunc_mask;
    } else {
        prs->pfunc_mask = (1 << pci->func);
    }

    rc = 0;
    prs->next_func = 7;
out:
    device_pci_remove_common_next(egc, prs, rc);
}

static void device_pci_remove_common_next(libxl__egc *egc,
                                          pci_remove_state *prs,
                                          int rc)
{
    EGC_GC;

    /* Convenience aliases */
    libxl_device_pci *const pci = &prs->pci;
    libxl__ao_device *const aodev = prs->aodev;
    const unsigned int pfunc_mask = prs->pfunc_mask;
    const unsigned int orig_vdev = prs->orig_vdev;

    if (rc) goto out;

    while (prs->next_func >= 0) {
        const int i = prs->next_func;
        prs->next_func--;
        if ( (1 << i) & pfunc_mask ) {
            if ( pci->vfunc_mask == pfunc_mask ) {
                pci->func = i;
                pci->vdevfn = orig_vdev | i;
            } else {
                pci->vdevfn = orig_vdev;
            }
            do_pci_remove(egc, prs);
            return;
        }
    }

    rc = 0;
out:
    libxl__ev_qmp_dispose(gc, &prs->qmp);
    libxl__xswait_stop(gc, &prs->xswait);
    libxl__ev_time_deregister(gc, &prs->timeout);
    libxl__ev_time_deregister(gc, &prs->retry_timer);

    if (!rc) pci_info_xs_remove(gc, pci, "domid");

    libxl_device_pci_dispose(pci);
    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_pci *pci,
                            const libxl_asyncop_how *ao_how)

{
    AO_CREATE(ctx, domid, ao_how);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    libxl__prepare_ao_device(ao, aodev);
    aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
    aodev->callback = device_addrm_aocomplete;
    aodev->update_json = true;
    libxl__device_pci_remove_common(egc, domid, pci, false, aodev);
    return AO_INPROGRESS;
}

int libxl_device_pci_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_pci *pci,
                             const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    libxl__ao_device *aodev;

    GCNEW(aodev);
    libxl__prepare_ao_device(ao, aodev);
    aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
    aodev->callback = device_addrm_aocomplete;
    aodev->update_json = true;
    libxl__device_pci_remove_common(egc, domid, pci, true, aodev);
    return AO_INPROGRESS;
}

static int libxl__device_pci_from_xs_be(libxl__gc *gc,
                                        const char *be_path,
                                        libxl_devid nr, void *data)
{
    char *s;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0;
    libxl_device_pci *pci = data;

    libxl_device_pci_init(pci);

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/dev-%d", be_path, nr));
    sscanf(s, PCI_BDF, &domain, &bus, &dev, &func);

    pci_struct_fill(pci, domain, bus, dev, func);

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/vdevfn-%d", be_path, nr));
    if (s)
        pci->vdevfn = strtol(s, (char **) NULL, 16);

    s = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/name-%d", be_path, nr));
    if (s)
        pci->name = strdup(s);

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
            } else if (!strcmp(p, "rdm_policy")) {
                p = strtok_r(NULL, ",=", &saveptr);
                libxl_rdm_reserve_policy_from_string(p, &pci->rdm_policy);
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

static int libxl__device_pci_get_path(libxl__gc *gc, uint32_t domid,
                                      char **path)
{
    *path = libxl__domain_device_backend_path(gc, 0, domid, 0,
                                              LIBXL__DEVICE_KIND_PCI);

    return 0;
}

void libxl__device_pci_destroy_all(libxl__egc *egc, uint32_t domid,
                                   libxl__multidev *multidev)
{
    STATE_AO_GC(multidev->ao);
    libxl_device_pci *pcis;
    int num, i;

    pcis = libxl_device_pci_list(CTX, domid, &num);
    if ( pcis == NULL )
        return;

    for (i = 0; i < num; i++) {
        /* Force remove on shutdown since, on HVM, qemu will not always
         * respond to SCI interrupt because the guest kernel has shut down the
         * devices by the time we even get here!
         */
        libxl__ao_device *aodev = libxl__multidev_prepare(multidev);
        libxl__device_pci_remove_common(egc, domid, pcis + i, true,
                                        aodev);
    }

    libxl_device_pci_list_free(pcis, num);
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
        libxl_device_pci *pci = &d_config->pcidevs[i];
        unsigned long pci_device_class;

        if (sysfs_dev_get_class(gc, pci, &pci_device_class))
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

LIBXL_DEFINE_DEVICE_LIST(pci)

#define libxl__device_pci_update_devid NULL

DEFINE_DEVICE_TYPE_STRUCT(pci, PCI, pcidevs,
    .get_num = libxl__device_pci_get_num,
    .get_path = libxl__device_pci_get_path,
    .from_xenstore = libxl__device_pci_from_xs_be,
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
