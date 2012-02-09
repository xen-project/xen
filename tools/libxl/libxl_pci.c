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

static unsigned int pcidev_encode_bdf(libxl_device_pci *pcidev)
{
    unsigned int value;

    value = pcidev->domain << 16;
    value |= (pcidev->bus & 0xff) << 8;
    value |= (pcidev->dev & 0x1f) << 3;
    value |= (pcidev->func & 0x7);

    return value;
}

static int pcidev_init(libxl_device_pci *pcidev, unsigned int domain,
                          unsigned int bus, unsigned int dev,
                          unsigned int func, unsigned int vdevfn)
{
    pcidev->domain = domain;
    pcidev->bus = bus;
    pcidev->dev = dev;
    pcidev->func = func;
    pcidev->vdevfn = vdevfn;
    return 0;
}

static int hex_convert(const char *str, unsigned int *val, unsigned int mask)
{
    unsigned long ret;
    char *end;

    ret = strtoul(str, &end, 16);
    if ( end == str || *end != '\0' )
        return -1;
    if ( ret & ~mask )
        return -1;
    *val = (unsigned int)ret & mask;
    return 0;
}

#define STATE_DOMAIN    0
#define STATE_BUS       1
#define STATE_DEV       2
#define STATE_FUNC      3
#define STATE_VSLOT     4
#define STATE_OPTIONS_K 6
#define STATE_OPTIONS_V 7
#define STATE_TERMINAL  8
int libxl_device_pci_parse_bdf(libxl_ctx *ctx, libxl_device_pci *pcidev, const char *str)
{
    unsigned state = STATE_DOMAIN;
    unsigned dom, bus, dev, func, vslot = 0;
    char *buf2, *tok, *ptr, *end, *optkey = NULL;

    if ( NULL == (buf2 = ptr = strdup(str)) )
        return ERROR_NOMEM;

    for(tok = ptr, end = ptr + strlen(ptr) + 1; ptr < end; ptr++) {
        switch(state) {
        case STATE_DOMAIN:
            if ( *ptr == ':' ) {
                state = STATE_BUS;
                *ptr = '\0';
                if ( hex_convert(tok, &dom, 0xffff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_BUS:
            if ( *ptr == ':' ) {
                state = STATE_DEV;
                *ptr = '\0';
                if ( hex_convert(tok, &bus, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }else if ( *ptr == '.' ) {
                state = STATE_FUNC;
                *ptr = '\0';
                if ( dom & ~0xff )
                    goto parse_error;
                bus = dom;
                dom = 0;
                if ( hex_convert(tok, &dev, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_DEV:
            if ( *ptr == '.' ) {
                state = STATE_FUNC;
                *ptr = '\0';
                if ( hex_convert(tok, &dev, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_FUNC:
            if ( *ptr == '\0' || *ptr == '@' || *ptr == ',' ) {
                switch( *ptr ) {
                case '\0':
                    state = STATE_TERMINAL;
                    break;
                case '@':
                    state = STATE_VSLOT;
                    break;
                case ',':
                    state = STATE_OPTIONS_K;
                    break;
                }
                *ptr = '\0';
                if ( !strcmp(tok, "*") ) {
                    pcidev->vfunc_mask = LIBXL_PCI_FUNC_ALL;
                }else{
                    if ( hex_convert(tok, &func, 0x7) )
                        goto parse_error;
                    pcidev->vfunc_mask = (1 << 0);
                }
                tok = ptr + 1;
            }
            break;
        case STATE_VSLOT:
            if ( *ptr == '\0' || *ptr == ',' ) {
                state = ( *ptr == ',' ) ? STATE_OPTIONS_K : STATE_TERMINAL;
                *ptr = '\0';
                if ( hex_convert(tok, &vslot, 0xff) )
                    goto parse_error;
                tok = ptr + 1;
            }
            break;
        case STATE_OPTIONS_K:
            if ( *ptr == '=' ) {
                state = STATE_OPTIONS_V;
                *ptr = '\0';
                optkey = tok;
                tok = ptr + 1;
            }
            break;
        case STATE_OPTIONS_V:
            if ( *ptr == ',' || *ptr == '\0' ) {
                state = (*ptr == ',') ? STATE_OPTIONS_K : STATE_TERMINAL;
                *ptr = '\0';
                if ( !strcmp(optkey, "msitranslate") ) {
                    pcidev->msitranslate = atoi(tok);
                }else if ( !strcmp(optkey, "power_mgmt") ) {
                    pcidev->power_mgmt = atoi(tok);
                }else{
                    LIBXL__LOG(ctx, LIBXL__LOG_WARNING,
                           "Unknown PCI BDF option: %s", optkey);
                }
                tok = ptr + 1;
            }
        default:
            break;
        }
    }

    free(buf2);

    if ( tok != ptr || state != STATE_TERMINAL )
        goto parse_error;

    pcidev_init(pcidev, dom, bus, dev, func, vslot << 3);

    return 0;

parse_error:
    return ERROR_INVAL;
}

static void libxl_create_pci_backend_device(libxl__gc *gc, flexarray_t *back, int num, libxl_device_pci *pcidev)
{
    flexarray_append(back, libxl__sprintf(gc, "key-%d", num));
    flexarray_append(back, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    flexarray_append(back, libxl__sprintf(gc, "dev-%d", num));
    flexarray_append(back, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    if (pcidev->vdevfn)
        flexarray_append_pair(back, libxl__sprintf(gc, "vdevfn-%d", num), libxl__sprintf(gc, "%x", pcidev->vdevfn));
    flexarray_append(back, libxl__sprintf(gc, "opts-%d", num));
    flexarray_append(back, libxl__sprintf(gc, "msitranslate=%d,power_mgmt=%d", pcidev->msitranslate, pcidev->power_mgmt));
    flexarray_append_pair(back, libxl__sprintf(gc, "state-%d", num), libxl__sprintf(gc, "%d", 1));
}

int libxl__create_pci_backend(libxl__gc *gc, uint32_t domid,
                              libxl_device_pci *pcidev, int num)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    flexarray_t *front = NULL;
    flexarray_t *back = NULL;
    libxl__device device;
    int ret = ERROR_NOMEM, i;

    front = flexarray_make(16, 1);
    if (!front)
        goto out;
    back = flexarray_make(16, 1);
    if (!back)
        goto out;

    ret = 0;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Creating pci backend");

    /* add pci device */
    device.backend_devid = 0;
    device.backend_domid = 0;
    device.backend_kind = LIBXL__DEVICE_KIND_PCI;
    device.devid = 0;
    device.domid = domid;
    device.kind = LIBXL__DEVICE_KIND_PCI;

    flexarray_append_pair(back, "frontend-id", libxl__sprintf(gc, "%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state", libxl__sprintf(gc, "%d", 1));
    flexarray_append_pair(back, "domain", libxl__domid_to_name(gc, domid));

    for (i = 0; i < num; i++, pcidev++)
        libxl_create_pci_backend_device(gc, back, i, pcidev);

    flexarray_append_pair(back, "num_devs", libxl__sprintf(gc, "%d", num));
    flexarray_append_pair(front, "backend-id", libxl__sprintf(gc, "%d", 0));
    flexarray_append_pair(front, "state", libxl__sprintf(gc, "%d", 1));

    libxl__device_generic_add(gc, &device,
                              libxl__xs_kvs_of_flexarray(gc, back, back->count),
                              libxl__xs_kvs_of_flexarray(gc, front, front->count));

out:
    if (back)
        flexarray_free(back);
    if (front)
        flexarray_free(front);
    return 0;
}

static int libxl__device_pci_add_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    flexarray_t *back;
    char *num_devs, *be_path;
    int num = 0;
    xs_transaction_t t;

    be_path = libxl__sprintf(gc, "%s/backend/pci/%d/0", libxl__xs_get_dompath(gc, 0), domid);
    num_devs = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/num_devs", be_path));
    if (!num_devs)
        return libxl__create_pci_backend(gc, domid, pcidev, 1);

    if (!starting && LIBXL__DOMAIN_IS_TYPE(gc, domid, PV)) {
        if (libxl__wait_for_backend(gc, be_path, "4") < 0)
            return ERROR_FAIL;
    }

    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Adding new pci device to xenstore");
    num = atoi(num_devs);
    libxl_create_pci_backend_device(gc, back, num, pcidev);
    flexarray_append_pair(back, "num_devs", libxl__sprintf(gc, "%d", num + 1));
    if (!starting)
        flexarray_append_pair(back, "state", libxl__sprintf(gc, "%d", 7));

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    libxl__xs_writev(gc, t, be_path,
                    libxl__xs_kvs_of_flexarray(gc, back, back->count));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    flexarray_free(back);
    return 0;
}

static int libxl__device_pci_remove_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *be_path, *num_devs_path, *num_devs, *xsdev, *tmp, *tmppath;
    int num, i, j;
    xs_transaction_t t;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0;

    be_path = libxl__sprintf(gc, "%s/backend/pci/%d/0", libxl__xs_get_dompath(gc, 0), domid);
    num_devs_path = libxl__sprintf(gc, "%s/num_devs", be_path);
    num_devs = libxl__xs_read(gc, XBT_NULL, num_devs_path);
    if (!num_devs)
        return ERROR_INVAL;
    num = atoi(num_devs);

    if (LIBXL__DOMAIN_IS_TYPE(gc, domid, PV)) {
        if (libxl__wait_for_backend(gc, be_path, "4") < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "pci backend at %s is not ready", be_path);
            return ERROR_FAIL;
        }
    }

    for (i = 0; i < num; i++) {
        xsdev = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/dev-%d", be_path, i));
        sscanf(xsdev, PCI_BDF, &domain, &bus, &dev, &func);
        if (domain == pcidev->domain && bus == pcidev->bus &&
            pcidev->dev == dev && pcidev->func == func) {
            break;
        }
    }
    if (i == num) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Couldn't find the device on xenstore");
        return ERROR_INVAL;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/state-%d", be_path, i), "5", strlen("5"));
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/state", be_path), "7", strlen("7"));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    if (LIBXL__DOMAIN_IS_TYPE(gc, domid, PV)) {
        if (libxl__wait_for_backend(gc, be_path, "4") < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "pci backend at %s is not ready", be_path);
            return ERROR_FAIL;
        }
    }

retry_transaction2:
    t = xs_transaction_start(ctx->xsh);
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/state-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/key-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/dev-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/vdev-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/opts-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl__sprintf(gc, "%s/vdevfn-%d", be_path, i));
    libxl__xs_write(gc, t, num_devs_path, "%d", num - 1);
    for (j = i + 1; j < num; j++) {
        tmppath = libxl__sprintf(gc, "%s/state-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/state-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl__sprintf(gc, "%s/dev-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/dev-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl__sprintf(gc, "%s/key-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/key-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl__sprintf(gc, "%s/vdev-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/vdev-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = libxl__sprintf(gc, "%s/opts-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/opts-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = libxl__sprintf(gc, "%s/vdevfn-%d", be_path, j);
        tmp = libxl__xs_read(gc, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/vdevfn-%d", be_path, j - 1), tmp, strlen(tmp));
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

        path = libxl__sprintf(gc, "/local/domain/0/backend/pci/%s/0/num_devs", domlist[i]);
        num_devs = libxl__xs_read(gc, XBT_NULL, path);
        if ( num_devs ) {
            int ndev = atoi(num_devs), j;
            char *devpath, *bdf;

            for(j = 0; j < ndev; j++) {
                devpath = libxl__sprintf(gc, "/local/domain/0/backend/pci/%s/0/dev-%u",
                                        domlist[i], j);
                bdf = libxl__xs_read(gc, XBT_NULL, devpath);
                if ( bdf ) {
                    unsigned dom, bus, dev, func;
                    if ( sscanf(bdf, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
                        continue;

                    *list = realloc(*list, sizeof(libxl_device_pci) * ((*num) + 1));
                    if (*list == NULL)
                        return ERROR_NOMEM;
                    pcidev_init(*list + *num, dom, bus, dev, func, 0);
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

libxl_device_pci *libxl_device_pci_list_assignable(libxl_ctx *ctx, int *num)
{
    GC_INIT(ctx);
    libxl_device_pci *pcidevs = NULL, *new, *assigned;
    struct dirent *de;
    DIR *dir;
    int rc, num_assigned;

    *num = 0;

    rc = get_all_assigned_devices(gc, &assigned, &num_assigned);
    if ( rc )
        goto out;

    dir = opendir(SYSFS_PCIBACK_DRIVER);
    if ( NULL == dir ) {
        if ( errno == ENOENT ) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Looks like pciback driver not loaded");
        }else{
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER);
        }
        goto out_closedir;
    }

    while( (de = readdir(dir)) ) {
        unsigned dom, bus, dev, func;
        if ( sscanf(de->d_name, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
            continue;

        if ( is_pcidev_in_array(assigned, num_assigned, dom, bus, dev, func) )
            continue;

        new = realloc(pcidevs, ((*num) + 1) * sizeof(*new));
        if ( NULL == new )
            continue;

        pcidevs = new;
        new = pcidevs + *num;

        memset(new, 0, sizeof(*new));
        pcidev_init(new, dom, bus, dev, func, 0);
        (*num)++;
    }

out_closedir:
    closedir(dir);
out:
    GC_FREE;
    return pcidevs;
}

/*
 * This function checks that all functions of a device are bound to pciback
 * driver. It also initialises a bit-mask of which function numbers are present
 * on that device.
*/
static int pci_multifunction_check(libxl__gc *gc, libxl_device_pci *pcidev, unsigned int *func_mask)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    struct dirent *de;
    DIR *dir;

    *func_mask = 0;

    dir = opendir(SYSFS_PCI_DEV);
    if ( NULL == dir ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", SYSFS_PCI_DEV);
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

        path = libxl__sprintf(gc, "%s/" PCI_BDF, SYSFS_PCIBACK_DRIVER, dom, bus, dev, func);
        if ( lstat(path, &st) ) {
            if ( errno == ENOENT )
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR, PCI_BDF " is not assigned to pciback driver",
                       dom, bus, dev, func);
            else
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't lstat %s", path);
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

    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    state = libxl__xs_read(gc, XBT_NULL, path);
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter",
                          domid);
    if (pcidev->vdevfn) {
        libxl__xs_write(gc, XBT_NULL, path, PCI_BDF_VDEVFN,
                        pcidev->domain, pcidev->bus, pcidev->dev,
                        pcidev->func, pcidev->vdevfn);
    } else {
        libxl__xs_write(gc, XBT_NULL, path, PCI_BDF, pcidev->domain,
                        pcidev->bus, pcidev->dev, pcidev->func);
    }

    libxl__qemu_traditional_cmd(gc, domid, "pci-ins");
    rc = libxl__wait_for_device_model(gc, domid, NULL, NULL,
                                      pci_ins_check, state);
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter",
                          domid);
    vdevfn = libxl__xs_read(gc, XBT_NULL, path);
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state",
                          domid);
    if ( rc < 0 )
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "qemu refused to add device: %s", vdevfn);
    else if ( sscanf(vdevfn, "0x%x", &pcidev->vdevfn) != 1 ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "wrong format for the vdevfn: '%s'", vdevfn);
        rc = -1;
    }
    xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));

    return rc;
}

static int do_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc, hvm = 0;

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        hvm = 1;
        if (libxl__wait_for_device_model(gc, domid, "running",
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
        break;
    case LIBXL_DOMAIN_TYPE_PV:
    {
        char *sysfs_path = libxl__sprintf(gc, SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
                                         pcidev->bus, pcidev->dev, pcidev->func);
        FILE *f = fopen(sysfs_path, "r");
        unsigned long long start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", sysfs_path);
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
                        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "Error: xc_domain_ioport_permission error 0x%llx/0x%llx", start, size);
                        fclose(f);
                        return ERROR_FAIL;
                    }
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 1);
                    if (rc < 0) {
                        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "Error: xc_domain_iomem_permission error 0x%llx/0x%llx", start, size);
                        fclose(f);
                        return ERROR_FAIL;
                    }
                }
            }
        }
        fclose(f);
        sysfs_path = libxl__sprintf(gc, SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
                                   pcidev->bus, pcidev->dev, pcidev->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", sysfs_path);
            goto out;
        }
        if ((fscanf(f, "%u", &irq) == 1) && irq) {
            rc = xc_physdev_map_pirq(ctx->xch, domid, irq, &irq);
            if (rc < 0) {
                LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "Error: xc_physdev_map_pirq irq=%d", irq);
                fclose(f);
                return ERROR_FAIL;
            }
            rc = xc_domain_irq_permission(ctx->xch, domid, irq, 1);
            if (rc < 0) {
                LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "Error: xc_domain_irq_permission irq=%d", irq);
                fclose(f);
                return ERROR_FAIL;
            }
        }
        fclose(f);
        break;
    }
    default:
        abort();
    }
out:
    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_assign_device(ctx->xch, domid, pcidev_encode_bdf(pcidev));
        if (rc < 0 && (hvm || errno != ENOSYS)) {
            LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_assign_device failed");
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
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *reset;
    int fd, rc;

    reset = libxl__sprintf(gc, "%s/pciback/do_flr", SYSFS_PCI_DEV);
    fd = open(reset, O_WRONLY);
    if (fd > 0) {
        char *buf = libxl__sprintf(gc, PCI_BDF, domain, bus, dev, func);
        rc = write(fd, buf, strlen(buf));
        if (rc < 0)
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno != ENOENT)
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to access pciback path %s", reset);
    reset = libxl__sprintf(gc, "%s/"PCI_BDF"/reset", SYSFS_PCI_DEV, domain, bus, dev, func);
    fd = open(reset, O_WRONLY);
    if (fd > 0) {
        rc = write(fd, "1", 1);
        if (rc < 0)
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno == ENOENT) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "The kernel doesn't support reset from sysfs for PCI device "PCI_BDF, domain, bus, dev, func);
    } else {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to access reset path %s", reset);
    }
    return -1;
}

int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    GC_INIT(ctx);
    int rc;
    rc = libxl__device_pci_add(gc, domid, pcidev, 0);
    GC_FREE;
    return rc;
}

int libxl__device_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    unsigned int orig_vdev, pfunc_mask;
    libxl_device_pci *assigned;
    int num_assigned, i, rc;
    int stubdomid = 0;

    rc = get_all_assigned_devices(gc, &assigned, &num_assigned);
    if ( rc ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot determine if device is assigned, refusing to continue");
        goto out;
    }
    if ( is_pcidev_in_array(assigned, num_assigned, pcidev->domain,
                     pcidev->bus, pcidev->dev, pcidev->func) ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "PCI device already attached to a domain");
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
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Must specify a v-slot for multi-function devices");
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

static int qemu_pci_remove_xenstore(libxl__gc *gc, uint32_t domid,
                                    libxl_device_pci *pcidev, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *state;
    char *path;

    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    state = libxl__xs_read(gc, XBT_NULL, path);
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter", domid);
    libxl__xs_write(gc, XBT_NULL, path, PCI_BDF, pcidev->domain,
                    pcidev->bus, pcidev->dev, pcidev->func);

    /* Remove all functions at once atomically by only signalling
     * device-model for function 0 */
    if ( !force && (pcidev->vdevfn & 0x7) == 0 ) {
        libxl__qemu_traditional_cmd(gc, domid, "pci-rem");
        if (libxl__wait_for_device_model(gc, domid, "pci-removed",
                                         NULL, NULL, NULL) < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Device Model didn't respond in time");
            /* This depends on guest operating system acknowledging the
             * SCI, if it doesn't respond in time then we may wish to
             * force the removal.
             */
            return ERROR_FAIL;
        }
    }
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));

    return 0;
}

static int do_pci_remove(libxl__gc *gc, uint32_t domid,
                         libxl_device_pci *pcidev, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_device_pci *assigned;
    int hvm = 0, rc, num;
    int stubdomid = 0;

    assigned = libxl_device_pci_list(ctx, domid, &num);
    if ( assigned == NULL )
        return ERROR_FAIL;

    rc = ERROR_INVAL;
    if ( !is_pcidev_in_array(assigned, num, pcidev->domain,
                      pcidev->bus, pcidev->dev, pcidev->func) ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "PCI device not attached to this domain");
        goto out_fail;
    }

    rc = ERROR_FAIL;
    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        hvm = 1;
        if (libxl__wait_for_device_model(gc, domid, "running",
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
        if (rc) {
            rc = ERROR_FAIL;
            goto out_fail;
        }
        break;
    case LIBXL_DOMAIN_TYPE_PV:
    {
        char *sysfs_path = libxl__sprintf(gc, SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
                                         pcidev->bus, pcidev->dev, pcidev->func);
        FILE *f = fopen(sysfs_path, "r");
        unsigned int start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", sysfs_path);
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
                        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_domain_ioport_permission error 0x%x/0x%x", start, size);
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 0);
                    if (rc < 0)
                        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_domain_iomem_permission error 0x%x/0x%x", start, size);
                }
            }
        }
        fclose(f);
skip1:
        sysfs_path = libxl__sprintf(gc, SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
                                   pcidev->bus, pcidev->dev, pcidev->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", sysfs_path);
            goto out;
        }
        if ((fscanf(f, "%u", &irq) == 1) && irq) {
            rc = xc_physdev_unmap_pirq(ctx->xch, domid, irq);
            if (rc < 0) {
                LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_physdev_unmap_pirq irq=%d", irq);
            }
            rc = xc_domain_irq_permission(ctx->xch, domid, irq, 0);
            if (rc < 0) {
                LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_domain_irq_permission irq=%d", irq);
            }
        }
        fclose(f);
        break;
    }
    default:
        abort();
    }
out:
    /* don't do multiple resets while some functions are still passed through */
    if ( (pcidev->vdevfn & 0x7) == 0 ) {
        libxl__device_pci_reset(gc, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    }

    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_deassign_device(ctx->xch, domid, pcidev_encode_bdf(pcidev));
        if (rc < 0 && (hvm || errno != ENOSYS))
            LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_deassign_device failed");
    }

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        if (force)
                libxl_device_pci_destroy(ctx, stubdomid, &pcidev_s);
        else
                libxl_device_pci_remove(ctx, stubdomid, &pcidev_s);
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

int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_remove_common(gc, domid, pcidev, 0);

    GC_FREE;
    return rc;
}

int libxl_device_pci_destroy(libxl_ctx *ctx, uint32_t domid,
                                  libxl_device_pci *pcidev)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__device_pci_remove_common(gc, domid, pcidev, 1);

    GC_FREE;
    return rc;
}

static void libxl__device_pci_from_xs_be(libxl__gc *gc,
                                         const char *be_path,
                                         libxl_device_pci *pci,
                                         int nr)
{
    char *s;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;

    s = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/dev-%d", be_path, nr));
    sscanf(s, PCI_BDF, &domain, &bus, &dev, &func);

    s = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/vdevfn-%d", be_path, nr));
    if (s)
        vdevfn = strtol(s, (char **) NULL, 16);

    pcidev_init(pci, domain, bus, dev, func, vdevfn);

    s = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/opts-%d", be_path, nr));
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
            }
        } while ((p = strtok_r(NULL, ",=", &saveptr)) != NULL);
    }
}

libxl_device_pci *libxl_device_pci_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);
    char *be_path, *num_devs;
    int n, i;
    libxl_device_pci *pcidevs = NULL;

    *num = 0;

    be_path = libxl__sprintf(gc, "%s/backend/pci/%d/0", libxl__xs_get_dompath(gc, 0), domid);
    num_devs = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/num_devs", be_path));
    if (!num_devs)
        goto out;

    n = atoi(num_devs);
    pcidevs = calloc(n, sizeof(libxl_device_pci));

    for (i = 0; i < n; i++)
        libxl__device_pci_from_xs_be(gc, be_path, pcidevs + i, i);

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
        if (libxl_device_pci_destroy(ctx, domid, pcidevs + i) < 0)
            rc = ERROR_FAIL;
    }

    free(pcidevs);
    return 0;
}

static const char *e820_names(int type)
{
    switch (type) {
        case E820_RAM: return "RAM";
        case E820_RESERVED: return "Reserved";
        case E820_ACPI: return "ACPI";
        case E820_NVS: return "ACPI NVS";
        case E820_UNUSABLE: return "Unusable";
        default: break;
    }
    return "Unknown";
}

static int e820_sanitize(libxl_ctx *ctx, struct e820entry src[],
                         uint32_t *nr_entries,
                         unsigned long map_limitkb,
                         unsigned long balloon_kb)
{
    uint64_t delta_kb = 0, start = 0, start_kb = 0, last = 0, ram_end;
    uint32_t i, idx = 0, nr;
    struct e820entry e820[E820MAX];

    if (!src || !map_limitkb || !balloon_kb || !nr_entries)
        return ERROR_INVAL;

    nr = *nr_entries;
    if (!nr)
        return ERROR_INVAL;

    if (nr > E820MAX)
        return ERROR_NOMEM;

    /* Weed out anything under 1MB */
    for (i = 0; i < nr; i++) {
        if (src[i].addr > 0x100000)
            continue;

        src[i].type = 0;
        src[i].size = 0;
        src[i].addr = -1ULL;
    }

    /* Find the lowest and highest entry in E820, skipping over
     * undesired entries. */
    start = -1ULL;
    last = 0;
    for (i = 0; i < nr; i++) {
        if ((src[i].type == E820_RAM) ||
            (src[i].type == E820_UNUSABLE) ||
            (src[i].type == 0))
            continue;

        start = src[i].addr < start ? src[i].addr : start;
        last = src[i].addr + src[i].size > last ?
               src[i].addr + src[i].size > last : last;
    }
    if (start > 1024)
        start_kb = start >> 10;

    /* Add the memory RAM region for the guest */
    e820[idx].addr = 0;
    e820[idx].size = (uint64_t)map_limitkb << 10;
    e820[idx].type = E820_RAM;

    /* .. and trim if neccessary */
    if (start_kb && map_limitkb > start_kb) {
        delta_kb = map_limitkb - start_kb;
        if (delta_kb)
            e820[idx].size -= (uint64_t)(delta_kb << 10);
    }
    /* Note: We don't touch balloon_kb here. Will add it at the end. */
    ram_end = e820[idx].addr + e820[idx].size;
    idx ++;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Memory: %"PRIu64"kB End of RAM: " \
               "0x%"PRIx64" (PFN) Delta: %"PRIu64"kB, PCI start: %"PRIu64"kB " \
               "(0x%"PRIx64" PFN), Balloon %"PRIu64"kB\n", (uint64_t)map_limitkb,
               ram_end >> 12, delta_kb, start_kb ,start >> 12,
               (uint64_t)balloon_kb);


    /* This whole code below is to guard against if the Intel IGD is passed into
     * the guest. If we don't pass in IGD, this whole code can be ignored.
     *
     * The reason for this code is that Intel boxes fill their E820 with
     * E820_RAM amongst E820_RESERVED and we can't just ditch those E820_RAM.
     * That is b/c any "gaps" in the E820 is considered PCI I/O space by
     * Linux and it would be utilized by the Intel IGD as I/O space while
     * in reality it was an RAM region.
     *
     * What this means is that we have to walk the E820 and for any region
     * that is RAM and below 4GB and above ram_end, needs to change its type
     * to E820_UNUSED. We also need to move some of the E820_RAM regions if
     * the overlap with ram_end. */
    for (i = 0; i < nr; i++) {
        uint64_t end = src[i].addr + src[i].size;

        /* We don't care about E820_UNUSABLE, but we need to
         * change the type to zero b/c the loop after this
         * sticks E820_UNUSABLE on the guest's E820 but ignores
         * the ones with type zero. */
        if ((src[i].type == E820_UNUSABLE) ||
            /* Any region that is within the "RAM region" can
             * be safely ditched. */
            (end < ram_end)) {
                src[i].type = 0;
                continue;
        }

        /* Look only at RAM regions. */
        if (src[i].type != E820_RAM)
            continue;

        /* We only care about RAM regions below 4GB. */
        if (src[i].addr >= (1ULL<<32))
            continue;

        /* E820_RAM overlaps with our RAM region. Move it */
        if (src[i].addr < ram_end) {
            uint64_t delta;

            src[i].type = E820_UNUSABLE;
            delta = ram_end - src[i].addr;
            /* The end < ram_end should weed this out */
            if (src[i].size - delta < 0)
                src[i].type = 0;
            else {
                src[i].size -= delta;
                src[i].addr = ram_end;
            }
            if (src[i].addr + src[i].size != end) {
                /* We messed up somewhere */
                src[i].type = 0;
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Computed E820 wrongly. Continuing on.");
            }
        }
        /* Lastly, convert the RAM to UNSUABLE. Look in the Linux kernel
           at git commit 2f14ddc3a7146ea4cd5a3d1ecd993f85f2e4f948
            "xen/setup: Inhibit resource API from using System RAM E820
           gaps as PCI mem gaps" for full explanation. */
        if (end > ram_end)
            src[i].type = E820_UNUSABLE;
    }

    /* Check if there is a region between ram_end and start. */
    if (start > ram_end) {
        int add_unusable = 1;
        for (i = 0; i < nr && add_unusable; i++) {
            if (src[i].type != E820_UNUSABLE)
                continue;
            if (ram_end != src[i].addr)
                continue;
            if (start != src[i].addr + src[i].size) {
                /* there is one, adjust it */
                src[i].size = start - src[i].addr;
            }
            add_unusable = 0;
        }
        /* .. and if not present, add it in. This is to guard against
           the Linux guest assuming that the gap between the end of
           RAM region and the start of the E820_[ACPI,NVS,RESERVED]
           is PCI I/O space. Which it certainly is _not_. */
        if (add_unusable) {
            e820[idx].type = E820_UNUSABLE;
            e820[idx].addr = ram_end;
            e820[idx].size = start - ram_end;
            idx++;
        }
    }
    /* Almost done: copy them over, ignoring the undesireable ones */
    for (i = 0; i < nr; i++) {
        if ((src[i].type == E820_RAM) ||
            (src[i].type == 0))
            continue;

        e820[idx].type = src[i].type;
        e820[idx].addr = src[i].addr;
        e820[idx].size = src[i].size;
        idx++;
    }
    /* At this point we have the mapped RAM + E820 entries from src. */
    if (balloon_kb) {
        /* and if we truncated the RAM region, then add it to the end. */
        e820[idx].type = E820_RAM;
        e820[idx].addr = (uint64_t)(1ULL << 32) > last ?
                         (uint64_t)(1ULL << 32) : last;
        /* also add the balloon memory to the end. */
        e820[idx].size = (uint64_t)(delta_kb << 10) +
                         (uint64_t)(balloon_kb << 10);
        idx++;

    }
    nr = idx;

    for (i = 0; i < nr; i++) {
      LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, ":\t[%"PRIx64" -> %"PRIx64"] %s",
                 e820[i].addr >> 12, (e820[i].addr + e820[i].size) >> 12,
                 e820_names(e820[i].type));
    }

    /* Done: copy the sanitized version. */
    *nr_entries = nr;
    memcpy(src, e820, nr * sizeof(struct e820entry));
    return 0;
}

int libxl__e820_alloc(libxl__gc *gc, uint32_t domid, libxl_domain_config *d_config)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int rc;
    uint32_t nr;
    struct e820entry map[E820MAX];
    libxl_domain_build_info *b_info;

    if (d_config == NULL || d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM)
        return ERROR_INVAL;

    b_info = &d_config->b_info;
    if (!b_info->u.pv.e820_host)
        return ERROR_INVAL;

    rc = xc_get_machine_memory_map(ctx->xch, map, E820MAX);
    if (rc < 0) {
        errno = rc;
        return ERROR_FAIL;
    }
    nr = rc;
    rc = e820_sanitize(ctx, map, &nr, b_info->target_memkb,
                       (b_info->max_memkb - b_info->target_memkb) +
                       b_info->u.pv.slack_memkb);
    if (rc)
        return ERROR_FAIL;

    rc = xc_domain_set_memory_map(ctx->xch, domid, map, nr);

    if (rc < 0) {
        errno  = rc;
        return ERROR_FAIL;
    }
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
