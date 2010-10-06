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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h> /* for write, unlink and close */
#include <stdint.h>
#include <inttypes.h>
#include <dirent.h>
#include <assert.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "libxl_internal.h"
#include "flexarray.h"

#define PCI_BDF                "%04x:%02x:%02x.%01x"
#define PCI_BDF_SHORT          "%02x:%02x.%01x"
#define PCI_BDF_VDEVFN         "%04x:%02x:%02x.%01x@%02x"

static unsigned int pcidev_value(libxl_device_pci *pcidev)
{
    union {
        unsigned int value;
        struct {
            unsigned int reserved1:2;
            unsigned int reg:6;
            unsigned int func:3;
            unsigned int dev:5;
            unsigned int bus:8;
            unsigned int reserved2:7;
            unsigned int enable:1;
        }fields;
    }u;

    u.value = 0;
    u.fields.reg = pcidev->reg;
    u.fields.func = pcidev->func;
    u.fields.dev = pcidev->dev;
    u.fields.bus = pcidev->bus;
    u.fields.enable = pcidev->enable;

    return u.value;
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

static int libxl_create_pci_backend(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int num)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl__device device;
    int i;

    front = flexarray_make(16, 1);
    if (!front)
        return ERROR_NOMEM;
    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Creating pci backend");

    /* add pci device */
    device.backend_devid = 0;
    device.backend_domid = 0;
    device.backend_kind = DEVICE_PCI;
    device.devid = 0;
    device.domid = domid;
    device.kind = DEVICE_PCI;

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, libxl__domid_to_name(gc, domid));
    for (i = 0; i < num; i++) {
        flexarray_set(back, boffset++, libxl__sprintf(gc, "key-%d", i));
        flexarray_set(back, boffset++, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
        flexarray_set(back, boffset++, libxl__sprintf(gc, "dev-%d", i));
        flexarray_set(back, boffset++, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
        if (pcidev->vdevfn) {
            flexarray_set(back, boffset++, libxl__sprintf(gc, "vdevfn-%d", i));
            flexarray_set(back, boffset++, libxl__sprintf(gc, "%x", pcidev->vdevfn));
        }
        flexarray_set(back, boffset++, libxl__sprintf(gc, "opts-%d", i));
        flexarray_set(back, boffset++, libxl__sprintf(gc, "msitranslate=%d,power_mgmt=%d", pcidev->msitranslate, pcidev->power_mgmt));
        flexarray_set(back, boffset++, libxl__sprintf(gc, "state-%d", i));
        flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", 1));
    }
    flexarray_set(back, boffset++, "num_devs");
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", num));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl__sprintf(gc, "%d", 0));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl__sprintf(gc, "%d", 1));

    libxl__device_generic_add(ctx, &device,
                             libxl__xs_kvs_of_flexarray(gc, back, boffset),
                             libxl__xs_kvs_of_flexarray(gc, front, foffset));

    flexarray_free(back);
    flexarray_free(front);
    return 0;
}

static int libxl_device_pci_add_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    flexarray_t *back;
    char *num_devs, *be_path;
    int num = 0;
    unsigned int boffset = 0;
    xs_transaction_t t;

    be_path = libxl__sprintf(gc, "%s/backend/pci/%d/0", libxl__xs_get_dompath(gc, 0), domid);
    num_devs = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/num_devs", be_path));
    if (!num_devs)
        return libxl_create_pci_backend(gc, domid, pcidev, 1);

    if (!libxl__domain_is_hvm(ctx, domid)) {
        if (libxl__wait_for_backend(ctx, be_path, "4") < 0)
            return ERROR_FAIL;
    }

    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Adding new pci device to xenstore");
    num = atoi(num_devs);
    flexarray_set(back, boffset++, libxl__sprintf(gc, "key-%d", num));
    flexarray_set(back, boffset++, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    flexarray_set(back, boffset++, libxl__sprintf(gc, "dev-%d", num));
    flexarray_set(back, boffset++, libxl__sprintf(gc, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    if (pcidev->vdevfn) {
        flexarray_set(back, boffset++, libxl__sprintf(gc, "vdevfn-%d", num));
        flexarray_set(back, boffset++, libxl__sprintf(gc, "%x", pcidev->vdevfn));
    }
    flexarray_set(back, boffset++, libxl__sprintf(gc, "opts-%d", num));
    flexarray_set(back, boffset++, libxl__sprintf(gc, "msitranslate=%d,power_mgmt=%d", pcidev->msitranslate, pcidev->power_mgmt));
    flexarray_set(back, boffset++, libxl__sprintf(gc, "state-%d", num));
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", 1));
    flexarray_set(back, boffset++, "num_devs");
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", num + 1));
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl__sprintf(gc, "%d", 7));

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    libxl__xs_writev(gc, t, be_path,
                    libxl__xs_kvs_of_flexarray(gc, back, boffset));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    flexarray_free(back);
    return 0;
}

static int libxl_device_pci_remove_xenstore(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev)
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

    if (!libxl__domain_is_hvm(ctx, domid)) {
        if (libxl__wait_for_backend(ctx, be_path, "4") < 0) {
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

    if (!libxl__domain_is_hvm(ctx, domid)) {
        if (libxl__wait_for_backend(ctx, be_path, "4") < 0) {
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
        char *fe_path = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/frontend", be_path));
        libxl__device_destroy(ctx, be_path, 1);
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        xs_rm(ctx->xsh, XBT_NULL, fe_path);
        return 0;
    }

    return 0;
}

static int get_all_assigned_devices(libxl__gc *gc, libxl_device_pci **list, int *num)
{
    libxl_device_pci *pcidevs = NULL;
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

            pcidevs = libxl__calloc(gc, sizeof(*pcidevs), ndev);
            for(j = (pcidevs) ? 0 : ndev; j < ndev; j++) {
                devpath = libxl__sprintf(gc, "/local/domain/0/backend/pci/%s/0/dev-%u",
                                        domlist[i], j);
                bdf = libxl__xs_read(gc, XBT_NULL, devpath);
                if ( bdf ) {
                    unsigned dom, bus, dev, func;
                    if ( sscanf(bdf, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
                        continue;

                    pcidev_init(pcidevs + *num, dom, bus, dev, func, 0);
                    (*num)++;
                }
            }
        }
    }

    if ( 0 == *num ) {
        free(pcidevs);
        pcidevs = NULL;
    }else{
        *list = pcidevs;
    }

    return 0;
}

static int is_assigned(libxl_device_pci *assigned, int num_assigned,
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

int libxl_device_pci_list_assignable(libxl_ctx *ctx, libxl_device_pci **list, int *num)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    libxl_device_pci *pcidevs = NULL, *new, *assigned;
    struct dirent *de;
    DIR *dir;
    int rc, num_assigned;

    *num = 0;
    *list = NULL;

    rc = get_all_assigned_devices(&gc, &assigned, &num_assigned);
    if ( rc )
        return rc;

    dir = opendir(SYSFS_PCIBACK_DRIVER);
    if ( NULL == dir ) {
        if ( errno == ENOENT ) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Looks like pciback driver not loaded");
        }else{
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER);
        }
        libxl__free_all(&gc);
        return ERROR_FAIL;
    }

    while( (de = readdir(dir)) ) {
        unsigned dom, bus, dev, func;
        if ( sscanf(de->d_name, PCI_BDF, &dom, &bus, &dev, &func) != 4 )
            continue;

        if ( is_assigned(assigned, num_assigned, dom, bus, dev, func) )
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

    closedir(dir);
    *list = pcidevs;
    libxl__free_all(&gc);
    return 0;
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

static int pci_ins_check(libxl_ctx *ctx, uint32_t domid, const char *state, void *priv)
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
 
static int do_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path;
    char *state, *vdevfn;
    int rc, hvm;

    hvm = libxl__domain_is_hvm(ctx, domid);
    if (hvm) {
        if (libxl__wait_for_device_model(ctx, domid, "running", NULL, NULL) < 0) {
            return ERROR_FAIL;
        }
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
        state = libxl__xs_read(gc, XBT_NULL, path);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter", domid);
        if (pcidev->vdevfn)
            libxl__xs_write(gc, XBT_NULL, path, PCI_BDF_VDEVFN, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func, pcidev->vdevfn);
        else
            libxl__xs_write(gc, XBT_NULL, path, PCI_BDF, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/command", domid);
        xs_write(ctx->xsh, XBT_NULL, path, "pci-ins", strlen("pci-ins"));
        rc = libxl__wait_for_device_model(ctx, domid, NULL, pci_ins_check, state);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter", domid);
        vdevfn = libxl__xs_read(gc, XBT_NULL, path);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
        if ( rc < 0 )
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "qemu refused to add device: %s", vdevfn);
        else if ( sscanf(vdevfn, "0x%x", &pcidev->vdevfn) != 1 )
            rc = -1;
        xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));
        if ( rc )
            return ERROR_FAIL;
    } else {
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
    }
out:
    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_assign_device(ctx->xch, domid, pcidev_value(pcidev));
        if (rc < 0 && (hvm || errno != ENOSYS)) {
            LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_assign_device failed");
            return ERROR_FAIL;
        }
    }

    libxl_device_pci_add_xenstore(gc, domid, pcidev);
    return 0;
}

static int libxl_device_pci_reset(libxl__gc *gc, unsigned int domain, unsigned int bus,
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
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "The kernel doesn't support PCI device reset from sysfs");
    } else {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to access reset path %s", reset);
    }
    return -1;
}

int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    unsigned int orig_vdev, pfunc_mask;
    libxl_device_pci *assigned;
    int num_assigned, i, rc;
    int stubdomid = 0;

    rc = get_all_assigned_devices(&gc, &assigned, &num_assigned);
    if ( rc ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot determine if device is assigned, refusing to continue");
        goto out;
    }
    if ( is_assigned(assigned, num_assigned, pcidev->domain,
                     pcidev->bus, pcidev->dev, pcidev->func) ) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "PCI device already attached to a domain");
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_device_pci_reset(&gc, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        rc = do_pci_add(&gc, stubdomid, &pcidev_s);
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
        if ( pci_multifunction_check(&gc, pcidev, &pfunc_mask) ) {
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
            if ( do_pci_add(&gc, domid, pcidev) )
                rc = ERROR_FAIL;
        }
    }

out:
    libxl__free_all(&gc);
    return rc;
}

static int do_pci_remove(libxl__gc *gc, uint32_t domid,
                         libxl_device_pci *pcidev, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_device_pci *assigned;
    char *path;
    char *state;
    int hvm, rc, num;
    int stubdomid = 0;

    if ( !libxl_device_pci_list_assigned(ctx, &assigned, domid, &num) ) {
        if ( !is_assigned(assigned, num, pcidev->domain,
                         pcidev->bus, pcidev->dev, pcidev->func) ) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "PCI device not attached to this domain");
            return ERROR_INVAL;
        }
    }

    hvm = libxl__domain_is_hvm(ctx, domid);
    if (hvm) {
        if (libxl__wait_for_device_model(ctx, domid, "running", NULL, NULL) < 0) {
            return ERROR_FAIL;
        }
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
        state = libxl__xs_read(gc, XBT_NULL, path);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/parameter", domid);
        libxl__xs_write(gc, XBT_NULL, path, PCI_BDF, pcidev->domain,
                       pcidev->bus, pcidev->dev, pcidev->func);
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/command", domid);

        /* Remove all functions at once atomically by only signalling
         * device-model for function 0 */
        if ( (pcidev->vdevfn & 0x7) == 0 ) {
            xs_write(ctx->xsh, XBT_NULL, path, "pci-rem", strlen("pci-rem"));
            if (libxl__wait_for_device_model(ctx, domid, "pci-removed", NULL, NULL) < 0) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Device Model didn't respond in time");
                /* This depends on guest operating system acknowledging the
                 * SCI, if it doesn't respond in time then we may wish to 
                 * force the removal.
                 */
                if ( !force )
                    return ERROR_FAIL;
            }
        }
        path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
        xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));
    } else {
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
    }
out:
    /* don't do multiple resets while some functions are still passed through */
    if ( (pcidev->vdevfn & 0x7) == 0 ) {
        libxl_device_pci_reset(gc, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);
    }

    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_deassign_device(ctx->xch, domid, pcidev_value(pcidev));
        if (rc < 0 && (hvm || errno != ENOSYS))
            LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, rc, "xc_deassign_device failed");
    }

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        libxl_device_pci_remove(ctx, stubdomid, &pcidev_s, force);
    }

    libxl_device_pci_remove_xenstore(gc, domid, pcidev);

    return 0;
}

int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_pci *pcidev, int force)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    unsigned int orig_vdev, pfunc_mask;
    int i, rc;

    orig_vdev = pcidev->vdevfn & ~7U;

    if ( pcidev->vfunc_mask == LIBXL_PCI_FUNC_ALL ) {
        if ( pci_multifunction_check(&gc, pcidev, &pfunc_mask) ) {
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
            if ( do_pci_remove(&gc, domid, pcidev, force) )
                rc = ERROR_FAIL;
        }
    }

out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_device_pci_list_assigned(libxl_ctx *ctx, libxl_device_pci **list, uint32_t domid, int *num)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *be_path, *num_devs, *xsdev, *xsvdevfn, *xsopts;
    int n, i;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;
    libxl_device_pci *pcidevs;

    be_path = libxl__sprintf(&gc, "%s/backend/pci/%d/0", libxl__xs_get_dompath(&gc, 0), domid);
    num_devs = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/num_devs", be_path));
    if (!num_devs) {
        *num = 0;
        *list = NULL;
        libxl__free_all(&gc);
        return 0;
    }
    n = atoi(num_devs);
    pcidevs = calloc(n, sizeof(libxl_device_pci));
    *num = n;

    for (i = 0; i < n; i++) {
        xsdev = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/dev-%d", be_path, i));
        sscanf(xsdev, PCI_BDF, &domain, &bus, &dev, &func);
        xsvdevfn = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/vdevfn-%d", be_path, i));
        if (xsvdevfn)
            vdevfn = strtol(xsvdevfn, (char **) NULL, 16);
        pcidev_init(pcidevs + i, domain, bus, dev, func, vdevfn);
        xsopts = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/opts-%d", be_path, i));
        if (xsopts) {
            char *saveptr;
            char *p = strtok_r(xsopts, ",=", &saveptr);
            do {
                while (*p == ' ')
                    p++;
                if (!strcmp(p, "msitranslate")) {
                    p = strtok_r(NULL, ",=", &saveptr);
                    pcidevs[i].msitranslate = atoi(p);
                } else if (!strcmp(p, "power_mgmt")) {
                    p = strtok_r(NULL, ",=", &saveptr);
                    pcidevs[i].power_mgmt = atoi(p);
                }
            } while ((p = strtok_r(NULL, ",=", &saveptr)) != NULL);
        }
    }
    if ( *num )
        *list = pcidevs;
    libxl__free_all(&gc);
    return 0;
}

int libxl_device_pci_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    libxl_device_pci *pcidevs;
    int num, i, rc;

    rc = libxl_device_pci_list_assigned(ctx, &pcidevs, domid, &num);
    if ( rc )
        return rc;
    for (i = 0; i < num; i++) {
        /* Force remove on shutdown since, on HVM, qemu will not always
         * respond to SCI interrupt because the guest kernel has shut down the
         * devices by the time we even get here!
         */
        if (libxl_device_pci_remove(ctx, domid, pcidevs + i, 1) < 0)
            return ERROR_FAIL;
    }
    free(pcidevs);
    return 0;
}
