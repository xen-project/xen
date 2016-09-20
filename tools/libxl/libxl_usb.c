/*
 * Copyright (C) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Author Chunyan Liu <cyliu@suse.com>
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
#include <inttypes.h>
#include <xen/io/usbif.h>

#define USBBACK_INFO_PATH "/libxl/usbback"

#define USBHUB_CLASS_CODE 9

static int usbback_is_loaded(libxl__gc *gc)
{
    int r;
    struct stat st;

    r = lstat(SYSFS_USBBACK_DRIVER, &st);

    if (r == 0)
        return 1;
    if (r < 0 && errno == ENOENT)
        return 0;
    LOGE(ERROR, "Accessing %s", SYSFS_USBBACK_DRIVER);
    return ERROR_FAIL;
}

static int libxl__device_usbctrl_setdefault(libxl__gc *gc, uint32_t domid,
                                            libxl_device_usbctrl *usbctrl)
{
    int rc;
    libxl_domain_type domtype = libxl__domain_type(gc, domid);

    if (usbctrl->type == LIBXL_USBCTRL_TYPE_AUTO) {
        if (domtype == LIBXL_DOMAIN_TYPE_PV) {
            rc = usbback_is_loaded(gc);
            if (rc < 0)
                goto out;
            usbctrl->type = rc ? LIBXL_USBCTRL_TYPE_PV
                               : LIBXL_USBCTRL_TYPE_QUSB;
        } else if (domtype == LIBXL_DOMAIN_TYPE_HVM) {
            /* FIXME: See if we can detect PV frontend */
            usbctrl->type = LIBXL_USBCTRL_TYPE_DEVICEMODEL;
        }
    }

    switch (usbctrl->type) {
    case LIBXL_USBCTRL_TYPE_PV:
    case LIBXL_USBCTRL_TYPE_QUSB:
        if (!usbctrl->version)
            usbctrl->version = 2;
        if (usbctrl->version < 1 || usbctrl->version > 2) {
            LOG(ERROR,
                "USB version for paravirtualized devices must be 1 or 2");
            rc = ERROR_INVAL;
            goto out;
        }
        if (!usbctrl->ports)
            usbctrl->ports = 8;
        if (usbctrl->ports < 1 || usbctrl->ports > USBIF_MAX_PORTNR) {
            LOG(ERROR, "Number of ports for USB controller is limited to %u",
                USBIF_MAX_PORTNR);
            rc = ERROR_INVAL;
            goto out;
        }
        break;
    case LIBXL_USBCTRL_TYPE_DEVICEMODEL:
        if (!usbctrl->version)
            usbctrl->version = 2;
        switch (usbctrl->version) {
        case 1:
            /* uhci controller in qemu has fixed number of ports. */
            if (usbctrl->ports && usbctrl->ports != 2) {
                LOG(ERROR,
                    "Number of ports for USB controller of version 1 is always 2");
                rc = ERROR_INVAL;
                goto out;
            }
            usbctrl->ports = 2;
            break;
        case 2:
            /* ehci controller in qemu has fixed number of ports. */
            if (usbctrl->ports && usbctrl->ports != 6) {
                LOG(ERROR,
                    "Number of ports for USB controller of version 2 is always 6");
                rc = ERROR_INVAL;
                goto out;
            }
            usbctrl->ports = 6;
            break;
        case 3:
            if (!usbctrl->ports)
                usbctrl->ports = 8;
            /* xhci controller in qemu supports up to 15 ports. */
            if (usbctrl->ports > 15) {
                LOG(ERROR,
                    "Number of ports for USB controller of version 3 is limited to 15");
                rc = ERROR_INVAL;
                goto out;
            }
            break;
        default:
            LOG(ERROR, "Illegal USB version");
            rc = ERROR_INVAL;
            goto out;
        }
        break;
    default:
        break;
    }

    rc = libxl__resolve_domid(gc, usbctrl->backend_domname,
                              &usbctrl->backend_domid);

out:
    return rc;
}

static int libxl__device_from_usbctrl(libxl__gc *gc, uint32_t domid,
                                      libxl_device_usbctrl *usbctrl,
                                      libxl__device *device)
{
    device->backend_devid   = usbctrl->devid;
    device->backend_domid   = usbctrl->backend_domid;
    switch (usbctrl->type) {
    case LIBXL_USBCTRL_TYPE_PV:
        device->backend_kind = LIBXL__DEVICE_KIND_VUSB;
        break;
    case LIBXL_USBCTRL_TYPE_QUSB:
        device->backend_kind = LIBXL__DEVICE_KIND_QUSB;
        break;
    case LIBXL_USBCTRL_TYPE_DEVICEMODEL:
        device->backend_kind = LIBXL__DEVICE_KIND_NONE;
        break;
    default:
        assert(0); /* can't really happen. */
        break;
    }
    device->devid           = usbctrl->devid;
    device->domid           = domid;
    device->kind            = LIBXL__DEVICE_KIND_VUSB;

    return 0;
}

static const char *vusb_be_from_xs_libxl_type(libxl__gc *gc,
                                              const char *libxl_path,
                                              libxl_usbctrl_type type)
{
    const char *be_path = NULL, *tmp;
    int r;

    if (type == LIBXL_USBCTRL_TYPE_AUTO) {
        r = libxl__xs_read_checked(gc, XBT_NULL,
                                   GCSPRINTF("%s/type", libxl_path), &tmp);
        if (r || libxl_usbctrl_type_from_string(tmp, &type))
            goto out;
    }

    if (type == LIBXL_USBCTRL_TYPE_DEVICEMODEL) {
        be_path = libxl_path;
        goto out;
    }

    r = libxl__xs_read_checked(gc, XBT_NULL,
                               GCSPRINTF("%s/backend", libxl_path),
                               &be_path);
    if (r)
        be_path = NULL;

out:
    return be_path;
}

/* Add usbctrl information to xenstore.
 *
 * Adding a usb controller will add a new 'qusb' or 'vusb' device in xenstore,
 * and add corresponding frontend, backend information to it. According to
 * "update_json", decide whether to update json config file.
 */
static int libxl__device_usbctrl_add_xenstore(libxl__gc *gc, uint32_t domid,
                                              libxl_device_usbctrl *usbctrl,
                                              bool update_json)
{
    libxl__device *device;
    flexarray_t *front = NULL;
    flexarray_t *back;
    xs_transaction_t t = XBT_NULL;
    int i, rc;
    libxl_domain_config d_config;
    libxl_device_usbctrl usbctrl_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_usbctrl_init(&usbctrl_saved);
    libxl_device_usbctrl_copy(CTX, &usbctrl_saved, usbctrl);

    GCNEW(device);
    rc = libxl__device_from_usbctrl(gc, domid, usbctrl, device);
    if (rc) goto out;

    back = flexarray_make(gc, 12, 1);

    if (device->backend_kind != LIBXL__DEVICE_KIND_NONE) {
        front = flexarray_make(gc, 4, 1);

        flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
        flexarray_append_pair(back, "online", "1");
        flexarray_append_pair(back, "state",
                              GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append_pair(front, "backend-id",
                              GCSPRINTF("%d", usbctrl->backend_domid));
        flexarray_append_pair(front, "state",
                              GCSPRINTF("%d", XenbusStateInitialising));
    }

    flexarray_append_pair(back, "type",
                          (char *)libxl_usbctrl_type_to_string(usbctrl->type));
    flexarray_append_pair(back, "usb-ver", GCSPRINTF("%d", usbctrl->version));
    flexarray_append_pair(back, "num-ports", GCSPRINTF("%d", usbctrl->ports));
    flexarray_append_pair(back, "port", "");
    for (i = 0; i < usbctrl->ports; i++)
        flexarray_append_pair(back, GCSPRINTF("port/%d", i + 1), "");

    if (update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        DEVICE_ADD(usbctrl, usbctrls, domid, &usbctrl_saved,
                   COMPARE_USBCTRL, &d_config);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;

        if (usbctrl->type == LIBXL_USBCTRL_TYPE_QUSB) {
            if (!libxl__query_qemu_backend(gc, domid, usbctrl->backend_domid,
                                           "qusb", false)) {
                LOG(ERROR, "backend type not supported by device model");
                rc = ERROR_FAIL;
                goto out;
            }
        }
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        rc = libxl__device_exists(gc, t, device);
        if (rc < 0) goto out;
        if (rc == 1) {
            /* already exists in xenstore */
            LOG(ERROR, "device already exists in xenstore");
            rc = ERROR_DEVICE_EXISTS;
            goto out;
        }

        if (update_json) {
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

out:
    libxl__xs_transaction_abort(gc, &t);
    if (lock) libxl__unlock_domain_userdata(lock);
    libxl_device_usbctrl_dispose(&usbctrl_saved);
    libxl_domain_config_dispose(&d_config);
    return rc;
}

static const char *vusb_be_from_xs_libxl(libxl__gc *gc, const char *libxl_path)
{
    return vusb_be_from_xs_libxl_type(gc, libxl_path, LIBXL_USBCTRL_TYPE_AUTO);
}

static void libxl__device_usbctrl_del_xenstore(libxl__gc *gc, uint32_t domid,
                                               libxl_device_usbctrl *usbctrl)
{
    const char *libxl_path, *be_path;
    xs_transaction_t t = XBT_NULL;
    int rc;

    libxl_path = GCSPRINTF("%s/device/vusb/%d",
                           libxl__xs_libxl_path(gc, domid), usbctrl->devid);
    be_path = vusb_be_from_xs_libxl_type(gc, libxl_path, usbctrl->type);

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        libxl__xs_path_cleanup(gc, t, be_path);

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    return;

out:
    libxl__xs_transaction_abort(gc, &t);
}

static char *pvusb_get_device_type(libxl_usbctrl_type type)
{
    switch (type) {
    case LIBXL_USBCTRL_TYPE_PV:
        return "vusb";
    case LIBXL_USBCTRL_TYPE_QUSB:
        return "qusb";
    default:
        return NULL;
    }
}

/* Send qmp commands to create a usb controller in qemu.
 *
 * Depending on the speed (usbctrl->version) we create:
 * - piix3-usb-uhci (version=1), always 2 ports
 * - usb-ehci       (version=2), always 6 ports
 * - nec-usb-xhci   (version=3), up to 15 ports
 */
static int libxl__device_usbctrl_add_hvm(libxl__gc *gc, uint32_t domid,
                                         libxl_device_usbctrl *usbctrl)
{
    flexarray_t *qmp_args;

    qmp_args = flexarray_make(gc, 8, 1);

    switch (usbctrl->version) {
    case 1:
        flexarray_append_pair(qmp_args, "driver", "piix3-usb-uhci");
        break;
    case 2:
        flexarray_append_pair(qmp_args, "driver", "usb-ehci");
        break;
    case 3:
        flexarray_append_pair(qmp_args, "driver", "nec-usb-xhci");
        flexarray_append_pair(qmp_args, "p2", GCSPRINTF("%d", usbctrl->ports));
        flexarray_append_pair(qmp_args, "p3", GCSPRINTF("%d", usbctrl->ports));
        break;
    default:
        assert(0); /* Should not be possible. */
        break;
    }

    flexarray_append_pair(qmp_args, "id",
                          GCSPRINTF("xenusb-%d", usbctrl->devid));

    return libxl__qmp_run_command_flexarray(gc, domid, "device_add", qmp_args);
}

/* Send qmp commands to delete a usb controller in qemu.  */
static int libxl__device_usbctrl_del_hvm(libxl__gc *gc, uint32_t domid,
                                         int devid)
{
    flexarray_t *qmp_args;

    qmp_args = flexarray_make(gc, 2, 1);
    flexarray_append_pair(qmp_args, "id", GCSPRINTF("xenusb-%d", devid));

    return libxl__qmp_run_command_flexarray(gc, domid, "device_del", qmp_args);
}

/* Send qmp commands to create a usb device in qemu. */
static int libxl__device_usbdev_add_hvm(libxl__gc *gc, uint32_t domid,
                                        libxl_device_usbdev *usbdev)
{
    flexarray_t *qmp_args;

    qmp_args = flexarray_make(gc, 12, 1);
    flexarray_append_pair(qmp_args, "id",
                          GCSPRINTF("xenusb-%d-%d",
                                    usbdev->u.hostdev.hostbus,
                                    usbdev->u.hostdev.hostaddr));
    flexarray_append_pair(qmp_args, "driver", "usb-host");
    flexarray_append_pair(qmp_args, "bus",
                          GCSPRINTF("xenusb-%d.0", usbdev->ctrl));
    flexarray_append_pair(qmp_args, "port", GCSPRINTF("%d", usbdev->port));
    flexarray_append_pair(qmp_args, "hostbus",
                          GCSPRINTF("%d", usbdev->u.hostdev.hostbus));
    flexarray_append_pair(qmp_args, "hostaddr",
                          GCSPRINTF("%d", usbdev->u.hostdev.hostaddr));

    return libxl__qmp_run_command_flexarray(gc, domid, "device_add", qmp_args);
}

/* Send qmp commands to delete a usb device in qemu. */
static int libxl__device_usbdev_del_hvm(libxl__gc *gc, uint32_t domid,
                                        libxl_device_usbdev *usbdev)
{
    flexarray_t *qmp_args;

    qmp_args = flexarray_make(gc, 2, 1);
    flexarray_append_pair(qmp_args, "id",
                          GCSPRINTF("xenusb-%d-%d",
                                    usbdev->u.hostdev.hostbus,
                                    usbdev->u.hostdev.hostaddr));

    return libxl__qmp_run_command_flexarray(gc, domid, "device_del", qmp_args);
}

/* AO operation to add a usb controller.
 *
 * Generally, it does:
 * 1) fill in necessary usb controler information with default value
 * 2) write usb controller frontend/backend info to xenstore, update json
 *    config file if necessary.
 * 3) wait for device connection. PVUSB frontend and backend driver will
 *    probe xenstore paths and build connection between frontend and backend.
 *
 * Before calling this function, aodev should be properly filled:
 * aodev->ao, aodev->callback, aodev->update_json, ...
 */
static void libxl__device_usbctrl_add(libxl__egc *egc, uint32_t domid,
                                      libxl_device_usbctrl *usbctrl,
                                      libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__device *device;
    int rc;

    rc = libxl__device_usbctrl_setdefault(gc, domid, usbctrl);
    if (rc < 0) goto out;

    if (usbctrl->devid == -1) {
        usbctrl->devid = libxl__device_nextid(gc, domid, "vusb");
        if (usbctrl->devid < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_usbctrl_add_xenstore(gc, domid, usbctrl,
                                            aodev->update_json);
    if (rc) goto out;

    GCNEW(device);
    rc = libxl__device_from_usbctrl(gc, domid, usbctrl, device);
    if (rc) goto outrm;

    if (device->backend_kind == LIBXL__DEVICE_KIND_NONE) {
        rc = libxl__device_usbctrl_add_hvm(gc, domid, usbctrl);
        if (rc) goto outrm;
        goto out;
    }

    aodev->dev = device;
    aodev->action = LIBXL__DEVICE_ACTION_ADD;
    libxl__wait_device_connection(egc, aodev);
    return;

outrm:
    libxl__device_usbctrl_del_xenstore(gc, domid, usbctrl);
out:
    aodev->rc = rc;
    aodev->callback(egc, aodev);
    return;
}

LIBXL_DEFINE_DEVICE_ADD(usbctrl)
static LIBXL_DEFINE_DEVICES_ADD(usbctrl)
LIBXL_DEFINE_DEVICE_REMOVE_CUSTOM(usbctrl)

static int libxl__device_usbdev_list_for_usbctrl(libxl__gc *gc, uint32_t domid,
                                                 libxl_devid usbctrl,
                                                 libxl_device_usbdev **usbdevs,
                                                 int *num);

static int libxl__device_usbdev_remove(libxl__gc *gc, uint32_t domid,
                                       libxl_device_usbdev *usbdev);

/* AO function to remove a usb controller.
 *
 * Generally, it does:
 * 1) check if the usb controller exists or not
 * 2) remove all usb devices under controller
 * 3) remove usb controller information from xenstore
 *
 * Before calling this function, aodev should be properly filled:
 * aodev->ao, aodev->dev, aodev->callback, ...
 */
void libxl__initiate_device_usbctrl_remove(libxl__egc *egc,
                                           libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl_device_usbdev *usbdevs = NULL;
    int num_usbdev = 0;
    int i, rc;
    uint32_t domid = ao->domid;
    int usbctrl_devid = aodev->dev->devid;
    libxl_device_usbctrl usbctrl;
    libxl_usbctrlinfo usbctrlinfo;

    libxl_device_usbctrl_init(&usbctrl);
    libxl_usbctrlinfo_init(&usbctrlinfo);
    usbctrl.devid = usbctrl_devid;

    rc = libxl_device_usbctrl_getinfo(CTX, domid, &usbctrl, &usbctrlinfo);
    if (rc) goto out;

    /* Remove usb devices first */
    rc = libxl__device_usbdev_list_for_usbctrl(gc, domid, usbctrl_devid,
                                               &usbdevs, &num_usbdev);
    if (rc) goto out;

    for (i = 0; i < num_usbdev; i++) {
        rc = libxl__device_usbdev_remove(gc, domid, &usbdevs[i]);
        if (rc) {
            LOG(ERROR, "libxl__device_usbdev_remove failed: controller %d, "
                "port %d", usbdevs[i].ctrl, usbdevs[i].port);
            goto out;
        }
    }

    if (usbctrlinfo.type == LIBXL_USBCTRL_TYPE_DEVICEMODEL) {
        rc = libxl__device_usbctrl_del_hvm(gc, domid, usbctrl_devid);
        if (!rc)
            libxl__device_usbctrl_del_xenstore(gc, domid, &usbctrl);
        goto out;
    }

    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);

    /* Remove usbctrl */
    libxl__initiate_device_generic_remove(egc, aodev);
    return;

out:
    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);
    aodev->rc = rc;
    aodev->callback(egc, aodev);
    return;
}

libxl_device_usbctrl *
libxl_device_usbctrl_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);
    libxl_device_usbctrl *usbctrls = NULL;
    char *libxl_vusbs_path = NULL;
    char **entry = NULL;
    unsigned int nentries = 0;

    *num = 0;

    libxl_vusbs_path = GCSPRINTF("%s/device/vusb",
                     libxl__xs_libxl_path(gc, domid));
    entry = libxl__xs_directory(gc, XBT_NULL, libxl_vusbs_path, &nentries);

    if (entry && nentries) {
        usbctrls = libxl__zalloc(NOGC, sizeof(*usbctrls) * nentries);
        libxl_device_usbctrl *usbctrl;
        libxl_device_usbctrl *end = usbctrls + nentries;
        for (usbctrl = usbctrls;
             usbctrl < end;
             usbctrl++, entry++, (*num)++) {
            const char *tmp, *be_path, *libxl_path;
            int ret;

            libxl_device_usbctrl_init(usbctrl);
            usbctrl->devid = atoi(*entry);

#define READ_SUBPATH(path, subpath) ({                                  \
        ret = libxl__xs_read_checked(gc, XBT_NULL,                      \
                                     GCSPRINTF("%s/" subpath, path),    \
                                     &tmp);                             \
        if (ret) goto out;                                              \
        (char *)tmp;                                                    \
    })

#define READ_SUBPATH_INT(path, subpath) ({                              \
        ret = libxl__xs_read_checked(gc, XBT_NULL,                      \
                                     GCSPRINTF("%s/" subpath, path),    \
                                     &tmp);                             \
        if (ret) goto out;                                              \
        tmp ? atoi(tmp) : -1;                                           \
    })

            libxl_path = GCSPRINTF("%s/%s", libxl_vusbs_path, *entry);
            libxl_usbctrl_type_from_string(READ_SUBPATH(libxl_path, "type"),
                                           &usbctrl->type);
            if (usbctrl->type == LIBXL_USBCTRL_TYPE_DEVICEMODEL) {
                be_path = libxl_path;
                ret = libxl__get_domid(gc, &usbctrl->backend_domid);
            } else {
                be_path = READ_SUBPATH(libxl_path, "backend");
                if (!be_path) goto out;
                ret = libxl__backendpath_parse_domid(gc, be_path,
                                                     &usbctrl->backend_domid);
            }
            if (ret) goto out;
            usbctrl->version = READ_SUBPATH_INT(be_path, "usb-ver");
            usbctrl->ports = READ_SUBPATH_INT(be_path, "num-ports");

#undef READ_SUBPATH
#undef READ_SUBPATH_INT
       }
    }

    GC_FREE;
    return usbctrls;

out:
    LOG(ERROR, "Unable to list USB Controllers");
    libxl_device_usbctrl_list_free(usbctrls, *num);
    GC_FREE;
    *num = 0;
    return NULL;
}

int libxl_device_usbctrl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_usbctrl *usbctrl,
                                 libxl_usbctrlinfo *usbctrlinfo)
{
    GC_INIT(ctx);
    const char *dompath, *fe_path, *be_path, *tmp;
    const char *libxl_dom_path, *libxl_path;
    int rc;

    usbctrlinfo->devid = usbctrl->devid;

#define READ_SUBPATH(path, subpath) ({                                  \
        rc = libxl__xs_read_checked(gc, XBT_NULL,                       \
                                    GCSPRINTF("%s/" subpath, path),     \
                                    &tmp);                              \
        if (rc) goto out;                                               \
        (char *)tmp;                                                    \
    })

#define READ_SUBPATH_INT(path, subpath) ({                              \
        rc = libxl__xs_read_checked(gc, XBT_NULL,                       \
                                    GCSPRINTF("%s/" subpath, path),     \
                                    &tmp);                              \
        if (rc) goto out;                                               \
        tmp ? atoi(tmp) : -1;                                           \
    })

    libxl_dom_path = libxl__xs_libxl_path(gc, domid);
    libxl_path = GCSPRINTF("%s/device/vusb/%d", libxl_dom_path, usbctrl->devid);
    libxl_usbctrl_type_from_string(READ_SUBPATH(libxl_path, "type"),
                                   &usbctrlinfo->type);

    if (usbctrlinfo->type != LIBXL_USBCTRL_TYPE_DEVICEMODEL) {
        dompath = libxl__xs_get_dompath(gc, domid);
        fe_path = GCSPRINTF("%s/device/vusb/%d", dompath, usbctrl->devid);
        be_path = READ_SUBPATH(libxl_path, "backend");
        usbctrlinfo->backend = libxl__strdup(NOGC, be_path);
        rc = libxl__backendpath_parse_domid(gc, be_path,
                                            &usbctrl->backend_domid);
        if (rc) goto out;
        usbctrlinfo->state = READ_SUBPATH_INT(fe_path, "state");
        usbctrlinfo->evtch = READ_SUBPATH_INT(fe_path, "event-channel");
        usbctrlinfo->ref_urb = READ_SUBPATH_INT(fe_path, "urb-ring-ref");
        usbctrlinfo->ref_conn = READ_SUBPATH_INT(fe_path, "urb-ring-ref");
        usbctrlinfo->frontend = libxl__strdup(NOGC, fe_path);
        usbctrlinfo->frontend_id = domid;
        usbctrlinfo->ports = READ_SUBPATH_INT(be_path, "num-ports");
        usbctrlinfo->version = READ_SUBPATH_INT(be_path, "usb-ver");
    } else {
        usbctrlinfo->ports = READ_SUBPATH_INT(libxl_path, "num-ports");
        usbctrlinfo->version = READ_SUBPATH_INT(libxl_path, "usb-ver");
        rc = libxl__get_domid(gc, &usbctrl->backend_domid);
        if (rc) goto out;
    }

#undef READ_SUBPATH
#undef READ_SUBPATH_INT

    rc = 0;

out:
    GC_FREE;
    return rc;
}

int libxl_devid_to_device_usbctrl(libxl_ctx *ctx,
                                  uint32_t domid,
                                  int devid,
                                  libxl_device_usbctrl *usbctrl)
{
    libxl_device_usbctrl *usbctrls;
    int nb = 0;
    int i, rc;

    usbctrls = libxl_device_usbctrl_list(ctx, domid, &nb);
    if (!usbctrls) return ERROR_FAIL;

    rc = ERROR_FAIL;
    for (i = 0; i < nb; i++) {
        if (devid == usbctrls[i].devid) {
            libxl_device_usbctrl_copy(ctx, usbctrl, &usbctrls[i]);
            rc = 0;
            break;
        }
    }

    libxl_device_usbctrl_list_free(usbctrls, nb);
    return rc;
}

static char *usbdev_busaddr_to_busid(libxl__gc *gc, int bus, int addr)
{
    DIR *dir;
    char *busid = NULL;
    struct dirent *de;

    /* invalid hostbus or hostaddr */
    if (bus < 1 || addr < 1)
        return NULL;

    dir = opendir(SYSFS_USB_DEV);
    if (!dir) {
        LOGE(ERROR, "opendir failed: '%s'", SYSFS_USB_DEV);
        return NULL;
    }

    for (;;) {
        char *filename;
        void *buf;
        int busnum = -1;
        int devnum = -1;

        errno = 0;
        de = readdir(dir);
        if (!de && errno) {
            LOGE(ERROR, "failed to readdir %s", SYSFS_USB_DEV);
            break;
        }
        if (!de)
            break;

        if (!strcmp(de->d_name, ".") ||
            !strcmp(de->d_name, ".."))
            continue;

        filename = GCSPRINTF(SYSFS_USB_DEV "/%s/devnum", de->d_name);
        if (!libxl__read_sysfs_file_contents(gc, filename, &buf, NULL))
            devnum = atoi(buf);

        filename = GCSPRINTF(SYSFS_USB_DEV "/%s/busnum", de->d_name);
        if (!libxl__read_sysfs_file_contents(gc, filename, &buf, NULL))
            busnum = atoi(buf);

        if (bus == busnum && addr == devnum) {
            busid = libxl__strdup(gc, de->d_name);
            break;
        }
    }

    closedir(dir);
    return busid;
}

static int usbdev_busaddr_from_busid(libxl__gc *gc, const char *busid,
                                     uint8_t *bus, uint8_t *addr)
{
    char *filename;
    void *buf;

    filename = GCSPRINTF(SYSFS_USB_DEV "/%s/busnum", busid);
    if (!libxl__read_sysfs_file_contents(gc, filename, &buf, NULL))
        *bus = atoi(buf);
    else
        return ERROR_FAIL;

    filename = GCSPRINTF(SYSFS_USB_DEV "/%s/devnum", busid);
    if (!libxl__read_sysfs_file_contents(gc, filename, &buf, NULL))
        *addr = atoi(buf);
    else
        return ERROR_FAIL;

    return 0;
}

static int get_assigned_devices(libxl__gc *gc,
                                libxl_device_usbdev **list, int *num)
{
    char **domlist;
    unsigned int ndom = 0;
    int i, j, k;
    int rc;

    *list = NULL;
    *num = 0;

    domlist = libxl__xs_directory(gc, XBT_NULL, "/local/domain", &ndom);
    for (i = 0; i < ndom; i++) {
        char *libxl_vusbs_path;
        char **usbctrls;
        unsigned int nc = 0;
        uint32_t domid = atoi(domlist[i]);

        libxl_vusbs_path = GCSPRINTF("%s/device/vusb",
                                     libxl__xs_libxl_path(gc, domid));
        usbctrls = libxl__xs_directory(gc, XBT_NULL,
                                       libxl_vusbs_path, &nc);

        for (j = 0; j < nc; j++) {
            libxl_device_usbdev *tmp = NULL;
            int nd = 0;

            rc = libxl__device_usbdev_list_for_usbctrl(gc, domid,
                                                       atoi(usbctrls[j]),
                                                       &tmp, &nd);
            if (rc) goto out;

            if (!nd) continue;

            GCREALLOC_ARRAY(*list, *num + nd);
            for (k = 0; k < nd; k++) {
                libxl_device_usbdev_copy(CTX, *list + *num, tmp + k);
                (*num)++;
            }
        }
    }

    return 0;

out:
    LOG(ERROR, "fail to get assigned devices");
    return rc;
}

static bool is_usbdev_in_array(libxl_device_usbdev *usbdevs, int num,
                               libxl_device_usbdev *usbdev)
{
    int i;

    for (i = 0; i < num; i++) {
        if (usbdevs[i].u.hostdev.hostbus == usbdev->u.hostdev.hostbus &&
            usbdevs[i].u.hostdev.hostaddr == usbdev->u.hostdev.hostaddr)
            return true;
    }

    return false;
}

/* check if USB device type is assignable */
static bool is_usbdev_assignable(libxl__gc *gc, libxl_device_usbdev *usbdev)
{
    int classcode;
    char *filename;
    void *buf = NULL;
    char *busid = NULL;

    busid = usbdev_busaddr_to_busid(gc, usbdev->u.hostdev.hostbus,
                                    usbdev->u.hostdev.hostaddr);
    if (!busid) return false;

    filename = GCSPRINTF(SYSFS_USB_DEV "/%s/bDeviceClass", busid);
    if (libxl__read_sysfs_file_contents(gc, filename, &buf, NULL))
        return false;

    classcode = atoi(buf);
    return classcode != USBHUB_CLASS_CODE;
}

/* get usb devices under certain usb controller */
static int
libxl__device_usbdev_list_for_usbctrl(libxl__gc *gc,
                                      uint32_t domid,
                                      libxl_devid usbctrl,
                                      libxl_device_usbdev **usbdevs,
                                      int *num)
{
    const char *libxl_path, *be_path, *num_devs;
    int n, i, rc;

    *usbdevs = NULL;
    *num = 0;

    libxl_path = GCSPRINTF("%s/device/vusb/%d",
                           libxl__xs_libxl_path(gc, domid), usbctrl);

    be_path = vusb_be_from_xs_libxl(gc, libxl_path);
    if (!be_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/num-ports", be_path),
                                &num_devs);
    if (rc) goto out;

    n = num_devs ? atoi(num_devs) : 0;

    for (i = 0; i < n; i++) {
        const char *busid;
        libxl_device_usbdev *usbdev;

        rc = libxl__xs_read_checked(gc, XBT_NULL,
                                    GCSPRINTF("%s/port/%d", be_path, i + 1),
                                    &busid);
        if (rc) goto out;

        if (busid && strcmp(busid, "")) {
            GCREALLOC_ARRAY(*usbdevs, *num + 1);
            usbdev = *usbdevs + *num;
            (*num)++;
            libxl_device_usbdev_init(usbdev);
            usbdev->ctrl = usbctrl;
            usbdev->port = i + 1;
            usbdev->type = LIBXL_USBDEV_TYPE_HOSTDEV;
            rc = usbdev_busaddr_from_busid(gc, busid,
                                           &usbdev->u.hostdev.hostbus,
                                           &usbdev->u.hostdev.hostaddr);
            if (rc) goto out;
        }
    }

    rc = 0;

out:
    return rc;
}

/* get all usb devices of the domain */
libxl_device_usbdev *
libxl_device_usbdev_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);
    libxl_device_usbdev *usbdevs = NULL;
    const char *libxl_vusbs_path;
    char **usbctrls;
    unsigned int nc = 0;
    int i, j;

    *num = 0;

    libxl_vusbs_path = GCSPRINTF("%s/device/vusb",
                                 libxl__xs_libxl_path(gc, domid));
    usbctrls = libxl__xs_directory(gc, XBT_NULL, libxl_vusbs_path, &nc);

    for (i = 0; i < nc; i++) {
        int rc, nd = 0;
        libxl_device_usbdev *tmp = NULL;

        rc = libxl__device_usbdev_list_for_usbctrl(gc, domid,
                                                  atoi(usbctrls[i]),
                                                  &tmp, &nd);
        if (rc || !nd) continue;

        usbdevs = libxl__realloc(NOGC, usbdevs,
                                 sizeof(*usbdevs) * (*num + nd));
        for (j = 0; j < nd; j++) {
            libxl_device_usbdev_copy(ctx, usbdevs + *num, tmp + j);
            (*num)++;
        }
    }

    GC_FREE;
    return usbdevs;
}

static char *vusb_get_port_path(libxl__gc *gc, uint32_t domid,
                                libxl_usbctrl_type type, int ctrl, int port)
{
    char *path;

    if (type == LIBXL_USBCTRL_TYPE_DEVICEMODEL)
        path = GCSPRINTF("%s/device/vusb", libxl__xs_libxl_path(gc, domid));
    else
        path = GCSPRINTF("%s/backend/%s/%d",
                         libxl__xs_get_dompath(gc, LIBXL_TOOLSTACK_DOMID),
                         pvusb_get_device_type(type), domid);

    return GCSPRINTF("%s/%d/port/%d", path, ctrl, port);
}

/* find first unused controller:port and give that to usb device */
static int
libxl__device_usbdev_set_default_usbctrl(libxl__gc *gc, uint32_t domid,
                                         libxl_device_usbdev *usbdev)
{
    libxl_device_usbctrl *usbctrls = NULL;
    int numctrl = 0;
    int i, j, rc;

    usbctrls = libxl_device_usbctrl_list(CTX, domid, &numctrl);
    if (!numctrl || !usbctrls) {
        rc = ERROR_FAIL;
        goto out;
    }

    for (i = 0; i < numctrl; i++) {
        for (j = 0; j < usbctrls[i].ports; j++) {
            const char *path, *tmp;

            path = vusb_get_port_path(gc, domid, usbctrls[i].type,
                                      usbctrls[i].devid, j + 1);
            rc = libxl__xs_read_checked(gc, XBT_NULL, path, &tmp);
            if (rc) goto out;

            if (tmp && !strcmp(tmp, "")) {
                usbdev->ctrl = usbctrls[i].devid;
                usbdev->port = j + 1;
                rc = 0;
                goto out;
            }
        }
    }

    /* no available controller:port */
    rc = ERROR_FAIL;

out:
    libxl_device_usbctrl_list_free(usbctrls, numctrl);
    return rc;
}

/* Fill in usb information with default value.
 *
 * Generally, it does:
 * 1) if "controller" is not specified:
 *    - if "port" is not specified, try to find an available controller:port,
 *      if found, use that; otherwise, create a new controller, use this
 *      controller and its first port
 *    - if "port" is specified, report error.
 * 2) if "controller" is specified, but port is not specified:
 *    try to find an available port under this controller, if found, use
 *    that, otherwise, report error.
 * 3) if both "controller" and "port" are specified:
 *    check the controller:port is available, if not, report error.
 */
static int libxl__device_usbdev_setdefault(libxl__gc *gc,
                                           uint32_t domid,
                                           libxl_device_usbdev *usbdev,
                                           bool update_json)
{
    int rc;

    if (!usbdev->type)
        usbdev->type = LIBXL_USBDEV_TYPE_HOSTDEV;

    if (usbdev->ctrl == -1) {
        if (usbdev->port) {
            LOG(ERROR, "USB controller must be specified if you specify port");
            return ERROR_INVAL;
        }

        rc = libxl__device_usbdev_set_default_usbctrl(gc, domid, usbdev);
        /* If no existing controller to host this usb device, add a new one */
        if (rc) {
            libxl_device_usbctrl *usbctrl;

            GCNEW(usbctrl);
            libxl_device_usbctrl_init(usbctrl);
            rc = libxl__device_usbctrl_setdefault(gc, domid, usbctrl);
            if (rc < 0) goto out;

            if (usbctrl->devid == -1) {
                usbctrl->devid = libxl__device_nextid(gc, domid, "vusb");
                if (usbctrl->devid < 0) {
                    rc = ERROR_FAIL;
                    goto out;
                }
            }

            rc = libxl__device_usbctrl_add_xenstore(gc, domid, usbctrl,
                                                    update_json);
            if (rc) goto out;

            usbdev->ctrl = usbctrl->devid;
            usbdev->port = 1;
        }
    } else {
        /* A controller was specified; look it up */
        const char *libxl_path, *be_path, *tmp;

        libxl_path = GCSPRINTF("%s/device/vusb/%d",
                            libxl__xs_libxl_path(gc, domid),
                            usbdev->ctrl);

        be_path = vusb_be_from_xs_libxl(gc, libxl_path);
        if (!be_path) {
            rc = ERROR_FAIL;
            goto out;
        }

        if (usbdev->port) {
            /* A specific port was requested; see if it's available */
            rc = libxl__xs_read_checked(gc, XBT_NULL,
                                        GCSPRINTF("%s/port/%d",
                                                  be_path, usbdev->port),
                                        &tmp);
            if (rc) goto out;

            if (tmp && strcmp(tmp, "")) {
                LOG(ERROR, "The controller port isn't available");
                rc = ERROR_FAIL;
                goto out;
            }
        } else {
            /* No port was requested. Choose free port. */
            int i, ports;

            rc = libxl__xs_read_checked(gc, XBT_NULL,
                                        GCSPRINTF("%s/num-ports", be_path), &tmp);
            if (rc) goto out;

            ports = tmp ? atoi(tmp) : 0;

            for (i = 0; i < ports; i++) {
                rc = libxl__xs_read_checked(gc, XBT_NULL,
                                            GCSPRINTF("%s/port/%d", be_path, i + 1),
                                            &tmp);
                if (rc) goto out;

                if (tmp && !strcmp(tmp, "")) {
                    usbdev->port = i + 1;
                    break;
                }
            }

            if (!usbdev->port) {
                LOG(ERROR, "No available port under specified controller");
                rc = ERROR_FAIL;
                goto out;
            }
        }
    }

    rc = 0;

out:
    return rc;
}

/* Add usb information to xenstore
 *
 * Adding a usb device won't create new 'qusb'/'vusb' device, but only write
 * the device busid to the controller:port in xenstore.
 */
static int libxl__device_usbdev_add_xenstore(libxl__gc *gc, uint32_t domid,
                                             libxl_device_usbdev *usbdev,
                                             libxl_usbctrl_type type,
                                             bool update_json)
{
    char *be_path, *busid;
    int rc;
    xs_transaction_t t = XBT_NULL;
    libxl_domain_config d_config;
    libxl_device_usbdev usbdev_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_usbdev_init(&usbdev_saved);
    libxl_device_usbdev_copy(CTX, &usbdev_saved, usbdev);

    busid = usbdev_busaddr_to_busid(gc, usbdev->u.hostdev.hostbus,
                                    usbdev->u.hostdev.hostaddr);
    if (!busid) {
        LOG(DEBUG, "Fail to get busid of usb device");
        rc = ERROR_FAIL;
        goto out;
    }

    if (update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        DEVICE_ADD(usbdev, usbdevs, domid, &usbdev_saved,
                   COMPARE_USB, &d_config);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        if (update_json) {
            rc = libxl__set_domain_configuration(gc, domid, &d_config);
            if (rc) goto out;
        }

        be_path = vusb_get_port_path(gc, domid, type, usbdev->ctrl,
                                     usbdev->port);

        LOG(DEBUG, "Adding usb device %s to xenstore: controller %d, port %d",
            busid, usbdev->ctrl, usbdev->port);

        rc = libxl__xs_write_checked(gc, t, be_path, busid);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    rc = 0;

out:
    if (lock) libxl__unlock_domain_userdata(lock);
    libxl_device_usbdev_dispose(&usbdev_saved);
    libxl_domain_config_dispose(&d_config);
    return rc;
}

static int libxl__device_usbdev_remove_xenstore(libxl__gc *gc, uint32_t domid,
                                                libxl_device_usbdev *usbdev,
                                                libxl_usbctrl_type type)
{
    char *be_path;

    be_path = vusb_get_port_path(gc, domid, type, usbdev->ctrl, usbdev->port);

    LOG(DEBUG, "Removing usb device from xenstore: controller %d, port %d",
        usbdev->ctrl, usbdev->port);

    return libxl__xs_write_checked(gc, XBT_NULL, be_path, "");
}

static char *usbdev_busid_from_ctrlport(libxl__gc *gc, uint32_t domid,
                                        libxl_device_usbdev *usbdev,
                                        libxl_usbctrl_type type)
{
    return libxl__xs_read(gc, XBT_NULL,
                          vusb_get_port_path(gc, domid, type, usbdev->ctrl,
                                             usbdev->port));
}

/* get original driver path of usb interface, stored in @drvpath */
static int usbintf_get_drvpath(libxl__gc *gc, const char *intf, char **drvpath)
{
    char *spath, *dp = NULL;

    spath = GCSPRINTF(SYSFS_USB_DEV "/%s/driver", intf);

    /* Find the canonical path to the driver. */
    dp = libxl__zalloc(gc, PATH_MAX);
    dp = realpath(spath, dp);
    if (!dp && errno != ENOENT) {
        LOGE(ERROR, "get realpath failed: '%s'", spath);
        return ERROR_FAIL;
    }

    *drvpath = dp;

    return 0;
}

static int unbind_usbintf(libxl__gc *gc, const char *intf)
{
    char *path;
    int fd = -1;
    int rc;

    path = GCSPRINTF(SYSFS_USB_DEV "/%s/driver/unbind", intf);

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "open file failed: '%s'", path);
        rc = ERROR_FAIL;
        goto out;
    }

    if (libxl_write_exactly(CTX, fd, intf, strlen(intf), path, intf)) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    if (fd >= 0) close(fd);
    return rc;
}

static int bind_usbintf(libxl__gc *gc, const char *intf, const char *drvpath)
{
    char *bind_path, *intf_path;
    struct stat st;
    int fd = -1;
    int rc, r;

    intf_path = GCSPRINTF("%s/%s", drvpath, intf);

    /* check through lstat, if intf already exists under drvpath,
     * it's already bound, return directly; if it doesn't exist,
     * continue to do bind work; otherwise, return error.
     */
    r = lstat(intf_path, &st);
    if (r == 0)
        return 0;
    if (r < 0 && errno != ENOENT)
        return ERROR_FAIL;

    bind_path = GCSPRINTF("%s/bind", drvpath);

    fd = open(bind_path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "open file failed: '%s'", bind_path);
        rc = ERROR_FAIL;
        goto out;
    }

    if (libxl_write_exactly(CTX, fd, intf, strlen(intf), bind_path, intf)) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    if (fd >= 0) close(fd);
    return rc;
}

/* Is usb interface bound to usbback? */
static int usbintf_is_assigned(libxl__gc *gc, char *intf)
{
    char *spath;
    int r;
    struct stat st;

    spath = GCSPRINTF(SYSFS_USBBACK_DRIVER "/%s", intf);
    r = lstat(spath, &st);

    if (r == 0)
        return 1;
    if (r < 0 && errno == ENOENT)
        return 0;
    LOGE(ERROR, "Accessing %s", spath);
    return -1;
}

static int usbdev_get_all_interfaces(libxl__gc *gc, const char *busid,
                                     char ***intfs, int *num)
{
    DIR *dir;
    char *buf;
    struct dirent *de;
    int rc;

    *intfs = NULL;
    *num = 0;

    buf = GCSPRINTF("%s:", busid);

    dir = opendir(SYSFS_USB_DEV);
    if (!dir) {
        LOGE(ERROR, "opendir failed: '%s'", SYSFS_USB_DEV);
        return ERROR_FAIL;
    }

    for (;;) {
        errno = 0;
        de = readdir(dir);

        if (!de && errno) {
            LOGE(ERROR, "failed to readdir %s", SYSFS_USB_DEV);
            rc = ERROR_FAIL;
            goto out;
        }
        if (!de)
            break;

        if (!strcmp(de->d_name, ".") ||
            !strcmp(de->d_name, ".."))
            continue;

        if (!strncmp(de->d_name, buf, strlen(buf))) {
            GCREALLOC_ARRAY(*intfs, *num + 1);
            (*intfs)[*num] = libxl__strdup(gc, de->d_name);
            (*num)++;
        }
    }

    rc = 0;

out:
    closedir(dir);
    return rc;
}

/* Encode usb interface so that it could be written to xenstore as a key.
 *
 * Since xenstore key cannot include '.' or ':', we'll change '.' to '_',
 * change ':' to '@'. For example, 3-1:2.1 will be encoded to 3-1@2_1.
 * This will be used to save original driver of USB device to xenstore.
 */
static char *usb_interface_xenstore_encode(libxl__gc *gc, const char *busid)
{
    char *str = libxl__strdup(gc, busid);
    int i, len = strlen(str);

    for (i = 0; i < len; i++) {
        if (str[i] == '.') str[i] = '_';
        if (str[i] == ':') str[i] = '@';
    }
    return str;
}

/* Unbind USB device from "usbback" driver.
 *
 * If there are many interfaces under USB device, check each interface,
 * unbind from "usbback" driver.
 */
static int usbback_dev_unassign(libxl__gc *gc, const char *busid)
{
    char **intfs = NULL;
    int i, num = 0;
    int rc;

    rc = usbdev_get_all_interfaces(gc, busid, &intfs, &num);
    if (rc) goto out;

    for (i = 0; i < num; i++) {
        char *intf = intfs[i];

        /* check if the USB interface is already bound to "usbback" */
        if (usbintf_is_assigned(gc, intf) > 0) {
            /* unbind interface from usbback driver */
            rc = unbind_usbintf(gc, intf);
            if (rc) {
                LOGE(ERROR, "Couldn't unbind %s from usbback", intf);
                goto out;
            }
        }
    }

    rc = 0;

out:
    return rc;
}

/* rebind USB device to original driver.
 *
 * If there are many interfaces under USB device, for reach interface,
 * read driver_path from xenstore (if there is) and rebind to its
 * original driver, then remove driver_path information from xenstore.
 */
static int usbdev_rebind(libxl__gc *gc, const char *busid)
{
    char **intfs = NULL;
    char *usbdev_encode = NULL;
    char *path = NULL;
    int i, num = 0;
    int rc;

    rc = usbdev_get_all_interfaces(gc, busid, &intfs, &num);
    if (rc) goto out;

    usbdev_encode = usb_interface_xenstore_encode(gc, busid);

    for (i = 0; i < num; i++) {
        char *intf = intfs[i];
        char *usbintf_encode = NULL;
        const char *drvpath;

        /* rebind USB interface to its originial driver */
        usbintf_encode = usb_interface_xenstore_encode(gc, intf);
        path = GCSPRINTF(USBBACK_INFO_PATH "/%s/%s/driver_path",
                         usbdev_encode, usbintf_encode);
        rc = libxl__xs_read_checked(gc, XBT_NULL, path, &drvpath);
        if (rc) goto out;

        if (drvpath) {
            rc = bind_usbintf(gc, intf, drvpath);
            if (rc) {
                LOGE(ERROR, "Couldn't rebind %s to %s", intf, drvpath);
                goto out;
            }
        }
    }

out:
    path = GCSPRINTF(USBBACK_INFO_PATH "/%s", usbdev_encode);
    libxl__xs_rm_checked(gc, XBT_NULL, path);
    return rc;
}


/* Bind USB device to "usbback" driver.
 *
 * If there are many interfaces under USB device, check each interface,
 * unbind from original driver and bind to "usbback" driver.
 */
static int usbback_dev_assign(libxl__gc *gc, const char *busid)
{
    char **intfs = NULL;
    int num = 0, i;
    int rc;
    char *usbdev_encode = NULL;

    rc = usbdev_get_all_interfaces(gc, busid, &intfs, &num);
    if (rc) return rc;

    usbdev_encode = usb_interface_xenstore_encode(gc, busid);

    for (i = 0; i < num; i++) {
        char *intf = intfs[i];
        char *drvpath = NULL;

        /* already assigned to usbback */
        if (usbintf_is_assigned(gc, intf) > 0)
            continue;

        rc = usbintf_get_drvpath(gc, intf, &drvpath);
        if (rc) goto out;

        if (drvpath) {
            /* write driver path to xenstore for later rebinding */
            char *usbintf_encode = NULL;
            char *path;

            usbintf_encode = usb_interface_xenstore_encode(gc, intf);
            path = GCSPRINTF(USBBACK_INFO_PATH "/%s/%s/driver_path",
                             usbdev_encode, usbintf_encode);
            rc = libxl__xs_write_checked(gc, XBT_NULL, path, drvpath);
            if (rc) goto out;

            /* unbind interface from original driver */
            rc = unbind_usbintf(gc, intf);
            if (rc) goto out;
        }

        /* bind interface to usbback */
        rc = bind_usbintf(gc, intf, SYSFS_USBBACK_DRIVER);
        if (rc) {
            LOG(ERROR, "Couldn't bind %s to %s", intf, SYSFS_USBBACK_DRIVER);
            goto out;
        }
    }

    return 0;

out:
    /* some interfaces might be bound to usbback, unbind it and
     * rebind it to its original driver
     */
    usbback_dev_unassign(gc, busid);
    usbdev_rebind(gc, busid);
    return rc;
}

static int do_usbdev_add(libxl__gc *gc, uint32_t domid,
                         libxl_device_usbdev *usbdev,
                         bool update_json)
{
    int rc;
    char *busid;
    libxl_device_usbctrl usbctrl;
    libxl_usbctrlinfo usbctrlinfo;

    libxl_device_usbctrl_init(&usbctrl);
    libxl_usbctrlinfo_init(&usbctrlinfo);
    usbctrl.devid = usbdev->ctrl;

    rc = libxl_device_usbctrl_getinfo(CTX, domid, &usbctrl, &usbctrlinfo);
    if (rc) goto out;

    switch (usbctrlinfo.type) {
    case LIBXL_USBCTRL_TYPE_PV:
        busid = usbdev_busaddr_to_busid(gc, usbdev->u.hostdev.hostbus,
                                        usbdev->u.hostdev.hostaddr);
        if (!busid) {
            rc = ERROR_FAIL;
            goto out;
        }

        rc = libxl__device_usbdev_add_xenstore(gc, domid, usbdev,
                                               LIBXL_USBCTRL_TYPE_PV,
                                               update_json);
        if (rc) goto out;

        rc = usbback_dev_assign(gc, busid);
        if (rc) {
            libxl__device_usbdev_remove_xenstore(gc, domid, usbdev,
                                                 LIBXL_USBCTRL_TYPE_PV);
            goto out;
        }
        break;
    case LIBXL_USBCTRL_TYPE_QUSB:
        rc = libxl__device_usbdev_add_xenstore(gc, domid, usbdev,
                                               LIBXL_USBCTRL_TYPE_QUSB,
                                               update_json);
        if (rc) goto out;

        break;
    case LIBXL_USBCTRL_TYPE_DEVICEMODEL:
        rc = libxl__device_usbdev_add_xenstore(gc, domid, usbdev,
                                               LIBXL_USBCTRL_TYPE_DEVICEMODEL,
                                               update_json);
        if (rc) goto out;

        rc = libxl__device_usbdev_add_hvm(gc, domid, usbdev);
        if (rc) {
            libxl__device_usbdev_remove_xenstore(gc, domid, usbdev,
                                             LIBXL_USBCTRL_TYPE_DEVICEMODEL);
            goto out;
        }
        break;
    default:
        LOG(ERROR, "Unsupported usb controller type");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);
    return rc;
}

/* AO operation to add a usb device.
 *
 * Generally, it does:
 * 1) check if the usb device type is assignable
 * 2) check if the usb device is already assigned to a domain
 * 3) add 'busid' of the usb device to xenstore contoller/port/.
 *    (PVUSB driver watches the xenstore changes and will detect that.)
 * 4) unbind usb device from original driver and bind to usbback.
 *    If usb device has many interfaces, then:
 *    - unbind each interface from its original driver and bind to usbback.
 *    - store the original driver to xenstore for later rebinding when
 *      detaching the device.
 *
 * Before calling this function, aodev should be properly filled:
 * aodev->ao, aodev->callback, aodev->update_json, ...
 */
static void libxl__device_usbdev_add(libxl__egc *egc, uint32_t domid,
                                     libxl_device_usbdev *usbdev,
                                     libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    int rc;
    libxl_device_usbdev *assigned;
    int num_assigned;
    libxl_device_usbctrl usbctrl;
    libxl_usbctrlinfo usbctrlinfo;

    libxl_device_usbctrl_init(&usbctrl);
    libxl_usbctrlinfo_init(&usbctrlinfo);

    /* Currently only support adding USB device from Dom0 backend.
     * So, if USB controller is specified, check its backend domain,
     * if it's not Dom0, report error.
     */
    if (usbdev->ctrl != -1) {
        usbctrl.devid = usbdev->ctrl;
        rc = libxl_device_usbctrl_getinfo(CTX, domid, &usbctrl, &usbctrlinfo);
        if (rc) goto out;

        if (usbctrlinfo.backend_id != LIBXL_TOOLSTACK_DOMID) {
            LOG(ERROR, "Don't support adding USB device from non-Dom0 backend");
            rc = ERROR_INVAL;
            goto out;
        }
    }

    /* check usb device is assignable type */
    if (!is_usbdev_assignable(gc, usbdev)) {
        LOG(ERROR, "USB device is not assignable.");
        rc = ERROR_FAIL;
        goto out;
    }

    /* check usb device is already assigned */
    rc = get_assigned_devices(gc, &assigned, &num_assigned);
    if (rc) {
        LOG(ERROR, "cannot determine if device is assigned,"
                   " refusing to continue");
        goto out;
    }

    if (is_usbdev_in_array(assigned, num_assigned, usbdev)) {
        LOG(ERROR, "USB device already attached to a domain");
        rc = ERROR_INVAL;
        goto out;
    }

    /* fill default values, e.g, if usbdev->ctrl and usbdev->port
     * not specified, choose available controller:port and fill in. */
    rc = libxl__device_usbdev_setdefault(gc, domid, usbdev,
                                         aodev->update_json);
    if (rc) goto out;

    /* do actual adding usb device operation */
    rc = do_usbdev_add(gc, domid, usbdev, aodev->update_json);

out:
    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);
    aodev->rc = rc;
    aodev->callback(egc, aodev);
    return;
}

LIBXL_DEFINE_DEVICE_ADD(usbdev)
static LIBXL_DEFINE_DEVICES_ADD(usbdev)

static int do_usbdev_remove(libxl__gc *gc, uint32_t domid,
                            libxl_device_usbdev *usbdev)
{
    int rc;
    char *busid;
    libxl_device_usbctrl usbctrl;
    libxl_usbctrlinfo usbctrlinfo;

    libxl_device_usbctrl_init(&usbctrl);
    libxl_usbctrlinfo_init(&usbctrlinfo);
    usbctrl.devid = usbdev->ctrl;

    rc = libxl_device_usbctrl_getinfo(CTX, domid, &usbctrl, &usbctrlinfo);
    if (rc) goto out;

    switch (usbctrlinfo.type) {
    case LIBXL_USBCTRL_TYPE_PV:
        busid = usbdev_busid_from_ctrlport(gc, domid, usbdev, usbctrlinfo.type);
        if (!busid) {
            rc = ERROR_FAIL;
            goto out;
        }

        /* Things are done in order of:
         *   unbind USB device from usbback,
         *   remove USB device from xenstore,
         *   rebind USB device to original driver.
         * It is to balance simplicity with robustness in case of failure:
         * - We unbind all interfaces before rebinding any interfaces, so
         *   that we never get into a situation where some interfaces are
         *   assigned to usbback and some are assigned to the original drivers.
         * - We also unbind the interfaces before removing the pvusb xenstore
         *   nodes, so that if the unbind fails in the middle, the device still
         *   shows up in xl usb-list, and the user can re-try removing it.
         */
        rc = usbback_dev_unassign(gc, busid);
        if (rc) {
            LOG(ERROR, "Error removing device from guest."
                " Try running usbdev-detach again.");
            goto out;
        }

        rc = libxl__device_usbdev_remove_xenstore(gc, domid, usbdev,
                                                  LIBXL_USBCTRL_TYPE_PV);
        if (rc) {
            LOG(ERROR, "Error removing device from guest."
                " Try running usbdev-detach again.");
            goto out;
        }

        rc = usbdev_rebind(gc, busid);
        if (rc) {
            LOG(ERROR, "USB device removed from guest, but couldn't"
                " re-bind to domain 0. Try removing and re-inserting"
                " the USB device or reloading the driver modules.");
            goto out;
        }

        break;
    case LIBXL_USBCTRL_TYPE_QUSB:
        rc = libxl__device_usbdev_remove_xenstore(gc, domid, usbdev,
                                                  LIBXL_USBCTRL_TYPE_QUSB);
        if (rc) goto out;

        break;
    case LIBXL_USBCTRL_TYPE_DEVICEMODEL:
        rc = libxl__device_usbdev_remove_xenstore(gc, domid, usbdev,
                                              LIBXL_USBCTRL_TYPE_DEVICEMODEL);
        if (rc) goto out;

        rc = libxl__device_usbdev_del_hvm(gc, domid, usbdev);
        if (rc) {
            libxl__device_usbdev_add_xenstore(gc, domid, usbdev,
                                              LIBXL_USBCTRL_TYPE_DEVICEMODEL,
                                              false);
            goto out;
        }

        break;
    default:
        LOG(ERROR, "Unsupported usb controller type");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);
    return rc;
}

/* Operation to remove usb device.
 *
 * Generally, it does:
 * 1) check if the usb device is assigned to the domain
 * 2) remove the usb device from xenstore controller/port.
 * 3) unbind usb device from usbback and rebind to its original driver.
 *    If usb device has many interfaces, do it to each interface.
 */
static int libxl__device_usbdev_remove(libxl__gc *gc, uint32_t domid,
                                       libxl_device_usbdev *usbdev)
{
    libxl_usbctrlinfo usbctrlinfo;
    libxl_device_usbctrl usbctrl;
    int rc;

    if (usbdev->ctrl < 0 || usbdev->port < 1) {
        LOG(ERROR, "Invalid USB device");
        return ERROR_FAIL;
    }

    libxl_device_usbctrl_init(&usbctrl);
    libxl_usbctrlinfo_init(&usbctrlinfo);
    usbctrl.devid = usbdev->ctrl;

    rc = libxl_device_usbctrl_getinfo(CTX, domid, &usbctrl, &usbctrlinfo);
    if (rc) goto out;

    if (usbctrlinfo.backend_id != LIBXL_TOOLSTACK_DOMID) {
        LOG(ERROR, "Don't support removing USB device from non-Dom0 backend");
        rc = ERROR_INVAL;
        goto out;
    }

    /* do actual removing usb device operation */
    rc = do_usbdev_remove(gc, domid, usbdev);

out:
    libxl_device_usbctrl_dispose(&usbctrl);
    libxl_usbctrlinfo_dispose(&usbctrlinfo);
    return rc;
}

int libxl_device_usbdev_remove(libxl_ctx *ctx, uint32_t domid,
                               libxl_device_usbdev *usbdev,
                               const libxl_asyncop_how *ao_how)

{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_usbdev_remove(gc, domid, usbdev);

    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl_ctrlport_to_device_usbdev(libxl_ctx *ctx,
                                    uint32_t domid,
                                    int ctrl,
                                    int port,
                                    libxl_device_usbdev *usbdev)
{
    GC_INIT(ctx);
    const char *libxl_dom_path, *libxl_path, *be_path, *busid;
    int rc;

    libxl_dom_path = libxl__xs_libxl_path(gc, domid);

    libxl_path = GCSPRINTF("%s/device/vusb/%d", libxl_dom_path, ctrl);
    be_path = vusb_be_from_xs_libxl(gc, libxl_path);
    if (!be_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                           GCSPRINTF("%s/port/%d", be_path, port),
                           &busid);
    if (rc) goto out;

    if (!busid || !strcmp(busid, "")) {
        rc = ERROR_FAIL;
        goto out;
    }

    usbdev->ctrl = ctrl;
    usbdev->port = port;
    usbdev->type = LIBXL_USBDEV_TYPE_HOSTDEV;
    rc = usbdev_busaddr_from_busid(gc, busid,
                                   &usbdev->u.hostdev.hostbus,
                                   &usbdev->u.hostdev.hostaddr);

out:
    GC_FREE;
    return rc;
}

static int libxl_device_usbctrl_compare(libxl_device_usbctrl *d1,
                                        libxl_device_usbctrl *d2)
{
    return COMPARE_USBCTRL(d1, d2);
}

static int libxl_device_usbctrl_dm_needed(void *e, unsigned domid)
{
    libxl_device_usbctrl *elem = e;

    return elem->type == LIBXL_USBCTRL_TYPE_QUSB &&
           elem->backend_domid == domid;
}

static int libxl_device_usbdev_compare(libxl_device_usbdev *d1,
                                       libxl_device_usbdev *d2)
{
    return COMPARE_USB(d1, d2);
}

void libxl_device_usbctrl_list_free(libxl_device_usbctrl *list, int nr)
{
   int i;

   for (i = 0; i < nr; i++)
       libxl_device_usbctrl_dispose(&list[i]);
   free(list);
}

void libxl_device_usbdev_list_free(libxl_device_usbdev *list, int nr)
{
   int i;

   for (i = 0; i < nr; i++)
       libxl_device_usbdev_dispose(&list[i]);
   free(list);
}

DEFINE_DEVICE_TYPE_STRUCT(usbctrl,
    .dm_needed = libxl_device_usbctrl_dm_needed
);
DEFINE_DEVICE_TYPE_STRUCT(usbdev);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
