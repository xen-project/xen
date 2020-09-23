/*
 * Copyright (C) 2014 FUJITSU LIMITED
 * Author: Yang Hongyang <yanghy@cn.fujitsu.com>
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

/*----- setup() and teardown() -----*/

/* callbacks */

static void all_devices_setup_cb(libxl__egc *egc,
                                 libxl__multidev *multidev,
                                 int rc);
static void device_setup_iterate(libxl__egc *egc,
                                 libxl__ao_device *aodev);
static void devices_teardown_cb(libxl__egc *egc,
                                libxl__multidev *multidev,
                                int rc);

/* checkpoint device setup and teardown */

static libxl__checkpoint_device* checkpoint_device_init(libxl__egc *egc,
                                        libxl__checkpoint_devices_state *cds,
                                        libxl__device_kind kind,
                                        void *libxl_dev)
{
    libxl__checkpoint_device *dev = NULL;

    STATE_AO_GC(cds->ao);
    GCNEW(dev);
    dev->backend_dev = libxl_dev;
    dev->kind = kind;
    dev->cds = cds;

    return dev;
}

static void checkpoint_devices_setup(libxl__egc *egc,
                                     libxl__checkpoint_devices_state *cds);

void libxl__checkpoint_devices_setup(libxl__egc *egc,
                                     libxl__checkpoint_devices_state *cds)
{
    int i;

    STATE_AO_GC(cds->ao);

    cds->num_devices = 0;
    cds->num_nics = 0;
    cds->num_disks = 0;

    if (cds->device_kind_flags & (1 << LIBXL__DEVICE_KIND_VIF))
        cds->nics = libxl__device_list(gc, &libxl__nic_devtype, cds->domid,
                                       &cds->num_nics);

    if (cds->device_kind_flags & (1 << LIBXL__DEVICE_KIND_VBD))
        cds->disks = libxl__device_list(gc, &libxl__disk_devtype, cds->domid,
                                        &cds->num_disks);

    if (cds->num_nics == 0 && cds->num_disks == 0)
        goto out;

    GCNEW_ARRAY(cds->devs, cds->num_nics + cds->num_disks);

    for (i = 0; i < cds->num_nics; i++) {
        cds->devs[cds->num_devices++] = checkpoint_device_init(egc, cds,
                                                LIBXL__DEVICE_KIND_VIF,
                                                &cds->nics[i]);
    }

    for (i = 0; i < cds->num_disks; i++) {
        cds->devs[cds->num_devices++] = checkpoint_device_init(egc, cds,
                                                LIBXL__DEVICE_KIND_VBD,
                                                &cds->disks[i]);
    }

    checkpoint_devices_setup(egc, cds);

    return;

out:
    cds->callback(egc, cds, 0);
}

static void checkpoint_devices_setup(libxl__egc *egc,
                                     libxl__checkpoint_devices_state *cds)
{
    int i, rc;

    STATE_AO_GC(cds->ao);

    libxl__multidev_begin(ao, &cds->multidev);
    cds->multidev.callback = all_devices_setup_cb;
    for (i = 0; i < cds->num_devices; i++) {
        libxl__checkpoint_device *dev = cds->devs[i];
        dev->ops_index = -1;
        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);

        dev->aodev.rc = ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED;
        dev->aodev.callback = device_setup_iterate;
        device_setup_iterate(egc,&dev->aodev);
    }

    rc = 0;
    libxl__multidev_prepared(egc, &cds->multidev, rc);
}


static void device_setup_iterate(libxl__egc *egc, libxl__ao_device *aodev)
{
    libxl__checkpoint_device *dev = CONTAINER_OF(aodev, *dev, aodev);
    EGC_GC;

    if (aodev->rc != ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED &&
        aodev->rc != ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH)
        /* might be success or disaster */
        goto out;

    do {
        dev->ops = dev->cds->ops[++dev->ops_index];
        if (!dev->ops) {
            libxl_device_nic * nic = NULL;
            libxl_device_disk * disk = NULL;
            uint32_t domid = INVALID_DOMID;
            int devid;
            if (dev->kind == LIBXL__DEVICE_KIND_VIF) {
                nic = (libxl_device_nic *)dev->backend_dev;
                domid = nic->backend_domid;
                devid = nic->devid;
            } else if (dev->kind == LIBXL__DEVICE_KIND_VBD) {
                disk = (libxl_device_disk *)dev->backend_dev;
                domid = disk->backend_domid;
                devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);
            } else {
                LOGD(ERROR, domid, "device kind not handled by checkpoint: %s",
                     libxl__device_kind_to_string(dev->kind));
                aodev->rc = ERROR_FAIL;
                goto out;
            }
            LOGD(ERROR, domid, "device not handled by checkpoint"
                 " (device=%s:%"PRId32"/%"PRId32")",
                 libxl__device_kind_to_string(dev->kind),
                 domid, devid);
            aodev->rc = ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED;
            goto out;
        }
    } while (dev->ops->kind != dev->kind);

    /* found the next ops_index to try */
    assert(dev->aodev.callback == device_setup_iterate);
    dev->ops->setup(egc,dev);
    return;

 out:
    libxl__multidev_one_callback(egc,aodev);
}

static void all_devices_setup_cb(libxl__egc *egc,
                                 libxl__multidev *multidev,
                                 int rc)
{
    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    cds->callback(egc, cds, rc);
}

void libxl__checkpoint_devices_teardown(libxl__egc *egc,
                                   libxl__checkpoint_devices_state *cds)
{
    int i;
    libxl__checkpoint_device *dev;

    STATE_AO_GC(cds->ao);

    libxl__multidev_begin(ao, &cds->multidev);
    cds->multidev.callback = devices_teardown_cb;
    for (i = 0; i < cds->num_devices; i++) {
        dev = cds->devs[i];
        if (!dev->ops || !dev->matched)
            continue;

        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);
        dev->ops->teardown(egc,dev);
    }

    libxl__multidev_prepared(egc, &cds->multidev, 0);
}

static void devices_teardown_cb(libxl__egc *egc,
                                libxl__multidev *multidev,
                                int rc)
{
    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    /* clean nic */
    libxl__device_list_free(&libxl__nic_devtype, cds->nics, cds->num_nics);
    cds->nics = NULL;
    cds->num_nics = 0;

    /* clean disk */
    libxl__device_list_free(&libxl__disk_devtype, cds->disks, cds->num_disks);
    cds->disks = NULL;
    cds->num_disks = 0;

    cds->callback(egc, cds, rc);
}

/*----- checkpointing APIs -----*/

/* callbacks */

static void devices_checkpoint_cb(libxl__egc *egc,
                                  libxl__multidev *multidev,
                                  int rc);

/* API implementations */

#define define_checkpoint_api(api)                                      \
void libxl__checkpoint_devices_##api(libxl__egc *egc,                   \
                                libxl__checkpoint_devices_state *cds)   \
{                                                                       \
    int i;                                                              \
    libxl__checkpoint_device *dev;                                      \
                                                                        \
    STATE_AO_GC(cds->ao);                                               \
                                                                        \
    libxl__multidev_begin(ao, &cds->multidev);                          \
    cds->multidev.callback = devices_checkpoint_cb;                     \
    for (i = 0; i < cds->num_devices; i++) {                            \
        dev = cds->devs[i];                                             \
        if (!dev->matched || !dev->ops->api)                            \
            continue;                                                   \
        libxl__multidev_prepare_with_aodev(&cds->multidev, &dev->aodev);\
        dev->ops->api(egc,dev);                                         \
    }                                                                   \
                                                                        \
    libxl__multidev_prepared(egc, &cds->multidev, 0);                   \
}

define_checkpoint_api(postsuspend);

define_checkpoint_api(preresume);

define_checkpoint_api(commit);

static void devices_checkpoint_cb(libxl__egc *egc,
                                  libxl__multidev *multidev,
                                  int rc)
{
    STATE_AO_GC(multidev->ao);

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds =
                            CONTAINER_OF(multidev, *cds, multidev);

    cds->callback(egc, cds, rc);
}
