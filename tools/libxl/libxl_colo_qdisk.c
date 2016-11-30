/*
 * Copyright (C) 2016 FUJITSU LIMITED
 * Author: Wen Congyang <wency@cn.fujitsu.com>
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

/* ========== init() and cleanup() ========== */

int init_subkind_qdisk(libxl__checkpoint_devices_state *cds)
{
    /*
     * We don't know if we use qemu block replication, so
     * we cannot start block replication here.
     */
    return 0;
}

void cleanup_subkind_qdisk(libxl__checkpoint_devices_state *cds)
{
}

/* ========== setup() and teardown() ========== */

static void colo_qdisk_setup(libxl__egc *egc, libxl__checkpoint_device *dev,
                             bool primary)
{
    const libxl_device_disk *disk = dev->backend_dev;
    int ret, rc = 0;
    libxl__colo_qdisk *colo_qdisk = NULL;
    char port[32];

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = dev->cds;
    const char *host = disk->colo_host;
    const char *export_name = disk->colo_export;
    const int domid = cds->domid;

    STATE_AO_GC(dev->cds->ao);

    if (disk->backend != LIBXL_DISK_BACKEND_QDISK ||
        !libxl_defbool_val(disk->colo_enable) ||
        !host || !export_name || (disk->colo_port <= 0) ||
        !disk->active_disk || !disk->hidden_disk) {
        rc = ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH;
        goto out;
    }

    dev->matched = true;

    GCNEW(colo_qdisk);
    dev->concrete_data = colo_qdisk;

    if (primary) {
        libxl__colo_save_state *css = cds->concrete_data;

        css->qdisk_used = true;
        /* NBD server is not ready, so we cannot start block replication now */
        goto out;
    } else {
        libxl__colo_restore_state *crs = cds->concrete_data;
        sprintf(port, "%d", disk->colo_port);

        if (!crs->qdisk_used) {
            /* start nbd server */
            ret = libxl__qmp_nbd_server_start(gc, domid, host, port);
            if (ret) {
                rc = ERROR_FAIL;
                goto out;
            }
            crs->host = host;
            crs->port = port;
        } else {
            if (strcmp(crs->host, host) || strcmp(crs->port, port)) {
                LOGD(ERROR, domid, "The host and port of all disks must be the same");
                rc = ERROR_FAIL;
                goto out;
            }
        }

        crs->qdisk_used = true;

        ret = libxl__qmp_nbd_server_add(gc, domid, export_name);
        if (ret)
            rc = ERROR_FAIL;

        colo_qdisk->setuped = true;
    }

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

static void colo_qdisk_teardown(libxl__egc *egc, libxl__checkpoint_device *dev,
                                bool primary)
{
    int ret, rc = 0;
    const libxl__colo_qdisk *colo_qdisk = dev->concrete_data;
    const libxl_device_disk *disk = dev->backend_dev;

    /* Convenience aliases */
    libxl__checkpoint_devices_state *const cds = dev->cds;
    const int domid = cds->domid;
    const char *export_name = disk->colo_export;

    EGC_GC;

    if (primary) {
        if (!colo_qdisk->setuped)
            goto out;

        /*
         * There is no way to get the child name, but we know it is children.1
         */
        ret = libxl__qmp_x_blockdev_change(gc, domid, export_name,
                                           "children.1", NULL);
        if (ret)
            rc = ERROR_FAIL;
    } else {
        libxl__colo_restore_state *crs = cds->concrete_data;

        if (crs->qdisk_used) {
            ret = libxl__qmp_nbd_server_stop(gc, domid);
            if (ret)
                rc = ERROR_FAIL;
        }
    }

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

/* ========== checkpointing APIs ========== */

static void colo_qdisk_save_preresume(libxl__egc *egc,
                                      libxl__checkpoint_device *dev)
{
    libxl__colo_qdisk *colo_qdisk = dev->concrete_data;
    const libxl_device_disk *disk = dev->backend_dev;
    int ret, rc = 0;
    char *node = NULL;
    char *cmd = NULL;

    /* Convenience aliases */
    const int domid = dev->cds->domid;
    const char *host = disk->colo_host;
    int port = disk->colo_port;
    const char *export_name = disk->colo_export;

    EGC_GC;

    if (colo_qdisk->setuped)
        goto out;

    /* qmp command doesn't support the driver "nbd" */
    node = GCSPRINTF("colo_node%d",
                     libxl__device_disk_dev_number(disk->vdev, NULL, NULL));
    cmd = GCSPRINTF("drive_add -n buddy driver=replication,mode=primary,"
                    "file.driver=nbd,file.host=%s,file.port=%d,"
                    "file.export=%s,node-name=%s",
                    host, port, export_name, node);
    ret = libxl__qmp_hmp(gc, domid, cmd, NULL);
    if (ret)
        rc = ERROR_FAIL;

    ret = libxl__qmp_x_blockdev_change(gc, domid, export_name, NULL, node);
    if (ret)
        rc = ERROR_FAIL;

    colo_qdisk->setuped = true;

out:
    dev->aodev.rc = rc;
    dev->aodev.callback(egc, &dev->aodev);
}

/* ======== primary ======== */

static void colo_qdisk_save_setup(libxl__egc *egc,
                                  libxl__checkpoint_device *dev)
{
    colo_qdisk_setup(egc, dev, true);
}

static void colo_qdisk_save_teardown(libxl__egc *egc,
                                   libxl__checkpoint_device *dev)
{
    colo_qdisk_teardown(egc, dev, true);
}

const libxl__checkpoint_device_instance_ops colo_save_device_qdisk = {
    .kind = LIBXL__DEVICE_KIND_VBD,
    .setup = colo_qdisk_save_setup,
    .teardown = colo_qdisk_save_teardown,
    .preresume = colo_qdisk_save_preresume,
};

/* ======== secondary ======== */

static void colo_qdisk_restore_setup(libxl__egc *egc,
                                     libxl__checkpoint_device *dev)
{
    colo_qdisk_setup(egc, dev, false);
}

static void colo_qdisk_restore_teardown(libxl__egc *egc,
                                      libxl__checkpoint_device *dev)
{
    colo_qdisk_teardown(egc, dev, false);
}

const libxl__checkpoint_device_instance_ops colo_restore_device_qdisk = {
    .kind = LIBXL__DEVICE_KIND_VBD,
    .setup = colo_qdisk_restore_setup,
    .teardown = colo_qdisk_restore_teardown,
};
