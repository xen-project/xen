/*
 * Copyright (C) 2014
 * Author Roger Pau Monne <roger.pau@entel.upc.edu>
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

int libxl__try_phy_backend(mode_t st_mode)
{
    if (S_ISREG(st_mode) || S_ISBLK(st_mode) || S_ISCHR(st_mode))
        return 1;

    return 0;
}

char *libxl__devid_to_localdev(libxl__gc *gc, int devid)
{
    /* This translation table has been copied from the FreeBSD blkfront code. */
    const static struct vdev_info {
        int major;
        int shift;
        int base;
        const char *name;
    } info[] = {
        {3,     6,  0,      "ada"}, /* ide0 */
        {22,    6,  2,      "ada"}, /* ide1 */
        {33,    6,  4,      "ada"}, /* ide2 */
        {34,    6,  6,      "ada"}, /* ide3 */
        {56,    6,  8,      "ada"}, /* ide4 */
        {57,    6,  10,     "ada"}, /* ide5 */
        {88,    6,  12,     "ada"}, /* ide6 */
        {89,    6,  14,     "ada"}, /* ide7 */
        {90,    6,  16,     "ada"}, /* ide8 */
        {91,    6,  18,     "ada"}, /* ide9 */

        {8,     4,  0,      "da"},  /* scsi disk0 */
        {65,    4,  16,     "da"},  /* scsi disk1 */
        {66,    4,  32,     "da"},  /* scsi disk2 */
        {67,    4,  48,     "da"},  /* scsi disk3 */
        {68,    4,  64,     "da"},  /* scsi disk4 */
        {69,    4,  80,     "da"},  /* scsi disk5 */
        {70,    4,  96,     "da"},  /* scsi disk6 */
        {71,    4,  112,    "da"},  /* scsi disk7 */
        {128,   4,  128,    "da"},  /* scsi disk8 */
        {129,   4,  144,    "da"},  /* scsi disk9 */
        {130,   4,  160,    "da"},  /* scsi disk10 */
        {131,   4,  176,    "da"},  /* scsi disk11 */
        {132,   4,  192,    "da"},  /* scsi disk12 */
        {133,   4,  208,    "da"},  /* scsi disk13 */
        {134,   4,  224,    "da"},  /* scsi disk14 */
        {135,   4,  240,    "da"},  /* scsi disk15 */

        {202,   4,  0,      "xbd"}, /* xbd */

        {0, 0,  0,  NULL},
    };
    int major = devid >> 8;
    int minor = devid & 0xff;
    int i;

    if (devid & (1 << 28))
        return GCSPRINTF("%s%d", "xbd", (devid & ((1 << 28) - 1)) >> 8);

    for (i = 0; info[i].major; i++)
        if (info[i].major == major)
            return GCSPRINTF("%s%d", info[i].name,
                             info[i].base + (minor >> info[i].shift));

    return GCSPRINTF("%s%d", "xbd", minor >> 4);
}

/* Hotplug scripts caller functions */
static int libxl__hotplug_env_nic(libxl__gc *gc, libxl__device *dev, char ***env,
                                  int num_exec)
{
    int nr = 0;
    const int arraysize = 5;
    libxl_nic_type type;

    assert(dev->backend_kind == LIBXL__DEVICE_KIND_VIF);

    /*
     * On the first pass the PV interface is added to the bridge,
     * on the second pass the tap interface will also be added.
     */
    type = num_exec == 0 ? LIBXL_NIC_TYPE_VIF : LIBXL_NIC_TYPE_VIF_IOEMU;

    GCNEW_ARRAY(*env, arraysize);
    (*env)[nr++] = "iface_dev";
    (*env)[nr++] = (char *) libxl__device_nic_devname(gc, dev->domid,
                                                      dev->devid, type);
    (*env)[nr++] = "emulated";
    (*env)[nr++] = type == LIBXL_NIC_TYPE_VIF_IOEMU ? "1" : "0";
    (*env)[nr++] = NULL;
    assert(nr == arraysize);

    return 0;
}

static int libxl__hotplug_nic(libxl__gc *gc, libxl__device *dev,
                              char ***args, char ***env,
                              libxl__device_action action,
                              int num_exec)
{
    libxl_nic_type nictype;
    char *be_path = libxl__device_backend_path(gc, dev);
    char *script;
    int nr = 0, rc;

    rc = libxl__nic_type(gc, dev, &nictype);
    if (rc) {
        LOGD(ERROR, dev->domid, "error when fetching nic type");
        rc = ERROR_FAIL;
        goto out;
    }

    /*
     * For PV domains only one pass is needed (because there's no emulated
     * interface). For HVM domains two passes are needed in order to add
     * both the PV and the tap interfaces to the bridge.
     */
    if (nictype == LIBXL_NIC_TYPE_VIF && num_exec != 0) {
        rc = 0;
        goto out;
    }

    rc = libxl__hotplug_env_nic(gc, dev, env, num_exec);
    if (rc)
        goto out;

    script = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF("%s/%s", be_path, "script"));
    if (!script) {
        LOGEVD(ERROR, errno, dev->domid,
               "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }

    const int arraysize = 4;
    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;
    (*args)[nr++] = be_path;
    (*args)[nr++] = (char *) libxl__device_action_to_string(action);
    (*args)[nr++] = NULL;
    assert(nr == arraysize);
    rc = 1;

out:
    return rc;
}

static int libxl__hotplug_disk(libxl__gc *gc, libxl__device *dev,
                               char ***args, char ***env,
                               libxl__device_action action)
{
    char *be_path = libxl__device_backend_path(gc, dev);
    char *script;
    int nr = 0, rc;

    script = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF("%s/%s", be_path, "script"));
    if (!script) {
        LOGEVD(ERROR, errno, dev->domid,
               "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }

    const int arraysize = 4;
    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;
    (*args)[nr++] = be_path;
    (*args)[nr++] = (char *) libxl__device_action_to_string(action);
    (*args)[nr++] = NULL;
    assert(nr == arraysize);
    rc = 1;

out:
    return rc;
}

int libxl__get_hotplug_script_info(libxl__gc *gc, libxl__device *dev,
                                   char ***args, char ***env,
                                   libxl__device_action action,
                                   int num_exec)
{
    int rc;

    switch (dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VIF:
        /*
         * If domain has a stubdom we don't have to execute hotplug scripts
         * for emulated interfaces
         */
        if ((num_exec > 1) ||
            (libxl_get_stubdom_id(CTX, dev->domid) && num_exec)) {
            rc = 0;
            goto out;
        }
        rc = libxl__hotplug_nic(gc, dev, args, env, action, num_exec);
        break;
    case LIBXL__DEVICE_KIND_VBD:
        if (num_exec != 0) {
            rc = 0;
            goto out;
        }
        rc = libxl__hotplug_disk(gc, dev, args, env, action);
        break;
    default:
        /* No need to execute any hotplug scripts */
        rc = 0;
        break;
    }

out:
    return rc;
}

libxl_device_model_version libxl__default_device_model(libxl__gc *gc)
{
    return LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
}

int libxl__pci_numdevs(libxl__gc *gc)
{
    return ERROR_NI;
}

int libxl__pci_topology_init(libxl__gc *gc,
                             physdev_pci_device_t *devs,
                             int num_devs)
{
    return ERROR_NI;
}
