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
    /* TODO */
    return NULL;
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

static int libxl__hotplug_nic(libxl__gc *gc, libxl__device *dev, char ***args,
                              libxl__device_action action)
{
    char *be_path = libxl__device_backend_path(gc, dev);
    char *script;
    int nr = 0, rc = 0, arraysize = 4;

    assert(dev->backend_kind == LIBXL__DEVICE_KIND_VIF);

    script = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF("%s/%s", be_path, "script"));
    if (!script) {
        LOGEV(ERROR, errno, "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }

    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;
    (*args)[nr++] = be_path;
    (*args)[nr++] = GCSPRINTF("%s", action == LIBXL__DEVICE_ACTION_ADD ?
                                    "add" : "remove");
    (*args)[nr++] = NULL;
    assert(nr == arraysize);

out:
    return rc;
}

int libxl__get_hotplug_script_info(libxl__gc *gc, libxl__device *dev,
                                   char ***args, char ***env,
                                   libxl__device_action action,
                                   int num_exec)
{
    libxl_nic_type nictype;
    int rc;

    if (dev->backend_kind != LIBXL__DEVICE_KIND_VIF || num_exec == 2)
        return 0;

    rc = libxl__nic_type(gc, dev, &nictype);
    if (rc) {
        LOG(ERROR, "error when fetching nic type");
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

    rc = libxl__hotplug_nic(gc, dev, args, action);
    if (!rc) rc = 1;

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
