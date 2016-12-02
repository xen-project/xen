/*
 * Copyright (C) 2011
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
    if (S_ISREG(st_mode) || S_ISBLK(st_mode))
        return 1;

    return 0;
}

char *libxl__devid_to_localdev(libxl__gc *gc, int devid)
{
    /* TODO */
    return NULL;
}

/* Hotplug scripts caller functions */
static int libxl__hotplug(libxl__gc *gc, libxl__device *dev, char ***args,
                          libxl__device_action action)
{
    char *be_path = libxl__device_backend_path(gc, dev);
    char *script;
    int nr = 0, rc = 0, arraysize = 4;

    script = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF("%s/%s", be_path, "script"));
    if (!script) {
        LOGEVD(ERROR, errno, dev->domid,
               "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }

    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;
    (*args)[nr++] = be_path;
    (*args)[nr++] = GCSPRINTF("%d", action == LIBXL__DEVICE_ACTION_ADD ?
                                    XenbusStateInitWait : XenbusStateClosed);
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
    int rc;

    switch (dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VBD:
        if (num_exec != 0) {
            LOGD(DEBUG, dev->domid,
                 "num_exec %d, not running hotplug scripts", num_exec);
            rc = 0;
            goto out;
        }
        rc = libxl__hotplug(gc, dev, args, action);
        if (!rc) rc = 1;
        break;
    case LIBXL__DEVICE_KIND_VIF:
        /*
         * If domain has a stubdom we don't have to execute hotplug scripts
         * for emulated interfaces
         *
         * NetBSD let QEMU call a script to plug emulated nic, so
         * only test if num_exec == 0 in that case.
         */
        if ((num_exec != 0) ||
            (libxl_get_stubdom_id(CTX, dev->domid) && num_exec)) {
            LOGD(DEBUG, dev->domid,
                 "num_exec %d, not running hotplug scripts", num_exec);
            rc = 0;
            goto out;
        }
        rc = libxl__hotplug(gc, dev, args, action);
        if (!rc) rc = 1;
        break;
    default:
        /* If no need to execute any hotplug scripts,
         * call the callback manually
         */
        rc = 0;
        break;
    }

out:
    return rc;
}

libxl_device_model_version libxl__default_device_model(libxl__gc *gc)
{
    return LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
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
