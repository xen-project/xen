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
    if (S_ISBLK(st_mode) || S_ISREG(st_mode)) {
        return 1;
    }

    return 0;
}

char *libxl__devid_to_localdev(libxl__gc *gc, int devid)
{
    return libxl__devid_to_vdev(gc, devid);
}

/* Hotplug scripts helpers */

static char **get_hotplug_env(libxl__gc *gc,
                              char *script, libxl__device *dev)
{
    const char *type = libxl__device_kind_to_string(dev->backend_kind);
    char *be_path = libxl__device_backend_path(gc, dev);
    char **env;
    int nr = 0;

    const int arraysize = 15;
    GCNEW_ARRAY(env, arraysize);
    env[nr++] = "script";
    env[nr++] = script;
    env[nr++] = "XENBUS_TYPE";
    env[nr++] = (char *) type;
    env[nr++] = "XENBUS_PATH";
    env[nr++] = GCSPRINTF("backend/%s/%u/%d", type, dev->domid, dev->devid);
    env[nr++] = "XENBUS_BASE_PATH";
    env[nr++] = "backend";
    if (dev->backend_kind == LIBXL__DEVICE_KIND_VIF) {
        libxl_nic_type nictype;
        char *gatewaydev;

        gatewaydev = libxl__xs_read(gc, XBT_NULL,
                                    GCSPRINTF("%s/%s", be_path, "gatewaydev"));
        env[nr++] = "netdev";
        env[nr++] = gatewaydev ? : "";

        if (libxl__nic_type(gc, dev, &nictype)) {
            LOGD(ERROR, dev->domid, "unable to get nictype");
            return NULL;
        }
        switch (nictype) {
        case LIBXL_NIC_TYPE_VIF_IOEMU:
            env[nr++] = "INTERFACE";
            env[nr++] = (char *) libxl__device_nic_devname(gc, dev->domid,
                                                    dev->devid,
                                                    LIBXL_NIC_TYPE_VIF_IOEMU);
            /*
             * We need to fall through because for PV_IOEMU nic types we need
             * to execute both the vif and the tap hotplug script, and we
             * don't know which one we are executing in this call, so provide
             * both env variables.
             */
        case LIBXL_NIC_TYPE_VIF:
            env[nr++] = "vif";
            env[nr++] = (char *) libxl__device_nic_devname(gc, dev->domid,
                                                    dev->devid,
                                                    LIBXL_NIC_TYPE_VIF);
            break;
        default:
            return NULL;
        }
    }

    env[nr++] = NULL;
    assert(nr <= arraysize);

    return env;
}

/* Hotplug scripts caller functions */

static int libxl__hotplug_nic(libxl__gc *gc, libxl__device *dev,
                               char ***args, char ***env,
                               libxl__device_action action, int num_exec)
{
    char *be_path = libxl__device_backend_path(gc, dev);
    char *script;
    int nr = 0, rc = 0;
    libxl_nic_type nictype;

    script = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/%s", be_path,
                                                             "script"));
    if (!script) {
        LOGED(ERROR, dev->domid,
              "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__nic_type(gc, dev, &nictype);
    if (rc) {
        LOGD(ERROR, dev->domid, "error when fetching nic type");
        rc = ERROR_FAIL;
        goto out;
    }
    if (nictype == LIBXL_NIC_TYPE_VIF && num_exec != 0) {
        rc = 0;
        goto out;
    }

    *env = get_hotplug_env(gc, script, dev);
    if (!*env) {
        rc = ERROR_FAIL;
        goto out;
    }

    const int arraysize = 4;
    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;

    if (nictype == LIBXL_NIC_TYPE_VIF_IOEMU && num_exec) {
        (*args)[nr++] = (char *) libxl__device_action_to_string(action);
        (*args)[nr++] = "type_if=tap";
        (*args)[nr++] = NULL;
    } else {
        (*args)[nr++] = action == LIBXL__DEVICE_ACTION_ADD ? "online" :
                                                             "offline";
        (*args)[nr++] = "type_if=vif";
        (*args)[nr++] = NULL;
    }
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
    int nr = 0, rc = 0;

    script = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF("%s/%s", be_path, "script"));
    if (!script) {
        LOGEVD(ERROR, errno, dev->domid,
               "unable to read script from %s", be_path);
        rc = ERROR_FAIL;
        goto error;
    }

    *env = get_hotplug_env(gc, script, dev);
    if (!*env) {
        LOGD(ERROR, dev->domid, "Failed to get hotplug environment");
        rc = ERROR_FAIL;
        goto error;
    }

    const int arraysize = 3;
    GCNEW_ARRAY(*args, arraysize);
    (*args)[nr++] = script;
    (*args)[nr++] = (char *) libxl__device_action_to_string(action);
    (*args)[nr++] = NULL;
    assert(nr == arraysize);

    LOGD(DEBUG, dev->domid, "Args and environment ready");
    rc = 1;

error:
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
        rc = libxl__hotplug_disk(gc, dev, args, env, action);
        break;
    case LIBXL__DEVICE_KIND_VIF:
        /*
         * If domain has a stubdom we don't have to execute hotplug scripts
         * for emulated interfaces
         */
        if ((num_exec > 1) ||
            (libxl_get_stubdom_id(CTX, dev->domid) && num_exec)) {
            LOGD(DEBUG, dev->domid,
                 "num_exec %d, not running hotplug scripts", num_exec);
            rc = 0;
            goto out;
        }
        rc = libxl__hotplug_nic(gc, dev, args, env, action, num_exec);
        break;
    default:
        /* No need to execute any hotplug scripts */
        LOGD(DEBUG, dev->domid,
             "backend_kind %d, no need to execute scripts", dev->backend_kind);
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
    DIR *dir;
    struct dirent *entry;
    int num_devs = 0;

    dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        LOGE(ERROR, "Cannot open /sys/bus/pci/devices");
        return ERROR_FAIL;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;
        num_devs++;
    }
    closedir(dir);

    return num_devs;
}

int libxl__pci_topology_init(libxl__gc *gc,
                             physdev_pci_device_t *devs,
                             int num_devs)
{

    DIR *dir;
    struct dirent *entry;
    int i, err = 0;

    dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        LOGE(ERROR, "Cannot open /sys/bus/pci/devices");
        return ERROR_FAIL;
    }

    i = 0;
    while ((entry = readdir(dir))) {
        unsigned int dom, bus, dev, func;

        if (entry->d_name[0] == '.')
            continue;

        if (i == num_devs) {
            LOG(ERROR, "Too many devices");
            err = ERROR_FAIL;
            errno = -ENOSPC;
            goto out;
        }

        if (sscanf(entry->d_name, "%x:%x:%x.%d", &dom, &bus, &dev, &func) < 4) {
            LOGE(ERROR, "Error processing /sys/bus/pci/devices");
            err = ERROR_FAIL;
            goto out;
        }

        devs[i].seg = dom;
        devs[i].bus = bus;
        devs[i].devfn = ((dev & 0x1f) << 3) | (func & 7);

        i++;
    }

 out:
    closedir(dir);

    return err;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
