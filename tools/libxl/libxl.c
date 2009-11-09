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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>
#include "libxl.h"
#include "libxl_utils.h"
#include "libxl_internal.h"
#include "flexarray.h"

int libxl_ctx_init(struct libxl_ctx *ctx)
{
    memset(ctx, 0, sizeof(struct libxl_ctx));
    ctx->alloc_maxsize = 256;
    ctx->alloc_ptrs = calloc(ctx->alloc_maxsize, sizeof(void *));
    if (!ctx->alloc_ptrs)
        return ERROR_NOMEM;

    ctx->xch = xc_interface_open();
    ctx->xsh = xs_daemon_open();
    return 0;
}

int libxl_ctx_free(struct libxl_ctx *ctx)
{
    libxl_free_all(ctx);
    free(ctx->alloc_ptrs);
    ctx->alloc_ptrs = NULL;
    xc_interface_close(ctx->xch);
    xs_daemon_close(ctx->xsh);
    return 0;
}

int libxl_ctx_set_log(struct libxl_ctx *ctx, libxl_log_callback log_callback, void *log_data)
{
    ctx->log_callback = log_callback;
    ctx->log_userdata = log_data;
    return 0;
}

/******************************************************************************/

int libxl_domain_make(struct libxl_ctx *ctx, libxl_domain_create_info *info,
                       uint32_t *domid)
{
    int flags, ret, i;
        char *uuid_string;
    char *rw_paths[] = { "device" };
    char *ro_paths[] = { "cpu", "memory", "device", "error", "drivers",
                         "control", "attr", "data", "messages" };
    char *dom_path, *vm_path, *vss_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    xs_transaction_t t;

    uuid_string = uuid_to_string(ctx, info->uuid);
    if (!uuid_string) {
        XL_LOG(ctx, XL_LOG_ERROR, "missing uuid");
        return ERROR_FAIL;
    }

    flags = info->hvm ? XEN_DOMCTL_CDF_hvm_guest : 0;
    flags |= info->hap ? XEN_DOMCTL_CDF_hap : 0;
    *domid = 0;

    ret = xc_domain_create(ctx->xch, info->ssidref, info->uuid, flags, domid);
    if (ret < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "domain creation fail: %d", ret);
        return ERROR_FAIL;
    }

    dom_path = libxl_xs_get_dompath(ctx, *domid);
    vm_path = libxl_sprintf(ctx, "/vm/%s", uuid_string);
    vss_path = libxl_sprintf(ctx, "/vss/%s", uuid_string);
    if (!dom_path || !vm_path || !vss_path) {
        XL_LOG(ctx, XL_LOG_ERROR, "cannot allocate create paths");
        return ERROR_FAIL;
    }

    roperm[0].id = 0;
    roperm[0].perms = XS_PERM_NONE;
    roperm[1].id = *domid;
    roperm[1].perms = XS_PERM_READ;
    rwperm[0].id = *domid;
    rwperm[0].perms = XS_PERM_NONE;

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_rm(ctx->xsh, t, dom_path);
    xs_mkdir(ctx->xsh, t, dom_path);
    xs_set_permissions(ctx->xsh, t, dom_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, vm_path);
    xs_mkdir(ctx->xsh, t, vm_path);
    xs_set_permissions(ctx->xsh, t, vm_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, vss_path);
    xs_mkdir(ctx->xsh, t, vss_path);
    xs_set_permissions(ctx->xsh, t, vss_path, rwperm, ARRAY_SIZE(rwperm));

    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/vm", dom_path), vm_path, strlen(vm_path));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/vss", dom_path), vss_path, strlen(vss_path));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/name", dom_path), info->name, strlen(info->name));

    for (i = 0; i < ARRAY_SIZE(rw_paths); i++) {
        char *path = libxl_sprintf(ctx, "%s/%s", dom_path, rw_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, rwperm, ARRAY_SIZE(rwperm));
        libxl_free(ctx, path);
    }
    for (i = 0; i < ARRAY_SIZE(ro_paths); i++) {
        char *path = libxl_sprintf(ctx, "%s/%s", dom_path, ro_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
        libxl_free(ctx, path);
    }

    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/uuid", vm_path), uuid_string, strlen(uuid_string));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/name", vm_path), info->name, strlen(info->name));

    libxl_xs_writev(ctx, t, dom_path, info->xsdata);
    libxl_xs_writev(ctx, t, libxl_sprintf(ctx, "%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    return 0;
}

int libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid)
{
    libxl_domain_build_state state;
    char **vments = NULL, **localents = NULL;

    memset(&state, '\0', sizeof(state));

    build_pre(ctx, domid, info, &state);
    if (info->hvm) {
        build_hvm(ctx, domid, info, &state);
        vments = libxl_calloc(ctx, 4, sizeof(char *));
        vments[0] = libxl_sprintf(ctx, "rtc/timeoffset");
        vments[1] = libxl_sprintf(ctx, "%s", (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "");
    } else {
        build_pv(ctx, domid, info, &state);
    }
    build_post(ctx, domid, info, &state, vments, localents);
    return 0;
}

int libxl_domain_restore(struct libxl_ctx *ctx, libxl_domain_build_info *info,
                          uint32_t domid, int fd)
{
    libxl_domain_build_state state;
    char **vments = NULL, **localents = NULL;

    memset(&state, '\0', sizeof(state));

    build_pre(ctx, domid, info, &state);
    restore_common(ctx, domid, info, &state, fd);
    if (info->hvm) {
        vments = libxl_calloc(ctx, 4, sizeof(char *));
        vments[0] = libxl_sprintf(ctx, "rtc/timeoffset");
        vments[1] = libxl_sprintf(ctx, "%s", (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "");
    } else {
        localents = libxl_calloc(ctx, 4 * 2, sizeof(char *));
        localents[0] = libxl_sprintf(ctx, "serial/0/limit");
        localents[1] = libxl_sprintf(ctx, "%d", 65536);
        localents[2] = libxl_sprintf(ctx, "console/port");
        localents[3] = libxl_sprintf(ctx, "%d", state.console_port);
        localents[4] = libxl_sprintf(ctx, "console/ring-ref");
        localents[5] = libxl_sprintf(ctx, "%ld", state.console_mfn);
    }
    build_post(ctx, domid, info, &state, vments, localents);
    return 0;
}

struct libxl_dominfo * libxl_domain_list(struct libxl_ctx *ctx, int *nb_domain)
{
    struct libxl_dominfo *ptr;
    int index, i, ret, first_domain;
    xc_domaininfo_t info[16];
    int size = 16;

    first_domain = 1;
    index = 0;
    ptr = libxl_calloc(ctx, size, sizeof(struct libxl_dominfo));
    if (!ptr)
        return NULL;
redo:
    ret = xc_domain_getinfolist(ctx->xch, first_domain, 16, info);
    for (i = 0; i < ret; i++) {
        if (index == size) {
            struct libxl_dominfo *ptr2;

            ptr2 = libxl_calloc(ctx, size * 2, sizeof(struct libxl_dominfo));
            if (!ptr2) {
                libxl_free(ctx, ptr);
                return NULL;
            }
            memcpy(ptr2, ptr, sizeof(struct libxl_dominfo) * size);
            libxl_free(ctx, ptr);
            ptr = ptr2;
            size *= 2;
        }
        memcpy(ptr[index].uuid, info[i].handle, 16 * sizeof(uint8_t));
        ptr[index].domid = info[i].domain;
        first_domain = info[i].domain + 1;
        index++;
    }
    if (ret == 16)
        goto redo;
    *nb_domain = index;
    return ptr;
}

xc_dominfo_t * libxl_domain_infolist(struct libxl_ctx *ctx, int *nb_domain)
{
    int index, first_domain;
    xc_dominfo_t *info;
    int size = 1024;

    first_domain = 0;
    index = 0;
    info = (xc_dominfo_t *) libxl_calloc(ctx, size, sizeof(xc_dominfo_t));
    if (!info) {
        *nb_domain = 0;
        return NULL;
    }
    *nb_domain = xc_domain_getinfo(ctx->xch, first_domain, 1024, info);
    return info;
}

int libxl_domain_suspend(struct libxl_ctx *ctx, libxl_domain_suspend_info *info,
                         uint32_t domid, int fd)
{
    int hvm = 1;
    int live = 0;
    int debug = 0;
    char savesig[] = "XenSavedDomain\n";

    write(fd, savesig, strlen(savesig));

    core_suspend(ctx, domid, fd, hvm, live, debug);

    return 0;
}

int libxl_domain_pause(struct libxl_ctx *ctx, uint32_t domid)
{
    xc_domain_pause(ctx->xch, domid);
    return 0;
}

int libxl_domain_unpause(struct libxl_ctx *ctx, uint32_t domid)
{
    xc_domain_unpause(ctx->xch, domid);
    return 0;
}

static char *req_table[] = {
    [0] = "poweroff",
    [1] = "reboot",
    [2] = "suspend",
    [3] = "crash",
    [4] = "halt",
};

int libxl_domain_shutdown(struct libxl_ctx *ctx, uint32_t domid, int req)
{
    char *shutdown_path;
    char *dom_path;

    if (req > ARRAY_SIZE(req_table))
        return ERROR_INVAL;

    dom_path = libxl_xs_get_dompath(ctx, domid);
    shutdown_path = libxl_sprintf(ctx, "%s/control/shutdown", dom_path);

    xs_write(ctx->xsh, XBT_NULL, shutdown_path, req_table[req], strlen(req_table[req]));
    if (/* hvm */ 0) {
        unsigned long acpi_s_state = 0;
        unsigned long pvdriver = 0;
        xc_get_hvm_param(ctx->xch, domid, HVM_PARAM_ACPI_S_STATE, &acpi_s_state);
        xc_get_hvm_param(ctx->xch, domid, HVM_PARAM_CALLBACK_IRQ, &pvdriver);
        if (!pvdriver && acpi_s_state != 0)
            xc_domain_shutdown(ctx->xch, domid, req);
    }
    return 0;
}

static int libxl_destroy_device_model(struct libxl_ctx *ctx, uint32_t domid)
{
    char *pid;
    int ret;

    pid = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/image/device-model-pid", domid));
    if (!pid) {
        XL_LOG(ctx, XL_LOG_ERROR, "Couldn't find device model's pid\n");
        return -1;
    }
    xs_rm(ctx->xsh, XBT_NULL, libxl_sprintf(ctx, "/local/domain/0/device-model/%d", domid));

    ret = kill(atoi(pid), SIGHUP);
    if (ret < 0 && errno == ESRCH) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Device Model already exited\n");
        ret = 0;
    } else if (ret == 0) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Device Model signaled\n");
        ret = 0;
    } else {
        XL_LOG(ctx, XL_LOG_ERROR, "kill %d returned %d errno=%d\n", atoi(pid), ret, errno);
    }
    return ret;
}

int libxl_domain_destroy(struct libxl_ctx *ctx, uint32_t domid, int force)
{
    char *dom_path, vm_path[41];
    uint8_t *uuid;

    dom_path = libxl_xs_get_dompath(ctx, domid);
    if (!dom_path) {
        XL_LOG(ctx, XL_LOG_ERROR, "dompath doesn't exist for %d\n", domid);
        return -1;
    }
    if (libxl_domid_to_uuid(ctx, &uuid, domid) < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "failed ot get uuid for %d\n", domid);
        return -1;
    }
    xs_write(ctx->xsh, XBT_NULL,
             libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid),
             "shutdown", strlen("shutdown"));
    if (xc_domain_pause(ctx->xch, domid) < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "xc_domain_pause failed for %d\n", domid);
        return -1;
    }
    /* do_FLR */
    if (xc_domain_destroy(ctx->xch, domid) < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "xc_domain_destroy failed for %d\n", domid);
        return -1;
    }
    if (libxl_devices_destroy(ctx, domid, force) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_devices failed for %d\n", domid);
    if (libxl_destroy_device_model(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_device_model failed for %d\n", domid);
    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        XL_LOG(ctx, XL_LOG_ERROR, "xs_rm failed for %s\n", dom_path);
    snprintf(vm_path, sizeof(vm_path), "/vm/%s", uuid_to_string(ctx, uuid));
    if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
        XL_LOG(ctx, XL_LOG_ERROR, "xs_rm failed for %s\n", vm_path);
    return 0;
}

static char ** libxl_build_device_model_args(struct libxl_ctx *ctx,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    int num = 0, i;
    flexarray_t *dm_args;
    dm_args = flexarray_make(16, 1);
    if (!dm_args)
        return NULL;

    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "qemu-dm"));
    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-d"));

    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%d", info->domid));

    if (info->dom_name) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-domain-name"));
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->dom_name));
    }
    if (info->videoram) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-videoram"));
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%d", info->videoram));
    }
    if (info->stdvga) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-std-vga"));
    }
    if (info->vnc || info->vncdisplay || info->vnclisten || info->vncunused) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-vnc"));
        if (info->vncdisplay) {
            if (info->vnclisten && strchr(info->vnclisten, ':') == NULL) {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s:%d", info->vnclisten, info->vncdisplay));
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "127.0.0.1:%d", info->vncdisplay));
            }
        } else if (info->vnclisten) {
            if (strchr(info->vnclisten, ':') != NULL) {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->vnclisten));
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s:0", info->vnclisten));
            }
        } else {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "127.0.0.1:0"));
        }
        if (info->vncunused) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-vncunused"));
        }
    }
    if (info->sdl || info->opengl) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-sdl"));
        if (info->opengl) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-disable-opengl"));
        }
    }
    if (info->keymap) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-k"));
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->keymap));
    }
    if (info->nographic && (!info->sdl && !info->vnc)) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-nographic"));
    }
    if (info->serial) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-serial"));
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->serial));
    }
    if (info->boot) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-boot"));
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->boot));
    }
    if (info->usb) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-usb"));
        if (info->usbdevice) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-usbdevice"));
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->usbdevice));
        }
    }
    if (info->apic) {
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-acpi"));
    }
    if (info->extra) {
        int i = 0;
        while (info->extra[i] != NULL) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s", info->extra[i]));
        }
    }
    for (i = 0; i < num_vifs; i++) {
        if (vifs[i].nictype == NICTYPE_IOEMU) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-net"));
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "nic,vlan=%d,macaddr=%s,model=%s",
                                                        vifs[i].devid, vifs[i].smac, vifs[i].model));
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-net"));
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "tap,vlan=%d,ifname=%s,bridge=%s",
                                                        vifs[i].devid, vifs[i].ifname, vifs[i].bridge));
        }
    }
    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-M"));
    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "xenfv"));
    flexarray_set(dm_args, num++, NULL);

    return (char **) flexarray_contents(dm_args);
}

int libxl_create_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_nic *vifs, int num_vifs)
{
    char *dom_path, *path, *logfile, *logfile_new;
    char *kvs[3];
    struct stat stat_buf;
    int logfile_w, null, pid;
    int i;
    char **args;

    args = libxl_build_device_model_args(ctx, info, vifs, num_vifs);
    if (!args)
        return ERROR_FAIL;

    dom_path = libxl_xs_get_dompath(ctx, info->domid);

    path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d", info->domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);

    logfile = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log", info->dom_name);
    if (stat(logfile, &stat_buf) == 0) {
        /* file exists, rotate */
        logfile = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log.10", info->dom_name);
        unlink(logfile);
        for (i = 9; i > 0; i--) {
            logfile = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log.%d", info->dom_name, i);
            logfile_new = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log.%d", info->dom_name, i + 1);
            rename(logfile, logfile_new);
        }
        logfile = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log", info->dom_name);
        logfile_new = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log.1", info->dom_name);
        rename(logfile, logfile_new);
    }
    logfile = libxl_sprintf(ctx, "/var/log/xen/qemu-dm-%s.log", info->dom_name);
    logfile_w = open(logfile, O_WRONLY|O_CREAT);
    null = open("/dev/null", O_RDONLY);
    pid = libxl_exec(ctx, null, logfile_w, logfile_w, info->device_model, args);
    close(null);
    close(logfile_w);

    kvs[0] = libxl_sprintf(ctx, "image/device-model-pid");
    kvs[1] = libxl_sprintf(ctx, "%d", pid);
    kvs[2] = NULL;
    libxl_xs_writev(ctx, XBT_NULL, dom_path, kvs);

    return 0;
}

/******************************************************************************/
int libxl_device_disk_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk)
{
    flexarray_t *front;
    flexarray_t *back;
    char *backend_type;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    int devid;
    libxl_device device;

    front = flexarray_make(16, 1);
    if (!front)
        return ERROR_NOMEM;
    back = flexarray_make(16, 1);
    if (!back) /* leaks front if error */
        return ERROR_NOMEM;

    backend_type = device_disk_backend_type_of_phystype(disk->phystype);
    devid = device_disk_dev_number(disk->virtpath);

    device.backend_devid = devid;
    device.backend_domid = disk->backend_domid;
    device.devid = devid;
    device.domid = disk->domid;
    device.kind = DEVICE_VBD;

    switch (disk->phystype) {
        case PHYSTYPE_FILE:
            return ERROR_NI; /* FIXME */
            break;
        case PHYSTYPE_PHY: {
            int major, minor;

            device_disk_major_minor(disk->virtpath, &major, &minor);
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "physical-device"));
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%x:%x", major, minor));

            flexarray_set(back, boffset++, libxl_sprintf(ctx, "params"));
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", disk->physpath));

            device.backend_kind = DEVICE_VBD;
            break;
        }
        case PHYSTYPE_AIO: case PHYSTYPE_QCOW: case PHYSTYPE_QCOW2: case PHYSTYPE_VHD:
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "params"));
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s:%s",
                          device_disk_string_of_phystype(disk->phystype), disk->physpath));

            device.backend_kind = DEVICE_TAP;
            break;
    }

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", disk->domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "removable"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", (disk->unpluggable) ? 1 : 0));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "dev"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", disk->virtpath));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "type"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", backend_type));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "mode"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", (disk->readwrite) ? "w" : "r"));

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", disk->backend_domid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "virtual-device"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", devid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "device-type"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%s", (disk->is_cdrom) ? "cdrom" : "disk"));

    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "protocol"));
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "x86_32-abi")); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));
    /* leaks both flexarray here */
    return 0;
}

int libxl_device_disk_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_disk_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

/******************************************************************************/
int libxl_device_nic_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic)
{
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;

    front = flexarray_make(16, 1);
    if (!front)
        return ERROR_NOMEM;
    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    device.backend_devid = nic->devid;
    device.backend_domid = nic->backend_domid;
    device.backend_kind = DEVICE_VIF;
    device.devid = nic->devid;
    device.domid = nic->domid;
    device.kind = DEVICE_VIF;

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", nic->domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "script"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", nic->script));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "mac"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                 nic->mac[0], nic->mac[1], nic->mac[2],
                                                 nic->mac[3], nic->mac[4], nic->mac[5]));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "handle"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", nic->devid));

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", nic->backend_domid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "handle"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", nic->devid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "mac"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  nic->mac[0], nic->mac[1], nic->mac[2],
                                                  nic->mac[3], nic->mac[4], nic->mac[5]));
    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "protocol"));
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "x86_32-abi")); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));

    /* FIXME: wait for plug */
    return 0;
}

int libxl_device_nic_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_nic_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

/******************************************************************************/
int libxl_device_vkb_add(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vkb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vkb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

/******************************************************************************/
int libxl_device_vfb_add(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vfb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vfb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

/******************************************************************************/
int libxl_device_pci_add(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_pci_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_pci_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}
