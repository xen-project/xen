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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h> /* for write, unlink and close */
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

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

    ctx->waitpid_instead= libxl_waitpid_instead_default;
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
    xen_domain_handle_t handle;

    uuid_string = libxl_uuid_to_string(ctx, info->uuid);
    if (!uuid_string) {
        XL_LOG(ctx, XL_LOG_ERROR, "missing uuid");
        return ERROR_FAIL;
    }

    flags = info->hvm ? XEN_DOMCTL_CDF_hvm_guest : 0;
    flags |= info->hap ? XEN_DOMCTL_CDF_hap : 0;
    *domid = 0;

    /* XXX handle has to be initialised here.
     * info->uuid != xen_domain_handle_t
     * See: 
     *      http://www.opengroup.org/dce/info/draft-leach-uuids-guids-01.txt
     *      http://www.opengroup.org/onlinepubs/009629399/apdxa.htm
     *
     * A DCE 1.1 compatible source representation of UUIDs.
     *
     * struct uuid {
     *     uint32_t        time_low;
     *     uint16_t        time_mid;
     *     uint16_t        time_hi_and_version;
     *     uint8_t         clock_seq_hi_and_reserved;
     *     uint8_t         clock_seq_low;
     *     uint8_t         node[_UUID_NODE_LEN];
     * };
     */

    ret = xc_domain_create(ctx->xch, info->ssidref, handle, flags, domid);
    if (ret < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "domain creation fail");
        return ERROR_FAIL;
    }

    dom_path = libxl_xs_get_dompath(ctx, *domid);
    if (!dom_path)
        return ERROR_FAIL;

    vm_path = libxl_sprintf(ctx, "/vm/%s", uuid_string);
    vss_path = libxl_sprintf(ctx, "/vss/%s", uuid_string);
    if (!vm_path || !vss_path) {
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

libxl_domain_build_state *libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid)
{
    libxl_domain_build_state *state = (libxl_domain_build_state *) libxl_calloc(ctx, 1, sizeof(libxl_domain_build_state));
    char **vments = NULL, **localents = NULL;

    build_pre(ctx, domid, info, state);
    if (info->hvm) {
        build_hvm(ctx, domid, info, state);
        vments = libxl_calloc(ctx, 5, sizeof(char *));
        vments[0] = libxl_sprintf(ctx, "rtc/timeoffset");
        vments[1] = libxl_sprintf(ctx, "%s", (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "");
        vments[2] = libxl_sprintf(ctx, "image/ostype");
        vments[3] = libxl_sprintf(ctx, "hvm");
    } else {
        build_pv(ctx, domid, info, state);
        vments = libxl_calloc(ctx, 9, sizeof(char *));
        vments[0] = libxl_sprintf(ctx, "image/ostype");
        vments[1] = libxl_sprintf(ctx, "linux");
        vments[2] = libxl_sprintf(ctx, "image/kernel");
        vments[3] = libxl_sprintf(ctx, info->kernel);
        vments[4] = libxl_sprintf(ctx, "image/ramdisk");
        vments[5] = libxl_sprintf(ctx, info->u.pv.ramdisk);
        vments[6] = libxl_sprintf(ctx, "image/cmdline");
        vments[7] = libxl_sprintf(ctx, info->u.pv.cmdline);
    }
    build_post(ctx, domid, info, state, vments, localents);
    return state;
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
    if (!dom_path)
        return ERROR_FAIL;

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
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't find device model's pid");
        return -1;
    }
    xs_rm(ctx->xsh, XBT_NULL, libxl_sprintf(ctx, "/local/domain/0/device-model/%d", domid));

    ret = kill(atoi(pid), SIGHUP);
    if (ret < 0 && errno == ESRCH) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Device Model already exited");
        ret = 0;
    } else if (ret == 0) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Device Model signaled");
        ret = 0;
    } else {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "failed to kill Device Model [%d]",
                     atoi(pid));
    }
    return ret;
}

int libxl_domain_destroy(struct libxl_ctx *ctx, uint32_t domid, int force)
{
    char *dom_path, vm_path[41];
    xen_uuid_t *uuid;
    int rc;

    dom_path = libxl_xs_get_dompath(ctx, domid);
    if (!dom_path)
        return -1;

    if (libxl_domid_to_uuid(ctx, &uuid, domid) < 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "failed ot get uuid for %d", domid);
        return -1;
    }
    if (libxl_device_pci_shutdown(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "pci shutdown failed for domid %d", domid);
    xs_write(ctx->xsh, XBT_NULL,
             libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid),
             "shutdown", strlen("shutdown"));
    rc = xc_domain_pause(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_pause failed for %d", domid);
        return -1;
    }
    rc = xc_domain_destroy(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_destroy failed for %d", domid);
        return -1;
    }
    if (libxl_devices_destroy(ctx, domid, force) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_devices failed for %d", domid);
    if (libxl_destroy_device_model(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_device_model failed for %d", domid);
    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", dom_path);
    snprintf(vm_path, sizeof(vm_path), "/vm/%s", libxl_uuid_to_string(ctx, uuid));
    if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vm_path);
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
    if (info->type == XENFV) {
        if (info->videoram) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-videoram"));
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%d", info->videoram));
        }
        if (info->stdvga) {
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-std-vga"));
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
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_set(dm_args, num++, info->extra[i]);
    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "-M"));
    if (info->type == XENPV)
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "xenpv"));
    else
        flexarray_set(dm_args, num++, libxl_sprintf(ctx, "xenfv"));
    flexarray_set(dm_args, num++, NULL);

    return (char **) flexarray_contents(dm_args);
}

struct libxl_device_model_starting {
    struct libxl_spawn_starting for_spawn; /* first! */
    char *dom_path; /* from libxl_malloc, only for dm_xenstore_record_pid */
    int domid;
};

void dm_xenstore_record_pid(struct libxl_ctx *ctx, void *for_spawn,
                            pid_t innerchild) {
    struct libxl_device_model_starting *starting = for_spawn;
    struct libxl_ctx clone;
    char *kvs[3];
    int rc;

    clone = *ctx;
    clone.xsh = xs_daemon_open();
    /* we mustn't use the parent's handle in the child */

    kvs[0] = "image/device-model-pid";
    kvs[1] = libxl_sprintf(ctx, "%d", innerchild);
    kvs[2] = NULL;
    rc = libxl_xs_writev(ctx, XBT_NULL, starting->dom_path, kvs);
    if (rc) XL_LOG_ERRNO(ctx, XL_LOG_ERROR,
                         "Couldn't record device model pid %ld at %s/%s",
                         (unsigned long)innerchild, starting->dom_path, kvs);
}

int libxl_create_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl_device_model_starting **starting_r)
{
    char *path, *logfile, *logfile_new;
    struct stat stat_buf;
    int logfile_w, null;
    int i, rc;
    char **args;
    struct libxl_spawn_starting buf_spawn, *for_spawn;

    *starting_r= 0;

    args = libxl_build_device_model_args(ctx, info, vifs, num_vifs);
    if (!args)
        return ERROR_FAIL;

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
    logfile_w = open(logfile, O_WRONLY|O_CREAT, 0644);
    null = open("/dev/null", O_RDONLY);

    if (starting_r) {
        *starting_r= libxl_calloc(ctx, sizeof(**starting_r), 1);
        if (!*starting_r) return ERROR_NOMEM;
        (*starting_r)->domid= info->domid;

        (*starting_r)->dom_path = libxl_xs_get_dompath(ctx, info->domid);
        if (!(*starting_r)->dom_path) { free(*starting_r); return ERROR_FAIL; }

        for_spawn= &(*starting_r)->for_spawn;
    } else {
        for_spawn= &buf_spawn;
    }
    rc = libxl_spawn_spawn(ctx, for_spawn, "device model",
                           dm_xenstore_record_pid);
    if (rc < 0) goto xit;
    if (!rc) { /* inner child */
        libxl_exec(ctx, null, logfile_w, logfile_w,
                   info->device_model, args);
    }

    rc = 0;
 xit:
    close(null);
    close(logfile_w);

    return rc;
}

int libxl_detach_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_starting *starting) {
    int rc;
    rc = libxl_spawn_detach(ctx, &starting->for_spawn);
    libxl_free(ctx, starting);
    return rc;
}


int libxl_confirm_device_model_startup(struct libxl_ctx *ctx,
                                       libxl_device_model_starting *starting) {
    int problem = libxl_wait_for_device_model(ctx, starting->domid, "running",
                                              libxl_spawn_check,
                                              &starting->for_spawn);
    int detach = libxl_detach_device_model(ctx, starting);
    return problem ? problem : detach;
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

            device_physdisk_major_minor(disk->physpath, &major, &minor);
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
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "bootable"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
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
int libxl_device_console_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_console *console)
{
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;

    if (console->build_state) {
        xs_transaction_t t;
        char **ents = (char **) libxl_calloc(ctx, 9, sizeof(char *));
        ents[0] = libxl_sprintf(ctx, "console/port");
        ents[1] = libxl_sprintf(ctx, "%"PRIu32, console->build_state->console_port);
        ents[2] = libxl_sprintf(ctx, "console/ring-ref");
        ents[3] = libxl_sprintf(ctx, "%lu", console->build_state->console_mfn);
        ents[4] = libxl_sprintf(ctx, "console/limit");
        ents[5] = libxl_sprintf(ctx, "%d", LIBXL_XENCONSOLE_LIMIT);
        ents[6] = libxl_sprintf(ctx, "console/type");
        if (console->constype == CONSTYPE_XENCONSOLED)
            ents[7] = "xenconsoled";
        else
            ents[7] = "ioemu";
retry_transaction:
        t = xs_transaction_start(ctx->xsh);
        libxl_xs_writev(ctx, t, xs_get_domain_path(ctx->xsh, console->domid), ents);
        if (!xs_transaction_end(ctx->xsh, t, 0))
            if (errno == EAGAIN)
                goto retry_transaction;
    }

    front = flexarray_make(16, 1);
    if (!front)
        return ERROR_NOMEM;
    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    device.backend_devid = console->devid;
    device.backend_domid = console->backend_domid;
    device.backend_kind = DEVICE_CONSOLE;
    device.devid = console->devid;
    device.domid = console->domid;
    device.kind = DEVICE_CONSOLE;

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", console->domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "domain"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", libxl_domid_to_name(ctx, domid)));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "protocol"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, LIBXL_XENCONSOLE_PROTOCOL));

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", console->backend_domid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "limit"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "protocol"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, LIBXL_XENCONSOLE_PROTOCOL));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "type"));
    if (console->constype == CONSTYPE_XENCONSOLED)
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "xenconsoled"));
    else
        flexarray_set(front, foffset++, libxl_sprintf(ctx, "ioemu"));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));


    return 0;
}

/******************************************************************************/
int libxl_device_vkb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb)
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

    device.backend_devid = vkb->devid;
    device.backend_domid = vkb->backend_domid;
    device.backend_kind = DEVICE_VKBD;
    device.devid = vkb->devid;
    device.domid = vkb->domid;
    device.kind = DEVICE_VKBD;

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vkb->domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "domain"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", libxl_domid_to_name(ctx, domid)));

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", vkb->backend_domid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));

    return 0;
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
static int libxl_build_xenpv_qemu_args(struct libxl_ctx *ctx,
                                       libxl_device_vfb *vfb,
                                       int num_console,
                                       libxl_device_console *console,
                                       libxl_device_model_info *info) {
    int i = 0, j = 0, num = 0;
    memset(info, 0x00, sizeof(libxl_device_model_info));

    info->vnc = vfb->vnc;
    if (vfb->vnclisten)
        info->vnclisten = libxl_sprintf(ctx, "%s", vfb->vnclisten);
    info->vncdisplay = vfb->vncdisplay;
    info->vncunused = vfb->vncunused;
    if (vfb->keymap)
        info->keymap = libxl_sprintf(ctx, "%s", vfb->keymap);
    info->sdl = vfb->sdl;
    info->opengl = vfb->opengl;
    for (i = 0; i < num_console; i++) {
        if (console->constype == CONSTYPE_IOEMU)
            num++;
    }
    if (num > 0) {
        info->serial = "pty";
        num--;
    }
    if (num > 0) {
        info->extra = (char **) libxl_calloc(ctx, num * 2 + 1, sizeof(char *));
        for (j = 0; j < num * 2; j = j + 2) {
            info->extra[j] = "-serial";
            info->extra[j + 1] = "pty";
        }
        info->extra[j] = NULL;
    }
    info->domid = vfb->domid;
    info->dom_name = libxl_domid_to_name(ctx, vfb->domid);
    info->device_model = "/usr/lib/xen/bin/qemu-dm";
    info->type = XENPV;
    return 0;
}

int libxl_create_xenpv_qemu(struct libxl_ctx *ctx, libxl_device_vfb *vfb,
                            int num_console, libxl_device_console *console,
                            struct libxl_device_model_starting **starting_r)
{
    libxl_device_model_info info;

    libxl_build_xenpv_qemu_args(ctx, vfb, num_console, console, &info);
    libxl_create_device_model(ctx, &info, NULL, 0, starting_r);
    return 0;
}

int libxl_device_vfb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb)
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

    device.backend_devid = vfb->devid;
    device.backend_domid = vfb->backend_domid;
    device.backend_kind = DEVICE_VFB;
    device.devid = vfb->devid;
    device.domid = vfb->domid;
    device.kind = DEVICE_VFB;

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "domain"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", libxl_domid_to_name(ctx, domid)));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "vnc"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vnc));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "vnclisten"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", vfb->vnclisten));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "vncdisplay"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vncdisplay));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "vncunused"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vncunused));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "sdl"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->sdl));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "opengl"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->opengl));
    if (vfb->xauthority) {
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "xauthority"));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", vfb->xauthority));
    }
    if (vfb->display) {
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "display"));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", vfb->display));
    }

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", vfb->backend_domid));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));
    flexarray_free(front);
    flexarray_free(back);

    return 0;
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

int libxl_device_pci_init(libxl_device_pci *pcidev, unsigned int domain,
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

static int libxl_create_pci_backend(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev, int num)
{
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;
    int i;

    front = flexarray_make(16, 1);
    if (!front)
        return ERROR_NOMEM;
    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    XL_LOG(ctx, XL_LOG_DEBUG, "Creating pci backend");

    /* add pci device */
    device.backend_devid = 0;
    device.backend_domid = 0;
    device.backend_kind = DEVICE_PCI;
    device.devid = 0;
    device.domid = domid;
    device.kind = DEVICE_PCI;

    flexarray_set(back, boffset++, libxl_sprintf(ctx, "frontend-id"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", domid));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "online"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "1"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "domain"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", libxl_domid_to_name(ctx, domid)));
    for (i = 0; i < num; i++) {
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "key-%d", i));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "dev-%d", i));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
        if (pcidev->vdevfn) {
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "vdevfn-%d", i));
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%x", pcidev->vdevfn));
        }
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "opts-%d", i));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "msitranslate=%d,power_mgmt=%d", pcidev->msitranslate, pcidev->power_mgmt));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "state-%d", i));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    }
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "num_devs"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", num));

    flexarray_set(front, foffset++, libxl_sprintf(ctx, "backend-id"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 0));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));

    flexarray_free(back);
    flexarray_free(front);
    return 0;
}

static int libxl_device_pci_add_xenstore(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    flexarray_t *back;
    char *num_devs, *be_path;
    int num = 0;
    unsigned int boffset = 0;
    xs_transaction_t t;

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", xs_get_domain_path(ctx->xsh, 0), domid);
    num_devs = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/num_devs", be_path));
    if (!num_devs)
        return libxl_create_pci_backend(ctx, domid, pcidev, 1);

    if (!is_hvm(ctx, domid)) {
        if (libxl_wait_for_backend(ctx, be_path, "4") < 0)
            return -1;
    }

    back = flexarray_make(16, 1);
    if (!back)
        return ERROR_NOMEM;

    XL_LOG(ctx, XL_LOG_DEBUG, "Adding new pci device to xenstore");
    num = atoi(num_devs);
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "key-%d", num));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "dev-%d", num));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, PCI_BDF, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func));
    if (pcidev->vdevfn) {
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "vdevfn-%d", num));
        flexarray_set(back, boffset++, libxl_sprintf(ctx, "%x", pcidev->vdevfn));
    }
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "opts-%d", num));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "msitranslate=%d,power_mgmt=%d", pcidev->msitranslate, pcidev->power_mgmt));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state-%d", num));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "num_devs"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", num + 1));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "state"));
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 7));

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    libxl_xs_writev(ctx, t, be_path,
                    libxl_xs_kvs_of_flexarray(ctx, back, boffset));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    flexarray_free(back);
    return 0;
}

static int libxl_device_pci_remove_xenstore(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char *be_path, *num_devs_path, *num_devs, *xsdev;
    int num, i;
    xs_transaction_t t;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0;

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", xs_get_domain_path(ctx->xsh, 0), domid);
    num_devs_path = libxl_sprintf(ctx, "%s/num_devs", be_path);
    num_devs = libxl_xs_read(ctx, XBT_NULL, num_devs_path);
    if (!num_devs)
        return -1;
    num = atoi(num_devs);
    if (num == 1) {
        libxl_device_destroy(ctx, be_path, 1);
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        return 0;
    }

    if (!is_hvm(ctx, domid)) {
        if (libxl_wait_for_backend(ctx, be_path, "4") < 0) {
            XL_LOG(ctx, XL_LOG_DEBUG, "pci backend at %s is not ready");
            return -1;
        }
    }

    for (i = 0; i < num; i++) {
        xsdev = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/dev-%d", be_path, i));
        sscanf(xsdev, PCI_BDF, &domain, &bus, &dev, &func);
        if (domain == pcidev->domain && bus == pcidev->bus &&
            pcidev->dev == dev && pcidev->func == func) {
            break;
        }
    }
    if (i == num) {
        XL_LOG(ctx, XL_LOG_ERROR, "Couldn't find the device on xenstore");
        return -1;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    libxl_xs_write(ctx, t, num_devs_path, "%d", num - 1);
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/state-%d", be_path, i), "6", strlen("6"));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/state", be_path), "7", strlen("7"));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    return 0;
}

int libxl_device_pci_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char path[50];
    char *state, *vdevfn;
    int rc, hvm;

    /* TODO: check if the device can be assigned */

    libxl_device_pci_flr(ctx, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    hvm = is_hvm(ctx, domid);
    if (hvm) {
        if (libxl_wait_for_device_model(ctx, domid, "running", 0,0) < 0) {
            return -1;
        }
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(ctx, XBT_NULL, path);
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/parameter", domid);
        if (pcidev->vdevfn)
            libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF_VDEVFN, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func, pcidev->vdevfn);
        else
            libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func);
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/command", domid);
        xs_write(ctx->xsh, XBT_NULL, path, "pci-ins", strlen("pci-ins"));
        if (libxl_wait_for_device_model(ctx, domid, "pci-inserted", 0,0) < 0)
            XL_LOG(ctx, XL_LOG_ERROR, "Device Model didn't respond in time");
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/parameter", domid);
        vdevfn = libxl_xs_read(ctx, XBT_NULL, path);
        sscanf(vdevfn + 2, "%x", &pcidev->vdevfn);
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/state", domid);
        xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));
    } else {
        char *sysfs_path = libxl_sprintf(ctx, "SYSFS_PCI_DEV/"PCI_BDF"/resource", pcidev->domain,
                                         pcidev->bus, pcidev->dev, pcidev->func);
        FILE *f = fopen(sysfs_path, "r");
        unsigned int start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't open %s", sysfs_path);
            return -1;
        }
        for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
            fscanf(f, "0x%x 0x%x 0x%x", &start, &end, &flags);
            size = end - start + 1;
            if (start) {
                if (flags & PCI_BAR_IO) {
                    rc = xc_domain_ioport_permission(ctx->xch, domid, start, size, 1);
                    if (rc < 0)
                        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "Error: xc_domain_ioport_permission error 0x%x/0x%x", start, size);
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 1);
                    if (rc < 0)
                        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "Error: xc_domain_iomem_permission error 0x%x/0x%x", start, size);
                }
            }
        }
        fclose(f);
        sysfs_path = libxl_sprintf(ctx, "SYSFS_PCI_DEV/"PCI_BDF"/irq", pcidev->domain,
                                   pcidev->bus, pcidev->dev, pcidev->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't open %s", sysfs_path);
            goto out;
        }
        fscanf(f, "%u", &irq);
        if (irq) {
            rc = xc_physdev_map_pirq(ctx->xch, domid, irq, &irq);
            if (rc < 0) {
                XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "Error: xc_physdev_map_pirq irq=%d", irq);
            }
            rc = xc_domain_irq_permission(ctx->xch, domid, irq, 1);
            if (rc < 0) {
                XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "Error: xc_domain_irq_permission irq=%d", irq);
            }
        }
        fclose(f);
    }
out:
    if ((rc = xc_assign_device(ctx->xch, domid, pcidev->value)) < 0)
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_assign_device failed");

    libxl_device_pci_add_xenstore(ctx, domid, pcidev);
    return 0;
}

int libxl_device_pci_remove(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char path[50];
    char *state;
    int hvm, rc;

    /* TODO: check if the device can be detached */

    hvm = is_hvm(ctx, domid);
    if (hvm) {
        if (libxl_wait_for_device_model(ctx, domid, "running", 0,0) < 0) {
            return -1;
        }
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(ctx, XBT_NULL, path);
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/parameter", domid);
        libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF, pcidev->domain,
                       pcidev->bus, pcidev->dev, pcidev->func);
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/command", domid);
        xs_write(ctx->xsh, XBT_NULL, path, "pci-rem", strlen("pci-rem"));
        if (libxl_wait_for_device_model(ctx, domid, "pci-removed", 0,0) < 0) {
            XL_LOG(ctx, XL_LOG_ERROR, "Device Model didn't respond in time");
            return -1;
        }
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/state", domid);
        xs_write(ctx->xsh, XBT_NULL, path, state, strlen(state));
    } else {
        char *sysfs_path = libxl_sprintf(ctx, "SYSFS_PCI_DEV/"PCI_BDF"/resource", pcidev->domain,
                                         pcidev->bus, pcidev->dev, pcidev->func);
        FILE *f = fopen(sysfs_path, "r");
        unsigned int start = 0, end = 0, flags = 0, size = 0;
        int irq = 0;
        int i;

        if (f == NULL) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't open %s", sysfs_path);
            goto skip1;
        }
        for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
            fscanf(f, "0x%x 0x%x 0x%x\n", &start, &end, &flags);
            size = end - start + 1;
            if (start) {
                if (flags & PCI_BAR_IO) {
                    rc = xc_domain_ioport_permission(ctx->xch, domid, start, size, 0);
                    if (rc < 0)
                        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_ioport_permission error 0x%x/0x%x", start, size);
                } else {
                    rc = xc_domain_iomem_permission(ctx->xch, domid, start>>XC_PAGE_SHIFT,
                                                    (size+(XC_PAGE_SIZE-1))>>XC_PAGE_SHIFT, 0);
                    if (rc < 0)
                        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_iomem_permission error 0x%x/0x%x", start, size);
                }
            }
        }
        fclose(f);
skip1:
        sysfs_path = libxl_sprintf(ctx, "SYSFS_PCI_DEV/"PCI_BDF"/irq", pcidev->domain,
                                   pcidev->bus, pcidev->dev, pcidev->func);
        f = fopen(sysfs_path, "r");
        if (f == NULL) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't open %s", sysfs_path);
            goto out;
        }
        fscanf(f, "%u", &irq);
        if (irq) {
            rc = xc_physdev_unmap_pirq(ctx->xch, domid, irq);
            if (rc < 0) {
                XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_physdev_map_pirq irq=%d", irq);
            }
            rc = xc_domain_irq_permission(ctx->xch, domid, irq, 0);
            if (rc < 0) {
                XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_irq_permission irq=%d", irq);
            }
        }
        fclose(f);
    }
out:
    libxl_device_pci_remove_xenstore(ctx, domid, pcidev);

    libxl_device_pci_flr(ctx, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    if ((rc = xc_deassign_device(ctx->xch, domid, pcidev->value)) < 0)
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_deassign_device failed");
    return 0;
}

libxl_device_pci *libxl_device_pci_list(struct libxl_ctx *ctx, uint32_t domid, int *num)
{
    char *be_path, *num_devs, *xsdev, *xsvdevfn, *xsopts;
    int n, i;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;
    libxl_device_pci *pcidevs;

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", xs_get_domain_path(ctx->xsh, 0), domid);
    num_devs = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/num_devs", be_path));
    if (!num_devs) {
        *num = 0;
        return NULL;
    }
    n = atoi(num_devs);
    pcidevs = (libxl_device_pci *) libxl_calloc(ctx, n, sizeof(libxl_device_pci));
    *num = n;

    for (i = 0; i < n; i++) {
        xsdev = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/dev-%d", be_path, i));
        sscanf(xsdev, PCI_BDF, &domain, &bus, &dev, &func);
        xsvdevfn = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/vdevfn-%d", be_path, i));
        if (xsvdevfn)
            vdevfn = strtol(xsvdevfn, (char **) NULL, 16);
        libxl_device_pci_init(pcidevs + i, domain, bus, dev, func, vdevfn);
        xsopts = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/opts-%d", be_path, i));
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
    return pcidevs;
}

int libxl_device_pci_shutdown(struct libxl_ctx *ctx, uint32_t domid)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_list(ctx, domid, &num);
    for (i = 0; i < num; i++) {
        if (libxl_device_pci_remove(ctx, domid, pcidevs + i) < 0)
            return -1;
    }
    return 0;
}

