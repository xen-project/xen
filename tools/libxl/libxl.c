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
    ctx->alloc_ptrs = calloc(ctx->alloc_maxsize, sizeof(void *));
    if (!ctx->alloc_ptrs)
        return ERROR_NOMEM;
    return 0;
}

int libxl_ctx_close(struct libxl_ctx *ctx)
{
    libxl_ctx_free(ctx);
    free(ctx->alloc_ptrs);
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
    char *rw_paths[] = { "device", "device/suspend/event-channel" };
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

    /*
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
    /* Ultimately, handle is an array of 16 uint8_t, same as uuid */
    memcpy(handle, info->uuid, sizeof(xen_domain_handle_t));

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

int libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid, libxl_domain_build_state *state)
{
    char **vments = NULL, **localents = NULL;
    int i;

    build_pre(ctx, domid, info, state);
    if (info->hvm) {
        build_hvm(ctx, domid, info, state);
        vments = libxl_calloc(ctx, 5, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
    } else {
        build_pv(ctx, domid, info, state);
        vments = libxl_calloc(ctx, 9, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char*) info->kernel;
        if (info->u.pv.ramdisk) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char*) info->u.pv.ramdisk;
        }
        if (info->u.pv.cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char*) info->u.pv.cmdline;
        }
    }
    build_post(ctx, domid, info, state, vments, localents);
    return 0;
}

int libxl_domain_restore(struct libxl_ctx *ctx, libxl_domain_build_info *info,
                         uint32_t domid, int fd, libxl_domain_build_state *state,
                         libxl_device_model_info *dm_info)
{
    char **vments = NULL, **localents = NULL;

    build_pre(ctx, domid, info, state);
    restore_common(ctx, domid, info, state, fd);
    if (info->hvm) {
        vments = libxl_calloc(ctx, 5, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
    } else {
        vments = libxl_calloc(ctx, 9, sizeof(char *));
        vments[0] = "image/ostype";
        vments[1] = "linux";
        vments[2] = "image/kernel";
        vments[3] = (char*) info->kernel;
        vments[4] = "image/ramdisk";
        vments[5] = (char*) info->u.pv.ramdisk;
        vments[6] = "image/cmdline";
        vments[7] = (char*) info->u.pv.cmdline;
    }
    build_post(ctx, domid, info, state, vments, localents);
    if (info->hvm)
        asprintf(&(dm_info->saved_state), "/var/lib/xen/qemu-save.%d", domid);
    else
        dm_info->saved_state = NULL;

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
    ptr = calloc(size, sizeof(struct libxl_dominfo));
    if (!ptr)
        return NULL;
redo:
    ret = xc_domain_getinfolist(ctx->xch, first_domain, 16, info);
    for (i = 0; i < ret; i++) {
        if (index == size) {
            struct libxl_dominfo *ptr2;

            ptr2 = calloc(size * 2, sizeof(struct libxl_dominfo));
            if (!ptr2) {
                free(ptr);
                return NULL;
            }
            memcpy(ptr2, ptr, sizeof(struct libxl_dominfo) * size);
            free(ptr);
            ptr = ptr2;
            size *= 2;
        }
        memcpy(&(ptr[index].uuid), info[i].handle, sizeof(xen_domain_handle_t));
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
    info = (xc_dominfo_t *) calloc(size, sizeof(xc_dominfo_t));
    if (!info) {
        *nb_domain = 0;
        return NULL;
    }
    *nb_domain = xc_domain_getinfo(ctx->xch, first_domain, 1024, info);
    return info;
}

static int libxl_save_device_model(struct libxl_ctx *ctx, uint32_t domid, int fd)
{
    int fd2, c;
    char buf[1024];
    char *filename = libxl_sprintf(ctx, "/var/lib/xen/qemu-save.%d", domid);

    XL_LOG(ctx, XL_LOG_DEBUG, "Saving device model state to %s", filename);
    libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid), "save", strlen("save"));
    libxl_wait_for_device_model(ctx, domid, "paused", NULL, NULL);

    write(fd, QEMU_SIGNATURE, strlen(QEMU_SIGNATURE));
    fd2 = open(filename, O_RDONLY);
    while ((c = read(fd2, buf, sizeof(buf))) != 0) {
        write(fd, buf, c);
    }
    close(fd2);
    unlink(filename);
    return 0;
}

int libxl_domain_suspend(struct libxl_ctx *ctx, libxl_domain_suspend_info *info,
                         uint32_t domid, int fd)
{
    int hvm = is_hvm(ctx, domid);
    int live = info != NULL && info->flags & XL_SUSPEND_LIVE;
    int debug = info != NULL && info->flags & XL_SUSPEND_LIVE;


    core_suspend(ctx, domid, fd, hvm, live, debug);
    if (hvm)
        libxl_save_device_model(ctx, domid, fd);

    return 0;
}

int libxl_domain_pause(struct libxl_ctx *ctx, uint32_t domid)
{
    xc_domain_pause(ctx->xch, domid);
    return 0;
}

int libxl_domain_unpause(struct libxl_ctx *ctx, uint32_t domid)
{
    char path[50];
    char *state;

    if (is_hvm(ctx, domid)) {
        snprintf(path, sizeof(path), "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(ctx, XBT_NULL, path);
        if (state != NULL && !strcmp(state, "paused")) {
            libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid), "continue", strlen("continue"));
            libxl_wait_for_device_model(ctx, domid, "running", NULL, NULL);
        }
    }
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

int libxl_wait_for_domain_death(struct libxl_ctx *ctx, uint32_t domid, int *fd)
{
    if (!xs_watch(ctx->xsh, "@releaseDomain", "domain_death"))
        return -1;
    *fd = xs_fileno(ctx->xsh);
    return 0;
}

int libxl_is_domain_dead(struct libxl_ctx *ctx, uint32_t domid, xc_dominfo_t *info)
{
    unsigned int num;
    int nb_domain, i, rc = 0;
    char **vec = NULL;
    xc_dominfo_t *list = NULL;

    vec = xs_read_watch(ctx->xsh, &num);
    if (!vec)
        return 0;
    if (!strcmp(vec[XS_WATCH_TOKEN], "domain_death")) {
        list = libxl_domain_infolist(ctx, &nb_domain);
        for (i = 0; i < nb_domain; i++) {
            if (domid == list[i].domid) {
                if (list[i].running || (!list[i].shutdown && !list[i].crashed && !list[i].dying))
                    goto out;
                *info = list[i];
                rc = 1;
                goto out;
            }
        }
        memset(info, 0x00, sizeof(xc_dominfo_t));
        rc = 1;
        goto out;
    }

out:
    free(list);
    free(vec);
    return rc;
}

static int libxl_destroy_device_model(struct libxl_ctx *ctx, uint32_t domid)
{
    char *pid;
    int ret;

    pid = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/image/device-model-pid", domid));
    if (!pid) {
        int stubdomid = libxl_get_stubdom_id(ctx, domid);
        if (!stubdomid) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't find device model's pid");
            return -1;
        }
        XL_LOG(ctx, XL_LOG_ERROR, "Device model is a stubdom, domid=%d\n", stubdomid);
        return libxl_domain_destroy(ctx, stubdomid, 0);
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
    char *dom_path, *uuid_str;
    char vm_path[UUID_LEN_STR + 5], vss_path[UUID_LEN_STR + 6], xapi_path[20];
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
    if (libxl_destroy_device_model(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_device_model failed for %d", domid);
    if (libxl_devices_destroy(ctx, domid, force) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_devices failed for %d", domid);
    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", dom_path);
    uuid_str = libxl_uuid_to_string(ctx, uuid);
    snprintf(vm_path, sizeof(vm_path), "/vm/%s", uuid_str);
    if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vm_path);
    snprintf(vss_path, sizeof(vss_path), "/vss/%s", uuid_str);
    if (!xs_rm(ctx->xsh, XBT_NULL, vss_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vss_path);
    libxl_free(ctx, uuid_str);
    snprintf(xapi_path, sizeof(xapi_path), "/xapi/%u", domid);
    if (!xs_rm(ctx->xsh, XBT_NULL, xapi_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", xapi_path);
    rc = xc_domain_destroy(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_destroy failed for %d", domid);
        return -1;
    }
    return 0;
}

int libxl_console_attach(struct libxl_ctx *ctx, uint32_t domid, int cons_num)
{
    struct stat st;
    const char *XENCONSOLE = "/usr/lib/xen/bin/xenconsole";
    char *cmd;

    if (stat(XENCONSOLE, &st) != 0) {
        XL_LOG(ctx, XL_LOG_ERROR, "could not access %s", XENCONSOLE);
        return ERROR_FAIL;
    }

    cmd = libxl_sprintf(ctx, "%s %d --num %d", XENCONSOLE, domid, cons_num);
    return (system(cmd) != 0) ? ERROR_FAIL : 0;
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

    flexarray_set(dm_args, num++, "qemu-dm");
    flexarray_set(dm_args, num++, "-d");

    flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%d", info->domid));

    if (info->dom_name) {
        flexarray_set(dm_args, num++, "-domain-name");
        flexarray_set(dm_args, num++, info->dom_name);
    }
    if (info->vnc || info->vncdisplay || info->vnclisten || info->vncunused) {
        flexarray_set(dm_args, num++, "-vnc");
        if (info->vncdisplay) {
            if (info->vnclisten && strchr(info->vnclisten, ':') == NULL) {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s:%d", info->vnclisten, info->vncdisplay));
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "127.0.0.1:%d", info->vncdisplay));
            }
        } else if (info->vnclisten) {
            if (strchr(info->vnclisten, ':') != NULL) {
                flexarray_set(dm_args, num++, info->vnclisten);
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%s:0", info->vnclisten));
            }
        } else {
            flexarray_set(dm_args, num++, "127.0.0.1:0");
        }
        if (info->vncunused) {
            flexarray_set(dm_args, num++, "-vncunused");
        }
    }
    if (info->sdl || info->opengl) {
        flexarray_set(dm_args, num++, "-sdl");
        if (info->opengl) {
            flexarray_set(dm_args, num++, "-disable-opengl");
        }
    }
    if (info->keymap) {
        flexarray_set(dm_args, num++, "-k");
        flexarray_set(dm_args, num++, info->keymap);
    }
    if (info->nographic && (!info->sdl && !info->vnc)) {
        flexarray_set(dm_args, num++, "-nographic");
    }
    if (info->serial) {
        flexarray_set(dm_args, num++, "-serial");
        flexarray_set(dm_args, num++, info->serial);
    }
    if (info->type == XENFV) {
        if (info->videoram) {
            flexarray_set(dm_args, num++, "-videoram");
            flexarray_set(dm_args, num++, libxl_sprintf(ctx, "%d", info->videoram));
        }
        if (info->stdvga) {
            flexarray_set(dm_args, num++, "-std-vga");
        }

        if (info->boot) {
            flexarray_set(dm_args, num++, "-boot");
            flexarray_set(dm_args, num++, info->boot);
        }
        if (info->usb) {
            flexarray_set(dm_args, num++, "-usb");
            if (info->usbdevice) {
                flexarray_set(dm_args, num++, "-usbdevice");
                flexarray_set(dm_args, num++, info->usbdevice);
            }
        }
        if (info->apic) {
            flexarray_set(dm_args, num++, "-acpi");
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == NICTYPE_IOEMU) {
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "nic,vlan=%d,macaddr=%s,model=%s",
                            vifs[i].devid, vifs[i].smac, vifs[i].model));
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "tap,vlan=%d,ifname=%s,bridge=%s",
                            vifs[i].devid, vifs[i].ifname, vifs[i].bridge));
            }
        }
    }
    if (info->saved_state) {
        flexarray_set(dm_args, num++, "-loadvm");
        flexarray_set(dm_args, num++, info->saved_state);
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_set(dm_args, num++, info->extra[i]);
    flexarray_set(dm_args, num++, "-M");
    if (info->type == XENPV)
        flexarray_set(dm_args, num++, "xenpv");
    else
        flexarray_set(dm_args, num++, "xenfv");
    flexarray_set(dm_args, num++, NULL);

    return (char **) flexarray_contents(dm_args);
}

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
    kvs[1] = libxl_sprintf(&clone, "%d", innerchild);
    kvs[2] = NULL;
    rc = libxl_xs_writev(&clone, XBT_NULL, starting->dom_path, kvs);
    if (rc) XL_LOG_ERRNO(&clone, XL_LOG_ERROR,
                         "Couldn't record device model pid %ld at %s/%s",
                         (unsigned long)innerchild, starting->dom_path, kvs);
    xs_daemon_close(clone.xsh);
}

static int libxl_vfb_and_vkb_from_device_model_info(struct libxl_ctx *ctx,
                                                    libxl_device_model_info *info,
                                                    libxl_device_vfb *vfb,
                                                    libxl_device_vkb *vkb)
{
    memset(vfb, 0x00, sizeof(libxl_device_vfb));
    memset(vkb, 0x00, sizeof(libxl_device_vkb));

    vfb->backend_domid = 0;
    vfb->devid = 0;
    vfb->vnc = info->vnc;
    vfb->vnclisten = info->vnclisten;
    vfb->vncdisplay = info->vncdisplay;
    vfb->vncunused = info->vncunused;
    vfb->keymap = info->keymap;
    vfb->sdl = info->sdl;
    vfb->opengl = info->opengl;

    vkb->backend_domid = 0;
    vkb->devid = 0;
    return 0;
}

static int libxl_write_dmargs(struct libxl_ctx *ctx, int domid, int guest_domid, char **args)
{
    int i;
    char *vm_path;
    char *dmargs, *path;
    int dmargs_size;
    struct xs_permissions roperm[2];
    xs_transaction_t t;

    roperm[0].id = 0;
    roperm[0].perms = XS_PERM_NONE;
    roperm[1].id = domid;
    roperm[1].perms = XS_PERM_READ;

    vm_path = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/vm", guest_domid));

    i = 0;
    dmargs_size = 0;
    while (args[i] != NULL) {
        dmargs_size = dmargs_size + strlen(args[i]) + 1;
        i++;
    }
    dmargs_size++;
    dmargs = (char *) malloc(dmargs_size);
    i = 1;
    dmargs[0] = '\0';
    while (args[i] != NULL) {
        if (strcmp(args[i], "-sdl") && strcmp(args[i], "-M") && strcmp(args[i], "xenfv")) {
            strcat(dmargs, " ");
            strcat(dmargs, args[i]);
        }
        i++;
    }
    path = libxl_sprintf(ctx, "%s/image/dmargs", vm_path);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, path, dmargs, strlen(dmargs));
    xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(ctx, "%s/rtc/timeoffset", vm_path), roperm, ARRAY_SIZE(roperm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    free(dmargs);
    return 0;
}

static int libxl_create_stubdom(struct libxl_ctx *ctx,
                                libxl_device_model_info *info,
                                libxl_device_disk *disks, int num_disks,
                                libxl_device_nic *vifs, int num_vifs,
                                libxl_device_vfb *vfb,
                                libxl_device_vkb *vkb,
                                libxl_device_model_starting **starting_r)
{
    int i, num_console = 1;
    libxl_device_console *console;
    libxl_domain_create_info c_info;
    libxl_domain_build_info b_info;
    libxl_domain_build_state state;
    uint32_t domid;
    char **args;
    xen_uuid_t uuid[16];
    struct xs_permissions perm[2];
    xs_transaction_t t;
    libxl_device_model_starting *dm_starting = 0;

    args = libxl_build_device_model_args(ctx, info, vifs, num_vifs);
    if (!args)
        return ERROR_FAIL;

    memset(&c_info, 0x00, sizeof(libxl_domain_create_info));
    c_info.hvm = 0;
    c_info.name = libxl_sprintf(ctx, "%s-dm", libxl_domid_to_name(ctx, info->domid));
    xen_uuid_generate(uuid);
    c_info.uuid = uuid;

    memset(&b_info, 0x00, sizeof(libxl_domain_build_info));
    b_info.max_vcpus = 1;
    b_info.max_memkb = 32 * 1024;
    b_info.kernel = "/usr/lib/xen/boot/ioemu-stubdom.gz";
    b_info.u.pv.cmdline = libxl_sprintf(ctx, " -d %d", info->domid);
    b_info.u.pv.ramdisk = "";
    b_info.u.pv.features = "";
    b_info.hvm = 0;

    libxl_domain_make(ctx, &c_info, &domid);
    libxl_domain_build(ctx, &b_info, domid, &state);

    libxl_write_dmargs(ctx, domid, info->domid, args);
    libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/image/device-model-domid", libxl_xs_get_dompath(ctx, info->domid)), "%d", domid);
    libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/target", libxl_xs_get_dompath(ctx, domid)), "%d", info->domid);
    xc_domain_set_target(ctx->xch, domid, info->domid);
    xs_set_target(ctx->xsh, domid, info->domid);

    perm[0].id = domid;
    perm[0].perms = XS_PERM_NONE;
    perm[1].id = info->domid;
    perm[1].perms = XS_PERM_READ;
retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_mkdir(ctx->xsh, t, libxl_sprintf(ctx, "/local/domain/0/device-model/%d", info->domid));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(ctx, "/local/domain/0/device-model/%d", info->domid), perm, ARRAY_SIZE(perm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    for (i = 0; i < num_disks; i++) {
        libxl_device_disk disk = disks[i];
        disk_info_domid_fixup(&disk, domid);
        libxl_device_disk_add(ctx, domid, &disk);
    }
    for (i = 0; i < num_vifs; i++) {
        libxl_device_nic nic = vifs[i];
        nic_info_domid_fixup(&nic, domid);
        libxl_device_nic_add(ctx, domid, &nic);
    }
    vfb_info_domid_fixup(vfb, domid);
    libxl_device_vfb_add(ctx, domid, vfb);
    vkb_info_domid_fixup(vkb, domid);
    libxl_device_vkb_add(ctx, domid, vkb);

    if (info->serial)
        num_console++;
    console = libxl_calloc(ctx, num_console, sizeof(libxl_device_console));
    for (i = 0; i < num_console; i++) {
        if (!i)
            init_console_info(&console[i], i, &state);
        else
            init_console_info(&console[i], i, NULL);
        console_info_domid_fixup(&console[i], domid);
        console[i].constype = CONSTYPE_IOEMU;
        libxl_device_console_add(ctx, domid, &console[i]);
    }
    if (libxl_create_xenpv_qemu(ctx, vfb, num_console, console, &dm_starting) < 0) {
        free(args);
        return -1;
    }
    if (libxl_confirm_device_model_startup(ctx, dm_starting) < 0) {
        free(args);
        return -1;
    }

    libxl_domain_unpause(ctx, domid);

    if (starting_r) {
        *starting_r = libxl_calloc(ctx, sizeof(libxl_device_model_starting), 1);
        (*starting_r)->domid = info->domid;
        (*starting_r)->dom_path = libxl_xs_get_dompath(ctx, info->domid);
        (*starting_r)->for_spawn = NULL;
    }

    free(args);
    return 0;
}

int libxl_create_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_disk *disks, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl_device_model_starting **starting_r)
{
    char *path, *logfile;
    int logfile_w, null;
    int rc;
    char **args;
    struct libxl_device_model_starting buf_starting, *p;

    if (strstr(info->device_model, "stubdom-dm")) {
        libxl_device_vfb vfb;
        libxl_device_vkb vkb;

        libxl_vfb_and_vkb_from_device_model_info(ctx, info, &vfb, &vkb);
        return libxl_create_stubdom(ctx, info, disks, num_disks, vifs, num_vifs, &vfb, &vkb, starting_r);
    }

    args = libxl_build_device_model_args(ctx, info, vifs, num_vifs);
    if (!args)
        return ERROR_FAIL;

    path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d", info->domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);

    libxl_create_logfile(ctx, libxl_sprintf(ctx, "qemu-dm-%s", info->dom_name), &logfile);
    logfile_w = open(logfile, O_WRONLY|O_CREAT, 0644);
    free(logfile);
    null = open("/dev/null", O_RDONLY);

    if (starting_r) {
        rc = ERROR_NOMEM;
        *starting_r = libxl_calloc(ctx, sizeof(libxl_device_model_starting), 1);
        if (!*starting_r) goto xit;
        p = *starting_r;
        p->for_spawn = libxl_calloc(ctx, sizeof(struct libxl_spawn_starting), 1);
    } else {
        p = &buf_starting;
        p->for_spawn = NULL;
    }

    p->domid = info->domid;
    p->dom_path = libxl_xs_get_dompath(ctx, info->domid);
    if (!p->dom_path) { libxl_free(ctx, p); return ERROR_FAIL; }

    rc = libxl_spawn_spawn(ctx, p, "device model", dm_xenstore_record_pid);
    if (rc < 0) goto xit;
    if (!rc) { /* inner child */
        libxl_exec(ctx, null, logfile_w, logfile_w,
                   info->device_model, args);
    }

    rc = 0;
 xit:
    free(args);
    close(null);
    close(logfile_w);

    return rc;
}

int libxl_detach_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_starting *starting) {
    int rc;
    rc = libxl_spawn_detach(ctx, starting->for_spawn);
    if (starting->for_spawn) libxl_free(ctx, starting->for_spawn);
    libxl_free(ctx, starting);
    return rc;
}


int libxl_confirm_device_model_startup(struct libxl_ctx *ctx,
                                       libxl_device_model_starting *starting) {
    int problem = libxl_wait_for_device_model(ctx, starting->domid, "running",
                                              libxl_spawn_check,
                                              starting->for_spawn);
    int detach = libxl_detach_device_model(ctx, starting);
    return problem ? problem : detach;
    return 0;
}


/******************************************************************************/

static int is_blktap2_supported(void)
{
    char buf[1024];
    FILE *f = fopen("/proc/devices", "r");

    
    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (strstr(buf, "blktap2")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static char *get_blktap2_device(struct libxl_ctx *ctx, char *name, char *type)
{
    char buf[1024];
    char *p;
    int devnum;
    FILE *f = fopen("/sys/class/blktap2/devices", "r");

    
    while (!feof(f)) {
        fscanf(f, "%d %s", &devnum, buf);
        p = strchr(buf, ':');
        if (p == NULL)
            continue;
        p++;
        if (!strcmp(p, name) && !strncmp(buf, type, 3)) {
            fclose(f);
            return libxl_sprintf(ctx, "/dev/xen/blktap-2/tapdev%d", devnum);
        }
    }
    fclose(f);
    return NULL;
}

int libxl_device_disk_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk)
{
    flexarray_t *front;
    flexarray_t *back;
    char *backend_type;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    int devid;
    libxl_device device;
    int major, minor;

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
        case PHYSTYPE_PHY: {

            device_physdisk_major_minor(disk->physpath, &major, &minor);
            flexarray_set(back, boffset++, "physical-device");
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%x:%x", major, minor));

            flexarray_set(back, boffset++, "params");
            flexarray_set(back, boffset++, disk->physpath);

            device.backend_kind = DEVICE_VBD;
            break;
        }
        case PHYSTYPE_FILE:
            /* let's pretend is tap:aio for the moment */
            disk->phystype = PHYSTYPE_AIO;
        case PHYSTYPE_AIO: case PHYSTYPE_QCOW: case PHYSTYPE_QCOW2: case PHYSTYPE_VHD:
            if (is_blktap2_supported()) {
                int rc, c, p[2], tot;
                char buf[1024], *dev;
                if ((dev = get_blktap2_device(ctx, disk->physpath, device_disk_string_of_phystype(disk->phystype))) == NULL) {
                    if (pipe(p) < 0) {
                        XL_LOG(ctx, XL_LOG_ERROR, "Failed to create a pipe");
                        return -1;
                    }
                    rc = fork();
                    if (rc < 0) {
                        XL_LOG(ctx, XL_LOG_ERROR, "Failed to fork a new process");
                        return -1;
                    } else if (!rc) { /* child */
                        int null_r, null_w;
                        char *args[4];
                        args[0] = "tapdisk2";
                        args[1] = "-n";
                        args[2] = libxl_sprintf(ctx, "%s:%s", device_disk_string_of_phystype(disk->phystype), disk->physpath);
                        args[3] = NULL;

                        null_r = open("/dev/null", O_RDONLY);
                        null_w = open("/dev/null", O_WRONLY);
                        libxl_exec(ctx, null_r, p[1], null_w, "/usr/sbin/tapdisk2", args);
                        XL_LOG(ctx, XL_LOG_ERROR, "Error execing tapdisk2");
                    }
                    close(p[1]);
                    tot = 0;
                    while ((c = read(p[0], buf + tot, sizeof(buf) - tot)) > 0)
                        tot = tot + c;
                    close(p[0]);
                    buf[tot - 1] = '\0';
                    dev = buf;
                }
                flexarray_set(back, boffset++, "tapdisk-params");
                flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s:%s", device_disk_string_of_phystype(disk->phystype), disk->physpath));
                flexarray_set(back, boffset++, "params");
                flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s", dev));
                backend_type = "phy";
                device_physdisk_major_minor(dev, &major, &minor);
                flexarray_set(back, boffset++, "physical-device");
                flexarray_set(back, boffset++, libxl_sprintf(ctx, "%x:%x", major, minor));
                device.backend_kind = DEVICE_VBD;

                break;
            }
            flexarray_set(back, boffset++, "params");
            flexarray_set(back, boffset++, libxl_sprintf(ctx, "%s:%s",
                          device_disk_string_of_phystype(disk->phystype), disk->physpath));

            device.backend_kind = DEVICE_TAP;
            break;
    }

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", disk->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "removable");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", (disk->unpluggable) ? 1 : 0));
    flexarray_set(back, boffset++, "bootable");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "dev");
    flexarray_set(back, boffset++, disk->virtpath);
    flexarray_set(back, boffset++, "type");
    flexarray_set(back, boffset++, backend_type);
    flexarray_set(back, boffset++, "mode");
    flexarray_set(back, boffset++, disk->readwrite ? "w" : "r");

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", disk->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, "virtual-device");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", devid));
    flexarray_set(front, foffset++, "device-type");
    flexarray_set(front, foffset++, disk->is_cdrom ? "cdrom" : "disk");

    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, "protocol");
        flexarray_set(front, foffset++, "x86_32-abi"); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));
    flexarray_free(back);
    flexarray_free(front);
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

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", nic->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "script");
    flexarray_set(back, boffset++, nic->script);
    flexarray_set(back, boffset++, "mac");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                 nic->mac[0], nic->mac[1], nic->mac[2],
                                                 nic->mac[3], nic->mac[4], nic->mac[5]));
    flexarray_set(back, boffset++, "handle");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", nic->devid));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", nic->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, "handle");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", nic->devid));
    flexarray_set(front, foffset++, "mac");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  nic->mac[0], nic->mac[1], nic->mac[2],
                                                  nic->mac[3], nic->mac[4], nic->mac[5]));
    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, "protocol");
        flexarray_set(front, foffset++, "x86_32-abi"); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));

    /* FIXME: wait for plug */
    flexarray_free(back);
    flexarray_free(front);
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
        ents[0] = "console/port";
        ents[1] = libxl_sprintf(ctx, "%"PRIu32, console->build_state->console_port);
        ents[2] = "console/ring-ref";
        ents[3] = libxl_sprintf(ctx, "%lu", console->build_state->console_mfn);
        ents[4] = "console/limit";
        ents[5] = libxl_sprintf(ctx, "%d", LIBXL_XENCONSOLE_LIMIT);
        ents[6] = "console/type";
        if (console->constype == CONSTYPE_XENCONSOLED)
            ents[7] = "xenconsoled";
        else
            ents[7] = "ioemu";
retry_transaction:
        t = xs_transaction_start(ctx->xsh);
        libxl_xs_writev(ctx, t, libxl_xs_get_dompath(ctx, console->domid), ents);
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

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", console->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, libxl_domid_to_name(ctx, domid));
    flexarray_set(back, boffset++, "protocol");
    flexarray_set(back, boffset++, LIBXL_XENCONSOLE_PROTOCOL);

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", console->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(front, foffset++, "limit");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_set(front, foffset++, "protocol");
    flexarray_set(front, foffset++, LIBXL_XENCONSOLE_PROTOCOL);
    flexarray_set(front, foffset++, "type");
    if (console->constype == CONSTYPE_XENCONSOLED)
        flexarray_set(front, foffset++, "xenconsoled");
    else
        flexarray_set(front, foffset++, "ioemu");

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));
    flexarray_free(back);
    flexarray_free(front);

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

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vkb->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, libxl_domid_to_name(ctx, domid));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", vkb->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(ctx, back, boffset),
                             libxl_xs_kvs_of_flexarray(ctx, front, foffset));
    flexarray_free(back);
    flexarray_free(front);

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
        uint32_t guest_domid = libxl_is_stubdom(ctx, vfb->domid);
        if (guest_domid) {
            char *filename;
            char *name = libxl_sprintf(ctx, "qemu-dm-%s", libxl_domid_to_name(ctx, guest_domid));
            libxl_create_logfile(ctx, name, &filename);
            info->serial = libxl_sprintf(ctx, "file:%s", filename);
            free(filename);
        } else {
            info->serial = "pty";
        }
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
    libxl_create_device_model(ctx, &info, NULL, 0, NULL, 0, starting_r);
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

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, libxl_domid_to_name(ctx, domid));
    flexarray_set(back, boffset++, "vnc");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vnc));
    flexarray_set(back, boffset++, "vnclisten");
    flexarray_set(back, boffset++, vfb->vnclisten);
    flexarray_set(back, boffset++, "vncdisplay");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vncdisplay));
    flexarray_set(back, boffset++, "vncunused");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->vncunused));
    flexarray_set(back, boffset++, "sdl");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->sdl));
    flexarray_set(back, boffset++, "opengl");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", vfb->opengl));
    if (vfb->xauthority) {
        flexarray_set(back, boffset++, "xauthority");
        flexarray_set(back, boffset++, vfb->xauthority);
    }
    if (vfb->display) {
        flexarray_set(back, boffset++, "display");
        flexarray_set(back, boffset++, vfb->display);
    }

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", vfb->backend_domid));
    flexarray_set(front, foffset++, "state");
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

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, libxl_domid_to_name(ctx, domid));
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
    flexarray_set(back, boffset++, "num_devs");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", num));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(ctx, "%d", 0));
    flexarray_set(front, foffset++, "state");
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

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", libxl_xs_get_dompath(ctx, 0), domid);
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
    flexarray_set(back, boffset++, "num_devs");
    flexarray_set(back, boffset++, libxl_sprintf(ctx, "%d", num + 1));
    flexarray_set(back, boffset++, "state");
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
    char *be_path, *num_devs_path, *num_devs, *xsdev, *tmp, *tmppath;
    int num, i, j;
    xs_transaction_t t;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0;

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", libxl_xs_get_dompath(ctx, 0), domid);
    num_devs_path = libxl_sprintf(ctx, "%s/num_devs", be_path);
    num_devs = libxl_xs_read(ctx, XBT_NULL, num_devs_path);
    if (!num_devs)
        return -1;
    num = atoi(num_devs);

    if (!is_hvm(ctx, domid)) {
        if (libxl_wait_for_backend(ctx, be_path, "4") < 0) {
            XL_LOG(ctx, XL_LOG_DEBUG, "pci backend at %s is not ready", be_path);
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
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/state-%d", be_path, i), "5", strlen("5"));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/state", be_path), "7", strlen("7"));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    if (!is_hvm(ctx, domid)) {
        if (libxl_wait_for_backend(ctx, be_path, "4") < 0) {
            XL_LOG(ctx, XL_LOG_DEBUG, "pci backend at %s is not ready", be_path);
            return -1;
        }
    }

retry_transaction2:
    t = xs_transaction_start(ctx->xsh);
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/state-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/key-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/dev-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/vdev-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/opts-%d", be_path, i));
    xs_rm(ctx->xsh, t, libxl_sprintf(ctx, "%s/vdevfn-%d", be_path, i));
    libxl_xs_write(ctx, t, num_devs_path, "%d", num - 1);
    for (j = i + 1; j < num; j++) {
        tmppath = libxl_sprintf(ctx, "%s/state-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/state-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl_sprintf(ctx, "%s/dev-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/dev-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl_sprintf(ctx, "%s/key-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/key-%d", be_path, j - 1), tmp, strlen(tmp));
        xs_rm(ctx->xsh, t, tmppath);
        tmppath = libxl_sprintf(ctx, "%s/vdev-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/vdev-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = libxl_sprintf(ctx, "%s/opts-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/opts-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
        tmppath = libxl_sprintf(ctx, "%s/vdevfn-%d", be_path, j);
        tmp = libxl_xs_read(ctx, t, tmppath);
        if (tmp) {
            xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/vdevfn-%d", be_path, j - 1), tmp, strlen(tmp));
            xs_rm(ctx->xsh, t, tmppath);
        }
    }
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction2;

    if (num == 1) {
        char *fe_path = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/frontend", be_path));
        libxl_device_destroy(ctx, be_path, 1);
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        xs_rm(ctx->xsh, XBT_NULL, fe_path);
        return 0;
    }

    return 0;
}

int libxl_device_pci_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char path[50];
    char *state, *vdevfn;
    int rc, hvm;
    int stubdomid = 0;

    /* TODO: check if the device can be assigned */

    libxl_device_pci_flr(ctx, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    if ((stubdomid = libxl_get_stubdom_id(ctx, domid)) != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        libxl_device_pci_add(ctx, stubdomid, &pcidev_s);
    }

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
        char *sysfs_path = libxl_sprintf(ctx, SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
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
        sysfs_path = libxl_sprintf(ctx, SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
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
    if (!libxl_is_stubdom(ctx, domid)) {
        if ((rc = xc_assign_device(ctx->xch, domid, pcidev->value)) < 0)
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_assign_device failed");
    }

    libxl_device_pci_add_xenstore(ctx, domid, pcidev);
    return 0;
}

int libxl_device_pci_remove(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char path[50];
    char *state;
    int hvm, rc;
    int stubdomid = 0;

    /* TODO: check if the device can be detached */
    libxl_device_pci_remove_xenstore(ctx, domid, pcidev);

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
        char *sysfs_path = libxl_sprintf(ctx, SYSFS_PCI_DEV"/"PCI_BDF"/resource", pcidev->domain,
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
        sysfs_path = libxl_sprintf(ctx, SYSFS_PCI_DEV"/"PCI_BDF"/irq", pcidev->domain,
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
    libxl_device_pci_flr(ctx, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    if (!libxl_is_stubdom(ctx, domid)) {
        if ((rc = xc_deassign_device(ctx->xch, domid, pcidev->value)) < 0)
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_deassign_device failed");
    }

    if ((stubdomid = libxl_get_stubdom_id(ctx, domid)) != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        libxl_device_pci_remove(ctx, stubdomid, &pcidev_s);
    }

    return 0;
}

libxl_device_pci *libxl_device_pci_list(struct libxl_ctx *ctx, uint32_t domid, int *num)
{
    char *be_path, *num_devs, *xsdev, *xsvdevfn, *xsopts;
    int n, i;
    unsigned int domain = 0, bus = 0, dev = 0, func = 0, vdevfn = 0;
    libxl_device_pci *pcidevs;

    be_path = libxl_sprintf(ctx, "%s/backend/pci/%d/0", libxl_xs_get_dompath(ctx, 0), domid);
    num_devs = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/num_devs", be_path));
    if (!num_devs) {
        *num = 0;
        return NULL;
    }
    n = atoi(num_devs);
    pcidevs = (libxl_device_pci *) calloc(n, sizeof(libxl_device_pci));
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
    free(pcidevs);
    return 0;
}

void nic_info_domid_fixup(libxl_device_nic *nic_info, int domid)
{
    nic_info->domid = domid;
    asprintf(&(nic_info->ifname), "tap%d.%d", domid, nic_info->devid - 1);
}

void disk_info_domid_fixup(libxl_device_disk *disk_info, int domid)
{
    disk_info->domid = domid;
}

void vfb_info_domid_fixup(libxl_device_vfb *vfb, int domid)
{
    vfb->domid = domid;
}

void vkb_info_domid_fixup(libxl_device_vkb *vkb, int domid)
{
    vkb->domid = domid;
}

void console_info_domid_fixup(libxl_device_console *console, int domid)
{
    console->domid = domid;
}

void device_model_info_domid_fixup(libxl_device_model_info *dm_info, int domid)
{
    dm_info->domid = domid;
}

void init_create_info(libxl_domain_create_info *c_info)
{
    memset(c_info, '\0', sizeof(*c_info));
    c_info->xsdata = NULL;
    c_info->platformdata = NULL;
    c_info->hvm = 1;
    c_info->ssidref = 0;
}

void init_build_info(libxl_domain_build_info *b_info, libxl_domain_create_info *c_info)
{
    memset(b_info, '\0', sizeof(*b_info));
    b_info->timer_mode = -1;
    b_info->hpet = 1;
    b_info->vpt_align = -1;
    b_info->max_vcpus = 1;
    b_info->max_memkb = 32 * 1024;
    if (c_info->hvm) {
        b_info->shadow_memkb = libxl_get_required_shadow_memory(b_info->max_memkb, b_info->max_vcpus);
        b_info->video_memkb = 8 * 1024;
        b_info->kernel = "/usr/lib/xen/boot/hvmloader";
        b_info->hvm = 1;
        b_info->u.hvm.pae = 1;
        b_info->u.hvm.apic = 1;
        b_info->u.hvm.acpi = 1;
        b_info->u.hvm.nx = 1;
        b_info->u.hvm.viridian = 0;
    }
}

void init_dm_info(libxl_device_model_info *dm_info,
        libxl_domain_create_info *c_info, libxl_domain_build_info *b_info)
{
    memset(dm_info, '\0', sizeof(*dm_info));

    dm_info->dom_name = c_info->name;
    dm_info->device_model = "/usr/lib/xen/bin/qemu-dm";
    dm_info->videoram = b_info->video_memkb / 1024;
    dm_info->apic = b_info->u.hvm.apic;

    dm_info->stdvga = 0;
    dm_info->vnc = 1;
    dm_info->vnclisten = "127.0.0.1";
    dm_info->vncdisplay = 0;
    dm_info->vncunused = 0;
    dm_info->keymap = NULL;
    dm_info->sdl = 0;
    dm_info->opengl = 0;
    dm_info->nographic = 0;
    dm_info->serial = NULL;
    dm_info->boot = "cda";
    dm_info->usb = 0;
    dm_info->usbdevice = NULL;
}

void init_nic_info(libxl_device_nic *nic_info, int devnum)
{
    memset(nic_info, '\0', sizeof(*nic_info));


    nic_info->backend_domid = 0;
    nic_info->domid = 0;
    nic_info->devid = devnum;
    nic_info->mtu = 1492;
    nic_info->model = "e1000";
    srand(time(0));
    nic_info->mac[0] = 0x00;
    nic_info->mac[1] = 0x16;
    nic_info->mac[2] = 0x3e;
    nic_info->mac[3] = 1 + (int) (0x7f * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[4] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    nic_info->mac[5] = 1 + (int) (0xff * (rand() / (RAND_MAX + 1.0)));
    asprintf(&(nic_info->smac), "%02x:%02x:%02x:%02x:%02x:%02x", nic_info->mac[0], nic_info->mac[1], nic_info->mac[2], nic_info->mac[3], nic_info->mac[4], nic_info->mac[5]);
    nic_info->ifname = NULL;
    nic_info->bridge = "xenbr0";
    nic_info->script = "/etc/xen/scripts/vif-bridge";
    nic_info->nictype = NICTYPE_IOEMU;
}

void init_vfb_info(libxl_device_vfb *vfb, int dev_num)
{
    memset(vfb, 0x00, sizeof(libxl_device_vfb));
    vfb->devid = dev_num;
    vfb->vnc = 1;
    vfb->vnclisten = "127.0.0.1";
    vfb->vncdisplay = 0;
    vfb->vncunused = 1;
    vfb->keymap = NULL;
    vfb->sdl = 0;
    vfb->opengl = 0;
}

void init_vkb_info(libxl_device_vkb *vkb, int dev_num)
{
    memset(vkb, 0x00, sizeof(libxl_device_vkb));
    vkb->devid = dev_num;
}

void init_console_info(libxl_device_console *console, int dev_num, libxl_domain_build_state *state)
{
    memset(console, 0x00, sizeof(libxl_device_console));
    console->devid = dev_num;
    console->constype = CONSTYPE_XENCONSOLED;
    if (state)
        console->build_state = state;
}


