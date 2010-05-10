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

#define PAGE_TO_MEMKB(pages) ((pages) * 4)

int libxl_ctx_init(struct libxl_ctx *ctx, int version)
{
    if (version != LIBXL_VERSION)
        return ERROR_VERSION;
    memset(ctx, 0, sizeof(struct libxl_ctx));
    ctx->alloc_maxsize = 256;
    ctx->alloc_ptrs = calloc(ctx->alloc_maxsize, sizeof(void *));
    if (!ctx->alloc_ptrs)
        return ERROR_NOMEM;
    memset(&ctx->version_info, 0, sizeof(libxl_version_info));

    ctx->xch = xc_interface_open();
    if (ctx->xch == -1) {
        free(ctx->alloc_ptrs);
        return ERROR_FAIL;
    }

    ctx->xsh = xs_daemon_open();
    if (!ctx->xsh) {
        xc_interface_close(ctx->xch);
        free(ctx->alloc_ptrs);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_ctx_free(struct libxl_ctx *ctx)
{
    libxl_free_all(ctx);
    free(ctx->alloc_ptrs);
    xc_interface_close(ctx->xch);
    if (ctx->xsh) xs_daemon_close(ctx->xsh); 
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
    int flags, ret, i, rc;
    char *uuid_string;
    char *rw_paths[] = { "device", "device/suspend/event-channel" , "data"};
    char *ro_paths[] = { "cpu", "memory", "device", "error", "drivers",
                         "control", "attr", "messages" };
    char *dom_path, *vm_path, *vss_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    xs_transaction_t t;
    xen_domain_handle_t handle;

    uuid_string = libxl_uuid2string(ctx, info->uuid);
    if (!uuid_string) return ERROR_NOMEM;

    flags = info->hvm ? XEN_DOMCTL_CDF_hvm_guest : 0;
    flags |= info->hap ? XEN_DOMCTL_CDF_hap : 0;
    flags |= info->oos ? 0 : XEN_DOMCTL_CDF_oos_off;
    *domid = -1;

    /* Ultimately, handle is an array of 16 uint8_t, same as uuid */
    memcpy(handle, info->uuid, sizeof(xen_domain_handle_t));

    ret = xc_domain_create(ctx->xch, info->ssidref, handle, flags, domid);
    if (ret < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "domain creation fail");
        return ERROR_FAIL;
    }

    ret = xc_cpupool_movedomain(ctx->xch, info->poolid, *domid);
    if (ret < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "domain move fail");
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
    rc = libxl_domain_rename(ctx, *domid, 0, info->name, t);
    if (rc) return rc;

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
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/pool_name", vm_path), info->poolname, strlen(info->poolname));

    libxl_xs_writev(ctx, t, dom_path, info->xsdata);
    libxl_xs_writev(ctx, t, libxl_sprintf(ctx, "%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    return 0;
}

int libxl_domain_rename(struct libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name,
                        xs_transaction_t trans) {
    char *dom_path = 0;
    const char *name_path;
    char *got_old_name;
    unsigned int got_old_len;
    xs_transaction_t our_trans = 0;
    int rc;

    dom_path = libxl_xs_get_dompath(ctx, domid);
    if (!dom_path) goto x_nomem;

    name_path= libxl_sprintf(ctx, "%s/name", dom_path);
    if (!name_path) goto x_nomem;

 retry_transaction:
    if (!trans) {
        trans = our_trans = xs_transaction_start(ctx->xsh);
        if (!our_trans) {
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, errno,
                            "create xs transaction for domain (re)name");
            goto x_fail;
        }
    }

    if (old_name) {
        got_old_name = xs_read(ctx->xsh, trans, name_path, &got_old_len);
        if (!got_old_name) {
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, errno, "check old name"
                            " for domain %"PRIu32" allegedly named `%s'",
                            domid, old_name);
            goto x_fail;
        }
        if (strcmp(old_name, got_old_name)) {
            XL_LOG(ctx, XL_LOG_ERROR, "domain %"PRIu32" allegedly named "
                   "`%s' is actually named `%s' - racing ?",
                   domid, old_name, got_old_name);
            free(got_old_name);
            goto x_fail;
        }
        free(got_old_name);
    }
    if (!xs_write(ctx->xsh, trans, name_path,
                  new_name, strlen(new_name))) {
        XL_LOG(ctx, XL_LOG_ERROR, "failed to write new name `%s'"
               " for domain %"PRIu32" previously named `%s'",
               domid, new_name, old_name);
        goto x_fail;
    }

    if (our_trans) {
        if (!xs_transaction_end(ctx->xsh, our_trans, 0)) {
            trans = our_trans = 0;
            if (errno != EAGAIN) {
                XL_LOG(ctx, XL_LOG_ERROR, "failed to commit new name `%s'"
                       " for domain %"PRIu32" previously named `%s'",
                       domid, new_name, old_name);
                goto x_fail;
            }
            XL_LOG(ctx, XL_LOG_DEBUG, "need to retry rename transaction"
                   " for domain %"PRIu32" (name_path=\"%s\", new_name=\"%s\")",
                   domid, name_path, new_name);
            goto retry_transaction;
        }
        our_trans = 0;
    }

    rc = 0;
 x_rc:
    if (dom_path) libxl_free(ctx, dom_path);
    if (our_trans) xs_transaction_end(ctx->xsh, our_trans, 1);
    return rc;

 x_fail:  rc = ERROR_FAIL;  goto x_rc;
 x_nomem: rc = ERROR_NOMEM; goto x_rc;
}

int libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid, libxl_domain_build_state *state)
{
    char **vments = NULL, **localents = NULL;
    int i, ret;

    ret = build_pre(ctx, domid, info, state);
    if (ret) goto out;

    if (info->hvm) {
        ret = build_hvm(ctx, domid, info, state);
        if (ret) goto out;

        vments = libxl_calloc(ctx, 5, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
    } else {
        ret = build_pv(ctx, domid, info, state);
        if (ret) goto out;

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
    ret = build_post(ctx, domid, info, state, vments, localents);
out:
    return ret;
}

int libxl_domain_restore(struct libxl_ctx *ctx, libxl_domain_build_info *info,
                         uint32_t domid, int fd, libxl_domain_build_state *state,
                         libxl_device_model_info *dm_info)
{
    char **vments = NULL, **localents = NULL;
    int i, ret, esave, flags;

    ret = build_pre(ctx, domid, info, state);
    if (ret) goto out;

    ret = restore_common(ctx, domid, info, state, fd);
    if (ret) goto out;

    if (info->hvm) {
        vments = libxl_calloc(ctx, 5, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
    } else {
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
    ret = build_post(ctx, domid, info, state, vments, localents);
    if (ret) goto out;

    if (info->hvm)
        asprintf(&(dm_info->saved_state), "/var/lib/xen/qemu-save.%d", domid);
    else
        dm_info->saved_state = NULL;
out:
    esave = errno;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "unable to get flags on restore fd");
    } else {
        flags &= ~O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1)
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "unable to put restore fd"
                         " back to blocking mode");
    }

    errno = esave;
    return ret;
}

int libxl_domain_resume(struct libxl_ctx *ctx, uint32_t domid)
{
    if (is_hvm(ctx, domid)) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Called domain_resume on "
                "non-cooperative hvm domain %u", domid);
        return ERROR_NI;
    }
    if (xc_domain_resume(ctx->xch, domid, 1)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, 
                        "xc_domain_resume failed for domain %u", 
                        domid);
        return ERROR_FAIL;
    }
    if (!xs_resume_domain(ctx->xsh, domid)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, 
                        "xs_resume_domain failed for domain %u", 
                        domid);
        return ERROR_FAIL;
    }
    return 0;
}

static void xcinfo2xlinfo(const xc_domaininfo_t *xcinfo,
                          struct libxl_dominfo *xlinfo) {
    memcpy(&(xlinfo->uuid), xcinfo->handle, sizeof(xen_domain_handle_t));
    xlinfo->domid = xcinfo->domain;

    if (xcinfo->flags & XEN_DOMINF_dying)
        xlinfo->dying = 1;
    else if (xcinfo->flags & XEN_DOMINF_paused)
        xlinfo->paused = 1;
    else if (xcinfo->flags & XEN_DOMINF_blocked ||
             xcinfo->flags & XEN_DOMINF_running)
        xlinfo->running = 1;
    xlinfo->max_memkb = PAGE_TO_MEMKB(xcinfo->tot_pages);
    xlinfo->cpu_time = xcinfo->cpu_time;
    xlinfo->vcpu_max_id = xcinfo->max_vcpu_id;
    xlinfo->vcpu_online = xcinfo->nr_online_vcpus;
}

struct libxl_dominfo * libxl_list_domain(struct libxl_ctx *ctx, int *nb_domain)
{
    struct libxl_dominfo *ptr;
    int i, ret;
    xc_domaininfo_t info[1024];
    int size = 1024;

    ptr = calloc(size, sizeof(struct libxl_dominfo));
    if (!ptr) return NULL;

    ret = xc_domain_getinfolist(ctx->xch, 0, 1024, info);
    if (ret<0) return NULL;

    for (i = 0; i < ret; i++) {
        xcinfo2xlinfo(&info[i], &ptr[i]);
    }
    *nb_domain = ret;
    return ptr;
}

int libxl_domain_info(struct libxl_ctx *ctx, struct libxl_dominfo *info_r,
                      uint32_t domid) {
    xc_domaininfo_t xcinfo;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &xcinfo);
    if (ret<0) return ERROR_FAIL;
    if (ret==0 || xcinfo.domain != domid) return ERROR_INVAL;

    xcinfo2xlinfo(&xcinfo, info_r);
    return 0;
}

struct libxl_poolinfo * libxl_list_pool(struct libxl_ctx *ctx, int *nb_pool)
{
    struct libxl_poolinfo *ptr;
    int i, ret;
    xc_cpupoolinfo_t info[256];
    int size = 256;

    ptr = calloc(size, sizeof(struct libxl_poolinfo));
    if (!ptr) return NULL;

    ret = xc_cpupool_getinfo(ctx->xch, 0, 256, info);
    if (ret<0) return NULL;

    for (i = 0; i < ret; i++) {
        ptr[i].poolid = info[i].cpupool_id;
    }
    *nb_pool = ret;
    return ptr;
}

/* this API call only list VM running on this host. a VM can be an aggregate of multiple domains. */
struct libxl_vminfo * libxl_list_vm(struct libxl_ctx *ctx, int *nb_vm)
{
    struct libxl_vminfo *ptr;
    int index, i, ret;
    xc_domaininfo_t info[1024];
    int size = 1024;

    ptr = calloc(size, sizeof(struct libxl_dominfo));
    if (!ptr)
        return NULL;

    ret = xc_domain_getinfolist(ctx->xch, 1, 1024, info);
    for (index = i = 0; i < ret; i++) {
        if (libxl_is_stubdom(ctx, info[i].domain, NULL))
            continue;
        memcpy(&(ptr[index].uuid), info[i].handle, sizeof(xen_domain_handle_t));
        ptr[index].domid = info[i].domain;

        index++;
    }
    *nb_vm = index;
    return ptr;
}

int libxl_domain_suspend(struct libxl_ctx *ctx, libxl_domain_suspend_info *info,
                         uint32_t domid, int fd)
{
    int hvm = is_hvm(ctx, domid);
    int live = info != NULL && info->flags & XL_SUSPEND_LIVE;
    int debug = info != NULL && info->flags & XL_SUSPEND_LIVE;

    core_suspend(ctx, domid, fd, hvm, live, debug);
    if (hvm)
        save_device_model(ctx, domid, fd);
    return 0;
}

int libxl_domain_pause(struct libxl_ctx *ctx, uint32_t domid)
{
    xc_domain_pause(ctx->xch, domid);
    return 0;
}

int libxl_domain_unpause(struct libxl_ctx *ctx, uint32_t domid)
{
    char *path;
    char *state;

    if (is_hvm(ctx, domid)) {
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/state", domid);
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

int libxl_get_wait_fd(struct libxl_ctx *ctx, int *fd)
{
    *fd = xs_fileno(ctx->xsh);
    return 0;
}

int libxl_wait_for_domain_death(struct libxl_ctx *ctx, uint32_t domid, libxl_waiter *waiter)
{
    waiter->path = strdup("@releaseDomain");
    asprintf(&(waiter->token), "%d", DOMAIN_DEATH);
    if (!xs_watch(ctx->xsh, waiter->path, waiter->token))
        return -1;
    return 0;
}

int libxl_wait_for_disk_ejects(struct libxl_ctx *ctx, uint32_t guest_domid, libxl_device_disk *disks, int num_disks, libxl_waiter *waiter)
{
    int i;
    uint32_t domid = libxl_get_stubdom_id(ctx, guest_domid);

    if (!domid)
        domid = guest_domid;

    for (i = 0; i < num_disks; i++) {
        asprintf(&(waiter[i].path), "%s/device/vbd/%d/eject", libxl_xs_get_dompath(ctx, domid), device_disk_dev_number(disks[i].virtpath));
        asprintf(&(waiter[i].token), "%d", DISK_EJECT);
        xs_watch(ctx->xsh, waiter->path, waiter->token);
    }
    return 0;
}

int libxl_get_event(struct libxl_ctx *ctx, libxl_event *event)
{
    unsigned int num;
    char **events = xs_read_watch(ctx->xsh, &num);
    if (num != 2) {
        free(events);
        return -1;
    }
    event->path = strdup(events[XS_WATCH_PATH]);
    event->token = strdup(events[XS_WATCH_TOKEN]);
    event->type = atoi(event->token);
    free(events);
    return 0;
}

int libxl_stop_waiting(struct libxl_ctx *ctx, libxl_waiter *waiter)
{
    if (!xs_unwatch(ctx->xsh, waiter->path, waiter->token))
        return -1;
    else
        return 0;
}

int libxl_free_event(libxl_event *event)
{
    free(event->path);
    free(event->token);
    return 0;
}

int libxl_free_waiter(libxl_waiter *waiter)
{
    free(waiter->path);
    free(waiter->token);
    return 0;
}

int libxl_event_get_domain_death_info(struct libxl_ctx *ctx, uint32_t domid, libxl_event *event, xc_domaininfo_t *info)
{
    int rc = 0, ret;

    if (event && event->type == DOMAIN_DEATH) {
        ret = xc_domain_getinfolist(ctx->xch, domid, 1, info);
        if (ret == 1 && info->domain == domid) {
                if (info->flags & XEN_DOMINF_running ||
                    (!(info->flags & XEN_DOMINF_shutdown) && !(info->flags & XEN_DOMINF_dying)))
                    goto out;
                rc = 1;
                goto out;
        }
        memset(info, 0, sizeof(xc_dominfo_t));
        rc = 1;
        goto out;
    }
out:
    return rc;
}

int libxl_event_get_disk_eject_info(struct libxl_ctx *ctx, uint32_t domid, libxl_event *event, libxl_device_disk *disk)
{
    if (event && event->type == DISK_EJECT) {
        char *path;
        char *backend;
        char *value = libxl_xs_read(ctx, XBT_NULL, event->path);

        if (!value || strcmp(value,  "eject"))
            return 0;

        path = strdup(event->path);
        path[strlen(path) - 6] = '\0';
        backend = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/backend", path));

        disk->backend_domid = 0;
        disk->domid = domid;
        disk->physpath = NULL;
        disk->phystype = 0;
        /* this value is returned to the user: do not free right away */
        disk->virtpath = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/dev", backend));
        disk->unpluggable = 1;
        disk->readwrite = 0;
        disk->is_cdrom = 1;

        free(path);
        return 1;
    }
    return 0;
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
    char *dom_path;
    char *vm_path, *vss_path, *xapi_path;
    int rc, dm_present;

    if (is_hvm(ctx, domid)) {
        dm_present = 1;
    } else {
        char *pid;
        pid = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/image/device-model-pid", domid));
        dm_present = (pid != NULL);
        libxl_free(ctx, pid);
    }

    dom_path = libxl_xs_get_dompath(ctx, domid);
    if (!dom_path)
        return -1;

    if (libxl_device_pci_shutdown(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "pci shutdown failed for domid %d", domid);
    if (dm_present) {
        xs_write(ctx->xsh, XBT_NULL,
                 libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid),
                 "shutdown", strlen("shutdown"));
    }
    rc = xc_domain_pause(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_pause failed for %d", domid);
        return -1;
    }
    if (dm_present) {
        if (libxl_destroy_device_model(ctx, domid) < 0)
            XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_device_model failed for %d", domid);
    }
    if (libxl_devices_destroy(ctx, domid, force) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_devices failed for %d", domid);
    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", dom_path);

    vm_path = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/vm", domid));
    if (vm_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vm_path);

    vss_path = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "/local/domain/%d/vss", domid));
    if (vss_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, vss_path))
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vss_path);

    xapi_path = libxl_sprintf(ctx, "/xapi/%u", domid);
    if (xapi_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, xapi_path))
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", xapi_path);

    libxl__userdata_destroyall(ctx, domid);

    rc = xc_domain_destroy(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_destroy failed for %d", domid);
        return -1;
    }
    return 0;
}

int libxl_console_attach(struct libxl_ctx *ctx, uint32_t domid, int cons_num)
{
    char *cmd = libxl_sprintf(
        ctx, "%s/xenconsole %d --num %d",
        libxl_private_bindir_path(), domid, cons_num);
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
                flexarray_set(
                    dm_args, num++,
                    libxl_sprintf(ctx, "%s:%d%s",
                                  info->vnclisten,
                                  info->vncdisplay,
                                  info->vncpasswd ? ",password" : ""));
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
    if (info->sdl) {
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
                char *smac = libxl_sprintf(ctx, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2],
                                           vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
                if (!vifs[i].ifname)
                    vifs[i].ifname = libxl_sprintf(ctx, "tap%d.%d", info->domid, vifs[i].devid - 1);
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(ctx, "nic,vlan=%d,macaddr=%s,model=%s",
                            vifs[i].devid, smac, vifs[i].model));
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

void dm_xenstore_record_pid(void *for_spawn, pid_t innerchild)
{
    struct libxl_device_model_starting *starting = for_spawn;
    char *kvs[3];
    int rc;
    struct xs_handle *xsh;

    xsh = xs_daemon_open();
    /* we mustn't use the parent's handle in the child */

    kvs[0] = "image/device-model-pid";
    asprintf(&kvs[1], "%d", innerchild);
    kvs[2] = NULL;

    rc = xs_writev(xsh, XBT_NULL, starting->dom_path, kvs);
    if (rc)
        return;
    xs_daemon_close(xsh);
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
    vfb->vncpasswd = info->vncpasswd;
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
    int i, num_console = 1, ret;
    libxl_device_console *console;
    libxl_domain_create_info c_info;
    libxl_domain_build_info b_info;
    libxl_domain_build_state state;
    uint32_t domid;
    char **args;
    struct xs_permissions perm[2];
    xs_transaction_t t;
    libxl_device_model_starting *dm_starting = 0;

    args = libxl_build_device_model_args(ctx, info, vifs, num_vifs);
    if (!args)
        return ERROR_FAIL;

    memset(&c_info, 0x00, sizeof(libxl_domain_create_info));
    c_info.hvm = 0;
    c_info.name = libxl_sprintf(ctx, "%s-dm", libxl_domid_to_name(ctx, info->domid));
    for (i = 0; i < 16; i++)
        c_info.uuid[i] = info->uuid[i];

    memset(&b_info, 0x00, sizeof(libxl_domain_build_info));
    b_info.max_vcpus = 1;
    b_info.max_memkb = 32 * 1024;
    b_info.target_memkb = b_info.max_memkb;
    b_info.kernel = libxl_abs_path(ctx, "ioemu-stubdom.gz", libxl_xenfirmwaredir_path());
    b_info.u.pv.cmdline = libxl_sprintf(ctx, " -d %d", info->domid);
    b_info.u.pv.ramdisk = "";
    b_info.u.pv.features = "";
    b_info.hvm = 0;

    ret = libxl_domain_make(ctx, &c_info, &domid);
    if (ret) return ret;
    ret = libxl_domain_build(ctx, &b_info, domid, &state);
    if (ret) return ret;

    libxl_write_dmargs(ctx, domid, info->domid, args);
    libxl_xs_write(ctx, XBT_NULL,
                   libxl_sprintf(ctx, "%s/image/device-model-domid", libxl_xs_get_dompath(ctx, info->domid)),
                   "%d", domid);
    libxl_xs_write(ctx, XBT_NULL,
                   libxl_sprintf(ctx, "%s/target", libxl_xs_get_dompath(ctx, domid)),
                   "%d", info->domid);
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
    xs_mkdir(ctx->xsh, t, libxl_sprintf(ctx, "/local/domain/%d/device/vfs", domid));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(ctx, "/local/domain/%d/device/vfs",domid), perm, ARRAY_SIZE(perm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    for (i = 0; i < num_disks; i++) {
        disks[i].domid = domid;
        ret = libxl_device_disk_add(ctx, domid, &disks[i]);
        if (ret) return ret;
    }
    for (i = 0; i < num_vifs; i++) {
        vifs[i].domid = domid;
        ret = libxl_device_nic_add(ctx, domid, &vifs[i]);
        if (ret) return ret;
    }
    vfb->domid = domid;
    ret = libxl_device_vfb_add(ctx, domid, vfb);
    if (ret) return ret;
    vkb->domid = domid;
    ret = libxl_device_vkb_add(ctx, domid, vkb);
    if (ret) return ret;

    if (info->serial)
        num_console++;

    console = libxl_calloc(ctx, num_console, sizeof(libxl_device_console));
    if (!console)
        return ERROR_NOMEM;

    for (i = 0; i < num_console; i++) {
        console[i].devid = i;
        console[i].constype = CONSTYPE_IOEMU;
        console[i].domid = domid;
        if (!i)
            console[i].build_state = &state;
        ret = libxl_device_console_add(ctx, domid, &console[i]);
        if (ret) return ret;
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
    xs_transaction_t t; 
    char *vm_path;
    char **pass_stuff;

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

    if (info->vncpasswd) {
    retry_transaction:
        /* Find uuid and the write the vnc password to xenstore for qemu. */
        t = xs_transaction_start(ctx->xsh);
        vm_path = libxl_xs_read(ctx,t,libxl_sprintf(ctx, "%s/vm", p->dom_path));
        if (vm_path) {
            /* Now write the vncpassword into it. */
            pass_stuff = libxl_calloc(ctx, 2, sizeof(char *));
            pass_stuff[0] = "vncpasswd";
            pass_stuff[1] = info->vncpasswd;
            libxl_xs_writev(ctx,t,vm_path,pass_stuff);
            if (!xs_transaction_end(ctx->xsh, t, 0))
                if (errno == EAGAIN)
                    goto retry_transaction;
        }
    }

    rc = libxl_spawn_spawn(ctx, p, "device model", dm_xenstore_record_pid);
    if (rc < 0) goto xit;
    if (!rc) { /* inner child */
        libxl_exec(null, logfile_w, logfile_w,
                   libxl_abs_path(ctx, info->device_model, libxl_private_bindir_path()),
                   args);
    }

    rc = 0;
 xit:
    free(args);
    close(null);
    close(logfile_w);

    return rc;
}

int libxl_detach_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_starting *starting)
{
    int rc;
    rc = libxl_spawn_detach(ctx, starting->for_spawn);
    if (starting->for_spawn) libxl_free(ctx, starting->for_spawn);
    libxl_free(ctx, starting);
    return rc;
}


int libxl_confirm_device_model_startup(struct libxl_ctx *ctx,
                                       libxl_device_model_starting *starting)
{
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
    if (devid==-1) {
        XL_LOG(ctx, XL_LOG_ERROR, "Invalid or unuspported"
               " virtual disk identifier %s", disk->virtpath);
        return ERROR_INVAL;
    }

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
                dev = get_blktap2_device(ctx, disk->physpath, device_disk_string_of_phystype(disk->phystype));
                if (dev == NULL) {
                    rc= libxl_pipe(ctx, p);  if (rc==-1) return -1;
                    rc= libxl_fork(ctx);  if (rc==-1) return -1;
                    if (!rc) { /* child */
                        int null_r, null_w;
                        char *args[4];
                        args[0] = "tapdisk2";
                        args[1] = "-n";
                        args[2] = libxl_sprintf(ctx, "%s:%s", device_disk_string_of_phystype(disk->phystype), disk->physpath);
                        args[3] = NULL;

                        null_r = open("/dev/null", O_RDONLY);
                        null_w = open("/dev/null", O_WRONLY);
                        libxl_exec(null_r, p[1], null_w,
                                   libxl_abs_path(ctx, "tapdisk2",
                                                  libxl_sbindir_path()),
                                   args);
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
        default:
            XL_LOG(ctx, XL_LOG_ERROR, "unrecognized disk physical type: %d\n", disk->phystype);
            return ERROR_INVAL;
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

int libxl_device_disk_del(struct libxl_ctx *ctx, 
                          libxl_device_disk *disk, int wait)
{
    libxl_device device;
    int devid;

    devid = device_disk_dev_number(disk->virtpath);
    device.backend_domid    = disk->backend_domid;
    device.backend_devid    = devid;
    device.backend_kind     = 
        (disk->phystype == PHYSTYPE_PHY) ? DEVICE_VBD : DEVICE_TAP;
    device.domid            = disk->domid;
    device.devid            = devid;
    device.kind             = DEVICE_VBD;
    return libxl_device_del(ctx, &device, wait);
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

int libxl_device_nic_del(struct libxl_ctx *ctx, 
                         libxl_device_nic *nic, int wait)
{
    libxl_device device;

    device.backend_devid    = nic->devid;
    device.backend_domid    = nic->backend_domid;
    device.backend_kind     = DEVICE_VIF;
    device.devid            = nic->devid;
    device.domid            = nic->domid;
    device.kind             = DEVICE_VIF;

    return libxl_device_del(ctx, &device, wait);
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

libxl_device_disk *libxl_device_disk_list(struct libxl_ctx *ctx, uint32_t domid, int *num)
{
    char *be_path_tap, *be_path_vbd;
    libxl_device_disk *disks = NULL;
    char **l = NULL;
    unsigned int numl;
    int num_disks = 0, i;
    char *type;

    be_path_vbd = libxl_sprintf(ctx, "%s/backend/vbd/%d", libxl_xs_get_dompath(ctx, 0), domid);
    be_path_tap = libxl_sprintf(ctx, "%s/backend/tap/%d", libxl_xs_get_dompath(ctx, 0), domid);

    l = libxl_xs_directory(ctx, XBT_NULL, be_path_vbd, &numl);
    if (l) {
        num_disks += numl;
        disks = realloc(disks, sizeof(libxl_device_disk) * num_disks);
        for (i = 0; i < numl; i++) {
            disks[i].backend_domid = 0;
            disks[i].domid = domid;
            disks[i].physpath = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/params", be_path_vbd, l[i]));
            libxl_string_to_phystype(ctx, libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/type", be_path_vbd, l[i])), &(disks[i].phystype));
            disks[i].virtpath = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/dev", be_path_vbd, l[i]));
            disks[i].unpluggable = atoi(libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/removable", be_path_vbd, l[i])));
            if (!strcmp(libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/mode", be_path_vbd, l[i])), "w"))
                disks[i].readwrite = 1;
            else
                disks[i].readwrite = 0;
            type = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/device-type", libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/frontend", be_path_vbd, l[i]))));
            disks[i].is_cdrom = !strcmp(type, "cdrom");
        }
        free(l);
    }
    l = libxl_xs_directory(ctx, XBT_NULL, be_path_tap, &numl);
    if (l) {
        num_disks += numl;
        disks = realloc(disks, sizeof(libxl_device_disk) * num_disks);
        for (i = 0; i < numl; i++) {
            disks[i].backend_domid = 0;
            disks[i].domid = domid;
            disks[i].physpath = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/params", be_path_tap, l[i]));
            libxl_string_to_phystype(ctx, libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/type", be_path_tap, l[i])), &(disks[i].phystype));
            disks[i].virtpath = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/dev", be_path_tap, l[i]));
            disks[i].unpluggable = atoi(libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/removable", be_path_tap, l[i])));
            if (!strcmp(libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/mode", be_path_tap, l[i])), "w"))
                disks[i].readwrite = 1;
            else
                disks[i].readwrite = 0;
            type = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/device-type", libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/%s/frontend", be_path_vbd, l[i]))));
            disks[i].is_cdrom = !strcmp(type, "cdrom");
        }
        free(l);
    }
    *num = num_disks;
    return disks;
}

int libxl_cdrom_insert(struct libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk)
{
    int num, i;
    uint32_t stubdomid;
    libxl_device_disk *disks;

    if (!disk->physpath) {
        disk->physpath = "";
        disk->phystype = PHYSTYPE_PHY;
    }
    disks = libxl_device_disk_list(ctx, domid, &num);
    for (i = 0; i < num; i++) {
        if (disks[i].is_cdrom && !strcmp(disk->virtpath, disks[i].virtpath))
            /* found */
            break;
    }
    if (i == num) {
        XL_LOG(ctx, XL_LOG_ERROR, "Virtual device not found");
        return -1;
    }
    libxl_device_disk_del(ctx, disks + i, 1);
    libxl_device_disk_add(ctx, domid, disk);
    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid) {
        disks[i].domid = stubdomid;
        libxl_device_disk_del(ctx, disks + i, 1);
        disk->domid = stubdomid;
        libxl_device_disk_add(ctx, stubdomid, disk);
        disk->domid = domid;
    }
    return 0;
}

/******************************************************************************/
static int libxl_build_xenpv_qemu_args(struct libxl_ctx *ctx,
                                       libxl_device_vfb *vfb,
                                       int num_console,
                                       libxl_device_console *console,
                                       libxl_device_model_info *info)
{
    int i = 0, j = 0, num = 0;
    memset(info, 0x00, sizeof(libxl_device_model_info));

    info->vnc = vfb->vnc;
    if (vfb->vnclisten)
        info->vnclisten = libxl_sprintf(ctx, "%s", vfb->vnclisten);
    info->vncdisplay = vfb->vncdisplay;
    info->vncunused = vfb->vncunused;
    if (vfb->vncpasswd)
        info->vncpasswd = vfb->vncpasswd;
    if (vfb->keymap)
        info->keymap = libxl_sprintf(ctx, "%s", vfb->keymap);
    info->sdl = vfb->sdl;
    info->opengl = vfb->opengl;
    for (i = 0; i < num_console; i++) {
        if (console->constype == CONSTYPE_IOEMU)
            num++;
    }
    if (num > 0) {
        uint32_t guest_domid;
        if (libxl_is_stubdom(ctx, vfb->domid, &guest_domid)) {
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
    info->device_model = libxl_abs_path(ctx, "qemu-dm", libxl_libexec_path());
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
    flexarray_set(back, boffset++, "vncpasswd");
    flexarray_set(back, boffset++, vfb->vncpasswd);
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
    char *path;
    char *state, *vdevfn;
    int rc, hvm;
    int stubdomid = 0;

    /* TODO: check if the device can be assigned */

    libxl_device_pci_flr(ctx, pcidev->domain, pcidev->bus, pcidev->dev, pcidev->func);

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
        libxl_device_pci pcidev_s = *pcidev;
        libxl_device_pci_add(ctx, stubdomid, &pcidev_s);
    }

    hvm = is_hvm(ctx, domid);
    if (hvm) {
        if (libxl_wait_for_device_model(ctx, domid, "running", NULL, NULL) < 0) {
            return -1;
        }
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(ctx, XBT_NULL, path);
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/parameter", domid);
        if (pcidev->vdevfn)
            libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF_VDEVFN, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func, pcidev->vdevfn);
        else
            libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF, pcidev->domain,
                           pcidev->bus, pcidev->dev, pcidev->func);
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid);
        xs_write(ctx->xsh, XBT_NULL, path, "pci-ins", strlen("pci-ins"));
        if (libxl_wait_for_device_model(ctx, domid, "pci-inserted", NULL, NULL) < 0)
            XL_LOG(ctx, XL_LOG_ERROR, "Device Model didn't respond in time");
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/parameter", domid);
        vdevfn = libxl_xs_read(ctx, XBT_NULL, path);
        sscanf(vdevfn + 2, "%x", &pcidev->vdevfn);
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/state", domid);
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
    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_assign_device(ctx->xch, domid, pcidev->value);
        if (rc < 0)
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_assign_device failed");
    }

    libxl_device_pci_add_xenstore(ctx, domid, pcidev);
    return 0;
}

int libxl_device_pci_remove(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev)
{
    char *path;
    char *state;
    int hvm, rc;
    int stubdomid = 0;

    /* TODO: check if the device can be detached */
    libxl_device_pci_remove_xenstore(ctx, domid, pcidev);

    hvm = is_hvm(ctx, domid);
    if (hvm) {
        if (libxl_wait_for_device_model(ctx, domid, "running", NULL, NULL) < 0) {
            return -1;
        }
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(ctx, XBT_NULL, path);
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/parameter", domid);
        libxl_xs_write(ctx, XBT_NULL, path, PCI_BDF, pcidev->domain,
                       pcidev->bus, pcidev->dev, pcidev->func);
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/command", domid);
        xs_write(ctx->xsh, XBT_NULL, path, "pci-rem", strlen("pci-rem"));
        if (libxl_wait_for_device_model(ctx, domid, "pci-removed", NULL, NULL) < 0) {
            XL_LOG(ctx, XL_LOG_ERROR, "Device Model didn't respond in time");
            return -1;
        }
        path = libxl_sprintf(ctx, "/local/domain/0/device-model/%d/state", domid);
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

    if (!libxl_is_stubdom(ctx, domid, NULL)) {
        rc = xc_deassign_device(ctx->xch, domid, pcidev->value);
        if (rc < 0)
            XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_deassign_device failed");
    }

    stubdomid = libxl_get_stubdom_id(ctx, domid);
    if (stubdomid != 0) {
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
    pcidevs = calloc(n, sizeof(libxl_device_pci));
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

int libxl_set_memory_target(struct libxl_ctx *ctx, uint32_t domid, uint32_t target_memkb)
{
    int rc = 0;
    uint32_t videoram;
    char *videoram_s = NULL;
    char *dompath = libxl_xs_get_dompath(ctx, domid);
    xc_domaininfo_t info;
    struct libxl_dominfo ptr;
    char *uuid;

    videoram_s = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/memory/videoram", dompath));
    videoram = videoram_s ? atoi(videoram_s) : 0;

    libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/memory/target", dompath), "%lu", target_memkb);

    rc = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (rc != 1 || info.domain != domid)
        return rc;
    xcinfo2xlinfo(&info, &ptr);
    uuid = libxl_uuid2string(ctx, ptr.uuid);
    libxl_xs_write(ctx, XBT_NULL, libxl_sprintf(ctx, "/vm/%s/memory", uuid), "%lu", target_memkb / 1024);

    rc = xc_domain_setmaxmem(ctx->xch, domid, target_memkb + LIBXL_MAXMEM_CONSTANT);
    if (rc != 0)
        return rc;
    rc = xc_domain_memory_set_pod_target(ctx->xch, domid, (target_memkb - videoram) / 4, NULL, NULL, NULL);
    return rc;
}

int libxl_button_press(struct libxl_ctx *ctx, uint32_t domid, libxl_button button)
{
    int rc = -1;

    switch (button) {
    case POWER_BUTTON:
        rc = xc_domain_send_trigger(ctx->xch, domid, XEN_DOMCTL_SENDTRIGGER_POWER, 0);
        break;
    case SLEEP_BUTTON:
        rc = xc_domain_send_trigger(ctx->xch, domid, XEN_DOMCTL_SENDTRIGGER_SLEEP, 0);
        break;
    default:
        break;
    }

    return rc;
}

int libxl_get_physinfo(struct libxl_ctx *ctx, struct libxl_physinfo *physinfo)
{
    xc_physinfo_t xcphysinfo = { 0 };
    int rc;

    rc = xc_physinfo(ctx->xch, &xcphysinfo);
    if (rc != 0) {
        return rc;
    }
    physinfo->threads_per_core = xcphysinfo.threads_per_core;
    physinfo->cores_per_socket = xcphysinfo.cores_per_socket;
    physinfo->max_cpu_id = xcphysinfo.max_cpu_id;
    physinfo->nr_cpus = xcphysinfo.nr_cpus;
    physinfo->cpu_khz = xcphysinfo.cpu_khz;
    physinfo->total_pages = xcphysinfo.total_pages;
    physinfo->free_pages = xcphysinfo.free_pages;
    physinfo->scrub_pages = xcphysinfo.scrub_pages;
    physinfo->nr_nodes = xcphysinfo.nr_nodes;
    memcpy(physinfo->hw_cap,xcphysinfo.hw_cap, sizeof(physinfo->hw_cap));
    physinfo->phys_cap = xcphysinfo.capabilities;

    return 0;
}

const libxl_version_info* libxl_get_version_info(struct libxl_ctx *ctx)
{
    union {
        xen_extraversion_t xen_extra;
        xen_compile_info_t xen_cc;
        xen_changeset_info_t xen_chgset;
        xen_capabilities_info_t xen_caps;
        xen_platform_parameters_t p_parms;
        xen_commandline_t xen_commandline;
    } u;
    long xen_version;
    libxl_version_info *info = &ctx->version_info;

    if (info->xen_version_extra != NULL)
        return info;

    xen_version = xc_version(ctx->xch, XENVER_version, NULL);
    info->xen_version_major = xen_version >> 16;
    info->xen_version_minor = xen_version & 0xFF;
    xc_version(ctx->xch, XENVER_extraversion, &u.xen_extra);
    info->xen_version_extra = libxl_sprintf(ctx, "%s", u.xen_extra);

    xc_version(ctx->xch, XENVER_compile_info, &u.xen_cc);
    info->compiler = libxl_sprintf(ctx, "%s", u.xen_cc.compiler);
    info->compile_by = libxl_sprintf(ctx, "%s", u.xen_cc.compile_by);
    info->compile_domain = libxl_sprintf(ctx, "%s", u.xen_cc.compile_domain);
    info->compile_date = libxl_sprintf(ctx, "%s", u.xen_cc.compile_date);

    xc_version(ctx->xch, XENVER_capabilities, &u.xen_caps);
    info->capabilities = libxl_sprintf(ctx, "%s", u.xen_caps);

    xc_version(ctx->xch, XENVER_changeset, &u.xen_chgset);
    info->changeset = libxl_sprintf(ctx, "%s", u.xen_chgset);

    xc_version(ctx->xch, XENVER_platform_parameters, &u.p_parms);
    info->virt_start = u.p_parms.virt_start;

    info->pagesize = xc_version(ctx->xch, XENVER_pagesize, NULL);

    xc_version(ctx->xch, XENVER_commandline, &u.xen_commandline);
    info->commandline = libxl_sprintf(ctx, "%s", u.xen_commandline);

    return info;
}

struct libxl_vcpuinfo *libxl_list_vcpu(struct libxl_ctx *ctx, uint32_t domid,
                                       int *nb_vcpu, int *cpusize)
{
    struct libxl_vcpuinfo *ptr, *ret;
    xc_domaininfo_t domaininfo;
    xc_vcpuinfo_t vcpuinfo;
    xc_physinfo_t physinfo = { 0 };

    if (xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo) != 1) {
        return NULL;
    }
    if (xc_physinfo(ctx->xch, &physinfo) == -1) {
        return NULL;
    }
    *cpusize = physinfo.max_cpu_id + 1;
    ptr = libxl_calloc(ctx, domaininfo.max_vcpu_id + 1, sizeof (struct libxl_vcpuinfo));
    if (!ptr) {
        return NULL;
    }

    ret = ptr;
    for (*nb_vcpu = 0; *nb_vcpu <= domaininfo.max_vcpu_id; ++*nb_vcpu, ++ptr) {
        ptr->cpumap = libxl_calloc(ctx, (*cpusize + 63) / 64, sizeof (uint64_t));
        if (!ptr->cpumap) {
            return NULL;
        }
        if (xc_vcpu_getinfo(ctx->xch, domid, *nb_vcpu, &vcpuinfo) == -1) {
            return NULL;
        }
        if (xc_vcpu_getaffinity(ctx->xch, domid, *nb_vcpu, ptr->cpumap, *cpusize) == -1) {
            return NULL;
        }
        ptr->vcpuid = *nb_vcpu;
        ptr->cpu = vcpuinfo.cpu;
        ptr->online = !!vcpuinfo.online;
        ptr->blocked = !!vcpuinfo.blocked;
        ptr->running = !!vcpuinfo.running;
        ptr->vcpu_time = vcpuinfo.cpu_time;
    }
    return ret;
}

int libxl_set_vcpuaffinity(struct libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           uint64_t *cpumap, int cpusize)
{
    return (xc_vcpu_setaffinity(ctx->xch, domid, vcpuid, cpumap, cpusize));
}

int libxl_set_vcpucount(struct libxl_ctx *ctx, uint32_t domid, uint32_t count)
{
    xc_domaininfo_t domaininfo;
    char *dompath;
    int i;

    if (xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo) != 1) {
        return ERROR_FAIL;
    }
    if (!count || ((domaininfo.max_vcpu_id + 1) < count)) {
        return ERROR_INVAL;
    }
    if (!(dompath = libxl_xs_get_dompath(ctx, domid)))
        return ERROR_FAIL;

    for (i = 0; i <= domaininfo.max_vcpu_id; ++i) {
        libxl_xs_write(ctx, XBT_NULL,
                       libxl_sprintf(ctx, "%s/cpu/%u/availability", dompath, i),
                       "%s", ((1 << i) & ((1 << count) - 1)) ? "online" : "offline");
    }
    return 0;
}

/*
 * returns one of the XEN_SCHEDULER_* constants from public/domctl.h
 * or -1 if an error occured.
 */
int libxl_get_sched_id(struct libxl_ctx *ctx)
{
    int sched, ret;

    if ((ret = xc_sched_id(ctx->xch, &sched)) != 0)
        return ret;
    return sched;
}

int libxl_sched_credit_domain_get(struct libxl_ctx *ctx, uint32_t domid, struct libxl_sched_credit *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    int rc;

    rc = xc_sched_credit_domain_get(ctx->xch, domid, &sdom);
    if (rc != 0)
        return rc;

    scinfo->weight = sdom.weight;
    scinfo->cap = sdom.cap;

    return 0;
}

int libxl_sched_credit_domain_set(struct libxl_ctx *ctx, uint32_t domid, struct libxl_sched_credit *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    xc_domaininfo_t domaininfo;
    int rc;

    rc = xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo);
    if (rc != 1 || domaininfo.domain != domid)
        return rc;


    if (scinfo->weight < 1 || scinfo->weight > 65535) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Cpu weight out of range, valid values are within range from 1 to 65535");
        return -1;
    }

    if (scinfo->cap < 0 || scinfo->cap > (domaininfo.max_vcpu_id + 1) * 100) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Cpu cap out of range, valid range is from 0 to %d for specified number of vcpus",
            ((domaininfo.max_vcpu_id + 1) * 100));
        return -1;
    }

    sdom.weight = scinfo->weight;
    sdom.cap = scinfo->cap;

    rc = xc_sched_credit_domain_set(ctx->xch, domid, &sdom);
    if (rc != 0)
        return rc;

    return 0;
}

