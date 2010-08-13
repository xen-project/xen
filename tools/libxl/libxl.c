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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h> /* for write, unlink and close */
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "libxl_internal.h"
#include "flexarray.h"
#include "tap-ctl.h"

#define PAGE_TO_MEMKB(pages) ((pages) * 4)

int libxl_ctx_init(libxl_ctx *ctx, int version, xentoollog_logger *lg)
{
    if (version != LIBXL_VERSION)
        return ERROR_VERSION;
    memset(ctx, 0, sizeof(libxl_ctx));
    ctx->lg = lg;
    memset(&ctx->version_info, 0, sizeof(libxl_version_info));

    ctx->xch = xc_interface_open(lg,lg,0);
    if (!ctx->xch) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, errno, 
                        "cannot open libxc handle");
        return ERROR_FAIL;
    }

    ctx->xsh = xs_daemon_open();
    if (!ctx->xsh) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, errno, 
                        "cannot connect to xenstore");
        xc_interface_close(ctx->xch);
        return ERROR_FAIL;
    }
    return 0;
}

static void do_free_version_info(libxl_version_info *info);
int libxl_ctx_free(libxl_ctx *ctx)
{
    xc_interface_close(ctx->xch);
    do_free_version_info(&ctx->version_info);
    if (ctx->xsh) xs_daemon_close(ctx->xsh); 
    return 0;
}

/******************************************************************************/

int libxl_domain_make(libxl_ctx *ctx, libxl_domain_create_info *info,
                       uint32_t *domid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int flags, ret, i, rc;
    char *uuid_string;
    char *rw_paths[] = { "device", "device/suspend/event-channel" , "data"};
    char *ro_paths[] = { "cpu", "memory", "device", "error", "drivers",
                         "control", "attr", "messages" };
    char *dom_path, *vm_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    xs_transaction_t t;
    xen_domain_handle_t handle;

    uuid_string = libxl_uuid2string(ctx, info->uuid);
    if (!uuid_string) {
        libxl_free_all(&gc);
        return ERROR_NOMEM;
    }

    flags = info->hvm ? XEN_DOMCTL_CDF_hvm_guest : 0;
    flags |= info->hap ? XEN_DOMCTL_CDF_hap : 0;
    flags |= info->oos ? 0 : XEN_DOMCTL_CDF_oos_off;
    *domid = -1;

    /* Ultimately, handle is an array of 16 uint8_t, same as uuid */
    memcpy(handle, info->uuid, sizeof(xen_domain_handle_t));

    ret = xc_domain_create(ctx->xch, info->ssidref, handle, flags, domid);
    if (ret < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "domain creation fail");
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    ret = xc_cpupool_movedomain(ctx->xch, info->poolid, *domid);
    if (ret < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, ret, "domain move fail");
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    dom_path = libxl_xs_get_dompath(&gc, *domid);
    if (!dom_path) {
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    vm_path = libxl_sprintf(&gc, "/vm/%s", uuid_string);
    if (!vm_path) {
        XL_LOG(ctx, XL_LOG_ERROR, "cannot allocate create paths");
        libxl_free_all(&gc);
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

    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl_domain_rename(ctx, *domid, 0, info->name, t);
    if (rc) {
        libxl_free_all(&gc);
        return rc;
    }

    for (i = 0; i < ARRAY_SIZE(rw_paths); i++) {
        char *path = libxl_sprintf(&gc, "%s/%s", dom_path, rw_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, rwperm, ARRAY_SIZE(rwperm));
    }
    for (i = 0; i < ARRAY_SIZE(ro_paths); i++) {
        char *path = libxl_sprintf(&gc, "%s/%s", dom_path, ro_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    }

    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/uuid", vm_path), uuid_string, strlen(uuid_string));
    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/name", vm_path), info->name, strlen(info->name));
    if (info->poolname)
        xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/pool_name", vm_path), info->poolname, strlen(info->poolname));

    libxl_xs_writev(&gc, t, dom_path, info->xsdata);
    libxl_xs_writev(&gc, t, libxl_sprintf(&gc, "%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    libxl_free_all(&gc);
    return 0;
}

int libxl_domain_rename(libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name,
                        xs_transaction_t trans)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dom_path = 0;
    const char *name_path;
    char *got_old_name;
    unsigned int got_old_len;
    xs_transaction_t our_trans = 0;
    int rc;

    dom_path = libxl_xs_get_dompath(&gc, domid);
    if (!dom_path) goto x_nomem;

    name_path= libxl_sprintf(&gc, "%s/name", dom_path);
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
               new_name, domid, old_name);
        goto x_fail;
    }

    if (our_trans) {
        if (!xs_transaction_end(ctx->xsh, our_trans, 0)) {
            trans = our_trans = 0;
            if (errno != EAGAIN) {
                XL_LOG(ctx, XL_LOG_ERROR, "failed to commit new name `%s'"
                       " for domain %"PRIu32" previously named `%s'",
                       new_name, domid, old_name);
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
    if (our_trans) xs_transaction_end(ctx->xsh, our_trans, 1);
    libxl_free_all(&gc);
    return rc;

 x_fail:  rc = ERROR_FAIL;  goto x_rc;
 x_nomem: rc = ERROR_NOMEM; goto x_rc;
}

int libxl_domain_build(libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid, libxl_domain_build_state *state)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, ret;

    ret = build_pre(ctx, domid, info, state);
    if (ret)
        goto out;

    gettimeofday(&start_time, NULL);

    if (info->hvm) {
        ret = build_hvm(ctx, domid, info, state);
        if (ret)
            goto out;

        vments = libxl_calloc(&gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = libxl_sprintf(&gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
    } else {
        ret = build_pv(ctx, domid, info, state);
        if (ret)
            goto out;

        vments = libxl_calloc(&gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char*) info->kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl_sprintf(&gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (info->u.pv.ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char*) info->u.pv.ramdisk.path;
        }
        if (info->u.pv.cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char*) info->u.pv.cmdline;
        }
    }
    ret = build_post(ctx, domid, info, state, vments, localents);
out:
    libxl_file_reference_unmap(ctx, &info->kernel);
    if (!info->hvm)
	    libxl_file_reference_unmap(ctx, &info->u.pv.ramdisk);

    libxl_free_all(&gc);
    return ret;
}

int libxl_domain_restore(libxl_ctx *ctx, libxl_domain_build_info *info,
                         uint32_t domid, int fd, libxl_domain_build_state *state,
                         libxl_device_model_info *dm_info)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, ret, esave, flags;

    ret = build_pre(ctx, domid, info, state);
    if (ret)
        goto out;

    ret = restore_common(ctx, domid, info, state, fd);
    if (ret)
        goto out;

    gettimeofday(&start_time, NULL);

    if (info->hvm) {
        vments = libxl_calloc(&gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = libxl_sprintf(&gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
    } else {
        vments = libxl_calloc(&gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char*) info->kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl_sprintf(&gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (info->u.pv.ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char*) info->u.pv.ramdisk.path;
        }
        if (info->u.pv.cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char*) info->u.pv.cmdline;
        }
    }
    ret = build_post(ctx, domid, info, state, vments, localents);
    if (ret)
        goto out;

    dm_info->saved_state = NULL;
    if (info->hvm) {
        ret = asprintf(&dm_info->saved_state,
                       "/var/lib/xen/qemu-save.%d", domid);
        ret = (ret < 0) ? ERROR_FAIL : 0;
    }

out:
    libxl_file_reference_unmap(ctx, &info->kernel);
    if (!info->hvm)
	    libxl_file_reference_unmap(ctx, &info->u.pv.ramdisk);

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
    libxl_free_all(&gc);
    return ret;
}

int libxl_domain_resume(libxl_ctx *ctx, uint32_t domid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int rc = 0;

    if (is_hvm(ctx, domid)) {
        XL_LOG(ctx, XL_LOG_DEBUG, "Called domain_resume on "
                "non-cooperative hvm domain %u", domid);
        rc = ERROR_NI;
        goto out;
    }
    if (xc_domain_resume(ctx->xch, domid, 1)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, 
                        "xc_domain_resume failed for domain %u", 
                        domid);
        rc = ERROR_FAIL;
        goto out;
    }
    if (!xs_resume_domain(ctx->xsh, domid)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, 
                        "xs_resume_domain failed for domain %u", 
                        domid);
        rc = ERROR_FAIL;
    }
out:
    libxl_free_all(&gc);
    return 0;
}

/*
 * Preserves a domain but rewrites xenstore etc to make it unique so
 * that the domain can be restarted.
 *
 * Does not modify info so that it may be reused.
 */
int libxl_domain_preserve(libxl_ctx *ctx, uint32_t domid,
                          libxl_domain_create_info *info, const char *name_suffix, libxl_uuid new_uuid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    struct xs_permissions roperm[2];
    xs_transaction_t t;
    char *preserved_name;
    char *uuid_string;
    char *vm_path;
    char *dom_path;

    int rc;

    preserved_name = libxl_sprintf(&gc, "%s%s", info->name, name_suffix);
    if (!preserved_name) {
        libxl_free_all(&gc);
        return ERROR_NOMEM;
    }

    uuid_string = libxl_uuid2string(ctx, new_uuid);
    if (!uuid_string) {
        libxl_free_all(&gc);
        return ERROR_NOMEM;
    }

    dom_path = libxl_xs_get_dompath(&gc, domid);
    if (!dom_path) {
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    vm_path = libxl_sprintf(&gc, "/vm/%s", uuid_string);
    if (!vm_path) {
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    roperm[0].id = 0;
    roperm[0].perms = XS_PERM_NONE;
    roperm[1].id = domid;
    roperm[1].perms = XS_PERM_READ;

 retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    xs_rm(ctx->xsh, t, vm_path);
    xs_mkdir(ctx->xsh, t, vm_path);
    xs_set_permissions(ctx->xsh, t, vm_path, roperm, ARRAY_SIZE(roperm));

    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl_domain_rename(ctx, domid, info->name, preserved_name, t);
    if (rc) return rc;

    xs_write(ctx->xsh, t, libxl_sprintf(&gc, "%s/uuid", vm_path), uuid_string, strlen(uuid_string));

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    libxl_free_all(&gc);
    return 0;
}

static void xcinfo2xlinfo(const xc_domaininfo_t *xcinfo,
                          libxl_dominfo *xlinfo)
{
    memcpy(&(xlinfo->uuid), xcinfo->handle, sizeof(xen_domain_handle_t));
    xlinfo->domid = xcinfo->domain;

    xlinfo->dying    = !!(xcinfo->flags&XEN_DOMINF_dying);
    xlinfo->shutdown = !!(xcinfo->flags&XEN_DOMINF_shutdown);
    xlinfo->paused   = !!(xcinfo->flags&XEN_DOMINF_paused);
    xlinfo->blocked  = !!(xcinfo->flags&XEN_DOMINF_blocked);
    xlinfo->running  = !!(xcinfo->flags&XEN_DOMINF_running);

    if (xlinfo->shutdown || xlinfo->dying)
        xlinfo->shutdown_reason = (xcinfo->flags>>XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
    else
        xlinfo->shutdown_reason  = ~0;

    xlinfo->max_memkb = PAGE_TO_MEMKB(xcinfo->tot_pages);
    xlinfo->cpu_time = xcinfo->cpu_time;
    xlinfo->vcpu_max_id = xcinfo->max_vcpu_id;
    xlinfo->vcpu_online = xcinfo->nr_online_vcpus;
}

libxl_dominfo * libxl_list_domain(libxl_ctx *ctx, int *nb_domain)
{
    libxl_dominfo *ptr;
    int i, ret;
    xc_domaininfo_t info[1024];
    int size = 1024;

    ptr = calloc(size, sizeof(libxl_dominfo));
    if (!ptr) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "allocating domain info");
        return NULL;
    }

    ret = xc_domain_getinfolist(ctx->xch, 0, 1024, info);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "geting domain info list");
        return NULL;
    }

    for (i = 0; i < ret; i++) {
        xcinfo2xlinfo(&info[i], &ptr[i]);
    }
    *nb_domain = ret;
    return ptr;
}

int libxl_domain_info(libxl_ctx *ctx, libxl_dominfo *info_r,
                      uint32_t domid) {
    xc_domaininfo_t xcinfo;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &xcinfo);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "geting domain info list");
        return ERROR_FAIL;
    }
    if (ret==0 || xcinfo.domain != domid) return ERROR_INVAL;

    xcinfo2xlinfo(&xcinfo, info_r);
    return 0;
}

libxl_poolinfo * libxl_list_pool(libxl_ctx *ctx, int *nb_pool)
{
    libxl_poolinfo *ptr;
    int i, ret;
    xc_cpupoolinfo_t info[256];
    int size = 256;

    ptr = calloc(size, sizeof(libxl_poolinfo));
    if (!ptr) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "allocating cpupool info");
        return NULL;
    }

    ret = xc_cpupool_getinfo(ctx->xch, 0, 256, info);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting cpupool info");
        return NULL;
    }

    for (i = 0; i < ret; i++) {
        ptr[i].poolid = info[i].cpupool_id;
    }
    *nb_pool = ret;
    return ptr;
}

/* this API call only list VM running on this host. a VM can be an aggregate of multiple domains. */
libxl_vminfo * libxl_list_vm(libxl_ctx *ctx, int *nb_vm)
{
    libxl_vminfo *ptr;
    int index, i, ret;
    xc_domaininfo_t info[1024];
    int size = 1024;

    ptr = calloc(size, sizeof(libxl_dominfo));
    if (!ptr)
        return NULL;

    ret = xc_domain_getinfolist(ctx->xch, 1, 1024, info);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "geting domain info list");
        return NULL;
    }
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

int libxl_domain_suspend(libxl_ctx *ctx, libxl_domain_suspend_info *info,
                         uint32_t domid, int fd)
{
    int hvm = is_hvm(ctx, domid);
    int live = info != NULL && info->flags & XL_SUSPEND_LIVE;
    int debug = info != NULL && info->flags & XL_SUSPEND_DEBUG;
    int rc = 0;

    core_suspend(ctx, domid, fd, hvm, live, debug);
    if (hvm)
        rc = save_device_model(ctx, domid, fd);
    return rc;
}

int libxl_domain_pause(libxl_ctx *ctx, uint32_t domid)
{
    int ret;
    ret = xc_domain_pause(ctx->xch, domid);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "pausing domain %d", domid);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_domain_core_dump(libxl_ctx *ctx, uint32_t domid,
                           const char *filename)
{
    int ret;
    ret = xc_domain_dumpcore(ctx->xch, domid, filename);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "core dumping domain %d to %s",
                     domid, filename);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_domain_unpause(libxl_ctx *ctx, uint32_t domid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *path;
    char *state;
    int ret, rc = 0;

    if (is_hvm(ctx, domid)) {
        path = libxl_sprintf(&gc, "/local/domain/0/device-model/%d/state", domid);
        state = libxl_xs_read(&gc, XBT_NULL, path);
        if (state != NULL && !strcmp(state, "paused")) {
            libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "/local/domain/0/device-model/%d/command", domid), "continue");
            libxl_wait_for_device_model(ctx, domid, "running", NULL, NULL);
        }
    }
    ret = xc_domain_unpause(ctx->xch, domid);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "unpausing domain %d", domid);
        rc = ERROR_FAIL;
    }
    libxl_free_all(&gc);
    return rc;
}

static char *req_table[] = {
    [0] = "poweroff",
    [1] = "reboot",
    [2] = "suspend",
    [3] = "crash",
    [4] = "halt",
};

int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid, int req)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *shutdown_path;
    char *dom_path;

    if (req > ARRAY_SIZE(req_table)) {
        libxl_free_all(&gc);
        return ERROR_INVAL;
    }

    dom_path = libxl_xs_get_dompath(&gc, domid);
    if (!dom_path) {
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }

    shutdown_path = libxl_sprintf(&gc, "%s/control/shutdown", dom_path);

    xs_write(ctx->xsh, XBT_NULL, shutdown_path, req_table[req], strlen(req_table[req]));
    if (is_hvm(ctx,domid)) {
        unsigned long acpi_s_state = 0;
        unsigned long pvdriver = 0;
        int ret;
        ret = xc_get_hvm_param(ctx->xch, domid, HVM_PARAM_ACPI_S_STATE, &acpi_s_state);
        if (ret<0) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting ACPI S-state");
            return ERROR_FAIL;
        }
        ret = xc_get_hvm_param(ctx->xch, domid, HVM_PARAM_CALLBACK_IRQ, &pvdriver);
        if (ret<0) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting HVM callback IRQ");
            return ERROR_FAIL;
        }
        if (!pvdriver || acpi_s_state != 0) {
            ret = xc_domain_shutdown(ctx->xch, domid, req);
            if (ret<0) {
                XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "unpausing domain");
                return ERROR_FAIL;
            }
       }
    }
    libxl_free_all(&gc);
    return 0;
}

int libxl_get_wait_fd(libxl_ctx *ctx, int *fd)
{
    *fd = xs_fileno(ctx->xsh);
    return 0;
}

int libxl_wait_for_domain_death(libxl_ctx *ctx, uint32_t domid, libxl_waiter *waiter)
{
    waiter->path = strdup("@releaseDomain");
    if (asprintf(&(waiter->token), "%d", LIBXL_EVENT_DOMAIN_DEATH) < 0)
        return -1;
    if (!xs_watch(ctx->xsh, waiter->path, waiter->token))
        return -1;
    return 0;
}

int libxl_wait_for_disk_ejects(libxl_ctx *ctx, uint32_t guest_domid, libxl_device_disk *disks, int num_disks, libxl_waiter *waiter)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int i, rc = -1;
    uint32_t domid = libxl_get_stubdom_id(ctx, guest_domid);

    if (!domid)
        domid = guest_domid;

    for (i = 0; i < num_disks; i++) {
        if (asprintf(&(waiter[i].path), "%s/device/vbd/%d/eject",
                     libxl_xs_get_dompath(&gc, domid),
                     device_disk_dev_number(disks[i].virtpath)) < 0)
            goto out;
        if (asprintf(&(waiter[i].token), "%d", LIBXL_EVENT_DISK_EJECT) < 0)
            goto out;
        xs_watch(ctx->xsh, waiter->path, waiter->token);
    }
    rc = 0;
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_get_event(libxl_ctx *ctx, libxl_event *event)
{
    unsigned int num;
    char **events = xs_read_watch(ctx->xsh, &num);
    if (num != 2) {
        free(events);
        return ERROR_FAIL;
    }
    event->path = strdup(events[XS_WATCH_PATH]);
    event->token = strdup(events[XS_WATCH_TOKEN]);
    event->type = atoi(event->token);
    free(events);
    return 0;
}

int libxl_stop_waiting(libxl_ctx *ctx, libxl_waiter *waiter)
{
    if (!xs_unwatch(ctx->xsh, waiter->path, waiter->token))
        return ERROR_FAIL;
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

int libxl_event_get_domain_death_info(libxl_ctx *ctx, uint32_t domid, libxl_event *event, libxl_dominfo *info)
{
    if (libxl_domain_info(ctx, info, domid) < 0)
        return 0;

    if (info->running || (!info->shutdown && !info->dying))
        return ERROR_INVAL;

    return 1;
}

int libxl_event_get_disk_eject_info(libxl_ctx *ctx, uint32_t domid, libxl_event *event, libxl_device_disk *disk)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *path;
    char *backend;
    char *value;

    value = libxl_xs_read(&gc, XBT_NULL, event->path);

    if (!value || strcmp(value,  "eject")) {
        libxl_free_all(&gc);
        return 0;
    }

    path = strdup(event->path);
    path[strlen(path) - 6] = '\0';
    backend = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/backend", path));

    disk->backend_domid = 0;
    disk->domid = domid;
    disk->physpath = NULL;
    disk->phystype = 0;
    /* this value is returned to the user: do not free right away */
    disk->virtpath = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/dev", backend));
    disk->unpluggable = 1;
    disk->readwrite = 0;
    disk->is_cdrom = 1;

    free(path);
    libxl_free_all(&gc);
    return 1;
}

static int libxl_destroy_device_model(libxl_ctx *ctx, uint32_t domid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *pid;
    int ret;

    pid = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "/local/domain/%d/image/device-model-pid", domid));
    if (!pid) {
        int stubdomid = libxl_get_stubdom_id(ctx, domid);
        if (!stubdomid) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "Couldn't find device model's pid");
            ret = ERROR_INVAL;
            goto out;
        }
        XL_LOG(ctx, XL_LOG_ERROR, "Device model is a stubdom, domid=%d\n", stubdomid);
        ret = libxl_domain_destroy(ctx, stubdomid, 0);
        goto out;
    }
    xs_rm(ctx->xsh, XBT_NULL, libxl_sprintf(&gc, "/local/domain/0/device-model/%d", domid));

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
out:
    libxl_free_all(&gc);
    return ret;
}

int libxl_domain_destroy(libxl_ctx *ctx, uint32_t domid, int force)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dom_path;
    char *vm_path;
    int rc, dm_present;

    if (is_hvm(ctx, domid)) {
        dm_present = 1;
    } else {
        char *pid;
        pid = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "/local/domain/%d/image/device-model-pid", domid));
        dm_present = (pid != NULL);
    }

    dom_path = libxl_xs_get_dompath(&gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (libxl_device_pci_shutdown(ctx, domid) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "pci shutdown failed for domid %d", domid);
    if (dm_present) {
        xs_write(ctx->xsh, XBT_NULL,
                 libxl_sprintf(&gc, "/local/domain/0/device-model/%d/command", domid),
                 "shutdown", strlen("shutdown"));
    }
    rc = xc_domain_pause(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_pause failed for %d", domid);
    }
    if (dm_present) {
        if (libxl_destroy_device_model(ctx, domid) < 0)
            XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_device_model failed for %d", domid);
    }
    if (libxl_devices_destroy(ctx, domid, force) < 0)
        XL_LOG(ctx, XL_LOG_ERROR, "libxl_destroy_devices failed for %d", domid);

    vm_path = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/vm", dom_path));
    if (vm_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", vm_path);

    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "xs_rm failed for %s", dom_path);

    libxl__userdata_destroyall(ctx, domid);

    rc = xc_domain_destroy(ctx->xch, domid);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc, "xc_domain_destroy failed for %d", domid);
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;
out:
    libxl_free_all(&gc);
    return 0;
}

int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *p = libxl_sprintf(&gc, "%s/xenconsole", libxl_private_bindir_path());
    char *domid_s = libxl_sprintf(&gc, "%d", domid);
    char *cons_num_s = libxl_sprintf(&gc, "%d", cons_num);
    execl(p, p, domid_s, "--num", cons_num_s, (void *)NULL);
    libxl_free_all(&gc);
    return ERROR_FAIL;
}

int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm)
{
    uint32_t stubdomid = libxl_get_stubdom_id(ctx, domid_vm);
    if (stubdomid)
        return libxl_console_exec(ctx, stubdomid, 1);
    else
        return libxl_console_exec(ctx, domid_vm, 0);
}

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    const char *vnc_port, *vfb_back;
    const char *vnc_listen = NULL, *vnc_pass = NULL;
    int port = 0, autopass_fd = -1;
    char *vnc_bin, *args[] = {
        "vncviewer",
        NULL, /* hostname:display */
        NULL, /* -autopass */
        NULL,
    };

    vnc_port = libxl_xs_read(&gc, XBT_NULL,
                            libxl_sprintf(&gc,
                            "/local/domain/%d/console/vnc-port", domid));
    if ( vnc_port )
        port = atoi(vnc_port) - 5900;

    vfb_back = libxl_xs_read(&gc, XBT_NULL,
                            libxl_sprintf(&gc,
                            "/local/domain/%d/device/vfb/0/backend", domid));
    if ( vfb_back ) {
        vnc_listen = libxl_xs_read(&gc, XBT_NULL,
                            libxl_sprintf(&gc,
                            "/local/domain/%d/console/vnc-listen", domid));
        if ( autopass )
            vnc_pass = libxl_xs_read(&gc, XBT_NULL,
                            libxl_sprintf(&gc,
                            "/local/domain/%d/console/vnc-pass", domid));
    }

    if ( NULL == vnc_listen )
        vnc_listen = "localhost";

    if ( (vnc_bin = getenv("VNCVIEWER")) )
        args[0] = vnc_bin;

    args[1] = libxl_sprintf(&gc, "%s:%d", vnc_listen, port);

    if ( vnc_pass ) {
        char tmpname[] = "/tmp/vncautopass.XXXXXX";
        autopass_fd = mkstemp(tmpname);
        if ( autopass_fd < 0 )
            goto skip_autopass;

        if ( unlink(tmpname) )
            /* should never happen */
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "unlink %s failed", tmpname);

        if ( libxl_write_exactly(ctx, autopass_fd, vnc_pass, strlen(vnc_pass),
                                    tmpname, "vnc password") ) {
            do { close(autopass_fd); } while(errno == EINTR);
            goto skip_autopass;
        }

        args[2] = "-autopass";
    }

skip_autopass:
    libxl_free_all(&gc);
    libxl_exec(autopass_fd, -1, -1, args[0], args);
    return 0;
}

static char ** libxl_build_device_model_args_old(libxl_gc *gc,
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

    flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d", info->domid));

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
                    libxl_sprintf(gc, "%s:%d%s",
                                  info->vnclisten,
                                  info->vncdisplay,
                                  info->vncpasswd ? ",password" : ""));
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "127.0.0.1:%d", info->vncdisplay));
            }
        } else if (info->vnclisten) {
            if (strchr(info->vnclisten, ':') != NULL) {
                flexarray_set(dm_args, num++, info->vnclisten);
            } else {
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "%s:0", info->vnclisten));
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
        int ioemu_vifs = 0;

        if (info->videoram) {
            flexarray_set(dm_args, num++, "-videoram");
            flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d", info->videoram));
        }
        if (info->stdvga) {
            flexarray_set(dm_args, num++, "-std-vga");
        }

        if (info->boot) {
            flexarray_set(dm_args, num++, "-boot");
            flexarray_set(dm_args, num++, info->boot);
        }
        if (info->usb || info->usbdevice) {
            flexarray_set(dm_args, num++, "-usb");
            if (info->usbdevice) {
                flexarray_set(dm_args, num++, "-usbdevice");
                flexarray_set(dm_args, num++, info->usbdevice);
            }
        }
        if (info->soundhw) {
            flexarray_set(dm_args, num++, "-soundhw");
            flexarray_set(dm_args, num++, info->soundhw);
        }
        if (info->apic) {
            flexarray_set(dm_args, num++, "-acpi");
        }
        if (info->vcpus > 1) {
            flexarray_set(dm_args, num++, "-vcpus");
            flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d", info->vcpus));
        }
        if (info->vcpu_avail) {
            flexarray_set(dm_args, num++, "-vcpu_avail");
            flexarray_set(dm_args, num++, libxl_sprintf(gc, "0x%x", info->vcpu_avail));
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == NICTYPE_IOEMU) {
                char *smac = libxl_sprintf(gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2],
                                           vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
                if (!vifs[i].ifname)
                    vifs[i].ifname = libxl_sprintf(gc, "tap%d.%d", info->domid, vifs[i].devid);
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "nic,vlan=%d,macaddr=%s,model=%s",
                            vifs[i].devid, smac, vifs[i].model));
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "tap,vlan=%d,ifname=%s,bridge=%s,script=no",
                            vifs[i].devid, vifs[i].ifname, vifs[i].bridge));
                ioemu_vifs++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_vifs == 0 ) {
            flexarray_set(dm_args, num++, "-net");
            flexarray_set(dm_args, num++, "none");
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

static char ** libxl_build_device_model_args_new(libxl_gc *gc,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    int num = 0, i;
    flexarray_t *dm_args;
    int nb;
    libxl_device_disk *disks;

    dm_args = flexarray_make(16, 1);
    if (!dm_args)
        return NULL;

    flexarray_set(dm_args, num++, "qemu-system-xen");
    flexarray_set(dm_args, num++, "-xen-domid");

    flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d", info->domid));

    if (info->dom_name) {
        flexarray_set(dm_args, num++, "-name");
        flexarray_set(dm_args, num++, info->dom_name);
    }
    if (info->vnc || info->vncdisplay || info->vnclisten || info->vncunused) {
        int display = 0;
        const char *listen = "127.0.0.1";

        flexarray_set(dm_args, num++, "-vnc");

        if (info->vncdisplay) {
            display = info->vncdisplay;
            if (info->vnclisten && strchr(info->vnclisten, ':') == NULL) {
                listen = info->vnclisten;
            }
        } else if (info->vnclisten) {
            listen = info->vnclisten;
        }

        if (strchr(listen, ':') != NULL)
            flexarray_set(dm_args, num++,
                    libxl_sprintf(gc, "%s%s", listen,
                        info->vncunused ? ",to=99" : ""));
        else
            flexarray_set(dm_args, num++,
                    libxl_sprintf(gc, "%s:%d%s", listen, display,
                        info->vncunused ? ",to=99" : ""));
    }
    if (info->sdl) {
        flexarray_set(dm_args, num++, "-sdl");
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
        int ioemu_vifs = 0;

        if (info->stdvga) {
                flexarray_set(dm_args, num++, "-vga");
                flexarray_set(dm_args, num++, "std");
        }

        if (info->boot) {
            flexarray_set(dm_args, num++, "-boot");
            flexarray_set(dm_args, num++, libxl_sprintf(gc, "order=%s", info->boot));
        }
        if (info->usb || info->usbdevice) {
            flexarray_set(dm_args, num++, "-usb");
            if (info->usbdevice) {
                flexarray_set(dm_args, num++, "-usbdevice");
                flexarray_set(dm_args, num++, info->usbdevice);
            }
        }
        if (info->soundhw) {
            flexarray_set(dm_args, num++, "-soundhw");
            flexarray_set(dm_args, num++, info->soundhw);
        }
        if (!info->apic) {
            flexarray_set(dm_args, num++, "-no-acpi");
        }
        if (info->vcpus > 1) {
            flexarray_set(dm_args, num++, "-smp");
            if (info->vcpu_avail)
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d,maxcpus=%d", info->vcpus, info->vcpu_avail));
            else
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "%d", info->vcpus));
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == NICTYPE_IOEMU) {
                char *smac = libxl_sprintf(gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2],
                                           vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
                if (!vifs[i].ifname)
                    vifs[i].ifname = libxl_sprintf(gc, "tap%d.%d", info->domid, vifs[i].devid);
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "nic,vlan=%d,macaddr=%s,model=%s",
                            vifs[i].devid, smac, vifs[i].model));
                flexarray_set(dm_args, num++, "-net");
                flexarray_set(dm_args, num++, libxl_sprintf(gc, "tap,vlan=%d,ifname=%s,script=no",
                            vifs[i].devid, vifs[i].ifname));
                ioemu_vifs++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_vifs == 0 ) {
            flexarray_set(dm_args, num++, "-net");
            flexarray_set(dm_args, num++, "none");
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

    disks = libxl_device_disk_list(libxl_gc_owner(gc), info->domid, &nb);
    for (; nb > 0; --nb, ++disks) {
        if ( disks->is_cdrom ) {
            flexarray_set(dm_args, num++, "-cdrom");
            flexarray_set(dm_args, num++, disks->physpath);
        }else{
            flexarray_set(dm_args, num++, libxl_sprintf(gc, "-%s", disks->virtpath));
            flexarray_set(dm_args, num++, disks->physpath);
        }
    }
    free(disks);

    flexarray_set(dm_args, num++, NULL);
    return (char **) flexarray_contents(dm_args);
}

static char ** libxl_build_device_model_args(libxl_gc *gc,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    int new_qemu;

    new_qemu = libxl_check_device_model_version(ctx, info->device_model);

    if (new_qemu == 1) {
        return libxl_build_device_model_args_new(gc, info, vifs, num_vifs);
    } else {
        return libxl_build_device_model_args_old(gc, info, vifs, num_vifs);
    }
}

void dm_xenstore_record_pid(void *for_spawn, pid_t innerchild)
{
    libxl_device_model_starting *starting = for_spawn;
    char *kvs[3];
    int rc;
    struct xs_handle *xsh;

    xsh = xs_daemon_open();
    /* we mustn't use the parent's handle in the child */

    kvs[0] = "image/device-model-pid";
    if (asprintf(&kvs[1], "%d", innerchild) < 0)
        return;
    kvs[2] = NULL;

    rc = xs_writev(xsh, XBT_NULL, starting->dom_path, kvs);
    if (rc)
        return;
    xs_daemon_close(xsh);
}

static int libxl_vfb_and_vkb_from_device_model_info(libxl_ctx *ctx,
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

static int libxl_write_dmargs(libxl_ctx *ctx, int domid, int guest_domid, char **args)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
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

    vm_path = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "/local/domain/%d/vm", guest_domid));

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
    path = libxl_sprintf(&gc, "%s/image/dmargs", vm_path);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, path, dmargs, strlen(dmargs));
    xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(&gc, "%s/rtc/timeoffset", vm_path), roperm, ARRAY_SIZE(roperm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    free(dmargs);
    libxl_free_all(&gc);
    return 0;
}

static int libxl_create_stubdom(libxl_ctx *ctx,
                                libxl_device_model_info *info,
                                libxl_device_disk *disks, int num_disks,
                                libxl_device_nic *vifs, int num_vifs,
                                libxl_device_vfb *vfb,
                                libxl_device_vkb *vkb,
                                libxl_device_model_starting **starting_r)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
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

    args = libxl_build_device_model_args(&gc, info, vifs, num_vifs);
    if (!args) {
        ret = ERROR_FAIL;
        goto out;
    }

    memset(&c_info, 0x00, sizeof(libxl_domain_create_info));
    c_info.hvm = 0;
    c_info.name = libxl_sprintf(&gc, "%s-dm", _libxl_domid_to_name(&gc, info->domid));
    for (i = 0; i < 16; i++)
        c_info.uuid[i] = info->uuid[i];

    memset(&b_info, 0x00, sizeof(libxl_domain_build_info));
    b_info.max_vcpus = 1;
    b_info.max_memkb = 32 * 1024;
    b_info.target_memkb = b_info.max_memkb;
    b_info.kernel.path = libxl_abs_path(&gc, "ioemu-stubdom.gz", libxl_xenfirmwaredir_path());
    b_info.u.pv.cmdline = libxl_sprintf(&gc, " -d %d", info->domid);
    b_info.u.pv.ramdisk.path = "";
    b_info.u.pv.features = "";
    b_info.hvm = 0;

    ret = libxl_domain_make(ctx, &c_info, &domid);
    if (ret)
        goto out_free;
    ret = libxl_domain_build(ctx, &b_info, domid, &state);
    if (ret)
        goto out_free;

    libxl_write_dmargs(ctx, domid, info->domid, args);
    libxl_xs_write(&gc, XBT_NULL,
                   libxl_sprintf(&gc, "%s/image/device-model-domid", libxl_xs_get_dompath(&gc, info->domid)),
                   "%d", domid);
    libxl_xs_write(&gc, XBT_NULL,
                   libxl_sprintf(&gc, "%s/target", libxl_xs_get_dompath(&gc, domid)),
                   "%d", info->domid);
    ret = xc_domain_set_target(ctx->xch, domid, info->domid);
    if (ret<0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "setting target domain %d -> %d", domid, info->domid);
        ret = ERROR_FAIL;
        goto out_free;
    }
    xs_set_target(ctx->xsh, domid, info->domid);

    perm[0].id = domid;
    perm[0].perms = XS_PERM_NONE;
    perm[1].id = info->domid;
    perm[1].perms = XS_PERM_READ;
retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_mkdir(ctx->xsh, t, libxl_sprintf(&gc, "/local/domain/0/device-model/%d", info->domid));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(&gc, "/local/domain/0/device-model/%d", info->domid), perm, ARRAY_SIZE(perm));
    xs_mkdir(ctx->xsh, t, libxl_sprintf(&gc, "/local/domain/%d/device/vfs", domid));
    xs_set_permissions(ctx->xsh, t, libxl_sprintf(&gc, "/local/domain/%d/device/vfs",domid), perm, ARRAY_SIZE(perm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    for (i = 0; i < num_disks; i++) {
        disks[i].domid = domid;
        ret = libxl_device_disk_add(ctx, domid, &disks[i]);
        if (ret)
            goto out_free;
    }
    for (i = 0; i < num_vifs; i++) {
        vifs[i].domid = domid;
        ret = libxl_device_nic_add(ctx, domid, &vifs[i]);
        if (ret)
            goto out_free;
    }
    vfb->domid = domid;
    ret = libxl_device_vfb_add(ctx, domid, vfb);
    if (ret)
        goto out_free;
    vkb->domid = domid;
    ret = libxl_device_vkb_add(ctx, domid, vkb);
    if (ret)
        goto out_free;

    if (info->serial)
        num_console++;

    console = libxl_calloc(&gc, num_console, sizeof(libxl_device_console));
    if (!console) {
        ret = ERROR_NOMEM;
        goto out_free;
    }

    for (i = 0; i < num_console; i++) {
        console[i].devid = i;
        console[i].constype = CONSTYPE_IOEMU;
        console[i].domid = domid;
        if (!i)
            console[i].build_state = &state;
        ret = libxl_device_console_add(ctx, domid, &console[i]);
        if (ret)
            goto out_free;
    }
    if (libxl_create_xenpv_qemu(ctx, vfb, num_console, console, &dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }
    if (libxl_confirm_device_model_startup(ctx, dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }

    libxl_domain_unpause(ctx, domid);

    if (starting_r) {
        *starting_r = calloc(sizeof(libxl_device_model_starting), 1);
        (*starting_r)->domid = info->domid;
        (*starting_r)->dom_path = libxl_xs_get_dompath(&gc, info->domid);
        (*starting_r)->for_spawn = NULL;
    }

    ret = 0;

out_free:
    free(args);
out:
    libxl_free_all(&gc);
    return ret;
}

int libxl_create_device_model(libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_disk *disks, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl_device_model_starting **starting_r)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *path, *logfile;
    int logfile_w, null;
    int rc;
    char **args;
    libxl_device_model_starting buf_starting, *p;
    xs_transaction_t t; 
    char *vm_path;
    char **pass_stuff;

    if (strstr(info->device_model, "stubdom-dm")) {
        libxl_device_vfb vfb;
        libxl_device_vkb vkb;

        libxl_vfb_and_vkb_from_device_model_info(ctx, info, &vfb, &vkb);
        rc = libxl_create_stubdom(ctx, info, disks, num_disks, vifs, num_vifs, &vfb, &vkb, starting_r);
        goto out;
    }

    args = libxl_build_device_model_args(&gc, info, vifs, num_vifs);
    if (!args) {
        rc = ERROR_FAIL;
        goto out;
    }

    path = libxl_sprintf(&gc, "/local/domain/0/device-model/%d", info->domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);
    libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/disable_pf", path), "%d", !info->xen_platform_pci);

    libxl_create_logfile(ctx, libxl_sprintf(&gc, "qemu-dm-%s", info->dom_name), &logfile);
    logfile_w = open(logfile, O_WRONLY|O_CREAT, 0644);
    free(logfile);
    null = open("/dev/null", O_RDONLY);

    if (starting_r) {
        rc = ERROR_NOMEM;
        *starting_r = calloc(sizeof(libxl_device_model_starting), 1);
        if (!*starting_r)
            goto out_close;
        p = *starting_r;
        p->for_spawn = calloc(sizeof(libxl_spawn_starting), 1);
    } else {
        p = &buf_starting;
        p->for_spawn = NULL;
    }

    p->domid = info->domid;
    p->dom_path = libxl_xs_get_dompath(&gc, info->domid);
    if (!p->dom_path) {
        rc = ERROR_FAIL;
        goto out_close;
    }

    if (info->vncpasswd) {
retry_transaction:
        /* Find uuid and the write the vnc password to xenstore for qemu. */
        t = xs_transaction_start(ctx->xsh);
        vm_path = libxl_xs_read(&gc,t,libxl_sprintf(&gc, "%s/vm", p->dom_path));
        if (vm_path) {
            /* Now write the vncpassword into it. */
            pass_stuff = libxl_calloc(&gc, 2, sizeof(char *));
            pass_stuff[0] = "vncpasswd";
            pass_stuff[1] = info->vncpasswd;
            libxl_xs_writev(&gc,t,vm_path,pass_stuff);
            if (!xs_transaction_end(ctx->xsh, t, 0))
                if (errno == EAGAIN)
                    goto retry_transaction;
        }
    }

    rc = libxl_spawn_spawn(ctx, p, "device model", dm_xenstore_record_pid);
    if (rc < 0)
        goto out_close;
    if (!rc) { /* inner child */
        libxl_exec(null, logfile_w, logfile_w,
                   libxl_abs_path(&gc, info->device_model, libxl_private_bindir_path()),
                   args);
    }

    rc = 0;

out_close:
    close(null);
    close(logfile_w);
    free(args);
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_detach_device_model(libxl_ctx *ctx,
                              libxl_device_model_starting *starting)
{
    int rc;
    rc = libxl_spawn_detach(ctx, starting->for_spawn);
    if (starting->for_spawn)
        free(starting->for_spawn);
    free(starting);
    return rc;
}


int libxl_confirm_device_model_startup(libxl_ctx *ctx,
                                       libxl_device_model_starting *starting)
{
    int problem = libxl_wait_for_device_model(ctx, starting->domid, "running", NULL, NULL);
    int detach;
    if ( !problem )
        problem = libxl_spawn_check(ctx, starting->for_spawn);
    detach = libxl_detach_device_model(ctx, starting);
    return problem ? problem : detach;
}


/******************************************************************************/

static char *get_blktap2_device(libxl_gc *gc,
				const char *name, const char *type)
{
    int minor = tap_ctl_find_minor(type, name);
    if (minor < 0)
        return NULL;
    return libxl_sprintf(gc, "/dev/xen/blktap-2/tapdev%d", minor);
}

static char *make_blktap2_device(libxl_gc *gc,
				 const char *name, const char *type)
{
    char *params, *devname = NULL;
    int err;
    params = libxl_sprintf(gc, "%s:%s", type, name);
    err = tap_ctl_create(params, &devname);
    if (!err)
        libxl_ptr_add(gc, devname);
    return err ? NULL : devname;
}

int libxl_device_disk_add(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front;
    flexarray_t *back;
    char *backend_type;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    int devid;
    libxl_device device;
    int major, minor, rc;

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto out;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto out_free;
    }

    backend_type = device_disk_backend_type_of_phystype(disk->phystype);
    devid = device_disk_dev_number(disk->virtpath);
    if (devid==-1) {
        XL_LOG(ctx, XL_LOG_ERROR, "Invalid or unsupported"
               " virtual disk identifier %s", disk->virtpath);
        rc = ERROR_INVAL;
        goto out_free;
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
            flexarray_set(back, boffset++, libxl_sprintf(&gc, "%x:%x", major, minor));

            flexarray_set(back, boffset++, "params");
            flexarray_set(back, boffset++, disk->physpath);

            device.backend_kind = DEVICE_VBD;
            break;
        }
        case PHYSTYPE_FILE:
            /* let's pretend is tap:aio for the moment */
            disk->phystype = PHYSTYPE_AIO;
        case PHYSTYPE_AIO: case PHYSTYPE_QCOW: case PHYSTYPE_QCOW2: case PHYSTYPE_VHD: {
            const char *msg;
            if (!tap_ctl_check(&msg)) {
                const char *type = device_disk_string_of_phystype(disk->phystype);
                char *dev;
                dev = get_blktap2_device(&gc, disk->physpath, type);
                if (!dev)
                    dev = make_blktap2_device(&gc, disk->physpath, type);
                if (!dev) {
                    rc = ERROR_FAIL;
                    goto out_free;
                }
                flexarray_set(back, boffset++, "tapdisk-params");
                flexarray_set(back, boffset++, libxl_sprintf(&gc, "%s:%s", device_disk_string_of_phystype(disk->phystype), disk->physpath));
                flexarray_set(back, boffset++, "params");
                flexarray_set(back, boffset++, libxl_strdup(&gc, dev));
                backend_type = "phy";
                device_physdisk_major_minor(dev, &major, &minor);
                flexarray_set(back, boffset++, "physical-device");
                flexarray_set(back, boffset++, libxl_sprintf(&gc, "%x:%x", major, minor));
                device.backend_kind = DEVICE_VBD;

                break;
            }
            flexarray_set(back, boffset++, "params");
            flexarray_set(back, boffset++, libxl_sprintf(&gc, "%s:%s",
                          device_disk_string_of_phystype(disk->phystype), disk->physpath));

            device.backend_kind = DEVICE_TAP;
            break;
        }
        default:
            XL_LOG(ctx, XL_LOG_ERROR, "unrecognized disk physical type: %d\n", disk->phystype);
            rc = ERROR_INVAL;
            goto out_free;
    }

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", disk->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "removable");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", (disk->unpluggable) ? 1 : 0));
    flexarray_set(back, boffset++, "bootable");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "dev");
    flexarray_set(back, boffset++, disk->virtpath);
    flexarray_set(back, boffset++, "type");
    flexarray_set(back, boffset++, backend_type);
    flexarray_set(back, boffset++, "mode");
    flexarray_set(back, boffset++, disk->readwrite ? "w" : "r");

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", disk->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(front, foffset++, "virtual-device");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", devid));
    flexarray_set(front, foffset++, "device-type");
    flexarray_set(front, foffset++, disk->is_cdrom ? "cdrom" : "disk");

    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, "protocol");
        flexarray_set(front, foffset++, "x86_32-abi"); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));

    rc = 0;

out_free:
    flexarray_free(back);
    flexarray_free(front);
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_device_disk_del(libxl_ctx *ctx, 
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

char * libxl_device_disk_local_attach(libxl_ctx *ctx, libxl_device_disk *disk)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dev = NULL, *ret;
    int phystype = disk->phystype;
    switch (phystype) {
        case PHYSTYPE_PHY: {
            fprintf(stderr, "attaching PHY disk %s to domain 0\n", disk->physpath);
            dev = disk->physpath;
            break;
        }
        case PHYSTYPE_FILE:
            /* let's pretend is tap:aio for the moment */
            phystype = PHYSTYPE_AIO;
        case PHYSTYPE_AIO: case PHYSTYPE_QCOW: case PHYSTYPE_QCOW2: case PHYSTYPE_VHD: {
            const char *msg;
            if (!tap_ctl_check(&msg)) {
                const char *type = device_disk_string_of_phystype(phystype);
                dev = get_blktap2_device(&gc, disk->physpath, type);
                if (!dev)
                    dev = make_blktap2_device(&gc, disk->physpath, type);
            }
            break;
        }
        default:
            XL_LOG(ctx, XL_LOG_ERROR, "unrecognized disk physical type: %d\n", phystype);
            break;
    }
    ret = strdup(dev);
    libxl_free_all(&gc);
    return ret;
}

int libxl_device_disk_local_detach(libxl_ctx *ctx, libxl_device_disk *disk)
{
    /* Nothing to do for PHYSTYPE_PHY. */

    /*
     * For other device types assume that the blktap2 process is
     * needed by the soon to be started domain and do nothing.
     */

    return 0;
}

/******************************************************************************/
int libxl_device_nic_add(libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;
    char *dompath, **l;
    unsigned int nb, rc;

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto out;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto out_free;
    }

    if (nic->devid == -1) {
        if (!(dompath = libxl_xs_get_dompath(&gc, domid))) {
            rc = ERROR_FAIL;
            goto out_free;
        }
        if (!(l = libxl_xs_directory(&gc, XBT_NULL,
                                     libxl_sprintf(&gc, "%s/device/vif", dompath), &nb))) {
            nic->devid = 0;
        } else {
            nic->devid = strtoul(l[nb - 1], NULL, 10) + 1;
        }
    }

    device.backend_devid = nic->devid;
    device.backend_domid = nic->backend_domid;
    device.backend_kind = DEVICE_VIF;
    device.devid = nic->devid;
    device.domid = nic->domid;
    device.kind = DEVICE_VIF;

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", nic->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "script");
    flexarray_set(back, boffset++, nic->script);
    flexarray_set(back, boffset++, "mac");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                 nic->mac[0], nic->mac[1], nic->mac[2],
                                                 nic->mac[3], nic->mac[4], nic->mac[5]));
    flexarray_set(back, boffset++, "bridge");
    flexarray_set(back, boffset++, libxl_strdup(&gc, nic->bridge));
    flexarray_set(back, boffset++, "handle");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", nic->devid));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", nic->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(front, foffset++, "handle");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", nic->devid));
    flexarray_set(front, foffset++, "mac");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  nic->mac[0], nic->mac[1], nic->mac[2],
                                                  nic->mac[3], nic->mac[4], nic->mac[5]));
    if (0 /* protocol != native*/) {
        flexarray_set(front, foffset++, "protocol");
        flexarray_set(front, foffset++, "x86_32-abi"); /* hardcoded ! */
    }

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));

    /* FIXME: wait for plug */
    rc = 0;
out_free:
    flexarray_free(back);
    flexarray_free(front);
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_device_nic_del(libxl_ctx *ctx, 
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

void libxl_free_nics_list(libxl_nicinfo *nics, unsigned int nb)
{
    unsigned int i;
    for(i = 0; i < nb; i++) {
        free(nics[i].backend);
        free(nics[i].frontend);
        free(nics[i].script);
    }
    free(nics);
}

libxl_nicinfo *libxl_list_nics(libxl_ctx *ctx, uint32_t domid, unsigned int *nb)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dompath, *nic_path_fe;
    char **l, **list;
    char *val, *tok;
    unsigned int nb_nics, i;
    libxl_nicinfo *res, *nics;

    dompath = libxl_xs_get_dompath(&gc, domid);
    if (!dompath)
        goto err;
    list = l = libxl_xs_directory(&gc, XBT_NULL,
                           libxl_sprintf(&gc, "%s/device/vif", dompath), &nb_nics);
    if (!l)
        goto err;
    nics = res = calloc(nb_nics, sizeof (libxl_device_nic));
    if (!res)
        goto err;
    for (*nb = nb_nics; nb_nics > 0; --nb_nics, ++l, ++nics) {
        nic_path_fe = libxl_sprintf(&gc, "%s/device/vif/%s", dompath, *l);

        nics->backend = xs_read(ctx->xsh, XBT_NULL,
                                libxl_sprintf(&gc, "%s/backend", nic_path_fe), NULL);
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/backend-id", nic_path_fe));
        nics->backend_id = val ? strtoul(val, NULL, 10) : -1;

        nics->devid = strtoul(*l, NULL, 10);
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/state", nic_path_fe));
        nics->state = val ? strtoul(val, NULL, 10) : -1;
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/mac", nic_path_fe));
        for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
             ++i, tok = strtok(NULL, ":")) {
            nics->mac[i] = strtoul(tok, NULL, 16);
        }
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/event-channel", nic_path_fe));
        nics->evtch = val ? strtol(val, NULL, 10) : -1;
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/tx-ring-ref", nic_path_fe));
        nics->rref_tx = val ? strtol(val, NULL, 10) : -1;
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/rx-ring-ref", nic_path_fe));
        nics->rref_rx = val ? strtol(val, NULL, 10) : -1;
        nics->frontend = xs_read(ctx->xsh, XBT_NULL,
                                 libxl_sprintf(&gc, "%s/frontend", nics->backend), NULL);
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/frontend-id", nics->backend));
        nics->frontend_id = val ? strtoul(val, NULL, 10) : -1;
        nics->script = xs_read(ctx->xsh, XBT_NULL,
                               libxl_sprintf(&gc, "%s/script", nics->backend), NULL);
    }

    libxl_free_all(&gc);
    return res;
err:
    libxl_free_all(&gc);
    return NULL;
}

/******************************************************************************/
int libxl_device_net2_add(libxl_ctx *ctx, uint32_t domid, libxl_device_net2 *net2)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front, *back;
    unsigned int boffset = 0, foffset = 0;
    libxl_device device;
    char *dompath, *dom, **l;
    unsigned int nb;
    int rc;

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto err;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto err_free;
    }

    if (!(dompath = libxl_xs_get_dompath(&gc, domid))) {
        rc = ERROR_FAIL;
        goto err_free;
    }
    dom = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/name", dompath));

    if (net2->devid == -1) {
        if (!(l = libxl_xs_directory(&gc, XBT_NULL,
                                     libxl_sprintf(&gc, "%s/device/vif2", dompath), &nb))) {
            net2->devid = 0;
        } else {
            net2->devid = strtoul(l[nb - 1], NULL, 10) + 1;
        }
    }

    device.backend_devid = net2->devid;
    device.backend_domid = net2->backend_domid;
    device.backend_kind = DEVICE_VIF2;
    device.devid = net2->devid;
    device.domid = net2->domid;
    device.kind = DEVICE_VIF2;

    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, dom);
    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", net2->domid));

    flexarray_set(back, boffset++, "local-trusted");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", net2->back_trusted));
    flexarray_set(back, boffset++, "mac");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                 net2->back_mac[0], net2->back_mac[1],
                                                 net2->back_mac[2], net2->back_mac[3],
                                                 net2->back_mac[4], net2->back_mac[5]));

    flexarray_set(back, boffset++, "remote-trusted");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", net2->trusted));
    flexarray_set(back, boffset++, "remote-mac");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                 net2->front_mac[0], net2->front_mac[1],
                                                 net2->front_mac[2], net2->front_mac[3],
                                                 net2->front_mac[4], net2->front_mac[5]));

    flexarray_set(back, boffset++, "max-bypasses");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", net2->max_bypasses));
    flexarray_set(back, boffset++, "filter-mac");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", !!(net2->filter_mac)));
    flexarray_set(back, boffset++, "handle");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", net2->devid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, "1");

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", net2->backend_domid));

    flexarray_set(front, foffset++, "local-trusted");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", net2->trusted));
    flexarray_set(front, foffset++, "mac");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  net2->front_mac[0], net2->front_mac[1],
                                                  net2->front_mac[2], net2->front_mac[3],
                                                  net2->front_mac[4], net2->front_mac[5]));

    flexarray_set(front, foffset++, "remote-trusted");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", net2->back_trusted));
    flexarray_set(front, foffset++, "remote-mac");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                                  net2->back_mac[0], net2->back_mac[1],
                                                  net2->back_mac[2], net2->back_mac[3],
                                                  net2->back_mac[4], net2->back_mac[5]));

    flexarray_set(front, foffset++, "filter-mac");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", !!(net2->filter_mac)));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, "1");

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));

    /* FIXME: wait for plug */
    rc = 0;
err_free:
    flexarray_free(back);
    flexarray_free(front);
err:
    libxl_free_all(&gc);
    return rc;
}

libxl_net2info *libxl_device_net2_list(libxl_ctx *ctx, uint32_t domid, unsigned int *nb)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dompath, *net2_path_fe;
    char **l;
    char *val, *tok;
    unsigned int nb_net2s, i;
    libxl_net2info *res, *net2s;

    dompath = libxl_xs_get_dompath(&gc, domid);
    if (!dompath)
        goto err;
    l = libxl_xs_directory(&gc, XBT_NULL,
                           libxl_sprintf(&gc, "%s/device/vif2", dompath), &nb_net2s);
    if (!l)
        goto err;
    res = calloc(nb_net2s, sizeof (libxl_net2info));
    if (!res)
        goto err;
    net2s = res;
    for (*nb = nb_net2s; nb_net2s > 0; --nb_net2s, ++l, ++net2s) {
        net2_path_fe = libxl_sprintf(&gc, "%s/device/vif2/%s", dompath, *l);

        net2s->backend = libxl_xs_read(&gc, XBT_NULL,
                                       libxl_sprintf(&gc, "%s/backend", net2_path_fe));
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/backend-id", net2_path_fe));
        net2s->backend_id = val ? strtoul(val, NULL, 10) : -1;

        net2s->devid = strtoul(*l, NULL, 10);
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/state", net2_path_fe));
        net2s->state = val ? strtoul(val, NULL, 10) : -1;

        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/mac", net2_path_fe));
        for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
             ++i, tok = strtok(NULL, ":")) {
            net2s->mac[i] = strtoul(tok, NULL, 16);
        }
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/remote-trusted", net2_path_fe));
        net2s->trusted = val ? strtoul(val, NULL, 10) : -1;

        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/remote-mac", net2_path_fe));
        for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
             ++i, tok = strtok(NULL, ":")) {
            net2s->back_mac[i] = strtoul(tok, NULL, 16);
        }
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/filter-mac", net2_path_fe));
        net2s->filter_mac = val ? strtoul(val, NULL, 10) : -1;

        net2s->frontend = libxl_xs_read(&gc, XBT_NULL,
                                        libxl_sprintf(&gc, "%s/frontend", net2s->backend));
        val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/frontend-id", net2s->backend));
        net2s->frontend_id = val ? strtoul(val, NULL, 10) : -1;
    }

    libxl_free_all(&gc);
    return res;
err:
    libxl_free_all(&gc);
    return NULL;
}

int libxl_device_net2_del(libxl_ctx *ctx, libxl_device_net2 *net2, int wait)
{
    libxl_device device;

    device.backend_devid    = net2->devid;
    device.backend_domid    = net2->backend_domid;
    device.backend_kind     = DEVICE_VIF2;
    device.devid            = net2->devid;
    device.domid            = net2->domid;
    device.kind             = DEVICE_VIF2;

    return libxl_device_del(ctx, &device, wait);
}


/******************************************************************************/
int libxl_device_console_add(libxl_ctx *ctx, uint32_t domid, libxl_device_console *console)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;
    int rc;

    if (console->build_state) {
        xs_transaction_t t;
        char **ents = (char **) libxl_calloc(&gc, 9, sizeof(char *));
        ents[0] = "console/port";
        ents[1] = libxl_sprintf(&gc, "%"PRIu32, console->build_state->console_port);
        ents[2] = "console/ring-ref";
        ents[3] = libxl_sprintf(&gc, "%lu", console->build_state->console_mfn);
        ents[4] = "console/limit";
        ents[5] = libxl_sprintf(&gc, "%d", LIBXL_XENCONSOLE_LIMIT);
        ents[6] = "console/type";
        if (console->constype == CONSTYPE_XENCONSOLED)
            ents[7] = "xenconsoled";
        else
            ents[7] = "ioemu";
retry_transaction:
        t = xs_transaction_start(ctx->xsh);
        libxl_xs_writev(&gc, t, libxl_xs_get_dompath(&gc, console->domid), ents);
        if (!xs_transaction_end(ctx->xsh, t, 0))
            if (errno == EAGAIN)
                goto retry_transaction;
    }

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto out;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto out_free;
    }

    device.backend_devid = console->devid;
    device.backend_domid = console->backend_domid;
    device.backend_kind = DEVICE_CONSOLE;
    device.devid = console->devid;
    device.domid = console->domid;
    device.kind = DEVICE_CONSOLE;

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", console->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, _libxl_domid_to_name(&gc, domid));
    flexarray_set(back, boffset++, "protocol");
    flexarray_set(back, boffset++, LIBXL_XENCONSOLE_PROTOCOL);

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", console->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(front, foffset++, "limit");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_set(front, foffset++, "protocol");
    flexarray_set(front, foffset++, LIBXL_XENCONSOLE_PROTOCOL);
    flexarray_set(front, foffset++, "type");
    if (console->constype == CONSTYPE_XENCONSOLED)
        flexarray_set(front, foffset++, "xenconsoled");
    else
        flexarray_set(front, foffset++, "ioemu");

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));
    rc = 0;
out_free:
    flexarray_free(back);
    flexarray_free(front);
out:
    libxl_free_all(&gc);
    return rc;
}

/******************************************************************************/
int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;
    int rc;

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto out;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto out_free;
    }

    device.backend_devid = vkb->devid;
    device.backend_domid = vkb->backend_domid;
    device.backend_kind = DEVICE_VKBD;
    device.devid = vkb->devid;
    device.domid = vkb->domid;
    device.kind = DEVICE_VKBD;

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vkb->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, _libxl_domid_to_name(&gc, domid));

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", vkb->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));
    rc = 0;
out_free:
    flexarray_free(back);
    flexarray_free(front);
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_device_vkb_clean_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vkb_hard_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

libxl_device_disk *libxl_device_disk_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *be_path_tap, *be_path_vbd;
    libxl_device_disk *dend, *disks, *ret = NULL;
    char **b, **l = NULL;
    unsigned int numl;
    char *type;

    be_path_vbd = libxl_sprintf(&gc, "%s/backend/vbd/%d", libxl_xs_get_dompath(&gc, 0), domid);
    be_path_tap = libxl_sprintf(&gc, "%s/backend/tap/%d", libxl_xs_get_dompath(&gc, 0), domid);

    b = l = libxl_xs_directory(&gc, XBT_NULL, be_path_vbd, &numl);
    if (l) {
        ret = realloc(ret, sizeof(libxl_device_disk) * numl);
        disks = ret;
        *num = numl;
        dend = ret + *num;
        for (; disks < dend; ++disks, ++l) {
            disks->backend_domid = 0;
            disks->domid = domid;
            disks->physpath = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/params", be_path_vbd, *l));
            libxl_string_to_phystype(ctx, libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/type", be_path_vbd, *l)), &(disks->phystype));
            disks->virtpath = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/dev", be_path_vbd, *l));
            disks->unpluggable = atoi(libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/removable", be_path_vbd, *l)));
            if (!strcmp(libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/mode", be_path_vbd, *l)), "w"))
                disks->readwrite = 1;
            else
                disks->readwrite = 0;
            type = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/device-type", libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/frontend", be_path_vbd, *l))));
            disks->is_cdrom = !strcmp(type, "cdrom");
        }
    }
    b = l = libxl_xs_directory(&gc, XBT_NULL, be_path_tap, &numl);
    if (l) {
        ret = realloc(ret, sizeof(libxl_device_disk) * (*num + numl));
        disks = ret + *num;
        *num += numl;
        for (dend = ret + *num; disks < dend; ++disks, ++l) {
            disks->backend_domid = 0;
            disks->domid = domid;
            disks->physpath = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/params", be_path_tap, *l));
            libxl_string_to_phystype(ctx, libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/type", be_path_tap, *l)), &(disks->phystype));
            disks->virtpath = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/dev", be_path_tap, *l));
            disks->unpluggable = atoi(libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/removable", be_path_tap, *l)));
            if (!strcmp(libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/mode", be_path_tap, *l)), "w"))
                disks->readwrite = 1;
            else
                disks->readwrite = 0;
            type = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/device-type", libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/%s/frontend", be_path_tap, *l))));
            disks->is_cdrom = !strcmp(type, "cdrom");
        }
    }
    libxl_free_all(&gc);
    return ret;
}

int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk, libxl_diskinfo *diskinfo)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dompath, *diskpath;
    char *val;

    dompath = libxl_xs_get_dompath(&gc, domid);
    diskinfo->devid = device_disk_dev_number(disk->virtpath);

    /* tap devices entries in xenstore are written as vbd devices. */
    diskpath = libxl_sprintf(&gc, "%s/device/vbd/%d", dompath, diskinfo->devid);
    diskinfo->backend = libxl_xs_read(&gc, XBT_NULL,
                                      libxl_sprintf(&gc, "%s/backend", diskpath));
    if (!diskinfo->backend) {
        libxl_free_all(&gc);
        return ERROR_FAIL;
    }
    val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/backend-id", diskpath));
    diskinfo->backend_id = val ? strtoul(val, NULL, 10) : -1;
    val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/state", diskpath));
    diskinfo->state = val ? strtoul(val, NULL, 10) : -1;
    val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/event-channel", diskpath));
    diskinfo->evtch = val ? strtoul(val, NULL, 10) : -1;
    val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/ring-ref", diskpath));
    diskinfo->rref = val ? strtoul(val, NULL, 10) : -1;
    diskinfo->frontend = libxl_xs_read(&gc, XBT_NULL,
                                       libxl_sprintf(&gc, "%s/frontend", diskinfo->backend));
    val = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/frontend-id", diskinfo->backend));
    diskinfo->frontend_id = val ? strtoul(val, NULL, 10) : -1;

    libxl_free_all(&gc);
    return 0;
}

int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk)
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
        free(disks);
        return ERROR_FAIL;
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
    free(disks);
    return 0;
}

/******************************************************************************/
static int libxl_build_xenpv_qemu_args(libxl_gc *gc,
                                       libxl_device_vfb *vfb,
                                       int num_console,
                                       libxl_device_console *console,
                                       libxl_device_model_info *info)
{
    libxl_ctx *ctx = libxl_gc_owner(gc);
    int i = 0, j = 0, num = 0;
    memset(info, 0x00, sizeof(libxl_device_model_info));

    info->vnc = vfb->vnc;
    if (vfb->vnclisten)
        info->vnclisten = libxl_strdup(gc, vfb->vnclisten);
    info->vncdisplay = vfb->vncdisplay;
    info->vncunused = vfb->vncunused;
    if (vfb->vncpasswd)
        info->vncpasswd = vfb->vncpasswd;
    if (vfb->keymap)
        info->keymap = libxl_strdup(gc, vfb->keymap);
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
            char *name = libxl_sprintf(gc, "qemu-dm-%s", _libxl_domid_to_name(gc, guest_domid));
            libxl_create_logfile(ctx, name, &filename);
            info->serial = libxl_sprintf(gc, "file:%s", filename);
            free(filename);
        } else {
            info->serial = "pty";
        }
        num--;
    }
    if (num > 0) {
        info->extra = (char **) libxl_calloc(gc, num * 2 + 1, sizeof(char *));
        for (j = 0; j < num * 2; j = j + 2) {
            info->extra[j] = "-serial";
            info->extra[j + 1] = "pty";
        }
        info->extra[j] = NULL;
    }
    info->domid = vfb->domid;
    info->dom_name = _libxl_domid_to_name(gc, vfb->domid);
    info->device_model = libxl_abs_path(gc, "qemu-dm", libxl_libexec_path());
    info->type = XENPV;
    return 0;
}

int libxl_create_xenpv_qemu(libxl_ctx *ctx, libxl_device_vfb *vfb,
                            int num_console, libxl_device_console *console,
                            libxl_device_model_starting **starting_r)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    libxl_device_model_info info;

    libxl_build_xenpv_qemu_args(&gc, vfb, num_console, console, &info);
    libxl_create_device_model(ctx, &info, NULL, 0, NULL, 0, starting_r);
    libxl_free_all(&gc);
    return 0;
}

int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    flexarray_t *front;
    flexarray_t *back;
    unsigned int boffset = 0;
    unsigned int foffset = 0;
    libxl_device device;
    int rc;

    front = flexarray_make(16, 1);
    if (!front) {
        rc = ERROR_NOMEM;
        goto out;
    }
    back = flexarray_make(16, 1);
    if (!back) {
        rc = ERROR_NOMEM;
        goto out_free;
    }

    device.backend_devid = vfb->devid;
    device.backend_domid = vfb->backend_domid;
    device.backend_kind = DEVICE_VFB;
    device.devid = vfb->devid;
    device.domid = vfb->domid;
    device.kind = DEVICE_VFB;

    flexarray_set(back, boffset++, "frontend-id");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->domid));
    flexarray_set(back, boffset++, "online");
    flexarray_set(back, boffset++, "1");
    flexarray_set(back, boffset++, "state");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", 1));
    flexarray_set(back, boffset++, "domain");
    flexarray_set(back, boffset++, _libxl_domid_to_name(&gc, domid));
    flexarray_set(back, boffset++, "vnc");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->vnc));
    flexarray_set(back, boffset++, "vnclisten");
    flexarray_set(back, boffset++, vfb->vnclisten);
    flexarray_set(back, boffset++, "vncpasswd");
    flexarray_set(back, boffset++, vfb->vncpasswd);
    flexarray_set(back, boffset++, "vncdisplay");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->vncdisplay));
    flexarray_set(back, boffset++, "vncunused");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->vncunused));
    flexarray_set(back, boffset++, "sdl");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->sdl));
    flexarray_set(back, boffset++, "opengl");
    flexarray_set(back, boffset++, libxl_sprintf(&gc, "%d", vfb->opengl));
    if (vfb->xauthority) {
        flexarray_set(back, boffset++, "xauthority");
        flexarray_set(back, boffset++, vfb->xauthority);
    }
    if (vfb->display) {
        flexarray_set(back, boffset++, "display");
        flexarray_set(back, boffset++, vfb->display);
    }

    flexarray_set(front, foffset++, "backend-id");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", vfb->backend_domid));
    flexarray_set(front, foffset++, "state");
    flexarray_set(front, foffset++, libxl_sprintf(&gc, "%d", 1));

    libxl_device_generic_add(ctx, &device,
                             libxl_xs_kvs_of_flexarray(&gc, back, boffset),
                             libxl_xs_kvs_of_flexarray(&gc, front, foffset));
    rc = 0;
out_free:
    flexarray_free(front);
    flexarray_free(back);
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_device_vfb_clean_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

int libxl_device_vfb_hard_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    return ERROR_NI;
}

/******************************************************************************/

int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint32_t max_memkb)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *mem, *endptr;
    uint32_t memorykb;
    char *dompath = libxl_xs_get_dompath(&gc, domid);
    int rc = 1;

    mem = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/memory/target", dompath));
    if (!mem) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "cannot get memory info from %s/memory/target\n", dompath);
        goto out;
    }
    memorykb = strtoul(mem, &endptr, 10);
    if (*endptr != '\0') {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "invalid memory %s from %s/memory/target\n", mem, dompath);
        goto out;
    }

    if (max_memkb < memorykb) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "memory_static_max must be greater than or or equal to memory_dynamic_max\n");
        goto out;
    }

    if (domid != 0)
        libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/memory/static-max", dompath), "%"PRIu32, max_memkb);

    rc = 0;
out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid, uint32_t target_memkb, int enforce)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    int rc = 1;
    uint32_t memorykb = 0, videoram = 0;
    char *memmax, *endptr, *videoram_s = NULL;
    char *dompath = libxl_xs_get_dompath(&gc, domid);
    xc_domaininfo_t info;
    libxl_dominfo ptr;
    char *uuid;

    if (domid) {
        memmax = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/memory/static-max", dompath));
        if (!memmax) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR,
                "cannot get memory info from %s/memory/static-max\n", dompath);
            goto out;
        }
        memorykb = strtoul(memmax, &endptr, 10);
        if (*endptr != '\0') {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR,
                "invalid max memory %s from %s/memory/static-max\n", memmax, dompath);
            goto out;
        }

        if (target_memkb > memorykb) {
            XL_LOG(ctx, XL_LOG_ERROR,
                "memory_dynamic_max must be less than or equal to memory_static_max\n");
            goto out;
        }
    }

    videoram_s = libxl_xs_read(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/memory/videoram", dompath));
    videoram = videoram_s ? atoi(videoram_s) : 0;

    libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/memory/target", dompath), "%"PRIu32, target_memkb);

    rc = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (rc != 1 || info.domain != domid)
        goto out;
    xcinfo2xlinfo(&info, &ptr);
    uuid = libxl_uuid2string(ctx, ptr.uuid);
    libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "/vm/%s/memory", uuid), "%"PRIu32, target_memkb / 1024);

    if (enforce || !domid)
        memorykb = target_memkb;
    rc = xc_domain_setmaxmem(ctx->xch, domid, memorykb + LIBXL_MAXMEM_CONSTANT);
    if (rc != 0)
        goto out;
    rc = xc_domain_memory_set_pod_target(ctx->xch, domid, (target_memkb - videoram) / 4, NULL, NULL, NULL);

out:
    libxl_free_all(&gc);
    return rc;
}

int libxl_button_press(libxl_ctx *ctx, uint32_t domid, libxl_button button)
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

int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo)
{
    xc_physinfo_t xcphysinfo = { 0 };
    int rc;

    rc = xc_physinfo(ctx->xch, &xcphysinfo);
    if (rc != 0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting physinfo");
        return ERROR_FAIL;
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

static void do_free_version_info(libxl_version_info *info)
{
    free(info->xen_version_extra);
    free(info->compiler);
    free(info->compile_by);
    free(info->compile_domain);
    free(info->compile_date);
    free(info->capabilities);
    free(info->changeset);
    free(info->commandline);
}

const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx)
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
    info->xen_version_extra = strdup(u.xen_extra);

    xc_version(ctx->xch, XENVER_compile_info, &u.xen_cc);
    info->compiler = strdup(u.xen_cc.compiler);
    info->compile_by = strdup(u.xen_cc.compile_by);
    info->compile_domain = strdup(u.xen_cc.compile_domain);
    info->compile_date = strdup(u.xen_cc.compile_date);

    xc_version(ctx->xch, XENVER_capabilities, &u.xen_caps);
    info->capabilities = strdup(u.xen_caps);

    xc_version(ctx->xch, XENVER_changeset, &u.xen_chgset);
    info->changeset = strdup(u.xen_chgset);

    xc_version(ctx->xch, XENVER_platform_parameters, &u.p_parms);
    info->virt_start = u.p_parms.virt_start;

    info->pagesize = xc_version(ctx->xch, XENVER_pagesize, NULL);

    xc_version(ctx->xch, XENVER_commandline, &u.xen_commandline);
    info->commandline = strdup(u.xen_commandline);

    return info;
}

libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
                                       int *nb_vcpu, int *nrcpus)
{
    libxl_vcpuinfo *ptr, *ret;
    xc_domaininfo_t domaininfo;
    xc_vcpuinfo_t vcpuinfo;
    xc_physinfo_t physinfo = { 0 };
    uint64_t *cpumaps;
    unsigned num_cpuwords;

    if (xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo) != 1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting infolist");
        return NULL;
    }
    if (xc_physinfo(ctx->xch, &physinfo) == -1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting physinfo");
        return NULL;
    }
    *nrcpus = physinfo.max_cpu_id + 1;
    ret = ptr = calloc(domaininfo.max_vcpu_id + 1, sizeof (libxl_vcpuinfo));
    if (!ptr) {
        return NULL;
    }

    num_cpuwords = ((physinfo.max_cpu_id + 64) / 64);
    cpumaps = calloc(num_cpuwords * sizeof(*cpumaps), domaininfo.max_vcpu_id + 1);
    for (*nb_vcpu = 0; *nb_vcpu <= domaininfo.max_vcpu_id; ++*nb_vcpu, ++ptr) {
        ptr->cpumap = cpumaps + (num_cpuwords * *nb_vcpu);
        if (!ptr->cpumap) {
            return NULL;
        }
        if (xc_vcpu_getinfo(ctx->xch, domid, *nb_vcpu, &vcpuinfo) == -1) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting vcpu info");
            return NULL;
        }
        if (xc_vcpu_getaffinity(ctx->xch, domid, *nb_vcpu,
            ptr->cpumap, ((*nrcpus) + 7) / 8) == -1) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting vcpu affinity");
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

void libxl_free_vcpu_list(libxl_vcpuinfo *vcpu)
{
    if ( vcpu )
        free(vcpu[0].cpumap);
    free(vcpu);
}

int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           uint64_t *cpumap, int nrcpus)
{
    if (xc_vcpu_setaffinity(ctx->xch, domid, vcpuid, cpumap, (nrcpus + 7) / 8)) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "setting vcpu affinity");
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_set_vcpucount(libxl_ctx *ctx, uint32_t domid, uint32_t count)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    xc_domaininfo_t domaininfo;
    char *dompath;
    int i, rc = ERROR_FAIL;

    if (xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo) != 1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting domain info list");
        goto out;
    }
    if (!count || ((domaininfo.max_vcpu_id + 1) < count)) {
        rc = ERROR_INVAL;
        goto out;
    }
    if (!(dompath = libxl_xs_get_dompath(&gc, domid)))
        goto out;

    for (i = 0; i <= domaininfo.max_vcpu_id; ++i) {
        libxl_xs_write(&gc, XBT_NULL,
                       libxl_sprintf(&gc, "%s/cpu/%u/availability", dompath, i),
                       "%s", ((1 << i) & ((1 << count) - 1)) ? "online" : "offline");
    }
    rc = 0;
out:
    libxl_free_all(&gc);
    return rc;
}

/*
 * returns one of the XEN_SCHEDULER_* constants from public/domctl.h
 */
int libxl_get_sched_id(libxl_ctx *ctx)
{
    int sched, ret;

    if ((ret = xc_sched_id(ctx->xch, &sched)) != 0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting domain info list");
        return ERROR_FAIL;
    }
    return sched;
}

int libxl_sched_credit_domain_get(libxl_ctx *ctx, uint32_t domid, libxl_sched_credit *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    int rc;

    rc = xc_sched_credit_domain_get(ctx->xch, domid, &sdom);
    if (rc != 0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "setting domain sched credit");
        return ERROR_FAIL;
    }

    scinfo->weight = sdom.weight;
    scinfo->cap = sdom.cap;

    return 0;
}

int libxl_sched_credit_domain_set(libxl_ctx *ctx, uint32_t domid, libxl_sched_credit *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    xc_domaininfo_t domaininfo;
    int rc;

    rc = xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo);
    if (rc < 0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "getting domain info list");
        return ERROR_FAIL;
    }
    if (rc != 1 || domaininfo.domain != domid)
        return ERROR_INVAL;


    if (scinfo->weight < 1 || scinfo->weight > 65535) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Cpu weight out of range, valid values are within range from 1 to 65535");
        return ERROR_INVAL;
    }

    if (scinfo->cap < 0 || scinfo->cap > (domaininfo.max_vcpu_id + 1) * 100) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Cpu cap out of range, valid range is from 0 to %d for specified number of vcpus",
            ((domaininfo.max_vcpu_id + 1) * 100));
        return ERROR_INVAL;
    }

    sdom.weight = scinfo->weight;
    sdom.cap = scinfo->cap;

    rc = xc_sched_credit_domain_set(ctx->xch, domid, &sdom);
    if ( rc < 0 ) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "setting domain sched credit");
        return ERROR_FAIL;
    }

    return 0;
}

static int trigger_type_from_string(char *trigger_name)
{
    if (!strcmp(trigger_name, "nmi"))
        return XEN_DOMCTL_SENDTRIGGER_NMI;
    else if (!strcmp(trigger_name, "reset"))
        return XEN_DOMCTL_SENDTRIGGER_RESET;
    else if (!strcmp(trigger_name, "init"))
        return XEN_DOMCTL_SENDTRIGGER_INIT;
    else if (!strcmp(trigger_name, "power"))
        return XEN_DOMCTL_SENDTRIGGER_POWER;
    else if (!strcmp(trigger_name, "sleep"))
        return XEN_DOMCTL_SENDTRIGGER_SLEEP;
    else
        return -1;
}

int libxl_send_trigger(libxl_ctx *ctx, uint32_t domid, char *trigger_name, uint32_t vcpuid)
{
    int rc = -1;
    int trigger_type = trigger_type_from_string(trigger_name);

    if (trigger_type == -1) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, -1,
            "Invalid trigger, valid triggers are <nmi|reset|init|power|sleep>");
        return ERROR_INVAL;
    }

    rc = xc_domain_send_trigger(ctx->xch, domid, trigger_type, vcpuid);
    if (rc != 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Send trigger '%s' failed", trigger_name);
        return ERROR_FAIL;
    }

    return 0;
}

int libxl_send_sysrq(libxl_ctx *ctx, uint32_t domid, char sysrq)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dompath = libxl_xs_get_dompath(&gc, domid);

    libxl_xs_write(&gc, XBT_NULL, libxl_sprintf(&gc, "%s/control/sysrq", dompath), "%c", sysrq);

    libxl_free_all(&gc);
    return 0;
}

int libxl_send_debug_keys(libxl_ctx *ctx, char *keys)
{
    int ret;
    ret = xc_send_debug_keys(ctx->xch, keys);
    if ( ret < 0 ) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "sending debug keys");
        return ERROR_FAIL;
    }
    return 0;
}

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear)
{
    libxl_xen_console_reader *cr;
    unsigned int size = 16384;
    char *buf = malloc(size);

    if (!buf) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "cannot malloc buffer for libxl_xen_console_reader,"
            " size is %u", size);
        return NULL;
    }

    cr = malloc(sizeof(libxl_xen_console_reader));
    if (!cr) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "cannot malloc libxl_xen_console_reader");
        return NULL;
    }

    memset(cr, 0, sizeof(libxl_xen_console_reader));
    cr->buffer = buf;
    cr->size = size;
    cr->count = size;
    cr->clear = clear;
    cr->incremental = 1;

    return cr;
}

/* return values:                                          *line_r
 *   1          success, whole line obtained from buffer    non-0
 *   0          no more lines available right now           0
 *   negative   error code ERROR_*                          0
 * On success *line_r is updated to point to a nul-terminated
 * string which is valid until the next call on the same console
 * reader.  The libxl caller may overwrite parts of the string
 * if it wishes. */
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r)
{
    int ret;

    memset(cr->buffer, 0, cr->size);
    ret = xc_readconsolering(ctx->xch, &cr->buffer, &cr->count,
                             cr->clear, cr->incremental, &cr->index);
    if (ret < 0) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "reading console ring buffer");
        return ERROR_FAIL;
    }
    if (!ret) {
        if (cr->count) {
            *line_r = cr->buffer;
            ret = 1;
        } else {
            *line_r = NULL;
            ret = 0;
        }
    }

    return ret;
}

void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr)
{
    free(cr->buffer);
    free(cr);
}

uint32_t libxl_vm_get_start_time(libxl_ctx *ctx, uint32_t domid)
{
    libxl_gc gc = LIBXL_INIT_GC(ctx);
    char *dompath = libxl_xs_get_dompath(&gc, domid);
    char *vm_path, *start_time;
    uint32_t ret;

    vm_path = libxl_xs_read(
        &gc, XBT_NULL, libxl_sprintf(&gc, "%s/vm", dompath));
    start_time = libxl_xs_read(
        &gc, XBT_NULL, libxl_sprintf(&gc, "%s/start_time", vm_path));
    if (start_time == NULL) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, -1,
                        "Can't get start time of domain '%d'", domid);
        ret = -1;
    }else{
        ret = strtoul(start_time, NULL, 10);
    }
    libxl_free_all(&gc);
    return ret;
}

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long)
{
    int rc;
    char _buf[32768];

    rc = xc_tmem_control(ctx->xch, -1, TMEMC_LIST, domid, 32768, use_long,
                         0, _buf);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not get tmem list");
        return NULL;
    }

    return strdup(_buf);
}

int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid)
{
    int rc;

    rc = xc_tmem_control(ctx->xch, -1, TMEMC_FREEZE, domid, 0, 0,
                         0, NULL);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not freeze tmem pools");
        return ERROR_FAIL;
    }

    return rc;
}

int libxl_tmem_destroy(libxl_ctx *ctx, uint32_t domid)
{
    int rc;

    rc = xc_tmem_control(ctx->xch, -1, TMEMC_DESTROY, domid, 0, 0,
                         0, NULL);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not destroy tmem pools");
        return ERROR_FAIL;
    }

    return rc;
}

int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid)
{
    int rc;

    rc = xc_tmem_control(ctx->xch, -1, TMEMC_THAW, domid, 0, 0,
                         0, NULL);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not thaw tmem pools");
        return ERROR_FAIL;
    }

    return rc;
}

static int32_t tmem_setop_from_string(char *set_name)
{
    if (!strcmp(set_name, "weight"))
        return TMEMC_SET_WEIGHT;
    else if (!strcmp(set_name, "cap"))
        return TMEMC_SET_CAP;
    else if (!strcmp(set_name, "compress"))
        return TMEMC_SET_COMPRESS;
    else
        return -1;
}

int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name, uint32_t set)
{
    int rc;
    int32_t subop = tmem_setop_from_string(name);

    if (subop == -1) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, -1,
            "Invalid set, valid sets are <weight|cap|compress>");
        return ERROR_INVAL;
    }
    rc = xc_tmem_control(ctx->xch, -1, subop, domid, set, 0, 0, NULL);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not set tmem %s", name);
        return ERROR_FAIL;
    }

    return rc;
}

int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid,
                           char* uuid, int auth)
{
    int rc;

    rc = xc_tmem_auth(ctx->xch, domid, uuid, auth);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not set tmem shared auth");
        return ERROR_FAIL;
    }

    return rc;
}

int libxl_tmem_freeable(libxl_ctx *ctx)
{
    int rc;

    rc = xc_tmem_control(ctx->xch, -1, TMEMC_QUERY_FREEABLE_MB, -1, 0, 0, 0, 0);
    if (rc < 0) {
        XL_LOG_ERRNOVAL(ctx, XL_LOG_ERROR, rc,
            "Can not get tmem freeable memory");
        return ERROR_FAIL;
    }

    return rc;
}

int libxl_file_reference_map(libxl_ctx *ctx, libxl_file_reference *f)
{
	struct stat st_buf;
	int ret, fd;
	void *data;

	if (f->mapped)
		return 0;

	fd = open(f->path, O_RDONLY);
	if (f < 0)
		return ERROR_FAIL;

	ret = fstat(fd, &st_buf);
	if (ret < 0)
		goto out;

	ret = -1;
	data = mmap(NULL, st_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == NULL)
		goto out;

	f->mapped = 1;
	f->data = data;
	f->size = st_buf.st_size;

	ret = 0;
out:
	close(fd);

	return ret == 0 ? 0 : ERROR_FAIL;
}

int libxl_file_reference_unmap(libxl_ctx *ctx, libxl_file_reference *f)
{
	int ret;

	if (!f->mapped)
		return 0;

	ret = munmap(f->data, f->size);

	return ret == 0 ? 0 : ERROR_FAIL;
}
