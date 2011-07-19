/*
 * Copyright (C) 2010      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 * Author Gianni Tedesco <gianni.tedesco@citrix.com>
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
#include <unistd.h>
#include <fcntl.h>
#include <xenctrl.h>
#include <xc_dom.h>
#include <xenguest.h>
#include <assert.h>
#include "libxl.h"
#include "libxl_utils.h"
#include "libxl_internal.h"
#include "flexarray.h"

void libxl_domain_config_destroy(libxl_domain_config *d_config)
{
    int i;

    for (i=0; i<d_config->num_disks; i++)
        libxl_device_disk_destroy(&d_config->disks[i]);
    free(d_config->disks);

    for (i=0; i<d_config->num_vifs; i++)
        libxl_device_nic_destroy(&d_config->vifs[i]);
    free(d_config->vifs);

    for (i=0; i<d_config->num_pcidevs; i++)
        libxl_device_pci_destroy(&d_config->pcidevs[i]);
    free(d_config->pcidevs);

    for (i=0; i<d_config->num_vfbs; i++)
        libxl_device_vfb_destroy(&d_config->vfbs[i]);
    free(d_config->vfbs);

    for (i=0; i<d_config->num_vkbs; i++)
        libxl_device_vkb_destroy(&d_config->vkbs[i]);
    free(d_config->vkbs);

    libxl_domain_create_info_destroy(&d_config->c_info);
    libxl_domain_build_info_destroy(&d_config->b_info);
    libxl_device_model_info_destroy(&d_config->dm_info);
}

int libxl_init_create_info(libxl_ctx *ctx, libxl_domain_create_info *c_info)
{
    memset(c_info, '\0', sizeof(*c_info));
    c_info->xsdata = NULL;
    c_info->platformdata = NULL;
    c_info->hap = 1;
    c_info->type = LIBXL_DOMAIN_TYPE_HVM;
    c_info->oos = 1;
    c_info->ssidref = 0;
    c_info->poolid = 0;
    return 0;
}

int libxl_init_build_info(libxl_ctx *ctx,
                          libxl_domain_build_info *b_info,
                          libxl_domain_create_info *c_info)
{
    memset(b_info, '\0', sizeof(*b_info));
    b_info->max_vcpus = 1;
    b_info->cur_vcpus = 1;
    b_info->max_memkb = 32 * 1024;
    b_info->target_memkb = b_info->max_memkb;
    b_info->disable_migrate = 0;
    b_info->cpuid = NULL;
    b_info->shadow_memkb = 0;
    b_info->type = c_info->type;
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        b_info->video_memkb = 8 * 1024;
        b_info->u.hvm.firmware = NULL;
        b_info->u.hvm.pae = 1;
        b_info->u.hvm.apic = 1;
        b_info->u.hvm.acpi = 1;
        b_info->u.hvm.nx = 1;
        b_info->u.hvm.viridian = 0;
        b_info->u.hvm.hpet = 1;
        b_info->u.hvm.vpt_align = 1;
        b_info->u.hvm.timer_mode = 1;
        b_info->u.hvm.nested_hvm = 0;
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        b_info->u.pv.slack_memkb = 8 * 1024;
        break;
    default:
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "invalid domain type %s in create info",
                   libxl_domain_type_to_string(b_info->type));
        return ERROR_INVAL;
    }
    return 0;
}

int libxl_init_dm_info(libxl_ctx *ctx,
                       libxl_device_model_info *dm_info,
                       libxl_domain_create_info *c_info,
                       libxl_domain_build_info *b_info)
{
    memset(dm_info, '\0', sizeof(*dm_info));

    libxl_uuid_generate(&dm_info->uuid);

    dm_info->dom_name = strdup(c_info->name);
    dm_info->device_model_version = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
    dm_info->device_model_stubdomain = false;
    dm_info->device_model = NULL;
    dm_info->target_ram = libxl__sizekb_to_mb(b_info->target_memkb);
    dm_info->videoram = libxl__sizekb_to_mb(b_info->video_memkb);
    dm_info->acpi = b_info->u.hvm.acpi;
    dm_info->vcpus = b_info->max_vcpus;
    dm_info->vcpu_avail = b_info->cur_vcpus;

    dm_info->stdvga = 0;
    dm_info->vnc = 1;
    dm_info->vnclisten = strdup("127.0.0.1");
    dm_info->vncdisplay = 0;
    dm_info->vncunused = 1;
    dm_info->keymap = NULL;
    dm_info->sdl = 0;
    dm_info->opengl = 0;
    dm_info->nographic = 0;
    dm_info->serial = NULL;
    dm_info->boot = strdup("cda");
    dm_info->usb = 0;
    dm_info->usbdevice = NULL;
    dm_info->xen_platform_pci = 1;
    return 0;
}

static int init_console_info(libxl_device_console *console, int dev_num)
{
    memset(console, 0x00, sizeof(libxl_device_console));
    console->devid = dev_num;
    console->consback = LIBXL_CONSOLE_BACKEND_XENCONSOLED;
    console->output = strdup("pty");
    if ( NULL == console->output )
        return ERROR_NOMEM;
    return 0;
}

int libxl__domain_build(libxl__gc *gc,
                        libxl_domain_build_info *info,
                        libxl_device_model_info *dm_info,
                        uint32_t domid,
                        libxl__domain_build_state *state)
{
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, ret;

    ret = libxl__build_pre(gc, domid, info, state);
    if (ret)
        goto out;

    gettimeofday(&start_time, NULL);

    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        ret = libxl__build_hvm(gc, domid, info, dm_info, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        ret = libxl__build_pv(gc, domid, info, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char*) info->u.pv.kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (info->u.pv.ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char*) info->u.pv.ramdisk.path;
        }
        if (info->u.pv.cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char*) info->u.pv.cmdline;
        }
        break;
    default:
        ret = ERROR_INVAL;
        goto out;
    }
    ret = libxl__build_post(gc, domid, info, state, vments, localents);
out:
    return ret;
}

static int domain_restore(libxl__gc *gc, libxl_domain_build_info *info,
                          uint32_t domid, int fd,
                          libxl__domain_build_state *state,
                          libxl_device_model_info *dm_info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, ret, esave, flags;

    ret = libxl__build_pre(gc, domid, info, state);
    if (ret)
        goto out;

    ret = libxl__domain_restore_common(gc, domid, info, state, fd);
    if (ret)
        goto out;

    gettimeofday(&start_time, NULL);

    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        vments = libxl__calloc(gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        vments = libxl__calloc(gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char*) info->u.pv.kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (info->u.pv.ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char*) info->u.pv.ramdisk.path;
        }
        if (info->u.pv.cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char*) info->u.pv.cmdline;
        }
        break;
    default:
        ret = ERROR_INVAL;
        goto out;
    }
    ret = libxl__build_post(gc, domid, info, state, vments, localents);
    if (ret)
        goto out;

    dm_info->saved_state = NULL;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        ret = asprintf(&dm_info->saved_state,
                       XC_DEVICE_MODEL_RESTORE_FILE".%d", domid);
        ret = (ret < 0) ? ERROR_FAIL : 0;
    }

out:
    if (info->type == LIBXL_DOMAIN_TYPE_PV) {
        libxl__file_reference_unmap(&info->u.pv.kernel);
        libxl__file_reference_unmap(&info->u.pv.ramdisk);
    }

    esave = errno;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to get flags on restore fd");
    } else {
        flags &= ~O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1)
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to put restore fd"
                         " back to blocking mode");
    }

    errno = esave;
    return ret;
}

int libxl__domain_make(libxl__gc *gc, libxl_domain_create_info *info,
                       uint32_t *domid)
 /* on entry, libxl_domid_valid_guest(domid) must be false;
  * on exit (even error exit), domid may be valid and refer to a domain */
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int flags, ret, i, rc;
    char *uuid_string;
    char *rw_paths[] = { "control/shutdown", "device", "device/suspend/event-channel" , "data"};
    char *ro_paths[] = { "cpu", "memory", "device", "error", "drivers",
                         "control", "attr", "messages" };
    char *dom_path, *vm_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    xs_transaction_t t = 0;
    xen_domain_handle_t handle;

    assert(!libxl_domid_valid_guest(*domid));

    uuid_string = libxl__uuid2string(gc, info->uuid);
    if (!uuid_string) {
        rc = ERROR_NOMEM;
        goto out;
    }

    flags = 0;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        flags |= XEN_DOMCTL_CDF_hvm_guest;
        flags |= info->hap ? XEN_DOMCTL_CDF_hap : 0;
        flags |= info->oos ? 0 : XEN_DOMCTL_CDF_oos_off;
    }
    *domid = -1;

    /* Ultimately, handle is an array of 16 uint8_t, same as uuid */
    libxl_uuid_copy((libxl_uuid *)handle, &info->uuid);

    ret = xc_domain_create(ctx->xch, info->ssidref, handle, flags, domid);
    if (ret < 0) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "domain creation fail");
        rc = ERROR_FAIL;
        goto out;
    }

    ret = xc_cpupool_movedomain(ctx->xch, info->poolid, *domid);
    if (ret < 0) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "domain move fail");
        rc = ERROR_FAIL;
        goto out;
    }

    dom_path = libxl__xs_get_dompath(gc, *domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    vm_path = libxl__sprintf(gc, "/vm/%s", uuid_string);
    if (!vm_path) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot allocate create paths");
        rc = ERROR_FAIL;
        goto out;
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

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl__domain_rename(gc, *domid, 0, info->name, t);
    if (rc)
        goto out;

    for (i = 0; i < ARRAY_SIZE(rw_paths); i++) {
        char *path = libxl__sprintf(gc, "%s/%s", dom_path, rw_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, rwperm, ARRAY_SIZE(rwperm));
    }
    for (i = 0; i < ARRAY_SIZE(ro_paths); i++) {
        char *path = libxl__sprintf(gc, "%s/%s", dom_path, ro_paths[i]);
        xs_mkdir(ctx->xsh, t, path);
        xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    }

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/uuid", vm_path), uuid_string, strlen(uuid_string));
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/name", vm_path), info->name, strlen(info->name));
    if (info->poolname)
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/pool_name", vm_path), info->poolname, strlen(info->poolname));

    libxl__xs_writev(gc, t, dom_path, info->xsdata);
    libxl__xs_writev(gc, t, libxl__sprintf(gc, "%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN) {
            t = 0;
            goto retry_transaction;
        }
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "domain creation "
                         "xenstore transaction commit failed");
        rc = ERROR_FAIL;
        goto out;
    }
    t = 0;

    rc = 0;
 out:
    if (t) xs_transaction_end(ctx->xsh, t, 1);
    return rc;
}

static int do_domain_create(libxl__gc *gc, libxl_domain_config *d_config,
                            libxl_console_ready cb, void *priv,
                            uint32_t *domid_out, int restore_fd)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl__device_model_starting *dm_starting = 0;
    libxl_device_model_info *dm_info = &d_config->dm_info;
    libxl__domain_build_state state;
    uint32_t domid;
    int i, ret;

    domid = 0;

    ret = libxl__domain_make(gc, &d_config->c_info, &domid);
    if (ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot make domain: %d", ret);
        ret = ERROR_FAIL;
        goto error_out;
    }

    if ( d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV && cb ) {
        if ( (*cb)(ctx, domid, priv) )
            goto error_out;
    }


    for (i = 0; i < d_config->num_disks; i++) {
        ret = libxl__device_disk_set_backend(gc, &d_config->disks[i]);
        if (ret) goto error_out;
    }

    if ( restore_fd < 0 ) {
        ret = libxl_run_bootloader(ctx, &d_config->b_info, d_config->num_disks > 0 ? &d_config->disks[0] : NULL, domid);
        if (ret) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "failed to run bootloader: %d", ret);
            goto error_out;
        }
    }

    if ( restore_fd >= 0 ) {
        ret = domain_restore(gc, &d_config->b_info, domid, restore_fd, &state, dm_info);
    } else {
        if (dm_info->saved_state) {
            free(dm_info->saved_state);
            dm_info->saved_state = NULL;
        }
        ret = libxl__domain_build(gc, &d_config->b_info, dm_info, domid, &state);
    }

    if (ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot (re-)build domain: %d", ret);
        ret = ERROR_FAIL;
        goto error_out;
    }

    for (i = 0; i < d_config->num_disks; i++) {
        ret = libxl_device_disk_add(ctx, domid, &d_config->disks[i]);
        if (ret) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "cannot add disk %d to domain: %d", i, ret);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }
    for (i = 0; i < d_config->num_vifs; i++) {
        ret = libxl_device_nic_add(ctx, domid, &d_config->vifs[i]);
        if (ret) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "cannot add nic %d to domain: %d", i, ret);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }
    switch (d_config->c_info.type) {
    case LIBXL_DOMAIN_TYPE_HVM:
    {
        libxl_device_console console;

        ret = init_console_info(&console, 0);
        if ( ret )
            goto error_out;
        libxl__device_console_add(gc, domid, &console, &state);
        libxl_device_console_destroy(&console);

        dm_info->domid = domid;
        ret = libxl__create_device_model(gc, dm_info,
                                        d_config->disks, d_config->num_disks,
                                        d_config->vifs, d_config->num_vifs,
                                        &dm_starting);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "failed to create device model: %d", ret);
            goto error_out;
        }
        break;
    }
    case LIBXL_DOMAIN_TYPE_PV:
    {
        int need_qemu = 0;
        libxl_device_console console;
        libxl_device_model_info xenpv_dm_info;

        for (i = 0; i < d_config->num_vfbs; i++) {
            libxl_device_vfb_add(ctx, domid, &d_config->vfbs[i]);
            libxl_device_vkb_add(ctx, domid, &d_config->vkbs[i]);
        }

        ret = init_console_info(&console, 0);
        if ( ret )
            goto error_out;

        need_qemu = libxl__need_xenpv_qemu(gc, 1, &console,
                d_config->num_vfbs, d_config->vfbs,
                d_config->num_disks, &d_config->disks[0]);

        if (need_qemu)
             console.consback = LIBXL_CONSOLE_BACKEND_IOEMU;

        libxl__device_console_add(gc, domid, &console, &state);
        libxl_device_console_destroy(&console);

        if (need_qemu) {
            /* only copy those useful configs */
            memset((void*)&xenpv_dm_info, 0, sizeof(libxl_device_model_info));
            xenpv_dm_info.device_model_version =
                d_config->dm_info.device_model_version;
            xenpv_dm_info.type = d_config->dm_info.type;
            xenpv_dm_info.device_model = d_config->dm_info.device_model;
            xenpv_dm_info.extra = d_config->dm_info.extra;
            xenpv_dm_info.extra_pv = d_config->dm_info.extra_pv;
            xenpv_dm_info.extra_hvm = d_config->dm_info.extra_hvm;

            libxl__create_xenpv_qemu(gc, domid, &xenpv_dm_info,
                                     d_config->vfbs, &dm_starting);
        }
        break;
    }
    default:
        ret = ERROR_INVAL;
        goto error_out;
    }

    if (dm_starting) {
        ret = libxl__confirm_device_model_startup(gc, dm_starting);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "device model did not start: %d", ret);
            goto error_out;
        }
    }

    for (i = 0; i < d_config->num_pcidevs; i++)
        libxl__device_pci_add(gc, domid, &d_config->pcidevs[i], 1);

    ret = libxl__create_pci_backend(gc, domid, d_config->pcidevs,
                                    d_config->num_pcidevs);
    if (ret < 0) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "libxl_create_pci_backend failed: %d", ret);
        goto error_out;
    }

    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV &&
        d_config->b_info.u.pv.e820_host) {
        int rc;
        rc = libxl__e820_alloc(ctx, domid, d_config);
        if (rc)
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                      "Failed while collecting E820 with: %d (errno:%d)\n",
                      rc, errno);
    }
    if ( cb && (d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM ||
                (d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV &&
                 d_config->b_info.u.pv.bootloader ))) {
        if ( (*cb)(ctx, domid, priv) )
            goto error_out;
    }

    *domid_out = domid;
    return 0;

error_out:
    if (domid)
        libxl_domain_destroy(ctx, domid, 0);

    return ret;
}

int libxl_domain_create_new(libxl_ctx *ctx, libxl_domain_config *d_config,
                            libxl_console_ready cb, void *priv, uint32_t *domid)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int rc;
    rc = do_domain_create(&gc, d_config, cb, priv, domid, -1);
    libxl__free_all(&gc);
    return rc;
}

int libxl_domain_create_restore(libxl_ctx *ctx, libxl_domain_config *d_config,
                                libxl_console_ready cb, void *priv, uint32_t *domid, int restore_fd)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int rc;
    rc = do_domain_create(&gc, d_config, cb, priv, domid, restore_fd);
    libxl__free_all(&gc);
    return rc;
}
