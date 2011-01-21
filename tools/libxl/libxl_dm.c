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
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "libxl_utils.h"
#include "libxl_internal.h"
#include "libxl.h"
#include "flexarray.h"

static const char *libxl_tapif_script(libxl__gc *gc)
{
#ifdef __linux__
    return libxl__strdup(gc, "no");
#else
    return libxl__sprintf(gc, "%s/qemu-ifup", libxl_xen_script_dir_path());
#endif
}

static char ** libxl_build_device_model_args_old(libxl__gc *gc,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    int i;
    flexarray_t *dm_args;
    dm_args = flexarray_make(16, 1);

    if (!dm_args)
        return NULL;

    flexarray_vappend(dm_args, "qemu-dm", "-d", libxl__sprintf(gc, "%d", info->domid), NULL);

    if (info->dom_name)
        flexarray_vappend(dm_args, "-domain-name", info->dom_name, NULL);

    if (info->vnc || info->vncdisplay || info->vnclisten || info->vncunused) {
        flexarray_append(dm_args, "-vnc");
        if (info->vncdisplay) {
            if (info->vnclisten && strchr(info->vnclisten, ':') == NULL) {
                flexarray_append(dm_args, 
                    libxl__sprintf(gc, "%s:%d%s",
                                  info->vnclisten,
                                  info->vncdisplay,
                                  info->vncpasswd ? ",password" : ""));
            } else {
                flexarray_append(dm_args, libxl__sprintf(gc, "127.0.0.1:%d", info->vncdisplay));
            }
        } else if (info->vnclisten) {
            if (strchr(info->vnclisten, ':') != NULL) {
                flexarray_append(dm_args, info->vnclisten);
            } else {
                flexarray_append(dm_args, libxl__sprintf(gc, "%s:0", info->vnclisten));
            }
        } else {
            flexarray_append(dm_args, "127.0.0.1:0");
        }
        if (info->vncunused) {
            flexarray_append(dm_args, "-vncunused");
        }
    }
    if (info->sdl) {
        flexarray_append(dm_args, "-sdl");
        if (!info->opengl) {
            flexarray_append(dm_args, "-disable-opengl");
        }
    }
    if (info->keymap) {
        flexarray_vappend(dm_args, "-k", info->keymap, NULL);
    }
    if (info->nographic && (!info->sdl && !info->vnc)) {
        flexarray_append(dm_args, "-nographic");
    }
    if (info->serial) {
        flexarray_vappend(dm_args, "-serial", info->serial, NULL);
    }
    if (info->type == XENFV) {
        int ioemu_vifs = 0;

        if (info->videoram) {
            flexarray_vappend(dm_args, "-videoram", libxl__sprintf(gc, "%d", info->videoram), NULL);
        }
        if (info->stdvga) {
            flexarray_append(dm_args, "-std-vga");
        }

        if (info->boot) {
            flexarray_vappend(dm_args, "-boot", info->boot, NULL);
        }
        if (info->usb || info->usbdevice) {
            flexarray_append(dm_args, "-usb");
            if (info->usbdevice) {
                flexarray_vappend(dm_args, "-usbdevice", info->usbdevice, NULL);
            }
        }
        if (info->soundhw) {
            flexarray_vappend(dm_args, "-soundhw", info->soundhw, NULL);
        }
        if (info->apic) {
            flexarray_append(dm_args, "-acpi");
        }
        if (info->vcpus > 1) {
            flexarray_vappend(dm_args, "-vcpus", libxl__sprintf(gc, "%d", info->vcpus), NULL);
        }
        if (info->vcpu_avail) {
            flexarray_vappend(dm_args, "-vcpu_avail", libxl__sprintf(gc, "0x%x", info->vcpu_avail), NULL);
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == NICTYPE_IOEMU) {
                char *smac = libxl__sprintf(gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2],
                                           vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
                char *ifname;
                if (!vifs[i].ifname)
                    ifname = libxl__sprintf(gc, "tap%d.%d", info->domid, vifs[i].devid);
                else
                    ifname = vifs[i].ifname;
                flexarray_vappend(dm_args,
                                "-net", libxl__sprintf(gc, "nic,vlan=%d,macaddr=%s,model=%s",
                                                       vifs[i].devid, smac, vifs[i].model),
                                "-net", libxl__sprintf(gc, "tap,vlan=%d,ifname=%s,bridge=%s,script=%s",
                                                       vifs[i].devid, ifname, vifs[i].bridge, libxl_tapif_script(gc)),
                                NULL);
                ioemu_vifs++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_vifs == 0 ) {
            flexarray_vappend(dm_args, "-net", "none", NULL);
        }
    }
    if (info->saved_state) {
        flexarray_vappend(dm_args, "-loadvm", info->saved_state, NULL);
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_append(dm_args, info->extra[i]);
    flexarray_append(dm_args, "-M");
    if (info->type == XENPV)
        flexarray_append(dm_args, "xenpv");
    else
        flexarray_append(dm_args, "xenfv");
    flexarray_append(dm_args, NULL);
    return (char **) flexarray_contents(dm_args);
}

static char ** libxl_build_device_model_args_new(libxl__gc *gc,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    flexarray_t *dm_args;
    libxl_device_disk *disks;
    int nb, i;

    dm_args = flexarray_make(16, 1);
    if (!dm_args)
        return NULL;

    flexarray_vappend(dm_args, libxl__strdup(gc, info->device_model),
                        "-xen-domid", libxl__sprintf(gc, "%d", info->domid), NULL);

    if (info->type == XENPV) {
        flexarray_append(dm_args, "-xen-attach");
    }

    if (info->dom_name) {
        flexarray_vappend(dm_args, "-name", info->dom_name, NULL);
    }
    if (info->vnc || info->vncdisplay || info->vnclisten || info->vncunused) {
        int display = 0;
        const char *listen = "127.0.0.1";

        flexarray_append(dm_args, "-vnc");

        if (info->vncdisplay) {
            display = info->vncdisplay;
            if (info->vnclisten && strchr(info->vnclisten, ':') == NULL) {
                listen = info->vnclisten;
            }
        } else if (info->vnclisten) {
            listen = info->vnclisten;
        }

        if (strchr(listen, ':') != NULL)
            flexarray_append(dm_args, 
                    libxl__sprintf(gc, "%s%s", listen,
                        info->vncunused ? ",to=99" : ""));
        else
            flexarray_append(dm_args, 
                    libxl__sprintf(gc, "%s:%d%s", listen, display,
                        info->vncunused ? ",to=99" : ""));
    }
    if (info->sdl) {
        flexarray_append(dm_args, "-sdl");
    }

    if (info->type == XENPV && !info->nographic) {
        flexarray_vappend(dm_args, "-vga", "xenfb", NULL);
    }

    if (info->keymap) {
        flexarray_vappend(dm_args, "-k", info->keymap, NULL);
    }
    if (info->nographic && (!info->sdl && !info->vnc)) {
        flexarray_append(dm_args, "-nographic");
    }
    if (info->serial) {
        flexarray_vappend(dm_args, "-serial", info->serial, NULL);
    }
    if (info->type == XENFV) {
        int ioemu_vifs = 0;

        if (info->stdvga) {
                flexarray_vappend(dm_args, "-vga", "std", NULL);
        }

        if (info->boot) {
            flexarray_vappend(dm_args, "-boot", libxl__sprintf(gc, "order=%s", info->boot), NULL);
        }
        if (info->usb || info->usbdevice) {
            flexarray_append(dm_args, "-usb");
            if (info->usbdevice) {
                flexarray_vappend(dm_args, "-usbdevice", info->usbdevice, NULL);
            }
        }
        if (info->soundhw) {
            flexarray_vappend(dm_args, "-soundhw", info->soundhw, NULL);
        }
        if (!info->apic) {
            flexarray_append(dm_args, "-no-acpi");
        }
        if (info->vcpus > 1) {
            flexarray_append(dm_args, "-smp");
            if (info->vcpu_avail)
                flexarray_append(dm_args, libxl__sprintf(gc, "%d,maxcpus=%d", info->vcpus, info->vcpu_avail));
            else
                flexarray_append(dm_args, libxl__sprintf(gc, "%d", info->vcpus));
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == NICTYPE_IOEMU) {
                char *smac = libxl__sprintf(gc, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           vifs[i].mac[0], vifs[i].mac[1], vifs[i].mac[2],
                                           vifs[i].mac[3], vifs[i].mac[4], vifs[i].mac[5]);
                char *ifname;
                if (!vifs[i].ifname) {
                    ifname = libxl__sprintf(gc, "tap%d.%d", info->domid, vifs[i].devid);
                } else {
                    ifname = vifs[i].ifname;
                }
                flexarray_append(dm_args, "-net");
                flexarray_append(dm_args, libxl__sprintf(gc, "nic,vlan=%d,macaddr=%s,model=%s",
                            vifs[i].devid, smac, vifs[i].model));
                flexarray_append(dm_args, "-net");
                flexarray_append(dm_args, libxl__sprintf(gc, "tap,vlan=%d,ifname=%s,script=%s",
                            vifs[i].devid, ifname, libxl_tapif_script(gc)));
                ioemu_vifs++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_vifs == 0 ) {
            flexarray_append(dm_args, "-net");
            flexarray_append(dm_args, "none");
        }
    }
    if (info->saved_state) {
        flexarray_append(dm_args, "-loadvm");
        flexarray_append(dm_args, info->saved_state);
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_append(dm_args, info->extra[i]);
    flexarray_append(dm_args, "-M");
    if (info->type == XENPV)
        flexarray_append(dm_args, "xenpv");
    else
        flexarray_append(dm_args, "xenfv");

    /* RAM Size */
    flexarray_append(dm_args, "-m");
    flexarray_append(dm_args, libxl__sprintf(gc, "%d", info->target_ram));

    if (info->type == XENFV) {
        disks = libxl_device_disk_list(libxl__gc_owner(gc), info->domid, &nb);
        for (i; i < nb; i++) {
            if (disks[i].is_cdrom) {
                flexarray_append(dm_args, "-cdrom");
                flexarray_append(dm_args, libxl__strdup(gc, disks[i].physpath));
            } else {
                flexarray_append(dm_args, libxl__sprintf(gc, "-%s", disks[i].virtpath));
                flexarray_append(dm_args, libxl__strdup(gc, disks[i].physpath));
            }
            libxl_device_disk_destroy(&disks[i]);
        }
        free(disks);
    }
    flexarray_append(dm_args, NULL);
    return (char **) flexarray_contents(dm_args);
}

static char ** libxl_build_device_model_args(libxl__gc *gc,
                                             libxl_device_model_info *info,
                                             libxl_device_nic *vifs,
                                             int num_vifs)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int new_qemu;

    new_qemu = libxl_check_device_model_version(ctx, info->device_model);

    if (new_qemu == 1) {
        return libxl_build_device_model_args_new(gc, info, vifs, num_vifs);
    } else {
        return libxl_build_device_model_args_old(gc, info, vifs, num_vifs);
    }
}

static void dm_xenstore_record_pid(void *for_spawn, pid_t innerchild)
{
    libxl__device_model_starting *starting = for_spawn;
    struct xs_handle *xsh;
    char *path = NULL, *pid = NULL;
    int len;

    if (asprintf(&path, "%s/%s", starting->dom_path, "image/device-model-pid") < 0)
        goto out;

    len = asprintf(&pid, "%d", innerchild);
    if (len < 0)
        goto out;

    /* we mustn't use the parent's handle in the child */
    xsh = xs_daemon_open();

    xs_write(xsh, XBT_NULL, path, pid, len);

    xs_daemon_close(xsh);
out:
    free(path);
    free(pid);
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
    libxl__gc gc = LIBXL_INIT_GC(ctx);
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

    vm_path = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "/local/domain/%d/vm", guest_domid));

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
    path = libxl__sprintf(&gc, "%s/image/dmargs", vm_path);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, path, dmargs, strlen(dmargs));
    xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    xs_set_permissions(ctx->xsh, t, libxl__sprintf(&gc, "%s/rtc/timeoffset", vm_path), roperm, ARRAY_SIZE(roperm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    free(dmargs);
    libxl__free_all(&gc);
    return 0;
}

static int libxl_create_stubdom(libxl_ctx *ctx,
                                libxl_device_model_info *info,
                                libxl_device_disk *disks, int num_disks,
                                libxl_device_nic *vifs, int num_vifs,
                                libxl_device_vfb *vfb,
                                libxl_device_vkb *vkb,
                                libxl__device_model_starting **starting_r)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int i, num_console = STUBDOM_SPECIAL_CONSOLES, ret;
    libxl_device_console *console;
    libxl_domain_create_info c_info;
    libxl_domain_build_info b_info;
    libxl_domain_build_state state;
    uint32_t domid;
    char **args;
    struct xs_permissions perm[2];
    xs_transaction_t t;
    libxl__device_model_starting *dm_starting = 0;

    args = libxl_build_device_model_args(&gc, info, vifs, num_vifs);
    if (!args) {
        ret = ERROR_FAIL;
        goto out;
    }

    memset(&c_info, 0x00, sizeof(libxl_domain_create_info));
    c_info.hvm = 0;
    c_info.name = libxl__sprintf(&gc, "%s-dm", libxl__domid_to_name(&gc, info->domid));

    libxl_uuid_copy(&c_info.uuid, &info->uuid);

    memset(&b_info, 0x00, sizeof(libxl_domain_build_info));
    b_info.max_vcpus = 1;
    b_info.max_memkb = 32 * 1024;
    b_info.target_memkb = b_info.max_memkb;
    b_info.kernel.path = libxl__abs_path(&gc, "ioemu-stubdom.gz", libxl_xenfirmwaredir_path());
    b_info.u.pv.cmdline = libxl__sprintf(&gc, " -d %d", info->domid);
    b_info.u.pv.ramdisk.path = "";
    b_info.u.pv.features = "";
    b_info.hvm = 0;

    ret = libxl__domain_make(ctx, &c_info, &domid);
    if (ret)
        goto out_free;
    ret = libxl__domain_build(ctx, &b_info, domid, &state);
    if (ret)
        goto out_free;

    libxl_write_dmargs(ctx, domid, info->domid, args);
    libxl__xs_write(&gc, XBT_NULL,
                   libxl__sprintf(&gc, "%s/image/device-model-domid", libxl__xs_get_dompath(&gc, info->domid)),
                   "%d", domid);
    libxl__xs_write(&gc, XBT_NULL,
                   libxl__sprintf(&gc, "%s/target", libxl__xs_get_dompath(&gc, domid)),
                   "%d", info->domid);
    ret = xc_domain_set_target(ctx->xch, domid, info->domid);
    if (ret<0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "setting target domain %d -> %d", domid, info->domid);
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
    xs_mkdir(ctx->xsh, t, libxl__sprintf(&gc, "/local/domain/0/device-model/%d", info->domid));
    xs_set_permissions(ctx->xsh, t, libxl__sprintf(&gc, "/local/domain/0/device-model/%d", info->domid), perm, ARRAY_SIZE(perm));
    xs_mkdir(ctx->xsh, t, libxl__sprintf(&gc, "/local/domain/%d/device/vfs", domid));
    xs_set_permissions(ctx->xsh, t, libxl__sprintf(&gc, "/local/domain/%d/device/vfs",domid), perm, ARRAY_SIZE(perm));
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

    console = libxl__calloc(&gc, num_console, sizeof(libxl_device_console));
    if (!console) {
        ret = ERROR_NOMEM;
        goto out_free;
    }

    for (i = 0; i < num_console; i++) {
        console[i].devid = i;
        console[i].consback = LIBXL_CONSBACK_IOEMU;
        console[i].domid = domid;
        /* STUBDOM_CONSOLE_LOGGING (console 0) is for minios logging
         * STUBDOM_CONSOLE_SAVE (console 1) is for writing the save file
         * STUBDOM_CONSOLE_RESTORE (console 2) is for reading the save file
         */
        switch (i) {
            char *filename;
            char *name;
            case STUBDOM_CONSOLE_LOGGING:
                name = libxl__sprintf(&gc, "qemu-dm-%s", libxl_domid_to_name(ctx, info->domid));
                libxl_create_logfile(ctx, name, &filename);
                console[i].output = libxl__sprintf(&gc, "file:%s", filename);
                console[i].build_state = &state;
                free(filename);
                break;
            case STUBDOM_CONSOLE_SAVE:
                console[i].output = libxl__sprintf(&gc, "file:"SAVEFILE".%d", info->domid);
                break;
            case STUBDOM_CONSOLE_RESTORE:
                if (info->saved_state)
                    console[i].output = libxl__sprintf(&gc, "pipe:%s", info->saved_state);
                break;
            default:
                console[i].output = "pty";
                break;
        }
        ret = libxl_device_console_add(ctx, domid, &console[i]);
        if (ret)
            goto out_free;
    }
    if (libxl__create_xenpv_qemu(ctx, domid, vfb, &dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }
    if (libxl__confirm_device_model_startup(ctx, dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }

    libxl_domain_unpause(ctx, domid);

    if (starting_r) {
        *starting_r = calloc(sizeof(libxl__device_model_starting), 1);
        (*starting_r)->domid = info->domid;
        (*starting_r)->dom_path = libxl__xs_get_dompath(&gc, info->domid);
        (*starting_r)->for_spawn = NULL;
    }

    ret = 0;

out_free:
    free(args);
out:
    libxl__free_all(&gc);
    return ret;
}

int libxl__create_device_model(libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_disk *disks, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl__device_model_starting **starting_r)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *path, *logfile;
    int logfile_w, null;
    int rc;
    char **args;
    libxl__device_model_starting buf_starting, *p;
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

    path = libxl__sprintf(&gc, "/local/domain/0/device-model/%d", info->domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);
    libxl__xs_write(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/disable_pf", path), "%d", !info->xen_platform_pci);

    libxl_create_logfile(ctx, libxl__sprintf(&gc, "qemu-dm-%s", info->dom_name), &logfile);
    logfile_w = open(logfile, O_WRONLY|O_CREAT, 0644);
    free(logfile);
    null = open("/dev/null", O_RDONLY);

    if (starting_r) {
        rc = ERROR_NOMEM;
        *starting_r = calloc(sizeof(libxl__device_model_starting), 1);
        if (!*starting_r)
            goto out_close;
        p = *starting_r;
        p->for_spawn = calloc(sizeof(libxl__spawn_starting), 1);
    } else {
        p = &buf_starting;
        p->for_spawn = NULL;
    }

    p->domid = info->domid;
    p->dom_path = libxl__xs_get_dompath(&gc, info->domid);
    if (!p->dom_path) {
        rc = ERROR_FAIL;
        goto out_close;
    }

    if (info->vncpasswd) {
retry_transaction:
        /* Find uuid and the write the vnc password to xenstore for qemu. */
        t = xs_transaction_start(ctx->xsh);
        vm_path = libxl__xs_read(&gc,t,libxl__sprintf(&gc, "%s/vm", p->dom_path));
        if (vm_path) {
            /* Now write the vncpassword into it. */
            pass_stuff = libxl__calloc(&gc, 3, sizeof(char *));
            pass_stuff[0] = "vncpasswd";
            pass_stuff[1] = info->vncpasswd;
            libxl__xs_writev(&gc,t,vm_path,pass_stuff);
            if (!xs_transaction_end(ctx->xsh, t, 0))
                if (errno == EAGAIN)
                    goto retry_transaction;
        }
    }

    rc = libxl__spawn_spawn(ctx, p, "device model", dm_xenstore_record_pid);
    if (rc < 0)
        goto out_close;
    if (!rc) { /* inner child */
        libxl__exec(null, logfile_w, logfile_w,
                   libxl__abs_path(&gc, info->device_model, libxl_libexec_path()),
                   args);
    }

    rc = 0;

out_close:
    close(null);
    close(logfile_w);
    free(args);
out:
    libxl__free_all(&gc);
    return rc;
}

static int detach_device_model(libxl_ctx *ctx,
                              libxl__device_model_starting *starting)
{
    int rc;
    rc = libxl__spawn_detach(ctx, starting->for_spawn);
    if (starting->for_spawn)
        free(starting->for_spawn);
    free(starting);
    return rc;
}


int libxl__confirm_device_model_startup(libxl_ctx *ctx,
                                       libxl__device_model_starting *starting)
{
    int problem = libxl__wait_for_device_model(ctx, starting->domid, "running", NULL, NULL);
    int detach;
    if ( !problem )
        problem = libxl__spawn_check(ctx, starting->for_spawn);
    detach = detach_device_model(ctx, starting);
    return problem ? problem : detach;
}

int libxl__destroy_device_model(libxl_ctx *ctx, uint32_t domid)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *pid;
    int ret;

    pid = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "/local/domain/%d/image/device-model-pid", domid));
    if (!pid) {
        int stubdomid = libxl_get_stubdom_id(ctx, domid);
        if (!stubdomid) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't find device model's pid");
            ret = ERROR_INVAL;
            goto out;
        }
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Device model is a stubdom, domid=%d\n", stubdomid);
        ret = libxl_domain_destroy(ctx, stubdomid, 0);
        if (ret)
            goto out;
    } else {
        ret = kill(atoi(pid), SIGHUP);
        if (ret < 0 && errno == ESRCH) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Device Model already exited");
            ret = 0;
        } else if (ret == 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Device Model signaled");
            ret = 0;
        } else {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to kill Device Model [%d]",
                    atoi(pid));
            ret = ERROR_FAIL;
            goto out;
        }
    }
    xs_rm(ctx->xsh, XBT_NULL, libxl__sprintf(&gc, "/local/domain/0/device-model/%d", domid));

out:
    libxl__free_all(&gc);
    return ret;
}

static int libxl_build_xenpv_qemu_args(libxl__gc *gc,
                                       uint32_t domid,
                                       libxl_device_vfb *vfb,
                                       libxl_device_model_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    memset(info, 0x00, sizeof(libxl_device_model_info));

    if (vfb != NULL) {
        info->vnc = vfb->vnc;
        if (vfb->vnclisten)
            info->vnclisten = libxl__strdup(gc, vfb->vnclisten);
        info->vncdisplay = vfb->vncdisplay;
        info->vncunused = vfb->vncunused;
        if (vfb->vncpasswd)
            info->vncpasswd = vfb->vncpasswd;
        if (vfb->keymap)
            info->keymap = libxl__strdup(gc, vfb->keymap);
        info->sdl = vfb->sdl;
        info->opengl = vfb->opengl;
    } else
        info->nographic = 1;
    info->domid = domid;
    info->dom_name = libxl_domid_to_name(ctx, domid);
    info->device_model = libxl__abs_path(gc, "qemu-dm", libxl_libexec_path());
    info->type = XENPV;
    return 0;
}

int libxl__need_xenpv_qemu(libxl_ctx *ctx,
        int nr_consoles, libxl_device_console *consoles,
        int nr_vfbs, libxl_device_vfb *vfbs,
        int nr_disks, libxl_device_disk *disks)
{
    int i, ret = 0;
    libxl__gc gc = LIBXL_INIT_GC(ctx);

    if (nr_consoles > 1) {
        ret = 1;
        goto out;
    }

    for (i = 0; i < nr_consoles; i++) {
        if (consoles[i].consback == LIBXL_CONSBACK_IOEMU) {
            ret = 1;
            goto out;
        }
    }

    if (nr_vfbs > 0) {
        ret = 1;
        goto out;
    }

    if (nr_disks > 0 && !libxl__blktap_enabled(&gc))
        ret = 1;

out:
    libxl__free_all(&gc);
    return ret;
}

int libxl__create_xenpv_qemu(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb,
                            libxl__device_model_starting **starting_r)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    libxl_device_model_info info;

    libxl_build_xenpv_qemu_args(&gc, domid, vfb, &info);
    libxl__create_device_model(ctx, &info, NULL, 0, NULL, 0, starting_r);
    libxl__free_all(&gc);
    return 0;
}
