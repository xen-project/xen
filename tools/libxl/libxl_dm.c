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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

static const char *libxl_tapif_script(libxl__gc *gc)
{
#ifdef __linux__
    return libxl__strdup(gc, "no");
#else
    return libxl__sprintf(gc, "%s/qemu-ifup", libxl_xen_script_dir_path());
#endif
}

const char *libxl__device_model_savefile(libxl__gc *gc, uint32_t domid)
{
    return libxl__sprintf(gc, "/var/lib/xen/qemu-save.%d", domid);
}

const char *libxl__domain_device_model(libxl__gc *gc,
                                       libxl_device_model_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *dm;

    if (info->device_model_stubdomain)
        return NULL;

    if (info->device_model) {
        dm = libxl__strdup(gc, info->device_model);
    } else {
        switch (info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            dm = libxl__abs_path(gc, "qemu-dm", libxl_libexec_path());
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            dm = libxl__abs_path(gc, "qemu-system-i386", libxl_libexec_path());
            break;
        default:
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "invalid device model version %d\n",
                       info->device_model_version);
            dm = NULL;
            break;
        }
    }
    return dm;
}

static const char *libxl__domain_bios(libxl__gc *gc,
                                libxl_device_model_info *info)
{
    switch (info->device_model_version) {
    case 1: return "rombios";
    case 2: return "seabios";
    default:return NULL;
    }
}

static const libxl_vnc_info *dm_vnc(const libxl_domain_config *guest_config,
                                    const libxl_device_model_info *info)
{
    const libxl_vnc_info *vnc = NULL;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        vnc = &info->vnc;
    } else if (guest_config->num_vfbs > 0) {
        vnc = &guest_config->vfbs[0].vnc;
    }
    return vnc && vnc->enable ? vnc : NULL;
}

static const libxl_sdl_info *dm_sdl(const libxl_domain_config *guest_config,
                                    const libxl_device_model_info *info)
{
    const libxl_sdl_info *sdl = NULL;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        sdl = &info->sdl;
    } else if (guest_config->num_vfbs > 0) {
        sdl = &guest_config->vfbs[0].sdl;
    }
    return sdl && sdl->enable ? sdl : NULL;
}

static char ** libxl__build_device_model_args_old(libxl__gc *gc,
                                        const char *dm,
                                        const libxl_domain_config *guest_config,
                                        const libxl_device_model_info *info)
{
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_device_nic *vifs = guest_config->vifs;
    const libxl_vnc_info *vnc = dm_vnc(guest_config, info);
    const libxl_sdl_info *sdl = dm_sdl(guest_config, info);
    const int num_vifs = guest_config->num_vifs;
    int i;
    flexarray_t *dm_args;
    dm_args = flexarray_make(16, 1);

    if (!dm_args)
        return NULL;

    flexarray_vappend(dm_args, dm,
                      "-d", libxl__sprintf(gc, "%d", info->domid), NULL);

    if (c_info->name)
        flexarray_vappend(dm_args, "-domain-name", c_info->name, NULL);

    if (vnc) {
        char *vncarg;
        if (vnc->display) {
            if (vnc->listen && strchr(vnc->listen, ':') == NULL) {
                vncarg = libxl__sprintf(gc, "%s:%d",
                                  vnc->listen,
                                  vnc->display);
            } else {
                vncarg = libxl__sprintf(gc, "127.0.0.1:%d", vnc->display);
            }
        } else if (vnc->listen) {
            if (strchr(vnc->listen, ':') != NULL) {
                vncarg = vnc->listen;
            } else {
                vncarg = libxl__sprintf(gc, "%s:0", vnc->listen);
            }
        } else {
            vncarg = "127.0.0.1:0";
        }
        if (vnc->passwd && (vnc->passwd[0] != '\0'))
            vncarg = libxl__sprintf(gc, "%s,password", vncarg);
        flexarray_append(dm_args, "-vnc");
        flexarray_append(dm_args, vncarg);

        if (vnc->findunused) {
            flexarray_append(dm_args, "-vncunused");
        }
    }
    if (sdl) {
        flexarray_append(dm_args, "-sdl");
        if (!sdl->opengl) {
            flexarray_append(dm_args, "-disable-opengl");
        }
        /* XXX sdl->{display,xauthority} into $DISPLAY/$XAUTHORITY */
    }
    if (info->keymap) {
        flexarray_vappend(dm_args, "-k", info->keymap, NULL);
    }
    if (info->nographic && (!sdl && !vnc)) {
        flexarray_append(dm_args, "-nographic");
    }
    if (info->serial) {
        flexarray_vappend(dm_args, "-serial", info->serial, NULL);
    }
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
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
        if (b_info->u.hvm.acpi) {
            flexarray_append(dm_args, "-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_vappend(dm_args, "-vcpus",
                              libxl__sprintf(gc, "%d", b_info->max_vcpus),
                              NULL);
        }
        if (b_info->cur_vcpus) {
            flexarray_vappend(dm_args, "-vcpu_avail",
                              libxl__sprintf(gc, "0x%x", b_info->cur_vcpus),
                              NULL);
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == LIBXL_NIC_TYPE_IOEMU) {
                char *smac = libxl__sprintf(gc,
                                   LIBXL_MAC_FMT, LIBXL_MAC_BYTES(vifs[i].mac));
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
        if (info->gfx_passthru) {
            flexarray_append(dm_args, "-gfx_passthru");
        }
    }
    if (info->saved_state) {
        flexarray_vappend(dm_args, "-loadvm", info->saved_state, NULL);
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_append(dm_args, info->extra[i]);
    flexarray_append(dm_args, "-M");
    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_PV:
        flexarray_append(dm_args, "xenpv");
        for (i = 0; info->extra_pv && info->extra_pv[i] != NULL; i++)
            flexarray_append(dm_args, info->extra_pv[i]);
        break;
    case LIBXL_DOMAIN_TYPE_HVM:
        flexarray_append(dm_args, "xenfv");
        for (i = 0; info->extra_hvm && info->extra_hvm[i] != NULL; i++)
            flexarray_append(dm_args, info->extra_hvm[i]);
        break;
    }
    flexarray_append(dm_args, NULL);
    return (char **) flexarray_contents(dm_args);
}

static const char *qemu_disk_format_string(libxl_disk_format format)
{
    switch (format) {
    case LIBXL_DISK_FORMAT_QCOW: return "qcow";
    case LIBXL_DISK_FORMAT_QCOW2: return "qcow2";
    case LIBXL_DISK_FORMAT_VHD: return "vpc";
    case LIBXL_DISK_FORMAT_RAW: return "raw";
    case LIBXL_DISK_FORMAT_EMPTY: return NULL;
    default: return NULL;
    }
}

static char ** libxl__build_device_model_args_new(libxl__gc *gc,
                                        const char *dm,
                                        const libxl_domain_config *guest_config,
                                        const libxl_device_model_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_device_disk *disks = guest_config->disks;
    const libxl_device_nic *vifs = guest_config->vifs;
    const int num_disks = guest_config->num_disks;
    const int num_vifs = guest_config->num_vifs;
    const libxl_vnc_info *vnc = dm_vnc(guest_config, info);
    const libxl_sdl_info *sdl = dm_sdl(guest_config, info);
    flexarray_t *dm_args;
    int i;

    dm_args = flexarray_make(16, 1);
    if (!dm_args)
        return NULL;

    flexarray_vappend(dm_args, dm,
                      "-xen-domid", libxl__sprintf(gc, "%d", info->domid), NULL);

    flexarray_append(dm_args, "-chardev");
    flexarray_append(dm_args,
                     libxl__sprintf(gc, "socket,id=libxl-cmd,"
                                    "path=%s/qmp-libxl-%d,server,nowait",
                                    libxl_run_dir_path(),
                                    info->domid));

    flexarray_append(dm_args, "-mon");
    flexarray_append(dm_args, "chardev=libxl-cmd,mode=control");

    if (info->type == LIBXL_DOMAIN_TYPE_PV) {
        flexarray_append(dm_args, "-xen-attach");
    }

    if (c_info->name) {
        flexarray_vappend(dm_args, "-name", c_info->name, NULL);
    }
    if (vnc) {
        int display = 0;
        const char *listen = "127.0.0.1";

        if (vnc->passwd && vnc->passwd[0]) {
            assert(!"missing code for supplying vnc password to qemu");
        }
        flexarray_append(dm_args, "-vnc");

        if (vnc->display) {
            display = vnc->display;
            if (vnc->listen && strchr(vnc->listen, ':') == NULL) {
                listen = vnc->listen;
            }
        } else if (vnc->listen) {
            listen = vnc->listen;
        }

        if (strchr(listen, ':') != NULL)
            flexarray_append(dm_args,
                    libxl__sprintf(gc, "%s%s", listen,
                        vnc->findunused ? ",to=99" : ""));
        else
            flexarray_append(dm_args,
                    libxl__sprintf(gc, "%s:%d%s", listen, display,
                        vnc->findunused ? ",to=99" : ""));
    }
    if (sdl) {
        flexarray_append(dm_args, "-sdl");
        /* XXX sdl->{display,xauthority} into $DISPLAY/$XAUTHORITY */
    }
    if (info->spice.enable) {
        char *spiceoptions = NULL;
        if (!info->spice.port && !info->spice.tls_port) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                "at least one of the spiceport or tls_port must be provided");
            return NULL;
        }

        if (!info->spice.disable_ticketing) {
            if (!info->spice.passwd) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                    "spice ticketing is enabled but missing password");
                return NULL;
            }
            else if (!info->spice.passwd[0]) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                    "spice password can't be empty");
                return NULL;
            }
        }
        spiceoptions = libxl__sprintf(gc, "port=%d,tls-port=%d",
                                      info->spice.port, info->spice.tls_port);
        if (info->spice.host)
            spiceoptions = libxl__sprintf(gc,
                    "%s,addr=%s", spiceoptions, info->spice.host);
        if (info->spice.disable_ticketing)
            spiceoptions = libxl__sprintf(gc, "%s,disable-ticketing",
                                               spiceoptions);
        else
            spiceoptions = libxl__sprintf(gc,
                    "%s,password=%s", spiceoptions, info->spice.passwd);
        spiceoptions = libxl__sprintf(gc, "%s,agent-mouse=%s", spiceoptions,
                                      info->spice.agent_mouse ? "on" : "off");

        flexarray_append(dm_args, "-spice");
        flexarray_append(dm_args, spiceoptions);
    }

    if (info->type == LIBXL_DOMAIN_TYPE_PV && !info->nographic) {
        flexarray_vappend(dm_args, "-vga", "xenfb", NULL);
    }

    if (info->keymap) {
        flexarray_vappend(dm_args, "-k", info->keymap, NULL);
    }
    if (info->nographic && (!sdl && !vnc)) {
        flexarray_append(dm_args, "-nographic");
    }
    if (info->serial) {
        flexarray_vappend(dm_args, "-serial", info->serial, NULL);
    }
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
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
        if (!b_info->u.hvm.acpi) {
            flexarray_append(dm_args, "-no-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_append(dm_args, "-smp");
            if (b_info->cur_vcpus)
                flexarray_append(dm_args, libxl__sprintf(gc, "%d,maxcpus=%d",
                                                         b_info->max_vcpus,
                                                         b_info->cur_vcpus));
            else
                flexarray_append(dm_args, libxl__sprintf(gc, "%d",
                                                         b_info->max_vcpus));
        }
        for (i = 0; i < num_vifs; i++) {
            if (vifs[i].nictype == LIBXL_NIC_TYPE_IOEMU) {
                char *smac = libxl__sprintf(gc,
                                LIBXL_MAC_FMT, LIBXL_MAC_BYTES(vifs[i].mac));
                char *ifname;
                if (!vifs[i].ifname) {
                    ifname = libxl__sprintf(gc, "tap%d.%d", info->domid, vifs[i].devid);
                } else {
                    ifname = vifs[i].ifname;
                }
                flexarray_append(dm_args, "-device");
                flexarray_append(dm_args,
                   libxl__sprintf(gc, "%s,id=nic%d,netdev=net%d,mac=%s",
                                                vifs[i].model, vifs[i].devid,
                                                vifs[i].devid, smac));
                flexarray_append(dm_args, "-netdev");
                flexarray_append(dm_args,
                   libxl__sprintf(gc, "type=tap,id=net%d,ifname=%s,script=%s",
                                                vifs[i].devid, ifname,
                                                libxl_tapif_script(gc)));
                ioemu_vifs++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_vifs == 0 ) {
            flexarray_append(dm_args, "-net");
            flexarray_append(dm_args, "none");
        }
        if (info->gfx_passthru) {
            flexarray_append(dm_args, "-gfx_passthru");
        }
    }
    if (info->saved_state) {
        /* This file descriptor is meant to be used by QEMU */
        int migration_fd = open(info->saved_state, O_RDONLY);
        flexarray_append(dm_args, "-incoming");
        flexarray_append(dm_args, libxl__sprintf(gc, "fd:%d", migration_fd));
    }
    for (i = 0; info->extra && info->extra[i] != NULL; i++)
        flexarray_append(dm_args, info->extra[i]);
    flexarray_append(dm_args, "-M");
    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_PV:
        flexarray_append(dm_args, "xenpv");
        for (i = 0; info->extra_pv && info->extra_pv[i] != NULL; i++)
            flexarray_append(dm_args, info->extra_pv[i]);
        break;
    case LIBXL_DOMAIN_TYPE_HVM:
        flexarray_append(dm_args, "xenfv");
        for (i = 0; info->extra_hvm && info->extra_hvm[i] != NULL; i++)
            flexarray_append(dm_args, info->extra_hvm[i]);
        break;
    }

    /* RAM Size */
    flexarray_append(dm_args, "-m");
    flexarray_append(dm_args,
                     libxl__sprintf(gc, "%d",
                                    libxl__sizekb_to_mb(b_info->target_memkb)));

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        for (i = 0; i < num_disks; i++) {
            int disk, part;
            int dev_number =
                libxl__device_disk_dev_number(disks[i].vdev, &disk, &part);
            const char *format = qemu_disk_format_string(disks[i].format);
            char *drive;

            if (dev_number == -1) {
                LIBXL__LOG(ctx, LIBXL__LOG_WARNING, "unable to determine"
                           " disk number for %s", disks[i].vdev);
                continue;
            }

            if (disks[i].is_cdrom) {
                if (disks[i].format == LIBXL_DISK_FORMAT_EMPTY)
                    drive = libxl__sprintf
                        (gc, "if=ide,index=%d,media=cdrom", disk);
                else
                    drive = libxl__sprintf
                        (gc, "file=%s,if=ide,index=%d,media=cdrom,format=%s",
                         disks[i].pdev_path, disk, format);
            } else {
                if (disks[i].format == LIBXL_DISK_FORMAT_EMPTY) {
                    LIBXL__LOG(ctx, LIBXL__LOG_WARNING, "cannot support"
                               " empty disk format for %s", disks[i].vdev);
                    continue;
                }

                if (format == NULL) {
                    LIBXL__LOG(ctx, LIBXL__LOG_WARNING, "unable to determine"
                               " disk image format %s", disks[i].vdev);
                    continue;
                }

                /*
                 * Explicit sd disks are passed through as is.
                 *
                 * For other disks we translate devices 0..3 into
                 * hd[a-d] and ignore the rest.
                 */
                if (strncmp(disks[i].vdev, "sd", 2) == 0)
                    drive = libxl__sprintf
                        (gc, "file=%s,if=scsi,bus=0,unit=%d,format=%s",
                         disks[i].pdev_path, disk, format);
                else if (disk < 4)
                    drive = libxl__sprintf
                        (gc, "file=%s,if=ide,index=%d,media=disk,format=%s",
                         disks[i].pdev_path, disk, format);
                else
                    continue; /* Do not emulate this disk */
            }

            flexarray_append(dm_args, "-drive");
            flexarray_append(dm_args, drive);
        }
    }
    flexarray_append(dm_args, NULL);
    return (char **) flexarray_contents(dm_args);
}

static char ** libxl__build_device_model_args(libxl__gc *gc,
                                        const char *dm,
                                        const libxl_domain_config *guest_config,
                                        const libxl_device_model_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);

    switch (info->device_model_version) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        return libxl__build_device_model_args_old(gc, dm, guest_config, info);
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        return libxl__build_device_model_args_new(gc, dm, guest_config, info);
    default:
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unknown device model version %d",
                         info->device_model_version);
        return NULL;
    }
}

static int libxl__vfb_and_vkb_from_device_model_info(libxl__gc *gc,
                                        const libxl_device_model_info *info,
                                        libxl_device_vfb *vfb,
                                        libxl_device_vkb *vkb)
{
    memset(vfb, 0x00, sizeof(libxl_device_vfb));
    memset(vkb, 0x00, sizeof(libxl_device_vkb));

    vfb->backend_domid = 0;
    vfb->devid = 0;
    vfb->vnc = info->vnc;
    vfb->keymap = info->keymap;
    vfb->sdl = info->sdl;

    vkb->backend_domid = 0;
    vkb->devid = 0;
    return 0;
}

static int libxl__write_dmargs(libxl__gc *gc, int domid, int guest_domid, char **args)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
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

    vm_path = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "/local/domain/%d/vm", guest_domid));

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
    path = libxl__sprintf(gc, "%s/image/dmargs", vm_path);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, path, dmargs, strlen(dmargs));
    xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    xs_set_permissions(ctx->xsh, t, libxl__sprintf(gc, "%s/rtc/timeoffset", vm_path), roperm, ARRAY_SIZE(roperm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    free(dmargs);
    return 0;
}

static int libxl__create_stubdom(libxl__gc *gc,
                                 libxl_domain_config *guest_config,
                                 libxl_device_model_info *info,
                                 libxl__spawner_starting **starting_r)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int i, num_console = STUBDOM_SPECIAL_CONSOLES, ret;
    libxl_device_console *console;
    libxl_domain_config dm_config;
    libxl_device_vfb vfb;
    libxl_device_vkb vkb;
    libxl__domain_build_state state;
    uint32_t domid;
    char **args;
    struct xs_permissions perm[2];
    xs_transaction_t t;
    libxl__spawner_starting *dm_starting = 0;
    libxl_device_model_info xenpv_dm_info;

    if (info->device_model_version != LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL) {
        ret = ERROR_INVAL;
        goto out;
    }

    memset(&dm_config.c_info, 0x00, sizeof(libxl_domain_create_info));
    dm_config.c_info.type = LIBXL_DOMAIN_TYPE_PV;
    dm_config.c_info.name = libxl__sprintf(gc, "%s-dm", libxl__domid_to_name(gc, info->domid));

    libxl_uuid_copy(&dm_config.c_info.uuid, &info->uuid);

    memset(&dm_config.b_info, 0x00, sizeof(libxl_domain_build_info));
    dm_config.b_info.max_vcpus = 1;
    dm_config.b_info.max_memkb = 32 * 1024;
    dm_config.b_info.target_memkb = dm_config.b_info.max_memkb;

    dm_config.b_info.type = LIBXL_DOMAIN_TYPE_PV;
    dm_config.b_info.u.pv.kernel.path = libxl__abs_path(gc, "ioemu-stubdom.gz",
                                              libxl_xenfirmwaredir_path());
    dm_config.b_info.u.pv.cmdline = libxl__sprintf(gc, " -d %d", info->domid);
    dm_config.b_info.u.pv.ramdisk.path = "";
    dm_config.b_info.u.pv.features = "";

    dm_config.disks = guest_config->disks;
    dm_config.num_disks = guest_config->num_disks;

    dm_config.vifs = guest_config->vifs;
    dm_config.num_vifs = guest_config->num_vifs;

    libxl__vfb_and_vkb_from_device_model_info(gc, info, &vfb, &vkb);

    dm_config.vfbs = &vfb;
    dm_config.num_vfbs = 1;
    dm_config.vkbs = &vkb;
    dm_config.num_vkbs = 1;

    /* fixme: this function can leak the stubdom if it fails */
    domid = 0;
    ret = libxl__domain_make(gc, &dm_config.c_info, &domid);
    if (ret)
        goto out;
    ret = libxl__domain_build(gc, &dm_config.b_info, info, domid, &state);
    if (ret)
        goto out;

    args = libxl__build_device_model_args(gc, "stubdom-dm",
                                          guest_config, info);
    if (!args) {
        ret = ERROR_FAIL;
        goto out;
    }

    libxl__write_dmargs(gc, domid, info->domid, args);
    libxl__xs_write(gc, XBT_NULL,
                   libxl__sprintf(gc, "%s/image/device-model-domid", libxl__xs_get_dompath(gc, info->domid)),
                   "%d", domid);
    libxl__xs_write(gc, XBT_NULL,
                   libxl__sprintf(gc, "%s/target", libxl__xs_get_dompath(gc, domid)),
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
    xs_mkdir(ctx->xsh, t, libxl__sprintf(gc, "/local/domain/0/device-model/%d", info->domid));
    xs_set_permissions(ctx->xsh, t, libxl__sprintf(gc, "/local/domain/0/device-model/%d", info->domid), perm, ARRAY_SIZE(perm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    for (i = 0; i < dm_config.num_disks; i++) {
        ret = libxl_device_disk_add(ctx, domid, &dm_config.disks[i]);
        if (ret)
            goto out_free;
    }
    for (i = 0; i < dm_config.num_vifs; i++) {
        ret = libxl_device_nic_add(ctx, domid, &dm_config.vifs[i]);
        if (ret)
            goto out_free;
    }
    ret = libxl_device_vfb_add(ctx, domid, &dm_config.vfbs[0]);
    if (ret)
        goto out_free;
    ret = libxl_device_vkb_add(ctx, domid, &dm_config.vkbs[0]);
    if (ret)
        goto out_free;

    if (info->serial)
        num_console++;

    console = libxl__calloc(gc, num_console, sizeof(libxl_device_console));
    if (!console) {
        ret = ERROR_NOMEM;
        goto out_free;
    }

    for (i = 0; i < num_console; i++) {
        console[i].devid = i;
        console[i].consback = LIBXL_CONSOLE_BACKEND_IOEMU;
        /* STUBDOM_CONSOLE_LOGGING (console 0) is for minios logging
         * STUBDOM_CONSOLE_SAVE (console 1) is for writing the save file
         * STUBDOM_CONSOLE_RESTORE (console 2) is for reading the save file
         */
        switch (i) {
            char *filename;
            char *name;
            case STUBDOM_CONSOLE_LOGGING:
                name = libxl__sprintf(gc, "qemu-dm-%s", libxl_domid_to_name(ctx, info->domid));
                libxl_create_logfile(ctx, name, &filename);
                console[i].output = libxl__sprintf(gc, "file:%s", filename);
                free(filename);
                break;
            case STUBDOM_CONSOLE_SAVE:
                console[i].output = libxl__sprintf(gc, "file:%s",
                                libxl__device_model_savefile(gc, info->domid));
                break;
            case STUBDOM_CONSOLE_RESTORE:
                if (info->saved_state)
                    console[i].output = libxl__sprintf(gc, "pipe:%s", info->saved_state);
                break;
            default:
                console[i].output = "pty";
                break;
        }
        ret = libxl__device_console_add(gc, domid, &console[i],
                                    i == STUBDOM_CONSOLE_LOGGING ? &state : NULL);
        if (ret)
            goto out_free;
    }

    memset((void*)&xenpv_dm_info, 0, sizeof(libxl_device_model_info));
    xenpv_dm_info.device_model_version = info->device_model_version;
    xenpv_dm_info.type = LIBXL_DOMAIN_TYPE_PV;
    xenpv_dm_info.device_model = info->device_model;
    xenpv_dm_info.extra = info->extra;
    xenpv_dm_info.extra_pv = info->extra_pv;
    xenpv_dm_info.extra_hvm = info->extra_hvm;

    if (libxl__create_xenpv_qemu(gc, domid,
                                 &dm_config,
                                 &xenpv_dm_info,
                                 &dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }
    if (libxl__confirm_device_model_startup(gc, &xenpv_dm_info,
                                            dm_starting) < 0) {
        ret = ERROR_FAIL;
        goto out_free;
    }

    libxl_domain_unpause(ctx, domid);

    if (starting_r) {
        *starting_r = calloc(1, sizeof(libxl__spawner_starting));
        (*starting_r)->domid = info->domid;
        (*starting_r)->dom_path = libxl__xs_get_dompath(gc, info->domid);
        (*starting_r)->for_spawn = NULL;
    }

    ret = 0;

out_free:
    free(args);
out:
    return ret;
}

int libxl__create_device_model(libxl__gc *gc,
                              libxl_domain_config *guest_config,
                              libxl_device_model_info *info,
                              libxl__spawner_starting **starting_r)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_vnc_info *vnc = dm_vnc(guest_config, info);
    char *path, *logfile;
    int logfile_w, null;
    int rc;
    char **args;
    libxl__spawner_starting buf_starting, *p;
    xs_transaction_t t;
    char *vm_path;
    char **pass_stuff;
    const char *dm;

    if (info->device_model_stubdomain) {
        rc = libxl__create_stubdom(gc, guest_config, info, starting_r);
        goto out;
    }

    dm = libxl__domain_device_model(gc, info);
    if (!dm) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (access(dm, X_OK) < 0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                         "device model %s is not executable", dm);
        rc = ERROR_FAIL;
        goto out;
    }
    args = libxl__build_device_model_args(gc, dm, guest_config, info);
    if (!args) {
        rc = ERROR_FAIL;
        goto out;
    }

    path = xs_get_domain_path(ctx->xsh, info->domid);
    libxl__xs_write(gc, XBT_NULL, libxl__sprintf(gc, "%s/hvmloader/bios", path),
                    "%s", libxl__domain_bios(gc, info));
    free(path);

    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d", info->domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);
    libxl__xs_write(gc, XBT_NULL, libxl__sprintf(gc, "%s/disable_pf", path), "%d", !info->xen_platform_pci);

    libxl_create_logfile(ctx,
                         libxl__sprintf(gc, "qemu-dm-%s", c_info->name),
                         &logfile);
    logfile_w = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
    free(logfile);
    null = open("/dev/null", O_RDONLY);

    if (starting_r) {
        rc = ERROR_NOMEM;
        *starting_r = calloc(1, sizeof(libxl__spawner_starting));
        if (!*starting_r)
            goto out_close;
        p = *starting_r;
        p->for_spawn = calloc(1, sizeof(libxl__spawn_starting));
    } else {
        p = &buf_starting;
        p->for_spawn = NULL;
    }

    p->domid = info->domid;
    p->dom_path = libxl__xs_get_dompath(gc, info->domid);
    p->pid_path = "image/device-model-pid";
    if (!p->dom_path) {
        rc = ERROR_FAIL;
        goto out_close;
    }

    if (vnc && vnc->passwd) {
retry_transaction:
        /* Find uuid and the write the vnc password to xenstore for qemu. */
        t = xs_transaction_start(ctx->xsh);
        vm_path = libxl__xs_read(gc,t,libxl__sprintf(gc, "%s/vm", p->dom_path));
        if (vm_path) {
            /* Now write the vncpassword into it. */
            pass_stuff = libxl__calloc(gc, 3, sizeof(char *));
            pass_stuff[0] = "vncpasswd";
            pass_stuff[1] = vnc->passwd;
            libxl__xs_writev(gc,t,vm_path,pass_stuff);
            if (!xs_transaction_end(ctx->xsh, t, 0))
                if (errno == EAGAIN)
                    goto retry_transaction;
        }
    }

    rc = libxl__spawn_spawn(gc, p->for_spawn, "device model",
                            libxl_spawner_record_pid, p);
    if (rc < 0)
        goto out_close;
    if (!rc) { /* inner child */
        setsid();
        libxl__exec(null, logfile_w, logfile_w, dm, args);
    }

    rc = 0;

out_close:
    close(null);
    close(logfile_w);
    free(args);
out:
    return rc;
}


int libxl__confirm_device_model_startup(libxl__gc *gc,
                                libxl_device_model_info *dm_info,
                                libxl__spawner_starting *starting)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path;
    int domid = starting->domid;
    int ret, ret2;
    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    ret = libxl__spawn_confirm_offspring_startup(gc,
                                     LIBXL_DEVICE_MODEL_START_TIMEOUT,
                                     "Device Model", path, "running", starting);
    if (dm_info->saved_state) {
        ret2 = unlink(dm_info->saved_state);
        if (ret2) LIBXL__LOG_ERRNO(ctx, XTL_ERROR,
                                   "failed to remove device-model state %s\n",
                                   dm_info->saved_state);
        /* Do not clobber spawn_confirm error code with unlink error code. */
        if (!ret) ret = ret2;
    }
    return ret;
}

int libxl__destroy_device_model(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *pid;
    int ret;

    pid = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "/local/domain/%d/image/device-model-pid", domid));
    if (!pid) {
        int stubdomid = libxl_get_stubdom_id(ctx, domid);
        const char *savefile;

        if (!stubdomid) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Couldn't find device model's pid");
            ret = ERROR_INVAL;
            goto out;
        }
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Device model is a stubdom, domid=%d", stubdomid);
        ret = libxl_domain_destroy(ctx, stubdomid);
        if (ret)
            goto out;

        savefile = libxl__device_model_savefile(gc, domid);
        ret = unlink(savefile);
        /*
         * On suspend libxl__domain_save_device_model will have already
         * unlinked the save file.
         */
        if (ret && errno == ENOENT) ret = 0;
        if (ret) {
            LIBXL__LOG_ERRNO(ctx, XTL_ERROR,
                             "failed to remove device-model savefile %s\n",
                             savefile);
            goto out;
        }
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
    xs_rm(ctx->xsh, XBT_NULL, libxl__sprintf(gc, "/local/domain/0/device-model/%d", domid));
    xs_rm(ctx->xsh, XBT_NULL, libxl__sprintf(gc, "/local/domain/%d/hvmloader", domid));

out:
    return ret;
}

static int libxl__build_xenpv_qemu_args(libxl__gc *gc,
                                        uint32_t domid,
                                        libxl_device_model_info *info)
{
    info->domid = domid;
    return 0;
}

int libxl__need_xenpv_qemu(libxl__gc *gc,
        int nr_consoles, libxl_device_console *consoles,
        int nr_vfbs, libxl_device_vfb *vfbs,
        int nr_disks, libxl_device_disk *disks)
{
    int i, ret = 0;

    if (nr_consoles > 1) {
        ret = 1;
        goto out;
    }

    for (i = 0; i < nr_consoles; i++) {
        if (consoles[i].consback == LIBXL_CONSOLE_BACKEND_IOEMU) {
            ret = 1;
            goto out;
        }
    }

    if (nr_vfbs > 0) {
        ret = 1;
        goto out;
    }

    if (nr_disks > 0) {
        for (i = 0; i < nr_disks; i++) {
            if (disks[i].backend == LIBXL_DISK_BACKEND_QDISK) {
                ret = 1;
                goto out;
            }
        }
    }

out:
    return ret;
}

int libxl__create_xenpv_qemu(libxl__gc *gc, uint32_t domid,
                             libxl_domain_config *guest_config,
                             libxl_device_model_info *info,
                             libxl__spawner_starting **starting_r)
{
    libxl__build_xenpv_qemu_args(gc, domid, info);
    libxl__create_device_model(gc, guest_config, info, starting_r);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
