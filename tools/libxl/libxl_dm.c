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
    return libxl__sprintf(gc, "%s/qemu-ifup", libxl__xen_script_dir_path());
#endif
}

const char *libxl__device_model_savefile(libxl__gc *gc, uint32_t domid)
{
    return libxl__sprintf(gc, "/var/lib/xen/qemu-save.%d", domid);
}

static const char *qemu_xen_path(libxl__gc *gc)
{
#ifdef QEMU_XEN_PATH
    return QEMU_XEN_PATH;
#else
    return libxl__abs_path(gc, "qemu-system-i386", libxl__libexec_path());
#endif
}

static int libxl__create_qemu_logfile(libxl__gc *gc, char *name)
{
    char *logfile;
    int logfile_w;

    libxl_create_logfile(CTX, name, &logfile);
    logfile_w = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
    free(logfile);

    if (logfile_w < 0) {
        LOGE(ERROR, "unable to open Qemu logfile");
        return ERROR_FAIL;
    }

    return logfile_w;
}

const char *libxl__domain_device_model(libxl__gc *gc,
                                       const libxl_domain_build_info *info)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const char *dm;

    if (libxl_defbool_val(info->device_model_stubdomain))
        return NULL;

    if (info->device_model) {
        dm = libxl__strdup(gc, info->device_model);
    } else {
        switch (info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            dm = libxl__abs_path(gc, "qemu-dm", libxl__libexec_path());
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            dm = qemu_xen_path(gc);
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

const libxl_vnc_info *libxl__dm_vnc(const libxl_domain_config *guest_config)
{
    const libxl_vnc_info *vnc = NULL;
    if (guest_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        vnc = &guest_config->b_info.u.hvm.vnc;
    } else if (guest_config->num_vfbs > 0) {
        vnc = &guest_config->vfbs[0].vnc;
    }
    return vnc && libxl_defbool_val(vnc->enable) ? vnc : NULL;
}

static const libxl_sdl_info *dm_sdl(const libxl_domain_config *guest_config)
{
    const libxl_sdl_info *sdl = NULL;
    if (guest_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        sdl = &guest_config->b_info.u.hvm.sdl;
    } else if (guest_config->num_vfbs > 0) {
        sdl = &guest_config->vfbs[0].sdl;
    }
    return sdl && libxl_defbool_val(sdl->enable) ? sdl : NULL;
}

static const char *dm_keymap(const libxl_domain_config *guest_config)
{
    if (guest_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        return guest_config->b_info.u.hvm.keymap;
    } else if (guest_config->num_vfbs > 0) {
        return guest_config->vfbs[0].keymap;
    } else
        return NULL;
}

static char ** libxl__build_device_model_args_old(libxl__gc *gc,
                                        const char *dm, int domid,
                                        const libxl_domain_config *guest_config,
                                        const libxl__domain_build_state *state)
{
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_device_nic *nics = guest_config->nics;
    const libxl_vnc_info *vnc = libxl__dm_vnc(guest_config);
    const libxl_sdl_info *sdl = dm_sdl(guest_config);
    const int num_nics = guest_config->num_nics;
    const char *keymap = dm_keymap(guest_config);
    int i;
    flexarray_t *dm_args;
    dm_args = flexarray_make(gc, 16, 1);

    flexarray_vappend(dm_args, dm,
                      "-d", libxl__sprintf(gc, "%d", domid), NULL);

    if (c_info->name)
        flexarray_vappend(dm_args, "-domain-name", c_info->name, NULL);

    if (vnc) {
        char *vncarg = NULL;

        flexarray_append(dm_args, "-vnc");

        /*
         * If vnc->listen is present and contains a :, and
         *  - vnc->display is 0, use vnc->listen
         *  - vnc->display is non-zero, be confused
         * If vnc->listen is present but doesn't, use vnc->listen:vnc->display.
         * If vnc->listen is not present, use 127.0.0.1:vnc->display
         * (Remembering that vnc->display already defaults to 0.)
         */
        if (vnc->listen) {
            if (strchr(vnc->listen, ':') != NULL) {
                if (vnc->display) {
                    LOG(ERROR, "vncdisplay set, vnclisten contains display");
                    return NULL;
                }
                vncarg = vnc->listen;
            } else {
                vncarg = libxl__sprintf(gc, "%s:%d", vnc->listen,
                                        vnc->display);
            }
        } else
            vncarg = libxl__sprintf(gc, "127.0.0.1:%d", vnc->display);

        if (vnc->passwd && vnc->passwd[0]) {
            vncarg = libxl__sprintf(gc, "%s,password", vncarg);
        }

        flexarray_append(dm_args, vncarg);

        if (libxl_defbool_val(vnc->findunused)) {
            flexarray_append(dm_args, "-vncunused");
        }
    } else
        /*
         * VNC is not enabled by default by qemu-xen-traditional,
         * however passing -vnc none causes SDL to not be
         * (unexpectedly) enabled by default. This is overridden by
         * explicitly passing -sdl below as required.
         */
        flexarray_append_pair(dm_args, "-vnc", "none");

    if (sdl) {
        flexarray_append(dm_args, "-sdl");
        if (!libxl_defbool_val(sdl->opengl)) {
            flexarray_append(dm_args, "-disable-opengl");
        }
        /* XXX sdl->{display,xauthority} into $DISPLAY/$XAUTHORITY */
    }
    if (keymap) {
        flexarray_vappend(dm_args, "-k", keymap, NULL);
    }
    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        int ioemu_nics = 0;
        int nr_set_cpus = 0;
        char *s;

        if (b_info->u.hvm.serial) {
            flexarray_vappend(dm_args, "-serial", b_info->u.hvm.serial, NULL);
        }

        if (libxl_defbool_val(b_info->u.hvm.nographic) && (!sdl && !vnc)) {
            flexarray_append(dm_args, "-nographic");
        }

        if (b_info->video_memkb) {
            flexarray_vappend(dm_args, "-videoram",
                    libxl__sprintf(gc, "%d",
                                   libxl__sizekb_to_mb(b_info->video_memkb)),
                    NULL);
        }

        switch (b_info->u.hvm.vga.kind) {
        case LIBXL_VGA_INTERFACE_TYPE_STD:
            flexarray_append(dm_args, "-std-vga");
            break;
        case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            break;
        }

        if (b_info->u.hvm.boot) {
            flexarray_vappend(dm_args, "-boot", b_info->u.hvm.boot, NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.usb)
            || b_info->u.hvm.usbdevice
            || b_info->u.hvm.usbdevice_list) {
            if ( b_info->u.hvm.usbdevice && b_info->u.hvm.usbdevice_list )
            {
                LOG(ERROR, "%s: Both usbdevice and usbdevice_list set",
                    __func__);
                return NULL;
            }
            flexarray_append(dm_args, "-usb");
            if (b_info->u.hvm.usbdevice) {
                flexarray_vappend(dm_args,
                                  "-usbdevice", b_info->u.hvm.usbdevice, NULL);
            } else if (b_info->u.hvm.usbdevice_list) {
                char **p;
                for (p = b_info->u.hvm.usbdevice_list;
                     *p;
                     p++) {
                    flexarray_vappend(dm_args,
                                      "-usbdevice",
                                      *p, NULL);
                }
            }
        }
        if (b_info->u.hvm.soundhw) {
            flexarray_vappend(dm_args, "-soundhw", b_info->u.hvm.soundhw, NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.acpi)) {
            flexarray_append(dm_args, "-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_vappend(dm_args, "-vcpus",
                              libxl__sprintf(gc, "%d", b_info->max_vcpus),
                              NULL);
        }

        nr_set_cpus = libxl_bitmap_count_set(&b_info->avail_vcpus);
        s = libxl_bitmap_to_hex_string(CTX, &b_info->avail_vcpus);
        flexarray_vappend(dm_args, "-vcpu_avail",
                              libxl__sprintf(gc, "%s", s), NULL);
        free(s);

        for (i = 0; i < num_nics; i++) {
            if (nics[i].nictype == LIBXL_NIC_TYPE_VIF_IOEMU) {
                char *smac = libxl__sprintf(gc,
                                   LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nics[i].mac));
                const char *ifname = libxl__device_nic_devname(gc,
                                                domid, nics[i].devid,
                                                LIBXL_NIC_TYPE_VIF_IOEMU);
                flexarray_vappend(dm_args,
                                  "-net",
                                  GCSPRINTF(
                                      "nic,vlan=%d,macaddr=%s,model=%s",
                                      nics[i].devid, smac, nics[i].model),
                                  "-net",
                                  GCSPRINTF(
                                      "tap,vlan=%d,ifname=%s,bridge=%s,"
                                      "script=%s,downscript=%s",
                                      nics[i].devid, ifname, nics[i].bridge,
                                      libxl_tapif_script(gc),
                                      libxl_tapif_script(gc)),
                                  NULL);
                ioemu_nics++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_nics == 0 ) {
            flexarray_vappend(dm_args, "-net", "none", NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.gfx_passthru)) {
            flexarray_append(dm_args, "-gfx_passthru");
        }
    } else {
        if (!sdl && !vnc)
            flexarray_append(dm_args, "-nographic");
    }

    if (state->saved_state) {
        flexarray_vappend(dm_args, "-loadvm", state->saved_state, NULL);
    }
    for (i = 0; b_info->extra && b_info->extra[i] != NULL; i++)
        flexarray_append(dm_args, b_info->extra[i]);
    flexarray_append(dm_args, "-M");
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PV:
        flexarray_append(dm_args, "xenpv");
        for (i = 0; b_info->extra_pv && b_info->extra_pv[i] != NULL; i++)
            flexarray_append(dm_args, b_info->extra_pv[i]);
        break;
    case LIBXL_DOMAIN_TYPE_HVM:
        flexarray_append(dm_args, "xenfv");
        for (i = 0; b_info->extra_hvm && b_info->extra_hvm[i] != NULL; i++)
            flexarray_append(dm_args, b_info->extra_hvm[i]);
        break;
    default:
        abort();
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

static char *dm_spice_options(libxl__gc *gc,
                                    const libxl_spice_info *spice)
{
    char *opt;

    if (!spice->port && !spice->tls_port) {
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                   "at least one of the spiceport or tls_port must be provided");
        return NULL;
    }

    if (!libxl_defbool_val(spice->disable_ticketing)) {
        if (!spice->passwd) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                       "spice ticketing is enabled but missing password");
            return NULL;
        }
        else if (!spice->passwd[0]) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                               "spice password can't be empty");
            return NULL;
        }
    }
    opt = libxl__sprintf(gc, "port=%d,tls-port=%d",
                         spice->port, spice->tls_port);
    if (spice->host)
        opt = libxl__sprintf(gc, "%s,addr=%s", opt, spice->host);
    if (libxl_defbool_val(spice->disable_ticketing))
        opt = libxl__sprintf(gc, "%s,disable-ticketing", opt);
    else
        opt = libxl__sprintf(gc, "%s,password=%s", opt, spice->passwd);
    opt = libxl__sprintf(gc, "%s,agent-mouse=%s", opt,
                         libxl_defbool_val(spice->agent_mouse) ? "on" : "off");

    if (!libxl_defbool_val(spice->clipboard_sharing))
        opt = libxl__sprintf(gc, "%s,disable-copy-paste", opt);

    return opt;
}

static char ** libxl__build_device_model_args_new(libxl__gc *gc,
                                        const char *dm, int guest_domid,
                                        const libxl_domain_config *guest_config,
                                        const libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_device_disk *disks = guest_config->disks;
    const libxl_device_nic *nics = guest_config->nics;
    const int num_disks = guest_config->num_disks;
    const int num_nics = guest_config->num_nics;
    const libxl_vnc_info *vnc = libxl__dm_vnc(guest_config);
    const libxl_sdl_info *sdl = dm_sdl(guest_config);
    const char *keymap = dm_keymap(guest_config);
    flexarray_t *dm_args;
    int i;
    uint64_t ram_size;

    dm_args = flexarray_make(gc, 16, 1);

    flexarray_vappend(dm_args, dm,
                      "-xen-domid",
                      libxl__sprintf(gc, "%d", guest_domid), NULL);

    flexarray_append(dm_args, "-chardev");
    flexarray_append(dm_args,
                     libxl__sprintf(gc, "socket,id=libxl-cmd,"
                                    "path=%s/qmp-libxl-%d,server,nowait",
                                    libxl__run_dir_path(), guest_domid));

    flexarray_append(dm_args, "-mon");
    flexarray_append(dm_args, "chardev=libxl-cmd,mode=control");

    /*
     * Remove default devices created by qemu. Qemu will create only devices
     * defined by xen, since the devices not defined by xen are not usable.
     * Remove deleting of empty floppy no more needed with nodefault.
     */
    flexarray_append(dm_args, "-nodefaults");

    if (b_info->type == LIBXL_DOMAIN_TYPE_PV) {
        flexarray_append(dm_args, "-xen-attach");
    }

    if (c_info->name) {
        flexarray_vappend(dm_args, "-name", c_info->name, NULL);
    }

    if (vnc) {
        char *vncarg = NULL;

        flexarray_append(dm_args, "-vnc");

        /*
         * If vnc->listen is present and contains a :, and
         *  - vnc->display is 0, use vnc->listen
         *  - vnc->display is non-zero, be confused
         * If vnc->listen is present but doesn't, use vnc->listen:vnc->display.
         * If vnc->listen is not present, use 127.0.0.1:vnc->display
         * (Remembering that vnc->display already defaults to 0.)
         */
        if (vnc->listen) {
            if (strchr(vnc->listen, ':') != NULL) {
                if (vnc->display) {
                    LOG(ERROR, "vncdisplay set, vnclisten contains display");
                    return NULL;
                }
                vncarg = vnc->listen;
            } else {
                vncarg = libxl__sprintf(gc, "%s:%d", vnc->listen,
                                        vnc->display);
            }
        } else
            vncarg = libxl__sprintf(gc, "127.0.0.1:%d", vnc->display);

        if (vnc->passwd && vnc->passwd[0]) {
            vncarg = libxl__sprintf(gc, "%s,password", vncarg);
        }

        if (libxl_defbool_val(vnc->findunused)) {
            /* This option asks to QEMU to try this number of port before to
             * give up.  So QEMU will try ports between $display and $display +
             * 99.  This option needs to be the last one of the vnc options. */
            vncarg = libxl__sprintf(gc, "%s,to=99", vncarg);
        }

        flexarray_append(dm_args, vncarg);
    } else
        /*
         * Ensure that by default no vnc server is created.
         */
        flexarray_append_pair(dm_args, "-vnc", "none");

    /*
     * Ensure that by default no display backend is created. Further
     * options given below might then enable more.
     */
    flexarray_append_pair(dm_args, "-display", "none");

    if (sdl) {
        flexarray_append(dm_args, "-sdl");
        /* XXX sdl->{display,xauthority} into $DISPLAY/$XAUTHORITY */
    }

    /*if (info->type == LIBXL_DOMAIN_TYPE_PV && !b_info->nographic) {
        flexarray_vappend(dm_args, "-vga", "xenfb", NULL);
      } never was possible?*/

    if (keymap) {
        flexarray_vappend(dm_args, "-k", keymap, NULL);
    }

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        int ioemu_nics = 0;

        if (b_info->u.hvm.serial) {
            flexarray_vappend(dm_args, "-serial", b_info->u.hvm.serial, NULL);
        }

        if (libxl_defbool_val(b_info->u.hvm.nographic) && (!sdl && !vnc)) {
            flexarray_append(dm_args, "-nographic");
        }

        if (libxl_defbool_val(b_info->u.hvm.spice.enable)) {
            const libxl_spice_info *spice = &b_info->u.hvm.spice;
            char *spiceoptions = dm_spice_options(gc, spice);
            if (!spiceoptions)
                return NULL;

            flexarray_append(dm_args, "-spice");
            flexarray_append(dm_args, spiceoptions);
            if (libxl_defbool_val(b_info->u.hvm.spice.vdagent)) {
                flexarray_vappend(dm_args, "-device", "virtio-serial",
                    "-chardev", "spicevmc,id=vdagent,name=vdagent", "-device",
                    "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
                    NULL);
            }
        }

        switch (b_info->u.hvm.vga.kind) {
        case LIBXL_VGA_INTERFACE_TYPE_STD:
            flexarray_append_pair(dm_args, "-device", "VGA");
            break;
        case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            flexarray_append_pair(dm_args, "-device", "cirrus-vga");
            flexarray_append_pair(dm_args, "-global",
                GCSPRINTF("vga.vram_size_mb=%d",
                libxl__sizekb_to_mb(b_info->video_memkb)));
            break;
        }

        if (b_info->u.hvm.boot) {
            flexarray_vappend(dm_args, "-boot",
                    libxl__sprintf(gc, "order=%s", b_info->u.hvm.boot), NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.usb)
            || b_info->u.hvm.usbdevice
            || b_info->u.hvm.usbdevice_list) {
            if ( b_info->u.hvm.usbdevice && b_info->u.hvm.usbdevice_list )
            {
                LOG(ERROR, "%s: Both usbdevice and usbdevice_list set",
                    __func__);
                return NULL;
            }
            flexarray_append(dm_args, "-usb");
            if (b_info->u.hvm.usbdevice) {
                flexarray_vappend(dm_args,
                                  "-usbdevice", b_info->u.hvm.usbdevice, NULL);
            } else if (b_info->u.hvm.usbdevice_list) {
                char **p;
                for (p = b_info->u.hvm.usbdevice_list;
                     *p;
                     p++) {
                    flexarray_vappend(dm_args,
                                      "-usbdevice",
                                      *p, NULL);
                }
            }
        } else if (b_info->u.hvm.usbversion) {
            switch (b_info->u.hvm.usbversion) {
            case 1:
                flexarray_vappend(dm_args,
                    "-device", "piix3-usb-uhci,id=usb", NULL);
                break;
            case 2:
                flexarray_append_pair(dm_args, "-device",
                    "ich9-usb-ehci1,id=usb,addr=0x1d.0x7,multifunction=on");
                for (i = 1; i < 4; i++)
                    flexarray_append_pair(dm_args, "-device",
                        GCSPRINTF("ich9-usb-uhci%d,masterbus=usb.0,"
                        "firstport=%d,addr=0x1d.%#x,multifunction=on",
                        i, 2*(i-1), i-1));
                break;
            case 3:
                flexarray_vappend(dm_args,
                    "-device", "nec-usb-xhci,id=usb", NULL);
                break;
            default:
                LOG(ERROR, "%s: usbversion parameter is invalid, "
                    "must be between 1 and 3", __func__);
                return NULL;
            }
            if (b_info->u.hvm.spice.usbredirection >= 0 &&
                b_info->u.hvm.spice.usbredirection < 5) {
                for (i = 1; i <= b_info->u.hvm.spice.usbredirection; i++)
                    flexarray_vappend(dm_args, "-chardev", libxl__sprintf(gc,
                        "spicevmc,name=usbredir,id=usbrc%d", i), "-device",
                        libxl__sprintf(gc, "usb-redir,chardev=usbrc%d,"
                        "id=usbrc%d", i, i), NULL);
            } else {
                LOG(ERROR, "%s: usbredirection parameter is invalid, "
                    "it must be between 1 and 4", __func__);
                return NULL;
            }
        }
        if (b_info->u.hvm.soundhw) {
            flexarray_vappend(dm_args, "-soundhw", b_info->u.hvm.soundhw, NULL);
        }
        if (!libxl_defbool_val(b_info->u.hvm.acpi)) {
            flexarray_append(dm_args, "-no-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_append(dm_args, "-smp");
            if (b_info->avail_vcpus.size) {
                int nr_set_cpus = 0;
                nr_set_cpus = libxl_bitmap_count_set(&b_info->avail_vcpus);

                flexarray_append(dm_args, libxl__sprintf(gc, "%d,maxcpus=%d",
                                                         nr_set_cpus,
                                                         b_info->max_vcpus));
            } else
                flexarray_append(dm_args, libxl__sprintf(gc, "%d",
                                                         b_info->max_vcpus));
        }
        for (i = 0; i < num_nics; i++) {
            if (nics[i].nictype == LIBXL_NIC_TYPE_VIF_IOEMU) {
                char *smac = libxl__sprintf(gc,
                                LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nics[i].mac));
                const char *ifname = libxl__device_nic_devname(gc,
                                                guest_domid, nics[i].devid,
                                                LIBXL_NIC_TYPE_VIF_IOEMU);
                flexarray_append(dm_args, "-device");
                flexarray_append(dm_args,
                   libxl__sprintf(gc, "%s,id=nic%d,netdev=net%d,mac=%s",
                                                nics[i].model, nics[i].devid,
                                                nics[i].devid, smac));
                flexarray_append(dm_args, "-netdev");
                flexarray_append(dm_args, GCSPRINTF(
                                          "type=tap,id=net%d,ifname=%s,"
                                          "script=%s,downscript=%s",
                                          nics[i].devid, ifname,
                                          libxl_tapif_script(gc),
                                          libxl_tapif_script(gc)));
                ioemu_nics++;
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_nics == 0 ) {
            flexarray_append(dm_args, "-net");
            flexarray_append(dm_args, "none");
        }
        if (libxl_defbool_val(b_info->u.hvm.gfx_passthru)) {
            flexarray_append(dm_args, "-gfx_passthru");
        }
    } else {
        if (!sdl && !vnc) {
            flexarray_append(dm_args, "-nographic");
        }
    }

    if (state->saved_state) {
        /* This file descriptor is meant to be used by QEMU */
        int migration_fd = open(state->saved_state, O_RDONLY);
        flexarray_append(dm_args, "-incoming");
        flexarray_append(dm_args, libxl__sprintf(gc, "fd:%d", migration_fd));
    }
    for (i = 0; b_info->extra && b_info->extra[i] != NULL; i++)
        flexarray_append(dm_args, b_info->extra[i]);

    flexarray_append(dm_args, "-machine");
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PV:
        flexarray_append(dm_args, "xenpv");
        for (i = 0; b_info->extra_pv && b_info->extra_pv[i] != NULL; i++)
            flexarray_append(dm_args, b_info->extra_pv[i]);
        break;
    case LIBXL_DOMAIN_TYPE_HVM:
        if (!libxl_defbool_val(b_info->u.hvm.xen_platform_pci)) {
            /* Switching here to the machine "pc" which does not add
             * the xen-platform device instead of the default "xenfv" machine.
             */
            flexarray_append(dm_args, "pc,accel=xen");
        } else {
            flexarray_append(dm_args, "xenfv");
        }
        for (i = 0; b_info->extra_hvm && b_info->extra_hvm[i] != NULL; i++)
            flexarray_append(dm_args, b_info->extra_hvm[i]);
        break;
    default:
        abort();
    }

    ram_size = libxl__sizekb_to_mb(b_info->max_memkb - b_info->video_memkb);
    flexarray_append(dm_args, "-m");
    flexarray_append(dm_args, libxl__sprintf(gc, "%"PRId64, ram_size));

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
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
                        (gc, "if=ide,index=%d,media=cdrom,cache=writeback,id=ide-%i",
                         disk, dev_number);
                else
                    drive = libxl__sprintf
                        (gc, "file=%s,if=ide,index=%d,media=cdrom,format=%s,cache=writeback,id=ide-%i",
                         disks[i].pdev_path, disk, format, dev_number);
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
                        (gc, "file=%s,if=scsi,bus=0,unit=%d,format=%s,cache=writeback",
                         disks[i].pdev_path, disk, format);
                else if (disk < 4)
                    drive = libxl__sprintf
                        (gc, "file=%s,if=ide,index=%d,media=disk,format=%s,cache=writeback",
                         disks[i].pdev_path, disk, format);
                else
                    continue; /* Do not emulate this disk */
            }

            flexarray_append(dm_args, "-drive");
            flexarray_append(dm_args, drive);
        }

        switch (b_info->u.hvm.vendor_device) {
        case LIBXL_VENDOR_DEVICE_XENSERVER:
            flexarray_append(dm_args, "-device");
            flexarray_append(dm_args, "xen-pvdevice,device-id=0xc000");
            break;
        default:
            break;
        }
    }
    flexarray_append(dm_args, NULL);
    return (char **) flexarray_contents(dm_args);
}

static char ** libxl__build_device_model_args(libxl__gc *gc,
                                        const char *dm, int guest_domid,
                                        const libxl_domain_config *guest_config,
                                        const libxl__domain_build_state *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);

    switch (guest_config->b_info.device_model_version) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        return libxl__build_device_model_args_old(gc, dm,
                                                  guest_domid, guest_config,
                                                  state);
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        return libxl__build_device_model_args_new(gc, dm,
                                                  guest_domid, guest_config,
                                                  state);
    default:
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unknown device model version %d",
                         guest_config->b_info.device_model_version);
        return NULL;
    }
}

static void libxl__dm_vifs_from_hvm_guest_config(libxl__gc *gc,
                                    libxl_domain_config * const guest_config,
                                    libxl_domain_config *dm_config)
{
    int i, nr = guest_config->num_nics;

    GCNEW_ARRAY(dm_config->nics, nr);

    for (i=0; i<nr; i++) {
        dm_config->nics[i] = guest_config->nics[i];
        dm_config->nics[i].nictype = LIBXL_NIC_TYPE_VIF;
        if (dm_config->nics[i].ifname)
            dm_config->nics[i].ifname = GCSPRINTF("%s" TAP_DEVICE_SUFFIX,
                                                  dm_config->nics[i].ifname);
    }

    dm_config->num_nics = nr;
}

static int libxl__vfb_and_vkb_from_hvm_guest_config(libxl__gc *gc,
                                        const libxl_domain_config *guest_config,
                                        libxl_device_vfb *vfb,
                                        libxl_device_vkb *vkb)
{
    const libxl_domain_build_info *b_info = &guest_config->b_info;

    if (b_info->type != LIBXL_DOMAIN_TYPE_HVM)
        return ERROR_INVAL;

    libxl_device_vfb_init(vfb);
    libxl_device_vkb_init(vkb);

    vfb->backend_domid = 0;
    vfb->devid = 0;
    vfb->vnc = b_info->u.hvm.vnc;
    vfb->keymap = b_info->u.hvm.keymap;
    vfb->sdl = b_info->u.hvm.sdl;

    vkb->backend_domid = 0;
    vkb->devid = 0;
    return 0;
}

static int libxl__write_stub_dmargs(libxl__gc *gc,
                                    int dm_domid, int guest_domid,
                                    char **args)
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
    roperm[1].id = dm_domid;
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

static void spawn_stubdom_pvqemu_cb(libxl__egc *egc,
                                libxl__dm_spawn_state *stubdom_dmss,
                                int rc);

static void spawn_stub_launch_dm(libxl__egc *egc,
                                 libxl__multidev *aodevs, int ret);

static void stubdom_pvqemu_cb(libxl__egc *egc,
                              libxl__multidev *aodevs,
                              int rc);

static void spaw_stubdom_pvqemu_destroy_cb(libxl__egc *egc,
                                           libxl__destroy_domid_state *dis,
                                           int rc);

char *libxl__stub_dm_name(libxl__gc *gc, const char *guest_name)
{
    return libxl__sprintf(gc, "%s-dm", guest_name);
}

void libxl__spawn_stub_dm(libxl__egc *egc, libxl__stub_dm_spawn_state *sdss)
{
    STATE_AO_GC(sdss->dm.spawn.ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int ret;
    libxl_device_vfb *vfb;
    libxl_device_vkb *vkb;
    char **args;
    struct xs_permissions perm[2];
    xs_transaction_t t;

    /* convenience aliases */
    libxl_domain_config *const dm_config = &sdss->dm_config;
    libxl_domain_config *const guest_config = sdss->dm.guest_config;
    const int guest_domid = sdss->dm.guest_domid;
    libxl__domain_build_state *const d_state = sdss->dm.build_state;
    libxl__domain_build_state *const stubdom_state = &sdss->dm_state;

    if (guest_config->b_info.device_model_version !=
        LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL) {
        ret = ERROR_INVAL;
        goto out;
    }

    sdss->pvqemu.guest_domid = 0;

    libxl_domain_create_info_init(&dm_config->c_info);
    dm_config->c_info.type = LIBXL_DOMAIN_TYPE_PV;
    dm_config->c_info.name = libxl__stub_dm_name(gc,
                                    libxl__domid_to_name(gc, guest_domid));
    dm_config->c_info.ssidref = guest_config->b_info.device_model_ssidref;

    libxl_uuid_generate(&dm_config->c_info.uuid);

    libxl_domain_build_info_init(&dm_config->b_info);
    libxl_domain_build_info_init_type(&dm_config->b_info, LIBXL_DOMAIN_TYPE_PV);

    dm_config->b_info.max_vcpus = 1;
    dm_config->b_info.max_memkb = 32 * 1024;
    dm_config->b_info.target_memkb = dm_config->b_info.max_memkb;

    dm_config->b_info.u.pv.features = "";

    dm_config->b_info.device_model_version =
        guest_config->b_info.device_model_version;
    dm_config->b_info.device_model =
        guest_config->b_info.device_model;
    dm_config->b_info.extra = guest_config->b_info.extra;
    dm_config->b_info.extra_pv = guest_config->b_info.extra_pv;
    dm_config->b_info.extra_hvm = guest_config->b_info.extra_hvm;

    dm_config->disks = guest_config->disks;
    dm_config->num_disks = guest_config->num_disks;

    libxl__dm_vifs_from_hvm_guest_config(gc, guest_config, dm_config);

    dm_config->c_info.run_hotplug_scripts =
        guest_config->c_info.run_hotplug_scripts;

    ret = libxl__domain_create_info_setdefault(gc, &dm_config->c_info);
    if (ret) goto out;
    ret = libxl__domain_build_info_setdefault(gc, &dm_config->b_info);
    if (ret) goto out;

    GCNEW(vfb);
    GCNEW(vkb);
    libxl__vfb_and_vkb_from_hvm_guest_config(gc, guest_config, vfb, vkb);
    dm_config->vfbs = vfb;
    dm_config->num_vfbs = 1;
    dm_config->vkbs = vkb;
    dm_config->num_vkbs = 1;

    stubdom_state->pv_kernel.path
        = libxl__abs_path(gc, "ioemu-stubdom.gz", libxl__xenfirmwaredir_path());
    stubdom_state->pv_cmdline = libxl__sprintf(gc, " -d %d", guest_domid);
    stubdom_state->pv_ramdisk.path = "";

    /* fixme: this function can leak the stubdom if it fails */
    ret = libxl__domain_make(gc, &dm_config->c_info, &sdss->pvqemu.guest_domid);
    if (ret)
        goto out;
    uint32_t dm_domid = sdss->pvqemu.guest_domid;
    ret = libxl__domain_build(gc, dm_config, dm_domid, stubdom_state);
    if (ret)
        goto out;

    args = libxl__build_device_model_args(gc, "stubdom-dm", guest_domid,
                                          guest_config, d_state);
    if (!args) {
        ret = ERROR_FAIL;
        goto out;
    }

    libxl__write_stub_dmargs(gc, dm_domid, guest_domid, args);
    libxl__xs_write(gc, XBT_NULL,
                   libxl__sprintf(gc, "%s/image/device-model-domid",
                                  libxl__xs_get_dompath(gc, guest_domid)),
                   "%d", dm_domid);
    libxl__xs_write(gc, XBT_NULL,
                   libxl__sprintf(gc, "%s/target",
                                  libxl__xs_get_dompath(gc, dm_domid)),
                   "%d", guest_domid);
    ret = xc_domain_set_target(ctx->xch, dm_domid, guest_domid);
    if (ret<0) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                         "setting target domain %d -> %d",
                         dm_domid, guest_domid);
        ret = ERROR_FAIL;
        goto out;
    }
    xs_set_target(ctx->xsh, dm_domid, guest_domid);

    perm[0].id = dm_domid;
    perm[0].perms = XS_PERM_NONE;
    perm[1].id = guest_domid;
    perm[1].perms = XS_PERM_READ;
retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_mkdir(ctx->xsh, t,
        libxl__sprintf(gc, "/local/domain/0/device-model/%d", guest_domid));
    xs_set_permissions(ctx->xsh, t,
        libxl__sprintf(gc, "/local/domain/0/device-model/%d", guest_domid),
                       perm, ARRAY_SIZE(perm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    libxl__multidev_begin(ao, &sdss->multidev);
    sdss->multidev.callback = spawn_stub_launch_dm;
    libxl__add_disks(egc, ao, dm_domid, dm_config, &sdss->multidev);
    libxl__multidev_prepared(egc, &sdss->multidev, 0);

    return;

out:
    assert(ret);
    spawn_stubdom_pvqemu_cb(egc, &sdss->pvqemu, ret);
}

static void spawn_stub_launch_dm(libxl__egc *egc,
                                 libxl__multidev *multidev, int ret)
{
    libxl__stub_dm_spawn_state *sdss = CONTAINER_OF(multidev, *sdss, multidev);
    STATE_AO_GC(sdss->dm.spawn.ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int i, num_console = STUBDOM_SPECIAL_CONSOLES;
    libxl__device_console *console;

    /* convenience aliases */
    libxl_domain_config *const dm_config = &sdss->dm_config;
    libxl_domain_config *const guest_config = sdss->dm.guest_config;
    const int guest_domid = sdss->dm.guest_domid;
    libxl__domain_build_state *const d_state = sdss->dm.build_state;
    libxl__domain_build_state *const stubdom_state = &sdss->dm_state;
    uint32_t dm_domid = sdss->pvqemu.guest_domid;

    if (ret) {
        LOG(ERROR, "error connecting disk devices");
        goto out;
     }

    for (i = 0; i < dm_config->num_nics; i++) {
         /* We have to init the nic here, because we still haven't
         * called libxl_device_nic_add at this point, but qemu needs
         * the nic information to be complete.
         */
        ret = libxl__device_nic_setdefault(gc, &dm_config->nics[i], dm_domid);
        if (ret)
            goto out;
    }
    ret = libxl__device_vfb_add(gc, dm_domid, &dm_config->vfbs[0]);
    if (ret)
        goto out;
    ret = libxl__device_vkb_add(gc, dm_domid, &dm_config->vkbs[0]);
    if (ret)
        goto out;

    if (guest_config->b_info.u.hvm.serial)
        num_console++;

    console = libxl__calloc(gc, num_console, sizeof(libxl__device_console));
    if (!console) {
        ret = ERROR_NOMEM;
        goto out;
    }

    for (i = 0; i < num_console; i++) {
        console[i].devid = i;
        console[i].consback = LIBXL__CONSOLE_BACKEND_IOEMU;
        /* STUBDOM_CONSOLE_LOGGING (console 0) is for minios logging
         * STUBDOM_CONSOLE_SAVE (console 1) is for writing the save file
         * STUBDOM_CONSOLE_RESTORE (console 2) is for reading the save file
         */
        switch (i) {
            char *filename;
            char *name;
            case STUBDOM_CONSOLE_LOGGING:
                name = libxl__sprintf(gc, "qemu-dm-%s",
                                      libxl_domid_to_name(ctx, guest_domid));
                libxl_create_logfile(ctx, name, &filename);
                console[i].output = libxl__sprintf(gc, "file:%s", filename);
                free(filename);
                break;
            case STUBDOM_CONSOLE_SAVE:
                console[i].output = libxl__sprintf(gc, "file:%s",
                                libxl__device_model_savefile(gc, guest_domid));
                break;
            case STUBDOM_CONSOLE_RESTORE:
                if (d_state->saved_state)
                    console[i].output =
                        libxl__sprintf(gc, "pipe:%s", d_state->saved_state);
                break;
            default:
                console[i].output = "pty";
                break;
        }
        ret = libxl__device_console_add(gc, dm_domid, &console[i],
                        i == STUBDOM_CONSOLE_LOGGING ? stubdom_state : NULL);
        if (ret)
            goto out;
    }

    sdss->pvqemu.spawn.ao = ao;
    sdss->pvqemu.guest_domid = dm_domid;
    sdss->pvqemu.guest_config = &sdss->dm_config;
    sdss->pvqemu.build_state = &sdss->dm_state;
    sdss->pvqemu.callback = spawn_stubdom_pvqemu_cb;

    libxl__spawn_local_dm(egc, &sdss->pvqemu);

    return;

out:
    assert(ret);
    spawn_stubdom_pvqemu_cb(egc, &sdss->pvqemu, ret);
}

static void spawn_stubdom_pvqemu_cb(libxl__egc *egc,
                                libxl__dm_spawn_state *stubdom_dmss,
                                int rc)
{
    libxl__stub_dm_spawn_state *sdss =
        CONTAINER_OF(stubdom_dmss, *sdss, pvqemu);
    STATE_AO_GC(sdss->dm.spawn.ao);
    uint32_t dm_domid = sdss->pvqemu.guest_domid;
    libxl_domain_config *d_config = stubdom_dmss->guest_config;

    if (rc) goto out;

    if (d_config->num_nics > 0) {
        libxl__multidev_begin(ao, &sdss->multidev);
        sdss->multidev.callback = stubdom_pvqemu_cb;
        libxl__add_nics(egc, ao, dm_domid, d_config, &sdss->multidev);
        libxl__multidev_prepared(egc, &sdss->multidev, 0);
        return;
    }

out:
    stubdom_pvqemu_cb(egc, &sdss->multidev, rc);
}

static void stubdom_pvqemu_cb(libxl__egc *egc,
                              libxl__multidev *multidev,
                              int rc)
{
    libxl__stub_dm_spawn_state *sdss = CONTAINER_OF(multidev, *sdss, multidev);
    STATE_AO_GC(sdss->dm.spawn.ao);
    uint32_t dm_domid = sdss->pvqemu.guest_domid;

    if (rc) {
        LOGE(ERROR, "error connecting nics devices");
        goto out;
    }

    rc = libxl_domain_unpause(CTX, dm_domid);
    if (rc) goto out;

 out:
    if (rc) {
        if (dm_domid) {
            sdss->dis.ao = ao;
            sdss->dis.domid = dm_domid;
            sdss->dis.callback = spaw_stubdom_pvqemu_destroy_cb;
            libxl__destroy_domid(egc, &sdss->dis);
            return;
        }
    }
    sdss->callback(egc, &sdss->dm, rc);
}

static void spaw_stubdom_pvqemu_destroy_cb(libxl__egc *egc,
                                           libxl__destroy_domid_state *dis,
                                           int rc)
{
    libxl__stub_dm_spawn_state *sdss = CONTAINER_OF(dis, *sdss, dis);
    STATE_AO_GC(sdss->dis.ao);

    if (rc)
        LOG(ERROR, "destruction of domain %u after failed creation failed",
                   sdss->pvqemu.guest_domid);

    sdss->callback(egc, &sdss->dm, rc);
}

/* callbacks passed to libxl__spawn_spawn */
static void device_model_confirm(libxl__egc *egc, libxl__spawn_state *spawn,
                                 const char *xsdata);
static void device_model_startup_failed(libxl__egc *egc,
                                        libxl__spawn_state *spawn);
static void device_model_detached(libxl__egc *egc,
                                  libxl__spawn_state *spawn);

/* our "next step" function, called from those callbacks and elsewhere */
static void device_model_spawn_outcome(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int rc);

void libxl__spawn_local_dm(libxl__egc *egc, libxl__dm_spawn_state *dmss)
{
    /* convenience aliases */
    const int domid = dmss->guest_domid;
    libxl__domain_build_state *const state = dmss->build_state;
    libxl__spawn_state *const spawn = &dmss->spawn;

    STATE_AO_GC(dmss->spawn.ao);

    libxl_ctx *ctx = CTX;
    libxl_domain_config *guest_config = dmss->guest_config;
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_vnc_info *vnc = libxl__dm_vnc(guest_config);
    char *path;
    int logfile_w, null;
    int rc;
    char **args, **arg;
    xs_transaction_t t;
    char *vm_path;
    char **pass_stuff;
    const char *dm;

    if (libxl_defbool_val(b_info->device_model_stubdomain)) {
        abort();
    }

    dm = libxl__domain_device_model(gc, b_info);
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
    args = libxl__build_device_model_args(gc, dm, domid, guest_config, state);
    if (!args) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        path = xs_get_domain_path(ctx->xsh, domid);
        libxl__xs_write(gc, XBT_NULL,
                        libxl__sprintf(gc, "%s/hvmloader/bios", path),
                        "%s", libxl_bios_type_to_string(b_info->u.hvm.bios));
        /* Disable relocating memory to make the MMIO hole larger
         * unless we're running qemu-traditional */
        libxl__xs_write(gc, XBT_NULL,
                        libxl__sprintf(gc,
                                       "%s/hvmloader/allow-memory-relocate",
                                       path),
                        "%d",
                        b_info->device_model_version==LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL);
        free(path);
    }

    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d", domid);
    xs_mkdir(ctx->xsh, XBT_NULL, path);

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM &&
        b_info->device_model_version
        == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL)
        libxl__xs_write(gc, XBT_NULL, libxl__sprintf(gc, "%s/disable_pf", path),
                    "%d", !libxl_defbool_val(b_info->u.hvm.xen_platform_pci));

    logfile_w = libxl__create_qemu_logfile(gc, GCSPRINTF("qemu-dm-%s",
                                                         c_info->name));
    if (logfile_w < 0) {
        rc = logfile_w;
        goto out;
    }
    null = open("/dev/null", O_RDONLY);
    if (null < 0) {
        LOGE(ERROR, "unable to open /dev/null");
        rc = ERROR_FAIL;
        goto out_close;
    }

    const char *dom_path = libxl__xs_get_dompath(gc, domid);
    spawn->pidpath = GCSPRINTF("%s/%s", dom_path, "image/device-model-pid");

    if (vnc && vnc->passwd) {
        /* This xenstore key will only be used by qemu-xen-traditionnal.
         * The code to supply vncpasswd to qemu-xen is later. */
retry_transaction:
        /* Find uuid and the write the vnc password to xenstore for qemu. */
        t = xs_transaction_start(ctx->xsh);
        vm_path = libxl__xs_read(gc,t,libxl__sprintf(gc, "%s/vm", dom_path));
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

    LIBXL__LOG(CTX, XTL_DEBUG, "Spawning device-model %s with arguments:", dm);
    for (arg = args; *arg; arg++)
        LIBXL__LOG(CTX, XTL_DEBUG, "  %s", *arg);

    spawn->what = GCSPRINTF("domain %d device model", domid);
    spawn->xspath = GCSPRINTF("/local/domain/0/device-model/%d/state", domid);
    spawn->timeout_ms = LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000;
    spawn->pidpath = GCSPRINTF("%s/image/device-model-pid", dom_path);
    spawn->midproc_cb = libxl__spawn_record_pid;
    spawn->confirm_cb = device_model_confirm;
    spawn->failure_cb = device_model_startup_failed;
    spawn->detached_cb = device_model_detached;

    rc = libxl__spawn_spawn(egc, spawn);
    if (rc < 0)
        goto out_close;
    if (!rc) { /* inner child */
        setsid();
        libxl__exec(gc, null, logfile_w, logfile_w, dm, args, NULL);
    }

    rc = 0;

out_close:
    if (null >= 0) close(null);
    if (logfile_w >= 0) close(logfile_w);
out:
    if (rc)
        device_model_spawn_outcome(egc, dmss, rc);
}


static void device_model_confirm(libxl__egc *egc, libxl__spawn_state *spawn,
                                 const char *xsdata)
{
    STATE_AO_GC(spawn->ao);

    if (!xsdata)
        return;

    if (strcmp(xsdata, "running"))
        return;

    libxl__spawn_initiate_detach(gc, spawn);
}

static void device_model_startup_failed(libxl__egc *egc,
                                        libxl__spawn_state *spawn)
{
    libxl__dm_spawn_state *dmss = CONTAINER_OF(spawn, *dmss, spawn);
    device_model_spawn_outcome(egc, dmss, ERROR_FAIL);
}

static void device_model_detached(libxl__egc *egc,
                                  libxl__spawn_state *spawn)
{
    libxl__dm_spawn_state *dmss = CONTAINER_OF(spawn, *dmss, spawn);
    device_model_spawn_outcome(egc, dmss, 0);
}

static void device_model_spawn_outcome(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int rc)
{
    STATE_AO_GC(dmss->spawn.ao);
    int ret2;

    if (rc)
        LOG(ERROR, "%s: spawn failed (rc=%d)", dmss->spawn.what, rc);

    libxl__domain_build_state *state = dmss->build_state;

    if (state->saved_state) {
        ret2 = unlink(state->saved_state);
        if (ret2) {
            LOGE(ERROR, "%s: failed to remove device-model state %s",
                 dmss->spawn.what, state->saved_state);
            rc = ERROR_FAIL;
            goto out;
        }
    }

 out:
    dmss->callback(egc, dmss, rc);
}

void libxl__spawn_qdisk_backend(libxl__egc *egc, libxl__dm_spawn_state *dmss)
{
    STATE_AO_GC(dmss->spawn.ao);
    flexarray_t *dm_args;
    char **args;
    const char *dm;
    int logfile_w, null, rc;
    uint32_t domid = dmss->guest_domid;

    /* Always use qemu-xen as device model */
    dm = qemu_xen_path(gc);

    dm_args = flexarray_make(gc, 15, 1);
    flexarray_vappend(dm_args, dm, "-xen-domid",
                      GCSPRINTF("%d", domid), NULL);
    flexarray_append(dm_args, "-xen-attach");
    flexarray_vappend(dm_args, "-name",
                      GCSPRINTF("domain-%u", domid), NULL);
    flexarray_append(dm_args, "-nographic");
    flexarray_vappend(dm_args, "-M", "xenpv", NULL);
    flexarray_vappend(dm_args, "-monitor", "/dev/null", NULL);
    flexarray_vappend(dm_args, "-serial", "/dev/null", NULL);
    flexarray_vappend(dm_args, "-parallel", "/dev/null", NULL);
    flexarray_append(dm_args, NULL);
    args = (char **) flexarray_contents(dm_args);

    logfile_w = libxl__create_qemu_logfile(gc, GCSPRINTF("qdisk-%u", domid));
    if (logfile_w < 0) {
        rc = logfile_w;
        goto error;
    }
    null = open("/dev/null", O_RDONLY);

    dmss->guest_config = NULL;
    /*
     * Clearly specify Qemu not using a saved state, so
     * device_model_spawn_outcome doesn't try to unlink it.
     */
    dmss->build_state = libxl__zalloc(gc, sizeof(*dmss->build_state));
    dmss->build_state->saved_state = 0;

    dmss->spawn.what = GCSPRINTF("domain %u Qdisk backend", domid);
    dmss->spawn.xspath = GCSPRINTF("device-model/%u/state", domid);
    dmss->spawn.timeout_ms = LIBXL_DEVICE_MODEL_START_TIMEOUT * 1000;
    /*
     * We cannot save Qemu pid anywhere in the xenstore guest dir,
     * because we will call this from unprivileged driver domains,
     * so save it in the current domain libxl private dir.
     */
    dmss->spawn.pidpath = GCSPRINTF("libxl/%u/qdisk-backend-pid", domid);
    dmss->spawn.midproc_cb = libxl__spawn_record_pid;
    dmss->spawn.confirm_cb = device_model_confirm;
    dmss->spawn.failure_cb = device_model_startup_failed;
    dmss->spawn.detached_cb = device_model_detached;
    rc = libxl__spawn_spawn(egc, &dmss->spawn);
    if (rc < 0)
        goto error;
    if (!rc) { /* inner child */
        setsid();
        libxl__exec(gc, null, logfile_w, logfile_w, dm, args, NULL);
    }

    return;

error:
    assert(rc);
    dmss->callback(egc, dmss, rc);
    return;
}

/* Generic function to signal a Qemu instance to exit */
static int kill_device_model(libxl__gc *gc, const char *xs_path_pid)
{
    const char *xs_pid;
    int ret, pid;

    ret = libxl__xs_read_checked(gc, XBT_NULL, xs_path_pid, &xs_pid);
    if (ret || !xs_pid) {
        LOG(ERROR, "unable to find device model pid in %s", xs_path_pid);
        ret = ret ? : ERROR_FAIL;
        goto out;
    }
    pid = atoi(xs_pid);

    ret = kill(pid, SIGHUP);
    if (ret < 0 && errno == ESRCH) {
        LOG(ERROR, "Device Model already exited");
        ret = 0;
    } else if (ret == 0) {
        LOG(DEBUG, "Device Model signaled");
        ret = 0;
    } else {
        LOGE(ERROR, "failed to kill Device Model [%d]", pid);
        ret = ERROR_FAIL;
        goto out;
    }

out:
    return ret;
}

/* Helper to destroy a Qdisk backend */
int libxl__destroy_qdisk_backend(libxl__gc *gc, uint32_t domid)
{
    char *pid_path;
    int rc;

    pid_path = GCSPRINTF("libxl/%u/qdisk-backend-pid", domid);

    rc = kill_device_model(gc, pid_path);
    if (rc)
        goto out;

    libxl__xs_rm_checked(gc, XBT_NULL, pid_path);
    libxl__xs_rm_checked(gc, XBT_NULL,
                         GCSPRINTF("device-model/%u", domid));

out:
    return rc;
}

int libxl__destroy_device_model(libxl__gc *gc, uint32_t domid)
{
    return kill_device_model(gc,
                GCSPRINTF("/local/domain/%d/image/device-model-pid", domid));
}

int libxl__need_xenpv_qemu(libxl__gc *gc,
        int nr_consoles, libxl__device_console *consoles,
        int nr_vfbs, libxl_device_vfb *vfbs,
        int nr_disks, libxl_device_disk *disks)
{
    int i, ret = 0;
    uint32_t domid;

    /*
     * qemu is required in order to support 2 or more consoles. So switch all
     * backends to qemu if this is the case
     */
    if (nr_consoles > 1) {
        for (i = 0; i < nr_consoles; i++)
            consoles[i].consback = LIBXL__CONSOLE_BACKEND_IOEMU;
        ret = 1;
        goto out;
    }

    for (i = 0; i < nr_consoles; i++) {
        if (consoles[i].consback == LIBXL__CONSOLE_BACKEND_IOEMU) {
            ret = 1;
            goto out;
        }
    }

    if (nr_vfbs > 0) {
        ret = 1;
        goto out;
    }

    if (nr_disks > 0) {
        ret = libxl__get_domid(gc, &domid);
        if (ret) goto out;
        for (i = 0; i < nr_disks; i++) {
            if (disks[i].backend == LIBXL_DISK_BACKEND_QDISK &&
                disks[i].backend_domid == domid) {
                ret = 1;
                goto out;
            }
        }
    }

out:
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
