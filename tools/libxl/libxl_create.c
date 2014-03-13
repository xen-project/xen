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
#include "libxl_arch.h"

#include <xc_dom.h>
#include <xenguest.h>
#include <xen/hvm/hvm_info_table.h>

int libxl__domain_create_info_setdefault(libxl__gc *gc,
                                         libxl_domain_create_info *c_info)
{
    if (!c_info->type)
        return ERROR_INVAL;

    if (c_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        libxl_defbool_setdefault(&c_info->hap, true);
        libxl_defbool_setdefault(&c_info->oos, true);
    } else {
        libxl_defbool_setdefault(&c_info->pvh, false);
        libxl_defbool_setdefault(&c_info->hap, libxl_defbool_val(c_info->pvh));
    }

    libxl_defbool_setdefault(&c_info->run_hotplug_scripts, true);
    libxl_defbool_setdefault(&c_info->driver_domain, false);

    return 0;
}

static int sched_params_valid(libxl__gc *gc,
                              uint32_t domid, libxl_domain_sched_params *scp)
{
    int has_weight = scp->weight != LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT;
    int has_period = scp->period != LIBXL_DOMAIN_SCHED_PARAM_PERIOD_DEFAULT;
    int has_slice = scp->slice != LIBXL_DOMAIN_SCHED_PARAM_SLICE_DEFAULT;
    int has_extratime =
                scp->extratime != LIBXL_DOMAIN_SCHED_PARAM_EXTRATIME_DEFAULT;

    /* The sedf scheduler needs some more consistency checking */
    if (libxl__domain_scheduler(gc, domid) == LIBXL_SCHEDULER_SEDF) {
        if (has_weight && (has_period || has_slice))
            return 0;
        /* If you want a real-time domain, with its own period and
         * slice, please, do provide both! */
        if (has_period != has_slice)
            return 0;

        /*
         * Idea is, if we specify a weight, then both period and
         * slice has to be zero. OTOH, if we do specify a period and
         * slice, it is weight that should be zeroed. See
         * docs/misc/sedf_scheduler_mini-HOWTO.txt for more details
         * on the meaningful combinations and their meanings.
         */
        if (has_weight) {
            scp->slice = 0;
            scp->period = 0;
        }
        else if (!has_period) {
            /* No weight nor slice/period means best effort. Parameters needs
             * some mangling in order to properly ask for that, though. */

            /*
             * Providing no weight does not make any sense if we do not allow
             * the domain to run in extra time. On the other hand, if we have
             * extra time, weight will be ignored (and zeroed) by Xen, but it
             * can't be zero here, or the call for setting the scheduling
             * parameters will fail. So, avoid the latter by setting a random
             * weight (namely, 1), as it will be ignored anyway.
             */

            /* We can setup a proper best effort domain (extra time only)
             * iff we either already have or are asking for some extra time. */
            scp->weight = has_extratime ? scp->extratime : 1;
            scp->period = 0;
        } else {
            /* Real-time domain: will get slice CPU time over every period */
            scp->weight = 0;
        }
    }

    return 1;
}

int libxl__domain_build_info_setdefault(libxl__gc *gc,
                                        libxl_domain_build_info *b_info)
{
    if (b_info->type != LIBXL_DOMAIN_TYPE_HVM &&
        b_info->type != LIBXL_DOMAIN_TYPE_PV)
        return ERROR_INVAL;

    libxl_defbool_setdefault(&b_info->device_model_stubdomain, false);

    if (!b_info->device_model_version) {
        if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
            if (libxl_defbool_val(b_info->device_model_stubdomain)) {
                b_info->device_model_version =
                    LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
            } else {
                b_info->device_model_version = libxl__default_device_model(gc);
            }
        } else {
            b_info->device_model_version =
                LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
        }
        if (b_info->device_model_version
                == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
            const char *dm;
            int rc;

            dm = libxl__domain_device_model(gc, b_info);
            rc = access(dm, X_OK);
            if (rc < 0) {
                /* qemu-xen unavailable, use qemu-xen-traditional */
                if (errno == ENOENT) {
                    LIBXL__LOG_ERRNO(CTX, XTL_VERBOSE, "qemu-xen is unavailable"
                                     ", use qemu-xen-traditional instead");
                    b_info->device_model_version =
                        LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
                } else {
                    LIBXL__LOG_ERRNO(CTX, XTL_ERROR, "qemu-xen access error");
                    return ERROR_FAIL;
                }
            }
        }
    }

    if (b_info->blkdev_start == NULL)
        b_info->blkdev_start = libxl__strdup(NOGC, "xvda");

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        if (!b_info->u.hvm.bios)
            switch (b_info->device_model_version) {
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
                b_info->u.hvm.bios = LIBXL_BIOS_TYPE_ROMBIOS; break;
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
                b_info->u.hvm.bios = LIBXL_BIOS_TYPE_SEABIOS; break;
            default:return ERROR_INVAL;
            }

        /* Enforce BIOS<->Device Model version relationship */
        switch (b_info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            if (b_info->u.hvm.bios != LIBXL_BIOS_TYPE_ROMBIOS)
                return ERROR_INVAL;
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            if (b_info->u.hvm.bios == LIBXL_BIOS_TYPE_ROMBIOS)
                return ERROR_INVAL;
            break;
        default:abort();
        }
    }

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM &&
        b_info->device_model_version !=
            LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL &&
        libxl_defbool_val(b_info->device_model_stubdomain)) {
        LIBXL__LOG(CTX, XTL_ERROR,
            "device model stubdomains require \"qemu-xen-traditional\"");
        return ERROR_INVAL;
    }

    if (!b_info->max_vcpus)
        b_info->max_vcpus = 1;
    if (!b_info->avail_vcpus.size) {
        if (libxl_cpu_bitmap_alloc(CTX, &b_info->avail_vcpus, 1))
            return ERROR_FAIL;
        libxl_bitmap_set(&b_info->avail_vcpus, 0);
    } else if (b_info->avail_vcpus.size > HVM_MAX_VCPUS)
        return ERROR_FAIL;

    if (!b_info->cpumap.size) {
        if (libxl_cpu_bitmap_alloc(CTX, &b_info->cpumap, 0))
            return ERROR_FAIL;
        libxl_bitmap_set_any(&b_info->cpumap);
    }

    libxl_defbool_setdefault(&b_info->numa_placement, true);

    if (!b_info->nodemap.size) {
        if (libxl_node_bitmap_alloc(CTX, &b_info->nodemap, 0))
            return ERROR_FAIL;
        libxl_bitmap_set_any(&b_info->nodemap);
    }

    if (b_info->max_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->max_memkb = 32 * 1024;
    if (b_info->target_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->target_memkb = b_info->max_memkb;

    libxl_defbool_setdefault(&b_info->claim_mode, false);

    libxl_defbool_setdefault(&b_info->localtime, false);

    libxl_defbool_setdefault(&b_info->disable_migrate, false);

    if (!b_info->event_channels)
        b_info->event_channels = 1023;

    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        if (b_info->shadow_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->shadow_memkb = 0;

        if (!b_info->u.hvm.vga.kind)
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_CIRRUS;

        switch (b_info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            switch (b_info->u.hvm.vga.kind) {
            case LIBXL_VGA_INTERFACE_TYPE_NONE:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 0;
                break;
            case LIBXL_VGA_INTERFACE_TYPE_STD:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 8 * 1024;
                if (b_info->video_memkb < 8 * 1024) {
                    LOG(ERROR, "videoram must be at least 8 MB for STDVGA on QEMU_XEN_TRADITIONAL");
                    return ERROR_INVAL;
                }
                break;
            case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            default:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 4 * 1024;
                if (b_info->video_memkb != 4 * 1024)
                    LOG(WARN, "ignoring videoram other than 4 MB for CIRRUS on QEMU_XEN_TRADITIONAL");
                break;
            }
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        default:
            switch (b_info->u.hvm.vga.kind) {
            case LIBXL_VGA_INTERFACE_TYPE_NONE:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 0;
                break;
            case LIBXL_VGA_INTERFACE_TYPE_STD:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 16 * 1024;
                if (b_info->video_memkb < 16 * 1024) {
                    LOG(ERROR, "videoram must be at least 16 MB for STDVGA on QEMU_XEN");
                    return ERROR_INVAL;
                }
                break;
            case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            default:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 8 * 1024;
                if (b_info->video_memkb < 8 * 1024) {
                    LOG(ERROR, "videoram must be at least 8 MB for CIRRUS on QEMU_XEN");
                    return ERROR_INVAL;
                }
                break;
            }
            break;
        }

        if (b_info->u.hvm.timer_mode == LIBXL_TIMER_MODE_DEFAULT)
            b_info->u.hvm.timer_mode =
                LIBXL_TIMER_MODE_NO_DELAY_FOR_MISSED_TICKS;

        libxl_defbool_setdefault(&b_info->u.hvm.pae,                true);
        libxl_defbool_setdefault(&b_info->u.hvm.apic,               true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi,               true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi_s3,            true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi_s4,            true);
        libxl_defbool_setdefault(&b_info->u.hvm.nx,                 true);
        libxl_defbool_setdefault(&b_info->u.hvm.viridian,           false);
        libxl_defbool_setdefault(&b_info->u.hvm.hpet,               true);
        libxl_defbool_setdefault(&b_info->u.hvm.vpt_align,          true);
        libxl_defbool_setdefault(&b_info->u.hvm.nested_hvm,         false);
        libxl_defbool_setdefault(&b_info->u.hvm.usb,                false);
        libxl_defbool_setdefault(&b_info->u.hvm.xen_platform_pci,   true);

        if (!b_info->u.hvm.usbversion &&
            (b_info->u.hvm.spice.usbredirection > 0) )
            b_info->u.hvm.usbversion = 2;

        if ((b_info->u.hvm.usbversion || b_info->u.hvm.spice.usbredirection) &&
            ( libxl_defbool_val(b_info->u.hvm.usb)
            || b_info->u.hvm.usbdevice_list
            || b_info->u.hvm.usbdevice) ){
            LOG(ERROR,"usbversion and/or usbredirection cannot be "
            "enabled with usb and/or usbdevice parameters.");
            return ERROR_INVAL;
        }

        if (!b_info->u.hvm.boot) {
            b_info->u.hvm.boot = strdup("cda");
            if (!b_info->u.hvm.boot) return ERROR_NOMEM;
        }

        libxl_defbool_setdefault(&b_info->u.hvm.vnc.enable, true);
        if (libxl_defbool_val(b_info->u.hvm.vnc.enable)) {
            libxl_defbool_setdefault(&b_info->u.hvm.vnc.findunused, true);
            if (!b_info->u.hvm.vnc.listen) {
                b_info->u.hvm.vnc.listen = strdup("127.0.0.1");
                if (!b_info->u.hvm.vnc.listen) return ERROR_NOMEM;
            }
        }

        libxl_defbool_setdefault(&b_info->u.hvm.sdl.enable, false);
        if (libxl_defbool_val(b_info->u.hvm.sdl.enable)) {
            libxl_defbool_setdefault(&b_info->u.hvm.sdl.opengl, false);
        }

        libxl_defbool_setdefault(&b_info->u.hvm.spice.enable, false);
        if (libxl_defbool_val(b_info->u.hvm.spice.enable)) {
            libxl_defbool_setdefault(&b_info->u.hvm.spice.disable_ticketing,
                                     false);
            libxl_defbool_setdefault(&b_info->u.hvm.spice.agent_mouse, true);
            libxl_defbool_setdefault(&b_info->u.hvm.spice.vdagent, false);
            libxl_defbool_setdefault(&b_info->u.hvm.spice.clipboard_sharing,
                                     false);
        }

        libxl_defbool_setdefault(&b_info->u.hvm.nographic, false);

        libxl_defbool_setdefault(&b_info->u.hvm.gfx_passthru, false);

        break;
    case LIBXL_DOMAIN_TYPE_PV:
        libxl_defbool_setdefault(&b_info->u.pv.e820_host, false);
        if (b_info->shadow_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->shadow_memkb = 0;
        if (b_info->u.pv.slack_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->u.pv.slack_memkb = 0;
        break;
    default:
        LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                   "invalid domain type %s in create info",
                   libxl_domain_type_to_string(b_info->type));
        return ERROR_INVAL;
    }
    return 0;
}

static int init_console_info(libxl__device_console *console, int dev_num)
{
    memset(console, 0x00, sizeof(libxl__device_console));
    console->devid = dev_num;
    console->consback = LIBXL__CONSOLE_BACKEND_XENCONSOLED;
    console->output = strdup("pty");
    if (!console->output)
        return ERROR_NOMEM;
    return 0;
}

int libxl__domain_build(libxl__gc *gc,
                        libxl_domain_config *d_config,
                        uint32_t domid,
                        libxl__domain_build_state *state)
{
    libxl_domain_build_info *const info = &d_config->b_info;
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, ret;

    ret = libxl__build_pre(gc, domid, d_config, state);
    if (ret)
        goto out;

    gettimeofday(&start_time, NULL);

    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        ret = libxl__build_hvm(gc, domid, info, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);

        localents = libxl__calloc(gc, 7, sizeof(char *));
        localents[0] = "platform/acpi";
        localents[1] = libxl_defbool_val(info->u.hvm.acpi) ? "1" : "0";
        localents[2] = "platform/acpi_s3";
        localents[3] = libxl_defbool_val(info->u.hvm.acpi_s3) ? "1" : "0";
        localents[4] = "platform/acpi_s4";
        localents[5] = libxl_defbool_val(info->u.hvm.acpi_s4) ? "1" : "0";

        break;
    case LIBXL_DOMAIN_TYPE_PV:
        state->pvh_enabled = libxl_defbool_val(d_config->c_info.pvh);

        ret = libxl__build_pv(gc, domid, info, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char *) state->pv_kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (state->pv_ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char *) state->pv_ramdisk.path;
        }
        if (state->pv_cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char *) state->pv_cmdline;
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

int libxl__domain_make(libxl__gc *gc, libxl_domain_create_info *info,
                       uint32_t *domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int flags, ret, rc, nb_vm;
    char *uuid_string;
    char *dom_path, *vm_path, *libxl_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    struct xs_permissions noperm[1];
    xs_transaction_t t = 0;
    xen_domain_handle_t handle;
    libxl_vminfo *vm_list;


    assert(!libxl_domid_valid_guest(*domid));

    uuid_string = libxl__uuid2string(gc, info->uuid);
    if (!uuid_string) {
        rc = ERROR_NOMEM;
        goto out;
    }

    flags = 0;
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        flags |= XEN_DOMCTL_CDF_hvm_guest;
        flags |= libxl_defbool_val(info->hap) ? XEN_DOMCTL_CDF_hap : 0;
        flags |= libxl_defbool_val(info->oos) ? 0 : XEN_DOMCTL_CDF_oos_off;
    } else if (libxl_defbool_val(info->pvh)) {
        flags |= XEN_DOMCTL_CDF_pvh_guest;
        if (!libxl_defbool_val(info->hap)) {
            LOG(ERROR, "HAP must be on for PVH");
            rc = ERROR_INVAL;
            goto out;
        }
        flags |= XEN_DOMCTL_CDF_hap;
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

    libxl_path = libxl__xs_libxl_path(gc, *domid);
    if (!libxl_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    noperm[0].id = 0;
    noperm[0].perms = XS_PERM_NONE;

    roperm[0].id = 0;
    roperm[0].perms = XS_PERM_NONE;
    roperm[1].id = *domid;
    roperm[1].perms = XS_PERM_READ;

    rwperm[0].id = *domid;
    rwperm[0].perms = XS_PERM_NONE;

retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    xs_rm(ctx->xsh, t, dom_path);
    libxl__xs_mkdir(gc, t, dom_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, vm_path);
    libxl__xs_mkdir(gc, t, vm_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, libxl_path);
    libxl__xs_mkdir(gc, t, libxl_path, noperm, ARRAY_SIZE(noperm));

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl__domain_rename(gc, *domid, 0, info->name, t);
    if (rc)
        goto out;

    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/cpu", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/memory", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/device", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/control", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    if (info->type == LIBXL_DOMAIN_TYPE_HVM)
        libxl__xs_mkdir(gc, t,
                        libxl__sprintf(gc, "%s/hvmloader", dom_path),
                        roperm, ARRAY_SIZE(roperm));

    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/control/shutdown", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/device/suspend/event-channel", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mkdir(gc, t,
                    libxl__sprintf(gc, "%s/data", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));

    if (libxl_defbool_val(info->driver_domain)) {
        /*
         * Create a local "libxl" directory for each guest, since we might want
         * to use libxl from inside the guest
         */
        libxl__xs_mkdir(gc, t, GCSPRINTF("%s/libxl", dom_path), rwperm,
                        ARRAY_SIZE(rwperm));
        /*
         * Create a local "device-model" directory for each guest, since we
         * might want to use Qemu from inside the guest
         */
        libxl__xs_mkdir(gc, t, GCSPRINTF("%s/device-model", dom_path), rwperm,
                        ARRAY_SIZE(rwperm));
    }

    if (info->type == LIBXL_DOMAIN_TYPE_HVM)
        libxl__xs_mkdir(gc, t,
            libxl__sprintf(gc, "%s/hvmloader/generation-id-address", dom_path),
                        rwperm, ARRAY_SIZE(rwperm));

                    vm_list = libxl_list_vm(ctx, &nb_vm);
    if (!vm_list) {
        LOG(ERROR, "cannot get number of running guests");
        rc = ERROR_FAIL;
        goto out;
    }
    libxl_vminfo_list_free(vm_list, nb_vm);
    int hotplug_setting = libxl__hotplug_settings(gc, t);
    if (hotplug_setting < 0) {
        LOG(ERROR, "unable to get current hotplug scripts execution setting");
        rc = ERROR_FAIL;
        goto out;
    }
    if (libxl_defbool_val(info->run_hotplug_scripts) != hotplug_setting &&
        (nb_vm - 1)) {
        LOG(ERROR, "cannot change hotplug execution option once set, "
                    "please shutdown all guests before changing it");
        rc = ERROR_FAIL;
        goto out;
    }

    if (libxl_defbool_val(info->run_hotplug_scripts)) {
        rc = libxl__xs_write_checked(gc, t, DISABLE_UDEV_PATH, "1");
        if (rc) {
            LOGE(ERROR, "unable to write %s = 1", DISABLE_UDEV_PATH);
            goto out;
        }
    } else {
        rc = libxl__xs_rm_checked(gc, t, DISABLE_UDEV_PATH);
        if (rc) {
            LOGE(ERROR, "unable to delete %s", DISABLE_UDEV_PATH);
            goto out;
        }
    }

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/uuid", vm_path), uuid_string, strlen(uuid_string));
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/name", vm_path), info->name, strlen(info->name));

    libxl__xs_writev(gc, t, dom_path, info->xsdata);
    libxl__xs_writev(gc, t, libxl__sprintf(gc, "%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/control/platform-feature-xs_reset_watches", dom_path), "1", 1);
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

static int store_libxl_entry(libxl__gc *gc, uint32_t domid,
                             libxl_domain_build_info *b_info)
{
    char *path = NULL;

    path = libxl__xs_libxl_path(gc, domid);
    path = libxl__sprintf(gc, "%s/dm-version", path);
    return libxl__xs_write(gc, XBT_NULL, path, "%s",
        libxl_device_model_version_to_string(b_info->device_model_version));
}

/*----- main domain creation -----*/

/* We have a linear control flow; only one event callback is
 * outstanding at any time.  Each initiation and callback function
 * arranges for the next to be called, as the very last thing it
 * does.  (If that particular sub-operation is not needed, a
 * function will call the next event callback directly.)
 */

/* Event callbacks, in this order: */
static void domcreate_devmodel_started(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int rc);
static void domcreate_bootloader_console_available(libxl__egc *egc,
                                                   libxl__bootloader_state *bl);
static void domcreate_bootloader_done(libxl__egc *egc,
                                      libxl__bootloader_state *bl,
                                      int rc);

static void domcreate_launch_dm(libxl__egc *egc, libxl__multidev *aodevs,
                                int ret);

static void domcreate_attach_vtpms(libxl__egc *egc, libxl__multidev *multidev,
                                   int ret);
static void domcreate_attach_pci(libxl__egc *egc, libxl__multidev *aodevs,
                                 int ret);

static void domcreate_console_available(libxl__egc *egc,
                                        libxl__domain_create_state *dcs);

static void domcreate_rebuild_done(libxl__egc *egc,
                                   libxl__domain_create_state *dcs,
                                   int ret);

/* Our own function to clean up and call the user's callback.
 * The final call in the sequence. */
static void domcreate_complete(libxl__egc *egc,
                               libxl__domain_create_state *dcs,
                               int rc);

/* If creation is not successful, this callback will be executed
 * when domain destruction is finished */
static void domcreate_destruction_cb(libxl__egc *egc,
                                     libxl__domain_destroy_state *dds,
                                     int rc);

static void initiate_domain_create(libxl__egc *egc,
                                   libxl__domain_create_state *dcs)
{
    STATE_AO_GC(dcs->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    uint32_t domid;
    int i, ret;
    size_t last_devid = -1;
    bool pod_enabled = false;

    /* convenience aliases */
    libxl_domain_config *const d_config = dcs->guest_config;
    const int restore_fd = dcs->restore_fd;
    memset(&dcs->build_state, 0, sizeof(dcs->build_state));

    domid = 0;

    /* If target_memkb is smaller than max_memkb, the subsequent call
     * to libxc when building HVM domain will enable PoD mode.
     */
    pod_enabled = (d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM) &&
        (d_config->b_info.target_memkb < d_config->b_info.max_memkb);

    /* We cannot have PoD and PCI device assignment at the same time
     * for HVM guest. It was reported that IOMMU cannot work with PoD
     * enabled because it needs to populated entire page table for
     * guest. To stay on the safe side, we disable PCI device
     * assignment when PoD is enabled.
     */
    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM &&
        d_config->num_pcidevs && pod_enabled) {
        ret = ERROR_INVAL;
        LOG(ERROR, "PCI device assignment for HVM guest failed due to PoD enabled");
        goto error_out;
    }

    ret = libxl__domain_create_info_setdefault(gc, &d_config->c_info);
    if (ret) goto error_out;

    ret = libxl__domain_make(gc, &d_config->c_info, &domid);
    if (ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot make domain: %d", ret);
        dcs->guest_domid = domid;
        ret = ERROR_FAIL;
        goto error_out;
    }

    dcs->guest_domid = domid;
    dcs->dmss.dm.guest_domid = 0; /* means we haven't spawned */

    ret = libxl__domain_build_info_setdefault(gc, &d_config->b_info);
    if (ret) goto error_out;

    if (!sched_params_valid(gc, domid, &d_config->b_info.sched_params)) {
        LOG(ERROR, "Invalid scheduling parameters\n");
        ret = ERROR_INVAL;
        goto error_out;
    }

    for (i = 0; i < d_config->num_disks; i++) {
        ret = libxl__device_disk_setdefault(gc, &d_config->disks[i]);
        if (ret) goto error_out;
    }

    dcs->bl.ao = ao;
    libxl_device_disk *bootdisk =
        d_config->num_disks > 0 ? &d_config->disks[0] : NULL;

    /*
     * The devid has to be set before launching the device model. For the
     * hotplug case this is done in libxl_device_nic_add but on domain
     * creation this is called too late.
     * Make two runs over configured NICs in order to avoid duplicate IDs
     * in case the caller partially assigned IDs.
     */
    for (i = 0; i < d_config->num_nics; i++) {
        /* We have to init the nic here, because we still haven't
         * called libxl_device_nic_add when domcreate_launch_dm gets called,
         * but qemu needs the nic information to be complete.
         */
        ret = libxl__device_nic_setdefault(gc, &d_config->nics[i], domid);
        if (ret) goto error_out;

        if (d_config->nics[i].devid > last_devid)
            last_devid = d_config->nics[i].devid;
    }
    for (i = 0; i < d_config->num_nics; i++) {
        if (d_config->nics[i].devid < 0)
            d_config->nics[i].devid = ++last_devid;
    }

    if (restore_fd >= 0) {
        LOG(DEBUG, "restoring, not running bootloader\n");
        domcreate_bootloader_done(egc, &dcs->bl, 0);
    } else  {
        LOG(DEBUG, "running bootloader");
        dcs->bl.callback = domcreate_bootloader_done;
        dcs->bl.console_available = domcreate_bootloader_console_available;
        dcs->bl.info = &d_config->b_info;
        dcs->bl.disk = bootdisk;
        dcs->bl.domid = dcs->guest_domid;

        dcs->bl.kernel = &dcs->build_state.pv_kernel;
        dcs->bl.ramdisk = &dcs->build_state.pv_ramdisk;

        libxl__bootloader_run(egc, &dcs->bl);
    }
    return;

error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_bootloader_console_available(libxl__egc *egc,
                                                   libxl__bootloader_state *bl)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(bl, *dcs, bl);
    STATE_AO_GC(bl->ao);
    domcreate_console_available(egc, dcs);
}

static void domcreate_console_available(libxl__egc *egc,
                                        libxl__domain_create_state *dcs) {
    libxl__ao_progress_report(egc, dcs->ao, &dcs->aop_console_how,
                              NEW_EVENT(egc, DOMAIN_CREATE_CONSOLE_AVAILABLE,
                                        dcs->guest_domid,
                                        dcs->aop_console_how.for_event));
}

static void domcreate_bootloader_done(libxl__egc *egc,
                                      libxl__bootloader_state *bl,
                                      int rc)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(bl, *dcs, bl);
    STATE_AO_GC(bl->ao);

    /* convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl_domain_build_info *const info = &d_config->b_info;
    const int restore_fd = dcs->restore_fd;
    libxl__domain_build_state *const state = &dcs->build_state;
    libxl__srm_restore_autogen_callbacks *const callbacks =
        &dcs->shs.callbacks.restore.a;

    if (rc) {
        domcreate_rebuild_done(egc, dcs, rc);
        return;
    }

    /* consume bootloader outputs. state->pv_{kernel,ramdisk} have
     * been initialised by the bootloader already.
     */
    state->pv_cmdline = bl->cmdline;

    /* We might be going to call libxl__spawn_local_dm, or _spawn_stub_dm.
     * Fill in any field required by either, including both relevant
     * callbacks (_spawn_stub_dm will overwrite our trespass if needed). */
    dcs->dmss.dm.spawn.ao = ao;
    dcs->dmss.dm.guest_config = dcs->guest_config;
    dcs->dmss.dm.build_state = &dcs->build_state;
    dcs->dmss.dm.callback = domcreate_devmodel_started;
    dcs->dmss.callback = domcreate_devmodel_started;

    if ( restore_fd < 0 ) {
        rc = libxl__domain_build(gc, d_config, domid, state);
        domcreate_rebuild_done(egc, dcs, rc);
        return;
    }

    /* Restore */

    rc = libxl__build_pre(gc, domid, d_config, state);
    if (rc)
        goto out;

    /* read signature */
    int hvm, pae, superpages;
    switch (info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        hvm = 1;
        superpages = 1;
        pae = libxl_defbool_val(info->u.hvm.pae);
        callbacks->toolstack_restore = libxl__toolstack_restore;
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        hvm = 0;
        superpages = 0;
        pae = 1;
        break;
    default:
        rc = ERROR_INVAL;
        goto out;
    }
    libxl__xc_domain_restore(egc, dcs,
                             hvm, pae, superpages, 1);
    return;

 out:
    libxl__xc_domain_restore_done(egc, dcs, rc, 0, 0);
}

void libxl__srm_callout_callback_restore_results(unsigned long store_mfn,
          unsigned long console_mfn, unsigned long genidad, void *user)
{
    libxl__save_helper_state *shs = user;
    libxl__domain_create_state *dcs = CONTAINER_OF(shs, *dcs, shs);
    STATE_AO_GC(dcs->ao);
    libxl__domain_build_state *const state = &dcs->build_state;

    state->store_mfn =            store_mfn;
    state->console_mfn =          console_mfn;
    state->vm_generationid_addr = genidad;
    shs->need_results =           0;
}

void libxl__xc_domain_restore_done(libxl__egc *egc, void *dcs_void,
                                   int ret, int retval, int errnoval)
{
    libxl__domain_create_state *dcs = dcs_void;
    STATE_AO_GC(dcs->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, esave, flags;

    /* convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl_domain_build_info *const info = &d_config->b_info;
    libxl__domain_build_state *const state = &dcs->build_state;
    const int fd = dcs->restore_fd;

    if (ret)
        goto out;

    if (retval) {
        LOGEV(ERROR, errnoval, "restoring domain");
        ret = ERROR_FAIL;
        goto out;
    }

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
        vments[i++] = (char *) state->pv_kernel.path;
        vments[i++] = "start_time";
        vments[i++] = libxl__sprintf(gc, "%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (state->pv_ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char *) state->pv_ramdisk.path;
        }
        if (state->pv_cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char *) state->pv_cmdline;
        }
        break;
    default:
        ret = ERROR_INVAL;
        goto out;
    }
    ret = libxl__build_post(gc, domid, info, state, vments, localents);
    if (ret)
        goto out;

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        state->saved_state = GCSPRINTF(
                       XC_DEVICE_MODEL_RESTORE_FILE".%d", domid);
    }

out:
    if (info->type == LIBXL_DOMAIN_TYPE_PV) {
        libxl__file_reference_unmap(&state->pv_kernel);
        libxl__file_reference_unmap(&state->pv_ramdisk);
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
    domcreate_rebuild_done(egc, dcs, ret);
}

static void domcreate_rebuild_done(libxl__egc *egc,
                                   libxl__domain_create_state *dcs,
                                   int ret)
{
    STATE_AO_GC(dcs->ao);

    /* convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl_ctx *const ctx = CTX;

    if (ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "cannot (re-)build domain: %d", ret);
        ret = ERROR_FAIL;
        goto error_out;
    }

    store_libxl_entry(gc, domid, &d_config->b_info);

    libxl__multidev_begin(ao, &dcs->multidev);
    dcs->multidev.callback = domcreate_launch_dm;
    libxl__add_disks(egc, ao, domid, d_config, &dcs->multidev);
    libxl__multidev_prepared(egc, &dcs->multidev, 0);

    return;

 error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_launch_dm(libxl__egc *egc, libxl__multidev *multidev,
                                int ret)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(multidev, *dcs, multidev);
    STATE_AO_GC(dcs->ao);
    int i;

    /* convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl__domain_build_state *const state = &dcs->build_state;

    if (ret) {
        LOG(ERROR, "unable to add disk devices");
        goto error_out;
    }

    for (i = 0; i < d_config->b_info.num_ioports; i++) {
        libxl_ioport_range *io = &d_config->b_info.ioports[i];

        LOG(DEBUG, "dom%d ioports %"PRIx32"-%"PRIx32,
            domid, io->first, io->first + io->number - 1);

        ret = xc_domain_ioport_permission(CTX->xch, domid,
                                          io->first, io->number, 1);
        if (ret < 0) {
            LOGE(ERROR,
                 "failed give dom%d access to ioports %"PRIx32"-%"PRIx32,
                 domid, io->first, io->first + io->number - 1);
            ret = ERROR_FAIL;
        }
    }

    for (i = 0; i < d_config->b_info.num_irqs; i++) {
        int irq = d_config->b_info.irqs[i];

        LOG(DEBUG, "dom%d irq %d", domid, irq);

        ret = irq >= 0 ? xc_physdev_map_pirq(CTX->xch, domid, irq, &irq)
                       : -EOVERFLOW;
        if (!ret)
            ret = xc_domain_irq_permission(CTX->xch, domid, irq, 1);
        if (ret < 0) {
            LOGE(ERROR, "failed give dom%d access to irq %d", domid, irq);
            ret = ERROR_FAIL;
        }
    }

    for (i = 0; i < d_config->b_info.num_iomem; i++) {
        libxl_iomem_range *io = &d_config->b_info.iomem[i];

        LOG(DEBUG, "dom%d iomem %"PRIx64"-%"PRIx64,
            domid, io->start, io->start + io->number - 1);

        ret = xc_domain_iomem_permission(CTX->xch, domid,
                                          io->start, io->number, 1);
        if (ret < 0) {
            LOGE(ERROR,
                 "failed give dom%d access to iomem range %"PRIx64"-%"PRIx64,
                 domid, io->start, io->start + io->number - 1);
            ret = ERROR_FAIL;
        }
    }

    switch (d_config->c_info.type) {
    case LIBXL_DOMAIN_TYPE_HVM:
    {
        libxl__device_console console;
        libxl_device_vkb vkb;

        ret = init_console_info(&console, 0);
        if ( ret )
            goto error_out;
        console.backend_domid = state->console_domid;
        libxl__device_console_add(gc, domid, &console, state);
        libxl__device_console_dispose(&console);

        libxl_device_vkb_init(&vkb);
        libxl__device_vkb_add(gc, domid, &vkb);
        libxl_device_vkb_dispose(&vkb);

        dcs->dmss.dm.guest_domid = domid;
        if (libxl_defbool_val(d_config->b_info.device_model_stubdomain))
            libxl__spawn_stub_dm(egc, &dcs->dmss);
        else
            libxl__spawn_local_dm(egc, &dcs->dmss.dm);
        return;
    }
    case LIBXL_DOMAIN_TYPE_PV:
    {
        int need_qemu = 0;
        libxl__device_console console;

        for (i = 0; i < d_config->num_vfbs; i++) {
            libxl__device_vfb_add(gc, domid, &d_config->vfbs[i]);
            libxl__device_vkb_add(gc, domid, &d_config->vkbs[i]);
        }

        ret = init_console_info(&console, 0);
        if ( ret )
            goto error_out;

        need_qemu = libxl__need_xenpv_qemu(gc, 1, &console,
                d_config->num_vfbs, d_config->vfbs,
                d_config->num_disks, &d_config->disks[0]);

        console.backend_domid = state->console_domid;
        libxl__device_console_add(gc, domid, &console, state);
        libxl__device_console_dispose(&console);

        if (need_qemu) {
            dcs->dmss.dm.guest_domid = domid;
            libxl__spawn_local_dm(egc, &dcs->dmss.dm);
            return;
        } else {
            assert(!dcs->dmss.dm.guest_domid);
            domcreate_devmodel_started(egc, &dcs->dmss.dm, 0);
            return;
        }
    }
    default:
        ret = ERROR_INVAL;
        goto error_out;
    }
    abort(); /* not reached */

 error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_devmodel_started(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int ret)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(dmss, *dcs, dmss.dm);
    STATE_AO_GC(dmss->spawn.ao);
    libxl_ctx *ctx = CTX;
    int domid = dcs->guest_domid;

    /* convenience aliases */
    libxl_domain_config *const d_config = dcs->guest_config;

    if (ret) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                   "device model did not start: %d", ret);
        goto error_out;
    }

    if (dcs->dmss.dm.guest_domid) {
        if (d_config->b_info.device_model_version
            == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
            libxl__qmp_initializations(gc, domid, d_config);
        }
    }

    /* Plug nic interfaces */
    if (d_config->num_nics > 0) {
        /* Attach nics */
        libxl__multidev_begin(ao, &dcs->multidev);
        dcs->multidev.callback = domcreate_attach_vtpms;
        libxl__add_nics(egc, ao, domid, d_config, &dcs->multidev);
        libxl__multidev_prepared(egc, &dcs->multidev, 0);
        return;
    }

    domcreate_attach_vtpms(egc, &dcs->multidev, 0);
    return;

error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_attach_vtpms(libxl__egc *egc,
                                   libxl__multidev *multidev,
                                   int ret)
{
   libxl__domain_create_state *dcs = CONTAINER_OF(multidev, *dcs, multidev);
   STATE_AO_GC(dcs->ao);
   int domid = dcs->guest_domid;

   libxl_domain_config* const d_config = dcs->guest_config;

   if(ret) {
       LOG(ERROR, "unable to add nic devices");
       goto error_out;
   }

    /* Plug vtpm devices */
   if (d_config->num_vtpms > 0) {
       /* Attach vtpms */
       libxl__multidev_begin(ao, &dcs->multidev);
       dcs->multidev.callback = domcreate_attach_pci;
       libxl__add_vtpms(egc, ao, domid, d_config, &dcs->multidev);
       libxl__multidev_prepared(egc, &dcs->multidev, 0);
       return;
   }

   domcreate_attach_pci(egc, multidev, 0);
   return;

error_out:
   assert(ret);
   domcreate_complete(egc, dcs, ret);
}

static void domcreate_attach_pci(libxl__egc *egc, libxl__multidev *multidev,
                                 int ret)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(multidev, *dcs, multidev);
    STATE_AO_GC(dcs->ao);
    int i;
    libxl_ctx *ctx = CTX;
    int domid = dcs->guest_domid;

    /* convenience aliases */
    libxl_domain_config *const d_config = dcs->guest_config;

    if (ret) {
        LOG(ERROR, "unable to add vtpm devices");
        goto error_out;
    }

    for (i = 0; i < d_config->num_pcidevs; i++) {
        ret = libxl__device_pci_add(gc, domid, &d_config->pcidevs[i], 1);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                       "libxl_device_pci_add failed: %d", ret);
            goto error_out;
        }
    }

    if (d_config->num_pcidevs > 0) {
        ret = libxl__create_pci_backend(gc, domid, d_config->pcidevs,
            d_config->num_pcidevs);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                "libxl_create_pci_backend failed: %d", ret);
            goto error_out;
        }
    }

    domcreate_console_available(egc, dcs);

    domcreate_complete(egc, dcs, 0);
    return;

error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_complete(libxl__egc *egc,
                               libxl__domain_create_state *dcs,
                               int rc)
{
    STATE_AO_GC(dcs->ao);
    libxl_domain_config *const d_config = dcs->guest_config;

    if (!rc && d_config->b_info.exec_ssidref)
        rc = xc_flask_relabel_domain(CTX->xch, dcs->guest_domid, d_config->b_info.exec_ssidref);

    if (rc) {
        if (dcs->guest_domid) {
            dcs->dds.ao = ao;
            dcs->dds.domid = dcs->guest_domid;
            dcs->dds.callback = domcreate_destruction_cb;
            libxl__domain_destroy(egc, &dcs->dds);
            return;
        }
        dcs->guest_domid = -1;
    }
    dcs->callback(egc, dcs, rc, dcs->guest_domid);
}

static void domcreate_destruction_cb(libxl__egc *egc,
                                     libxl__domain_destroy_state *dds,
                                     int rc)
{
    STATE_AO_GC(dds->ao);
    libxl__domain_create_state *dcs = CONTAINER_OF(dds, *dcs, dds);

    if (rc)
        LOG(ERROR, "unable to destroy domain %u following failed creation",
                   dds->domid);

    dcs->callback(egc, dcs, ERROR_FAIL, dcs->guest_domid);
}

/*----- application-facing domain creation interface -----*/

typedef struct {
    libxl__domain_create_state dcs;
    uint32_t *domid_out;
} libxl__app_domain_create_state;

static void domain_create_cb(libxl__egc *egc,
                             libxl__domain_create_state *dcs,
                             int rc, uint32_t domid);

static int do_domain_create(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid,
                            int restore_fd, int checkpointed_stream,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how)
{
    AO_CREATE(ctx, 0, ao_how);
    libxl__app_domain_create_state *cdcs;

    GCNEW(cdcs);
    cdcs->dcs.ao = ao;
    cdcs->dcs.guest_config = d_config;
    cdcs->dcs.restore_fd = restore_fd;
    cdcs->dcs.callback = domain_create_cb;
    cdcs->dcs.checkpointed_stream = checkpointed_stream;
    libxl__ao_progress_gethow(&cdcs->dcs.aop_console_how, aop_console_how);
    cdcs->domid_out = domid;

    initiate_domain_create(egc, &cdcs->dcs);

    return AO_INPROGRESS;
}

static void domain_create_cb(libxl__egc *egc,
                             libxl__domain_create_state *dcs,
                             int rc, uint32_t domid)
{
    libxl__app_domain_create_state *cdcs = CONTAINER_OF(dcs, *cdcs, dcs);
    STATE_AO_GC(cdcs->dcs.ao);

    if (!rc)
        *cdcs->domid_out = domid;

    libxl__ao_complete(egc, ao, rc);
}
    
int libxl_domain_create_new(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how)
{
    return do_domain_create(ctx, d_config, domid, -1, 0,
                            ao_how, aop_console_how);
}

int libxl_domain_create_restore(libxl_ctx *ctx, libxl_domain_config *d_config,
                                uint32_t *domid, int restore_fd,
                                const libxl_domain_restore_params *params,
                                const libxl_asyncop_how *ao_how,
                                const libxl_asyncprogress_how *aop_console_how)
{
    return do_domain_create(ctx, d_config, domid, restore_fd,
                            params->checkpointed_stream, ao_how, aop_console_how);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
