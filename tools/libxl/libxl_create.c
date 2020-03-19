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
#include <xen/hvm/e820.h>

#include <xen-xsm/flask/flask.h>

int libxl__domain_create_info_setdefault(libxl__gc *gc,
                                         libxl_domain_create_info *c_info,
                                         const libxl_physinfo *info)
{
    if (!c_info->type) {
        LOG(ERROR, "domain type unspecified");
        return ERROR_INVAL;
    }

    libxl__arch_domain_create_info_setdefault(gc, c_info);

    if (c_info->type != LIBXL_DOMAIN_TYPE_PV) {
        if (info->cap_hap) {
            libxl_defbool_setdefault(&c_info->hap, true);
        } else if (info->cap_shadow) {
            libxl_defbool_setdefault(&c_info->hap, false);
        } else {
            LOG(ERROR, "neither hap nor shadow paging available");
            return ERROR_INVAL;
        }

        libxl_defbool_setdefault(&c_info->oos, true);
    }

    libxl_defbool_setdefault(&c_info->run_hotplug_scripts, true);
    libxl_defbool_setdefault(&c_info->driver_domain, false);

    if (!c_info->ssidref)
        c_info->ssidref = SECINITSID_DOMU;

    return 0;
}

void libxl__rdm_setdefault(libxl__gc *gc, libxl_domain_build_info *b_info)
{
    if (b_info->u.hvm.rdm.policy == LIBXL_RDM_RESERVE_POLICY_INVALID)
        b_info->u.hvm.rdm.policy = LIBXL_RDM_RESERVE_POLICY_RELAXED;

    if (b_info->u.hvm.rdm_mem_boundary_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->u.hvm.rdm_mem_boundary_memkb =
                            LIBXL_RDM_MEM_BOUNDARY_MEMKB_DEFAULT;
}

int libxl__domain_build_info_setdefault(libxl__gc *gc,
                                        libxl_domain_build_info *b_info)
{
    int i, rc;

    if (b_info->type != LIBXL_DOMAIN_TYPE_HVM &&
        b_info->type != LIBXL_DOMAIN_TYPE_PV &&
        b_info->type != LIBXL_DOMAIN_TYPE_PVH) {
        LOG(ERROR, "invalid domain type");
        return ERROR_INVAL;
    }

    /* Copy deprecated options to it's new position. */
    rc = libxl__domain_build_info_copy_deprecated(CTX, b_info);
    if (rc) {
        LOG(ERROR, "Unable to copy deprecated fields");
        return rc;
    }

    libxl_defbool_setdefault(&b_info->device_model_stubdomain, false);

    if (libxl_defbool_val(b_info->device_model_stubdomain) &&
        !b_info->device_model_ssidref)
        b_info->device_model_ssidref = SECINITSID_DOMDM;

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

            dm = libxl__domain_device_model(gc, b_info);
            rc = access(dm, X_OK);
            if (rc < 0) {
                /* qemu-xen unavailable, use qemu-xen-traditional */
                if (errno == ENOENT) {
                    LOGE(INFO, "qemu-xen is unavailable"
                         ", using qemu-xen-traditional instead");
                    b_info->device_model_version =
                        LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
                } else {
                    LOGE(ERROR, "qemu-xen access error");
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
            default:
                LOG(ERROR, "unknown device model version");
                return ERROR_INVAL;
            }

        /* Enforce BIOS<->Device Model version relationship */
        switch (b_info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            if (b_info->u.hvm.bios != LIBXL_BIOS_TYPE_ROMBIOS) {
                LOG(ERROR, "qemu-xen-traditional requires bios=rombios.");
                return ERROR_INVAL;
            }
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            if (b_info->u.hvm.bios == LIBXL_BIOS_TYPE_ROMBIOS) {
                LOG(ERROR, "qemu-xen does not support bios=rombios.");
                return ERROR_INVAL;
            }
            break;
        default:abort();
        }

        /* Check HVM direct boot parameters, we should honour ->ramdisk and
         * ->cmdline iff ->kernel is set.
         */
        if (!b_info->kernel && (b_info->ramdisk || b_info->cmdline)) {
            LOG(ERROR, "direct boot parameters specified but kernel missing");
            return ERROR_INVAL;
        }
    }

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM &&
        b_info->device_model_version !=
            LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL &&
        libxl_defbool_val(b_info->device_model_stubdomain)) {
        LOG(ERROR,
            "device model stubdomains require \"qemu-xen-traditional\"");
        return ERROR_INVAL;
    }

    if (!b_info->max_vcpus)
        b_info->max_vcpus = 1;
    if (!b_info->avail_vcpus.size) {
        if (libxl_cpu_bitmap_alloc(CTX, &b_info->avail_vcpus, 1)) {
            LOG(ERROR, "unable to allocate avail_vcpus bitmap");
            return ERROR_FAIL;
        }
        libxl_bitmap_set(&b_info->avail_vcpus, 0);
    } else if (b_info->avail_vcpus.size > HVM_MAX_VCPUS) {
        LOG(ERROR, "avail_vcpus bitmap contains too many VCPUS");
        return ERROR_FAIL;
    }

    /* In libxl internals, we want to deal with vcpu_hard_affinity only! */
    if (b_info->cpumap.size && !b_info->num_vcpu_hard_affinity) {
        b_info->vcpu_hard_affinity = libxl__calloc(gc, b_info->max_vcpus,
                                                   sizeof(libxl_bitmap));
        for (i = 0; i < b_info->max_vcpus; i++) {
            if (libxl_cpu_bitmap_alloc(CTX, &b_info->vcpu_hard_affinity[i], 0)) {
                LOG(ERROR, "failed to allocate vcpu hard affinity bitmap");
                return ERROR_FAIL;
            }
            libxl_bitmap_copy(CTX, &b_info->vcpu_hard_affinity[i],
                              &b_info->cpumap);
        }
        b_info->num_vcpu_hard_affinity = b_info->max_vcpus;
    }

    libxl_defbool_setdefault(&b_info->numa_placement, true);

    if (b_info->max_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->max_memkb = 32 * 1024;
    if (b_info->target_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->target_memkb = b_info->max_memkb;

    libxl_defbool_setdefault(&b_info->claim_mode, false);

    libxl_defbool_setdefault(&b_info->localtime, false);

    libxl_defbool_setdefault(&b_info->disable_migrate, false);

    for (i = 0 ; i < b_info->num_iomem; i++)
        if (b_info->iomem[i].gfn == LIBXL_INVALID_GFN)
            b_info->iomem[i].gfn = b_info->iomem[i].start;

    if (!b_info->event_channels)
        b_info->event_channels = 1023;

    libxl__arch_domain_build_info_setdefault(gc, b_info);
    libxl_defbool_setdefault(&b_info->dm_restrict, false);

    if (b_info->iommu_memkb == LIBXL_MEMKB_DEFAULT)
        /* Normally defaulted in libxl__domain_create_info_setdefault */
        b_info->iommu_memkb = 0;

    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        if (b_info->shadow_memkb == LIBXL_MEMKB_DEFAULT)
            /* Normally defaulted in libxl__domain_create_info_setdefault */
            b_info->shadow_memkb = 0;
        if (b_info->u.hvm.mmio_hole_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->u.hvm.mmio_hole_memkb = 0;

        if (b_info->u.hvm.vga.kind == LIBXL_VGA_INTERFACE_TYPE_UNKNOWN) {
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_CIRRUS;
        }

        if (!b_info->u.hvm.hdtype)
            b_info->u.hvm.hdtype = LIBXL_HDTYPE_IDE;

        switch (b_info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            switch (b_info->u.hvm.vga.kind) {
            case LIBXL_VGA_INTERFACE_TYPE_NONE:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
                    b_info->video_memkb = 0;
                break;
            case LIBXL_VGA_INTERFACE_TYPE_QXL:
                LOG(ERROR,"qemu upstream required for qxl vga");
                return ERROR_INVAL;
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
            case LIBXL_VGA_INTERFACE_TYPE_QXL:
                if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT) {
                    b_info->video_memkb = (128 * 1024);
                } else if (b_info->video_memkb < (128 * 1024)) {
                    LOG(ERROR,
                        "128 Mib videoram is the minimum for qxl default");
                    return ERROR_INVAL;
                }
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

        libxl_defbool_setdefault(&b_info->u.hvm.pae,                true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi,               true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi_s3,            true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi_s4,            true);
        libxl_defbool_setdefault(&b_info->u.hvm.acpi_laptop_slate,  false);
        libxl_defbool_setdefault(&b_info->u.hvm.nx,                 true);
        libxl_defbool_setdefault(&b_info->u.hvm.viridian,           false);
        libxl_defbool_setdefault(&b_info->u.hvm.hpet,               true);
        libxl_defbool_setdefault(&b_info->u.hvm.vpt_align,          true);
        libxl_defbool_setdefault(&b_info->u.hvm.altp2m,             false);
        libxl_defbool_setdefault(&b_info->u.hvm.usb,                false);
        libxl_defbool_setdefault(&b_info->u.hvm.vkb_device,         true);
        libxl_defbool_setdefault(&b_info->u.hvm.xen_platform_pci,   true);

        libxl_defbool_setdefault(&b_info->u.hvm.spice.enable, false);
        if (!libxl_defbool_val(b_info->u.hvm.spice.enable) &&
            (b_info->u.hvm.spice.usbredirection > 0) ){
            b_info->u.hvm.spice.usbredirection = 0;
            LOG(WARN, "spice disabled, disabling usbredirection");
        }

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

        if (!b_info->u.hvm.boot)
            b_info->u.hvm.boot = libxl__strdup(NOGC, "cda");

        libxl_defbool_setdefault(&b_info->u.hvm.vnc.enable, true);
        if (libxl_defbool_val(b_info->u.hvm.vnc.enable)) {
            libxl_defbool_setdefault(&b_info->u.hvm.vnc.findunused, true);
            if (!b_info->u.hvm.vnc.listen)
                b_info->u.hvm.vnc.listen = libxl__strdup(NOGC, "127.0.0.1");
        }

        libxl_defbool_setdefault(&b_info->u.hvm.sdl.enable, false);
        if (libxl_defbool_val(b_info->u.hvm.sdl.enable)) {
            libxl_defbool_setdefault(&b_info->u.hvm.sdl.opengl, false);
        }

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

        libxl__rdm_setdefault(gc, b_info);
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        libxl_defbool_setdefault(&b_info->u.pv.e820_host, false);
        if (b_info->video_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->video_memkb = 0;
        if (b_info->shadow_memkb == LIBXL_MEMKB_DEFAULT)
            /* Normally defaulted in libxl__domain_create_info_setdefault */
            b_info->shadow_memkb = 0;
        if (b_info->u.pv.slack_memkb == LIBXL_MEMKB_DEFAULT)
            b_info->u.pv.slack_memkb = 0;
        break;
    case LIBXL_DOMAIN_TYPE_PVH:
        libxl_defbool_setdefault(&b_info->u.pvh.pvshim, false);
        if (libxl_defbool_val(b_info->u.pvh.pvshim)) {
            if (!b_info->u.pvh.pvshim_path)
                b_info->u.pvh.pvshim_path =
                    libxl__sprintf(NOGC, "%s/%s",
                                   libxl__xenfirmwaredir_path(),
                                   PVSHIM_BASENAME);
            if (!b_info->u.pvh.pvshim_cmdline)
                b_info->u.pvh.pvshim_cmdline =
                    libxl__strdup(NOGC, PVSHIM_CMDLINE);
        }

        break;
    default:
        LOG(ERROR, "invalid domain type %s in create info",
            libxl_domain_type_to_string(b_info->type));
        return ERROR_INVAL;
    }

    /* Configuration fields shared between PVH and HVM. */
    if (b_info->type != LIBXL_DOMAIN_TYPE_PV) {
        if (libxl__timer_mode_is_default(&b_info->timer_mode))
            b_info->timer_mode = LIBXL_TIMER_MODE_NO_DELAY_FOR_MISSED_TICKS;

        libxl_defbool_setdefault(&b_info->apic,                     true);
        libxl_defbool_setdefault(&b_info->nested_hvm,               false);
    }

    return 0;
}

static void init_console_info(libxl__gc *gc,
                             libxl__device_console *console,
                             int dev_num)
{
    libxl__device_console_init(console);
    console->devid = dev_num;
    console->consback = LIBXL__CONSOLE_BACKEND_XENCONSOLED;
    console->output = libxl__strdup(NOGC, "pty");
    /* console->{name,connection,path} are NULL on normal consoles.
       Only 'channels' when mapped to consoles have a string name. */
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
        ret = libxl__build_hvm(gc, domid, d_config, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 7, sizeof(char *));
        vments[0] = "rtc/timeoffset";
        vments[1] = (info->u.hvm.timeoffset) ? info->u.hvm.timeoffset : "";
        vments[2] = "image/ostype";
        vments[3] = "hvm";
        vments[4] = "start_time";
        vments[5] = GCSPRINTF("%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);

        localents = libxl__calloc(gc, 13, sizeof(char *));
        i = 0;
        localents[i++] = "platform/acpi";
        localents[i++] = libxl__acpi_defbool_val(info) ? "1" : "0";
        localents[i++] = "platform/acpi_s3";
        localents[i++] = libxl_defbool_val(info->u.hvm.acpi_s3) ? "1" : "0";
        localents[i++] = "platform/acpi_s4";
        localents[i++] = libxl_defbool_val(info->u.hvm.acpi_s4) ? "1" : "0";
        localents[i++] = "platform/acpi_laptop_slate";
        localents[i++] = libxl_defbool_val(info->u.hvm.acpi_laptop_slate) ? "1" : "0";
        if (info->u.hvm.mmio_hole_memkb) {
            uint64_t max_ram_below_4g =
                (1ULL << 32) - (info->u.hvm.mmio_hole_memkb << 10);

            if (max_ram_below_4g <= HVM_BELOW_4G_MMIO_START) {
                localents[i++] = "platform/mmio_hole_size";
                localents[i++] =
                    GCSPRINTF("%"PRIu64,
                                   info->u.hvm.mmio_hole_memkb << 10);
            }
        }
        localents[i++] = "platform/device-model";
        localents[i++] = (char *)libxl_device_model_version_to_string(info->device_model_version);

        break;
    case LIBXL_DOMAIN_TYPE_PV:
        ret = libxl__build_pv(gc, domid, d_config, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char *) state->pv_kernel.path;
        vments[i++] = "start_time";
        vments[i++] = GCSPRINTF("%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (state->pv_ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char *) state->pv_ramdisk.path;
        }
        if (state->pv_cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char *) state->pv_cmdline;
        }

        break;
    case LIBXL_DOMAIN_TYPE_PVH:
        state->shim_path = info->u.pvh.pvshim_path;
        state->shim_cmdline = GCSPRINTF("%s%s%s",
                    info->u.pvh.pvshim_cmdline,
                    info->u.pvh.pvshim_extra ? " " : "",
                    info->u.pvh.pvshim_extra ? info->u.pvh.pvshim_extra : "");

        ret = libxl__build_hvm(gc, domid, d_config, state);
        if (ret)
            goto out;

        vments = libxl__calloc(gc, 3, sizeof(char *));
        vments[0] = "start_time";
        vments[1] = GCSPRINTF("%"PRIu64".%02ld",
                              (uint64_t)start_time.tv_sec,
                              (long)start_time.tv_usec/10000);

        break;
    default:
        ret = ERROR_INVAL;
        goto out;
    }
    ret = libxl__build_post(gc, domid, info, state, vments, localents);
out:
    return ret;
}

int libxl__domain_make(libxl__gc *gc, libxl_domain_config *d_config,
                       libxl__domain_build_state *state,
                       uint32_t *domid, bool soft_reset)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int ret, rc, nb_vm;
    const char *dom_type;
    char *uuid_string;
    char *dom_path, *vm_path, *libxl_path;
    struct xs_permissions roperm[2];
    struct xs_permissions rwperm[1];
    struct xs_permissions noperm[1];
    xs_transaction_t t = 0;
    libxl_vminfo *vm_list;

    /* convenience aliases */
    libxl_domain_create_info *info = &d_config->c_info;
    libxl_domain_build_info *b_info = &d_config->b_info;

    assert(soft_reset || *domid == INVALID_DOMID);

    uuid_string = libxl__uuid2string(gc, info->uuid);
    if (!uuid_string) {
        rc = ERROR_NOMEM;
        goto out;
    }

    if (!soft_reset) {
        struct xen_domctl_createdomain create = {
            .ssidref = info->ssidref,
            .max_vcpus = b_info->max_vcpus,
            .max_evtchn_port = b_info->event_channels,
            .max_grant_frames = b_info->max_grant_frames,
            .max_maptrack_frames = b_info->max_maptrack_frames,
        };

        if (info->type != LIBXL_DOMAIN_TYPE_PV) {
            create.flags |= XEN_DOMCTL_CDF_hvm;
            create.flags |=
                libxl_defbool_val(info->hap) ? XEN_DOMCTL_CDF_hap : 0;
            create.flags |=
                libxl_defbool_val(info->oos) ? 0 : XEN_DOMCTL_CDF_oos_off;
        }

        assert(info->passthrough != LIBXL_PASSTHROUGH_DEFAULT);
        LOG(DETAIL, "passthrough: %s",
            libxl_passthrough_to_string(info->passthrough));

        if (info->passthrough != LIBXL_PASSTHROUGH_DISABLED)
            create.flags |= XEN_DOMCTL_CDF_iommu;

        if (info->passthrough == LIBXL_PASSTHROUGH_SYNC_PT)
            create.iommu_opts |= XEN_DOMCTL_IOMMU_no_sharept;

        /* Ultimately, handle is an array of 16 uint8_t, same as uuid */
        libxl_uuid_copy(ctx, (libxl_uuid *)&create.handle, &info->uuid);

        ret = libxl__arch_domain_prepare_config(gc, d_config, &create);
        if (ret < 0) {
            LOGED(ERROR, *domid, "fail to get domain config");
            rc = ERROR_FAIL;
            goto out;
        }

        for (;;) {
            uint32_t local_domid;
            bool recent;

            if (info->domid == RANDOM_DOMID) {
                uint16_t v;

                ret = libxl__random_bytes(gc, (void *)&v, sizeof(v));
                if (ret < 0)
                    break;

                v &= DOMID_MASK;
                if (!libxl_domid_valid_guest(v))
                    continue;

                local_domid = v;
            } else {
                local_domid = info->domid; /* May not be valid */
            }

            ret = xc_domain_create(ctx->xch, &local_domid, &create);
            if (ret < 0) {
                /*
                 * If we generated a random domid and creation failed
                 * because that domid already exists then simply try
                 * again.
                 */
                if (errno == EEXIST && info->domid == RANDOM_DOMID)
                    continue;

                LOGED(ERROR, local_domid, "domain creation fail");
                rc = ERROR_FAIL;
                goto out;
            }

            /* A new domain now exists */
            *domid = local_domid;

            rc = libxl__is_domid_recent(gc, local_domid, &recent);
            if (rc)
                goto out;

            /* The domid is not recent, so we're done */
            if (!recent)
                break;

            /*
             * If the domid was specified then there's no point in
             * trying again.
             */
            if (libxl_domid_valid_guest(info->domid)) {
                LOGED(ERROR, local_domid, "domain id recently used");
                rc = ERROR_FAIL;
                goto out;
            }

            /*
             * The domain is recent and so cannot be used. Clear domid
             * here since, if xc_domain_destroy() fails below there is
             * little point calling it again in the error path.
             */
            *domid = INVALID_DOMID;

            ret = xc_domain_destroy(ctx->xch, local_domid);
            if (ret < 0) {
                LOGED(ERROR, local_domid, "domain destroy fail");
                rc = ERROR_FAIL;
                goto out;
            }

            /* The domain was successfully destroyed, so we can try again */
        }

        rc = libxl__arch_domain_save_config(gc, d_config, state, &create);
        if (rc < 0)
            goto out;
    }

    /*
     * If soft_reset is set the the domid will have been valid on entry.
     * If it was not set then xc_domain_create() should have assigned a
     * valid value. Either way, if we reach this point, domid should be
     * valid.
     */
    assert(libxl_domid_valid_guest(*domid));

    ret = xc_cpupool_movedomain(ctx->xch, info->poolid, *domid);
    if (ret < 0) {
        LOGED(ERROR, *domid, "domain move fail");
        rc = ERROR_FAIL;
        goto out;
    }

    dom_path = libxl__xs_get_dompath(gc, *domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    vm_path = GCSPRINTF("/vm/%s", uuid_string);
    if (!vm_path) {
        LOGD(ERROR, *domid, "cannot allocate create paths");
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
    libxl__xs_mknod(gc, t, dom_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, vm_path);
    libxl__xs_mknod(gc, t, vm_path, roperm, ARRAY_SIZE(roperm));

    xs_rm(ctx->xsh, t, libxl_path);
    libxl__xs_mknod(gc, t, libxl_path, noperm, ARRAY_SIZE(noperm));
    libxl__xs_mknod(gc, t, GCSPRINTF("%s/device", libxl_path),
                    noperm, ARRAY_SIZE(noperm));

    xs_write(ctx->xsh, t, GCSPRINTF("%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl__domain_rename(gc, *domid, 0, info->name, t);
    if (rc)
        goto out;

    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/cpu", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/memory", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/device", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control", dom_path),
                    roperm, ARRAY_SIZE(roperm));
    if (info->type == LIBXL_DOMAIN_TYPE_HVM)
        libxl__xs_mknod(gc, t,
                        GCSPRINTF("%s/hvmloader", dom_path),
                        roperm, ARRAY_SIZE(roperm));

    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control/shutdown", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control/feature-poweroff", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control/feature-reboot", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control/feature-suspend", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        libxl__xs_mknod(gc, t,
                        GCSPRINTF("%s/control/feature-s3", dom_path),
                        rwperm, ARRAY_SIZE(rwperm));
        libxl__xs_mknod(gc, t,
                        GCSPRINTF("%s/control/feature-s4", dom_path),
                        rwperm, ARRAY_SIZE(rwperm));
    }
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/control/sysrq", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/device/suspend/event-channel", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/data", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/drivers", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/feature", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/attr", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));
    libxl__xs_mknod(gc, t,
                    GCSPRINTF("%s/error", dom_path),
                    rwperm, ARRAY_SIZE(rwperm));

    if (libxl_defbool_val(info->driver_domain)) {
        /*
         * Create a local "libxl" directory for each guest, since we might want
         * to use libxl from inside the guest
         */
        libxl__xs_mknod(gc, t, GCSPRINTF("%s/libxl", dom_path), rwperm,
                        ARRAY_SIZE(rwperm));
        /*
         * Create a local "device-model" directory for each guest, since we
         * might want to use Qemu from inside the guest
         */
        libxl__xs_mknod(gc, t, GCSPRINTF("%s/device-model", dom_path), rwperm,
                        ARRAY_SIZE(rwperm));
    }

    vm_list = libxl_list_vm(ctx, &nb_vm);
    if (!vm_list) {
        LOGD(ERROR, *domid, "cannot get number of running guests");
        rc = ERROR_FAIL;
        goto out;
    }
    libxl_vminfo_list_free(vm_list, nb_vm);

    xs_write(ctx->xsh, t, GCSPRINTF("%s/uuid", vm_path), uuid_string, strlen(uuid_string));
    xs_write(ctx->xsh, t, GCSPRINTF("%s/name", vm_path), info->name, strlen(info->name));

    libxl__xs_writev(gc, t, dom_path, info->xsdata);
    libxl__xs_writev(gc, t, GCSPRINTF("%s/platform", dom_path), info->platformdata);

    xs_write(ctx->xsh, t, GCSPRINTF("%s/control/platform-feature-multiprocessor-suspend", dom_path), "1", 1);
    xs_write(ctx->xsh, t, GCSPRINTF("%s/control/platform-feature-xs_reset_watches", dom_path), "1", 1);

    dom_type = libxl_domain_type_to_string(info->type);
    xs_write(ctx->xsh, t, GCSPRINTF("%s/type", libxl_path), dom_type,
             strlen(dom_type));

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN) {
            t = 0;
            goto retry_transaction;
        }
        LOGED(ERROR, *domid, "domain creation ""xenstore transaction commit failed");
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
    path = GCSPRINTF("%s/dm-version", path);
    return libxl__xs_printf(gc, XBT_NULL, path, "%s",
                            libxl_device_model_version_to_string(b_info->device_model_version));
}

void libxl__domain_build_state_init(libxl__domain_build_state *state)
{
    state->dm_monitor_fd = -1;
}

void libxl__domain_build_state_dispose(libxl__domain_build_state *state)
{
    libxl__file_reference_unmap(&state->pv_kernel);
    libxl__file_reference_unmap(&state->pv_ramdisk);
    if (state->dm_monitor_fd >= 0) {
        close(state->dm_monitor_fd);
        state->dm_monitor_fd = -1;
    }
}

/*----- main domain creation -----*/

/* We have a linear control flow; only one event callback is
 * outstanding at any time.  Each initiation and callback function
 * arranges for the next to be called, as the very last thing it
 * does.  (If that particular sub-operation is not needed, a
 * function will call the next event callback directly.)
 */

/* Event callbacks, in this order: */
static void domcreate_bootloader_console_available(libxl__egc *egc,
                                                   libxl__bootloader_state *bl);
static void domcreate_console_available(libxl__egc *egc,
                                        libxl__domain_create_state *dcs);

static void domcreate_bootloader_done(libxl__egc *egc,
                                      libxl__bootloader_state *bl,
                                      int rc);
static void libxl__colo_restore_setup_done(libxl__egc *egc,
                                           libxl__colo_restore_state *crs,
                                           int rc);
static void domcreate_stream_done(libxl__egc *egc,
                                  libxl__stream_read_state *srs,
                                  int ret);
static void domcreate_rebuild_done(libxl__egc *egc,
                                   libxl__domain_create_state *dcs,
                                   int ret);
static void domcreate_launch_dm(libxl__egc *egc, libxl__multidev *aodevs,
                                int ret);
static void domcreate_devmodel_started(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int rc);
static void domcreate_attach_devices(libxl__egc *egc,
                                     libxl__multidev *multidev,
                                     int ret);
static void console_xswait_callback(libxl__egc *egc, libxl__xswait_state *xswa,
                                    int rc, const char *p);

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

static bool ok_to_default_memkb_in_create(libxl__gc *gc)
{
    /*
     * This is a fudge.  We are trying to find whether the caller
     * calls the old version of libxl_domain_need_memory.  If they do
     * then, because it only gets the b_info, and because it can't
     * update the b_info (because it's const), it will base its
     * calculations on defaulting shadow_memkb and iommu_memkb to 0
     * In that case we probably shouldn't default them differently
     * during libxl_domain_create.
     *
     * The result is that the behaviour with old callers is the same
     * as in 4.13: no additional memory is allocated for shadow and
     * iommu (unless the caller set shadow_memkb, eg from a call to
     * libxl_get_required_shadow_memory).
     */
    return !CTX->libxl_domain_need_memory_0x041200_called ||
            CTX->libxl_domain_need_memory_called;
    /*
     * Treat mixed callers as new callers.  Presumably they know what
     * they are doing.
     */
}

static unsigned long libxl__get_required_iommu_memory(unsigned long maxmem_kb)
{
    unsigned long iommu_pages = 0, mem_pages = maxmem_kb / 4;
    unsigned int level;

    /* Assume a 4 level page table with 512 entries per level */
    for (level = 0; level < 4; level++)
    {
        mem_pages = DIV_ROUNDUP(mem_pages, 512);
        iommu_pages += mem_pages;
    }

    return iommu_pages * 4;
}

int libxl__domain_config_setdefault(libxl__gc *gc,
                                    libxl_domain_config *d_config,
                                    uint32_t domid /* for logging, only */)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int ret;
    bool pod_enabled = false;
    libxl_domain_create_info *c_info = &d_config->c_info;

    libxl_physinfo physinfo;
    ret = libxl_get_physinfo(CTX, &physinfo);
    if (ret) goto error_out;

    if (d_config->c_info.ssid_label) {
        char *s = d_config->c_info.ssid_label;
        ret = libxl_flask_context_to_sid(ctx, s, strlen(s),
                                         &d_config->c_info.ssidref);
        if (ret) {
            if (errno == ENOSYS) {
                LOGD(WARN, domid, "XSM Disabled: init_seclabel not supported");
                ret = 0;
            } else {
                LOGD(ERROR, domid, "Invalid init_seclabel: %s", s);
                goto error_out;
            }
        }
    }

    if (d_config->b_info.exec_ssid_label) {
        char *s = d_config->b_info.exec_ssid_label;
        ret = libxl_flask_context_to_sid(ctx, s, strlen(s),
                                         &d_config->b_info.exec_ssidref);
        if (ret) {
            if (errno == ENOSYS) {
                LOGD(WARN, domid, "XSM Disabled: seclabel not supported");
                ret = 0;
            } else {
                LOGD(ERROR, domid, "Invalid seclabel: %s", s);
                goto error_out;
            }
        }
    }

    if (d_config->b_info.device_model_ssid_label) {
        char *s = d_config->b_info.device_model_ssid_label;
        ret = libxl_flask_context_to_sid(ctx, s, strlen(s),
                                         &d_config->b_info.device_model_ssidref);
        if (ret) {
            if (errno == ENOSYS) {
                LOGD(WARN, domid,
                     "XSM Disabled: device_model_stubdomain_seclabel not supported");
                ret = 0;
            } else {
                LOGD(ERROR, domid, "Invalid device_model_stubdomain_seclabel: %s", s);
                goto error_out;
            }
        }
    }

    if (d_config->c_info.pool_name) {
        d_config->c_info.poolid = -1;
        libxl_cpupool_qualifier_to_cpupoolid(ctx, d_config->c_info.pool_name,
                                             &d_config->c_info.poolid,
                                             NULL);
    }
    if (!libxl_cpupoolid_is_valid(ctx, d_config->c_info.poolid)) {
        LOGD(ERROR, domid, "Illegal pool specified: %s",
             d_config->c_info.pool_name);
        ret = ERROR_INVAL;
        goto error_out;
    }

    ret = libxl__domain_create_info_setdefault(gc, &d_config->c_info,
                                               &physinfo);
    if (ret) {
        LOGD(ERROR, domid, "Unable to set domain create info defaults");
        goto error_out;
    }

    bool need_pt = d_config->num_pcidevs || d_config->num_dtdevs;
    if (c_info->passthrough == LIBXL_PASSTHROUGH_DEFAULT) {
        c_info->passthrough = need_pt
            ? LIBXL_PASSTHROUGH_ENABLED : LIBXL_PASSTHROUGH_DISABLED;
    }

    bool iommu_enabled = physinfo.cap_hvm_directio;
    if (c_info->passthrough != LIBXL_PASSTHROUGH_DISABLED && !iommu_enabled) {
        LOGD(ERROR, domid,
             "passthrough not supported on this platform\n");
        ret = ERROR_INVAL;
        goto error_out;
    }

    if (c_info->passthrough == LIBXL_PASSTHROUGH_DISABLED && need_pt) {
        LOGD(ERROR, domid,
             "passthrough disabled but devices are specified");
        ret = ERROR_INVAL;
        goto error_out;
    }

    ret = libxl__arch_passthrough_mode_setdefault(gc,domid,d_config,&physinfo);
    if (ret) goto error_out;

    /* An explicit setting should now have been chosen */
    assert(c_info->passthrough != LIBXL_PASSTHROUGH_DEFAULT);
    assert(c_info->passthrough != LIBXL_PASSTHROUGH_ENABLED);

    /* If target_memkb is smaller than max_memkb, the subsequent call
     * to libxc when building HVM domain will enable PoD mode.
     */
    pod_enabled = (d_config->c_info.type != LIBXL_DOMAIN_TYPE_PV) &&
        (d_config->b_info.target_memkb < d_config->b_info.max_memkb);

    /* We cannot have PoD and PCI device assignment at the same time
     * for HVM guest. It was reported that IOMMU cannot work with PoD
     * enabled because it needs to populated entire page table for
     * guest. To stay on the safe side, we disable PCI device
     * assignment when PoD is enabled.
     */
    if (d_config->c_info.type != LIBXL_DOMAIN_TYPE_PV &&
        d_config->num_pcidevs && pod_enabled) {
        ret = ERROR_INVAL;
        LOGD(ERROR, domid,
             "PCI device assignment for HVM guest failed due to PoD enabled");
        goto error_out;
    }

    /* Disallow PoD and vNUMA to be enabled at the same time because PoD
     * pool is not vNUMA-aware yet.
     */
    if (pod_enabled && d_config->b_info.num_vnuma_nodes) {
        ret = ERROR_INVAL;
        LOGD(ERROR, domid, "Cannot enable PoD and vNUMA at the same time");
        goto error_out;
    }

    /* PV vNUMA is not yet supported because there is an issue with
     * cpuid handling.
     */
    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV &&
        d_config->b_info.num_vnuma_nodes) {
        ret = ERROR_INVAL;
        LOGD(ERROR, domid, "PV vNUMA is not yet supported");
        goto error_out;
    }

    if (d_config->b_info.shadow_memkb == LIBXL_MEMKB_DEFAULT
        && ok_to_default_memkb_in_create(gc))
        d_config->b_info.shadow_memkb =
            libxl_get_required_shadow_memory(d_config->b_info.max_memkb,
                                             d_config->b_info.max_vcpus);

    /* No IOMMU reservation is needed if passthrough mode is not 'sync_pt' */
    if (d_config->b_info.iommu_memkb == LIBXL_MEMKB_DEFAULT
        && ok_to_default_memkb_in_create(gc))
        d_config->b_info.iommu_memkb =
            (d_config->c_info.passthrough == LIBXL_PASSTHROUGH_SYNC_PT)
            ? libxl__get_required_iommu_memory(d_config->b_info.max_memkb)
            : 0;

    ret = libxl__domain_build_info_setdefault(gc, &d_config->b_info);
    if (ret) {
        LOGD(ERROR, domid, "Unable to set domain build info defaults");
        goto error_out;
    }

    if (d_config->c_info.type != LIBXL_DOMAIN_TYPE_PV &&
        (libxl_defbool_val(d_config->b_info.nested_hvm) &&
        ((d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM &&
          libxl_defbool_val(d_config->b_info.u.hvm.altp2m)) ||
        (d_config->b_info.altp2m != LIBXL_ALTP2M_MODE_DISABLED)))) {
        ret = ERROR_INVAL;
        LOGD(ERROR, domid, "nestedhvm and altp2mhvm cannot be used together");
        goto error_out;
    }

    if (((d_config->c_info.type == LIBXL_DOMAIN_TYPE_HVM &&
         libxl_defbool_val(d_config->b_info.u.hvm.altp2m)) ||
        (d_config->c_info.type != LIBXL_DOMAIN_TYPE_PV &&
         d_config->b_info.altp2m != LIBXL_ALTP2M_MODE_DISABLED)) &&
        pod_enabled) {
        ret = ERROR_INVAL;
        LOGD(ERROR, domid, "Cannot enable PoD and ALTP2M at the same time");
        goto error_out;
    }

    ret = 0;
 error_out:
    return ret;
}

static void initiate_domain_create(libxl__egc *egc,
                                   libxl__domain_create_state *dcs)
{
    STATE_AO_GC(dcs->ao);
    uint32_t domid;
    int i, ret;

    /* convenience aliases */
    libxl_domain_config *const d_config = dcs->guest_config;
    const int restore_fd = dcs->restore_fd;

    libxl__xswait_init(&dcs->console_xswait);

    domid = dcs->domid;
    libxl__domain_build_state_init(&dcs->build_state);

    ret = libxl__domain_config_setdefault(gc,d_config,domid);
    if (ret) goto error_out;

    ret = libxl__domain_make(gc, d_config, &dcs->build_state, &domid,
                             dcs->soft_reset);
    if (ret) {
        LOGD(ERROR, domid, "cannot make domain: %d", ret);
        dcs->guest_domid = domid;
        ret = ERROR_FAIL;
        goto error_out;
    }

    dcs->guest_domid = domid;
    dcs->sdss.dm.guest_domid = 0; /* means we haven't spawned */

    /* post-4.13 todo: move these next bits of defaulting to
     * libxl__domain_config_setdefault */

    /*
     * Set the dm version quite early so that libxl doesn't have to pass the
     * build info around just to know if the domain has a device model or not.
     */
    store_libxl_entry(gc, domid, &d_config->b_info);

    for (i = 0; i < d_config->num_disks; i++) {
        ret = libxl__disk_devtype.set_default(gc, domid, &d_config->disks[i],
                                              false);
        if (ret) {
            LOGD(ERROR, domid, "Unable to set disk defaults for disk %d", i);
            goto error_out;
        }
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
    ret = libxl__device_nic_set_devids(gc, d_config, domid);
    if (ret)
        goto error_out;

    if (restore_fd >= 0 || dcs->soft_reset) {
        LOGD(DEBUG, domid, "restoring, not running bootloader");
        domcreate_bootloader_done(egc, &dcs->bl, 0);
    } else  {
        LOGD(DEBUG, domid, "running bootloader");
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
    const int restore_fd = dcs->restore_fd;
    libxl__domain_build_state *const state = &dcs->build_state;
    const int checkpointed_stream = dcs->restore_params.checkpointed_stream;
    libxl__colo_restore_state *const crs = &dcs->crs;
    libxl_domain_build_info *const info = &d_config->b_info;
    libxl__srm_restore_autogen_callbacks *const callbacks =
        &dcs->srs.shs.callbacks.restore.a;

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
    dcs->sdss.dm.spawn.ao = ao;
    dcs->sdss.dm.guest_config = dcs->guest_config;
    dcs->sdss.dm.build_state = &dcs->build_state;
    dcs->sdss.dm.callback = domcreate_devmodel_started;
    dcs->sdss.callback = domcreate_devmodel_started;

    if (restore_fd < 0 && !dcs->soft_reset) {
        rc = libxl__domain_build(gc, d_config, domid, state);
        domcreate_rebuild_done(egc, dcs, rc);
        return;
    }

    /* Prepare environment for domcreate_stream_done */
    dcs->srs.dcs = dcs;

    /* Restore */
    callbacks->restore_results = libxl__srm_callout_callback_restore_results;

    /* COLO only supports HVM now because it does not work very
     * well with pv drivers:
     * 1. We need to resume vm in the slow path. In this case we
     *    need to disconnect/reconnect backend and frontend. It
     *    will take too much time and the performance is very slow.
     * 2. PV disk cannot reuse block replication that is implemented
     *    in QEMU.
     */
    if (info->type != LIBXL_DOMAIN_TYPE_HVM &&
        checkpointed_stream == LIBXL_CHECKPOINTED_STREAM_COLO) {
        LOGD(ERROR, domid, "COLO only supports HVM, unable to restore domain");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__build_pre(gc, domid, d_config, state);
    if (rc)
        goto out;

    dcs->srs.ao = ao;
    dcs->srs.fd = restore_fd;
    dcs->srs.legacy = (dcs->restore_params.stream_version == 1);
    dcs->srs.back_channel = false;
    dcs->srs.completion_callback = domcreate_stream_done;

    if (restore_fd >= 0) {
        switch (checkpointed_stream) {
        case LIBXL_CHECKPOINTED_STREAM_COLO:
            /* colo restore setup */
            crs->ao = ao;
            crs->domid = domid;
            crs->send_back_fd = dcs->send_back_fd;
            crs->recv_fd = restore_fd;
            crs->hvm = (info->type != LIBXL_DOMAIN_TYPE_PV);
            crs->callback = libxl__colo_restore_setup_done;
            libxl__colo_restore_setup(egc, crs);
            break;
        case LIBXL_CHECKPOINTED_STREAM_REMUS:
            libxl__remus_restore_setup(egc, dcs);
            /* fall through */
        case LIBXL_CHECKPOINTED_STREAM_NONE:
            libxl__stream_read_start(egc, &dcs->srs);
        }
        return;
    }

 out:
    domcreate_stream_done(egc, &dcs->srs, rc);
}

static void libxl__colo_restore_setup_done(libxl__egc *egc,
                                           libxl__colo_restore_state *crs,
                                           int rc)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(crs, *dcs, crs);

    EGC_GC;

    if (rc) {
        LOGD(ERROR, dcs->guest_domid, "colo restore setup fails: %d", rc);
        domcreate_stream_done(egc, &dcs->srs, rc);
        return;
    }

    libxl__stream_read_start(egc, &dcs->srs);
}

void libxl__srm_callout_callback_restore_results(xen_pfn_t store_mfn,
          xen_pfn_t console_mfn, void *user)
{
    libxl__save_helper_state *shs = user;
    libxl__domain_create_state *dcs = shs->caller_state;
    STATE_AO_GC(dcs->ao);
    libxl__domain_build_state *const state = &dcs->build_state;

    state->store_mfn =            store_mfn;
    state->console_mfn =          console_mfn;
    shs->need_results =           0;
}

static void domcreate_stream_done(libxl__egc *egc,
                                  libxl__stream_read_state *srs,
                                  int ret)
{
    /* NB perhaps only srs->dcs is valid; eg in the case of an
     * early branch to domcreate_bootloader_done's `out' block */
    libxl__domain_create_state *dcs = srs->dcs;
    STATE_AO_GC(dcs->ao);
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char **vments = NULL, **localents = NULL;
    struct timeval start_time;
    int i, esave;

    /* convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl_domain_build_info *const info = &d_config->b_info;
    libxl__domain_build_state *const state = &dcs->build_state;
    const int fd = dcs->restore_fd;

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
        vments[5] = GCSPRINTF("%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        vments = libxl__calloc(gc, 11, sizeof(char *));
        i = 0;
        vments[i++] = "image/ostype";
        vments[i++] = "linux";
        vments[i++] = "image/kernel";
        vments[i++] = (char *) state->pv_kernel.path;
        vments[i++] = "start_time";
        vments[i++] = GCSPRINTF("%lu.%02d", start_time.tv_sec,(int)start_time.tv_usec/10000);
        if (state->pv_ramdisk.path) {
            vments[i++] = "image/ramdisk";
            vments[i++] = (char *) state->pv_ramdisk.path;
        }
        if (state->pv_cmdline) {
            vments[i++] = "image/cmdline";
            vments[i++] = (char *) state->pv_cmdline;
        }
        break;
    case LIBXL_DOMAIN_TYPE_PVH:
        vments = libxl__calloc(gc, 3, sizeof(char *));
        vments[0] = "start_time";
        vments[1] = GCSPRINTF("%"PRIu64".%02ld",
                              (uint64_t)start_time.tv_sec,
                              (long)start_time.tv_usec/10000);
        break;
    default:
        ret = ERROR_INVAL;
        goto out;
    }

    /*
     * The scheduler on the sending domain may be different than the
     * scheduler running here.  Setting the scheduler to UNKNOWN will
     * cause the code to take to take whatever parameters are
     * available in that scheduler, while discarding the rest.
     */
    info->sched_params.sched = LIBXL_SCHEDULER_UNKNOWN;

    ret = libxl__build_post(gc, domid, info, state, vments, localents);
    if (ret)
        goto out;

    if (info->type == LIBXL_DOMAIN_TYPE_HVM) {
        state->saved_state = GCSPRINTF(
                       LIBXL_DEVICE_MODEL_RESTORE_FILE".%d", domid);
    }

out:
    if (info->type == LIBXL_DOMAIN_TYPE_PV) {
        libxl__file_reference_unmap(&state->pv_kernel);
        libxl__file_reference_unmap(&state->pv_ramdisk);
    }

    /* fd == -1 here means we're doing soft reset. */
    if (fd != -1) {
        esave = errno;
        libxl_fd_set_nonblock(ctx, fd, 0);
        errno = esave;
    }
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

    if (ret) {
        LOGD(ERROR, domid, "cannot (re-)build domain: %d", ret);
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
        LOGD(ERROR, domid, "unable to add disk devices");
        goto error_out;
    }

    for (i = 0; i < d_config->b_info.num_ioports; i++) {
        libxl_ioport_range *io = &d_config->b_info.ioports[i];

        LOGD(DEBUG, domid, "ioports %"PRIx32"-%"PRIx32,
             io->first, io->first + io->number - 1);

        ret = xc_domain_ioport_permission(CTX->xch, domid,
                                          io->first, io->number, 1);
        if (ret < 0) {
            LOGED(ERROR, domid,
                  "failed give domain access to ioports %"PRIx32"-%"PRIx32,
                  io->first, io->first + io->number - 1);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }

    for (i = 0; i < d_config->b_info.num_irqs; i++) {
        int irq = d_config->b_info.irqs[i];

        LOGD(DEBUG, domid, "irq %d", irq);

        ret = irq >= 0 ? libxl__arch_domain_map_irq(gc, domid, irq)
                       : -EOVERFLOW;
        if (ret) {
            LOGED(ERROR, domid, "failed give domain access to irq %d", irq);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }

    for (i = 0; i < d_config->b_info.num_iomem; i++) {
        libxl_iomem_range *io = &d_config->b_info.iomem[i];

        LOGD(DEBUG, domid, "iomem %"PRIx64"-%"PRIx64,
             io->start, io->start + io->number - 1);

        ret = xc_domain_iomem_permission(CTX->xch, domid,
                                          io->start, io->number, 1);
        if (ret < 0) {
            LOGED(ERROR, domid,
                  "failed give domain access to iomem range %"PRIx64"-%"PRIx64,
                  io->start, io->start + io->number - 1);
            ret = ERROR_FAIL;
            goto error_out;
        }
        ret = xc_domain_memory_mapping(CTX->xch, domid,
                                       io->gfn, io->start,
                                       io->number, 1);
        if (ret < 0) {
            LOGED(ERROR, domid,
                  "failed to map to domain iomem range %"PRIx64"-%"PRIx64
                  " to guest address %"PRIx64,
                  io->start, io->start + io->number - 1, io->gfn);
            ret = ERROR_FAIL;
            goto error_out;
        }
    }

    /* For both HVM and PV the 0th console is a regular console. We
       map channels to IOEMU consoles starting at 1 */
    for (i = 0; i < d_config->num_channels; i++) {
        libxl__device_console console;
        libxl__device device;
        ret = libxl__init_console_from_channel(gc, &console, i + 1,
                                               &d_config->channels[i]);
        if ( ret ) {
            libxl__device_console_dispose(&console);
            goto error_out;
        }
        libxl__device_console_add(gc, domid, &console, NULL, &device);
        libxl__device_console_dispose(&console);
    }

    for (i = 0; i < d_config->num_p9s; i++)
        libxl__device_add(gc, domid, &libxl__p9_devtype, &d_config->p9s[i]);

    for (i = 0; i < d_config->num_pvcallsifs; i++)
        libxl__device_add(gc, domid, &libxl__pvcallsif_devtype,
                          &d_config->pvcallsifs[i]);

    switch (d_config->c_info.type) {
    case LIBXL_DOMAIN_TYPE_HVM:
    {
        libxl__device_console console;
        libxl__device device;
        libxl_device_vkb vkb;

        init_console_info(gc, &console, 0);
        console.backend_domid = state->console_domid;
        libxl__device_console_add(gc, domid, &console, state, &device);
        libxl__device_console_dispose(&console);

        if (libxl_defbool_val(d_config->b_info.u.hvm.vkb_device)) {
            libxl_device_vkb_init(&vkb);
            libxl__device_add(gc, domid, &libxl__vkb_devtype, &vkb);
            libxl_device_vkb_dispose(&vkb);
        }

        dcs->sdss.dm.guest_domid = domid;
        if (libxl_defbool_val(d_config->b_info.device_model_stubdomain))
            libxl__spawn_stub_dm(egc, &dcs->sdss);
        else
            libxl__spawn_local_dm(egc, &dcs->sdss.dm);

        /*
         * Handle the domain's (and the related stubdomain's) access to
         * the VGA framebuffer.
         */
        ret = libxl__grant_vga_iomem_permission(gc, domid, d_config);
        if ( ret )
            goto error_out;

        return;
    }
    case LIBXL_DOMAIN_TYPE_PV:
    case LIBXL_DOMAIN_TYPE_PVH:
    {
        libxl__device_console console, vuart;
        libxl__device device;

        for (i = 0; i < d_config->num_vfbs; i++) {
            libxl__device_add(gc, domid, &libxl__vfb_devtype,
                              &d_config->vfbs[i]);
        }

        for (i = 0; i < d_config->num_vkbs; i++) {
            libxl__device_add(gc, domid, &libxl__vkb_devtype,
                              &d_config->vkbs[i]);
        }

        if (d_config->b_info.arch_arm.vuart == LIBXL_VUART_TYPE_SBSA_UART) {
            init_console_info(gc, &vuart, 0);
            vuart.backend_domid = state->console_domid;
            libxl__device_vuart_add(gc, domid, &vuart, state);
            libxl__device_console_dispose(&vuart);
        }

        init_console_info(gc, &console, 0);
        console.backend_domid = state->console_domid;
        libxl__device_console_add(gc, domid, &console, state, &device);
        libxl__device_console_dispose(&console);

        ret = libxl__need_xenpv_qemu(gc, d_config);
        if (ret < 0)
            goto error_out;
        if (ret) {
            dcs->sdss.dm.guest_domid = domid;
            libxl__spawn_local_dm(egc, &dcs->sdss.dm);
            return;
        } else {
            assert(!dcs->sdss.dm.guest_domid);
            domcreate_devmodel_started(egc, &dcs->sdss.dm, 0);
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

static void libxl__add_dtdevs(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                              libxl_domain_config *d_config,
                              libxl__multidev *multidev)
{
    AO_GC;
    libxl__ao_device *aodev = libxl__multidev_prepare(multidev);
    int i, rc = 0;

    for (i = 0; i < d_config->num_dtdevs; i++) {
        const libxl_device_dtdev *dtdev = &d_config->dtdevs[i];

        LOGD(DEBUG, domid, "Assign device \"%s\" to domain", dtdev->path);
        rc = xc_assign_dt_device(CTX->xch, domid, dtdev->path);
        if (rc < 0) {
            LOGD(ERROR, domid, "xc_assign_dtdevice failed: %d", rc);
            goto out;
        }
    }

out:
    aodev->rc = rc;
    aodev->callback(egc, aodev);
}

#define libxl_device_dtdev_list NULL
#define libxl_device_dtdev_compare NULL
#define libxl__device_from_dtdev NULL
#define libxl__device_dtdev_setdefault NULL
#define libxl__device_dtdev_update_devid NULL
static DEFINE_DEVICE_TYPE_STRUCT(dtdev, NONE);

const libxl__device_type *device_type_tbl[] = {
    &libxl__disk_devtype,
    &libxl__nic_devtype,
    &libxl__vtpm_devtype,
    &libxl__usbctrl_devtype,
    &libxl__usbdev_devtype,
    &libxl__pcidev_devtype,
    &libxl__dtdev_devtype,
    &libxl__vdispl_devtype,
    &libxl__vsnd_devtype,
    NULL
};

static void domcreate_devmodel_started(libxl__egc *egc,
                                       libxl__dm_spawn_state *dmss,
                                       int ret)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(dmss, *dcs, sdss.dm);
    STATE_AO_GC(dmss->spawn.ao);
    int domid = dcs->guest_domid;

    if (ret) {
        LOGD(ERROR, domid, "device model did not start: %d", ret);
        goto error_out;
    }

    dcs->device_type_idx = -1;
    domcreate_attach_devices(egc, &dcs->multidev, 0);
    return;

error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void domcreate_attach_devices(libxl__egc *egc,
                                     libxl__multidev *multidev,
                                     int ret)
{
    libxl__domain_create_state *dcs = CONTAINER_OF(multidev, *dcs, multidev);
    STATE_AO_GC(dcs->ao);
    int domid = dcs->guest_domid;
    libxl_domain_config *const d_config = dcs->guest_config;
    const libxl__device_type *dt;
    char *tty_path;

    if (ret) {
        LOGD(ERROR, domid, "unable to add %s devices",
             libxl__device_kind_to_string(device_type_tbl[dcs->device_type_idx]->type));
        goto error_out;
    }

    dcs->device_type_idx++;
    dt = device_type_tbl[dcs->device_type_idx];
    if (dt) {
        if (*libxl__device_type_get_num(dt, d_config) > 0 && !dt->skip_attach) {
            /* Attach devices */
            libxl__multidev_begin(ao, &dcs->multidev);
            dcs->multidev.callback = domcreate_attach_devices;
            dt->add(egc, ao, domid, d_config, &dcs->multidev);
            libxl__multidev_prepared(egc, &dcs->multidev, 0);
            return;
        }

        domcreate_attach_devices(egc, &dcs->multidev, 0);
        return;
    }

    ret = libxl__console_tty_path(gc, domid, 0, LIBXL_CONSOLE_TYPE_PV, &tty_path);
    if (ret) {
        LOG(ERROR, "failed to get domain %d console tty path",
            domid);
        goto error_out;
    }

    dcs->console_xswait.ao = ao;
    dcs->console_xswait.what = GCSPRINTF("domain %d console tty", domid);
    dcs->console_xswait.path = tty_path;
    dcs->console_xswait.timeout_ms = LIBXL_INIT_TIMEOUT * 1000;
    dcs->console_xswait.callback = console_xswait_callback;
    ret = libxl__xswait_start(gc, &dcs->console_xswait);
    if (ret) {
        LOG(ERROR, "unable to set up watch for domain %d console tty path",
            domid);
        goto error_out;
    }

    return;

error_out:
    assert(ret);
    domcreate_complete(egc, dcs, ret);
}

static void console_xswait_callback(libxl__egc *egc, libxl__xswait_state *xswa,
                                    int rc, const char *p)
{
    EGC_GC;
    libxl__domain_create_state *dcs = CONTAINER_OF(xswa, *dcs, console_xswait);

    if (rc) {
        if (rc == ERROR_TIMEDOUT)
            LOG(ERROR, "%s: timed out", xswa->what);
        goto out;
    }

    if (p && p[0] != '\0') {
        domcreate_console_available(egc, dcs);
        goto out;
    }

    return;

out:
    libxl__xswait_stop(gc, xswa);
    domcreate_complete(egc, dcs, rc);
}

static void domcreate_complete(libxl__egc *egc,
                               libxl__domain_create_state *dcs,
                               int rc)
{
    STATE_AO_GC(dcs->ao);
    libxl_domain_config *const d_config = dcs->guest_config;
    libxl_domain_config *d_config_saved = &dcs->guest_config_saved;

    libxl__xswait_stop(gc, &dcs->console_xswait);

    libxl__domain_build_state_dispose(&dcs->build_state);

    if (!rc && d_config->b_info.exec_ssidref)
        rc = xc_flask_relabel_domain(CTX->xch, dcs->guest_domid, d_config->b_info.exec_ssidref);

    bool retain_domain = !rc || rc == ERROR_ABORTED;

    if (retain_domain) {
        libxl__flock *lock;

        /* Note that we hold CTX lock at this point so only need to
         * take data store lock
         */
        lock = libxl__lock_domain_userdata(gc, dcs->guest_domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
        } else {
            libxl__update_domain_configuration(gc, d_config_saved, d_config);
            int cfg_rc = libxl__set_domain_configuration
                (gc, dcs->guest_domid, d_config_saved);
            if (!rc)
                rc = cfg_rc;
            libxl__unlock_file(lock);
        }
    }

    libxl_domain_config_dispose(d_config_saved);

    if (!retain_domain) {
        if (dcs->guest_domid > 0) {
            dcs->dds.ao = ao;
            dcs->dds.domid = dcs->guest_domid;
            dcs->dds.callback = domcreate_destruction_cb;
            libxl__domain_destroy(egc, &dcs->dds);
            return;
        }
        dcs->guest_domid = INVALID_DOMID;
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
        LOGD(ERROR, dds->domid, "unable to destroy domain following failed creation");

    dcs->callback(egc, dcs, ERROR_FAIL, dcs->guest_domid);
}

/*----- application-facing domain creation interface -----*/

typedef struct {
    libxl__domain_create_state dcs;
    uint32_t *domid_out;
} libxl__app_domain_create_state;

typedef struct {
    libxl__app_domain_create_state cdcs;
    libxl__domain_destroy_state dds;
    libxl__domain_save_state dss;
    char *toolstack_buf;
    uint32_t toolstack_len;
} libxl__domain_soft_reset_state;

static void domain_create_cb(libxl__egc *egc,
                             libxl__domain_create_state *dcs,
                             int rc, uint32_t domid);

static int do_domain_create(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid, int restore_fd, int send_back_fd,
                            const libxl_domain_restore_params *params,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how)
{
    AO_CREATE(ctx, 0, ao_how);
    libxl__app_domain_create_state *cdcs;
    int rc;

    GCNEW(cdcs);
    cdcs->dcs.ao = ao;
    cdcs->dcs.guest_config = d_config;
    libxl_domain_config_init(&cdcs->dcs.guest_config_saved);
    libxl_domain_config_copy(ctx, &cdcs->dcs.guest_config_saved, d_config);
    cdcs->dcs.restore_fd = cdcs->dcs.libxc_fd = restore_fd;
    cdcs->dcs.send_back_fd = send_back_fd;
    if (restore_fd >= 0) {
        cdcs->dcs.restore_params = *params;
        rc = libxl__fd_flags_modify_save(gc, cdcs->dcs.restore_fd,
                                         ~(O_NONBLOCK|O_NDELAY), 0,
                                         &cdcs->dcs.restore_fdfl);
        if (rc < 0) goto out_err;
    }
    cdcs->dcs.callback = domain_create_cb;
    cdcs->dcs.domid = INVALID_DOMID;
    cdcs->dcs.soft_reset = false;

    if (cdcs->dcs.restore_params.checkpointed_stream ==
        LIBXL_CHECKPOINTED_STREAM_COLO) {
        cdcs->dcs.colo_proxy_script =
            cdcs->dcs.restore_params.colo_proxy_script;
        cdcs->dcs.crs.cps.is_userspace_proxy =
            libxl_defbool_val(cdcs->dcs.restore_params.userspace_colo_proxy);
    } else {
        cdcs->dcs.colo_proxy_script = NULL;
        cdcs->dcs.crs.cps.is_userspace_proxy = false;
    }

    libxl__ao_progress_gethow(&cdcs->dcs.aop_console_how, aop_console_how);
    cdcs->domid_out = domid;

    initiate_domain_create(egc, &cdcs->dcs);

    return AO_INPROGRESS;

 out_err:
    return AO_CREATE_FAIL(rc);

}

static void domain_soft_reset_cb(libxl__egc *egc,
                                 libxl__domain_destroy_state *dds,
                                 int rc)
{
    STATE_AO_GC(dds->ao);
    libxl__domain_soft_reset_state *srs = CONTAINER_OF(dds, *srs, dds);
    libxl__app_domain_create_state *cdcs = &srs->cdcs;
    char *savefile, *restorefile;

    if (rc) {
        LOGD(ERROR, dds->domid, "destruction of domain failed.");
        goto error;
    }

    cdcs->dcs.guest_domid = dds->domid;
    rc = libxl__restore_emulator_xenstore_data(&cdcs->dcs, srs->toolstack_buf,
                                               srs->toolstack_len);
    if (rc) {
        LOGD(ERROR, dds->domid, "failed to restore toolstack record.");
        goto error;
    }

    if (cdcs->dcs.guest_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM) {
        savefile = GCSPRINTF(LIBXL_DEVICE_MODEL_SAVE_FILE".%d", dds->domid);
        restorefile = GCSPRINTF(LIBXL_DEVICE_MODEL_RESTORE_FILE".%d",
                                dds->domid);
        rc = rename(savefile, restorefile);
        if (rc) {
            LOGD(ERROR, dds->domid, "failed to rename dm save file.");
            goto error;
        }
    }

    initiate_domain_create(egc, &cdcs->dcs);
    return;

error:
    domcreate_complete(egc, &cdcs->dcs, rc);
}

static void soft_reset_dm_suspended(libxl__egc *egc,
                                    libxl__domain_suspend_state *dsps,
                                    int rc);
static int do_domain_soft_reset(libxl_ctx *ctx,
                                libxl_domain_config *d_config,
                                uint32_t domid,
                                const libxl_asyncop_how *ao_how,
                                const libxl_asyncprogress_how
                                *aop_console_how)
{
    AO_CREATE(ctx, 0, ao_how);
    libxl__domain_soft_reset_state *srs;
    libxl__app_domain_create_state *cdcs;
    libxl__domain_create_state *dcs;
    libxl__domain_build_state *state;
    libxl__domain_save_state *dss;
    const char *console_tty, *xs_store_mfn, *xs_console_mfn;
    char *dom_path;
    uint32_t domid_out;
    int rc;

    GCNEW(srs);
    cdcs = &srs->cdcs;
    dcs = &cdcs->dcs;
    state = &dcs->build_state;
    dss = &srs->dss;

    srs->cdcs.dcs.ao = ao;
    srs->cdcs.dcs.guest_config = d_config;
    libxl_domain_config_init(&srs->cdcs.dcs.guest_config_saved);
    libxl_domain_config_copy(ctx, &srs->cdcs.dcs.guest_config_saved,
                             d_config);
    cdcs->dcs.restore_fd = -1;
    cdcs->dcs.domid = domid;
    cdcs->dcs.soft_reset = true;
    cdcs->dcs.callback = domain_create_cb;
    libxl__ao_progress_gethow(&srs->cdcs.dcs.aop_console_how,
                              aop_console_how);
    cdcs->domid_out = &domid_out;

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        LOGD(ERROR, domid, "failed to read domain path");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/store/ring-ref", dom_path),
                                &xs_store_mfn);
    if (rc) {
        LOGD(ERROR, domid, "failed to read store/ring-ref.");
        goto out;
    }
    state->store_mfn = xs_store_mfn ? atol(xs_store_mfn): 0;

    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/console/ring-ref", dom_path),
                                &xs_console_mfn);
    if (rc) {
        LOGD(ERROR, domid, "failed to read console/ring-ref.");
        goto out;
    }
    state->console_mfn = xs_console_mfn ? atol(xs_console_mfn): 0;

    rc = libxl__xs_read_mandatory(gc, XBT_NULL,
                                  GCSPRINTF("%s/console/tty", dom_path),
                                  &console_tty);
    if (rc) {
        LOGD(ERROR, domid, "failed to read console/tty.");
        goto out;
    }
    state->console_tty = libxl__strdup(gc, console_tty);

    dss->ao = ao;
    dss->domid = dss->dsps.domid = domid;
    dss->dsps.dm_savefile = GCSPRINTF(LIBXL_DEVICE_MODEL_SAVE_FILE".%d",
                                      domid);

    rc = libxl__save_emulator_xenstore_data(dss, &srs->toolstack_buf,
                                            &srs->toolstack_len);
    if (rc) {
        LOGD(ERROR, domid, "failed to save toolstack record.");
        goto out;
    }

    dss->dsps.ao = ao;
    dss->dsps.callback_device_model_done = soft_reset_dm_suspended;
    libxl__domain_suspend_device_model(egc, &dss->dsps); /* must be last */

    return AO_INPROGRESS;

 out:
    return AO_CREATE_FAIL(rc);
}

static void soft_reset_dm_suspended(libxl__egc *egc,
                                    libxl__domain_suspend_state *dsps,
                                    int rc)
{
    STATE_AO_GC(dsps->ao);
    libxl__domain_soft_reset_state *srs =
        CONTAINER_OF(dsps, *srs, dss.dsps);
    libxl__app_domain_create_state *cdcs = &srs->cdcs;

    /*
     * Ask all backends to disconnect by removing the domain from
     * xenstore. On the creation path the domain will be introduced to
     * xenstore again with probably different store/console/...
     * channels.
     */
    xs_release_domain(CTX->xsh, cdcs->dcs.domid);

    srs->dds.ao = ao;
    srs->dds.domid = cdcs->dcs.domid;
    srs->dds.callback = domain_soft_reset_cb;
    srs->dds.soft_reset = true;
    libxl__domain_destroy(egc, &srs->dds);
}

static void domain_create_cb(libxl__egc *egc,
                             libxl__domain_create_state *dcs,
                             int rc, uint32_t domid)
{
    libxl__app_domain_create_state *cdcs = CONTAINER_OF(dcs, *cdcs, dcs);
    int flrc;
    STATE_AO_GC(cdcs->dcs.ao);

    *cdcs->domid_out = domid;

    if (dcs->restore_fd >= 0) {
        flrc = libxl__fd_flags_restore(gc,
                dcs->restore_fd, dcs->restore_fdfl);
        /*
         * If restore has failed already then report that error not
         * this one.
         */
        if (flrc && !rc) rc = flrc;
    }

    libxl__ao_complete(egc, ao, rc);
}


static void set_disk_colo_restore(libxl_domain_config *d_config)
{
    int i;

    for (i = 0; i < d_config->num_disks; i++)
        libxl_defbool_set(&d_config->disks[i].colo_restore_enable, true);
}

static void unset_disk_colo_restore(libxl_domain_config *d_config)
{
    int i;

    for (i = 0; i < d_config->num_disks; i++)
        libxl_defbool_set(&d_config->disks[i].colo_restore_enable, false);
}

int libxl_domain_create_new(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how)
{
    unset_disk_colo_restore(d_config);
    return do_domain_create(ctx, d_config, domid, -1, -1, NULL,
                            ao_how, aop_console_how);
}

int libxl_domain_create_restore(libxl_ctx *ctx, libxl_domain_config *d_config,
                                uint32_t *domid, int restore_fd,
                                int send_back_fd,
                                const libxl_domain_restore_params *params,
                                const libxl_asyncop_how *ao_how,
                                const libxl_asyncprogress_how *aop_console_how)
{
    if (params->checkpointed_stream == LIBXL_CHECKPOINTED_STREAM_COLO) {
        set_disk_colo_restore(d_config);
    } else {
        unset_disk_colo_restore(d_config);
    }

    return do_domain_create(ctx, d_config, domid, restore_fd, send_back_fd,
                            params, ao_how, aop_console_how);
}

int libxl_domain_soft_reset(libxl_ctx *ctx,
                            libxl_domain_config *d_config,
                            uint32_t domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how
                            *aop_console_how)
{
    libxl_domain_build_info *const info = &d_config->b_info;

    if (info->type != LIBXL_DOMAIN_TYPE_HVM) return ERROR_INVAL;

    return do_domain_soft_reset(ctx, d_config, domid, ao_how,
                                aop_console_how);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
