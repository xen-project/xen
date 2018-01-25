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

#include <xc_dom.h>
#include <xen/hvm/e820.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

static const char *libxl_tapif_script(libxl__gc *gc)
{
#if defined(__linux__) || defined(__FreeBSD__)
    return libxl__strdup(gc, "no");
#else
    return GCSPRINTF("%s/qemu-ifup", libxl__xen_script_dir_path());
#endif
}

const char *libxl__device_model_savefile(libxl__gc *gc, uint32_t domid)
{
    return GCSPRINTF(LIBXL_DEVICE_MODEL_SAVE_FILE".%d", domid);
}

static const char *qemu_xen_path(libxl__gc *gc)
{
    return QEMU_XEN_PATH;
}

static int libxl__create_qemu_logfile(libxl__gc *gc, char *name)
{
    char *logfile;
    int rc, logfile_w;

    rc = libxl_create_logfile(CTX, name, &logfile);
    if (rc) return rc;

    logfile_w = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);

    if (logfile_w < 0) {
        LOGE(ERROR, "unable to open Qemu logfile: %s", logfile);
        free(logfile);
        return ERROR_FAIL;
    }

    free(logfile);

    return logfile_w;
}

const char *libxl__domain_device_model(libxl__gc *gc,
                                       const libxl_domain_build_info *info)
{
    const char *dm;

    if (libxl_defbool_val(info->device_model_stubdomain))
        return NULL;

    if (info->device_model) {
        dm = libxl__strdup(gc, info->device_model);
    } else {
        switch (info->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            dm = libxl__abs_path(gc, "qemu-dm", libxl__private_bindir_path());
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            dm = qemu_xen_path(gc);
            break;
        default:
            LOG(ERROR, "invalid device model version %d",
                info->device_model_version);
            dm = NULL;
            break;
        }
    }
    return dm;
}

static int
libxl__xc_device_get_rdm(libxl__gc *gc,
                         uint32_t flags,
                         uint16_t seg,
                         uint8_t bus,
                         uint8_t devfn,
                         unsigned int *nr_entries,
                         struct xen_reserved_device_memory **xrdm)
{
    int rc = 0, r;

    /*
     * We really can't presume how many entries we can get in advance.
     */
    *nr_entries = 0;
    r = xc_reserved_device_memory_map(CTX->xch, flags, seg, bus, devfn,
                                      NULL, nr_entries);
    assert(r <= 0);
    /* "0" means we have no any rdm entry. */
    if (!r) goto out;

    if (errno != ENOBUFS) {
        rc = ERROR_FAIL;
        goto out;
    }

    GCNEW_ARRAY(*xrdm, *nr_entries);
    r = xc_reserved_device_memory_map(CTX->xch, flags, seg, bus, devfn,
                                      *xrdm, nr_entries);
    if (r)
        rc = ERROR_FAIL;

 out:
    if (rc) {
        *nr_entries = 0;
        *xrdm = NULL;
        LOG(ERROR, "Could not get reserved device memory maps.");
    }
    return rc;
}

/*
 * Check whether there exists rdm hole in the specified memory range.
 * Returns true if exists, else returns false.
 */
static bool overlaps_rdm(uint64_t start, uint64_t memsize,
                         uint64_t rdm_start, uint64_t rdm_size)
{
    return (start + memsize > rdm_start) && (start < rdm_start + rdm_size);
}

static void
add_rdm_entry(libxl__gc *gc, libxl_domain_config *d_config,
              uint64_t rdm_start, uint64_t rdm_size, int rdm_policy)
{
    d_config->rdms = libxl__realloc(NOGC, d_config->rdms,
                    (d_config->num_rdms+1) * sizeof(libxl_device_rdm));

    d_config->rdms[d_config->num_rdms].start = rdm_start;
    d_config->rdms[d_config->num_rdms].size = rdm_size;
    d_config->rdms[d_config->num_rdms].policy = rdm_policy;
    d_config->num_rdms++;
}

/*
 * Check reported RDM regions and handle potential gfn conflicts according
 * to user preferred policy.
 *
 * RDM can reside in address space beyond 4G theoretically, but we never
 * see this in real world. So in order to avoid breaking highmem layout
 * we don't solve highmem conflict. Note this means highmem rmrr could
 * still be supported if no conflict.
 *
 * But in the case of lowmem, RDM probably scatter the whole RAM space.
 * Especially multiple RDM entries would worsen this to lead a complicated
 * memory layout. And then its hard to extend hvm_info_table{} to work
 * hvmloader out. So here we're trying to figure out a simple solution to
 * avoid breaking existing layout. So when a conflict occurs,
 *
 * #1. Above a predefined boundary (default 2G)
 * - Move lowmem_end below reserved region to solve conflict;
 *
 * #2. Below a predefined boundary (default 2G)
 * - Check strict/relaxed policy.
 * "strict" policy leads to fail libxl.
 * "relaxed" policy issue a warning message and also mask this entry
 * INVALID to indicate we shouldn't expose this entry to hvmloader.
 * Note when both policies are specified on a given region, the per-device
 * policy should override the global policy.
 */
int libxl__domain_device_construct_rdm(libxl__gc *gc,
                                       libxl_domain_config *d_config,
                                       uint64_t rdm_mem_boundary,
                                       struct xc_dom_image *dom)
{
    int i, j, conflict, rc;
    struct xen_reserved_device_memory *xrdm = NULL;
    uint32_t strategy = d_config->b_info.u.hvm.rdm.strategy;
    uint16_t seg;
    uint8_t bus, devfn;
    uint64_t rdm_start, rdm_size;
    uint64_t highmem_end = dom->highmem_end ? dom->highmem_end : (1ull<<32);

    /*
     * We just want to construct RDM once since RDM is specific to the
     * given platform, so this shouldn't change again.
     */
    if (d_config->num_rdms)
        return 0;

    /* Might not expose rdm. */
    if (strategy == LIBXL_RDM_RESERVE_STRATEGY_IGNORE &&
        !d_config->num_pcidevs)
        return 0;

    /* Query all RDM entries in this platform */
    if (strategy == LIBXL_RDM_RESERVE_STRATEGY_HOST) {
        unsigned int nr_entries;

        /* Collect all rdm info if exist. */
        rc = libxl__xc_device_get_rdm(gc, XENMEM_RDM_ALL,
                                      0, 0, 0, &nr_entries, &xrdm);
        if (rc)
            goto out;
        if (!nr_entries)
            return 0;

        assert(xrdm);

        for (i = 0; i < nr_entries; i++)
        {
            add_rdm_entry(gc, d_config,
                          pfn_to_paddr(xrdm[i].start_pfn),
                          pfn_to_paddr(xrdm[i].nr_pages),
                          d_config->b_info.u.hvm.rdm.policy);
        }
    }

    /* Query RDM entries per-device */
    for (i = 0; i < d_config->num_pcidevs; i++) {
        unsigned int nr_entries;
        bool new = true;

        seg = d_config->pcidevs[i].domain;
        bus = d_config->pcidevs[i].bus;
        devfn = PCI_DEVFN(d_config->pcidevs[i].dev,
                          d_config->pcidevs[i].func);
        nr_entries = 0;
        rc = libxl__xc_device_get_rdm(gc, 0,
                                      seg, bus, devfn, &nr_entries, &xrdm);
        if (rc)
            goto out;
        /* No RDM to associated with this device. */
        if (!nr_entries)
            continue;

        assert(xrdm);

        /*
         * Need to check whether this entry is already saved in the array.
         * This could come from two cases:
         *
         *   - user may configure to get all RDMs in this platform, which
         *   is already queried before this point
         *   - or two assigned devices may share one RDM entry
         *
         * Different policies may be configured on the same RDM due to
         * above two cases. But we don't allow to assign such a group
         * devies right now so it doesn't come true in our case.
         */
        for (j = 0; j < d_config->num_rdms; j++) {
            if (d_config->rdms[j].start == pfn_to_paddr(xrdm[0].start_pfn))
            {
                /*
                 * So the per-device policy always override the global
                 * policy in this case.
                 */
                d_config->rdms[j].policy = d_config->pcidevs[i].rdm_policy;
                new = false;
                break;
            }
        }

        if (new) {
            add_rdm_entry(gc, d_config,
                          pfn_to_paddr(xrdm[0].start_pfn),
                          pfn_to_paddr(xrdm[0].nr_pages),
                          d_config->pcidevs[i].rdm_policy);
        }
    }

    /*
     * Next step is to check and avoid potential conflict between RDM
     * entries and guest RAM. To avoid intrusive impact to existing
     * memory layout {lowmem, mmio, highmem} which is passed around
     * various function blocks, below conflicts are not handled which
     * are rare and handling them would lead to a more scattered
     * layout:
     *  - RDM  in highmem area (>4G)
     *  - RDM lower than a defined memory boundary (e.g. 2G)
     * Otherwise for conflicts between boundary and 4G, we'll simply
     * move lowmem end below reserved region to solve conflict.
     *
     * If a conflict is detected on a given RDM entry, an error will
     * be returned if 'strict' policy is specified. Instead, if
     * 'relaxed' policy specified, this conflict is treated just as a
     * warning, but we mark this RDM entry as INVALID to indicate that
     * this entry shouldn't be exposed to hvmloader.
     *
     * Firstly we should check the case of rdm < 4G because we may
     * need to expand highmem_end.
     */
    for (i = 0; i < d_config->num_rdms; i++) {
        rdm_start = d_config->rdms[i].start;
        rdm_size = d_config->rdms[i].size;
        conflict = overlaps_rdm(0, dom->lowmem_end, rdm_start, rdm_size);

        if (!conflict)
            continue;

        /* Just check if RDM > our memory boundary. */
        if (rdm_start > rdm_mem_boundary) {
            /*
             * We will move downwards lowmem_end so we have to expand
             * highmem_end.
             */
            highmem_end += (dom->lowmem_end - rdm_start);
            /* Now move downwards lowmem_end. */
            dom->lowmem_end = rdm_start;
        }
    }

    /* Sync highmem_end. */
    dom->highmem_end = highmem_end;

    /*
     * Finally we can take same policy to check lowmem(< 2G) and
     * highmem adjusted above.
     */
    for (i = 0; i < d_config->num_rdms; i++) {
        rdm_start = d_config->rdms[i].start;
        rdm_size = d_config->rdms[i].size;
        /* Does this entry conflict with lowmem? */
        conflict = overlaps_rdm(0, dom->lowmem_end,
                                rdm_start, rdm_size);
        /* Does this entry conflict with highmem? */
        conflict |= overlaps_rdm((1ULL<<32),
                                 dom->highmem_end - (1ULL<<32),
                                 rdm_start, rdm_size);

        if (!conflict)
            continue;

        if (d_config->rdms[i].policy == LIBXL_RDM_RESERVE_POLICY_STRICT) {
            LOG(ERROR, "RDM conflict at 0x%"PRIx64".\n",
                       d_config->rdms[i].start);
            goto out;
        } else {
            LOG(WARN, "Ignoring RDM conflict at 0x%"PRIx64".\n",
                      d_config->rdms[i].start);

            /*
             * Then mask this INVALID to indicate we shouldn't expose this
             * to hvmloader.
             */
            d_config->rdms[i].policy = LIBXL_RDM_RESERVE_POLICY_INVALID;
        }
    }

    return 0;

 out:
    return ERROR_FAIL;
}

/* XSA-180 / CVE-2014-3672
 *
 * The QEMU shipped with Xen has a bodge. It checks for
 * XEN_QEMU_CONSOLE_LIMIT to see how much data QEMU is allowed
 * to write to stderr. We set that to 1MB if it is not set by
 * system administrator.
 */
static void libxl__set_qemu_env_for_xsa_180(libxl__gc *gc,
                                            flexarray_t *dm_envs)
{
    if (getenv("XEN_QEMU_CONSOLE_LIMIT")) return;
    flexarray_append_pair(dm_envs, "XEN_QEMU_CONSOLE_LIMIT", "1048576");
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

static int libxl__build_device_model_args_old(libxl__gc *gc,
                                        const char *dm, int domid,
                                        const libxl_domain_config *guest_config,
                                        char ***args, char ***envs,
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
    flexarray_t *dm_args, *dm_envs;
    dm_args = flexarray_make(gc, 16, 1);
    dm_envs = flexarray_make(gc, 16, 1);

    libxl__set_qemu_env_for_xsa_180(gc, dm_envs);

    flexarray_vappend(dm_args, dm,
                      "-d", GCSPRINTF("%d", domid), NULL);

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
                    LOGD(ERROR, domid, "vncdisplay set, vnclisten contains display");
                    return ERROR_INVAL;
                }
                vncarg = vnc->listen;
            } else {
                vncarg = GCSPRINTF("%s:%d", vnc->listen, vnc->display);
            }
        } else
            vncarg = GCSPRINTF("127.0.0.1:%d", vnc->display);

        if (vnc->passwd && vnc->passwd[0]) {
            vncarg = GCSPRINTF("%s,password", vncarg);
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
        if (sdl->display)
            flexarray_append_pair(dm_envs, "DISPLAY", sdl->display);
        if (sdl->xauthority)
            flexarray_append_pair(dm_envs, "XAUTHORITY", sdl->xauthority);
    }
    if (keymap) {
        flexarray_vappend(dm_args, "-k", keymap, NULL);
    }
    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        int ioemu_nics = 0;
        int nr_set_cpus = 0;
        char *s;

        if (b_info->kernel) {
            LOGD(ERROR, domid, "HVM direct kernel boot is not supported by "
                 "qemu-xen-traditional");
            return ERROR_INVAL;
        }

        if (b_info->u.hvm.serial || b_info->u.hvm.serial_list) {
            if ( b_info->u.hvm.serial && b_info->u.hvm.serial_list )
            {
                LOGD(ERROR, domid, "Both serial and serial_list set");
                return ERROR_INVAL;
            }
            if (b_info->u.hvm.serial) {
                flexarray_vappend(dm_args,
                                  "-serial", b_info->u.hvm.serial, NULL);
            } else if (b_info->u.hvm.serial_list) {
                char **p;
                for (p = b_info->u.hvm.serial_list;
                     *p;
                     p++) {
                    flexarray_vappend(dm_args,
                                      "-serial",
                                      *p, NULL);
                }
            }
        }

        if (libxl_defbool_val(b_info->u.hvm.nographic) && (!sdl && !vnc)) {
            flexarray_append(dm_args, "-nographic");
        }

        if (b_info->video_memkb) {
            flexarray_vappend(dm_args, "-videoram",
                    GCSPRINTF("%d", libxl__sizekb_to_mb(b_info->video_memkb)),
                    NULL);
        }

        switch (b_info->u.hvm.vga.kind) {
        case LIBXL_VGA_INTERFACE_TYPE_STD:
            flexarray_append(dm_args, "-std-vga");
            break;
        case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            break;
        case LIBXL_VGA_INTERFACE_TYPE_NONE:
            flexarray_append_pair(dm_args, "-vga", "none");
            break;
        case LIBXL_VGA_INTERFACE_TYPE_QXL:
            break;
        default:
            LOGD(ERROR, domid, "Invalid emulated video card specified");
            return ERROR_INVAL;
        }

        if (b_info->u.hvm.boot) {
            flexarray_vappend(dm_args, "-boot", b_info->u.hvm.boot, NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.usb)
            || b_info->u.hvm.usbdevice
            || libxl_string_list_length(&b_info->u.hvm.usbdevice_list)) {
            if (b_info->u.hvm.usbdevice
                && libxl_string_list_length(&b_info->u.hvm.usbdevice_list)) {
                LOGD(ERROR, domid, "Both usbdevice and usbdevice_list set");
                return ERROR_INVAL;
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
        if (libxl__acpi_defbool_val(b_info)) {
            flexarray_append(dm_args, "-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_vappend(dm_args, "-vcpus",
                              GCSPRINTF("%d", b_info->max_vcpus),
                              NULL);
        }

        nr_set_cpus = libxl_bitmap_count_set(&b_info->avail_vcpus);
        s = libxl_bitmap_to_hex_string(CTX, &b_info->avail_vcpus);
        flexarray_vappend(dm_args, "-vcpu_avail",
                              GCSPRINTF("%s", s), NULL);
        free(s);

        for (i = 0; i < num_nics; i++) {
            if (nics[i].nictype == LIBXL_NIC_TYPE_VIF_IOEMU) {
                char *smac = GCSPRINTF(
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
            switch (b_info->u.hvm.gfx_passthru_kind) {
            case LIBXL_GFX_PASSTHRU_KIND_DEFAULT:
            case LIBXL_GFX_PASSTHRU_KIND_IGD:
                flexarray_append(dm_args, "-gfx_passthru");
                break;
            default:
                LOGD(ERROR, domid, "unsupported gfx_passthru_kind.");
                return ERROR_INVAL;
            }
        }
    } else {
        if (!sdl && !vnc)
            flexarray_append(dm_args, "-nographic");
    }

    if (libxl_defbool_val(b_info->dm_restrict)) {
        LOGD(ERROR, domid,
             "dm_restrict not supported by qemu-xen-traditional");
        return ERROR_INVAL;
    }

    if (state->saved_state) {
        flexarray_vappend(dm_args, "-loadvm", state->saved_state, NULL);
    }
    for (i = 0; b_info->extra && b_info->extra[i] != NULL; i++)
        flexarray_append(dm_args, b_info->extra[i]);
    flexarray_append(dm_args, "-M");
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PVH:
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
    *args = (char **) flexarray_contents(dm_args);
    flexarray_append(dm_envs, NULL);
    if (envs)
        *envs = (char **) flexarray_contents(dm_envs);
    return 0;
}

static const char *qemu_disk_format_string(libxl_disk_format format)
{
    switch (format) {
    case LIBXL_DISK_FORMAT_QCOW: return "qcow";
    case LIBXL_DISK_FORMAT_QCOW2: return "qcow2";
    case LIBXL_DISK_FORMAT_VHD: return "vpc";
    case LIBXL_DISK_FORMAT_RAW: return "raw";
    case LIBXL_DISK_FORMAT_EMPTY: return NULL;
    case LIBXL_DISK_FORMAT_QED: return "qed";
    default: return NULL;
    }
}

static char *dm_spice_options(libxl__gc *gc,
                                    const libxl_spice_info *spice)
{
    char *opt;

    if (!spice->port && !spice->tls_port) {
        LOG(ERROR,
            "at least one of the spiceport or tls_port must be provided");
        return NULL;
    }

    if (!libxl_defbool_val(spice->disable_ticketing)) {
        if (!spice->passwd) {
            LOG(ERROR, "spice ticketing is enabled but missing password");
            return NULL;
        }
        else if (!spice->passwd[0]) {
            LOG(ERROR, "spice password can't be empty");
            return NULL;
        }
    }
    opt = GCSPRINTF("port=%d,tls-port=%d", spice->port, spice->tls_port);
    if (spice->host)
        opt = GCSPRINTF("%s,addr=%s", opt, spice->host);
    if (libxl_defbool_val(spice->disable_ticketing))
        opt = GCSPRINTF("%s,disable-ticketing", opt);
    else
        opt = GCSPRINTF("%s,password=%s", opt, spice->passwd);
    opt = GCSPRINTF("%s,agent-mouse=%s", opt,
                    libxl_defbool_val(spice->agent_mouse) ? "on" : "off");

    if (!libxl_defbool_val(spice->clipboard_sharing))
        opt = GCSPRINTF("%s,disable-copy-paste", opt);

    if (spice->image_compression)
        opt = GCSPRINTF("%s,image-compression=%s", opt,
                        spice->image_compression);

    if (spice->streaming_video)
        opt = GCSPRINTF("%s,streaming-video=%s", opt, spice->streaming_video);

    return opt;
}

static enum libxl_gfx_passthru_kind
libxl__detect_gfx_passthru_kind(libxl__gc *gc,
                                const libxl_domain_config *guest_config)
{
    const libxl_domain_build_info *b_info = &guest_config->b_info;

    if (b_info->u.hvm.gfx_passthru_kind != LIBXL_GFX_PASSTHRU_KIND_DEFAULT)
        return b_info->u.hvm.gfx_passthru_kind;

    if (libxl__is_igd_vga_passthru(gc, guest_config)) {
        return LIBXL_GFX_PASSTHRU_KIND_IGD;
    }

    return LIBXL_GFX_PASSTHRU_KIND_DEFAULT;
}

/*
 *  userlookup_helper_getpwnam(libxl__gc*, const char *user,
 *                             struct passwd **pwd_r);
 *
 *  userlookup_helper_getpwuid(libxl__gc*, uid_t uid,
 *                             struct passwd **pwd_r);
 *
 *  returns 1 if the user was found, 0 if it was not, -1 on error
 */
#define DEFINE_USERLOOKUP_HELPER(NAME,SPEC_TYPE,STRUCTNAME,SYSCONF)     \
    static int userlookup_helper_##NAME(libxl__gc *gc,                  \
                                        SPEC_TYPE spec,                 \
                                        struct STRUCTNAME *resultbuf,   \
                                        struct STRUCTNAME **out)        \
    {                                                                   \
        struct STRUCTNAME *resultp = NULL;                              \
        char *buf = NULL;                                               \
        long buf_size;                                                  \
        int ret;                                                        \
                                                                        \
        buf_size = sysconf(SYSCONF);                                    \
        if (buf_size < 0) {                                             \
            buf_size = 2048;                                            \
            LOG(DEBUG,                                                  \
    "sysconf failed, setting the initial buffer size to %ld",           \
                buf_size);                                              \
        }                                                               \
                                                                        \
        while (1) {                                                     \
            buf = libxl__realloc(gc, buf, buf_size);                    \
            ret = NAME##_r(spec, resultbuf, buf, buf_size, &resultp);   \
            if (ret == ERANGE) {                                        \
                buf_size += 128;                                        \
                continue;                                               \
            }                                                           \
            if (ret != 0)                                               \
                return ERROR_FAIL;                                      \
            if (resultp != NULL) {                                      \
                if (out) *out = resultp;                                \
                return 1;                                               \
            }                                                           \
            return 0;                                                   \
        }                                                               \
    }

DEFINE_USERLOOKUP_HELPER(getpwnam, const char*, passwd, _SC_GETPW_R_SIZE_MAX);
DEFINE_USERLOOKUP_HELPER(getpwuid, uid_t,       passwd, _SC_GETPW_R_SIZE_MAX);

/* colo mode */
enum {
    LIBXL__COLO_NONE = 0,
    LIBXL__COLO_PRIMARY,
    LIBXL__COLO_SECONDARY,
};

static char *qemu_disk_scsi_drive_string(libxl__gc *gc, const char *target_path,
                                         int unit, const char *format,
                                         const libxl_device_disk *disk,
                                         int colo_mode)
{
    char *drive = NULL;
    const char *exportname = disk->colo_export;
    const char *active_disk = disk->active_disk;
    const char *hidden_disk = disk->hidden_disk;

    switch (colo_mode) {
    case LIBXL__COLO_NONE:
        drive = libxl__sprintf
            (gc, "file=%s,if=scsi,bus=0,unit=%d,format=%s,cache=writeback",
             target_path, unit, format);
        break;
    case LIBXL__COLO_PRIMARY:
        /*
         * primary:
         *  -dirve if=scsi,bus=0,unit=x,cache=writeback,driver=quorum,\
         *  id=exportname,\
         *  children.0.file.filename=target_path,\
         *  children.0.driver=format,\
         *  read-pattern=fifo,\
         *  vote-threshold=1
         */
        drive = GCSPRINTF(
            "if=scsi,bus=0,unit=%d,cache=writeback,driver=quorum,"
            "id=%s,"
            "children.0.file.filename=%s,"
            "children.0.driver=%s,"
            "read-pattern=fifo,"
            "vote-threshold=1",
            unit, exportname, target_path, format);
        break;
    case LIBXL__COLO_SECONDARY:
        /*
         * secondary:
         *  -drive if=scsi,bus=0,unit=x,cache=writeback,driver=replication,\
         *  mode=secondary,\
         *  file.driver=qcow2,\
         *  file.file.filename=active_disk,\
         *  file.backing.driver=qcow2,\
         *  file.backing.file.filename=hidden_disk,\
         *  file.backing.backing=exportname,
         */
        drive = GCSPRINTF(
            "if=scsi,id=top-colo,bus=0,unit=%d,cache=writeback,"
            "driver=replication,"
            "mode=secondary,"
            "top-id=top-colo,"
            "file.driver=qcow2,"
            "file.file.filename=%s,"
            "file.backing.driver=qcow2,"
            "file.backing.file.filename=%s,"
            "file.backing.backing=%s",
            unit, active_disk, hidden_disk, exportname);
        break;
    default:
        abort();
    }

    return drive;
}

static char *qemu_disk_ide_drive_string(libxl__gc *gc, const char *target_path,
                                        int unit, const char *format,
                                        const libxl_device_disk *disk,
                                        int colo_mode)
{
    char *drive = NULL;
    const char *exportname = disk->colo_export;
    const char *active_disk = disk->active_disk;
    const char *hidden_disk = disk->hidden_disk;

    switch (colo_mode) {
    case LIBXL__COLO_NONE:
        drive = GCSPRINTF
            ("file=%s,if=ide,index=%d,media=disk,format=%s,cache=writeback",
             target_path, unit, format);
        break;
    case LIBXL__COLO_PRIMARY:
        /*
         * primary:
         *  -dirve if=ide,index=x,media=disk,cache=writeback,driver=quorum,\
         *  id=exportname,\
         *  children.0.file.filename=target_path,\
         *  children.0.driver=format,\
         *  read-pattern=fifo,\
         *  vote-threshold=1
         */
        drive = GCSPRINTF(
            "if=ide,index=%d,media=disk,cache=writeback,driver=quorum,"
            "id=%s,"
            "children.0.file.filename=%s,"
            "children.0.driver=%s,"
            "read-pattern=fifo,"
            "vote-threshold=1",
             unit, exportname, target_path, format);
        break;
    case LIBXL__COLO_SECONDARY:
        /*
         * secondary:
         *  -drive if=ide,index=x,media=disk,cache=writeback,driver=replication,\
         *  mode=secondary,\
         *  file.driver=qcow2,\
         *  file.file.filename=active_disk,\
         *  file.backing.driver=qcow2,\
         *  file.backing.file.filename=hidden_disk,\
         *  file.backing.backing=exportname,
         */
        drive = GCSPRINTF(
            "if=ide,index=%d,id=top-colo,media=disk,cache=writeback,"
            "driver=replication,"
            "mode=secondary,"
            "top-id=top-colo,"
            "file.driver=qcow2,"
            "file.file.filename=%s,"
            "file.backing.driver=qcow2,"
            "file.backing.file.filename=%s,"
            "file.backing.backing=%s",
            unit, active_disk, hidden_disk, exportname);
        break;
    default:
         abort();
    }

    return drive;
}

static int libxl__build_device_model_args_new(libxl__gc *gc,
                                        const char *dm, int guest_domid,
                                        const libxl_domain_config *guest_config,
                                        char ***args, char ***envs,
                                        const libxl__domain_build_state *state,
                                        int *dm_state_fd)
{
    const libxl_domain_create_info *c_info = &guest_config->c_info;
    const libxl_domain_build_info *b_info = &guest_config->b_info;
    const libxl_device_disk *disks = guest_config->disks;
    const libxl_device_nic *nics = guest_config->nics;
    const int num_disks = guest_config->num_disks;
    const int num_nics = guest_config->num_nics;
    const libxl_vnc_info *vnc = libxl__dm_vnc(guest_config);
    const libxl_sdl_info *sdl = dm_sdl(guest_config);
    const char *keymap = dm_keymap(guest_config);
    char *machinearg;
    flexarray_t *dm_args, *dm_envs;
    int i, connection, devid, ret;
    uint64_t ram_size;
    const char *path, *chardev;
    char *user = NULL;
    struct passwd *user_base, user_pwbuf;

    dm_args = flexarray_make(gc, 16, 1);
    dm_envs = flexarray_make(gc, 16, 1);

    libxl__set_qemu_env_for_xsa_180(gc, dm_envs);

    flexarray_vappend(dm_args, dm,
                      "-xen-domid",
                      GCSPRINTF("%d", guest_domid), NULL);

    flexarray_append(dm_args, "-chardev");
    flexarray_append(dm_args,
                     GCSPRINTF("socket,id=libxl-cmd,"
                                    "path=%s/qmp-libxl-%d,server,nowait",
                                    libxl__run_dir_path(), guest_domid));

    flexarray_append(dm_args, "-no-shutdown");
    flexarray_append(dm_args, "-mon");
    flexarray_append(dm_args, "chardev=libxl-cmd,mode=control");

    flexarray_append(dm_args, "-chardev");
    flexarray_append(dm_args,
                     GCSPRINTF("socket,id=libxenstat-cmd,"
                                    "path=%s/qmp-libxenstat-%d,server,nowait",
                                    libxl__run_dir_path(), guest_domid));

    flexarray_append(dm_args, "-mon");
    flexarray_append(dm_args, "chardev=libxenstat-cmd,mode=control");

    for (i = 0; i < guest_config->num_channels; i++) {
        connection = guest_config->channels[i].connection;
        devid = guest_config->channels[i].devid;
        switch (connection) {
            case LIBXL_CHANNEL_CONNECTION_PTY:
                chardev = GCSPRINTF("pty,id=libxl-channel%d", devid);
                break;
            case LIBXL_CHANNEL_CONNECTION_SOCKET:
                path = guest_config->channels[i].u.socket.path;
                chardev = GCSPRINTF("socket,id=libxl-channel%d,path=%s,"
                                    "server,nowait", devid, path);
                break;
            default:
                /* We've forgotten to add the clause */
                LOGD(ERROR, guest_domid, "%s: unknown channel connection %d",
                    __func__, connection);
                return ERROR_INVAL;
        }
        flexarray_append(dm_args, "-chardev");
        flexarray_append(dm_args, (void*)chardev);
    }

    /*
     * Remove default devices created by qemu. Qemu will create only devices
     * defined by xen, since the devices not defined by xen are not usable.
     */
    flexarray_append(dm_args, "-nodefaults");

    /*
     * Do not use any of the user-provided config files in sysconfdir,
     * avoiding unkown and uncontrolled configuration.
     */
    flexarray_append(dm_args, "-no-user-config");

    if (b_info->type != LIBXL_DOMAIN_TYPE_HVM) {
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
                    LOGD(ERROR, guest_domid,
                         "vncdisplay set, vnclisten contains display");
                    return ERROR_INVAL;
                }
                vncarg = vnc->listen;
            } else {
                vncarg = GCSPRINTF("%s:%d", vnc->listen, vnc->display);
            }
        } else
            vncarg = GCSPRINTF("127.0.0.1:%d", vnc->display);

        if (vnc->passwd && vnc->passwd[0]) {
            vncarg = GCSPRINTF("%s,password", vncarg);
        }

        if (libxl_defbool_val(vnc->findunused)) {
            /* This option asks to QEMU to try this number of port before to
             * give up.  So QEMU will try ports between $display and $display +
             * 99.  This option needs to be the last one of the vnc options. */
            vncarg = GCSPRINTF("%s,to=99", vncarg);
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
        if (sdl->display)
            flexarray_append_pair(dm_envs, "DISPLAY", sdl->display);
        if (sdl->xauthority)
            flexarray_append_pair(dm_envs, "XAUTHORITY", sdl->xauthority);
    }

    if (keymap) {
        flexarray_vappend(dm_args, "-k", keymap, NULL);
    }

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        int ioemu_nics = 0;

        if (b_info->kernel)
            flexarray_vappend(dm_args, "-kernel", b_info->kernel, NULL);

        if (b_info->ramdisk)
            flexarray_vappend(dm_args, "-initrd", b_info->ramdisk, NULL);

        if (b_info->cmdline)
            flexarray_vappend(dm_args, "-append", b_info->cmdline, NULL);

        if (b_info->u.hvm.serial || b_info->u.hvm.serial_list) {
            if ( b_info->u.hvm.serial && b_info->u.hvm.serial_list )
            {
                LOGD(ERROR, guest_domid, "Both serial and serial_list set");
                return ERROR_INVAL;
            }
            if (b_info->u.hvm.serial) {
                flexarray_vappend(dm_args,
                                  "-serial", b_info->u.hvm.serial, NULL);
            } else if (b_info->u.hvm.serial_list) {
                char **p;
                for (p = b_info->u.hvm.serial_list;
                     *p;
                     p++) {
                    flexarray_vappend(dm_args,
                                      "-serial",
                                      *p, NULL);
                }
            }
        }

        if (libxl_defbool_val(b_info->u.hvm.nographic) && (!sdl && !vnc)) {
            flexarray_append(dm_args, "-nographic");
        }

        if (libxl_defbool_val(b_info->u.hvm.spice.enable)) {
            const libxl_spice_info *spice = &b_info->u.hvm.spice;
            char *spiceoptions = dm_spice_options(gc, spice);
            if (!spiceoptions)
                return ERROR_INVAL;

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
            flexarray_append_pair(dm_args, "-device",
                GCSPRINTF("VGA,vgamem_mb=%d",
                libxl__sizekb_to_mb(b_info->video_memkb)));
            break;
        case LIBXL_VGA_INTERFACE_TYPE_CIRRUS:
            flexarray_append_pair(dm_args, "-device",
                GCSPRINTF("cirrus-vga,vgamem_mb=%d",
                libxl__sizekb_to_mb(b_info->video_memkb)));
            break;
        case LIBXL_VGA_INTERFACE_TYPE_NONE:
            break;
        case LIBXL_VGA_INTERFACE_TYPE_QXL:
            /* QXL have 2 ram regions, ram and vram */
            flexarray_append_pair(dm_args, "-device",
                GCSPRINTF("qxl-vga,vram_size_mb=%"PRIu64",ram_size_mb=%"PRIu64,
                (b_info->video_memkb/2/1024), (b_info->video_memkb/2/1024) ) );
            break;
        default:
            LOGD(ERROR, guest_domid, "Invalid emulated video card specified");
            return ERROR_INVAL;
        }

        if (b_info->u.hvm.boot) {
            flexarray_vappend(dm_args, "-boot",
                    GCSPRINTF("order=%s", b_info->u.hvm.boot), NULL);
        }
        if (libxl_defbool_val(b_info->u.hvm.usb)
            || b_info->u.hvm.usbdevice
            || libxl_string_list_length(&b_info->u.hvm.usbdevice_list)) {
            if (b_info->u.hvm.usbdevice
                && libxl_string_list_length(&b_info->u.hvm.usbdevice_list)) {
                LOGD(ERROR, guest_domid, "Both usbdevice and usbdevice_list set");
                return ERROR_INVAL;
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
                LOGD(ERROR, guest_domid, "usbversion parameter is invalid, "
                    "must be between 1 and 3");
                return ERROR_INVAL;
            }
            if (b_info->u.hvm.spice.usbredirection >= 0 &&
                b_info->u.hvm.spice.usbredirection < 5) {
                for (i = 1; i <= b_info->u.hvm.spice.usbredirection; i++)
                    flexarray_vappend(dm_args, "-chardev",
                        GCSPRINTF("spicevmc,name=usbredir,id=usbrc%d", i),
                        "-device",
                        GCSPRINTF("usb-redir,chardev=usbrc%d,"
                        "id=usbrc%d", i, i), NULL);
            } else {
                LOGD(ERROR, guest_domid, "usbredirection parameter is invalid, "
                    "it must be between 1 and 4");
                return ERROR_INVAL;
            }
        }
        if (b_info->u.hvm.soundhw) {
            flexarray_vappend(dm_args, "-soundhw", b_info->u.hvm.soundhw, NULL);
        }
        if (!libxl__acpi_defbool_val(b_info)) {
            flexarray_append(dm_args, "-no-acpi");
        }
        if (b_info->max_vcpus > 1) {
            flexarray_append(dm_args, "-smp");
            if (b_info->avail_vcpus.size) {
                int nr_set_cpus = 0;
                nr_set_cpus = libxl_bitmap_count_set(&b_info->avail_vcpus);

                flexarray_append(dm_args, GCSPRINTF("%d,maxcpus=%d",
                                                    nr_set_cpus,
                                                    b_info->max_vcpus));
            } else
                flexarray_append(dm_args, GCSPRINTF("%d", b_info->max_vcpus));
        }
        for (i = 0; i < num_nics; i++) {
            if (nics[i].nictype == LIBXL_NIC_TYPE_VIF_IOEMU) {
                char *smac = GCSPRINTF(LIBXL_MAC_FMT,
                                       LIBXL_MAC_BYTES(nics[i].mac));
                const char *ifname = libxl__device_nic_devname(gc,
                                                guest_domid, nics[i].devid,
                                                LIBXL_NIC_TYPE_VIF_IOEMU);
                flexarray_append(dm_args, "-device");
                flexarray_append(dm_args,
                   GCSPRINTF("%s,id=nic%d,netdev=net%d,mac=%s",
                             nics[i].model, nics[i].devid,
                             nics[i].devid, smac));
                flexarray_append(dm_args, "-netdev");
                flexarray_append(dm_args,
                                 GCSPRINTF("type=tap,id=net%d,ifname=%s,"
                                           "script=%s,downscript=%s",
                                           nics[i].devid, ifname,
                                           libxl_tapif_script(gc),
                                           libxl_tapif_script(gc)));

                /* Userspace COLO Proxy need this */
#define APPEND_COLO_SOCK_SERVER(sock_id, sock_ip, sock_port) ({             \
    if (nics[i].colo_##sock_id &&                                           \
        nics[i].colo_##sock_ip &&                                           \
        nics[i].colo_##sock_port) {                                         \
        flexarray_append(dm_args, "-chardev");                              \
        flexarray_append(dm_args,                                           \
            GCSPRINTF("socket,id=%s,host=%s,port=%s,server,nowait",         \
                      nics[i].colo_##sock_id,                               \
                      nics[i].colo_##sock_ip,                               \
                      nics[i].colo_##sock_port));                           \
        }                                                                   \
})

#define APPEND_COLO_SOCK_CLIENT(sock_id, sock_ip, sock_port) ({             \
    if (nics[i].colo_##sock_id &&                                           \
        nics[i].colo_##sock_ip &&                                           \
        nics[i].colo_##sock_port) {                                         \
        flexarray_append(dm_args, "-chardev");                              \
        flexarray_append(dm_args,                                           \
            GCSPRINTF("socket,id=%s,host=%s,port=%s",                       \
                      nics[i].colo_##sock_id,                               \
                      nics[i].colo_##sock_ip,                               \
                      nics[i].colo_##sock_port));                           \
        }                                                                   \
})

                if (state->saved_state) {
                    /* secondary colo run */

                    APPEND_COLO_SOCK_CLIENT(sock_sec_redirector0_id,
                                            sock_sec_redirector0_ip,
                                            sock_sec_redirector0_port);

                    APPEND_COLO_SOCK_CLIENT(sock_sec_redirector1_id,
                                            sock_sec_redirector1_ip,
                                            sock_sec_redirector1_port);

                    if (nics[i].colo_filter_sec_redirector0_queue &&
                        nics[i].colo_filter_sec_redirector0_indev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("filter-redirector,id=rs1,netdev=net%d,queue=%s,indev=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_sec_redirector0_queue,
                                     nics[i].colo_filter_sec_redirector0_indev));
                    }
                    if (nics[i].colo_filter_sec_redirector1_queue &&
                        nics[i].colo_filter_sec_redirector1_outdev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("filter-redirector,id=rs2,netdev=net%d,queue=%s,outdev=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_sec_redirector1_queue,
                                     nics[i].colo_filter_sec_redirector1_outdev));
                    }
                    if (nics[i].colo_filter_sec_rewriter0_queue) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("filter-rewriter,id=rs3,netdev=net%d,queue=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_sec_rewriter0_queue));
                    }
                } else {
                    /* primary colo run */

                    APPEND_COLO_SOCK_SERVER(sock_mirror_id,
                                            sock_mirror_ip,
                                            sock_mirror_port);

                    APPEND_COLO_SOCK_SERVER(sock_compare_pri_in_id,
                                            sock_compare_pri_in_ip,
                                            sock_compare_pri_in_port);

                    APPEND_COLO_SOCK_SERVER(sock_compare_sec_in_id,
                                            sock_compare_sec_in_ip,
                                            sock_compare_sec_in_port);

                    APPEND_COLO_SOCK_SERVER(sock_compare_notify_id,
                                            sock_compare_notify_ip,
                                            sock_compare_notify_port);

                    APPEND_COLO_SOCK_SERVER(sock_redirector0_id,
                                            sock_redirector0_ip,
                                            sock_redirector0_port);

                    APPEND_COLO_SOCK_CLIENT(sock_redirector1_id,
                                            sock_redirector1_ip,
                                            sock_redirector1_port);

                    APPEND_COLO_SOCK_CLIENT(sock_redirector2_id,
                                            sock_redirector2_ip,
                                            sock_redirector2_port);

                    if (nics[i].colo_filter_mirror_queue &&
                        nics[i].colo_filter_mirror_outdev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("filter-mirror,id=m1,netdev=net%d,queue=%s,outdev=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_mirror_queue,
                                     nics[i].colo_filter_mirror_outdev));
                    }
                    if (nics[i].colo_filter_redirector0_queue &&
                        nics[i].colo_filter_redirector0_indev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("filter-redirector,id=r1,netdev=net%d,queue=%s,indev=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_redirector0_queue,
                                     nics[i].colo_filter_redirector0_indev));
                    }
                    if (nics[i].colo_filter_redirector1_queue &&
                        nics[i].colo_filter_redirector1_outdev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                          GCSPRINTF("filter-redirector,id=r2,netdev=net%d,queue=%s,outdev=%s",
                                     nics[i].devid,
                                     nics[i].colo_filter_redirector1_queue,
                                     nics[i].colo_filter_redirector1_outdev));
                    }
                    if (nics[i].colo_compare_pri_in &&
                        nics[i].colo_compare_sec_in &&
                        nics[i].colo_compare_out &&
                        nics[i].colo_compare_notify_dev) {
                        flexarray_append(dm_args, "-object");
                        flexarray_append(dm_args,
                           GCSPRINTF("colo-compare,id=c1,primary_in=%s,secondary_in=%s,outdev=%s,notify_dev=%s",
                                     nics[i].colo_compare_pri_in,
                                     nics[i].colo_compare_sec_in,
                                     nics[i].colo_compare_out,
                                     nics[i].colo_compare_notify_dev));
                    }
                }
                ioemu_nics++;

#undef APPEND_COLO_SOCK_SERVER
#undef APPEND_COLO_SOCK_CLIENT
            }
        }
        /* If we have no emulated nics, tell qemu not to create any */
        if ( ioemu_nics == 0 ) {
            flexarray_append(dm_args, "-net");
            flexarray_append(dm_args, "none");
        }
    } else {
        if (!sdl && !vnc) {
            flexarray_append(dm_args, "-nographic");
        }
    }

    if (libxl_defbool_val(b_info->dm_restrict))
        flexarray_append(dm_args, "-xen-domid-restrict");

    if (state->saved_state) {
        /* This file descriptor is meant to be used by QEMU */
        *dm_state_fd = open(state->saved_state, O_RDONLY);
        flexarray_append(dm_args, "-incoming");
        flexarray_append(dm_args, GCSPRINTF("fd:%d",*dm_state_fd));
    }
    for (i = 0; b_info->extra && b_info->extra[i] != NULL; i++)
        flexarray_append(dm_args, b_info->extra[i]);

    flexarray_append(dm_args, "-machine");
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PVH:
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
            machinearg = libxl__strdup(gc, "pc,accel=xen");
        } else {
            machinearg = libxl__strdup(gc, "xenfv");
        }
        if (b_info->u.hvm.mmio_hole_memkb) {
            uint64_t max_ram_below_4g = (1ULL << 32) -
                (b_info->u.hvm.mmio_hole_memkb << 10);

            if (max_ram_below_4g > HVM_BELOW_4G_MMIO_START) {
                LOGD(WARN, guest_domid, "mmio_hole_memkb=%"PRIu64
                     " invalid ignored.\n",
                    b_info->u.hvm.mmio_hole_memkb);
            } else {
                machinearg = GCSPRINTF("%s,max-ram-below-4g=%"PRIu64,
                                            machinearg, max_ram_below_4g);
            }
        }

        if (libxl_defbool_val(b_info->u.hvm.gfx_passthru)) {
            enum libxl_gfx_passthru_kind gfx_passthru_kind =
                            libxl__detect_gfx_passthru_kind(gc, guest_config);
            switch (gfx_passthru_kind) {
            case LIBXL_GFX_PASSTHRU_KIND_IGD:
                machinearg = GCSPRINTF("%s,igd-passthru=on", machinearg);
                break;
            case LIBXL_GFX_PASSTHRU_KIND_DEFAULT:
                LOGD(ERROR, guest_domid, "unable to detect required gfx_passthru_kind");
                return ERROR_FAIL;
            default:
                LOGD(ERROR, guest_domid, "invalid value for gfx_passthru_kind");
                return ERROR_INVAL;
            }
        }

        flexarray_append(dm_args, machinearg);
        for (i = 0; b_info->extra_hvm && b_info->extra_hvm[i] != NULL; i++)
            flexarray_append(dm_args, b_info->extra_hvm[i]);
        break;
    default:
        abort();
    }

    ram_size = libxl__sizekb_to_mb(b_info->max_memkb - b_info->video_memkb);
    flexarray_append(dm_args, "-m");
    flexarray_append(dm_args, GCSPRINTF("%"PRId64, ram_size));

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        if (b_info->u.hvm.hdtype == LIBXL_HDTYPE_AHCI)
            flexarray_append_pair(dm_args, "-device", "ahci,id=ahci0");
        for (i = 0; i < num_disks; i++) {
            int disk, part;
            int dev_number =
                libxl__device_disk_dev_number(disks[i].vdev, &disk, &part);
            const char *format;
            char *drive;
            const char *target_path = NULL;
            int colo_mode;

            if (dev_number == -1) {
                LOGD(WARN, guest_domid, "unable to determine"" disk number for %s",
                     disks[i].vdev);
                continue;
            }

            /* 
             * If qemu isn't doing the interpreting, the parameter is
             * always raw
             */
            if (disks[i].backend == LIBXL_DISK_BACKEND_QDISK)
                format = qemu_disk_format_string(disks[i].format);
            else
                format = qemu_disk_format_string(LIBXL_DISK_FORMAT_RAW);

            if (disks[i].format == LIBXL_DISK_FORMAT_EMPTY) {
                if (!disks[i].is_cdrom) {
                    LOGD(WARN, guest_domid, "Cannot support empty disk format for %s",
                         disks[i].vdev);
                    continue;
                }
            } else {
                if (format == NULL) {
                    LOGD(WARN, guest_domid,
                         "Unable to determine disk image format: %s\n"
                         "Disk will be available via PV drivers but not as an"
                         "emulated disk.",
                         disks[i].vdev);
                    continue;
                }

                /* 
                 * We can't call libxl__blktap_devpath from
                 * libxl__device_disk_find_local_path for now because
                 * the bootloader is called before the disks are set
                 * up, so this function would set up a blktap node,
                 * but there's no TAP tear-down on error conditions in
                 * the bootloader path.
                 */
                if (disks[i].backend == LIBXL_DISK_BACKEND_TAP)
                    target_path = libxl__blktap_devpath(gc, disks[i].pdev_path,
                                                        disks[i].format);
                else
                    target_path = libxl__device_disk_find_local_path(gc,
                                                 guest_domid, &disks[i], true);

                if (!target_path) {
                    LOGD(WARN, guest_domid, "No way to get local access disk to image: %s\n"
                         "Disk will be available via PV drivers but not as an"
                         "emulated disk.",
                         disks[i].vdev);
                    continue;
                }
            }

            if (disks[i].is_cdrom) {
                drive = libxl__sprintf(gc,
                         "if=ide,index=%d,readonly=on,media=cdrom,id=ide-%i",
                         disk, dev_number);

                if (target_path)
                    drive = libxl__sprintf(gc, "%s,file=%s,format=%s",
                                           drive, target_path, format);
            } else {
                /*
                 * Explicit sd disks are passed through as is.
                 *
                 * For other disks we translate devices 0..3 into
                 * hd[a-d] and ignore the rest.
                 */

                if (libxl_defbool_val(disks[i].colo_enable)) {
                    if (libxl_defbool_val(disks[i].colo_restore_enable))
                        colo_mode = LIBXL__COLO_SECONDARY;
                    else
                        colo_mode = LIBXL__COLO_PRIMARY;
                } else {
                    colo_mode = LIBXL__COLO_NONE;
                }

                if (strncmp(disks[i].vdev, "sd", 2) == 0) {
                    if (colo_mode == LIBXL__COLO_SECONDARY) {
                        drive = libxl__sprintf
                            (gc, "if=none,driver=%s,file=%s,id=%s",
                             format, target_path, disks[i].colo_export);

                        flexarray_append(dm_args, "-drive");
                        flexarray_append(dm_args, drive);
                    }
                    drive = qemu_disk_scsi_drive_string(gc, target_path, disk,
                                                        format,
                                                        &disks[i],
                                                        colo_mode);
                } else if (disk < 6 && b_info->u.hvm.hdtype == LIBXL_HDTYPE_AHCI) {
                    if (!disks[i].readwrite) {
                        LOGD(ERROR, guest_domid,
                             "qemu-xen doesn't support read-only AHCI disk drivers");
                        return ERROR_INVAL;
                    }
                    flexarray_vappend(dm_args, "-drive",
                        GCSPRINTF("file=%s,if=none,id=ahcidisk-%d,format=%s,cache=writeback",
                        target_path, disk, format),
                        "-device", GCSPRINTF("ide-hd,bus=ahci0.%d,unit=0,drive=ahcidisk-%d",
                        disk, disk), NULL);
                    continue;
                } else if (disk < 4) {
                    if (!disks[i].readwrite) {
                        LOGD(ERROR, guest_domid,
                             "qemu-xen doesn't support read-only IDE disk drivers");
                        return ERROR_INVAL;
                    }
                    if (colo_mode == LIBXL__COLO_SECONDARY) {
                        drive = libxl__sprintf
                            (gc, "if=none,driver=%s,file=%s,id=%s",
                             format, target_path, disks[i].colo_export);

                        flexarray_append(dm_args, "-drive");
                        flexarray_append(dm_args, drive);
                    }
                    drive = qemu_disk_ide_drive_string(gc, target_path, disk,
                                                       format,
                                                       &disks[i],
                                                       colo_mode);
                } else {
                    continue; /* Do not emulate this disk */
                }

                if (!drive)
                    continue;
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

        if (b_info->device_model_user) {
            user = b_info->device_model_user;
            goto end_search;
        }

        if (!libxl_defbool_val(b_info->dm_restrict)) {
            LOGD(DEBUG, guest_domid,
                 "dm_restrict disabled, starting QEMU as root");
            goto end_search;
        }

        user = GCSPRINTF("%s%d", LIBXL_QEMU_USER_BASE, guest_domid);
        ret = userlookup_helper_getpwnam(gc, user, &user_pwbuf, 0);
        if (ret < 0)
            return ret;
        if (ret > 0)
            goto end_search;

        ret = userlookup_helper_getpwnam(gc, LIBXL_QEMU_USER_RANGE_BASE,
                                         &user_pwbuf, &user_base);
        if (ret < 0)
            return ret;
        if (ret > 0) {
            struct passwd *user_clash, user_clash_pwbuf;
            uid_t intended_uid = user_base->pw_uid + guest_domid;
            ret = userlookup_helper_getpwuid(gc, intended_uid,
                                             &user_clash_pwbuf, &user_clash);
            if (ret < 0)
                return ret;
            if (ret > 0) {
                LOGD(ERROR, guest_domid,
                     "wanted to use uid %ld (%s + %d) but that is user %s !",
                     (long)intended_uid, LIBXL_QEMU_USER_RANGE_BASE,
                     guest_domid, user_clash->pw_name);
                return ERROR_FAIL;
            }
            LOGD(DEBUG, guest_domid, "using uid %ld", (long)intended_uid);
            flexarray_append(dm_args, "-runas");
            flexarray_append(dm_args,
                             GCSPRINTF("%ld:%ld", (long)intended_uid,
                                       (long)user_base->pw_gid));
            user = NULL; /* we have taken care of it */
            goto end_search;
        }

        user = LIBXL_QEMU_USER_SHARED;
        ret = userlookup_helper_getpwnam(gc, user, &user_pwbuf, 0);
        if (ret < 0)
            return ret;
        if (ret > 0) {
            LOGD(WARN, guest_domid, "Could not find user %s%d, falling back to %s",
                    LIBXL_QEMU_USER_BASE, guest_domid, LIBXL_QEMU_USER_SHARED);
            goto end_search;
        }

        LOGD(ERROR, guest_domid,
             "Could not find user %s%d or %s, cannot restrict",
             LIBXL_QEMU_USER_BASE, guest_domid, LIBXL_QEMU_USER_SHARED);
        return ERROR_INVAL;

end_search:
        if (user != NULL && strcmp(user, "root")) {
            flexarray_append(dm_args, "-runas");
            flexarray_append(dm_args, user);
        }
    }
    flexarray_append(dm_args, NULL);
    *args = (char **) flexarray_contents(dm_args);
    flexarray_append(dm_envs, NULL);
    if (envs)
        *envs = (char **) flexarray_contents(dm_envs);
    return 0;
}

static int libxl__build_device_model_args(libxl__gc *gc,
                                        const char *dm, int guest_domid,
                                        const libxl_domain_config *guest_config,
                                        char ***args, char ***envs,
                                        const libxl__domain_build_state *state,
                                        int *dm_state_fd)
/* dm_state_fd may be NULL iff caller knows we are using old stubdom
 * and therefore will be passing a filename rather than a fd. */
{
    switch (guest_config->b_info.device_model_version) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        return libxl__build_device_model_args_old(gc, dm,
                                                  guest_domid, guest_config,
                                                  args, envs,
                                                  state);
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        assert(dm_state_fd != NULL);
        assert(*dm_state_fd < 0);
        return libxl__build_device_model_args_new(gc, dm,
                                                  guest_domid, guest_config,
                                                  args, envs,
                                                  state, dm_state_fd);
    default:
        LOGED(ERROR, guest_domid, "unknown device model version %d",
              guest_config->b_info.device_model_version);
        return ERROR_INVAL;
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

    vm_path = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("/local/domain/%d/vm", guest_domid));

    i = 0;
    dmargs_size = 0;
    while (args[i] != NULL) {
        dmargs_size = dmargs_size + strlen(args[i]) + 1;
        i++;
    }
    dmargs_size++;
    dmargs = (char *) libxl__malloc(gc, dmargs_size);
    i = 1;
    dmargs[0] = '\0';
    while (args[i] != NULL) {
        if (strcmp(args[i], "-sdl") && strcmp(args[i], "-M") && strcmp(args[i], "xenfv")) {
            strcat(dmargs, " ");
            strcat(dmargs, args[i]);
        }
        i++;
    }
    path = GCSPRINTF("%s/image/dmargs", vm_path);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, path, dmargs, strlen(dmargs));
    xs_set_permissions(ctx->xsh, t, path, roperm, ARRAY_SIZE(roperm));
    xs_set_permissions(ctx->xsh, t, GCSPRINTF("%s/rtc/timeoffset", vm_path), roperm, ARRAY_SIZE(roperm));
    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
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

static void stubdom_xswait_cb(libxl__egc *egc, libxl__xswait_state *xswait,
                              int rc, const char *p);

char *libxl__stub_dm_name(libxl__gc *gc, const char *guest_name)
{
    return GCSPRINTF("%s-dm", guest_name);
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
    /* When we are here to launch stubdom, ssidref is a valid value
     * already, no need to parse it again.
     */
    dm_config->c_info.ssidref = guest_config->b_info.device_model_ssidref;
    dm_config->c_info.ssid_label = NULL;

    libxl_uuid_generate(&dm_config->c_info.uuid);

    libxl_domain_build_info_init(&dm_config->b_info);
    libxl_domain_build_info_init_type(&dm_config->b_info, LIBXL_DOMAIN_TYPE_PV);

    dm_config->b_info.max_vcpus = 1;
    dm_config->b_info.max_memkb = 28 * 1024 +
        guest_config->b_info.video_memkb;
    dm_config->b_info.target_memkb = dm_config->b_info.max_memkb;

    dm_config->b_info.max_grant_frames = guest_config->b_info.max_grant_frames;
    dm_config->b_info.max_maptrack_frames = 0;

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

    if (libxl_defbool_val(guest_config->b_info.u.hvm.vnc.enable)
        || libxl_defbool_val(guest_config->b_info.u.hvm.spice.enable)
        || libxl_defbool_val(guest_config->b_info.u.hvm.sdl.enable)) {
        GCNEW(vfb);
        GCNEW(vkb);
        libxl__vfb_and_vkb_from_hvm_guest_config(gc, guest_config, vfb, vkb);
        dm_config->vfbs = vfb;
        dm_config->num_vfbs = 1;
        dm_config->vkbs = vkb;
        dm_config->num_vkbs = 1;
    }

    stubdom_state->pv_kernel.path
        = libxl__abs_path(gc, "ioemu-stubdom.gz", libxl__xenfirmwaredir_path());
    stubdom_state->pv_cmdline = GCSPRINTF(" -d %d", guest_domid);
    stubdom_state->pv_ramdisk.path = "";

    /* fixme: this function can leak the stubdom if it fails */
    ret = libxl__domain_make(gc, dm_config, &sdss->pvqemu.guest_domid,
                             &stubdom_state->config);
    if (ret)
        goto out;
    uint32_t dm_domid = sdss->pvqemu.guest_domid;
    ret = libxl__domain_build(gc, dm_config, dm_domid, stubdom_state);
    if (ret)
        goto out;

    ret = libxl__build_device_model_args(gc, "stubdom-dm", guest_domid,
                                         guest_config, &args, NULL,
                                         d_state, NULL);
    if (ret) {
        ret = ERROR_FAIL;
        goto out;
    }

    libxl__write_stub_dmargs(gc, dm_domid, guest_domid, args);
    libxl__xs_printf(gc, XBT_NULL,
                     GCSPRINTF("%s/image/device-model-domid",
                               libxl__xs_get_dompath(gc, guest_domid)),
                     "%d", dm_domid);
    libxl__xs_printf(gc, XBT_NULL,
                     GCSPRINTF("%s/target",
                               libxl__xs_get_dompath(gc, dm_domid)),
                     "%d", guest_domid);
    ret = xc_domain_set_target(ctx->xch, dm_domid, guest_domid);
    if (ret<0) {
        LOGED(ERROR, guest_domid, "setting target domain %d -> %d",
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
    xs_mkdir(ctx->xsh, t, DEVICE_MODEL_XS_PATH(gc, dm_domid, guest_domid, ""));
    xs_set_permissions(ctx->xsh, t,
                       DEVICE_MODEL_XS_PATH(gc, dm_domid, guest_domid, ""),
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
    int need_qemu;

    if (ret) {
        LOGD(ERROR, guest_domid, "error connecting disk devices");
        goto out;
     }

    for (i = 0; i < dm_config->num_nics; i++) {
         /* We have to init the nic here, because we still haven't
         * called libxl_device_nic_add at this point, but qemu needs
         * the nic information to be complete.
         */
        ret = libxl__nic_devtype.set_default(gc, dm_domid, &dm_config->nics[i],
                                             false);
        if (ret)
            goto out;
    }
    if (dm_config->num_vfbs) {
        ret = libxl__device_add(gc, dm_domid, &libxl__vfb_devtype,
                                &dm_config->vfbs[0]);
        if (ret) goto out;
    }
    if (dm_config->num_vkbs) {
        ret = libxl__device_add(gc, dm_domid, &libxl__vkb_devtype,
                                &dm_config->vkbs[0]);
        if (ret) goto out;
    }

    if (guest_config->b_info.u.hvm.serial)
        num_console++;

    console = libxl__calloc(gc, num_console, sizeof(libxl__device_console));

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
                name = GCSPRINTF("qemu-dm-%s",
                                 libxl_domid_to_name(ctx, guest_domid));
                ret = libxl_create_logfile(ctx, name, &filename);
                if (ret) goto out;
                console[i].output = GCSPRINTF("file:%s", filename);
                free(filename);
                /* will be changed back to LIBXL__CONSOLE_BACKEND_IOEMU if qemu
                 * will be in use */
                console[i].consback = LIBXL__CONSOLE_BACKEND_XENCONSOLED;
                break;
            case STUBDOM_CONSOLE_SAVE:
                console[i].output = GCSPRINTF("file:%s",
                                libxl__device_model_savefile(gc, guest_domid));
                break;
            case STUBDOM_CONSOLE_RESTORE:
                if (d_state->saved_state)
                    console[i].output =
                        GCSPRINTF("pipe:%s", d_state->saved_state);
                break;
            default:
                console[i].output = "pty";
                break;
        }
    }

    need_qemu = libxl__need_xenpv_qemu(gc, dm_config);

    for (i = 0; i < num_console; i++) {
        libxl__device device;
        if (need_qemu)
            console[i].consback = LIBXL__CONSOLE_BACKEND_IOEMU;
        ret = libxl__device_console_add(gc, dm_domid, &console[i],
                        i == STUBDOM_CONSOLE_LOGGING ? stubdom_state : NULL,
                        &device);
        if (ret)
            goto out;
    }

    sdss->pvqemu.spawn.ao = ao;
    sdss->pvqemu.guest_domid = dm_domid;
    sdss->pvqemu.guest_config = &sdss->dm_config;
    sdss->pvqemu.build_state = &sdss->dm_state;
    sdss->pvqemu.callback = spawn_stubdom_pvqemu_cb;

    if (!need_qemu) {
        /* If dom0 qemu not needed, do not launch it */
        spawn_stubdom_pvqemu_cb(egc, &sdss->pvqemu, 0);
    } else {
        libxl__spawn_local_dm(egc, &sdss->pvqemu);
    }

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

    libxl__xswait_init(&sdss->xswait);

    if (rc) {
        LOGED(ERROR, sdss->dm.guest_domid,
              "error connecting nics devices");
        goto out;
    }

    rc = libxl_domain_unpause(CTX, dm_domid);
    if (rc) goto out;

    sdss->xswait.ao = ao;
    sdss->xswait.what = GCSPRINTF("Stubdom %u for %u startup",
                                  dm_domid, sdss->dm.guest_domid);
    sdss->xswait.path = DEVICE_MODEL_XS_PATH(gc, dm_domid, sdss->dm.guest_domid,
                                             "/state");
    sdss->xswait.timeout_ms = LIBXL_STUBDOM_START_TIMEOUT * 1000;
    sdss->xswait.callback = stubdom_xswait_cb;
    rc = libxl__xswait_start(gc, &sdss->xswait);
    if (rc) goto out;

    return;

 out:
    stubdom_xswait_cb(egc, &sdss->xswait, rc, NULL);
}

static void stubdom_xswait_cb(libxl__egc *egc, libxl__xswait_state *xswait,
                              int rc, const char *p)
{
    EGC_GC;
    libxl__stub_dm_spawn_state *sdss = CONTAINER_OF(xswait, *sdss, xswait);

    if (rc) {
        if (rc == ERROR_TIMEDOUT)
            LOGD(ERROR, sdss->dm.guest_domid,
                 "%s: startup timed out", xswait->what);
        goto out;
    }

    if (!p) return;

    if (strcmp(p, "running"))
        return;
 out:
    libxl__xswait_stop(gc, xswait);
    sdss->callback(egc, &sdss->dm, rc);
}

/* callbacks passed to libxl__spawn_spawn */
static void device_model_confirm(libxl__egc *egc, libxl__spawn_state *spawn,
                                 const char *xsdata);
static void device_model_startup_failed(libxl__egc *egc,
                                        libxl__spawn_state *spawn,
                                        int rc);
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
    char **args, **arg, **envs;
    xs_transaction_t t;
    char *vm_path;
    char **pass_stuff;
    const char *dm;
    int dm_state_fd = -1;

    if (libxl_defbool_val(b_info->device_model_stubdomain)) {
        abort();
    }

    dm = libxl__domain_device_model(gc, b_info);
    if (!dm) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (access(dm, X_OK) < 0) {
        LOGED(ERROR, domid, "device model %s is not executable", dm);
        rc = ERROR_FAIL;
        goto out;
    }
    rc = libxl__build_device_model_args(gc, dm, domid, guest_config,
                                          &args, &envs, state,
                                          &dm_state_fd);
    if (rc)
        goto out;

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        path = xs_get_domain_path(ctx->xsh, domid);
        libxl__xs_printf(gc, XBT_NULL,
                         GCSPRINTF("%s/hvmloader/bios", path),
                         "%s", libxl_bios_type_to_string(b_info->u.hvm.bios));
        /* Disable relocating memory to make the MMIO hole larger
         * unless we're running qemu-traditional and vNUMA is not
         * configured. */
        libxl__xs_printf(gc, XBT_NULL,
                         GCSPRINTF("%s/hvmloader/allow-memory-relocate", path),
                         "%d",
                         b_info->device_model_version==LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL &&
                         !libxl__vnuma_configured(b_info));
        free(path);
    }

    path = DEVICE_MODEL_XS_PATH(gc, LIBXL_TOOLSTACK_DOMID, domid, "");
    xs_mkdir(ctx->xsh, XBT_NULL, path);

    if (b_info->type == LIBXL_DOMAIN_TYPE_HVM &&
        b_info->device_model_version
        == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL)
        libxl__xs_printf(gc, XBT_NULL, GCSPRINTF("%s/disable_pf", path),
                         "%d", !libxl_defbool_val(b_info->u.hvm.xen_platform_pci));

    logfile_w = libxl__create_qemu_logfile(gc, GCSPRINTF("qemu-dm-%s",
                                                         c_info->name));
    if (logfile_w < 0) {
        rc = logfile_w;
        goto out;
    }
    null = open("/dev/null", O_RDONLY);
    if (null < 0) {
        LOGED(ERROR, domid, "unable to open /dev/null");
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
        vm_path = libxl__xs_read(gc,t,GCSPRINTF("%s/vm", dom_path));
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

    LOGD(DEBUG, domid, "Spawning device-model %s with arguments:", dm);
    for (arg = args; *arg; arg++)
        LOGD(DEBUG, domid, "  %s", *arg);
    if (*envs) {
        LOGD(DEBUG, domid, "Spawning device-model %s with additional environment:", dm);
        for (arg = envs; *arg; arg += 2)
            LOGD(DEBUG, domid, "  %s=%s", arg[0], arg[1]);
    }

    spawn->what = GCSPRINTF("domain %d device model", domid);
    spawn->xspath = DEVICE_MODEL_XS_PATH(gc, LIBXL_TOOLSTACK_DOMID, domid,
                                         "/state");
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
        libxl__exec(gc, null, logfile_w, logfile_w, dm, args, envs);
    }

    rc = 0;

out_close:
    if (null >= 0) close(null);
    if (logfile_w >= 0) close(logfile_w);
out:
    if (dm_state_fd >= 0) close(dm_state_fd);
    if (rc)
        device_model_spawn_outcome(egc, dmss, rc);
}

bool libxl__query_qemu_backend(libxl__gc *gc, uint32_t domid,
                               uint32_t backend_id, const char *type, bool def)
{
    char *path;
    char **dir;
    unsigned int n;

    path = GCSPRINTF("%s/device-model/%u/backends",
                     libxl__xs_get_dompath(gc, backend_id), domid);
    dir = libxl__xs_directory(gc, XBT_NULL, path, &n);
    if (!dir)
        return def;

    path = GCSPRINTF("%s/device-model/%u/backends/%s",
                     libxl__xs_get_dompath(gc, backend_id), domid, type);
    dir = libxl__xs_directory(gc, XBT_NULL, path, &n);

    return !!dir;
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
                                        libxl__spawn_state *spawn,
                                        int rc)
{
    libxl__dm_spawn_state *dmss = CONTAINER_OF(spawn, *dmss, spawn);
    device_model_spawn_outcome(egc, dmss, rc);
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
        LOGD(ERROR, dmss->guest_domid,
             "%s: spawn failed (rc=%d)", dmss->spawn.what, rc);

    libxl__domain_build_state *state = dmss->build_state;

    if (state->saved_state) {
        ret2 = unlink(state->saved_state);
        if (ret2) {
            LOGED(ERROR, dmss->guest_domid, "%s: failed to remove device-model state %s",
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
    flexarray_t *dm_args, *dm_envs;
    char **args, **envs;
    const char *dm;
    int logfile_w, null = -1, rc;
    uint32_t domid = dmss->guest_domid;

    /* Always use qemu-xen as device model */
    dm = qemu_xen_path(gc);

    dm_args = flexarray_make(gc, 15, 1);
    dm_envs = flexarray_make(gc, 1, 1);

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

    libxl__set_qemu_env_for_xsa_180(gc, dm_envs);
    envs = (char **) flexarray_contents(dm_envs);

    logfile_w = libxl__create_qemu_logfile(gc, GCSPRINTF("qdisk-%u", domid));
    if (logfile_w < 0) {
        rc = logfile_w;
        goto out;
    }
    null = open("/dev/null", O_RDONLY);
    if (null < 0) {
       rc = ERROR_FAIL;
       goto out;
    }

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
        goto out;
    if (!rc) { /* inner child */
        setsid();
        libxl__exec(gc, null, logfile_w, logfile_w, dm, args, envs);
    }

    rc = 0;
out:
    if (logfile_w >= 0) close(logfile_w);
    if (null >= 0) close(null);
    /* callback on error only, success goes via dmss->spawn.*_cb */
    if (rc) dmss->callback(egc, dmss, rc);
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
    char *path = DEVICE_MODEL_XS_PATH(gc, LIBXL_TOOLSTACK_DOMID, domid, "");
    if (!xs_rm(CTX->xsh, XBT_NULL, path))
        LOGD(ERROR, domid, "xs_rm failed for %s", path);
    /* We should try to destroy the device model anyway. */
    return kill_device_model(gc,
                GCSPRINTF("/local/domain/%d/image/device-model-pid", domid));
}

/* Return 0 if no dm needed, 1 if needed and <0 if error. */
int libxl__need_xenpv_qemu(libxl__gc *gc, libxl_domain_config *d_config)
{
    int idx, i, ret, num;
    uint32_t domid;
    const struct libxl_device_type *dt;

    ret = libxl__get_domid(gc, &domid);
    if (ret) {
        LOG(ERROR, "unable to get domain id");
        goto out;
    }

    if (d_config->num_vfbs > 0) {
        ret = 1;
        goto out;
    }

    for (idx = 0;; idx++) {
        dt = device_type_tbl[idx];
        if (!dt)
            break;

        num = *libxl__device_type_get_num(dt, d_config);
        if (!dt->dm_needed || !num)
            continue;

        for (i = 0; i < num; i++) {
            if (dt->dm_needed(libxl__device_type_get_elem(dt, d_config, i),
                              domid)) {
                ret = 1;
                goto out;
            }
        }
    }

    for (i = 0; i < d_config->num_channels; i++) {
        if (d_config->channels[i].backend_domid == domid) {
            /* xenconsoled is limited to the first console only.
               Until this restriction is removed we must use qemu for
               secondary consoles which includes all channels. */
            ret = 1;
            goto out;
        }
    }

out:
    return ret;
}

int libxl__dm_active(libxl__gc *gc, uint32_t domid)
{
    char *pid, *path;

    path = GCSPRINTF("/local/domain/%d/image/device-model-pid", domid);
    pid = libxl__xs_read(gc, XBT_NULL, path);

    return pid != NULL;
}

int libxl__dm_check_start(libxl__gc *gc, libxl_domain_config *d_config,
                          uint32_t domid)
{
    int rc;

    if (libxl__dm_active(gc, domid))
        return 0;

    rc = libxl__need_xenpv_qemu(gc, d_config);
    if (rc < 0)
        goto out;

    if (!rc)
        return 0;

    LOGD(ERROR, domid, "device model required but not running");
    rc = ERROR_FAIL;

out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
