/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

/*
 * Legacy SXP output handling
 */

#include "libxl_osdeps.h"

#include <stdlib.h>
#include <inttypes.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "xl.h"

/* In general you should not add new output to this function since it
 * is intended only for legacy use.
 */
void printf_info_sexp(int domid, libxl_domain_config *d_config)
{
    int i;
    libxl_dominfo info;

    libxl_domain_create_info *c_info = &d_config->c_info;
    libxl_domain_build_info *b_info = &d_config->b_info;
    char *pool;

    printf("(domain\n\t(domid %d)\n", domid);
    printf("\t(create_info)\n");
    printf("\t(hvm %d)\n", c_info->type == LIBXL_DOMAIN_TYPE_HVM);
    printf("\t(hap %s)\n", libxl_defbool_to_string(c_info->hap));
    printf("\t(oos %s)\n", libxl_defbool_to_string(c_info->oos));
    printf("\t(ssidref %d)\n", c_info->ssidref);
    printf("\t(name %s)\n", c_info->name);

    /* retrieve the UUID from dominfo, since it is probably generated
     * during parsing and thus does not match the real one
     */
    if (libxl_domain_info(ctx, &info, domid) == 0) {
        printf("\t(uuid " LIBXL_UUID_FMT ")\n", LIBXL_UUID_BYTES(info.uuid));
    } else {
        printf("\t(uuid <unknown>)\n");
    }
    pool = libxl_cpupoolid_to_name(ctx, c_info->poolid);
    if (pool)
        printf("\t(cpupool %s)\n", pool);
    free(pool);
    if (c_info->xsdata)
        printf("\t(xsdata contains data)\n");
    else
        printf("\t(xsdata (null))\n");
    if (c_info->platformdata)
        printf("\t(platformdata contains data)\n");
    else
        printf("\t(platformdata (null))\n");


    printf("\t(build_info)\n");
    printf("\t(max_vcpus %d)\n", b_info->max_vcpus);
    printf("\t(tsc_mode %s)\n", libxl_tsc_mode_to_string(b_info->tsc_mode));
    printf("\t(max_memkb %"PRId64")\n", b_info->max_memkb);
    printf("\t(target_memkb %"PRId64")\n", b_info->target_memkb);
    printf("\t(nomigrate %s)\n",
           libxl_defbool_to_string(b_info->disable_migrate));

    if (c_info->type == LIBXL_DOMAIN_TYPE_PV && b_info->u.pv.bootloader) {
        printf("\t(bootloader %s)\n", b_info->u.pv.bootloader);
        if (b_info->u.pv.bootloader_args) {
            printf("\t(bootloader_args");
            for (i=0; b_info->u.pv.bootloader_args[i]; i++)
                printf(" %s", b_info->u.pv.bootloader_args[i]);
            printf(")\n");
        }
    }

    printf("\t(image\n");
    switch (c_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        printf("\t\t(hvm\n");
        printf("\t\t\t(firmware %s)\n", b_info->u.hvm.firmware);
        printf("\t\t\t(video_memkb %"PRId64")\n", b_info->video_memkb);
        printf("\t\t\t(shadow_memkb %"PRId64")\n", b_info->shadow_memkb);
        printf("\t\t\t(pae %s)\n", libxl_defbool_to_string(b_info->u.hvm.pae));
        printf("\t\t\t(apic %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.apic));
        printf("\t\t\t(acpi %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.acpi));
        printf("\t\t\t(nx %s)\n", libxl_defbool_to_string(b_info->u.hvm.nx));
        printf("\t\t\t(viridian %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.viridian));
        printf("\t\t\t(hpet %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.hpet));
        printf("\t\t\t(vpt_align %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vpt_align));
        printf("\t\t\t(timer_mode %s)\n",
               libxl_timer_mode_to_string(b_info->u.hvm.timer_mode));
        printf("\t\t\t(nestedhvm %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.nested_hvm));
        printf("\t\t\t(stdvga %s)\n", b_info->u.hvm.vga.kind ==
                                      LIBXL_VGA_INTERFACE_TYPE_STD ?
                                      "True" : "False");
        printf("\t\t\t(vnc %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vnc.enable));
        printf("\t\t\t(vnclisten %s)\n", b_info->u.hvm.vnc.listen);
        printf("\t\t\t(vncdisplay %d)\n", b_info->u.hvm.vnc.display);
        printf("\t\t\t(vncunused %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vnc.findunused));
        printf("\t\t\t(keymap %s)\n", b_info->u.hvm.keymap);
        printf("\t\t\t(sdl %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.sdl.enable));
        printf("\t\t\t(opengl %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.sdl.opengl));
        printf("\t\t\t(nographic %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.nographic));
        printf("\t\t\t(spice %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.enable));
        printf("\t\t\t(spiceport %d)\n", b_info->u.hvm.spice.port);
        printf("\t\t\t(spicetls_port %d)\n", b_info->u.hvm.spice.tls_port);
        printf("\t\t\t(spicehost %s)\n", b_info->u.hvm.spice.host);
        printf("\t\t\t(spicedisable_ticketing %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.disable_ticketing));
        printf("\t\t\t(spiceagent_mouse %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.agent_mouse));

        printf("\t\t\t(device_model %s)\n", b_info->device_model ? : "default");
        printf("\t\t\t(gfx_passthru %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.gfx_passthru));
        printf("\t\t\t(serial %s)\n", b_info->u.hvm.serial);
        printf("\t\t\t(boot %s)\n", b_info->u.hvm.boot);
        printf("\t\t\t(usb %s)\n", libxl_defbool_to_string(b_info->u.hvm.usb));
        printf("\t\t\t(usbdevice %s)\n", b_info->u.hvm.usbdevice);
        printf("\t\t)\n");
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        printf("\t\t(linux %d)\n", 0);
        printf("\t\t\t(kernel %s)\n", b_info->u.pv.kernel);
        printf("\t\t\t(cmdline %s)\n", b_info->u.pv.cmdline);
        printf("\t\t\t(ramdisk %s)\n", b_info->u.pv.ramdisk);
        printf("\t\t\t(e820_host %s)\n",
               libxl_defbool_to_string(b_info->u.pv.e820_host));
        printf("\t\t)\n");
        break;
    default:
        fprintf(stderr, "Unknown domain type %d\n", c_info->type);
        exit(1);
    }
    printf("\t)\n");

    for (i = 0; i < d_config->num_disks; i++) {
        printf("\t(device\n");
        printf("\t\t(tap\n");
        printf("\t\t\t(backend_domid %d)\n", d_config->disks[i].backend_domid);
        printf("\t\t\t(frontend_domid %d)\n", domid);
        printf("\t\t\t(physpath %s)\n", d_config->disks[i].pdev_path);
        printf("\t\t\t(phystype %d)\n", d_config->disks[i].backend);
        printf("\t\t\t(virtpath %s)\n", d_config->disks[i].vdev);
        printf("\t\t\t(unpluggable %d)\n", d_config->disks[i].removable);
        printf("\t\t\t(readwrite %d)\n", d_config->disks[i].readwrite);
        printf("\t\t\t(is_cdrom %d)\n", d_config->disks[i].is_cdrom);
        printf("\t\t)\n");
        printf("\t)\n");
    }

    for (i = 0; i < d_config->num_nics; i++) {
        printf("\t(device\n");
        printf("\t\t(vif\n");
        if (d_config->nics[i].ifname)
            printf("\t\t\t(vifname %s)\n", d_config->nics[i].ifname);
        printf("\t\t\t(backend_domid %d)\n", d_config->nics[i].backend_domid);
        printf("\t\t\t(frontend_domid %d)\n", domid);
        printf("\t\t\t(devid %d)\n", d_config->nics[i].devid);
        printf("\t\t\t(mtu %d)\n", d_config->nics[i].mtu);
        printf("\t\t\t(model %s)\n", d_config->nics[i].model);
        printf("\t\t\t(mac %02x%02x%02x%02x%02x%02x)\n",
               d_config->nics[i].mac[0], d_config->nics[i].mac[1],
               d_config->nics[i].mac[2], d_config->nics[i].mac[3],
               d_config->nics[i].mac[4], d_config->nics[i].mac[5]);
        printf("\t\t)\n");
        printf("\t)\n");
    }

    for (i = 0; i < d_config->num_pcidevs; i++) {
        printf("\t(device\n");
        printf("\t\t(pci\n");
        printf("\t\t\t(pci dev %04x:%02x:%02x.%01x@%02x)\n",
               d_config->pcidevs[i].domain, d_config->pcidevs[i].bus,
               d_config->pcidevs[i].dev, d_config->pcidevs[i].func,
               d_config->pcidevs[i].vdevfn);
        printf("\t\t\t(opts msitranslate %d power_mgmt %d)\n",
               d_config->pcidevs[i].msitranslate,
               d_config->pcidevs[i].power_mgmt);
        printf("\t\t)\n");
        printf("\t)\n");
    }

    for (i = 0; i < d_config->num_vfbs; i++) {
        printf("\t(device\n");
        printf("\t\t(vfb\n");
        printf("\t\t\t(backend_domid %d)\n", d_config->vfbs[i].backend_domid);
        printf("\t\t\t(frontend_domid %d)\n", domid);
        printf("\t\t\t(devid %d)\n", d_config->vfbs[i].devid);
        printf("\t\t\t(vnc %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].vnc.enable));
        printf("\t\t\t(vnclisten %s)\n", d_config->vfbs[i].vnc.listen);
        printf("\t\t\t(vncdisplay %d)\n", d_config->vfbs[i].vnc.display);
        printf("\t\t\t(vncunused %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].vnc.findunused));
        printf("\t\t\t(keymap %s)\n", d_config->vfbs[i].keymap);
        printf("\t\t\t(sdl %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].sdl.enable));
        printf("\t\t\t(opengl %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].sdl.opengl));
        printf("\t\t\t(display %s)\n", d_config->vfbs[i].sdl.display);
        printf("\t\t\t(xauthority %s)\n", d_config->vfbs[i].sdl.xauthority);
        printf("\t\t)\n");
        printf("\t)\n");
    }
    printf(")\n");
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
