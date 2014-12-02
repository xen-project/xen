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
void printf_info_sexp(int domid, libxl_domain_config *d_config, FILE *fh)
{
    int i;
    libxl_dominfo info;

    libxl_domain_create_info *c_info = &d_config->c_info;
    libxl_domain_build_info *b_info = &d_config->b_info;

    fprintf(fh, "(domain\n\t(domid %d)\n", domid);
    fprintf(fh, "\t(create_info)\n");
    fprintf(fh, "\t(hvm %d)\n", c_info->type == LIBXL_DOMAIN_TYPE_HVM);
    fprintf(fh, "\t(hap %s)\n", libxl_defbool_to_string(c_info->hap));
    fprintf(fh, "\t(oos %s)\n", libxl_defbool_to_string(c_info->oos));
    fprintf(fh, "\t(ssidref %d)\n", c_info->ssidref);
    fprintf(fh, "\t(name %s)\n", c_info->name);

    /* retrieve the UUID from dominfo, since it is probably generated
     * during parsing and thus does not match the real one
     */
    if (libxl_domain_info(ctx, &info, domid) == 0) {
        fprintf(fh, "\t(uuid " LIBXL_UUID_FMT ")\n", LIBXL_UUID_BYTES(info.uuid));
    } else {
        fprintf(fh, "\t(uuid <unknown>)\n");
    }
    if (c_info->pool_name)
        fprintf(fh, "\t(cpupool %s)\n", c_info->pool_name);
    if (c_info->xsdata)
        fprintf(fh, "\t(xsdata contains data)\n");
    else
        fprintf(fh, "\t(xsdata (null))\n");
    if (c_info->platformdata)
        fprintf(fh, "\t(platformdata contains data)\n");
    else
        fprintf(fh, "\t(platformdata (null))\n");


    fprintf(fh, "\t(build_info)\n");
    fprintf(fh, "\t(max_vcpus %d)\n", b_info->max_vcpus);
    fprintf(fh, "\t(tsc_mode %s)\n", libxl_tsc_mode_to_string(b_info->tsc_mode));
    fprintf(fh, "\t(max_memkb %"PRId64")\n", b_info->max_memkb);
    fprintf(fh, "\t(target_memkb %"PRId64")\n", b_info->target_memkb);
    fprintf(fh, "\t(nomigrate %s)\n",
           libxl_defbool_to_string(b_info->disable_migrate));

    if (c_info->type == LIBXL_DOMAIN_TYPE_PV && b_info->u.pv.bootloader) {
        fprintf(fh, "\t(bootloader %s)\n", b_info->u.pv.bootloader);
        if (b_info->u.pv.bootloader_args) {
            fprintf(fh, "\t(bootloader_args");
            for (i=0; b_info->u.pv.bootloader_args[i]; i++)
                fprintf(fh, " %s", b_info->u.pv.bootloader_args[i]);
            fprintf(fh, ")\n");
        }
    }

    fprintf(fh, "\t(image\n");
    switch (c_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        fprintf(fh, "\t\t(hvm\n");
        fprintf(fh, "\t\t\t(firmware %s)\n", b_info->u.hvm.firmware);
        fprintf(fh, "\t\t\t(video_memkb %"PRId64")\n", b_info->video_memkb);
        fprintf(fh, "\t\t\t(shadow_memkb %"PRId64")\n", b_info->shadow_memkb);
        fprintf(fh, "\t\t\t(pae %s)\n", libxl_defbool_to_string(b_info->u.hvm.pae));
        fprintf(fh, "\t\t\t(apic %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.apic));
        fprintf(fh, "\t\t\t(acpi %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.acpi));
        fprintf(fh, "\t\t\t(nx %s)\n", libxl_defbool_to_string(b_info->u.hvm.nx));
        fprintf(fh, "\t\t\t(viridian %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.viridian));
        fprintf(fh, "\t\t\t(hpet %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.hpet));
        fprintf(fh, "\t\t\t(vpt_align %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vpt_align));
        fprintf(fh, "\t\t\t(timer_mode %s)\n",
               libxl_timer_mode_to_string(b_info->u.hvm.timer_mode));
        fprintf(fh, "\t\t\t(nestedhvm %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.nested_hvm));
        fprintf(fh, "\t\t\t(stdvga %s)\n", b_info->u.hvm.vga.kind ==
                                      LIBXL_VGA_INTERFACE_TYPE_STD ?
                                      "True" : "False");
        fprintf(fh, "\t\t\t(vnc %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vnc.enable));
        fprintf(fh, "\t\t\t(vnclisten %s)\n", b_info->u.hvm.vnc.listen);
        fprintf(fh, "\t\t\t(vncdisplay %d)\n", b_info->u.hvm.vnc.display);
        fprintf(fh, "\t\t\t(vncunused %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.vnc.findunused));
        fprintf(fh, "\t\t\t(keymap %s)\n", b_info->u.hvm.keymap);
        fprintf(fh, "\t\t\t(sdl %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.sdl.enable));
        fprintf(fh, "\t\t\t(opengl %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.sdl.opengl));
        fprintf(fh, "\t\t\t(nographic %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.nographic));
        fprintf(fh, "\t\t\t(spice %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.enable));
        fprintf(fh, "\t\t\t(spiceport %d)\n", b_info->u.hvm.spice.port);
        fprintf(fh, "\t\t\t(spicetls_port %d)\n", b_info->u.hvm.spice.tls_port);
        fprintf(fh, "\t\t\t(spicehost %s)\n", b_info->u.hvm.spice.host);
        fprintf(fh, "\t\t\t(spicedisable_ticketing %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.disable_ticketing));
        fprintf(fh, "\t\t\t(spiceagent_mouse %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.spice.agent_mouse));

        fprintf(fh, "\t\t\t(device_model %s)\n", b_info->device_model ? : "default");
        fprintf(fh, "\t\t\t(gfx_passthru %s)\n",
               libxl_defbool_to_string(b_info->u.hvm.gfx_passthru));
        fprintf(fh, "\t\t\t(serial %s)\n", b_info->u.hvm.serial);
        fprintf(fh, "\t\t\t(boot %s)\n", b_info->u.hvm.boot);
        fprintf(fh, "\t\t\t(usb %s)\n", libxl_defbool_to_string(b_info->u.hvm.usb));
        fprintf(fh, "\t\t\t(usbdevice %s)\n", b_info->u.hvm.usbdevice);
        fprintf(fh, "\t\t)\n");
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        fprintf(fh, "\t\t(linux %d)\n", 0);
        fprintf(fh, "\t\t\t(kernel %s)\n", b_info->kernel);
        fprintf(fh, "\t\t\t(cmdline %s)\n", b_info->cmdline);
        fprintf(fh, "\t\t\t(ramdisk %s)\n", b_info->ramdisk);
        fprintf(fh, "\t\t\t(e820_host %s)\n",
               libxl_defbool_to_string(b_info->u.pv.e820_host));
        fprintf(fh, "\t\t)\n");
        break;
    default:
        fprintf(stderr, "Unknown domain type %d\n", c_info->type);
        exit(1);
    }
    fprintf(fh, "\t)\n");

    for (i = 0; i < d_config->num_disks; i++) {
        fprintf(fh, "\t(device\n");
        fprintf(fh, "\t\t(tap\n");
        fprintf(fh, "\t\t\t(backend_domid %d)\n", d_config->disks[i].backend_domid);
        fprintf(fh, "\t\t\t(frontend_domid %d)\n", domid);
        fprintf(fh, "\t\t\t(physpath %s)\n", d_config->disks[i].pdev_path);
        fprintf(fh, "\t\t\t(phystype %d)\n", d_config->disks[i].backend);
        fprintf(fh, "\t\t\t(virtpath %s)\n", d_config->disks[i].vdev);
        fprintf(fh, "\t\t\t(unpluggable %d)\n", d_config->disks[i].removable);
        fprintf(fh, "\t\t\t(readwrite %d)\n", d_config->disks[i].readwrite);
        fprintf(fh, "\t\t\t(is_cdrom %d)\n", d_config->disks[i].is_cdrom);
        fprintf(fh, "\t\t)\n");
        fprintf(fh, "\t)\n");
    }

    for (i = 0; i < d_config->num_nics; i++) {
        fprintf(fh, "\t(device\n");
        fprintf(fh, "\t\t(vif\n");
        if (d_config->nics[i].ifname)
            fprintf(fh, "\t\t\t(vifname %s)\n", d_config->nics[i].ifname);
        fprintf(fh, "\t\t\t(backend_domid %d)\n", d_config->nics[i].backend_domid);
        fprintf(fh, "\t\t\t(frontend_domid %d)\n", domid);
        fprintf(fh, "\t\t\t(devid %d)\n", d_config->nics[i].devid);
        fprintf(fh, "\t\t\t(mtu %d)\n", d_config->nics[i].mtu);
        fprintf(fh, "\t\t\t(model %s)\n", d_config->nics[i].model);
        fprintf(fh, "\t\t\t(mac %02x%02x%02x%02x%02x%02x)\n",
               d_config->nics[i].mac[0], d_config->nics[i].mac[1],
               d_config->nics[i].mac[2], d_config->nics[i].mac[3],
               d_config->nics[i].mac[4], d_config->nics[i].mac[5]);
        fprintf(fh, "\t\t)\n");
        fprintf(fh, "\t)\n");
    }

    for (i = 0; i < d_config->num_pcidevs; i++) {
        fprintf(fh, "\t(device\n");
        fprintf(fh, "\t\t(pci\n");
        fprintf(fh, "\t\t\t(pci dev %04x:%02x:%02x.%01x@%02x)\n",
               d_config->pcidevs[i].domain, d_config->pcidevs[i].bus,
               d_config->pcidevs[i].dev, d_config->pcidevs[i].func,
               d_config->pcidevs[i].vdevfn);
        fprintf(fh, "\t\t\t(opts msitranslate %d power_mgmt %d)\n",
               d_config->pcidevs[i].msitranslate,
               d_config->pcidevs[i].power_mgmt);
        fprintf(fh, "\t\t)\n");
        fprintf(fh, "\t)\n");
    }

    for (i = 0; i < d_config->num_vfbs; i++) {
        fprintf(fh, "\t(device\n");
        fprintf(fh, "\t\t(vfb\n");
        fprintf(fh, "\t\t\t(backend_domid %d)\n", d_config->vfbs[i].backend_domid);
        fprintf(fh, "\t\t\t(frontend_domid %d)\n", domid);
        fprintf(fh, "\t\t\t(devid %d)\n", d_config->vfbs[i].devid);
        fprintf(fh, "\t\t\t(vnc %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].vnc.enable));
        fprintf(fh, "\t\t\t(vnclisten %s)\n", d_config->vfbs[i].vnc.listen);
        fprintf(fh, "\t\t\t(vncdisplay %d)\n", d_config->vfbs[i].vnc.display);
        fprintf(fh, "\t\t\t(vncunused %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].vnc.findunused));
        fprintf(fh, "\t\t\t(keymap %s)\n", d_config->vfbs[i].keymap);
        fprintf(fh, "\t\t\t(sdl %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].sdl.enable));
        fprintf(fh, "\t\t\t(opengl %s)\n",
               libxl_defbool_to_string(d_config->vfbs[i].sdl.opengl));
        fprintf(fh, "\t\t\t(display %s)\n", d_config->vfbs[i].sdl.display);
        fprintf(fh, "\t\t\t(xauthority %s)\n", d_config->vfbs[i].sdl.xauthority);
        fprintf(fh, "\t\t)\n");
        fprintf(fh, "\t)\n");
    }
    fprintf(fh, ")\n");
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
