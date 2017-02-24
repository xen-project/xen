/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_usbctrl_attach(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc = 0;
    libxl_device_usbctrl usbctrl;

    SWITCH_FOREACH_OPT(opt, "", NULL, "usbctrl-attach", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    libxl_device_usbctrl_init(&usbctrl);

    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        if (parse_usbctrl_config(&usbctrl, *argv))
            return 1;
    }

    rc = libxl_device_usbctrl_add(ctx, domid, &usbctrl, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_usbctrl_add failed.\n");
        rc = 1;
    }

    libxl_device_usbctrl_dispose(&usbctrl);
    return rc;
}

int main_usbctrl_detach(int argc, char **argv)
{
    uint32_t domid;
    int opt, devid, rc;
    libxl_device_usbctrl usbctrl;

    SWITCH_FOREACH_OPT(opt, "", NULL, "usbctrl-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    devid = atoi(argv[optind+1]);

    libxl_device_usbctrl_init(&usbctrl);
    if (libxl_devid_to_device_usbctrl(ctx, domid, devid, &usbctrl)) {
        fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
        return 1;
    }

    rc = libxl_device_usbctrl_remove(ctx, domid, &usbctrl, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_usbctrl_remove failed.\n");
        rc = 1;
    }

    libxl_device_usbctrl_dispose(&usbctrl);
    return rc;

}

int main_usbdev_attach(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc;
    libxl_device_usbdev usbdev;

    SWITCH_FOREACH_OPT(opt, "", NULL, "usbdev-attach", 2) {
        /* No options */
    }

    libxl_device_usbdev_init(&usbdev);

    domid = find_domain(argv[optind++]);

    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        if (parse_usbdev_config(&usbdev, *argv))
            return 1;
    }

    rc = libxl_device_usbdev_add(ctx, domid, &usbdev, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_usbdev_add failed.\n");
        rc = 1;
    }

    libxl_device_usbdev_dispose(&usbdev);
    return rc;
}

int main_usbdev_detach(int argc, char **argv)
{
    uint32_t domid;
    int ctrl, port;
    int opt, rc = 1;
    libxl_device_usbdev usbdev;

    SWITCH_FOREACH_OPT(opt, "", NULL, "usbdev-detach", 3) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    ctrl = atoi(argv[optind+1]);
    port = atoi(argv[optind+2]);

    if (argc - optind > 3) {
        fprintf(stderr, "Invalid arguments.\n");
        return 1;
    }

    libxl_device_usbdev_init(&usbdev);
    if (libxl_ctrlport_to_device_usbdev(ctx, domid, ctrl, port, &usbdev)) {
        fprintf(stderr, "Unknown device at controller %d port %d.\n",
                ctrl, port);
        return 1;
    }

    rc = libxl_device_usbdev_remove(ctx, domid, &usbdev, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_usbdev_remove failed.\n");
        rc = 1;
    }

    libxl_device_usbdev_dispose(&usbdev);
    return rc;
}

int main_usblist(int argc, char **argv)
{
    uint32_t domid;
    libxl_device_usbctrl *usbctrls;
    libxl_usbctrlinfo usbctrlinfo;
    int numctrl, i, j, opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "usb-list", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    if (argc > optind) {
        fprintf(stderr, "Invalid arguments.\n");
        exit(-1);
    }

    usbctrls = libxl_device_usbctrl_list(ctx, domid, &numctrl);
    if (!usbctrls) {
        return 0;
    }

    for (i = 0; i < numctrl; ++i) {
        printf("%-6s %-12s %-3s %-5s %-7s %-5s\n",
                "Devid", "Type", "BE", "state", "usb-ver", "ports");

        libxl_usbctrlinfo_init(&usbctrlinfo);

        if (!libxl_device_usbctrl_getinfo(ctx, domid,
                                &usbctrls[i], &usbctrlinfo)) {
            printf("%-6d %-12s %-3d %-5d %-7d %-5d\n",
                    usbctrlinfo.devid,
                    libxl_usbctrl_type_to_string(usbctrlinfo.type),
                    usbctrlinfo.backend_id, usbctrlinfo.state,
                    usbctrlinfo.version, usbctrlinfo.ports);

            for (j = 1; j <= usbctrlinfo.ports; j++) {
                libxl_device_usbdev usbdev;

                libxl_device_usbdev_init(&usbdev);

                printf("  Port %d:", j);

                if (!libxl_ctrlport_to_device_usbdev(ctx, domid,
                                                     usbctrlinfo.devid,
                                                     j, &usbdev)) {
                    printf(" Bus %03x Device %03x\n",
                           usbdev.u.hostdev.hostbus,
                           usbdev.u.hostdev.hostaddr);
                } else {
                    printf("\n");
                }

                libxl_device_usbdev_dispose(&usbdev);
            }
        }

        libxl_usbctrlinfo_dispose(&usbctrlinfo);
    }

    libxl_device_usbctrl_list_free(usbctrls, numctrl);
    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
