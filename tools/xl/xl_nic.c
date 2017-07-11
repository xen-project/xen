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

void set_default_nic_values(libxl_device_nic *nic);
void set_default_nic_values(libxl_device_nic *nic)
{

    if (default_vifscript) {
        free(nic->script);
        nic->script = strdup(default_vifscript);
    }

    if (default_bridge) {
        free(nic->bridge);
        nic->bridge = strdup(default_bridge);
    }

    if (default_gatewaydev) {
        free(nic->gatewaydev);
        nic->gatewaydev = strdup(default_gatewaydev);
    }

    if (default_vifbackend) {
        free(nic->backend_domname);
        nic->backend_domname = strdup(default_vifbackend);
    }
}

int main_networkattach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    libxl_device_nic nic;
    XLU_Config *config = 0;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-attach", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    config= xlu_cfg_init(stderr, "command line");
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        return 1;
    }

    libxl_device_nic_init(&nic);
    set_default_nic_values(&nic);

    for (argv += optind+1, argc -= optind+1; argc > 0; ++argv, --argc) {
        if (parse_nic_config(&nic, &config, *argv))
            return 1;
    }

    if (dryrun_only) {
        char *json = libxl_device_nic_to_json(ctx, &nic);
        printf("vif: %s\n", json);
        free(json);
        libxl_device_nic_dispose(&nic);
        if (ferror(stdout) || fflush(stdout)) { perror("stdout"); exit(-1); }
        return 0;
    }

    if (libxl_device_nic_add(ctx, domid, &nic, 0)) {
        fprintf(stderr, "libxl_device_nic_add failed.\n");
        return 1;
    }
    libxl_device_nic_dispose(&nic);
    xlu_cfg_destroy(config);
    return 0;
}

int main_networklist(int argc, char **argv)
{
    int opt;
    libxl_device_nic *nics;
    libxl_nicinfo nicinfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-list", 1) {
        /* No options */
    }

    /*      Idx  BE   MAC   Hdl  Sta  evch txr/rxr  BE-path */
    printf("%-3s %-2s %-17s %-6s %-5s %-6s %5s/%-5s %-30s\n",
           "Idx", "BE", "Mac Addr.", "handle", "state", "evt-ch", "tx-", "rx-ring-ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid = find_domain(*argv);
        nics = libxl_device_nic_list(ctx, domid, &nb);
        if (!nics) {
            continue;
        }
        for (i = 0; i < nb; ++i) {
            if (!libxl_device_nic_getinfo(ctx, domid, &nics[i], &nicinfo)) {
                /* Idx BE */
                printf("%-3d %-2d ", nicinfo.devid, nicinfo.backend_id);
                /* MAC */
                printf(LIBXL_MAC_FMT, LIBXL_MAC_BYTES(nics[i].mac));
                /* Hdl  Sta  evch txr/rxr  BE-path */
                printf("%6d %5d %6d %5d/%-11d %-30s\n",
                       nicinfo.devid, nicinfo.state, nicinfo.evtch,
                       nicinfo.rref_tx, nicinfo.rref_rx, nicinfo.backend);
                libxl_nicinfo_dispose(&nicinfo);
            }
        }
        libxl_device_nic_list_free(nics, nb);
    }
    return 0;
}

int main_networkdetach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    libxl_device_nic nic;

    SWITCH_FOREACH_OPT(opt, "", NULL, "network-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    if (!strchr(argv[optind+1], ':')) {
        if (libxl_devid_to_device_nic(ctx, domid, atoi(argv[optind+1]), &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    } else {
        if (libxl_mac_to_device_nic(ctx, domid, argv[optind+1], &nic)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    }
    if (libxl_device_nic_remove(ctx, domid, &nic, 0)) {
        fprintf(stderr, "libxl_device_nic_del failed.\n");
        return 1;
    }
    libxl_device_nic_dispose(&nic);
    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
