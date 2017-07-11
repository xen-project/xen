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

int main_vtpmattach(int argc, char **argv)
{
    int opt;
    libxl_device_vtpm vtpm;
    char *oparg;
    uint32_t domid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-attach", 1) {
        /* No options */
    }

    if (libxl_domain_qualifier_to_domid(ctx, argv[optind], &domid) < 0) {
        fprintf(stderr, "%s is an invalid domain identifier\n", argv[optind]);
        return 1;
    }
    ++optind;

    libxl_device_vtpm_init(&vtpm);
    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        if (MATCH_OPTION("uuid", *argv, oparg)) {
            if(libxl_uuid_from_string(&(vtpm.uuid), oparg)) {
                fprintf(stderr, "Invalid uuid specified (%s)\n", oparg);
                return 1;
            }
        } else if (MATCH_OPTION("backend", *argv, oparg)) {
            replace_string(&vtpm.backend_domname, oparg);
        } else {
            fprintf(stderr, "unrecognized argument `%s'\n", *argv);
            return 1;
        }
    }

    if(dryrun_only) {
       char* json = libxl_device_vtpm_to_json(ctx, &vtpm);
       printf("vtpm: %s\n", json);
       free(json);
       libxl_device_vtpm_dispose(&vtpm);
       if (ferror(stdout) || fflush(stdout)) { perror("stdout"); exit(-1); }
       return 0;
    }

    if (libxl_device_vtpm_add(ctx, domid, &vtpm, 0)) {
        fprintf(stderr, "libxl_device_vtpm_add failed.\n");
        return 1;
    }
    libxl_device_vtpm_dispose(&vtpm);
    return 0;
}

int main_vtpmlist(int argc, char **argv)
{
    int opt;
    libxl_device_vtpm *vtpms;
    libxl_vtpminfo vtpminfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-list", 1) {
        /* No options */
    }

    /*      Idx  BE   UUID   Hdl  Sta  evch rref  BE-path */
    printf("%-3s %-2s %-36s %-6s %-5s %-6s %-5s %-10s\n",
           "Idx", "BE", "Uuid", "handle", "state", "evt-ch", "ring-ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid;
        if (libxl_domain_qualifier_to_domid(ctx, *argv, &domid) < 0) {
            fprintf(stderr, "%s is an invalid domain identifier\n", *argv);
            continue;
        }
        if (!(vtpms = libxl_device_vtpm_list(ctx, domid, &nb))) {
            continue;
        }
        for (i = 0; i < nb; ++i) {
           if(!libxl_device_vtpm_getinfo(ctx, domid, &vtpms[i], &vtpminfo)) {
              /*      Idx  BE     UUID             Hdl Sta evch rref BE-path*/
              printf("%-3d %-2d " LIBXL_UUID_FMT " %6d %5d %6d %8d %-30s\n",
                    vtpminfo.devid, vtpminfo.backend_id,
                    LIBXL_UUID_BYTES(vtpminfo.uuid),
                    vtpminfo.devid, vtpminfo.state, vtpminfo.evtch,
                    vtpminfo.rref, vtpminfo.backend);

              libxl_vtpminfo_dispose(&vtpminfo);
           }
        }
        libxl_device_vtpm_list_free(vtpms, nb);
    }
    return 0;
}

int main_vtpmdetach(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc=0;
    libxl_device_vtpm vtpm;
    libxl_uuid uuid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vtpm-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    if ( libxl_uuid_from_string(&uuid, argv[optind+1])) {
        if (libxl_devid_to_device_vtpm(ctx, domid, atoi(argv[optind+1]), &vtpm)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    } else {
        if (libxl_uuid_to_device_vtpm(ctx, domid, &uuid, &vtpm)) {
            fprintf(stderr, "Unknown device %s.\n", argv[optind+1]);
            return 1;
        }
    }
    rc = libxl_device_vtpm_remove(ctx, domid, &vtpm, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_vtpm_remove failed.\n");
    }
    libxl_device_vtpm_dispose(&vtpm);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
