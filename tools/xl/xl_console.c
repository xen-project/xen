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

int main_console(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0, num = 0;
    libxl_console_type type = 0;
    char *console_names = "pv, serial, vuart";

    SWITCH_FOREACH_OPT(opt, "n:t:", NULL, "console", 1) {
    case 't':
        if (!strcmp(optarg, "pv"))
            type = LIBXL_CONSOLE_TYPE_PV;
        else if (!strcmp(optarg, "serial"))
            type = LIBXL_CONSOLE_TYPE_SERIAL;
        else if (!strcmp(optarg, "vuart"))
            type = LIBXL_CONSOLE_TYPE_VUART;
        else {
            fprintf(stderr, "console type supported are: %s\n", console_names);
            return EXIT_FAILURE;
        }
        break;
    case 'n':
        num = atoi(optarg);
        break;
    }

    domid = find_domain(argv[optind]);
    if (!type)
        libxl_primary_console_exec(ctx, domid, -1);
    else
        libxl_console_exec(ctx, domid, num, type, -1);
    fprintf(stderr, "Unable to attach console\n");
    return EXIT_FAILURE;
}

int main_vncviewer(int argc, char **argv)
{
    static const struct option opts[] = {
        {"autopass", 0, 0, 'a'},
        {"vncviewer-autopass", 0, 0, 'a'},
        COMMON_LONG_OPTS
    };
    uint32_t domid;
    int opt, autopass = 0;

    SWITCH_FOREACH_OPT(opt, "a", opts, "vncviewer", 1) {
    case 'a':
        autopass = 1;
        break;
    }

    domid = find_domain(argv[optind]);

    libxl_vncviewer_exec(ctx, domid, autopass);

    return EXIT_FAILURE;
}

/* Channel is just a console in disguise, so put it here */
int main_channellist(int argc, char **argv)
{
    int opt;
    libxl_device_channel *channels;
    libxl_channelinfo channelinfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "channel-list", 1) {
        /* No options */
    }

    /*      Idx BE state evt-ch ring-ref connection params*/
    printf("%-3s %-2s %-5s %-6s %8s %-10s %-30s\n",
           "Idx", "BE", "state", "evt-ch", "ring-ref", "connection", "");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid = find_domain(*argv);
        channels = libxl_device_channel_list(ctx, domid, &nb);
        if (!channels)
            continue;
        for (i = 0; i < nb; ++i) {
            if (!libxl_device_channel_getinfo(ctx, domid, &channels[i],
                &channelinfo)) {
                printf("%-3d %-2d ", channels[i].devid, channelinfo.backend_id);
                printf("%-5d ", channelinfo.state);
                printf("%-6d %-8d ", channelinfo.evtch, channelinfo.rref);
                printf("%-10s ", libxl_channel_connection_to_string(
                       channels[i].connection));
                switch (channels[i].connection) {
                    case LIBXL_CHANNEL_CONNECTION_PTY:
                        printf("%-30s ", channelinfo.u.pty.path);
                        break;
                    default:
                        break;
                }
                printf("\n");
                libxl_channelinfo_dispose(&channelinfo);
            }
            libxl_device_channel_dispose(&channels[i]);
        }
        free(channels);
    }
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
