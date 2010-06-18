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

#include "libxl_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h> /* for time */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h>

#include "libxl.h"
#include "libxl_utils.h"
#include "xl.h"

xentoollog_logger_stdiostream *logger;

static xentoollog_level minmsglevel = XTL_PROGRESS;

int main(int argc, char **argv)
{
    int opt = 0;
    char *cmd = 0;
    struct cmd_spec *cspec;

    while ((opt = getopt(argc, argv, "+v")) >= 0) {
        switch (opt) {
        case 'v':
            if (minmsglevel > 0) minmsglevel--;
            break;
        default:
            fprintf(stderr, "unknown global option\n");
            exit(2);
        }
    }

    cmd = argv[optind++];

    if (!cmd) {
        help(NULL);
        exit(1);
    }
    opterr = 0;

    logger = xtl_createlogger_stdiostream(stderr, minmsglevel,  0);
    if (!logger) exit(1);

    if (libxl_ctx_init(&ctx, LIBXL_VERSION, (xentoollog_logger*)logger)) {
        fprintf(stderr, "cannot init xl context\n");
        exit(1);
    }

    srand(time(0));

    cspec = cmdtable_lookup(cmd);
    if (cspec)
        return cspec->cmd_impl(argc, argv);
    else if (!strcmp(cmd, "help")) {
        help(argv[2]);
        exit(0);
    } else {
        fprintf(stderr, "command not implemented\n");
        exit(1);
    }
}
