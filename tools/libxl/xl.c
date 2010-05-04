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
#include "xl_cmdimpl.h"
#include "xl_cmdtable.h"

extern struct libxl_ctx ctx;
extern int logfile;

void log_callback(void *userdata, int loglevel, const char *file, int line, const char *func, char *s)
{
    char str[1024];

    snprintf(str, sizeof(str), "[%d] %s:%d:%s: %s\n", loglevel, file, line, func, s);
    write(logfile, str, strlen(str));
}

int main(int argc, char **argv)
{
    int i;

    if (argc < 2) {
        help(NULL);
        exit(1);
    }

    if (libxl_ctx_init(&ctx, LIBXL_VERSION)) {
        fprintf(stderr, "cannot init xl context\n");
        exit(1);
    }
    if (libxl_ctx_set_log(&ctx, log_callback, NULL)) {
        fprintf(stderr, "cannot set xl log callback\n");
        exit(-ERROR_FAIL);
    }

    srand(time(0));

    for (i = 0; i < cmdtable_len; i++) {
        if (!strcmp(argv[1], cmd_table[i].cmd_name))
        	cmd_table[i].cmd_impl(argc - 1, argv + 1);
    }

    if (i >= cmdtable_len) {
        if (!strcmp(argv[1], "help")) {
            if (argc > 2)
                help(argv[2]);
            else
                help(NULL);
            exit(0);
        } else {
            fprintf(stderr, "command not implemented\n");
            exit(1);
        }
    }
}
