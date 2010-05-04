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

    if (!strcmp(argv[1], "create")) {
        main_create(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "list")) {
        main_list(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "list-vm")) {
        main_list_vm(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "destroy")) {
        main_destroy(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-attach")) {
        main_pciattach(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-detach")) {
        main_pcidetach(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pci-list")) {
        main_pcilist(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "pause")) {
        main_pause(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "unpause")) {
        main_unpause(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "console")) {
        main_console(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "save")) {
        main_save(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "migrate")) {
        main_migrate(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "restore")) {
        main_restore(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "migrate-receive")) {
        main_migrate_receive(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "cd-insert")) {
        main_cd_insert(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "cd-eject")) {
        main_cd_eject(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "mem-set")) {
        main_memset(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "button-press")) {
        main_button_press(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-list")) {
        main_vcpulist(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-pin")) {
        main_vcpupin(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "vcpu-set")) {
        main_vcpuset(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "info")) {
        main_info(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "sched-credit")) {
        main_sched_credit(argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "help")) {
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
