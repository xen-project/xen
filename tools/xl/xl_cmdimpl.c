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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/utsname.h> /* for utsname in xl info */
#include <xentoollog.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <xen/hvm/e820.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxl_json.h>
#include <libxlutil.h>
#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int logfile = 2;

/* every libxl action in xl uses this same libxl context */
libxl_ctx *ctx;

xlchild children[child_max];

const char *common_domname;

int child_report(xlchildnum child)
{
    int status;
    pid_t got = xl_waitpid(child, &status, 0);
    if (got < 0) {
        fprintf(stderr, "xl: warning, failed to waitpid for %s: %s\n",
                children[child].description, strerror(errno));
        return ERROR_FAIL;
    } else if (status) {
        xl_report_child_exitstatus(XTL_ERROR, child, got, status);
        return ERROR_FAIL;
    } else {
        return 0;
    }
}

void help(const char *command)
{
    int i;
    struct cmd_spec *cmd;

    if (!command || !strcmp(command, "help")) {
        printf("Usage xl [-vfN] <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        for (i = 0; i < cmdtable_len; i++) {
            printf(" %-19s ", cmd_table[i].cmd_name);
            if (strlen(cmd_table[i].cmd_name) > 19)
                printf("\n %-19s ", "");
            printf("%s\n", cmd_table[i].cmd_desc);
        }
    } else {
        cmd = cmdtable_lookup(command);
        if (cmd) {
            printf("Usage: xl [-v%s%s] %s %s\n\n%s.\n\n",
                   cmd->modifies ? "f" : "",
                   cmd->can_dryrun ? "N" : "",
                   cmd->cmd_name,
                   cmd->cmd_usage,
                   cmd->cmd_desc);
            if (cmd->cmd_option)
                printf("Options:\n\n%s\n", cmd->cmd_option);
        }
        else {
            printf("command \"%s\" not implemented\n", command);
        }
    }
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
