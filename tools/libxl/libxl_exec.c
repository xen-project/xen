
/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "libxl.h"
#include "libxl_internal.h"

int libxl_exec(struct libxl_ctx *ctx, int stdinfd, int stdoutfd, int stderrfd,
               char *arg0, char **args)
{
    int pid, i;

    pid = fork();
    if (pid == -1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "fork failed");
        return -1;
    }
    if (pid == 0) {
        /* child */
        if (stdinfd != -1)
            dup2(stdinfd, STDIN_FILENO);
        if (stdoutfd != -1)
            dup2(stdoutfd, STDOUT_FILENO);
        if (stderrfd != -1)
            dup2(stderrfd, STDERR_FILENO);
        for (i = 4; i < 256; i++)
            close(i);
        execv(arg0, args);
        exit(256);
    }
    return pid;
}
