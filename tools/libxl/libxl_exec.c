
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

#include "libxl_osdeps.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h> /* for SIGKILL */

#include "libxl.h"
#include "libxl_internal.h"

pid_t libxl_fork(struct libxl_ctx *ctx)
{
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "fork failed");
        return -1;
    }

    return pid;
}

void libxl_exec(struct libxl_ctx *ctx, int stdinfd, int stdoutfd, int stderrfd,
                char *arg0, char **args)
     /* call this in the child */
{
    int i;

    if (stdinfd != -1)
        dup2(stdinfd, STDIN_FILENO);
    if (stdoutfd != -1)
        dup2(stdoutfd, STDOUT_FILENO);
    if (stderrfd != -1)
        dup2(stderrfd, STDERR_FILENO);
    for (i = 4; i < 256; i++)
        close(i);
    execv(arg0, args);
    XL_LOG_ERRNO(ctx, XL_LOG_ERROR, "exec %s failed", arg0);
    _exit(-1);
}

void libxl_report_child_exitstatus(struct libxl_ctx *ctx,
                                   const char *what, pid_t pid, int status) {
    /* treats all exit statuses as errors; if that's not what you want,
     * check status yourself first */

    if (WIFEXITED(status)) {
        int st= WEXITSTATUS(status);
        if (st)
            XL_LOG(ctx, XL_LOG_ERROR, "%s [%ld] exited"
                   " with error status %d", what, (unsigned long)pid, st);
        else
            XL_LOG(ctx, XL_LOG_ERROR, "%s [%ld] unexpectedly"
                   " exited status zero", what, (unsigned long)pid);
    } else if (WIFSIGNALED(status)) {
        int sig= WTERMSIG(status);
        const char *str= strsignal(sig);
        const char *coredump= WCOREDUMP(status) ? " (core dumped)" : "";
        if (str)
            XL_LOG(ctx, XL_LOG_ERROR, "%s [%ld] died due to"
                   " fatal signal %s%s", what, (unsigned long)pid,
                   str, coredump);
        else
            XL_LOG(ctx, XL_LOG_ERROR, "%s [%ld] died due to unknown"
                   " fatal signal number %d%s", what, (unsigned long)pid,
                   sig, coredump);
    } else {
        XL_LOG(ctx, XL_LOG_ERROR, "%s [%ld] gave unknown"
               " wait status 0x%x", what, (unsigned long)pid, status);
    }
}

pid_t libxl_waitpid_instead_default(pid_t pid, int *status, int flags) {
    return waitpid(pid,status,flags);
}



int libxl_spawn_spawn(struct libxl_ctx *ctx,
                      libxl_device_model_starting *starting,
                      const char *what,
                      void (*intermediate_hook)(struct libxl_ctx *ctx,
                                                void *for_spawn,
                                                pid_t innerchild)) {
    pid_t child, got;
    int status;
    pid_t intermediate;
    struct libxl_spawn_starting *for_spawn = starting->for_spawn;

    if (for_spawn) {
        for_spawn->what= libxl_sprintf(ctx, "%s", what);
        if (!for_spawn->what) return ERROR_NOMEM;
    }

    intermediate = libxl_fork(ctx);
    if (intermediate==-1) {
        if (for_spawn) free(for_spawn->what);
        return ERROR_FAIL;
    }
    if (intermediate) {
        /* parent */
        if (for_spawn) for_spawn->intermediate= intermediate;
        return 1;
    }

    /* we are now the intermediate process */

    child = libxl_fork(ctx);
    if (!child) return 0; /* caller runs child code */
    if (child<0) exit(255);

    intermediate_hook(ctx, starting, child);

    if (!for_spawn) _exit(0); /* just detach then */

    got = ctx->waitpid_instead(child, &status, 0);
    assert(got == child);

    libxl_report_child_exitstatus(ctx, what, child, status);
    _exit(WIFEXITED(status) ? WEXITSTATUS(status) :
          WIFSIGNALED(status) && WTERMSIG(status)<127
          ? WTERMSIG(status)+128 : -1);
}

static void report_spawn_intermediate_status(struct libxl_ctx *ctx,
                                 struct libxl_spawn_starting *for_spawn,
                                 int status) {
    if (!WIFEXITED(status)) {
        /* intermediate process did the logging itself if it exited */
        char *intermediate_what=
            libxl_sprintf(ctx,
                          "%s intermediate process (startup monitor)",
                          for_spawn->what);
        libxl_report_child_exitstatus(ctx, intermediate_what,
                                      for_spawn->intermediate, status);
    }
}

int libxl_spawn_detach(struct libxl_ctx *ctx,
                       struct libxl_spawn_starting *for_spawn) {
    int r, status;
    pid_t got;
    int rc = 0;

    if (!for_spawn) return 0;

    if (for_spawn->intermediate) {
        r = kill(for_spawn->intermediate, SIGKILL);
        if (r) {
            XL_LOG_ERRNO(ctx, XL_LOG_ERROR,
                         "could not kill %s intermediate process [%ld]",
                         for_spawn->what,
                         (unsigned long)for_spawn->intermediate);
            abort(); /* things are very wrong */
        }
        got = ctx->waitpid_instead(for_spawn->intermediate, &status, 0);
        assert(got == for_spawn->intermediate);
        if (!(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL)) {
            report_spawn_intermediate_status(ctx, for_spawn, status);
            rc = ERROR_FAIL;
        }
        for_spawn->intermediate = 0;
    }

    free(for_spawn->what);
    for_spawn->what = 0;

    return rc;
}

int libxl_spawn_check(struct libxl_ctx *ctx, void *for_spawn_void) {
    struct libxl_spawn_starting *for_spawn = for_spawn_void;
    pid_t got;
    int status;

    if (!for_spawn) return 0;

    assert(for_spawn->intermediate);
    got = ctx->waitpid_instead(for_spawn->intermediate, &status, WNOHANG);
    if (!got) return 0;

    assert(got == for_spawn->intermediate);
    report_spawn_intermediate_status(ctx, for_spawn, status);

    for_spawn->intermediate= 0;
    return ERROR_FAIL;
}
