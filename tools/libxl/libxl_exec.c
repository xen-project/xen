
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

static int call_waitpid(pid_t (*waitpid_cb)(pid_t, int *, int), pid_t pid, int *status, int options)
{
    return (waitpid_cb) ? waitpid_cb(pid, status, options) : waitpid(pid, status, options);
}

void libxl__exec(int stdinfd, int stdoutfd, int stderrfd, const char *arg0,
                char **args)
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

    signal(SIGPIPE, SIG_DFL);
    /* in case our caller set it to IGN.  subprocesses are entitled
     * to assume they got DFL. */

    execvp(arg0, args);
    _exit(-1);
}

void libxl_report_child_exitstatus(libxl_ctx *ctx,
                                   xentoollog_level level,
                                   const char *what, pid_t pid, int status)
{

    if (WIFEXITED(status)) {
        int st = WEXITSTATUS(status);
        if (st)
            LIBXL__LOG(ctx, level, "%s [%ld] exited"
                   " with error status %d", what, (unsigned long)pid, st);
        else
            LIBXL__LOG(ctx, level, "%s [%ld] unexpectedly"
                   " exited status zero", what, (unsigned long)pid);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        const char *str = strsignal(sig);
        const char *coredump = WCOREDUMP(status) ? " (core dumped)" : "";
        if (str)
            LIBXL__LOG(ctx, level, "%s [%ld] died due to"
                   " fatal signal %s%s", what, (unsigned long)pid,
                   str, coredump);
        else
            LIBXL__LOG(ctx, level, "%s [%ld] died due to unknown"
                   " fatal signal number %d%s", what, (unsigned long)pid,
                   sig, coredump);
    } else {
        LIBXL__LOG(ctx, level, "%s [%ld] gave unknown"
               " wait status 0x%x", what, (unsigned long)pid, status);
    }
}

int libxl__spawn_spawn(libxl_ctx *ctx,
                      libxl_device_model_starting *starting,
                      const char *what,
                      void (*intermediate_hook)(void *for_spawn,
                                                pid_t innerchild))
{
    pid_t child, got;
    int status;
    pid_t intermediate;
    libxl__spawn_starting *for_spawn = starting->for_spawn;

    if (for_spawn) {
        for_spawn->what = strdup(what);
        if (!for_spawn->what) return ERROR_NOMEM;
    }

    intermediate = libxl_fork(ctx);
    if (intermediate ==-1) {
        if (for_spawn) free(for_spawn->what);
        return ERROR_FAIL;
    }
    if (intermediate) {
        /* parent */
        if (for_spawn) for_spawn->intermediate = intermediate;
        return 1;
    }

    /* we are now the intermediate process */

    child = fork();
    if (child == -1)
        exit(255);
    if (!child)
        return 0; /* caller runs child code */

    intermediate_hook(starting, child);

    if (!for_spawn) _exit(0); /* just detach then */

    got = call_waitpid(ctx->waitpid_instead, child, &status, 0);
    assert(got == child);

    _exit(WIFEXITED(status) ? WEXITSTATUS(status) :
          WIFSIGNALED(status) && WTERMSIG(status) < 127
          ? WTERMSIG(status)+128 : -1);
}

static void report_spawn_intermediate_status(libxl_ctx *ctx,
                                 libxl__spawn_starting *for_spawn,
                                 int status)
{
    if (!WIFEXITED(status)) {
        char *intermediate_what;
        /* intermediate process did the logging itself if it exited */
        if ( asprintf(&intermediate_what,
                 "%s intermediate process (startup monitor)",
                 for_spawn->what) < 0 )
            intermediate_what = "intermediate process (startup monitor)";
        libxl_report_child_exitstatus(ctx, LIBXL__LOG_ERROR, intermediate_what,
                                      for_spawn->intermediate, status);
    }
}

int libxl__spawn_detach(libxl_ctx *ctx,
                       libxl__spawn_starting *for_spawn)
{
    int r, status;
    pid_t got;
    int rc = 0;

    if (!for_spawn) return 0;

    if (for_spawn->intermediate) {
        r = kill(for_spawn->intermediate, SIGKILL);
        if (r) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR,
                         "could not kill %s intermediate process [%ld]",
                         for_spawn->what,
                         (unsigned long)for_spawn->intermediate);
            abort(); /* things are very wrong */
        }
        got = call_waitpid(ctx->waitpid_instead, for_spawn->intermediate, &status, 0);
        assert(got == for_spawn->intermediate);
        if (!(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)) {
            report_spawn_intermediate_status(ctx, for_spawn, status);
            rc = ERROR_FAIL;
        }
        for_spawn->intermediate = 0;
    }

    free(for_spawn->what);
    for_spawn->what = 0;

    return rc;
}

int libxl__spawn_check(libxl_ctx *ctx, void *for_spawn_void)
{
    libxl__spawn_starting *for_spawn = for_spawn_void;
    pid_t got;
    int status;

    if (!for_spawn) return 0;

    assert(for_spawn->intermediate);
    got = call_waitpid(ctx->waitpid_instead, for_spawn->intermediate, &status, WNOHANG);
    if (!got) return 0;

    assert(got == for_spawn->intermediate);
    report_spawn_intermediate_status(ctx, for_spawn, status);

    for_spawn->intermediate = 0;
    return ERROR_FAIL;
}
