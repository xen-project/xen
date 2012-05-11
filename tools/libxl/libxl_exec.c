
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

static void check_open_fds(const char *what)
{
    const char *env_debug;
    int debug;
    int i, flags, badness = 0;

    env_debug = getenv("_LIBXL_DEBUG_EXEC_FDS");
    if (!env_debug) return;

    debug = strtol(env_debug, (char **) NULL, 10);
    if (debug <= 0) return;

    for (i = 4; i < 256; i++) {
#ifdef __linux__
        size_t len;
        char path[PATH_MAX];
        char link[PATH_MAX+1];
#endif
        flags = fcntl(i, F_GETFD);
        if ( flags == -1 ) {
            if ( errno != EBADF )
                fprintf(stderr, "libxl: execing %s: fd %d flags returned %s (%d)\n",
                        what, i, strerror(errno), errno);
            continue;
        }

        if ( flags & FD_CLOEXEC )
            continue;

        badness++;

#ifdef __linux__
        snprintf(path, PATH_MAX, "/proc/%d/fd/%d", getpid(), i);
        len = readlink(path, link, PATH_MAX);
        if (len > 0) {
            link[len] = '\0';
            fprintf(stderr, "libxl: execing %s: fd %d is open to %s with flags %#x\n",
                    what, i, link, flags);
        } else
#endif
            fprintf(stderr, "libxl: execing %s: fd %d is open with flags %#x\n",
                    what, i, flags);
    }
    if (debug < 2) return;
    if (badness) abort();
}

void libxl__exec(int stdinfd, int stdoutfd, int stderrfd, const char *arg0,
                char **args)
     /* call this in the child */
{
    if (stdinfd != -1)
        dup2(stdinfd, STDIN_FILENO);
    if (stdoutfd != -1)
        dup2(stdoutfd, STDOUT_FILENO);
    if (stderrfd != -1)
        dup2(stderrfd, STDERR_FILENO);

    if (stdinfd != -1)
        close(stdinfd);
    if (stdoutfd != -1 && stdoutfd != stdinfd)
        close(stdoutfd);
    if (stderrfd != -1 && stderrfd != stdinfd && stderrfd != stdoutfd)
        close(stderrfd);

    check_open_fds(arg0);

    signal(SIGPIPE, SIG_DFL);
    /* in case our caller set it to IGN.  subprocesses are entitled
     * to assume they got DFL. */

    execvp(arg0, args);

    fprintf(stderr, "libxl: cannot execute %s: %s\n", arg0, strerror(errno));
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

void libxl_spawner_record_pid(void *for_spawn, pid_t innerchild)
{
    libxl__spawner_starting *starting = for_spawn;
    struct xs_handle *xsh;
    char *path = NULL, *pid = NULL;
    int len;

    if (asprintf(&path, "%s/%s", starting->dom_path, starting->pid_path) < 0)
        goto out;

    len = asprintf(&pid, "%d", innerchild);
    if (len < 0)
        goto out;

    /* we mustn't use the parent's handle in the child */
    xsh = xs_daemon_open();

    xs_write(xsh, XBT_NULL, path, pid, len);

    xs_daemon_close(xsh);
out:
    free(path);
    free(pid);
}

int libxl__wait_for_offspring(libxl__gc *gc,
                                 uint32_t domid,
                                 uint32_t timeout, char *what,
                                 char *path, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *p;
    unsigned int len;
    int rc = 0;
    struct xs_handle *xsh;
    int nfds;
    fd_set rfds;
    struct timeval tv;
    unsigned int num;
    char **l = NULL;

    xsh = xs_daemon_open();
    if (xsh == NULL) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Unable to open xenstore connection");
        goto err;
    }

    xs_watch(xsh, path, path);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    nfds = xs_fileno(xsh) + 1;
    if (spawning && spawning->fd > xs_fileno(xsh))
        nfds = spawning->fd + 1;

    while (rc > 0 || (!rc && tv.tv_sec > 0)) {
        if ( spawning ) {
            rc = libxl__spawn_check(gc, spawning);
            if ( rc ) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                           "%s died during startup", what);
                rc = -1;
                goto err_died;
            }
        }
        p = xs_read(xsh, XBT_NULL, path, &len);
        if ( NULL == p )
            goto again;

        if ( NULL != state && strcmp(p, state) )
            goto again;

        if ( NULL != check_callback ) {
            rc = (*check_callback)(gc, domid, p, check_callback_userdata);
            if ( rc > 0 )
                goto again;
        }

        free(p);
        xs_unwatch(xsh, path, path);
        xs_daemon_close(xsh);
        return rc;
again:
        free(p);
        FD_ZERO(&rfds);
        FD_SET(xs_fileno(xsh), &rfds);
        if (spawning)
            FD_SET(spawning->fd, &rfds);
        rc = select(nfds, &rfds, NULL, NULL, &tv);
        if (rc > 0) {
            if (FD_ISSET(xs_fileno(xsh), &rfds)) {
                l = xs_read_watch(xsh, &num);
                if (l != NULL)
                    free(l);
                else
                    goto again;
            }
            if (spawning && FD_ISSET(spawning->fd, &rfds)) {
                unsigned char dummy;
                if (read(spawning->fd, &dummy, sizeof(dummy)) != 1)
                    LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_DEBUG,
                                     "failed to read spawn status pipe");
            }
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "%s not ready", what);
err_died:
    xs_unwatch(xsh, path, path);
    xs_daemon_close(xsh);
err:
    return -1;
}

static int detach_offspring(libxl__gc *gc,
                               libxl__spawner_starting *starting)
{
    int rc;
    rc = libxl__spawn_detach(gc, starting->for_spawn);
    if (starting->for_spawn)
        free(starting->for_spawn);
    free(starting);
    return rc;
}

int libxl__spawn_confirm_offspring_startup(libxl__gc *gc,
                                       uint32_t timeout, char *what,
                                       char *path, char *state,
                                       libxl__spawner_starting *starting)
{
    int detach;
    int problem = libxl__wait_for_offspring(gc, starting->domid, timeout, what,
                                               path, state,
                                               starting->for_spawn, NULL, NULL);
    detach = detach_offspring(gc, starting);
    return problem ? problem : detach;
}

static int libxl__set_fd_flag(libxl__gc *gc, int fd, int flag)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return ERROR_FAIL;

    flags |= flag;

    if (fcntl(fd, F_SETFL, flags) == -1)
        return ERROR_FAIL;

    return 0;
}

int libxl__spawn_spawn(libxl__gc *gc,
                      libxl__spawn_starting *for_spawn,
                      const char *what,
                      void (*intermediate_hook)(void *for_spawn,
                                                pid_t innerchild),
                      void *hook_data)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    pid_t child, got;
    int status, rc;
    pid_t intermediate;
    int pipes[2];
    unsigned char dummy = 0;

    if (for_spawn) {
        for_spawn->what = strdup(what);
        if (!for_spawn->what) return ERROR_NOMEM;

        if (libxl_pipe(ctx, pipes) < 0)
            goto err_parent;
        if (libxl__set_fd_flag(gc, pipes[0], O_NONBLOCK) < 0 ||
            libxl__set_fd_flag(gc, pipes[1], O_NONBLOCK) < 0)
            goto err_parent_pipes;
    }

    intermediate = libxl_fork(ctx);
    if (intermediate ==-1)
        goto err_parent_pipes;

    if (intermediate) {
        /* parent */
        if (for_spawn) {
            for_spawn->intermediate = intermediate;
            for_spawn->fd = pipes[0];
            close(pipes[1]);
        }
        return 1;
    }

    /* we are now the intermediate process */
    if (for_spawn) close(pipes[0]);

    child = fork();
    if (child == -1)
        exit(255);
    if (!child) {
        if (for_spawn) close(pipes[1]);
        return 0; /* caller runs child code */
    }

    intermediate_hook(hook_data, child);

    if (!for_spawn) _exit(0); /* just detach then */

    got = waitpid(child, &status, 0);
    assert(got == child);

    rc = (WIFEXITED(status) ? WEXITSTATUS(status) :
          WIFSIGNALED(status) && WTERMSIG(status) < 127
          ? WTERMSIG(status)+128 : -1);
    if (for_spawn) {
        if (write(pipes[1], &dummy, sizeof(dummy)) != 1)
            perror("libxl__spawn_spawn: unable to signal child exit to parent");
    }
    _exit(rc);

 err_parent_pipes:
    if (for_spawn) {
        close(pipes[0]);
        close(pipes[1]);
    }

 err_parent:
    if (for_spawn) free(for_spawn->what);

    return ERROR_FAIL;
}

static void report_spawn_intermediate_status(libxl__gc *gc,
                                             libxl__spawn_starting *for_spawn,
                                             int status)
{
    if (!WIFEXITED(status)) {
        libxl_ctx *ctx = libxl__gc_owner(gc);
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

int libxl__spawn_detach(libxl__gc *gc,
                       libxl__spawn_starting *for_spawn)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
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
        got = waitpid(for_spawn->intermediate, &status, 0);
        assert(got == for_spawn->intermediate);
        if (!(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)) {
            report_spawn_intermediate_status(gc, for_spawn, status);
            rc = ERROR_FAIL;
        }
        for_spawn->intermediate = 0;
    }

    free(for_spawn->what);
    for_spawn->what = 0;

    return rc;
}

int libxl__spawn_check(libxl__gc *gc, libxl__spawn_starting *for_spawn)
{
    pid_t got;
    int status;

    if (!for_spawn) return 0;

    assert(for_spawn->intermediate);
    got = waitpid(for_spawn->intermediate, &status, WNOHANG);
    if (!got) return 0;

    assert(got == for_spawn->intermediate);
    report_spawn_intermediate_status(gc, for_spawn, status);

    for_spawn->intermediate = 0;
    return ERROR_FAIL;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
