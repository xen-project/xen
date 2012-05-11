
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

int libxl__spawn_record_pid(libxl__gc *gc, libxl__spawn_state *spawn, pid_t pid)
{
    int r, rc;

    rc = libxl__ev_child_xenstore_reopen(gc, spawn->what);
    if (rc) goto out;

    r = libxl__xs_write(gc, XBT_NULL, spawn->pidpath, "%d", pid);
    if (r) {
        LOGE(ERROR,
             "write %s = %d: xenstore write failed", spawn->pidpath, pid);
        rc = ERROR_FAIL;  goto out;
    }

    rc = 0;

out:
    return rc ? SIGTERM : 0;
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
    assert(!spawning);

    while (rc > 0 || (!rc && tv.tv_sec > 0)) {
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
        rc = select(nfds, &rfds, NULL, NULL, &tv);
        if (rc > 0) {
            if (FD_ISSET(xs_fileno(xsh), &rfds)) {
                l = xs_read_watch(xsh, &num);
                if (l != NULL)
                    free(l);
                else
                    goto again;
            }
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "%s not ready", what);

    xs_unwatch(xsh, path, path);
    xs_daemon_close(xsh);
err:
    return -1;
}


/*----- spawn implementation -----*/

/*
 * Full set of possible states of a libxl__spawn_state and its _detachable:
 *
 *               ss->        ss->        ss->    | ssd->       ssd->
 *               timeout     xswatch     ssd     |  mid         ss
 *  - Undefined   undef       undef       no     |  -           -
 *  - Idle        Idle        Idle        no     |  -           -
 *  - Active      Active      Active      yes    |  Active      yes
 *  - Partial     Active/Idle Active/Idle maybe  |  Active/Idle yes  (if exists)
 *  - Detached    -           -           -      |  Active      no
 *
 * When in state Detached, the middle process has been sent a SIGKILL.
 */

/* Event callbacks. */
static void spawn_watch_event(libxl__egc *egc, libxl__ev_xswatch *xsw,
                              const char *watch_path, const char *event_path);
static void spawn_timeout(libxl__egc *egc, libxl__ev_time *ev,
                          const struct timeval *requested_abs);
static void spawn_middle_death(libxl__egc *egc, libxl__ev_child *childw,
                               pid_t pid, int status);

/* Precondition: Partial.  Results: Detached. */
static void spawn_cleanup(libxl__gc *gc, libxl__spawn_state *ss);

/* Precondition: Partial; caller has logged failure reason.
 * Results: Caller notified of failure;
 *  after return, ss may be completely invalid as caller may reuse it */
static void spawn_failed(libxl__egc *egc, libxl__spawn_state *ss);

void libxl__spawn_init(libxl__spawn_state *ss)
{
    libxl__ev_time_init(&ss->timeout);
    libxl__ev_xswatch_init(&ss->xswatch);
    ss->ssd = 0;
}

int libxl__spawn_spawn(libxl__egc *egc, libxl__spawn_state *ss)
{
    STATE_AO_GC(ss->ao);
    int r;
    pid_t child;
    int status, rc;

    libxl__spawn_init(ss);
    ss->ssd = libxl__zalloc(0, sizeof(*ss->ssd));
    libxl__ev_child_init(&ss->ssd->mid);

    rc = libxl__ev_time_register_rel(gc, &ss->timeout,
                                     spawn_timeout, ss->timeout_ms);
    if (rc) goto out_err;

    rc = libxl__ev_xswatch_register(gc, &ss->xswatch,
                                    spawn_watch_event, ss->xspath);
    if (rc) goto out_err;

    pid_t middle = libxl__ev_child_fork(gc, &ss->ssd->mid, spawn_middle_death);
    if (middle ==-1) { rc = ERROR_FAIL; goto out_err; }

    if (middle) {
        /* parent */
        return 1;
    }

    /* we are now the middle process */

    pid_t (*fork_replacement)(void*) =
        CTX->childproc_hooks
        ? CTX->childproc_hooks->fork_replacement
        : 0;
    child =
        fork_replacement
        ? fork_replacement(CTX->childproc_user)
        : fork();

    if (child == -1)
        exit(255);
    if (!child) {
        return 0; /* caller runs child code */
    }

    int failsig = ss->midproc_cb(gc, ss, child);
    if (failsig) {
        kill(child, failsig);
        _exit(127);
    }

    for (;;) {
        pid_t got = waitpid(child, &status, 0);
        if (got == -1) {
            assert(errno == EINTR);
            continue;
        }
        assert(got == child);
        break;
    }

    r = (WIFEXITED(status) && WEXITSTATUS(status) <= 127 ? WEXITSTATUS(status) :
         WIFSIGNALED(status) && WTERMSIG(status) < 127 ? WTERMSIG(status)+128 :
         -1);
    _exit(r);

 out_err:
    spawn_cleanup(gc, ss);
    return rc;
}

static void spawn_cleanup(libxl__gc *gc, libxl__spawn_state *ss)
{
    int r;

    libxl__ev_time_deregister(gc, &ss->timeout);
    libxl__ev_xswatch_deregister(gc, &ss->xswatch);

    libxl__spawn_state_detachable *ssd = ss->ssd;
    if (ssd) {
        if (libxl__ev_child_inuse(&ssd->mid)) {
            pid_t child = ssd->mid.pid;
            r = kill(child, SIGKILL);
            if (r && errno != ESRCH)
                LOGE(WARN, "%s: failed to kill intermediate child (pid=%lu)",
                     ss->what, (unsigned long)child);
        }

        /* disconnect the ss and ssd from each other */
        ssd->ss = 0;
        ss->ssd = 0;
    }
}

static void spawn_failed(libxl__egc *egc, libxl__spawn_state *ss)
{
    EGC_GC;
    spawn_cleanup(gc, ss);
    ss->failure_cb(egc, ss); /* must be last; callback may do anything to ss */
}

static void spawn_timeout(libxl__egc *egc, libxl__ev_time *ev,
                          const struct timeval *requested_abs)
{
    /* Before event, was Active; is now Partial. */
    EGC_GC;
    libxl__spawn_state *ss = CONTAINER_OF(ev, *ss, timeout);
    LOG(ERROR, "%s: startup timed out", ss->what);
    spawn_failed(egc, ss); /* must be last */
}

static void spawn_watch_event(libxl__egc *egc, libxl__ev_xswatch *xsw,
                              const char *watch_path, const char *event_path)
{
    /* On entry, is Active. */
    EGC_GC;
    libxl__spawn_state *ss = CONTAINER_OF(xsw, *ss, xswatch);
    char *p = libxl__xs_read(gc, 0, ss->xspath);
    if (!p && errno != ENOENT) {
        LOG(ERROR, "%s: xenstore read of %s failed", ss->what, ss->xspath);
        spawn_failed(egc, ss); /* must be last */
        return;
    }
    ss->confirm_cb(egc, ss, p); /* must be last */
}

static void spawn_middle_death(libxl__egc *egc, libxl__ev_child *childw,
                               pid_t pid, int status)
    /* Before event, was Active or Detached;
     * is now Active or Detached except that ssd->mid is Idle */
{
    EGC_GC;
    libxl__spawn_state_detachable *ssd = CONTAINER_OF(childw, *ssd, mid);
    libxl__spawn_state *ss = ssd->ss;

    if (!WIFEXITED(status)) {
        const char *what =
            GCSPRINTF("%s intermediate process (startup monitor)",
                      ss ? ss->what : "(detached)");
        int loglevel = ss ? XTL_ERROR : XTL_WARN;
        libxl_report_child_exitstatus(CTX, loglevel, what, pid, status);
    } else if (ss) { /* otherwise it was supposed to be a daemon by now */
        if (!status)
            LOG(ERROR, "%s [%ld]: unexpectedly exited with exit status 0,"
                " when we were waiting for it to confirm startup",
                ss->what, (unsigned long)pid);
        else if (status <= 127)
            LOG(ERROR, "%s [%ld]: failed startup with non-zero exit status %d",
                ss->what, (unsigned long)pid, status);
        else if (status < 255) {
            int sig = status - 128;
            const char *str = strsignal(sig);
            if (str)
                LOG(ERROR, "%s [%ld]: died during startup due to fatal"
                    " signal %s", ss->what, (unsigned long)pid, str);
            else
                LOG(ERROR, "%s [%ld]: died during startup due to unknown fatal"
                    " signal number %d", ss->what, (unsigned long)pid, sig);
        }
        ss->ssd = 0; /* detatch the ssd to make the ss be in state Partial */
        spawn_failed(egc, ss); /* must be last use of ss */
    }
    free(ssd);
}

void libxl__spawn_detach(libxl__gc *gc, libxl__spawn_state *ss)
{
    spawn_cleanup(gc, ss);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
