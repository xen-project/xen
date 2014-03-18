
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
        ssize_t len;
        char path[PATH_MAX];
        char linkpath[PATH_MAX+1];
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
        len = readlink(path, linkpath, PATH_MAX);
        if (len > 0) {
            linkpath[len] = '\0';
            fprintf(stderr, "libxl: execing %s: fd %d is open to %s with flags %#x\n",
                    what, i, linkpath, flags);
        } else
#endif
            fprintf(stderr, "libxl: execing %s: fd %d is open with flags %#x\n",
                    what, i, flags);
    }
    if (debug < 2) return;
    if (badness) abort();
}

void libxl__exec(libxl__gc *gc, int stdinfd, int stdoutfd, int stderrfd,
                 const char *arg0, char *const args[], char *const env[])
     /* call this in the child */
{
    if (stdinfd != -1)
        dup2(stdinfd, STDIN_FILENO);
    if (stdoutfd != -1)
        dup2(stdoutfd, STDOUT_FILENO);
    if (stderrfd != -1)
        dup2(stderrfd, STDERR_FILENO);

    if (stdinfd > 2)
        close(stdinfd);
    if (stdoutfd > 2 && stdoutfd != stdinfd)
        close(stdoutfd);
    if (stderrfd > 2 && stderrfd != stdinfd && stderrfd != stdoutfd)
        close(stderrfd);

    check_open_fds(arg0);

    signal(SIGPIPE, SIG_DFL);
    /* in case our caller set it to IGN.  subprocesses are entitled
     * to assume they got DFL. */

    if (env != NULL) {
        for (int i = 0; env[i] != NULL && env[i+1] != NULL; i += 2) {
            if (setenv(env[i], env[i+1], 1) < 0) {
                LOGEV(ERROR, errno, "setting env vars (%s = %s)",
                                    env[i], env[i+1]);
                goto out;
            }
        }
    }
    execvp(arg0, args);

out:
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

int libxl__xenstore_child_wait_deprecated(libxl__gc *gc,
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
 *                   detaching failed  mid     timeout      xswatch          
 *  - Undefined         undef   undef   -        undef        undef
 *  - Idle              any     any     Idle     Idle         Idle
 *  - Attached OK       0       0       Active   Active       Active
 *  - Attached Failed   0       1       Active   Idle         Idle
 *  - Detaching         1       maybe   Active   Idle         Idle
 *  - Partial           any     any     Idle     Active/Idle  Active/Idle
 *
 * When in states Detaching or Attached Failed, the middle process has
 * been sent a SIGKILL.
 *
 * The difference between Attached OK and Attached Failed is not
 * directly visible to callers - callers see these two the same,
 * although of course Attached OK will hopefully eventually result in
 * a call to detached_cb, whereas Attached Failed will end up
 * in a call to failure_cb.
 */

/* Event callbacks. */
static void spawn_watch_event(libxl__egc *egc, libxl__xswait_state *xswa,
                              int rc, const char *xsdata);
static void spawn_middle_death(libxl__egc *egc, libxl__ev_child *childw,
                               pid_t pid, int status);

/* Precondition: Partial.  Results: Idle. */
static void spawn_cleanup(libxl__gc *gc, libxl__spawn_state *ss);

/* Precondition: Attached or Detaching; caller has logged failure reason.
 * Results: Detaching, or Attached Failed */
static void spawn_fail(libxl__egc *egc, libxl__spawn_state *ss);

void libxl__spawn_init(libxl__spawn_state *ss)
{
    libxl__ev_child_init(&ss->mid);
    libxl__xswait_init(&ss->xswait);
}

int libxl__spawn_spawn(libxl__egc *egc, libxl__spawn_state *ss)
{
    STATE_AO_GC(ss->ao);
    int r;
    pid_t child;
    int status, rc;

    libxl__spawn_init(ss);
    ss->failed = ss->detaching = 0;

    ss->xswait.ao = ao;
    ss->xswait.what = GCSPRINTF("%s startup", ss->what);
    ss->xswait.path = ss->xspath;
    ss->xswait.timeout_ms = ss->timeout_ms;
    ss->xswait.callback = spawn_watch_event;
    rc = libxl__xswait_start(gc, &ss->xswait);
    if (rc) goto out_err;

    pid_t middle = libxl__ev_child_fork(gc, &ss->mid, spawn_middle_death);
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
    assert(!libxl__ev_child_inuse(&ss->mid));
    libxl__xswait_stop(gc, &ss->xswait);
}

static void spawn_detach(libxl__gc *gc, libxl__spawn_state *ss)
/* Precondition: Attached or Detaching, but caller must have just set
 * at least one of detaching or failed.
 * Results: Detaching or Attached Failed */
{
    int r;

    assert(libxl__ev_child_inuse(&ss->mid));
    libxl__xswait_stop(gc, &ss->xswait);

    pid_t child = ss->mid.pid;
    r = kill(child, SIGKILL);
    if (r && errno != ESRCH)
        LOGE(WARN, "%s: failed to kill intermediate child (pid=%lu)",
             ss->what, (unsigned long)child);
}

void libxl__spawn_initiate_detach(libxl__gc *gc, libxl__spawn_state *ss)
{
    ss->detaching = 1;
    spawn_detach(gc, ss);
}

static void spawn_fail(libxl__egc *egc, libxl__spawn_state *ss)
/* Caller must have logged.  Must be last thing in calling function,
 * as it may make the callback.  Precondition: Attached or Detaching. */
{
    EGC_GC;
    ss->failed = 1;
    spawn_detach(gc, ss);
}

static void spawn_watch_event(libxl__egc *egc, libxl__xswait_state *xswa,
                              int rc, const char *p)
{
    /* On entry, is Attached. */
    EGC_GC;
    libxl__spawn_state *ss = CONTAINER_OF(xswa, *ss, xswait);
    if (rc) {
        if (rc == ERROR_TIMEDOUT)
            LOG(ERROR, "%s: startup timed out", ss->what);
        spawn_fail(egc, ss); /* must be last */
        return;
    }
    ss->confirm_cb(egc, ss, p); /* must be last */
}

static void spawn_middle_death(libxl__egc *egc, libxl__ev_child *childw,
                               pid_t pid, int status)
    /* On entry, is Attached or Detaching */
{
    EGC_GC;
    libxl__spawn_state *ss = CONTAINER_OF(childw, *ss, mid);

    if ((ss->failed || ss->detaching) &&
        ((WIFEXITED(status) && WEXITSTATUS(status)==0) ||
         (WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL))) {
        /* as expected */
    } else if (!WIFEXITED(status)) {
        int loglevel = ss->detaching ? XTL_WARN : XTL_ERROR;
        const char *what =
            GCSPRINTF("%s intermediate process (startup monitor)", ss->what);
        libxl_report_child_exitstatus(CTX, loglevel, what, pid, status);
        ss->failed = 1;
    } else {
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
        ss->failed = 1;
    }

    spawn_cleanup(gc, ss);

    if (ss->failed && !ss->detaching) {
        ss->failure_cb(egc, ss); /* must be last */
        return;
    }
    
    if (ss->failed && ss->detaching)
        LOG(WARN,"%s underlying machinery seemed to fail,"
            " but its function seems to have been successful", ss->what);

    assert(ss->detaching);
    ss->detached_cb(egc, ss);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
