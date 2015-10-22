/*
 * Copyright (C) 2012      Citrix Ltd.
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
/*
 * Internal child process machinery for use by other parts of libxl
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

/*
 * carefd arrangements
 *
 * carefd_begin and _unlock take out the no_forking lock, which we
 * also take and release in our pthread_atfork handlers.  So when this
 * lock is held the whole process cannot fork.  We therefore protect
 * our fds from leaking into children made by other threads.
 *
 * We maintain a list of all the carefds, so that if the application
 * wants to fork a long-running but non-execing child, we can close
 * them all.
 *
 * So the record function sets CLOEXEC for the benefit of execing
 * children, and makes a note of the fd for the benefit of non-execing
 * ones.
 */

struct libxl__carefd {
    LIBXL_LIST_ENTRY(libxl__carefd) entry;
    int fd;
};

static pthread_mutex_t no_forking = PTHREAD_MUTEX_INITIALIZER;
static int atfork_registered;
static LIBXL_LIST_HEAD(, libxl__carefd) carefds =
    LIBXL_LIST_HEAD_INITIALIZER(carefds);

/* Protected against concurrency by no_forking.  sigchld_users is
 * protected against being interrupted by SIGCHLD (and thus read
 * asynchronously by the signal handler) by sigchld_defer (see
 * below). */
static bool sigchld_installed; /* 0 means not */
static pthread_mutex_t sigchld_defer_mutex = PTHREAD_MUTEX_INITIALIZER;
static LIBXL_LIST_HEAD(, libxl_ctx) sigchld_users =
    LIBXL_LIST_HEAD_INITIALIZER(sigchld_users);
static struct sigaction sigchld_saved_action;

static void sigchld_removehandler_core(void); /* idempotent */
static void sigchld_user_remove(libxl_ctx *ctx); /* idempotent */
static void sigchld_sethandler_raw(void (*handler)(int), struct sigaction *old);

static void defer_sigchld(void);
static void release_sigchld(void);

static void atfork_lock(void)
{
    int r = pthread_mutex_lock(&no_forking);
    assert(!r);
}

static void atfork_unlock(void)
{
    int r = pthread_mutex_unlock(&no_forking);
    assert(!r);
}

int libxl__atfork_init(libxl_ctx *ctx)
{
    int r, rc;
    
    atfork_lock();
    if (atfork_registered) { rc = 0; goto out; }

    r = pthread_atfork(atfork_lock, atfork_unlock, atfork_unlock);
    if (r) {
        assert(r == ENOMEM);
        libxl__alloc_failed(ctx, __func__, 0,0);
    }

    atfork_registered = 1;
    rc = 0;
 out:
    atfork_unlock();
    return rc;
}

void libxl__carefd_begin(void) { atfork_lock(); }
void libxl__carefd_unlock(void) { atfork_unlock(); }

libxl__carefd *libxl__carefd_record(libxl_ctx *ctx, int fd)
{
    libxl__carefd *cf = 0;

    libxl_fd_set_cloexec(ctx, fd, 1);
    cf = libxl__zalloc(&ctx->nogc_gc, sizeof(*cf));
    cf->fd = fd;
    LIBXL_LIST_INSERT_HEAD(&carefds, cf, entry);
    return cf;
}

libxl__carefd *libxl__carefd_opened(libxl_ctx *ctx, int fd)
{
    libxl__carefd *cf = 0;
    int saved_errno = errno;

    if (fd >= 0)
        cf = libxl__carefd_record(ctx, fd);
    libxl__carefd_unlock();
    errno = saved_errno;
    return cf;
}

void libxl_postfork_child_noexec(libxl_ctx *ctx)
{
    /*
     * Anything running without the no_forking lock (atfork_lock)
     * might be interrupted by fork.  But libxl functions other than
     * this one are then forbidden to the child.
     *
     * Conversely, this function might interrupt any other libxl
     * operation (even though that other operation has the libxl ctx
     * lock).  We don't take the lock ourselves, since we are running
     * in the child and if the lock is held the thread that took it no
     * longer exists.  To prevent us being interrupted by another call
     * to ourselves (whether in another thread or by virtue of another
     * fork) we take the atfork lock ourselves.
     */
    libxl__carefd *cf, *cf_tmp;
    int r;

    atfork_lock();

    LIBXL_LIST_FOREACH_SAFE(cf, &carefds, entry, cf_tmp) {
        if (cf->fd >= 0) {
            r = close(cf->fd);
            if (r)
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_WARNING,
                                 "failed to close fd=%d"
                                 " (perhaps of another libxl ctx)", cf->fd);
        }
        free(cf);
    }
    LIBXL_LIST_INIT(&carefds);

    if (sigchld_installed) {
        /* We are in theory not at risk of concurrent execution of the
         * SIGCHLD handler, because the application should call
         * libxl_postfork_child_noexec before the child forks again.
         * (If the SIGCHLD was in flight in the parent at the time of
         * the fork, the thread it was delivered on exists only in the
         * parent so is not our concern.)
         *
         * But in case the application violated this rule (and did so
         * while multithreaded in the child), we use our deferral
         * machinery.  The result is that the SIGCHLD may then be lost
         * (i.e. signaled to the now-defunct libxl ctx(s)).  But at
         * least we won't execute undefined behaviour (by examining
         * the list in the signal handler concurrently with clearing
         * it here), and since we won't actually reap the new children
         * things will in fact go OK if the application doesn't try to
         * use SIGCHLD, but instead just waits for the child(ren). */
        defer_sigchld();

        LIBXL_LIST_INIT(&sigchld_users);
        /* After this the ->sigchld_user_registered entries in the
         * now-obsolete contexts may be lies.  But that's OK because
         * no-one will look at them. */

        release_sigchld();
        sigchld_removehandler_core();
    }

    atfork_unlock();
}

int libxl__carefd_close(libxl__carefd *cf)
{
    if (!cf) return 0;
    atfork_lock();
    int r = cf->fd < 0 ? 0 : close(cf->fd);
    int esave = errno;
    LIBXL_LIST_REMOVE(cf, entry);
    atfork_unlock();
    free(cf);
    errno = esave;
    return r;
}

int libxl__carefd_fd(const libxl__carefd *cf)
{
    if (!cf) return -1;
    return cf->fd;
}

/*
 * Low-level functions for child process handling, including
 * the main SIGCHLD handler.
 */

/* Like waitpid(,,WNOHANG) but handles all errors except ECHILD. */
static pid_t checked_waitpid(libxl__egc *egc, pid_t want, int *status)
{
    for (;;) {
        pid_t got = waitpid(want, status, WNOHANG);
        if (got != -1)
            return got;
        if (errno == ECHILD)
            return got;
        if (errno == EINTR)
            continue;
        LIBXL__EVENT_DISASTER(egc, "waitpid() failed", errno, 0);
        return 0;
    }
}

static void sigchld_selfpipe_handler(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents);

static void sigchld_handler(int signo)
{
    /* This function has to be reentrant!  Luckily it is. */

    libxl_ctx *notify;
    int esave = errno;

    int r = pthread_mutex_lock(&sigchld_defer_mutex);
    assert(!r);

    LIBXL_LIST_FOREACH(notify, &sigchld_users, sigchld_users_entry) {
        int e = libxl__self_pipe_wakeup(notify->sigchld_selfpipe[1]);
        if (e) abort(); /* errors are probably EBADF, very bad */
    }

    r = pthread_mutex_unlock(&sigchld_defer_mutex);
    assert(!r);

    errno = esave;
}

static void sigchld_sethandler_raw(void (*handler)(int), struct sigaction *old)
{
    struct sigaction ours;
    int r;

    memset(&ours,0,sizeof(ours));
    ours.sa_handler = handler;
    sigemptyset(&ours.sa_mask);
    ours.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    r = sigaction(SIGCHLD, &ours, old);
    assert(!r);
}

/*
 * SIGCHLD deferral
 *
 * sigchld_defer and sigchld_release are a bit like using sigprocmask
 * to block the signal only they work for the whole process.  Sadly
 * this has to be done by setting a special handler that records the
 * "pendingness" of the signal here in the program.  How tedious.
 *
 * A property of this approach is that the signal handler itself
 * must be reentrant (see the comment in release_sigchld).
 *
 * Callers have the atfork_lock so there is no risk of concurrency
 * within these functions, aside from the risk of being interrupted by
 * the signal.  We use sigchld_defer_mutex to guard against the
 * possibility of the real signal handler being still running on
 * another thread.
 */

static volatile sig_atomic_t sigchld_occurred_while_deferred;

static void sigchld_handler_when_deferred(int signo)
{
    sigchld_occurred_while_deferred = 1;
}

static void defer_sigchld(void)
{
    assert(sigchld_installed);

    sigchld_sethandler_raw(sigchld_handler_when_deferred, 0);

    /* Now _this thread_ cannot any longer be interrupted by the
     * signal, so we can take the mutex without risk of deadlock.  If
     * another thread is in the signal handler, either it or we will
     * block and wait for the other. */

    int r = pthread_mutex_lock(&sigchld_defer_mutex);
    assert(!r);
}

static void release_sigchld(void)
{
    assert(sigchld_installed);

    int r = pthread_mutex_unlock(&sigchld_defer_mutex);
    assert(!r);

    sigchld_sethandler_raw(sigchld_handler, 0);
    if (sigchld_occurred_while_deferred) {
        sigchld_occurred_while_deferred = 0;
        /* We might get another SIGCHLD here, in which case
         * sigchld_handler will be interrupted and re-entered.
         * This is OK. */
        sigchld_handler(SIGCHLD);
    }
}

/*
 * Meat of the child process handling.
 */

static void sigchld_removehandler_core(void) /* idempotent */
{
    struct sigaction was;
    int r;
    
    if (!sigchld_installed)
        return;

    r = sigaction(SIGCHLD, &sigchld_saved_action, &was);
    assert(!r);
    assert(!(was.sa_flags & SA_SIGINFO));
    assert(was.sa_handler == sigchld_handler);

    sigchld_installed = 0;
}

static void sigchld_installhandler_core(void) /* idempotent */
{
    if (sigchld_installed)
        return;

    sigchld_installed = 1;

    sigchld_sethandler_raw(sigchld_handler, &sigchld_saved_action);

    assert(((void)"application must negotiate with libxl about SIGCHLD",
            !(sigchld_saved_action.sa_flags & SA_SIGINFO) &&
            (sigchld_saved_action.sa_handler == SIG_DFL ||
             sigchld_saved_action.sa_handler == SIG_IGN)));
}

static void sigchld_user_remove(libxl_ctx *ctx) /* idempotent */
{
    if (!ctx->sigchld_user_registered)
        return;

    atfork_lock();
    defer_sigchld();

    LIBXL_LIST_REMOVE(ctx, sigchld_users_entry);

    release_sigchld();

    if (LIBXL_LIST_EMPTY(&sigchld_users))
        sigchld_removehandler_core();

    atfork_unlock();

    ctx->sigchld_user_registered = 0;
}

void libxl__sigchld_notneeded(libxl__gc *gc) /* non-reentrant, idempotent */
{
    sigchld_user_remove(CTX);
    libxl__ev_fd_deregister(gc, &CTX->sigchld_selfpipe_efd);
}

int libxl__sigchld_needed(libxl__gc *gc) /* non-reentrant, idempotent */
{
    int rc;

    if (CTX->sigchld_selfpipe[0] < 0) {
        rc = libxl__pipe_nonblock(CTX, CTX->sigchld_selfpipe);
        if (rc) goto out;
    }
    if (!libxl__ev_fd_isregistered(&CTX->sigchld_selfpipe_efd)) {
        rc = libxl__ev_fd_register(gc, &CTX->sigchld_selfpipe_efd,
                                   sigchld_selfpipe_handler,
                                   CTX->sigchld_selfpipe[0], POLLIN);
        if (rc) goto out;
    } else {
        rc = libxl__ev_fd_modify(gc, &CTX->sigchld_selfpipe_efd, POLLIN);
        if (rc) goto out;
    }
    if (!CTX->sigchld_user_registered) {
        atfork_lock();

        sigchld_installhandler_core();

        defer_sigchld();

        LIBXL_LIST_INSERT_HEAD(&sigchld_users, CTX, sigchld_users_entry);

        release_sigchld();
        atfork_unlock();

        CTX->sigchld_user_registered = 1;
    }

    rc = 0;
 out:
    return rc;
}

static bool chldmode_ours(libxl_ctx *ctx, bool creating)
{
    switch (ctx->childproc_hooks->chldowner) {
    case libxl_sigchld_owner_libxl:
        return creating || !LIBXL_LIST_EMPTY(&ctx->children);
    case libxl_sigchld_owner_mainloop:
        return 0;
    case libxl_sigchld_owner_libxl_always:
    case libxl_sigchld_owner_libxl_always_selective_reap:
        return 1;
    }
    abort();
}

static void perhaps_sigchld_notneeded(libxl__gc *gc)
{
    if (!chldmode_ours(CTX, 0))
        libxl__sigchld_notneeded(gc);
}

static int perhaps_sigchld_needed(libxl__gc *gc, bool creating)
{
    int rc;

    if (chldmode_ours(CTX, creating)) {
        rc = libxl__sigchld_needed(gc);
        if (rc) return rc;
    }
    return 0;
}

static void childproc_reaped_ours(libxl__egc *egc, libxl__ev_child *ch,
                                 int status)
{
    pid_t pid = ch->pid;
    LIBXL_LIST_REMOVE(ch, entry);
    ch->pid = -1;
    ch->callback(egc, ch, pid, status);
}

static int childproc_reaped(libxl__egc *egc, pid_t pid, int status)
{
    EGC_GC;
    libxl__ev_child *ch;

    LIBXL_LIST_FOREACH(ch, &CTX->children, entry)
        if (ch->pid == pid)
            goto found;

    /* not found */
    return ERROR_UNKNOWN_CHILD;

 found:
    childproc_reaped_ours(egc, ch, status);

    perhaps_sigchld_notneeded(gc);

    return 0;
}

int libxl_childproc_reaped(libxl_ctx *ctx, pid_t pid, int status)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    assert(CTX->childproc_hooks->chldowner
           == libxl_sigchld_owner_mainloop);
    int rc = childproc_reaped(egc, pid, status);
    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}

static void childproc_checkall(libxl__egc *egc)
{
    EGC_GC;
    libxl__ev_child *ch;

    for (;;) {
        int status;
        pid_t got;

        LIBXL_LIST_FOREACH(ch, &CTX->children, entry) {
            got = checked_waitpid(egc, ch->pid, &status);
            if (got)
                goto found;
        }
        /* not found */
        return;

    found:
        if (got == -1) {
            LIBXL__EVENT_DISASTER
                (egc, "waitpid() gave ECHILD but we have a child",
                 ECHILD, 0);
            /* it must have finished but we don't know its status */
            status = 255<<8; /* no wait.h macro for this! */
            assert(WIFEXITED(status));
            assert(WEXITSTATUS(status)==255);
            assert(!WIFSIGNALED(status));
            assert(!WIFSTOPPED(status));
        }
        childproc_reaped_ours(egc, ch, status);
        /* we need to restart the loop, as children may have been edited */
    }
}

void libxl_childproc_sigchld_occurred(libxl_ctx *ctx)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    assert(CTX->childproc_hooks->chldowner
           == libxl_sigchld_owner_mainloop);
    childproc_checkall(egc);
    CTX_UNLOCK;
    EGC_FREE;
}

static void sigchld_selfpipe_handler(libxl__egc *egc, libxl__ev_fd *ev,
                                     int fd, short events, short revents)
{
    /* May make callbacks into the application for child processes.
     * So, this function may unlock and relock the CTX.  This is OK
     * because event callback functions are always called with the CTX
     * locked exactly once, and from code which copes with reentrancy.
     * (See also the comment in afterpoll_internal.) */
    EGC_GC;

    int selfpipe = CTX->sigchld_selfpipe[0];

    if (revents & ~POLLIN) {
        LOG(ERROR, "unexpected poll event 0x%x on SIGCHLD self pipe", revents);
        LIBXL__EVENT_DISASTER(egc,
                              "unexpected poll event on SIGCHLD self pipe",
                              0, 0);
    }
    assert(revents & POLLIN);

    int e = libxl__self_pipe_eatall(selfpipe);
    if (e) LIBXL__EVENT_DISASTER(egc, "read sigchld pipe", e, 0);

    if (CTX->childproc_hooks->chldowner
        == libxl_sigchld_owner_libxl_always_selective_reap) {
        childproc_checkall(egc);
        return;
    }

    while (chldmode_ours(CTX, 0) /* in case the app changes the mode */) {
        int status;
        pid_t pid = checked_waitpid(egc, -1, &status);

        if (pid == 0 || pid == -1 /* ECHILD */)
            return;

        int rc = childproc_reaped(egc, pid, status);

        if (rc) {
            if (CTX->childproc_hooks->reaped_callback) {
                CTX_UNLOCK;
                rc = CTX->childproc_hooks->reaped_callback
                        (pid, status, CTX->childproc_user);
                CTX_LOCK;
                if (rc != 0 && rc != ERROR_UNKNOWN_CHILD) {
                    char disasterbuf[200];
                    snprintf(disasterbuf, sizeof(disasterbuf), " reported by"
                             " libxl_childproc_hooks->reaped_callback"
                             " (for pid=%lu, status=%d; error code %d)",
                             (unsigned long)pid, status, rc);
                    LIBXL__EVENT_DISASTER(egc, disasterbuf, 0, 0);
                    return;
                }
            } else {
                rc = ERROR_UNKNOWN_CHILD;
            }
            if (rc)
                libxl_report_child_exitstatus(CTX, XTL_WARN,
                                "unknown child", (long)pid, status);
        }
    }
}

pid_t libxl__ev_child_fork(libxl__gc *gc, libxl__ev_child *ch,
                           libxl__ev_child_callback *death)
{
    CTX_LOCK;
    int rc;

    perhaps_sigchld_needed(gc, 1);

    pid_t pid =
        CTX->childproc_hooks->fork_replacement
        ? CTX->childproc_hooks->fork_replacement(CTX->childproc_user)
        : fork();
    if (pid == -1) {
        LOGE(ERROR, "fork failed");
        rc = ERROR_FAIL;
        goto out;
    }

    if (!pid) {
        /* woohoo! */
        if (CTX->xsh) {
            xs_daemon_destroy_postfork(CTX->xsh);
            CTX->xsh = NULL; /* turns mistakes into crashes */
        }
        /* Yes, CTX is left locked in the child. */
        return 0;
    }

    ch->pid = pid;
    ch->callback = death;
    LIBXL_LIST_INSERT_HEAD(&CTX->children, ch, entry);
    rc = pid;

 out:
    perhaps_sigchld_notneeded(gc);
    CTX_UNLOCK;
    return rc;
}

void libxl_childproc_setmode(libxl_ctx *ctx, const libxl_childproc_hooks *hooks,
                             void *user)
{
    GC_INIT(ctx);
    CTX_LOCK;

    assert(LIBXL_LIST_EMPTY(&CTX->children));

    if (!hooks)
        hooks = &libxl__childproc_default_hooks;

    ctx->childproc_hooks = hooks;
    ctx->childproc_user = user;

    perhaps_sigchld_notneeded(gc);
    perhaps_sigchld_needed(gc, 0); /* idempotent, ok to ignore errors for now */

    CTX_UNLOCK;
    GC_FREE;
}

const libxl_childproc_hooks libxl__childproc_default_hooks = {
    libxl_sigchld_owner_libxl, 0, 0
};

int libxl__ev_child_xenstore_reopen(libxl__gc *gc, const char *what) {
    int rc;

    assert(!CTX->xsh);
    CTX->xsh = xs_daemon_open();
    if (!CTX->xsh) {
        LOGE(ERROR, "%s: xenstore reopen failed", what);
        rc = ERROR_FAIL;  goto out;
    }

    libxl_fd_set_cloexec(CTX, xs_fileno(CTX->xsh), 1);

    return 0;

 out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
