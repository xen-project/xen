/*
 * Copyright (C) 2010      Citrix Ltd.
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

/*----- xswait -----*/

static libxl__ev_xswatch_callback xswait_xswatch_callback;
static libxl__ev_time_callback xswait_timeout_callback;
static void xswait_report_error(libxl__egc*, libxl__xswait_state*, int rc);

void libxl__xswait_init(libxl__xswait_state *xswa)
{
    libxl__ev_time_init(&xswa->time_ev);
    libxl__ev_xswatch_init(&xswa->watch_ev);
}

void libxl__xswait_stop(libxl__gc *gc, libxl__xswait_state *xswa)
{
    libxl__ev_time_deregister(gc, &xswa->time_ev);
    libxl__ev_xswatch_deregister(gc, &xswa->watch_ev);
}

bool libxl__xswait_inuse(const libxl__xswait_state *xswa)
{
    bool time_inuse = libxl__ev_time_isregistered(&xswa->time_ev);
    bool watch_inuse = libxl__ev_xswatch_isregistered(&xswa->watch_ev);
    assert(time_inuse == watch_inuse);
    return time_inuse;
}

int libxl__xswait_start(libxl__gc *gc, libxl__xswait_state *xswa)
{
    int rc;

    rc = libxl__ev_time_register_rel(xswa->ao, &xswa->time_ev,
                                     xswait_timeout_callback, xswa->timeout_ms);
    if (rc) goto err;

    rc = libxl__ev_xswatch_register(gc, &xswa->watch_ev,
                                    xswait_xswatch_callback, xswa->path);
    if (rc) goto err;

    return 0;

 err:
    libxl__xswait_stop(gc, xswa);
    return rc;
}

void xswait_xswatch_callback(libxl__egc *egc, libxl__ev_xswatch *xsw,
                             const char *watch_path, const char *event_path)
{
    EGC_GC;
    libxl__xswait_state *xswa = CONTAINER_OF(xsw, *xswa, watch_ev);
    int rc;
    const char *data;

    if (xswa->path[0] == '@') {
        data = 0;
    } else {
        rc = libxl__xs_read_checked(gc, XBT_NULL, xswa->path, &data);
        if (rc) { xswait_report_error(egc, xswa, rc); return; }
    }

    xswa->callback(egc, xswa, 0, data);
}

void xswait_timeout_callback(libxl__egc *egc, libxl__ev_time *ev,
                             const struct timeval *requested_abs,
                             int rc)
{
    EGC_GC;
    libxl__xswait_state *xswa = CONTAINER_OF(ev, *xswa, time_ev);
    LOG(DEBUG, "%s: xswait timeout (path=%s)", xswa->what, xswa->path);
    xswait_report_error(egc, xswa, rc);
}

static void xswait_report_error(libxl__egc *egc, libxl__xswait_state *xswa,
                                int rc)
{
    EGC_GC;
    libxl__xswait_stop(gc, xswa);
    xswa->callback(egc, xswa, rc, 0);
}


/*----- data copier -----*/

void libxl__datacopier_init(libxl__datacopier_state *dc)
{
    assert(dc->ao);
    libxl__ao_abortable_init(&dc->abrt);
    libxl__ev_fd_init(&dc->toread);
    libxl__ev_fd_init(&dc->towrite);
    LIBXL_TAILQ_INIT(&dc->bufs);
}

void libxl__datacopier_kill(libxl__datacopier_state *dc)
{
    STATE_AO_GC(dc->ao);
    libxl__datacopier_buf *buf, *tbuf;

    libxl__ao_abortable_deregister(&dc->abrt);
    libxl__ev_fd_deregister(gc, &dc->toread);
    libxl__ev_fd_deregister(gc, &dc->towrite);
    LIBXL_TAILQ_FOREACH_SAFE(buf, &dc->bufs, entry, tbuf)
        free(buf);
    LIBXL_TAILQ_INIT(&dc->bufs);
}

static void datacopier_callback(libxl__egc *egc, libxl__datacopier_state *dc,
                                int rc, int onwrite, int errnoval)
{
    libxl__datacopier_kill(dc);
    dc->callback(egc, dc, rc, onwrite, errnoval);
}

static void datacopier_writable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents);

static void datacopier_check_state(libxl__egc *egc, libxl__datacopier_state *dc)
{
    STATE_AO_GC(dc->ao);
    int rc;
    
    if (dc->used && !dc->readbuf) {
        if (!libxl__ev_fd_isregistered(&dc->towrite)) {
            rc = libxl__ev_fd_register(gc, &dc->towrite, datacopier_writable,
                                       dc->writefd, POLLOUT);
            if (rc) {
                LOG(ERROR, "unable to establish write event on %s"
                    " during copy of %s", dc->writewhat, dc->copywhat);
                datacopier_callback(egc, dc, ERROR_FAIL, -1, EIO);
                return;
            }
        }
    } else if (!libxl__ev_fd_isregistered(&dc->toread) ||
               dc->bytes_to_read == 0) {
        /* we have had eof */
        datacopier_callback(egc, dc, 0, 0, 0);
        return;
    } else {
        /* nothing buffered, but still reading */
        libxl__ev_fd_deregister(gc, &dc->towrite);
    }
}

void libxl__datacopier_prefixdata(libxl__egc *egc, libxl__datacopier_state *dc,
                                  const void *data, size_t len)
{
    EGC_GC;
    libxl__datacopier_buf *buf;
    const uint8_t *ptr;

    /*
     * It is safe for this to be called immediately after _start, as
     * is documented in the public comment.  _start's caller must have
     * the ctx locked, so other threads don't get to mess with the
     * contents, and the fd events cannot happen reentrantly.  So we
     * are guaranteed to beat the first data from the read fd.
     */

    assert(len < dc->maxsz - dc->used);

    for (ptr = data; len; len -= buf->used, ptr += buf->used) {
        buf = libxl__malloc(NOGC, sizeof(*buf));
        buf->used = min(len, sizeof(buf->buf));
        memcpy(buf->buf, ptr, buf->used);

        dc->used += buf->used;
        LIBXL_TAILQ_INSERT_TAIL(&dc->bufs, buf, entry);
    }
}

static int datacopier_pollhup_handled(libxl__egc *egc,
                                      libxl__datacopier_state *dc,
                                      int fd, short revents, int onwrite)
{
    STATE_AO_GC(dc->ao);

    if (dc->callback_pollhup && (revents & POLLHUP)) {
        LOG(DEBUG, "received POLLHUP on fd %d: %s during copy of %s",
            fd, onwrite ? dc->writewhat : dc->readwhat, dc->copywhat);
        libxl__datacopier_kill(dc);
        dc->callback_pollhup(egc, dc, ERROR_FAIL, onwrite, -1);
        return 1;
    }
    return 0;
}

static void datacopier_abort(libxl__egc *egc, libxl__ao_abortable *abrt,
                             int rc)
{
    libxl__datacopier_state *dc = CONTAINER_OF(abrt, *dc, abrt);
    STATE_AO_GC(dc->ao);

    datacopier_callback(egc, dc, rc, -1, 0);
}

static void datacopier_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents) {
    libxl__datacopier_state *dc = CONTAINER_OF(ev, *dc, toread);
    STATE_AO_GC(dc->ao);

    if (datacopier_pollhup_handled(egc, dc, fd, revents, 0))
        return;

    if (revents & ~(POLLIN|POLLHUP)) {
        LOG(ERROR, "unexpected poll event 0x%x on fd %d (expected POLLIN "
            "and/or POLLHUP) reading %s during copy of %s",
            revents, fd, dc->readwhat, dc->copywhat);
        datacopier_callback(egc, dc, ERROR_FAIL, -1, EIO);
        return;
    }
    assert(revents & (POLLIN|POLLHUP));
    for (;;) {
        libxl__datacopier_buf *buf = NULL;
        int r;

        if (dc->readbuf) {
            r = read(ev->fd, dc->readbuf + dc->used, dc->bytes_to_read);
        } else {
            while (dc->used >= dc->maxsz) {
                libxl__datacopier_buf *rm = LIBXL_TAILQ_FIRST(&dc->bufs);
                dc->used -= rm->used;
                assert(dc->used >= 0);
                LIBXL_TAILQ_REMOVE(&dc->bufs, rm, entry);
                free(rm);
            }

            buf = LIBXL_TAILQ_LAST(&dc->bufs, libxl__datacopier_bufs);
            if (!buf || buf->used >= sizeof(buf->buf)) {
                buf = libxl__malloc(NOGC, sizeof(*buf));
                buf->used = 0;
                LIBXL_TAILQ_INSERT_TAIL(&dc->bufs, buf, entry);
            }
            r = read(ev->fd, buf->buf + buf->used,
                     min_t(size_t, sizeof(buf->buf) - buf->used,
                           (dc->bytes_to_read == -1) ? SIZE_MAX : dc->bytes_to_read));
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            assert(errno);
            if (errno == EWOULDBLOCK) {
                if (revents & POLLHUP) {
                    LOG(ERROR,
                        "poll reported HUP but fd read gave EWOULDBLOCK"
                        " on %s during copy of %s",
                        dc->readwhat, dc->copywhat);
                    datacopier_callback(egc, dc, ERROR_FAIL, -1, 0);
                    return;
                }
                break;
            }
            LOGE(ERROR, "error reading %s during copy of %s",
                 dc->readwhat, dc->copywhat);
            datacopier_callback(egc, dc, ERROR_FAIL, 0, errno);
            return;
        }
        if (r == 0) {
            if (dc->callback_pollhup) {
                /* It might be that this "eof" is actually a HUP.  If
                 * the caller cares about the difference,
                 * double-check using poll(2). */
                struct pollfd hupchk;
                hupchk.fd = ev->fd;
                hupchk.events = POLLIN;
                hupchk.revents = 0;
                r = poll(&hupchk, 1, 0);
                if (r < 0)
                    LIBXL__EVENT_DISASTER(gc,
     "unexpected failure polling fd for datacopier eof hup check",
                                  errno, 0);
                if (datacopier_pollhup_handled(egc, dc, fd, hupchk.revents, 0))
                    return;
            }
            libxl__ev_fd_deregister(gc, &dc->toread);
            break;
        }
        if (dc->log) {
            int wrote = fwrite(buf->buf + buf->used, 1, r, dc->log);
            if (wrote != r) {
                assert(ferror(dc->log));
                assert(errno);
                LOGE(ERROR, "error logging %s", dc->copywhat);
                datacopier_callback(egc, dc, ERROR_FAIL, 0, errno);
                return;
            }
        }
        if (!dc->readbuf) {
            buf->used += r;
            assert(buf->used <= sizeof(buf->buf));
        }
        dc->used += r;
        if (dc->bytes_to_read > 0)
            dc->bytes_to_read -= r;
        if (dc->bytes_to_read == 0)
            break;
    }
    datacopier_check_state(egc, dc);
}

static void datacopier_writable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents) {
    libxl__datacopier_state *dc = CONTAINER_OF(ev, *dc, towrite);
    STATE_AO_GC(dc->ao);

    if (datacopier_pollhup_handled(egc, dc, fd, revents, 1))
        return;

    if (revents & ~POLLOUT) {
        LOG(ERROR, "unexpected poll event 0x%x on fd %d (should be POLLOUT)"
            " writing %s during copy of %s",
            revents, fd, dc->writewhat, dc->copywhat);
        datacopier_callback(egc, dc, ERROR_FAIL, -1, EIO);
        return;
    }
    assert(revents & POLLOUT);
    for (;;) {
        libxl__datacopier_buf *buf = LIBXL_TAILQ_FIRST(&dc->bufs);
        if (!buf)
            break;
        if (!buf->used) {
            LIBXL_TAILQ_REMOVE(&dc->bufs, buf, entry);
            free(buf);
            continue;
        }
        int r = write(ev->fd, buf->buf, buf->used);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EWOULDBLOCK) break;
            assert(errno);
            LOGE(ERROR, "error writing to %s during copy of %s",
                 dc->writewhat, dc->copywhat);
            datacopier_callback(egc, dc, ERROR_FAIL, 1, errno);
            return;
        }
        assert(r > 0);
        assert(r <= buf->used);
        buf->used -= r;
        dc->used -= r;
        assert(dc->used >= 0);
        memmove(buf->buf, buf->buf+r, buf->used);
    }
    datacopier_check_state(egc, dc);
}

int libxl__datacopier_start(libxl__datacopier_state *dc)
{
    int rc;
    STATE_AO_GC(dc->ao);

    libxl__datacopier_init(dc);

    assert(dc->readfd >= 0 || dc->writefd >= 0);
    assert(!(dc->readbuf && dc->bytes_to_read == -1));

    dc->abrt.ao = ao;
    dc->abrt.callback = datacopier_abort;
    rc = libxl__ao_abortable_register(&dc->abrt);
    if (rc) goto out;

    if (dc->readfd >= 0) {
        rc = libxl__ev_fd_register(gc, &dc->toread, datacopier_readable,
                                   dc->readfd, POLLIN);
        if (rc) goto out;
    }

    if (dc->writefd >= 0) {
        rc = libxl__ev_fd_register(gc, &dc->towrite, datacopier_writable,
                                   dc->writefd, POLLOUT);
        if (rc) goto out;
    }

    return 0;

 out:
    libxl__datacopier_kill(dc);
    return rc;
}

/*----- openpty -----*/

/* implementation */
    
static void openpty_cleanup(libxl__openpty_state *op)
{
    int i;

    for (i=0; i<op->count; i++) {
        libxl__openpty_result *res = &op->results[i];
        libxl__carefd_close(res->master);  res->master = 0;
        libxl__carefd_close(res->slave);   res->slave = 0;
    }
}

static void openpty_exited(libxl__egc *egc, libxl__ev_child *child,
                           pid_t pid, int status) {
    libxl__openpty_state *op = CONTAINER_OF(child, *op, child);
    STATE_AO_GC(op->ao);

    if (status) {
        /* Perhaps the child gave us the fds and then exited nonzero.
         * Well that would be odd but we don't really care. */
        libxl_report_child_exitstatus(CTX, op->rc ? LIBXL__LOG_ERROR
                                                  : LIBXL__LOG_WARNING,
                                      "openpty child", pid, status);
    }
    if (op->rc)
        openpty_cleanup(op);
    op->callback(egc, op);
}

int libxl__openptys(libxl__openpty_state *op,
                    struct termios *termp,
                    struct winsize *winp) {
    /*
     * This is completely crazy.  openpty calls grantpt which the spec
     * says may fork, and may not be called with a SIGCHLD handler.
     * Now our application may have a SIGCHLD handler so that's bad.
     * We could perhaps block it but we'd need to block it on all
     * threads.  This is just Too Hard.
     *
     * So instead, we run openpty in a child process.  That child
     * process then of course has only our own thread and our own
     * signal handlers.  We pass the fds back.
     *
     * Since our only current caller actually wants two ptys, we
     * support calling openpty multiple times for a single fork.
     */
    STATE_AO_GC(op->ao);
    int count = op->count;
    int r, i, rc, sockets[2], ptyfds[count][2];
    libxl__carefd *for_child = 0;
    pid_t pid = -1;

    for (i=0; i<count; i++) {
        ptyfds[i][0] = ptyfds[i][1] = -1;
        libxl__openpty_result *res = &op->results[i];
        assert(!res->master);
        assert(!res->slave);
    }
    sockets[0] = sockets[1] = -1; /* 0 is for us, 1 for our child */

    libxl__carefd_begin();
    r = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    if (r) { sockets[0] = sockets[1] = -1; }
    for_child = libxl__carefd_opened(CTX, sockets[1]);
    if (r) { LOGE(ERROR,"socketpair failed"); rc = ERROR_FAIL; goto out; }

    pid = libxl__ev_child_fork(gc, &op->child, openpty_exited);
    if (pid == -1) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (!pid) {
        /* child */
        close(sockets[0]);
        signal(SIGCHLD, SIG_DFL);

        for (i=0; i<count; i++) {
            r = openpty(&ptyfds[i][0], &ptyfds[i][1], NULL, termp, winp);
            if (r) { LOGE(ERROR,"openpty failed"); _exit(-1); }
        }
        rc = libxl__sendmsg_fds(gc, sockets[1], '\0',
                                2*count, &ptyfds[0][0], "ptys");
        if (rc) { LOGE(ERROR,"sendmsg to parent failed"); _exit(-1); }
        _exit(0);
    }

    libxl__carefd_close(for_child);
    for_child = 0;

    /* this should be fast so do it synchronously */

    libxl__carefd_begin();
    char buf[1];
    rc = libxl__recvmsg_fds(gc, sockets[0], buf,1,
                            2*count, &ptyfds[0][0], "ptys");
    if (!rc) {
        for (i=0; i<count; i++) {
            libxl__openpty_result *res = &op->results[i];
            res->master = libxl__carefd_record(CTX, ptyfds[i][0]);
            res->slave =  libxl__carefd_record(CTX, ptyfds[i][1]);
        }
    }
    /* now the pty fds are in the carefds, if they were ever open */
    libxl__carefd_unlock();
    if (rc)
        goto out;

    rc = 0;

 out:
    if (sockets[0] >= 0) close(sockets[0]);
    libxl__carefd_close(for_child);
    if (libxl__ev_child_inuse(&op->child)) {
        op->rc = rc;
        /* we will get a callback when the child dies */
        return 0;
    }

    assert(rc);
    openpty_cleanup(op);
    return rc;
}

/*----- async exec -----*/

static void async_exec_timeout(libxl__egc *egc,
                               libxl__ev_time *ev,
                               const struct timeval *requested_abs,
                               int rc)
{
    libxl__async_exec_state *aes = CONTAINER_OF(ev, *aes, time);
    STATE_AO_GC(aes->ao);

    if (!aes->rc)
        aes->rc = rc;

    libxl__ev_time_deregister(gc, &aes->time);

    assert(libxl__ev_child_inuse(&aes->child));
    LOG(ERROR, "killing execution of %s because of timeout", aes->what);

    if (kill(aes->child.pid, SIGKILL)) {
        LOGEV(ERROR, errno, "unable to kill %s [%ld]",
              aes->what, (unsigned long)aes->child.pid);
    }

    return;
}

static void async_exec_done(libxl__egc *egc,
                            libxl__ev_child *child,
                            pid_t pid, int status)
{
    libxl__async_exec_state *aes = CONTAINER_OF(child, *aes, child);
    STATE_AO_GC(aes->ao);

    libxl__ev_time_deregister(gc, &aes->time);

    if (status) {
        if (!aes->rc)
            libxl_report_child_exitstatus(CTX, LIBXL__LOG_ERROR,
                                          aes->what, pid, status);
    }

    aes->callback(egc, aes, aes->rc, status);
}

void libxl__async_exec_init(libxl__async_exec_state *aes)
{
    libxl__ev_time_init(&aes->time);
    libxl__ev_child_init(&aes->child);
}

int libxl__async_exec_start(libxl__async_exec_state *aes)
{
    pid_t pid;

    /* Convenience aliases */
    libxl__ao *ao = aes->ao;
    AO_GC;
    libxl__ev_child *const child = &aes->child;
    char ** const args = aes->args;

    aes->rc = 0;

    /* Set execution timeout */
    if (libxl__ev_time_register_rel(ao, &aes->time,
                                    async_exec_timeout,
                                    aes->timeout_ms)) {
        LOG(ERROR, "unable to register timeout for executing: %s", aes->what);
        goto out;
    }

    LOG(DEBUG, "forking to execute: %s ", aes->what);

    /* Fork and exec */
    pid = libxl__ev_child_fork(gc, child, async_exec_done);
    if (pid == -1) {
        LOG(ERROR, "unable to fork");
        goto out;
    }

    if (!pid) {
        /* child */
        libxl__exec(gc, aes->stdfds[0], aes->stdfds[1],
                    aes->stdfds[2], args[0], args, aes->env);
    }

    return 0;

out:
    return ERROR_FAIL;
}

bool libxl__async_exec_inuse(const libxl__async_exec_state *aes)
{
    bool time_inuse = libxl__ev_time_isregistered(&aes->time);
    bool child_inuse = libxl__ev_child_inuse(&aes->child);
    assert(time_inuse == child_inuse);
    return child_inuse;
}

void libxl__kill(libxl__gc *gc, pid_t pid, int sig, const char *what)
{
    int r = kill(pid, sig);
    if (r) LOGE(WARN, "failed to kill() %s [%lu] (signal %d)",
                what, (unsigned long)pid, sig);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
