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

/*----- data copier -----*/

void libxl__datacopier_init(libxl__datacopier_state *dc)
{
    assert(dc->ao);
    libxl__ev_fd_init(&dc->toread);
    libxl__ev_fd_init(&dc->towrite);
    LIBXL_TAILQ_INIT(&dc->bufs);
}

void libxl__datacopier_kill(libxl__datacopier_state *dc)
{
    STATE_AO_GC(dc->ao);
    libxl__datacopier_buf *buf, *tbuf;

    libxl__ev_fd_deregister(gc, &dc->toread);
    libxl__ev_fd_deregister(gc, &dc->towrite);
    LIBXL_TAILQ_FOREACH_SAFE(buf, &dc->bufs, entry, tbuf)
        free(buf);
    LIBXL_TAILQ_INIT(&dc->bufs);
}

static void datacopier_callback(libxl__egc *egc, libxl__datacopier_state *dc,
                                int onwrite, int errnoval)
{
    libxl__datacopier_kill(dc);
    dc->callback(egc, dc, onwrite, errnoval);
}

static void datacopier_writable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents);

static void datacopier_check_state(libxl__egc *egc, libxl__datacopier_state *dc)
{
    STATE_AO_GC(dc->ao);
    int rc;
    
    if (dc->used) {
        if (!libxl__ev_fd_isregistered(&dc->towrite)) {
            rc = libxl__ev_fd_register(gc, &dc->towrite, datacopier_writable,
                                       dc->writefd, POLLOUT);
            if (rc) {
                LOG(ERROR, "unable to establish write event on %s"
                    " during copy of %s", dc->writewhat, dc->copywhat);
                datacopier_callback(egc, dc, -1, 0);
                return;
            }
        }
    } else if (!libxl__ev_fd_isregistered(&dc->toread)) {
        /* we have had eof */
        datacopier_callback(egc, dc, 0, 0);
        return;
    } else {
        /* nothing buffered, but still reading */
        libxl__ev_fd_deregister(gc, &dc->towrite);
    }
}

static void datacopier_readable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents) {
    libxl__datacopier_state *dc = CONTAINER_OF(ev, *dc, toread);
    STATE_AO_GC(dc->ao);

    if (revents & ~POLLIN) {
        LOG(ERROR, "unexpected poll event 0x%x (should be POLLIN)"
            " on %s during copy of %s", revents, dc->readwhat, dc->copywhat);
        datacopier_callback(egc, dc, -1, 0);
        return;
    }
    assert(revents & POLLIN);
    for (;;) {
        while (dc->used >= dc->maxsz) {
            libxl__datacopier_buf *rm = LIBXL_TAILQ_FIRST(&dc->bufs);
            dc->used -= rm->used;
            assert(dc->used >= 0);
            LIBXL_TAILQ_REMOVE(&dc->bufs, rm, entry);
            free(rm);
        }

        libxl__datacopier_buf *buf =
            LIBXL_TAILQ_LAST(&dc->bufs, libxl__datacopier_bufs);
        if (!buf || buf->used >= sizeof(buf->buf)) {
            buf = malloc(sizeof(*buf));
            if (!buf) libxl__alloc_failed(CTX, __func__, 1, sizeof(*buf));
            buf->used = 0;
            LIBXL_TAILQ_INSERT_TAIL(&dc->bufs, buf, entry);
        }
        int r = read(ev->fd,
                     buf->buf + buf->used,
                     sizeof(buf->buf) - buf->used);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EWOULDBLOCK) break;
            LOGE(ERROR, "error reading %s during copy of %s",
                 dc->readwhat, dc->copywhat);
            datacopier_callback(egc, dc, 0, errno);
            return;
        }
        if (r == 0) {
            libxl__ev_fd_deregister(gc, &dc->toread);
            break;
        }
        buf->used += r;
        dc->used += r;
        assert(buf->used <= sizeof(buf->buf));
    }
    datacopier_check_state(egc, dc);
}

static void datacopier_writable(libxl__egc *egc, libxl__ev_fd *ev,
                                int fd, short events, short revents) {
    libxl__datacopier_state *dc = CONTAINER_OF(ev, *dc, towrite);
    STATE_AO_GC(dc->ao);

    if (revents & ~POLLOUT) {
        LOG(ERROR, "unexpected poll event 0x%x (should be POLLOUT)"
            " on %s during copy of %s", revents, dc->writewhat, dc->copywhat);
        datacopier_callback(egc, dc, -1, 0);
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
            LOGE(ERROR, "error writing to %s during copy of %s",
                 dc->writewhat, dc->copywhat);
            datacopier_callback(egc, dc, 1, errno);
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

    rc = libxl__ev_fd_register(gc, &dc->toread, datacopier_readable,
                               dc->readfd, POLLIN);
    if (rc) goto out;

    rc = libxl__ev_fd_register(gc, &dc->towrite, datacopier_writable,
                               dc->writefd, POLLOUT);
    if (rc) goto out;

    return 0;

 out:
    libxl__datacopier_kill(dc);
    return rc;
}

