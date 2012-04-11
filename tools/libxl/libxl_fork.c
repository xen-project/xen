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
    cf = libxl__zalloc(NULL, sizeof(*cf));
    cf->fd = fd;
    LIBXL_LIST_INSERT_HEAD(&carefds, cf, entry);
    return cf;
}

libxl__carefd *libxl__carefd_opened(libxl_ctx *ctx, int fd)
{
    libxl__carefd *cf = 0;

    cf = libxl__carefd_record(ctx, fd);
    libxl__carefd_unlock();
    return cf;
}

void libxl_postfork_child_noexec(libxl_ctx *ctx)
{
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
    atfork_unlock();
}

int libxl__carefd_close(libxl__carefd *cf)
{
    if (!cf) return 0;
    int r = cf->fd < 0 ? 0 : close(cf->fd);
    int esave = errno;
    atfork_lock();
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
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
