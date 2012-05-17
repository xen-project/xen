/*
 * Copyright (C) 2011      Citrix Ltd.
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
 * Internal event machinery for use by other parts of libxl
 */

#include <poll.h>

#include "libxl_internal.h"

/*
 * The counter osevent_in_hook is used to ensure that the application
 * honours the reentrancy restriction documented in libxl_event.h.
 *
 * The application's registration hooks should be called ONLY via
 * these macros, with the ctx locked.  Likewise all the "occurred"
 * entrypoints from the application should assert(!in_hook);
 */
#define OSEVENT_HOOK_INTERN(retval, hookname, ...) do {                      \
    if (CTX->osevent_hooks) {                                                \
        CTX->osevent_in_hook++;                                              \
        retval CTX->osevent_hooks->hookname(CTX->osevent_user, __VA_ARGS__); \
        CTX->osevent_in_hook--;                                              \
    }                                                                        \
} while (0)

#define OSEVENT_HOOK(hookname, ...) ({                                       \
    int osevent_hook_rc = 0;                                                 \
    OSEVENT_HOOK_INTERN(osevent_hook_rc = , hookname, __VA_ARGS__);          \
    osevent_hook_rc;                                                         \
})

#define OSEVENT_HOOK_VOID(hookname, ...) \
    OSEVENT_HOOK_INTERN(/* void */, hookname, __VA_ARGS__)

/*
 * fd events
 */

int libxl__ev_fd_register(libxl__gc *gc, libxl__ev_fd *ev,
                          libxl__ev_fd_callback *func,
                          int fd, short events)
{
    int rc;

    assert(fd >= 0);

    CTX_LOCK;

    rc = OSEVENT_HOOK(fd_register, fd, &ev->for_app_reg, events, ev);
    if (rc) goto out;

    ev->fd = fd;
    ev->events = events;
    ev->func = func;

    LIBXL_LIST_INSERT_HEAD(&CTX->efds, ev, entry);

    rc = 0;

 out:
    CTX_UNLOCK;
    return rc;
}

int libxl__ev_fd_modify(libxl__gc *gc, libxl__ev_fd *ev, short events)
{
    int rc;

    CTX_LOCK;
    assert(libxl__ev_fd_isregistered(ev));

    rc = OSEVENT_HOOK(fd_modify, ev->fd, &ev->for_app_reg, events);
    if (rc) goto out;

    ev->events = events;

    rc = 0;
 out:
    CTX_UNLOCK;
    return rc;
}

void libxl__ev_fd_deregister(libxl__gc *gc, libxl__ev_fd *ev)
{
    CTX_LOCK;

    if (!libxl__ev_fd_isregistered(ev))
        goto out;

    OSEVENT_HOOK_VOID(fd_deregister, ev->fd, ev->for_app_reg);
    LIBXL_LIST_REMOVE(ev, entry);
    ev->fd = -1;

 out:
    CTX_UNLOCK;
}

/*
 * timeouts
 */


int libxl__gettimeofday(libxl__gc *gc, struct timeval *now_r)
{
    int rc = gettimeofday(now_r, 0);
    if (rc) {
        LIBXL__LOG_ERRNO(CTX, LIBXL__LOG_ERROR, "gettimeofday failed");
        return ERROR_FAIL;
    }
    return 0;
}

static int time_rel_to_abs(libxl__gc *gc, int ms, struct timeval *abs_out)
{
    int rc;
    struct timeval additional = {
        .tv_sec = ms / 1000,
        .tv_usec = (ms % 1000) * 1000
    };
    struct timeval now;

    rc = libxl__gettimeofday(gc, &now);
    if (rc) return rc;

    timeradd(&now, &additional, abs_out);
    return 0;
}

static void time_insert_finite(libxl__gc *gc, libxl__ev_time *ev)
{
    libxl__ev_time *evsearch;
    LIBXL_TAILQ_INSERT_SORTED(&CTX->etimes, entry, ev, evsearch, /*empty*/,
                              timercmp(&ev->abs, &evsearch->abs, >));
    ev->infinite = 0;
}

static int time_register_finite(libxl__gc *gc, libxl__ev_time *ev,
                                struct timeval abs)
{
    int rc;

    rc = OSEVENT_HOOK(timeout_register, &ev->for_app_reg, abs, ev);
    if (rc) return rc;

    ev->infinite = 0;
    ev->abs = abs;
    time_insert_finite(gc, ev);

    return 0;
}

static void time_deregister(libxl__gc *gc, libxl__ev_time *ev)
{
    if (!ev->infinite) {
        OSEVENT_HOOK_VOID(timeout_deregister, &ev->for_app_reg);
        LIBXL_TAILQ_REMOVE(&CTX->etimes, ev, entry);
    }
}


int libxl__ev_time_register_abs(libxl__gc *gc, libxl__ev_time *ev,
                                libxl__ev_time_callback *func,
                                struct timeval abs)
{
    int rc;

    CTX_LOCK;

    rc = time_register_finite(gc, ev, abs);
    if (rc) goto out;

    ev->func = func;

    rc = 0;
 out:
    CTX_UNLOCK;
    return rc;
}


int libxl__ev_time_register_rel(libxl__gc *gc, libxl__ev_time *ev,
                                libxl__ev_time_callback *func,
                                int milliseconds /* as for poll(2) */)
{
    struct timeval abs;
    int rc;

    CTX_LOCK;

    if (milliseconds < 0) {
        ev->infinite = 1;
    } else {
        rc = time_rel_to_abs(gc, milliseconds, &abs);
        if (rc) goto out;

        rc = time_register_finite(gc, ev, abs);
        if (rc) goto out;
    }

    ev->func = func;
    rc = 0;

 out:
    CTX_UNLOCK;
    return rc;
}

int libxl__ev_time_modify_abs(libxl__gc *gc, libxl__ev_time *ev,
                              struct timeval abs)
{
    int rc;

    CTX_LOCK;

    assert(libxl__ev_time_isregistered(ev));

    if (ev->infinite) {
        rc = time_register_finite(gc, ev, abs);
        if (rc) goto out;
    } else {
        rc = OSEVENT_HOOK(timeout_modify, &ev->for_app_reg, abs);
        if (rc) goto out;

        LIBXL_TAILQ_REMOVE(&CTX->etimes, ev, entry);
        ev->abs = abs;
        time_insert_finite(gc, ev);
    }

    rc = 0;
 out:
    CTX_UNLOCK;
    return rc;
}

int libxl__ev_time_modify_rel(libxl__gc *gc, libxl__ev_time *ev,
                              int milliseconds)
{
    struct timeval abs;
    int rc;

    CTX_LOCK;

    assert(libxl__ev_time_isregistered(ev));

    if (milliseconds < 0) {
        time_deregister(gc, ev);
        ev->infinite = 1;
        rc = 0;
        goto out;
    }

    rc = time_rel_to_abs(gc, milliseconds, &abs);
    if (rc) goto out;

    rc = libxl__ev_time_modify_abs(gc, ev, abs);
    if (rc) goto out;

    rc = 0;
 out:
    CTX_UNLOCK;
    return rc;
}

void libxl__ev_time_deregister(libxl__gc *gc, libxl__ev_time *ev)
{
    CTX_LOCK;

    if (!libxl__ev_time_isregistered(ev))
        goto out;

    time_deregister(gc, ev);
    ev->func = 0;

 out:
    CTX_UNLOCK;
    return;
}


/*
 * xenstore watches
 */

libxl__ev_xswatch *libxl__watch_slot_contents(libxl__gc *gc, int slotnum)
{
    libxl__ev_watch_slot *slot = &CTX->watch_slots[slotnum];
    libxl__ev_watch_slot *slotcontents = LIBXL_SLIST_NEXT(slot, empty);

    if (slotcontents == NULL ||
        ((uintptr_t)slotcontents >= (uintptr_t)CTX->watch_slots &&
         (uintptr_t)slotcontents < (uintptr_t)(CTX->watch_slots +
                                               CTX->watch_nslots)))
        /* An empty slot has either a NULL pointer (end of the
         * free list), or a pointer to another entry in the array.
         * So we can do a bounds check to distinguish empty from
         * full slots.
         */
        /* We need to do the comparisons as uintptr_t because
         * comparing pointers which are not in the same object is
         * undefined behaviour; if the compiler managed to figure
         * out that watch_slots[0..watch_nslots-1] is all of the
         * whole array object it could prove that the above bounds
         * check was always true if it was legal, and remove it!
         *
         * uintptr_t because even on a machine with signed
         * pointers, objects do not cross zero; whereas on
         * machines with unsigned pointers, they may cross
         * 0x8bazillion.
         */
        return NULL;

        /* see comment near libxl__ev_watch_slot definition */
    return (void*)slotcontents;
}

static void libxl__set_watch_slot_contents(libxl__ev_watch_slot *slot,
                                           libxl__ev_xswatch *w)
{
    /* we look a bit behind the curtain of LIBXL_SLIST, to explicitly
     * assign to the pointer that's the next link.  See the comment
     * by the definition of libxl__ev_watch_slot */
    slot->empty.sle_next = (void*)w;
}

static void watchfd_callback(libxl__egc *egc, libxl__ev_fd *ev,
                             int fd, short events, short revents)
{
    EGC_GC;

    if (revents & (POLLERR|POLLHUP))
        LIBXL__EVENT_DISASTER(egc, "unexpected poll event on watch fd", 0, 0);

    for (;;) {
        char **event = xs_check_watch(CTX->xsh);
        if (!event) {
            if (errno == EAGAIN) break;
            if (errno == EINTR) continue;
            LIBXL__EVENT_DISASTER(egc, "cannot check/read watches", errno, 0);
            return;
        }

        const char *epath = event[0];
        const char *token = event[1];
        int slotnum;
        uint32_t counterval;
        int rc = sscanf(token, "%d/%"SCNx32, &slotnum, &counterval);
        if (rc != 2) {
            LIBXL__LOG(CTX, LIBXL__LOG_ERROR,
                       "watch epath=%s token=%s: failed to parse token",
                       epath, token);
            /* oh well */
            goto ignore;
        }
        if (slotnum < 0 || slotnum >= CTX->watch_nslots) {
            /* perhaps in the future we will make the watchslots array shrink */
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG, "watch epath=%s token=%s:"
                       " slotnum %d out of range [0,%d>",
                       epath, token, slotnum, CTX->watch_nslots);
            goto ignore;
        }

        libxl__ev_xswatch *w = libxl__watch_slot_contents(gc, slotnum);

        if (!w) {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG,
                       "watch epath=%s token=%s: empty slot",
                       epath, token);
            goto ignore;
        }

        if (w->counterval != counterval) {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG,
                       "watch epath=%s token=%s: counter != %"PRIx32,
                       epath, token, w->counterval);
            goto ignore;
        }

        /* Now it's possible, though unlikely, that this was an event
         * from a previous use of the same slot with the same counterval.
         *
         * In that case either:
         *  - the event path is a child of the watch path, in
         *    which case this watch would really have generated this
         *    event if it had been registered soon enough and we are
         *    OK to give this possibly-spurious event to the caller; or
         * - it is not, in which case we must suppress it as the
         *   caller should not see events for unrelated paths.
         *
         * See also docs/misc/xenstore.txt.
         */
        if (!xs_path_is_subpath(w->path, epath)) {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG,
                       "watch epath=%s token=%s: not child of wpath=%s",
                       epath, token, w->path);
            goto ignore;
        }

        /* At last, we have checked everything! */
        LIBXL__LOG(CTX, LIBXL__LOG_DEBUG,
                   "watch event: epath=%s token=%s wpath=%s w=%p",
                   epath, token, w->path, w);
        w->callback(egc, w, w->path, epath);

    ignore:
        free(event);
    }
}

static char *watch_token(libxl__gc *gc, int slotnum, uint32_t counterval)
{
    return libxl__sprintf(gc, "%d/%"PRIx32, slotnum, counterval);
}

int libxl__ev_xswatch_register(libxl__gc *gc, libxl__ev_xswatch *w,
                               libxl__ev_xswatch_callback *func,
                               const char *path /* copied */)
{
    libxl__ev_watch_slot *use = NULL;
    char *path_copy = NULL;
    int rc;

    CTX_LOCK;

    if (!libxl__ev_fd_isregistered(&CTX->watch_efd)) {
        rc = libxl__ev_fd_register(gc, &CTX->watch_efd, watchfd_callback,
                                   xs_fileno(CTX->xsh), POLLIN);
        if (rc) goto out_rc;
    }

    if (LIBXL_SLIST_EMPTY(&CTX->watch_freeslots)) {
        /* Free list is empty so there is not in fact a linked
         * free list in the array and we can safely realloc it */
        int newarraysize = (CTX->watch_nslots + 1) << 2;
        int i;
        libxl__ev_watch_slot *newarray =
            realloc(CTX->watch_slots, sizeof(*newarray) * newarraysize);
        if (!newarray) goto out_nomem;
        for (i = CTX->watch_nslots; i < newarraysize; i++)
            LIBXL_SLIST_INSERT_HEAD(&CTX->watch_freeslots,
                                    &newarray[i], empty);
        CTX->watch_slots = newarray;
        CTX->watch_nslots = newarraysize;
    }
    use = LIBXL_SLIST_FIRST(&CTX->watch_freeslots);
    assert(use);
    LIBXL_SLIST_REMOVE_HEAD(&CTX->watch_freeslots, empty);

    path_copy = strdup(path);
    if (!path_copy) goto out_nomem;

    int slotnum = use - CTX->watch_slots;
    w->counterval = CTX->watch_counter++;

    if (!xs_watch(CTX->xsh, path, watch_token(gc, slotnum, w->counterval))) {
        LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno,
                            "create watch for path %s", path);
        rc = ERROR_FAIL;
        goto out_rc;
    }

    w->slotnum = slotnum;
    w->path = path_copy;
    w->callback = func;
    libxl__set_watch_slot_contents(use, w);

    CTX_UNLOCK;
    return 0;

 out_nomem:
    rc = ERROR_NOMEM;
 out_rc:
    if (use)
        LIBXL_SLIST_INSERT_HEAD(&CTX->watch_freeslots, use, empty);
    if (path_copy)
        free(path_copy);
    CTX_UNLOCK;
    return rc;
}

void libxl__ev_xswatch_deregister(libxl__gc *gc, libxl__ev_xswatch *w)
{
    /* it is legal to deregister from within _callback */
    CTX_LOCK;

    if (w->slotnum >= 0) {
        char *token = watch_token(gc, w->slotnum, w->counterval);
        if (!xs_unwatch(CTX->xsh, w->path, token))
            /* Oh well, we will just get watch events forever more
             * and ignore them.  But we should complain to the log. */
            LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno,
                                "remove watch for path %s", w->path);

        libxl__ev_watch_slot *slot = &CTX->watch_slots[w->slotnum];
        LIBXL_SLIST_INSERT_HEAD(&CTX->watch_freeslots, slot, empty);
        w->slotnum = -1;
    }

    free(w->path);
    w->path = NULL;

    CTX_UNLOCK;
}

/*
 * waiting for device state
 */

static void devstate_watch_callback(libxl__egc *egc, libxl__ev_xswatch *watch,
                                const char *watch_path, const char *event_path)
{
    EGC_GC;
    libxl__ev_devstate *ds = CONTAINER_OF(watch, *ds, watch);
    int rc;

    char *sstate = libxl__xs_read(gc, XBT_NULL, watch_path);
    if (!sstate) {
        if (errno == ENOENT) {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG, "backend %s wanted state %d"
                       " but it was removed", watch_path, ds->wanted);
            rc = ERROR_INVAL;
        } else {
            LIBXL__LOG_ERRNO(CTX, LIBXL__LOG_ERROR, "backend %s wanted state"
                             " %d but read failed", watch_path, ds->wanted);
            rc = ERROR_FAIL;
        }
    } else {
        int got = atoi(sstate);
        if (got == ds->wanted) {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG, "backend %s wanted state %d ok",
                       watch_path, ds->wanted);
            rc = 0;
        } else {
            LIBXL__LOG(CTX, LIBXL__LOG_DEBUG, "backend %s wanted state %d"
                       " still waiting state %d", watch_path, ds->wanted, got);
            return;
        }
    }
    libxl__ev_devstate_cancel(gc, ds);
    ds->callback(egc, ds, rc);
}

static void devstate_timeout(libxl__egc *egc, libxl__ev_time *ev,
                             const struct timeval *requested_abs)
{
    EGC_GC;
    libxl__ev_devstate *ds = CONTAINER_OF(ev, *ds, timeout);
    LIBXL__LOG(CTX, LIBXL__LOG_DEBUG, "backend %s wanted state %d "
               " timed out", ds->watch.path, ds->wanted);
    libxl__ev_devstate_cancel(gc, ds);
    ds->callback(egc, ds, ERROR_TIMEDOUT);
}

int libxl__ev_devstate_wait(libxl__gc *gc, libxl__ev_devstate *ds,
                            libxl__ev_devstate_callback cb,
                            const char *state_path, int state, int milliseconds)
{
    int rc;

    libxl__ev_time_init(&ds->timeout);
    libxl__ev_xswatch_init(&ds->watch);
    ds->wanted = state;
    ds->callback = cb;

    rc = libxl__ev_time_register_rel(gc, &ds->timeout, devstate_timeout,
                                     milliseconds);
    if (rc) goto out;

    rc = libxl__ev_xswatch_register(gc, &ds->watch, devstate_watch_callback,
                                    state_path);
    if (rc) goto out;

    return 0;

 out:
    libxl__ev_devstate_cancel(gc, ds);
    return rc;
}

/*
 * domain death/destruction
 */

/*
 * We use a xenstore watch on the domain's path, rather than using an
 * @releaseDomain watch and asking the hypervisor.  This is simpler
 * because turning @releaseDomain into domain-specific information is
 * complicated.
 *
 * It is also sufficient for our callers, which are generally trying
 * to do cleanup of their own execution state on domain death, for the
 * following reason: if the domain is destroyed then either (a) the
 * entries in xenstore have already been deleted, in which case the
 * test here works or (b) they have not in which case something has
 * gone very badly wrong and we are going to leak those xenstore
 * entries, in which case trying to avoid leaking other stuff is
 * futile.
 */

static void domaindeathcheck_callback(libxl__egc *egc, libxl__ev_xswatch *w,
                            const char *watch_path, const char *event_path)
{
    libxl__domaindeathcheck *dc = CONTAINER_OF(w, *dc, watch);
    EGC_GC;
    const char *p = libxl__xs_read(gc, XBT_NULL, watch_path);
    if (p) return;

    if (errno!=ENOENT) {
        LIBXL__EVENT_DISASTER(egc,"failed to read xenstore"
                              " for domain detach check", errno, 0);
        return;
    }

    LOG(ERROR,"%s: domain %"PRIu32" removed (%s no longer in xenstore)",
        dc->what, dc->domid, watch_path);
    dc->callback(egc, dc);
}

int libxl__domaindeathcheck_start(libxl__gc *gc,
                                  libxl__domaindeathcheck *dc)
{
    const char *path = GCSPRINTF("/local/domain/%"PRIu32, dc->domid);
    return libxl__ev_xswatch_register(gc, &dc->watch,
                                      domaindeathcheck_callback, path);
}

/*
 * osevent poll
 */

static int beforepoll_internal(libxl__gc *gc, libxl__poller *poller,
                               int *nfds_io, struct pollfd *fds,
                               int *timeout_upd, struct timeval now)
{
    libxl__ev_fd *efd;
    int rc;

    /*
     * We need to look at the fds we want twice: firstly, to count
     * them so we can make the rindex array big enough, and secondly
     * to actually fill the arrays in.
     *
     * To ensure correctness and avoid repeating the logic for
     * deciding which fds are relevant, we define a macro
     *    REQUIRE_FDS( BODY )
     * which calls
     *    do{
     *        int req_fd;
     *        int req_events;
     *        BODY;
     *    }while(0)
     * for each fd with a nonzero events.  This is invoked twice.
     *
     * The definition of REQUIRE_FDS is simplified with the helper
     * macro
     *    void REQUIRE_FD(int req_fd, int req_events, BODY);
     */

#define REQUIRE_FDS(BODY) do{                                          \
                                                                       \
        LIBXL_LIST_FOREACH(efd, &CTX->efds, entry)                     \
            REQUIRE_FD(efd->fd, efd->events, BODY);                    \
                                                                       \
        REQUIRE_FD(poller->wakeup_pipe[0], POLLIN, BODY);              \
                                                                       \
        int selfpipe = libxl__fork_selfpipe_active(CTX);               \
        if (selfpipe >= 0)                                             \
            REQUIRE_FD(selfpipe, POLLIN, BODY);                        \
                                                                       \
    }while(0)

#define REQUIRE_FD(req_fd_, req_events_, BODY) do{      \
        int req_events = (req_events_);                 \
        int req_fd = (req_fd_);                         \
        if (req_events) {                               \
            BODY;                                       \
        }                                               \
    }while(0)


    /*
     * In order to be able to efficiently find the libxl__ev_fd for a
     * struct poll during _afterpoll, we maintain a shadow data
     * structure in CTX->fd_rindices: each fd corresponds to a slot in
     * fd_rindices, and each element in the rindices is three indices
     * into the fd array (for POLLIN, POLLPRI and POLLOUT).
     */

    if (*nfds_io) {
        /*
         * As an optimisation, we don't touch fd_rindex
         * if *nfds_io is zero on entry, since in that case the
         * caller just wanted to know how big an array to give us.
         *
         * If !*nfds_io, the unconditional parts below are guaranteed
         * not to mess with fd_rindex.
         */

        int maxfd = 0;

        REQUIRE_FDS({
            if (req_fd >= maxfd)
                maxfd = req_fd + 1;
        });

        /* make sure our array is as big as *nfds_io */
        if (poller->fd_rindices_allocd < maxfd) {
            assert(ARRAY_SIZE_OK(poller->fd_rindices, maxfd));
            poller->fd_rindices =
                libxl__realloc(0, poller->fd_rindices,
                               maxfd * sizeof(*poller->fd_rindices));
            memset(poller->fd_rindices + poller->fd_rindices_allocd,
                   0,
                   (maxfd - poller->fd_rindices_allocd)
                     * sizeof(*poller->fd_rindices));
            poller->fd_rindices_allocd = maxfd;
        }
    }

    int used = 0;

    REQUIRE_FDS({
        if (used < *nfds_io) {
            fds[used].fd = req_fd;
            fds[used].events = req_events;
            fds[used].revents = 0;
            assert(req_fd < poller->fd_rindices_allocd);
            if (req_events & POLLIN)  poller->fd_rindices[req_fd][0] = used;
            if (req_events & POLLPRI) poller->fd_rindices[req_fd][1] = used;
            if (req_events & POLLOUT) poller->fd_rindices[req_fd][2] = used;
        }
        used++;
    });

    rc = used <= *nfds_io ? 0 : ERROR_BUFFERFULL;

    *nfds_io = used;

    libxl__ev_time *etime = LIBXL_TAILQ_FIRST(&CTX->etimes);
    if (etime) {
        int our_timeout;
        struct timeval rel;
        static struct timeval zero;

        timersub(&etime->abs, &now, &rel);

        if (timercmp(&rel, &zero, <)) {
            our_timeout = 0;
        } else if (rel.tv_sec >= 2000000) {
            our_timeout = 2000000000;
        } else {
            our_timeout = rel.tv_sec * 1000 + (rel.tv_usec + 999) / 1000;
        }
        if (*timeout_upd < 0 || our_timeout < *timeout_upd)
            *timeout_upd = our_timeout;
    }

    return rc;
}

int libxl_osevent_beforepoll(libxl_ctx *ctx, int *nfds_io,
                             struct pollfd *fds, int *timeout_upd,
                             struct timeval now)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    int rc = beforepoll_internal(gc, &ctx->poller_app,
                                 nfds_io, fds, timeout_upd, now);
    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}

static int afterpoll_check_fd(libxl__poller *poller,
                              const struct pollfd *fds, int nfds,
                              int fd, int events)
    /* returns mask of events which were requested and occurred */
{
    if (fd >= poller->fd_rindices_allocd)
        /* added after we went into poll, have to try again */
        return 0;

    int i, revents = 0;
    for (i=0; i<3; i++) {
        int slot = poller->fd_rindices[fd][i];

        if (slot >= nfds)
            /* stale slot entry; again, added afterwards */
            continue;

        if (fds[slot].fd != fd)
            /* again, stale slot entry */
            continue;

        assert(!(fds[slot].revents & POLLNVAL));
        revents |= fds[slot].revents;
    }

    /* we mask in case requested events have changed */
    revents &= (events | POLLERR | POLLHUP);

    return revents;
}

static void afterpoll_internal(libxl__egc *egc, libxl__poller *poller,
                               int nfds, const struct pollfd *fds,
                               struct timeval now)
{
    /* May make callbacks into the application for child processes.
     * ctx must be locked exactly once */
    EGC_GC;
    libxl__ev_fd *efd;

    LIBXL_LIST_FOREACH(efd, &CTX->efds, entry) {
        if (!efd->events)
            continue;

        int revents = afterpoll_check_fd(poller,fds,nfds, efd->fd,efd->events);
        if (revents)
            efd->func(egc, efd, efd->fd, efd->events, revents);
    }

    if (afterpoll_check_fd(poller,fds,nfds, poller->wakeup_pipe[0],POLLIN)) {
        int e = libxl__self_pipe_eatall(poller->wakeup_pipe[0]);
        if (e) LIBXL__EVENT_DISASTER(egc, "read wakeup", e, 0);
    }

    int selfpipe = libxl__fork_selfpipe_active(CTX);
    if (selfpipe >= 0 &&
        afterpoll_check_fd(poller,fds,nfds, selfpipe, POLLIN)) {
        int e = libxl__self_pipe_eatall(selfpipe);
        if (e) LIBXL__EVENT_DISASTER(egc, "read sigchld pipe", e, 0);
        libxl__fork_selfpipe_woken(egc);
    }

    for (;;) {
        libxl__ev_time *etime = LIBXL_TAILQ_FIRST(&CTX->etimes);
        if (!etime)
            break;

        assert(!etime->infinite);

        if (timercmp(&etime->abs, &now, >))
            break;

        time_deregister(gc, etime);

        etime->func(egc, etime, &etime->abs);
    }
}

void libxl_osevent_afterpoll(libxl_ctx *ctx, int nfds, const struct pollfd *fds,
                             struct timeval now)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    afterpoll_internal(egc, &ctx->poller_app, nfds, fds, now);
    CTX_UNLOCK;
    EGC_FREE;
}

/*
 * osevent hook and callback machinery
 */

void libxl_osevent_register_hooks(libxl_ctx *ctx,
                                  const libxl_osevent_hooks *hooks,
                                  void *user)
{
    GC_INIT(ctx);
    CTX_LOCK;
    ctx->osevent_hooks = hooks;
    ctx->osevent_user = user;
    CTX_UNLOCK;
    GC_FREE;
}


void libxl_osevent_occurred_fd(libxl_ctx *ctx, void *for_libxl,
                               int fd, short events, short revents)
{
    libxl__ev_fd *ev = for_libxl;

    EGC_INIT(ctx);
    CTX_LOCK;
    assert(!CTX->osevent_in_hook);

    assert(fd == ev->fd);
    revents &= ev->events;
    if (revents)
        ev->func(egc, ev, fd, ev->events, revents);

    CTX_UNLOCK;
    EGC_FREE;
}

void libxl_osevent_occurred_timeout(libxl_ctx *ctx, void *for_libxl)
{
    libxl__ev_time *ev = for_libxl;

    EGC_INIT(ctx);
    CTX_LOCK;
    assert(!CTX->osevent_in_hook);

    assert(!ev->infinite);
    LIBXL_TAILQ_REMOVE(&CTX->etimes, ev, entry);
    ev->func(egc, ev, &ev->abs);

    CTX_UNLOCK;
    EGC_FREE;
}

void libxl__event_disaster(libxl__egc *egc, const char *msg, int errnoval,
                           libxl_event_type type /* may be 0 */,
                           const char *file, int line, const char *func)
{
    EGC_GC;

    libxl__log(CTX, XTL_CRITICAL, errnoval, file, line, func,
               "DISASTER in event loop: %s%s%s%s",
               msg,
               type ? " (relates to event type " : "",
               type ? libxl_event_type_to_string(type) : "",
               type ? ")" : "");

    if (CTX->event_hooks && CTX->event_hooks->disaster) {
        CTX->event_hooks->disaster(CTX->event_hooks_user, type, msg, errnoval);
        return;
    }

    const char verybad[] =
        "DISASTER in event loop not handled by libxl application";
    LIBXL__LOG(CTX, XTL_CRITICAL, verybad);
    fprintf(stderr, "libxl: fatal error, exiting program: %s\n", verybad);
    exit(-1);
}

static void egc_run_callbacks(libxl__egc *egc)
{
    /*
     * The callbacks must happen with the ctx unlocked.  See the
     * comment near #define EGC_GC in libxl_internal.h and those in
     * the definitions of libxl__egc, libxl__ao and libxl__aop.
     */
    EGC_GC;
    libxl_event *ev, *ev_tmp;
    libxl__aop_occurred *aop, *aop_tmp;

    LIBXL_TAILQ_FOREACH_SAFE(ev, &egc->occurred_for_callback, link, ev_tmp) {
        LIBXL_TAILQ_REMOVE(&egc->occurred_for_callback, ev, link);
        CTX->event_hooks->event_occurs(CTX->event_hooks_user, ev);
    }

    LIBXL_TAILQ_FOREACH_SAFE(aop, &egc->aops_for_callback, entry, aop_tmp) {
        LIBXL_TAILQ_REMOVE(&egc->aops_for_callback, aop, entry);
        aop->how->callback(CTX, aop->ev, aop->how->for_callback);

        CTX_LOCK;
        aop->ao->progress_reports_outstanding--;
        libxl__ao_complete_check_progress_reports(egc, aop->ao);
        CTX_UNLOCK;
    }

    libxl__ao *ao, *ao_tmp;
    LIBXL_TAILQ_FOREACH_SAFE(ao, &egc->aos_for_callback,
                             entry_for_callback, ao_tmp) {
        LIBXL_TAILQ_REMOVE(&egc->aos_for_callback, ao, entry_for_callback);
        ao->how.callback(CTX, ao->rc, ao->how.u.for_callback);
        CTX_LOCK;
        ao->notified = 1;
        if (!ao->in_initiator)
            libxl__ao__destroy(CTX, ao);
        CTX_UNLOCK;
    }
}

void libxl__egc_cleanup(libxl__egc *egc)
{
    EGC_GC;
    libxl__free_all(gc);

    egc_run_callbacks(egc);
}

/*
 * Event retrieval etc.
 */

void libxl_event_register_callbacks(libxl_ctx *ctx,
                  const libxl_event_hooks *hooks, void *user)
{
    ctx->event_hooks = hooks;
    ctx->event_hooks_user = user;
}

void libxl__event_occurred(libxl__egc *egc, libxl_event *event)
{
    EGC_GC;

    if (CTX->event_hooks &&
        (CTX->event_hooks->event_occurs_mask & (1UL << event->type))) {
        /* libxl__egc_cleanup will call the callback, just before exit
         * from libxl.  This helps avoid reentrancy bugs: parts of
         * libxl that call libxl__event_occurred do not have to worry
         * that libxl might be reentered at that point. */
        LIBXL_TAILQ_INSERT_TAIL(&egc->occurred_for_callback, event, link);
        return;
    } else {
        libxl__poller *poller;
        LIBXL_TAILQ_INSERT_TAIL(&CTX->occurred, event, link);
        LIBXL_LIST_FOREACH(poller, &CTX->pollers_event, entry)
            libxl__poller_wakeup(egc, poller);
    }
}

void libxl_event_free(libxl_ctx *ctx, libxl_event *event)
{
    /* Exceptionally, this function may be called from libxl, with ctx==0 */
    libxl_event_dispose(event);
    free(event);
}

libxl_event *libxl__event_new(libxl__egc *egc,
                              libxl_event_type type, uint32_t domid)
{
    libxl_event *ev;

    ev = libxl__zalloc(0,sizeof(*ev));
    ev->type = type;
    ev->domid = domid;

    return ev;
}

static int event_check_internal(libxl__egc *egc, libxl_event **event_r,
                                unsigned long typemask,
                                libxl_event_predicate *pred, void *pred_user)
{
    EGC_GC;
    libxl_event *ev;
    int rc;

    LIBXL_TAILQ_FOREACH(ev, &CTX->occurred, link) {
        if (!(typemask & ((uint64_t)1 << ev->type)))
            continue;

        if (pred && !pred(ev, pred_user))
            continue;

        /* got one! */
        LIBXL_TAILQ_REMOVE(&CTX->occurred, ev, link);
        *event_r = ev;
        rc = 0;
        goto out;
    }
    rc = ERROR_NOT_READY;

 out:
    return rc;
}

int libxl_event_check(libxl_ctx *ctx, libxl_event **event_r,
                      uint64_t typemask,
                      libxl_event_predicate *pred, void *pred_user)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    int rc = event_check_internal(egc, event_r, typemask, pred, pred_user);
    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}

/*
 * Manipulation of pollers
 */

int libxl__poller_init(libxl_ctx *ctx, libxl__poller *p)
{
    int r, rc;
    p->fd_polls = 0;
    p->fd_rindices = 0;

    r = pipe(p->wakeup_pipe);
    if (r) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "cannot create poller pipe");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_fd_set_nonblock(ctx, p->wakeup_pipe[0], 1);
    if (rc) goto out;

    rc = libxl_fd_set_nonblock(ctx, p->wakeup_pipe[1], 1);
    if (rc) goto out;

    return 0;

 out:
    libxl__poller_dispose(p);
    return rc;
}

void libxl__poller_dispose(libxl__poller *p)
{
    if (p->wakeup_pipe[1] > 0) close(p->wakeup_pipe[1]);
    if (p->wakeup_pipe[0] > 0) close(p->wakeup_pipe[0]);
    free(p->fd_polls);
    free(p->fd_rindices);
}

libxl__poller *libxl__poller_get(libxl_ctx *ctx)
{
    /* must be called with ctx locked */
    int rc;

    libxl__poller *p = LIBXL_LIST_FIRST(&ctx->pollers_idle);
    if (p) {
        LIBXL_LIST_REMOVE(p, entry);
        return p;
    }

    p = malloc(sizeof(*p));
    if (!p) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "cannot allocate poller");
        return 0;
    }
    memset(p, 0, sizeof(*p));

    rc = libxl__poller_init(ctx, p);
    if (rc) return NULL;

    return p;
}

void libxl__poller_put(libxl_ctx *ctx, libxl__poller *p)
{
    LIBXL_LIST_INSERT_HEAD(&ctx->pollers_idle, p, entry);
}

void libxl__poller_wakeup(libxl__egc *egc, libxl__poller *p)
{
    int e = libxl__self_pipe_wakeup(p->wakeup_pipe[1]);
    if (e) LIBXL__EVENT_DISASTER(egc, "cannot poke watch pipe", e, 0);
}

int libxl__self_pipe_wakeup(int fd)
{
    static const char buf[1] = "";

    for (;;) {
        int r = write(fd, buf, 1);
        if (r==1) return 0;
        assert(r==-1);
        if (errno == EINTR) continue;
        if (errno == EWOULDBLOCK) return 0;
        assert(errno);
        return errno;
    }
}

int libxl__self_pipe_eatall(int fd)
{
    char buf[256];
    for (;;) {
        int r = read(fd, buf, sizeof(buf));
        if (r == sizeof(buf)) continue;
        if (r >= 0) return 0;
        assert(r == -1);
        if (errno == EINTR) continue;
        if (errno == EWOULDBLOCK) return 0;
        assert(errno);
        return errno;
    }
}

/*
 * Main event loop iteration
 */

static int eventloop_iteration(libxl__egc *egc, libxl__poller *poller) {
    /* The CTX must be locked EXACTLY ONCE so that this function
     * can unlock it when it polls.
     */
    EGC_GC;
    int rc;
    struct timeval now;
    
    rc = libxl__gettimeofday(gc, &now);
    if (rc) goto out;

    int timeout;

    for (;;) {
        int nfds = poller->fd_polls_allocd;
        timeout = -1;
        rc = beforepoll_internal(gc, poller, &nfds, poller->fd_polls,
                                 &timeout, now);
        if (!rc) break;
        if (rc != ERROR_BUFFERFULL) goto out;

        struct pollfd *newarray =
            (nfds > INT_MAX / sizeof(struct pollfd) / 2) ? 0 :
            realloc(poller->fd_polls, sizeof(*newarray) * nfds);

        if (!newarray) { rc = ERROR_NOMEM; goto out; }

        poller->fd_polls = newarray;
        poller->fd_polls_allocd = nfds;
    }

    CTX_UNLOCK;
    rc = poll(poller->fd_polls, poller->fd_polls_allocd, timeout);
    CTX_LOCK;

    if (rc < 0) {
        if (errno == EINTR)
            return 0; /* will go round again if caller requires */

        LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno, "poll failed");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__gettimeofday(gc, &now);
    if (rc) goto out;

    afterpoll_internal(egc, poller,
                       poller->fd_polls_allocd, poller->fd_polls, now);

    rc = 0;
 out:
    return rc;
}

int libxl_event_wait(libxl_ctx *ctx, libxl_event **event_r,
                     uint64_t typemask,
                     libxl_event_predicate *pred, void *pred_user)
{
    int rc;
    libxl__poller *poller = NULL;

    EGC_INIT(ctx);
    CTX_LOCK;

    poller = libxl__poller_get(ctx);
    if (!poller) { rc = ERROR_FAIL; goto out; }

    for (;;) {
        rc = event_check_internal(egc, event_r, typemask, pred, pred_user);
        if (rc != ERROR_NOT_READY) goto out;

        rc = eventloop_iteration(egc, poller);
        if (rc) goto out;

        /* we unlock and cleanup the egc each time we go through this loop,
         * so that (a) we don't accumulate garbage and (b) any events
         * which are to be dispatched by callback are actually delivered
         * in a timely fashion.
         */
        CTX_UNLOCK;
        libxl__egc_cleanup(egc);
        CTX_LOCK;
    }

 out:
    libxl__poller_put(ctx, poller);

    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}



/*
 * The two possible state flow of an ao:
 *
 * Completion before initiator return:
 *
 *     Initiator thread                       Possible other threads
 *
 *   * ao_create allocates memory and
 *     initialises the struct
 *
 *   * the initiator function does its
 *     work, setting up various internal
 *     asynchronous operations -----------> * asynchronous operations
 *                                            start to take place and
 *                                            might cause ao completion
 *                                                |
 *   * initiator calls ao_inprogress              |
 *     - if synchronous, run event loop           |
 *       until the ao completes                   |
 *                              - ao completes on some thread
 *                              - completing thread releases the lock
 *                     <--------------'
 *     - ao_inprogress takes the lock
 *     - destroy the ao
 *
 *
 * Completion after initiator return (asynch. only):
 *
 *
 *     Initiator thread                       Possible other threads
 *
 *   * ao_create allocates memory and
 *     initialises the struct
 *
 *   * the initiator function does its
 *     work, setting up various internal
 *     asynchronous operations -----------> * asynchronous operations
 *                                            start to take place and
 *                                            might cause ao completion
 *                                                |
 *   * initiator calls ao_inprogress              |
 *     - observes event not yet done,             |
 *     - returns to caller                        |
 *                                                |
 *                              - ao completes on some thread
 *                              - generate the event or call the callback
 *                              - destroy the ao
 */

void libxl__ao__destroy(libxl_ctx *ctx, libxl__ao *ao)
{
    if (!ao) return;
    if (ao->poller) libxl__poller_put(ctx, ao->poller);
    ao->magic = LIBXL__AO_MAGIC_DESTROYED;
    libxl__free_all(&ao->gc);
    free(ao);
}

void libxl__ao_abort(libxl__ao *ao)
{
    AO_GC;
    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(ao->in_initiator);
    assert(!ao->complete);
    assert(!ao->progress_reports_outstanding);
    libxl__ao__destroy(CTX, ao);
}

libxl__gc *libxl__ao_inprogress_gc(libxl__ao *ao)
{
    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(!ao->complete);
    return &ao->gc;
}

void libxl__ao_complete(libxl__egc *egc, libxl__ao *ao, int rc)
{
    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(!ao->complete);
    ao->complete = 1;
    ao->rc = rc;

    libxl__ao_complete_check_progress_reports(egc, ao);
}

void libxl__ao_complete_check_progress_reports(libxl__egc *egc, libxl__ao *ao)
{
    /*
     * We don't consider an ao complete if it has any outstanding
     * callbacks.  These callbacks might be outstanding on other
     * threads, queued up in the other threads' egc's.  Those threads
     * will, after making the callback, take out the lock again,
     * decrement progress_reports_outstanding, and call us again.
     */

    assert(ao->progress_reports_outstanding >= 0);

    if (!ao->complete || ao->progress_reports_outstanding)
        return;

    if (ao->poller) {
        assert(ao->in_initiator);
        if (!ao->constructing)
            /* don't bother with this if we're not in the event loop */
            libxl__poller_wakeup(egc, ao->poller);
    } else if (ao->how.callback) {
        LIBXL_TAILQ_INSERT_TAIL(&egc->aos_for_callback, ao, entry_for_callback);
    } else {
        libxl_event *ev;
        ev = NEW_EVENT(egc, OPERATION_COMPLETE, ao->domid);
        if (ev) {
            ev->for_user = ao->how.u.for_event;
            ev->u.operation_complete.rc = ao->rc;
            libxl__event_occurred(egc, ev);
        }
        ao->notified = 1;
    }
    if (!ao->in_initiator && ao->notified)
        libxl__ao__destroy(libxl__gc_owner(&egc->gc), ao);
}

libxl__ao *libxl__ao_create(libxl_ctx *ctx, uint32_t domid,
                            const libxl_asyncop_how *how)
{
    libxl__ao *ao;

    ao = calloc(1, sizeof(*ao));
    if (!ao) goto out;

    ao->magic = LIBXL__AO_MAGIC;
    ao->constructing = 1;
    ao->in_initiator = 1;
    ao->poller = 0;
    ao->domid = domid;
    LIBXL_INIT_GC(ao->gc, ctx);

    if (how) {
        ao->how = *how;
    } else {
        ao->poller = libxl__poller_get(ctx);
        if (!ao->poller) goto out;
    }
    return ao;

 out:
    if (ao) libxl__ao__destroy(ctx, ao);
    return NULL;
}


int libxl__ao_inprogress(libxl__ao *ao)
{
    AO_GC;
    int rc;

    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(ao->constructing);
    assert(ao->in_initiator);
    ao->constructing = 0;

    if (ao->poller) {
        /* Caller wants it done synchronously. */
        /* We use a fresh gc, so that we can free things
         * each time round the loop. */
        libxl__egc egc;
        LIBXL_INIT_EGC(egc,CTX);

        for (;;) {
            assert(ao->magic == LIBXL__AO_MAGIC);

            if (ao->complete) {
                rc = ao->rc;
                ao->notified = 1;
                break;
            }

            rc = eventloop_iteration(&egc,ao->poller);
            if (rc) {
                /* Oh dear, this is quite unfortunate. */
                LIBXL__LOG(CTX, LIBXL__LOG_ERROR, "Error waiting for"
                           " event during long-running operation (rc=%d)", rc);
                sleep(1);
                /* It's either this or return ERROR_I_DONT_KNOW_WHETHER
                 * _THE_THING_YOU_ASKED_FOR_WILL_BE_DONE_LATER_WHEN
                 * _YOU_DIDNT_EXPECT_IT, since we don't have any kind of
                 * cancellation ability. */
            }

            CTX_UNLOCK;
            libxl__egc_cleanup(&egc);
            CTX_LOCK;
        }
    } else {
        rc = 0;
    }

    ao->in_initiator = 0;

    if (ao->notified) {
        assert(ao->complete);
        libxl__ao__destroy(CTX,ao);
    }

    return rc;
}


/* progress reporting */

/* The application indicates a desire to ignore events by passing NULL
 * for how.  But we want to copy *how.  So we have this dummy function
 * whose address is stored in callback if the app passed how==NULL. */
static void dummy_asyncprogress_callback_ignore
  (libxl_ctx *ctx, libxl_event *ev, void *for_callback) { }

void libxl__ao_progress_gethow(libxl_asyncprogress_how *in_state,
                               const libxl_asyncprogress_how *from_app) {
    if (from_app)
        *in_state = *from_app;
    else
        in_state->callback = dummy_asyncprogress_callback_ignore;
}

void libxl__ao_progress_report(libxl__egc *egc, libxl__ao *ao,
        const libxl_asyncprogress_how *how, libxl_event *ev)
{
    ev->for_user = how->for_event;
    if (how->callback == dummy_asyncprogress_callback_ignore) {
        /* ignore */
    } else if (how->callback) {
        libxl__aop_occurred *aop = libxl__zalloc(&egc->gc, sizeof(*aop));
        ao->progress_reports_outstanding++;
        aop->ao = ao;
        aop->ev = ev;
        aop->how = how;
        LIBXL_TAILQ_INSERT_TAIL(&egc->aops_for_callback, aop, entry);
    } else {
        libxl__event_occurred(egc, ev);
    }
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
