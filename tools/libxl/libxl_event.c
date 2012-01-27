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
#define OSEVENT_HOOK_INTERN(defval, hookname, ...)                      \
    (CTX->osevent_hooks                                                 \
     ? (CTX->osevent_in_hook++,                                         \
        CTX->osevent_hooks->hookname(CTX->osevent_user, __VA_ARGS__),   \
        CTX->osevent_in_hook--)                                         \
     : defval)

#define OSEVENT_HOOK(hookname,...)                      \
    OSEVENT_HOOK_INTERN(0, hookname, __VA_ARGS__)

#define OSEVENT_HOOK_VOID(hookname,...)                 \
    OSEVENT_HOOK_INTERN((void)0, hookname, __VA_ARGS__)

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
 * osevent poll
 */

static int beforepoll_internal(libxl__gc *gc, int *nfds_io,
                               struct pollfd *fds, int *timeout_upd,
                               struct timeval now)
{
    libxl__ev_fd *efd;
    int rc;

    /*
     * In order to be able to efficiently find the libxl__ev_fd
     * for a struct poll during _afterpoll, we maintain a shadow
     * data structure in CTX->fd_beforepolled: each slot in
     * the fds array corresponds to a slot in fd_beforepolled.
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
        LIBXL_LIST_FOREACH(efd, &CTX->efds, entry) {
            if (!efd->events)
                continue;
            if (efd->fd >= maxfd)
                maxfd = efd->fd + 1;
        }
        /* make sure our array is as big as *nfds_io */
        if (CTX->fd_rindex_allocd < maxfd) {
            assert(maxfd < INT_MAX / sizeof(int) / 2);
            int *newarray = realloc(CTX->fd_rindex, sizeof(int) * maxfd);
            if (!newarray) { rc = ERROR_NOMEM; goto out; }
            memset(newarray + CTX->fd_rindex_allocd, 0,
                   sizeof(int) * (maxfd - CTX->fd_rindex_allocd));
            CTX->fd_rindex = newarray;
            CTX->fd_rindex_allocd = maxfd;
        }
    }

    int used = 0;
    LIBXL_LIST_FOREACH(efd, &CTX->efds, entry) {
        if (!efd->events)
            continue;
        if (used < *nfds_io) {
            fds[used].fd = efd->fd;
            fds[used].events = efd->events;
            fds[used].revents = 0;
            assert(efd->fd < CTX->fd_rindex_allocd);
            CTX->fd_rindex[efd->fd] = used;
        }
        used++;
    }
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

 out:
    return rc;
}

int libxl_osevent_beforepoll(libxl_ctx *ctx, int *nfds_io,
                             struct pollfd *fds, int *timeout_upd,
                             struct timeval now)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    int rc = beforepoll_internal(gc, nfds_io, fds, timeout_upd, now);
    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}

static int afterpoll_check_fd(libxl_ctx *ctx,
                              const struct pollfd *fds, int nfds,
                              int fd, int events)
    /* returns mask of events which were requested and occurred */
{
    if (fd >= ctx->fd_rindex_allocd)
        /* added after we went into poll, have to try again */
        return 0;

    int slot = ctx->fd_rindex[fd];

    if (slot >= nfds)
        /* stale slot entry; again, added afterwards */
        return 0;

    if (fds[slot].fd != fd)
        /* again, stale slot entry */
        return 0;

    int revents = fds[slot].revents & events;
    /* we mask in case requested events have changed */

    return revents;
}

static void afterpoll_internal(libxl__egc *egc,
                               int nfds, const struct pollfd *fds,
                               struct timeval now)
{
    EGC_GC;
    libxl__ev_fd *efd;

    LIBXL_LIST_FOREACH(efd, &CTX->efds, entry) {
        if (!efd->events)
            continue;

        int revents = afterpoll_check_fd(CTX,fds,nfds, efd->fd,efd->events);
        if (revents)
            efd->func(egc, efd, efd->fd, efd->events, revents);
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
    afterpoll_internal(egc, nfds, fds, now);
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
    EGC_GC;
    libxl_event *ev, *ev_tmp;
    LIBXL_TAILQ_FOREACH_SAFE(ev, &egc->occurred_for_callback, link, ev_tmp) {
        LIBXL_TAILQ_REMOVE(&egc->occurred_for_callback, ev, link);
        CTX->event_hooks->event_occurs(CTX->event_hooks_user, ev);
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
        LIBXL_TAILQ_INSERT_TAIL(&CTX->occurred, event, link);
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

    ev = malloc(sizeof(*ev));
    if (!ev) {
        LIBXL__EVENT_DISASTER(egc, "allocate new event", errno, type);
        return NULL;
    }

    memset(ev, 0, sizeof(*ev));
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

static int eventloop_iteration(libxl__egc *egc) {
    EGC_GC;
    int rc;
    struct timeval now;
    
    CTX_LOCK;

    rc = libxl__gettimeofday(gc, &now);
    if (rc) goto out;

    int timeout;

    for (;;) {
        int nfds = CTX->fd_polls_allocd;
        timeout = -1;
        rc = beforepoll_internal(gc, &nfds, CTX->fd_polls, &timeout, now);
        if (!rc) break;
        if (rc != ERROR_BUFFERFULL) goto out;

        struct pollfd *newarray =
            (nfds > INT_MAX / sizeof(struct pollfd) / 2) ? 0 :
            realloc(CTX->fd_polls, sizeof(*newarray) * nfds);

        if (!newarray) { rc = ERROR_NOMEM; goto out; }

        CTX->fd_polls = newarray;
        CTX->fd_polls_allocd = nfds;
    }

    rc = poll(CTX->fd_polls, CTX->fd_polls_allocd, timeout);
    if (rc < 0) {
        if (errno == EINTR)
            return 0; /* will go round again if caller requires */

        LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno, "poll failed");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__gettimeofday(gc, &now);
    if (rc) goto out;

    afterpoll_internal(egc, CTX->fd_polls_allocd, CTX->fd_polls, now);

    CTX_UNLOCK;

    rc = 0;
 out:
    return rc;
}

int libxl_event_wait(libxl_ctx *ctx, libxl_event **event_r,
                     uint64_t typemask,
                     libxl_event_predicate *pred, void *pred_user)
{
    int rc;

    EGC_INIT(ctx);
    CTX_LOCK;

    for (;;) {
        rc = event_check_internal(egc, event_r, typemask, pred, pred_user);
        if (rc != ERROR_NOT_READY) goto out;

        rc = eventloop_iteration(egc);
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
    CTX_UNLOCK;
    EGC_FREE;
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
