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


//#define DEBUG 1

#ifdef DEBUG
# define LIBXL__DBG_LOG(ctx, args, ...) \
    LIBXL__LOG((ctx), XTL_DEBUG, args, __VA_ARGS__)
#else
# define LIBXL__DBG_LOG(ctx, args, ...) ((void)0)
#endif
#define DBG(args, ...) LIBXL__DBG_LOG(CTX, args, __VA_ARGS__)


/*
 * The counter osevent_in_hook is used to ensure that the application
 * honours the reentrancy restriction documented in libxl_event.h.
 *
 * The application's registration hooks should be called ONLY via
 * these macros, with the ctx locked.  Likewise all the "occurred"
 * entrypoints from the application should assert(!in_hook);
 *
 * During the hook call - including while the arguments are being
 * evaluated - ev->nexus is guaranteed to be valid and refer to the
 * nexus which is being used for this event registration.  The
 * arguments should specify ev->nexus for the for_libxl argument and
 * ev->nexus->for_app_reg (or a pointer to it) for for_app_reg.
 */
#define OSEVENT_HOOK_INTERN(retval, failedp, evkind, hookop, nexusop, ...) do { \
    if (CTX->osevent_hooks) {                                           \
        CTX->osevent_in_hook++;                                         \
        libxl__osevent_hook_nexi *nexi = &CTX->hook_##evkind##_nexi_idle; \
        osevent_hook_pre_##nexusop(gc, ev, nexi, &ev->nexus);            \
        retval CTX->osevent_hooks->evkind##_##hookop                    \
            (CTX->osevent_user, __VA_ARGS__);                           \
        if ((failedp))                                                  \
            osevent_hook_failed_##nexusop(gc, ev, nexi, &ev->nexus);     \
        CTX->osevent_in_hook--;                                         \
    }                                                                   \
} while (0)

#define OSEVENT_HOOK(evkind, hookop, nexusop, ...) ({                   \
    int osevent_hook_rc = 0;                                    \
    OSEVENT_HOOK_INTERN(osevent_hook_rc =, !!osevent_hook_rc,   \
                        evkind, hookop, nexusop, __VA_ARGS__);          \
    osevent_hook_rc;                                            \
})

#define OSEVENT_HOOK_VOID(evkind, hookop, nexusop, ...)                         \
    OSEVENT_HOOK_INTERN(/* void */, 0, evkind, hookop, nexusop, __VA_ARGS__)

/*
 * The application's calls to libxl_osevent_occurred_... may be
 * indefinitely delayed with respect to the rest of the program (since
 * they are not necessarily called with any lock held).  So the
 * for_libxl value we receive may be (almost) arbitrarily old.  All we
 * know is that it came from this ctx.
 *
 * Therefore we may not free the object referred to by any for_libxl
 * value until we free the whole libxl_ctx.  And if we reuse it we
 * must be able to tell when an old use turns up, and discard the
 * stale event.
 *
 * Thus we cannot use the ev directly as the for_libxl value - we need
 * a layer of indirection.
 *
 * We do this by keeping a pool of libxl__osevent_hook_nexus structs,
 * and use pointers to them as for_libxl values.  In fact, there are
 * two pools: one for fds and one for timeouts.  This ensures that we
 * don't risk a type error when we upcast nexus->ev.  In each nexus
 * the ev is either null or points to a valid libxl__ev_time or
 * libxl__ev_fd, as applicable.
 *
 * We /do/ allow ourselves to reassociate an old nexus with a new ev
 * as otherwise we would have to leak nexi.  (This reassociation
 * might, of course, be an old ev being reused for a new purpose so
 * simply comparing the ev pointer is not sufficient.)  Thus the
 * libxl_osevent_occurred functions need to check that the condition
 * allegedly signalled by this event actually exists.
 *
 * The nexi and the lists are all protected by the ctx lock.
 */

struct libxl__osevent_hook_nexus {
    void *ev;
    void *for_app_reg;
    LIBXL_SLIST_ENTRY(libxl__osevent_hook_nexus) next;
};

static void *osevent_ev_from_hook_nexus(libxl_ctx *ctx,
           libxl__osevent_hook_nexus *nexus /* pass  void *for_libxl */)
{
    return nexus->ev;
}

static void osevent_release_nexus(libxl__gc *gc,
                                  libxl__osevent_hook_nexi *nexi_idle,
                                  libxl__osevent_hook_nexus *nexus)
{
    nexus->ev = 0;
    LIBXL_SLIST_INSERT_HEAD(nexi_idle, nexus, next);
}

/*----- OSEVENT* hook functions for nexusop "alloc" -----*/
static void osevent_hook_pre_alloc(libxl__gc *gc, void *ev,
                                   libxl__osevent_hook_nexi *nexi_idle,
                                   libxl__osevent_hook_nexus **nexus_r)
{
    libxl__osevent_hook_nexus *nexus = LIBXL_SLIST_FIRST(nexi_idle);
    if (nexus) {
        LIBXL_SLIST_REMOVE_HEAD(nexi_idle, next);
    } else {
        nexus = libxl__zalloc(NOGC, sizeof(*nexus));
    }
    nexus->ev = ev;
    *nexus_r = nexus;
}
static void osevent_hook_failed_alloc(libxl__gc *gc, void *ev,
                                      libxl__osevent_hook_nexi *nexi_idle,
                                      libxl__osevent_hook_nexus **nexus)
{
    osevent_release_nexus(gc, nexi_idle, *nexus);
}

/*----- OSEVENT* hook functions for nexusop "release" -----*/
static void osevent_hook_pre_release(libxl__gc *gc, void *ev,
                                     libxl__osevent_hook_nexi *nexi_idle,
                                     libxl__osevent_hook_nexus **nexus)
{
    osevent_release_nexus(gc, nexi_idle, *nexus);
}
static void osevent_hook_failed_release(libxl__gc *gc, void *ev,
                                        libxl__osevent_hook_nexi *nexi_idle,
                                        libxl__osevent_hook_nexus **nexus)
{
    abort();
}

/*----- OSEVENT* hook functions for nexusop "noop" -----*/
static void osevent_hook_pre_noop(libxl__gc *gc, void *ev,
                                  libxl__osevent_hook_nexi *nexi_idle,
                                  libxl__osevent_hook_nexus **nexus) { }
static void osevent_hook_failed_noop(libxl__gc *gc, void *ev,
                                     libxl__osevent_hook_nexi *nexi_idle,
                                     libxl__osevent_hook_nexus **nexus) { }


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

    DBG("ev_fd=%p register fd=%d events=%x", ev, fd, events);

    rc = OSEVENT_HOOK(fd,register, alloc, fd, &ev->nexus->for_app_reg,
                      events, ev->nexus);
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

    DBG("ev_fd=%p modify fd=%d events=%x", ev, ev->fd, events);

    rc = OSEVENT_HOOK(fd,modify, noop, ev->fd, &ev->nexus->for_app_reg, events);
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

    if (!libxl__ev_fd_isregistered(ev)) {
        DBG("ev_fd=%p deregister unregistered",ev);
        goto out;
    }

    DBG("ev_fd=%p deregister fd=%d", ev, ev->fd);

    OSEVENT_HOOK_VOID(fd,deregister, release, ev->fd, ev->nexus->for_app_reg);
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

static int time_register_finite(libxl__gc *gc, libxl__ev_time *ev,
                                struct timeval absolute)
{
    int rc;
    libxl__ev_time *evsearch;

    rc = OSEVENT_HOOK(timeout,register, alloc, &ev->nexus->for_app_reg,
                      absolute, ev->nexus);
    if (rc) return rc;

    ev->infinite = 0;
    ev->abs = absolute;
    LIBXL_TAILQ_INSERT_SORTED(&CTX->etimes, entry, ev, evsearch, /*empty*/,
                              timercmp(&ev->abs, &evsearch->abs, >));

    return 0;
}

static void time_deregister(libxl__gc *gc, libxl__ev_time *ev)
{
    if (!ev->infinite) {
        struct timeval right_away = { 0, 0 };
        if (ev->nexus) /* only set if app provided hooks */
            ev->nexus->ev = 0;
        OSEVENT_HOOK_VOID(timeout,modify,
                          noop /* release nexus in _occurred_ */,
                          &ev->nexus->for_app_reg, right_away);
        LIBXL_TAILQ_REMOVE(&CTX->etimes, ev, entry);
    }
}

static void time_done_debug(libxl__gc *gc, const char *func,
                            libxl__ev_time *ev, int rc)
{
#ifdef DEBUG
    libxl__log(CTX, XTL_DEBUG, -1,__FILE__,0,func,
               "ev_time=%p done rc=%d .func=%p infinite=%d abs=%lu.%06lu",
               ev, rc, ev->func, ev->infinite,
               (unsigned long)ev->abs.tv_sec, (unsigned long)ev->abs.tv_usec);
#endif
}

int libxl__ev_time_register_abs(libxl__gc *gc, libxl__ev_time *ev,
                                libxl__ev_time_callback *func,
                                struct timeval absolute)
{
    int rc;

    CTX_LOCK;

    DBG("ev_time=%p register abs=%lu.%06lu",
        ev, (unsigned long)absolute.tv_sec, (unsigned long)absolute.tv_usec);

    rc = time_register_finite(gc, ev, absolute);
    if (rc) goto out;

    ev->func = func;

    rc = 0;
 out:
    time_done_debug(gc,__func__,ev,rc);
    CTX_UNLOCK;
    return rc;
}


int libxl__ev_time_register_rel(libxl__gc *gc, libxl__ev_time *ev,
                                libxl__ev_time_callback *func,
                                int milliseconds /* as for poll(2) */)
{
    struct timeval absolute;
    int rc;

    CTX_LOCK;

    DBG("ev_time=%p register ms=%d", ev, milliseconds);

    if (milliseconds < 0) {
        ev->infinite = 1;
    } else {
        rc = time_rel_to_abs(gc, milliseconds, &absolute);
        if (rc) goto out;

        rc = time_register_finite(gc, ev, absolute);
        if (rc) goto out;
    }

    ev->func = func;
    rc = 0;

 out:
    time_done_debug(gc,__func__,ev,rc);
    CTX_UNLOCK;
    return rc;
}

void libxl__ev_time_deregister(libxl__gc *gc, libxl__ev_time *ev)
{
    CTX_LOCK;

    DBG("ev_time=%p deregister", ev);

    if (!libxl__ev_time_isregistered(ev))
        goto out;

    time_deregister(gc, ev);
    ev->func = 0;

 out:
    time_done_debug(gc,__func__,ev,0);
    CTX_UNLOCK;
    return;
}

static void time_occurs(libxl__egc *egc, libxl__ev_time *etime)
{
    DBG("ev_time=%p occurs abs=%lu.%06lu",
        etime, (unsigned long)etime->abs.tv_sec,
        (unsigned long)etime->abs.tv_usec);

    libxl__ev_time_callback *func = etime->func;
    etime->func = 0;
    func(egc, etime, &etime->abs);
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
            LOG(DEBUG, "watch w=%p epath=%s token=%s: counter != %"PRIx32,
                w, epath, token, w->counterval);
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
            LOG(DEBUG, "watch w=%p wpath=%s token=%s: unexpected epath=%s",
                w, w->path, token, epath);
            goto ignore;
        }

        /* At last, we have checked everything! */
        LOG(DEBUG, "watch w=%p wpath=%s token=%s: event epath=%s",
            w, w->path, token, epath);
        w->callback(egc, w, w->path, epath);

    ignore:
        free(event);
    }
}

static char *watch_token(libxl__gc *gc, int slotnum, uint32_t counterval)
{
    return libxl__sprintf(gc, "%d/%"PRIx32, slotnum, counterval);
}

static void watches_check_fd_deregister(libxl__gc *gc)
{
    assert(CTX->nwatches>=0);
    if (!CTX->nwatches)
        libxl__ev_fd_deregister(gc, &CTX->watch_efd);
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
            libxl__realloc(NOGC,
                           CTX->watch_slots, sizeof(*newarray) * newarraysize);
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

    const char *token = watch_token(gc, slotnum, w->counterval);
    LOG(DEBUG, "watch w=%p wpath=%s token=%s: register slotnum=%d",
        w, path, token, slotnum);

    if (!xs_watch(CTX->xsh, path, token)) {
        LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno,
                            "create watch for path %s", path);
        rc = ERROR_FAIL;
        goto out_rc;
    }

    w->slotnum = slotnum;
    w->path = path_copy;
    w->callback = func;
    CTX->nwatches++;
    libxl__set_watch_slot_contents(use, w);

    CTX_UNLOCK;
    return 0;

 out_nomem:
    rc = ERROR_NOMEM;
 out_rc:
    if (use)
        LIBXL_SLIST_INSERT_HEAD(&CTX->watch_freeslots, use, empty);
    free(path_copy);
    watches_check_fd_deregister(gc);
    CTX_UNLOCK;
    return rc;
}

void libxl__ev_xswatch_deregister(libxl__gc *gc, libxl__ev_xswatch *w)
{
    /* it is legal to deregister from within _callback */
    CTX_LOCK;

    if (w->slotnum >= 0) {
        const char *token = watch_token(gc, w->slotnum, w->counterval);

        LOG(DEBUG, "watch w=%p wpath=%s token=%s: deregister slotnum=%d",
            w, w->path, token, w->slotnum);

        if (!xs_unwatch(CTX->xsh, w->path, token))
            /* Oh well, we will just get watch events forever more
             * and ignore them.  But we should complain to the log. */
            LIBXL__LOG_ERRNOVAL(CTX, LIBXL__LOG_ERROR, errno,
                                "remove watch for path %s", w->path);

        libxl__ev_watch_slot *slot = &CTX->watch_slots[w->slotnum];
        LIBXL_SLIST_INSERT_HEAD(&CTX->watch_freeslots, slot, empty);
        w->slotnum = -1;
        CTX->nwatches--;
        watches_check_fd_deregister(gc);
    } else {
        LOG(DEBUG, "watch w=%p: deregister unregistered", w);
    }

    free(w->path);
    w->path = NULL;

    CTX_UNLOCK;
}

/*
 * evtchn
 */

static int evtchn_revents_check(libxl__egc *egc, int revents)
{
    EGC_GC;

    if (revents & ~POLLIN) {
        LOG(ERROR, "unexpected poll event on event channel fd: %x", revents);
        LIBXL__EVENT_DISASTER(egc,
                   "unexpected poll event on event channel fd", 0, 0);
        libxl__ev_fd_deregister(gc, &CTX->evtchn_efd);
        return ERROR_FAIL;
    }

    assert(revents & POLLIN);

    return 0;
}

static void evtchn_fd_callback(libxl__egc *egc, libxl__ev_fd *ev,
                               int fd, short events, short revents)
{
    EGC_GC;
    libxl__ev_evtchn *evev;
    int r, rc;
    evtchn_port_or_error_t port;
    struct pollfd recheck;

    rc = evtchn_revents_check(egc, revents);
    if (rc) return;

    for (;;) {
        /* Check the fd again.  The incoming revent may no longer be
         * true, because the libxl ctx lock has not necessarily been
         * held continuously since someone noticed the fd.  Normally
         * this wouldn't be a problem but evtchn devices don't always
         * honour O_NONBLOCK (see xenctrl.h). */

        recheck.fd = fd;
        recheck.events = POLLIN;
        recheck.revents = 0;
        r = poll(&recheck, 1, 0);
        DBG("ev_evtchn recheck r=%d revents=%#x", r, recheck.revents);
        if (r < 0) {
            LIBXL__EVENT_DISASTER(egc,
     "unexpected failure polling event channel fd for recheck",
                                  errno, 0);
            return;
        }
        if (r == 0)
            break;
        rc = evtchn_revents_check(egc, recheck.revents);
        if (rc) return;

        /* OK, that's that workaround done.  We can actually check for
         * work for us to do: */

        port = xc_evtchn_pending(CTX->xce);
        if (port < 0) {
            if (errno == EAGAIN)
                break;
            LIBXL__EVENT_DISASTER(egc,
     "unexpected failure fetching occurring event port number from evtchn",
                                  errno, 0);
            return;
        }

        LIBXL_LIST_FOREACH(evev, &CTX->evtchns_waiting, entry)
            if (port == evev->port)
                goto found;
        /* not found */
        DBG("ev_evtchn port=%d no-one cared", port);
        continue;

    found:
        DBG("ev_evtchn=%p port=%d signaled", evev, port);
        evev->waiting = 0;
        LIBXL_LIST_REMOVE(evev, entry);
        evev->callback(egc, evev);
    }
}

int libxl__ctx_evtchn_init(libxl__gc *gc) {
    xc_evtchn *xce;
    int rc, fd;

    if (CTX->xce)
        return 0;

    xce = xc_evtchn_open(CTX->lg, 0);
    if (!xce) {
        LOGE(ERROR,"cannot open libxc evtchn handle");
        rc = ERROR_FAIL;
        goto out;
    }

    fd = xc_evtchn_fd(xce);
    assert(fd >= 0);

    rc = libxl_fd_set_nonblock(CTX, fd, 1);
    if (rc) goto out;

    CTX->xce = xce;
    return 0;

 out:
    xc_evtchn_close(xce);
    return rc;
}

static void evtchn_check_fd_deregister(libxl__gc *gc)
{
    if (CTX->xce && LIBXL_LIST_EMPTY(&CTX->evtchns_waiting))
        libxl__ev_fd_deregister(gc, &CTX->evtchn_efd);
}

int libxl__ev_evtchn_wait(libxl__gc *gc, libxl__ev_evtchn *evev)
{
    int r, rc;

    DBG("ev_evtchn=%p port=%d wait (was waiting=%d)",
        evev, evev->port, evev->waiting);

    rc = libxl__ctx_evtchn_init(gc);
    if (rc) goto out;

    if (!libxl__ev_fd_isregistered(&CTX->evtchn_efd)) {
        rc = libxl__ev_fd_register(gc, &CTX->evtchn_efd, evtchn_fd_callback,
                                   xc_evtchn_fd(CTX->xce), POLLIN);
        if (rc) goto out;
    }

    if (evev->waiting)
        return 0;

    r = xc_evtchn_unmask(CTX->xce, evev->port);
    if (r) {
        LOGE(ERROR,"cannot unmask event channel %d",evev->port);
        rc = ERROR_FAIL;
        goto out;
    }

    evev->waiting = 1;
    LIBXL_LIST_INSERT_HEAD(&CTX->evtchns_waiting, evev, entry);
    return 0;

 out:
    evtchn_check_fd_deregister(gc);
    return rc;
}

void libxl__ev_evtchn_cancel(libxl__gc *gc, libxl__ev_evtchn *evev)
{
    DBG("ev_evtchn=%p port=%d cancel (was waiting=%d)",
        evev, evev->port, evev->waiting);

    if (!evev->waiting)
        return;

    evev->waiting = 0;
    LIBXL_LIST_REMOVE(evev, entry);
    evtchn_check_fd_deregister(gc);
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
                libxl__realloc(NOGC, poller->fd_rindices,
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
    /* Returns mask of events which were requested and occurred.  Will
     * return nonzero only once for each (poller,fd,events)
     * combination, until the next beforepoll.  If events from
     * different combinations overlap, between one such combination
     * and all distinct combinations will produce nonzero returns. */
{
    if (fd >= poller->fd_rindices_allocd)
        /* added after we went into poll, have to try again */
        return 0;

    events |= POLLERR | POLLHUP;

    int i, revents = 0;
    for (i=0; i<3; i++) {
        int *slotp = &poller->fd_rindices[fd][i];
        int slot = *slotp;

        if (slot >= nfds)
            /* stale slot entry (again, added afterwards), */
            /* or slot for which we have already returned nonzero */
            continue;

        if (fds[slot].fd != fd)
            /* again, stale slot entry */
            continue;

        assert(!(fds[slot].revents & POLLNVAL));

        /* we mask in case requested events have changed */
        int slot_revents = fds[slot].revents & events;
        if (!slot_revents)
            /* this slot is for a different set of events */
            continue;

        revents |= slot_revents;
        *slotp = INT_MAX; /* so that next time we'll see slot >= nfds */
    }

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

    /*
     * Warning! Reentrancy hazards!
     *
     * Many parts of this function eventually call arbitrary callback
     * functions which may modify the event handling data structures.
     *
     * Of the data structures used here:
     *
     *   egc, poller, now
     *                are allocated by our caller and relate to the
     *                current thread and its call stack down into the
     *                event machinery; it is not freed until we return.
     *                So it is safe.
     *
     *   fds          is either what application passed into
     *                libxl_osevent_afterpoll (which, although this
     *                isn't explicitly stated, clearly must remain
     *                valid until libxl_osevent_afterpoll returns) or
     *                it's poller->fd_polls which is modified only by
     *                our (non-recursive) caller eventloop_iteration.
     *
     *   CTX          comes from our caller, and applications are
     *                forbidden from destroying it while we are running.
     *                So the ctx pointer itself is safe to use; now
     *                for its contents:
     *
     *   CTX->etimes  is used in a simple reentrancy-safe manner.
     *
     *   CTX->efds    is more complicated; see below.
     */

    for (;;) {
        /* We restart our scan of fd events whenever we call a
         * callback function.  This is necessary because such
         * a callback might make arbitrary changes to CTX->efds.
         * We invalidate the fd_rindices[] entries which were used
         * so that we don't call the same function again. */
        int revents;

        LIBXL_LIST_FOREACH(efd, &CTX->efds, entry) {

            if (!efd->events)
                continue;

            revents = afterpoll_check_fd(poller,fds,nfds,
                                         efd->fd,efd->events);
            if (revents)
                goto found_fd_event;
        }
        /* no ordinary fd events, then */
        break;

    found_fd_event:
        DBG("ev_fd=%p occurs fd=%d events=%x revents=%x",
            efd, efd->fd, efd->events, revents);

        efd->func(egc, efd, efd->fd, efd->events, revents);
    }

    if (afterpoll_check_fd(poller,fds,nfds, poller->wakeup_pipe[0],POLLIN)) {
        int e = libxl__self_pipe_eatall(poller->wakeup_pipe[0]);
        if (e) LIBXL__EVENT_DISASTER(egc, "read wakeup", e, 0);
    }

    for (;;) {
        libxl__ev_time *etime = LIBXL_TAILQ_FIRST(&CTX->etimes);
        if (!etime)
            break;

        assert(!etime->infinite);

        if (timercmp(&etime->abs, &now, >))
            break;

        time_deregister(gc, etime);

        time_occurs(egc, etime);
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
    assert(LIBXL_LIST_EMPTY(&ctx->efds));
    assert(LIBXL_TAILQ_EMPTY(&ctx->etimes));
    ctx->osevent_hooks = hooks;
    ctx->osevent_user = user;
    CTX_UNLOCK;
    GC_FREE;
}


void libxl_osevent_occurred_fd(libxl_ctx *ctx, void *for_libxl,
                               int fd, short events_ign, short revents_ign)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    assert(!CTX->osevent_in_hook);

    libxl__ev_fd *ev = osevent_ev_from_hook_nexus(ctx, for_libxl);
    if (!ev) goto out;
    if (ev->fd != fd) goto out;

    struct pollfd check;
    for (;;) {
        check.fd = fd;
        check.events = ev->events;
        int r = poll(&check, 1, 0);
        if (!r)
            goto out;
        if (r==1)
            break;
        assert(r<0);
        if (errno != EINTR) {
            LIBXL__EVENT_DISASTER(egc, "failed poll to check for fd", errno, 0);
            goto out;
        }
    }

    if (check.revents)
        ev->func(egc, ev, fd, ev->events, check.revents);

 out:
    CTX_UNLOCK;
    EGC_FREE;
}

void libxl_osevent_occurred_timeout(libxl_ctx *ctx, void *for_libxl)
{
    EGC_INIT(ctx);
    CTX_LOCK;
    assert(!CTX->osevent_in_hook);

    libxl__osevent_hook_nexus *nexus = for_libxl;
    libxl__ev_time *ev = osevent_ev_from_hook_nexus(ctx, nexus);

    osevent_release_nexus(gc, &CTX->hook_timeout_nexi_idle, nexus);

    if (!ev) goto out;
    assert(!ev->infinite);

    LIBXL_TAILQ_REMOVE(&CTX->etimes, ev, entry);

    time_occurs(egc, ev);

 out:
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
        LOG(DEBUG,"event %p callback type=%s",
            ev, libxl_event_type_to_string(ev->type));
        CTX->event_hooks->event_occurs(CTX->event_hooks_user, ev);
    }

    LIBXL_TAILQ_FOREACH_SAFE(aop, &egc->aops_for_callback, entry, aop_tmp) {
        LIBXL_TAILQ_REMOVE(&egc->aops_for_callback, aop, entry);
        LOG(DEBUG,"ao %p: progress report: callback aop=%p", aop->ao, aop);
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
        LOG(DEBUG,"ao %p: completion callback", ao);
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
    egc_run_callbacks(egc);

    libxl__free_all(gc);
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
                              libxl_event_type type, uint32_t domid,
                              libxl_ev_user for_user)
{
    EGC_GC;
    libxl_event *ev;

    ev = libxl__zalloc(NOGC,sizeof(*ev));

    libxl_event_init(ev);
    libxl_event_init_type(ev, type);

    ev->domid = domid;
    ev->for_user = for_user;

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
 * Utilities for pipes (specifically, useful for self-pipes)
 */

void libxl__pipe_close(int fds[2])
{
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    fds[0] = fds[1] = -1;
}

int libxl__pipe_nonblock(libxl_ctx *ctx, int fds[2])
{
    int r, rc;

    r = libxl_pipe(ctx, fds);
    if (r) {
        fds[0] = fds[1] = -1;
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_fd_set_nonblock(ctx, fds[0], 1);
    if (rc) goto out;

    rc = libxl_fd_set_nonblock(ctx, fds[1], 1);
    if (rc) goto out;

    return 0;

 out:
    libxl__pipe_close(fds);
    return rc;
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
 * Manipulation of pollers
 */

int libxl__poller_init(libxl__gc *gc, libxl__poller *p)
{
    int rc;
    p->fd_polls = 0;
    p->fd_rindices = 0;

    rc = libxl__pipe_nonblock(CTX, p->wakeup_pipe);
    if (rc) goto out;

    return 0;

 out:
    libxl__poller_dispose(p);
    return rc;
}

void libxl__poller_dispose(libxl__poller *p)
{
    libxl__pipe_close(p->wakeup_pipe);
    free(p->fd_polls);
    free(p->fd_rindices);
}

libxl__poller *libxl__poller_get(libxl__gc *gc)
{
    /* must be called with ctx locked */
    int rc;

    libxl__poller *p = LIBXL_LIST_FIRST(&CTX->pollers_idle);
    if (p) {
        LIBXL_LIST_REMOVE(p, entry);
        return p;
    }

    p = libxl__zalloc(NOGC, sizeof(*p));

    rc = libxl__poller_init(gc, p);
    if (rc) {
        free(p);
        return NULL;
    }

    return p;
}

void libxl__poller_put(libxl_ctx *ctx, libxl__poller *p)
{
    if (!p) return;
    LIBXL_LIST_INSERT_HEAD(&ctx->pollers_idle, p, entry);
}

void libxl__poller_wakeup(libxl__egc *egc, libxl__poller *p)
{
    int e = libxl__self_pipe_wakeup(p->wakeup_pipe[1]);
    if (e) LIBXL__EVENT_DISASTER(egc, "cannot poke watch pipe", e, 0);
}

/*
 * Main event loop iteration
 */

static int eventloop_iteration(libxl__egc *egc, libxl__poller *poller) {
    /* The CTX must be locked EXACTLY ONCE so that this function
     * can unlock it when it polls.
     */
    EGC_GC;
    int rc, nfds;
    struct timeval now;
    
    rc = libxl__gettimeofday(gc, &now);
    if (rc) goto out;

    int timeout;

    for (;;) {
        nfds = poller->fd_polls_allocd;
        timeout = -1;
        rc = beforepoll_internal(gc, poller, &nfds, poller->fd_polls,
                                 &timeout, now);
        if (!rc) break;
        if (rc != ERROR_BUFFERFULL) goto out;

        struct pollfd *newarray =
            (nfds > INT_MAX / sizeof(struct pollfd) / 2) ? 0 :
            libxl__realloc(NOGC, poller->fd_polls, sizeof(*newarray) * nfds);

        if (!newarray) { rc = ERROR_NOMEM; goto out; }

        poller->fd_polls = newarray;
        poller->fd_polls_allocd = nfds;
    }

    CTX_UNLOCK;
    rc = poll(poller->fd_polls, nfds, timeout);
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

    afterpoll_internal(egc, poller, nfds, poller->fd_polls, now);

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

    poller = libxl__poller_get(gc);
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
    AO_GC;
    if (!ao) return;
    LOG(DEBUG,"ao %p: destroy",ao);
    libxl__poller_put(ctx, ao->poller);
    ao->magic = LIBXL__AO_MAGIC_DESTROYED;
    libxl__free_all(&ao->gc);
    free(ao);
}

void libxl__ao_abort(libxl__ao *ao)
{
    AO_GC;
    LOG(DEBUG,"ao %p: abort",ao);
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
    AO_GC;
    LOG(DEBUG,"ao %p: complete, rc=%d",ao,rc);
    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(!ao->complete);
    assert(!ao->nested);
    ao->complete = 1;
    ao->rc = rc;

    libxl__ao_complete_check_progress_reports(egc, ao);
}

static bool ao_work_outstanding(libxl__ao *ao)
{
    /*
     * We don't consider an ao complete if it has any outstanding
     * callbacks.  These callbacks might be outstanding on other
     * threads, queued up in the other threads' egc's.  Those threads
     * will, after making the callback, take out the lock again,
     * decrement progress_reports_outstanding, and call
     * libxl__ao_complete_check_progress_reports.
     */
    return !ao->complete || ao->progress_reports_outstanding;
}

void libxl__ao_complete_check_progress_reports(libxl__egc *egc, libxl__ao *ao)
{
    libxl_ctx *ctx = libxl__gc_owner(&egc->gc);
    assert(ao->progress_reports_outstanding >= 0);

    if (ao_work_outstanding(ao))
        return;

    if (ao->poller) {
        assert(ao->in_initiator);
        if (!ao->constructing)
            /* don't bother with this if we're not in the event loop */
            libxl__poller_wakeup(egc, ao->poller);
    } else if (ao->how.callback) {
        LIBXL__LOG(ctx, XTL_DEBUG, "ao %p: complete for callback",ao);
        LIBXL_TAILQ_INSERT_TAIL(&egc->aos_for_callback, ao, entry_for_callback);
    } else {
        libxl_event *ev;
        ev = NEW_EVENT(egc, OPERATION_COMPLETE, ao->domid, ao->how.u.for_event);
        if (ev) {
            ev->u.operation_complete.rc = ao->rc;
            libxl__event_occurred(egc, ev);
        }
        ao->notified = 1;
    }
    if (!ao->in_initiator && ao->notified)
        libxl__ao__destroy(ctx, ao);
}

libxl__ao *libxl__ao_create(libxl_ctx *ctx, uint32_t domid,
                            const libxl_asyncop_how *how,
                            const char *file, int line, const char *func)
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
        ao->poller = libxl__poller_get(&ao->gc);
        if (!ao->poller) goto out;
    }
    libxl__log(ctx,XTL_DEBUG,-1,file,line,func,
               "ao %p: create: how=%p callback=%p poller=%p",
               ao, how, ao->how.callback, ao->poller);

    return ao;

 out:
    if (ao) libxl__ao__destroy(ctx, ao);
    return NULL;
}


int libxl__ao_inprogress(libxl__ao *ao,
                         const char *file, int line, const char *func)
{
    AO_GC;
    int rc;

    assert(ao->magic == LIBXL__AO_MAGIC);
    assert(ao->constructing);
    assert(ao->in_initiator);
    ao->constructing = 0;

    libxl__log(CTX,XTL_DEBUG,-1,file,line,func,
               "ao %p: inprogress: poller=%p, flags=%s%s%s%s",
               ao, ao->poller,
               ao->constructing ? "o" : "",
               ao->in_initiator ? "i" : "",
               ao->complete ? "c" : "",
               ao->notified ? "n" : "");

    if (ao->poller) {
        /* Caller wants it done synchronously. */
        /* We use a fresh gc, so that we can free things
         * each time round the loop. */
        libxl__egc egc;
        LIBXL_INIT_EGC(egc,CTX);

        for (;;) {
            assert(ao->magic == LIBXL__AO_MAGIC);

            if (!ao_work_outstanding(ao)) {
                rc = ao->rc;
                ao->notified = 1;
                break;
            }

            DBG("ao %p: not ready, waiting",ao);

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
    AO_GC;
    assert(!ao->nested);
    if (how->callback == dummy_asyncprogress_callback_ignore) {
        LOG(DEBUG,"ao %p: progress report: ignored",ao);
        libxl_event_free(CTX,ev);
        /* ignore */
    } else if (how->callback) {
        libxl__aop_occurred *aop = libxl__zalloc(&egc->gc, sizeof(*aop));
        ao->progress_reports_outstanding++;
        aop->ao = ao;
        aop->ev = ev;
        aop->how = how;
        LIBXL_TAILQ_INSERT_TAIL(&egc->aops_for_callback, aop, entry);
        LOG(DEBUG,"ao %p: progress report: callback queued aop=%p",ao,aop);
    } else {
        LOG(DEBUG,"ao %p: progress report: event queued ev=%p type=%s",
            ao, ev, libxl_event_type_to_string(ev->type));
        libxl__event_occurred(egc, ev);
    }
}


/* nested ao */

_hidden libxl__ao *libxl__nested_ao_create(libxl__ao *parent)
{
    /* We only use the parent to get the ctx.  However, we require the
     * caller to provide us with an ao, not just a ctx, to prove that
     * they are already in an asynchronous operation.  That will avoid
     * people using this to (for example) make an ao in a non-ao_how
     * function somewhere in the middle of libxl. */
    libxl__ao *child = NULL;
    libxl_ctx *ctx = libxl__gc_owner(&parent->gc);

    assert(parent->magic == LIBXL__AO_MAGIC);

    child = libxl__zalloc(&ctx->nogc_gc, sizeof(*child));
    child->magic = LIBXL__AO_MAGIC;
    child->nested = 1;
    LIBXL_INIT_GC(child->gc, ctx);
    libxl__gc *gc = &child->gc;

    LOG(DEBUG,"ao %p: nested ao, parent %p", child, parent);
    return child;
}

_hidden void libxl__nested_ao_free(libxl__ao *child)
{
    assert(child->magic == LIBXL__AO_MAGIC);
    assert(child->nested);
    libxl_ctx *ctx = libxl__gc_owner(&child->gc);
    libxl__ao__destroy(ctx, child);
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
