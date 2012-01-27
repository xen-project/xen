/*
 * Copyright (C) 2011      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
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

#ifndef LIBXL_EVENT_H
#define LIBXL_EVENT_H

#include <libxl.h>


/*======================================================================*/

/*
 * OS event handling - passing low-level OS events to libxl
 *
 * Event-driven programs must use these facilities to allow libxl
 * to become aware of readability/writeability of file descriptors
 * and the occurrence of timeouts.
 *
 * There are two approaches available.  The first is appropriate for
 * simple programs handling reasonably small numbers of domains:
 *
 *   for (;;) {
 *      libxl_osevent_beforepoll(...)
 *      poll();
 *      libxl_osevent_afterpoll(...);
 *      for (;;) {
 *        r=libxl_event_check(...);
 *        if (r==LIBXL_NOT_READY) break;
 *        if (r) handle failure;
 *        do something with the event;
 *      }
 *   }
 *
 * The second approach uses libxl_osevent_register_hooks and is
 * suitable for programs which are already using a callback-based
 * event library.
 *
 * An application may freely mix the two styles of interaction.
 *
 * (Callers inside libxl may not call libxl_osevent_... functions.)
 */

struct pollfd;

/* The caller should provide beforepoll with some space for libxl's
 * fds, and tell libxl how much space is available by setting *nfds_io.
 * fds points to the start of this space (and fds may be a pointer into
 * a larger array, for example, if the application has some fds of
 * its own that it is interested in).
 *
 * On return *nfds_io will in any case have been updated by libxl
 * according to how many fds libxl wants to poll on.
 *
 * If the space was sufficient, libxl fills in fds[0..<new
 * *nfds_io>] suitably for poll(2), updates *timeout_upd if needed,
 * and returns ok.
 *
 * If space was insufficient, fds[0..<old *nfds_io>] is undefined on
 * return; *nfds_io on return will be greater than the value on
 * entry; *timeout_upd may or may not have been updated; and
 * libxl_osevent_beforepoll returns ERROR_BUFERFULL.  In this case
 * the application needs to make more space (enough space for
 * *nfds_io struct pollfd) and then call beforepoll again, before
 * entering poll(2).  Typically this will involve calling realloc.
 *
 * The application may call beforepoll with fds==NULL and
 * *nfds_io==0 in order to find out how much space is needed.
 *
 * *timeout_upd is as for poll(2): it's in milliseconds, and
 * negative values mean no timeout (infinity).
 * libxl_osevent_beforepoll will only reduce the timeout, naturally.
 */
int libxl_osevent_beforepoll(libxl_ctx *ctx, int *nfds_io,
                             struct pollfd *fds, int *timeout_upd,
                             struct timeval now);

/* nfds and fds[0..nfds] must be from the most recent call to
 * _beforepoll, as modified by poll.  (It is therefore not possible
 * to have multiple threads simultaneously polling using this
 * interface.)
 *
 * This function actually performs all of the IO and other actions,
 * and generates events (libxl_event), which are implied by either
 * (a) the time of day or (b) both (i) the returned information from
 * _beforepoll, and (ii) the results from poll specified in
 * fds[0..nfds-1].  Generated events can then be retrieved by
 * libxl_event_check.
 */
void libxl_osevent_afterpoll(libxl_ctx *ctx, int nfds, const struct pollfd *fds,
                             struct timeval now);


typedef struct libxl_osevent_hooks {
  int (*fd_register)(void *user, int fd, void **for_app_registration_out,
                     short events, void *for_libxl);
  int (*fd_modify)(void *user, int fd, void **for_app_registration_update,
                   short events);
  void (*fd_deregister)(void *user, int fd, void *for_app_registration);
  int (*timeout_register)(void *user, void **for_app_registration_out,
                          struct timeval abs, void *for_libxl);
  int (*timeout_modify)(void *user, void **for_app_registration_update,
                         struct timeval abs);
  void (*timeout_deregister)(void *user, void *for_app_registration);
} libxl_osevent_hooks;

/* The application which calls register_fd_hooks promises to
 * maintain a register of fds and timeouts that libxl is interested
 * in, and make calls into libxl (libxl_osevent_occurred_*)
 * when those fd events and timeouts occur.  This is more efficient
 * than _beforepoll/_afterpoll if there are many fds (which can
 * happen if the same libxl application is managing many domains).
 *
 * For an fd event, events is as for poll().  register or modify may
 * be called with events==0, in which case it must still work
 * normally, just not generate any events.
 *
 * For a timeout event, milliseconds is as for poll().
 * Specifically, negative values of milliseconds mean NO TIMEOUT.
 * This is used by libxl to temporarily disable a timeout.
 *
 * If the register or modify hook succeeds it may update
 * *for_app_registration_out/_update and must then return 0.
 * On entry to register, *for_app_registration_out is always NULL.
 *
 * A registration or modification hook may fail, in which case it
 * must leave the registration state of the fd or timeout unchanged.
 * It may then either return ERROR_OSEVENT_REG_FAIL or any positive
 * int.  The value returned will be passed up through libxl and
 * eventually returned back to the application.  When register
 * fails, any value stored into *for_registration_out is ignored by
 * libxl; when modify fails, any changed value stored into
 * *for_registration_update is honoured by libxl and will be passed
 * to future modify or deregister calls.
 *
 * libxl will only attempt to register one callback for any one fd.
 * libxl will remember the value stored in *for_app_registration_out
 * (or *for_app_registration_update) by a successful call to
 * register (or modify), and pass it to subsequent calls to modify
 * or deregister.
 *
 * register_fd_hooks may be called only once for each libxl_ctx.
 * libxl may make calls to register/modify/deregister from within
 * any libxl function (indeed, it will usually call register from
 * register_event_hooks).  Conversely, the application MUST NOT make
 * the event occurrence calls (libxl_osevent_occurred_*) into libxl
 * reentrantly from within libxl (for example, from within the
 * register/modify functions).
 *
 * Lock hierarchy: the register/modify/deregister functions may be
 * called with locks held.  These locks (the "libxl internal locks")
 * are inside the libxl_ctx.  Therefore, if those register functions
 * acquire any locks of their own ("caller register locks") outside
 * libxl, to avoid deadlock one of the following must hold for each
 * such caller register lock:
 *  (a) "acquire libxl internal locks before caller register lock":
 *      No libxl function may be called with the caller register
 *      lock held.
 *  (b) "acquire caller register lock before libxl internal locks":
 *      No libxl function may be called _without_ the caller
 *      register lock held.
 * Of these we would normally recommend (a).
 *
 * The value *hooks is not copied and must outlast the libxl_ctx.
 */
void libxl_osevent_register_hooks(libxl_ctx *ctx,
                                  const libxl_osevent_hooks *hooks,
                                  void *user);

/* It is NOT legal to call _occurred_ reentrantly within any libxl
 * function.  Specifically it is NOT legal to call it from within
 * a register callback.  Conversely, libxl MAY call register/deregister
 * from within libxl_event_registered_call_*.
 */

void libxl_osevent_occurred_fd(libxl_ctx *ctx, void *for_libxl,
                               int fd, short events, short revents);

/* Implicitly, on entry to this function the timeout has been
 * deregistered.  If _occurred_timeout is called, libxl will not
 * call timeout_deregister; if it wants to requeue the timeout it
 * will call timeout_register again.
 */
void libxl_osevent_occurred_timeout(libxl_ctx *ctx, void *for_libxl);

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
