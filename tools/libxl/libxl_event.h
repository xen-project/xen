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
#include <poll.h>
#include <sys/time.h>

/*======================================================================*/

/*
 * Domain event handling - getting Xen events from libxl
 *
 * (Callers inside libxl may not call libxl_event_check or _wait.)
 */

#define LIBXL_EVENTMASK_ALL (~(unsigned long)0)

typedef int libxl_event_predicate(const libxl_event*, void *user);
  /* Return value is 0 if the event is unwanted or non-0 if it is.
   * Predicates are not allowed to fail.
   */

int libxl_event_check(libxl_ctx *ctx, libxl_event **event_r,
                      uint64_t typemask,
                      libxl_event_predicate *predicate, void *predicate_user)
                      LIBXL_EXTERNAL_CALLERS_ONLY;
  /* Searches for an event, already-happened, which matches typemask
   * and predicate.  predicate==0 matches any event.
   * libxl_event_check returns the event, which must then later be
   * freed by the caller using libxl_event_free.
   *
   * Returns ERROR_NOT_READY if no such event has happened.
   */

int libxl_event_wait(libxl_ctx *ctx, libxl_event **event_r,
                     uint64_t typemask,
                     libxl_event_predicate *predicate, void *predicate_user)
                     LIBXL_EXTERNAL_CALLERS_ONLY;
  /* Like libxl_event_check but blocks if no suitable events are
   * available, until some are.  Uses libxl_osevent_beforepoll/
   * _afterpoll so may be inefficient if very many domains are being
   * handled by a single program.
   */

void libxl_event_free(libxl_ctx *ctx, libxl_event *event);


/* Alternatively or additionally, the application may also use this: */

typedef struct libxl_event_hooks {
    uint64_t event_occurs_mask;
    void (*event_occurs)(void *user,
#ifndef LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG
                         const
#endif
                         libxl_event *event);
    void (*disaster)(void *user, libxl_event_type type,
                     const char *msg, int errnoval);
} libxl_event_hooks;

void libxl_event_register_callbacks(libxl_ctx *ctx,
                                    const libxl_event_hooks *hooks, void *user);
  /*
   * Arranges that libxl will henceforth call event_occurs for any
   * events whose type is set in event_occurs_mask, rather than
   * queueing the event for retrieval by libxl_event_check/wait.
   * Events whose bit is clear in mask are not affected.
   *
   * event becomes owned by the application and must be freed, either
   * by event_occurs or later.
   *
   * event_occurs may be NULL if mask is 0.
   *
   * libxl_event_register_callback also provides a way for libxl to
   * report to the application that there was a problem reporting
   * events; this can occur due to lack of host memory during event
   * handling, or other wholly unrecoverable errors from system calls
   * made by libxl.  This will not happen for frivolous reasons - only
   * if the system, or the Xen components of it, are badly broken.
   *
   * msg and errnoval will describe the action that libxl was trying
   * to do, and type specifies the type of libxl events which may be
   * missing.  type may be 0 in which case events of all types may be
   * missing.
   *
   * disaster may be NULL.  If it is, or if _register_callbacks has
   * not been called, errors of this kind are fatal to the entire
   * application: libxl will print messages to its logs and to stderr
   * and call exit(-1).
   *
   * If disaster returns, it may be the case that some or all future
   * libxl calls will return errors; likewise it may be the case that
   * no more events (of the specified type, if applicable) can be
   * produced.  An application which supplies a disaster function
   * should normally react either by exiting, or by (when it has
   * returned to its main event loop) shutting down libxl with
   * libxl_ctx_free and perhaps trying to restart it with
   * libxl_ctx_init.
   *
   * In any case before calling disaster, libxl will have logged a
   * message with level XTL_CRITICAL.
   *
   * Reentrancy: it IS permitted to call libxl from within
   * event_occurs.  It is NOT permitted to call libxl from within
   * disaster.  The event_occurs and disaster callbacks may occur on
   * any thread in which the application calls libxl.
   *
   * libxl_event_register_callbacks may be called as many times, with
   * different parameters, as the application likes; the most recent
   * call determines the libxl behaviour.  However it is NOT safe to
   * call _register_callbacks concurrently with, or reentrantly from,
   * any other libxl function.
   *
   * Calls to _register_callbacks do not affect events which have
   * already occurred.
   */


/*
 * Events are only generated if they have been requested.
 * The following functions request the generation of specific events.
 *
 * Each set of functions for controlling event generation has this form:
 *
 *   typedef struct libxl__evgen_FOO libxl__evgen_FOO;
 *   int libxl_evenable_FOO(libxl_ctx *ctx, FURTHER PARAMETERS,
 *                          libxl_ev_user user, libxl__evgen_FOO **evgen_out);
 *   void libxl_evdisable_FOO(libxl_ctx *ctx, libxl__evgen_FOO *evgen);
 *
 * The evenable function arranges that the events (as described in the
 * doc comment for the individual function) will start to be generated
 * by libxl.  On success, *evgen_out is set to a non-null pointer to
 * an opaque struct.
 *
 * The user value is returned in the generated events and may be
 * used by the caller for whatever it likes.  The type ev_user is
 * guaranteed to be an unsigned integer type which is at least
 * as big as uint64_t and is also guaranteed to be big enough to
 * contain any intptr_t value.
 *
 * If it becomes desirable to stop generation of the relevant events,
 * or to reclaim the resources in libxl associated with the evgen
 * structure, the same evgen value should be passed to the evdisable
 * function.  However, note that events which occurred prior to the
 * evdisable call may still be returned.
 *
 * The caller may enable identical events more than once.  If they do
 * so, each actual occurrence will generate several events to be
 * returned by libxl_event_check, with the appropriate user value(s).
 * Aside from this, each occurrence of each event is returned by
 * libxl_event_check exactly once.
 *
 * An evgen is associated with the libxl_ctx used for its creation.
 * After libxl_ctx_free, all corresponding evgen handles become
 * invalid and must no longer be passed to evdisable.
 *
 * Applications should ensure that they eventually retrieve every
 * event using libxl_event_check or libxl_event_wait, since events
 * which occur but are not retreived by the application will be queued
 * inside libxl indefinitely.  libxl_event_check/_wait may be O(n)
 * where n is the number of queued events which do not match the
 * criteria specified in the arguments to check/wait.
 */

typedef struct libxl__evgen_domain_death libxl_evgen_domain_death;
int libxl_evenable_domain_death(libxl_ctx *ctx, uint32_t domid,
                         libxl_ev_user, libxl_evgen_domain_death **evgen_out);
void libxl_evdisable_domain_death(libxl_ctx *ctx, libxl_evgen_domain_death*);
  /* Arranges for the generation of DOMAIN_SHUTDOWN and DOMAIN_DESTROY
   * events.  A domain which is destroyed before it shuts down
   * may generate only a DESTROY event.
   */

typedef struct libxl__evgen_disk_eject libxl_evgen_disk_eject;
int libxl_evenable_disk_eject(libxl_ctx *ctx, uint32_t domid, const char *vdev,
                        libxl_ev_user, libxl_evgen_disk_eject **evgen_out);
void libxl_evdisable_disk_eject(libxl_ctx *ctx, libxl_evgen_disk_eject*);
  /* Arranges for the generation of DISK_EJECT events.  A copy of the
   * string *vdev will be made for libxl's internal use, and a pointer
   * to this (or some other) copy will be returned as the vdev
   * member of event.u.
   */


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
 *          r = libxl_event_check(...);
 *          if (r==LIBXL_NOT_READY) break;
 *          if (r) goto error_out;
 *          do something with the event;
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
                             struct timeval now)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

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
                             struct timeval now)
                             LIBXL_EXTERNAL_CALLERS_ONLY;


typedef struct libxl_osevent_hooks {
  int (*fd_register)(void *user, int fd, void **for_app_registration_out,
                     short events, void *for_libxl);
  int (*fd_modify)(void *user, int fd, void **for_app_registration_update,
                   short events);
  void (*fd_deregister)(void *user, int fd, void *for_app_registration);
  int (*timeout_register)(void *user, void **for_app_registration_out,
                          struct timeval abs, void *for_libxl);
  int (*timeout_modify)(void *user, void **for_app_registration_update,
                         struct timeval abs)
      /* only ever called with abs={0,0}, meaning ASAP */;
  void (*timeout_deregister)(void *user, void *for_app_registration)
      /* will never be called */;
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
 * libxl may want to register more than one callback for any one fd;
 * in that case: (i) each such registration will have at least one bit
 * set in revents which is unique to that registration; (ii) if an
 * event occurs which is relevant for multiple registrations the
 * application's event system may call libxl_osevent_occurred_fd
 * for one, some, or all of those registrations.
 *
 * If fd_modify is used, it is permitted for the application's event
 * system to still make calls to libxl_osevent_occurred_fd for the
 * "old" set of requested events; these will be safely ignored by
 * libxl.
 *
 * libxl will remember the value stored in *for_app_registration_out
 * (or *for_app_registration_update) by a successful call to
 * register (or modify), and pass it to subsequent calls to modify
 * or deregister.
 *
 * Note that the application must cope with a call from libxl to
 * timeout_modify racing with its own call to
 * libxl__osevent_occurred_timeout.  libxl guarantees that
 * timeout_modify will only be called with abs={0,0} but the
 * application must still ensure that libxl's attempt to cause the
 * timeout to occur immediately is safely ignored even the timeout is
 * actually already in the process of occurring.
 *
 * timeout_deregister is not used because it forms part of a
 * deprecated unsafe mode of use of the API.
 *
 * osevent_register_hooks may be called only once for each libxl_ctx.
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
 * from within libxl_event_occurred_call_*.
 */

void libxl_osevent_occurred_fd(libxl_ctx *ctx, void *for_libxl,
                               int fd, short events, short revents)
                               LIBXL_EXTERNAL_CALLERS_ONLY;

/* Implicitly, on entry to this function the timeout has been
 * deregistered.  If _occurred_timeout is called, libxl will not
 * call timeout_deregister; if it wants to requeue the timeout it
 * will call timeout_register again.
 */
void libxl_osevent_occurred_timeout(libxl_ctx *ctx, void *for_libxl)
                                    LIBXL_EXTERNAL_CALLERS_ONLY;


/*======================================================================*/

/*
 * Subprocess handling.
 *
 * Unfortunately the POSIX interface makes this very awkward.
 *
 * There are two possible arrangements for collecting statuses from
 * wait/waitpid.
 *
 * For naive programs:
 *
 *     libxl will keep a SIGCHLD handler installed whenever it has an
 *     active (unreaped) child.  It will reap all children with
 *     wait(); any children it does not recognise will be passed to
 *     the application via an optional callback (and will result in
 *     logged warnings if no callback is provided or the callback
 *     denies responsibility for the child).
 *
 *     libxl may have children whenever:
 *
 *       - libxl is performing an operation which can be made
 *         asynchronous; ie one taking a libxl_asyncop_how, even
 *         if NULL is passed indicating that the operation is
 *         synchronous; or
 *
 *       - events of any kind are being generated, as requested
 *         by libxl_evenable_....
 *
 *     A multithreaded application which is naive in this sense may
 *     block SIGCHLD on some of its threads, but there must be at
 *     least one thread that has SIGCHLD unblocked.  libxl will not
 *     modify the blocking flag for SIGCHLD (except that it may create
 *     internal service threads with all signals blocked).
 *
 *     A naive program must only have at any one time only
 *     one libxl context which might have children.
 *
 * For programs which run their own children alongside libxl's:
 *
 *     A program which does this must call libxl_childproc_setmode.
 *     There are three options:
 * 
 *     libxl_sigchld_owner_libxl:
 *
 *       While any libxl operation which might use child processes
 *       is running, works like libxl_sigchld_owner_libxl_always;
 *       but, deinstalls the handler the rest of the time.
 *
 *       In this mode, the application, while it uses any libxl
 *       operation which might create or use child processes (see
 *       above):
 *           - Must not have any child processes running.
 *           - Must not install a SIGCHLD handler.
 *           - Must not reap any children.
 *
 *       This is the default (i.e. if setmode is not called, or 0 is
 *       passed for hooks).
 *
 *     libxl_sigchld_owner_mainloop:
 *
 *       The application must install a SIGCHLD handler and reap (at
 *       least) all of libxl's children and pass their exit status to
 *       libxl by calling libxl_childproc_exited.  (If the application
 *       has multiple libxl ctx's, it must call libxl_childproc_exited
 *       on each ctx.)
 *
 *     libxl_sigchld_owner_libxl_always:
 *
 *       The application expects this libxl ctx to reap all of the
 *       process's children, and provides a callback to be notified of
 *       their exit statuses.  The application must have only one
 *       libxl_ctx configured this way.
 *
 *     libxl_sigchld_owner_libxl_always_selective_reap:
 *
 *       The application expects to reap all of its own children
 *       synchronously, and does not use SIGCHLD.  libxl is to install
 *       a SIGCHLD handler.  The application may have multiple
 *       libxl_ctxs configured this way; in which case all of its ctxs
 *       must be so configured.
 */


typedef enum {
    /* libxl owns SIGCHLD whenever it has a child, and reaps
     * all children, including those not spawned by libxl. */
    libxl_sigchld_owner_libxl,

    /* Application promises to discover when SIGCHLD occurs and call
     * libxl_childproc_exited or libxl_childproc_sigchld_occurred (but
     * NOT from within a signal handler).  libxl will not itself
     * arrange to (un)block or catch SIGCHLD. */
    libxl_sigchld_owner_mainloop,

    /* libxl owns SIGCHLD all the time, and the application is
     * relying on libxl's event loop for reaping its children too. */
    libxl_sigchld_owner_libxl_always,

    /* libxl owns SIGCHLD all the time, but it must only reap its own
     * children.  The application will reap its own children
     * synchronously with waitpid, without the assistance of SIGCHLD. */
    libxl_sigchld_owner_libxl_always_selective_reap,
} libxl_sigchld_owner;

typedef struct {
    libxl_sigchld_owner chldowner;

    /* All of these are optional: */

    /* Called by libxl instead of fork.  Should behave exactly like
     * fork, including setting errno etc.  May NOT reenter into libxl.
     * Application may use this to discover pids of libxl's children,
     * for example.
     */
    pid_t (*fork_replacement)(void *user);

    /* With libxl_sigchld_owner_libxl, called by libxl when it has
     * reaped a pid.  (Not permitted with _owner_mainloop.)
     *
     * Should return 0 if the child was recognised by the application
     * (or if the application does not keep those kind of records),
     * ERROR_UNKNOWN_CHILD if the application knows that the child is not
     * the application's; if it returns another error code it is a
     * disaster as described for libxl_event_register_callbacks.
     * (libxl will report unexpected children to its error log.)
     *
     * If not supplied, the application is assumed not to start
     * any children of its own.
     *
     * This function is NOT called from within the signal handler.
     * Rather it will be called from inside a libxl's event handling
     * code and thus only when libxl is running, for example from
     * within libxl_event_wait.  (libxl uses the self-pipe trick
     * to implement this.)
     *
     * childproc_exited_callback may call back into libxl, but it
     * is best to avoid making long-running libxl calls as that might
     * stall the calling event loop while the nested operation
     * completes.
     */
    int (*reaped_callback)(pid_t, int status, void *user);
} libxl_childproc_hooks;

/* hooks may be 0 in which is equivalent to &{ libxl_sigchld_owner_libxl, 0, 0 }
 *
 * May not be called when libxl might have any child processes, or the
 * behaviour is undefined.  So it is best to call this at
 * initialisation.
 */
void libxl_childproc_setmode(libxl_ctx *ctx, const libxl_childproc_hooks *hooks,
                             void *user);

/*
 * This function is for an application which owns SIGCHLD and which
 * reaps all of the process's children, and dispatches the exit status
 * to the correct place inside the application.
 *
 * May be called only by an application which has called setmode with
 * chldowner == libxl_sigchld_owner_mainloop.  If pid was a process started
 * by this instance of libxl, returns 0 after doing whatever
 * processing is appropriate.  Otherwise silently returns
 * ERROR_UNKNOWN_CHILD.  No other error returns are possible.
 *
 * May NOT be called from within a signal handler which might
 * interrupt any libxl operation.  The application will almost
 * certainly need to use the self-pipe trick (or a working pselect or
 * ppoll) to implement this.
 */
int libxl_childproc_reaped(libxl_ctx *ctx, pid_t, int status)
                           LIBXL_EXTERNAL_CALLERS_ONLY;

/*
 * This function is for an application which owns SIGCHLD but which
 * doesn't keep track of all of its own children in a manner suitable
 * for reaping all of them and then dispatching them.
 *
 * Such an the application must notify libxl, by calling this
 * function, that a SIGCHLD occurred.  libxl will then check all its
 * children, reap any that are ready, and take any action necessary -
 * but it will not reap anything else.
 *
 * May be called only by an application which has called setmode with
 * chldowner == libxl_sigchld_owner_mainloop.
 *
 * May NOT be called from within a signal handler which might
 * interrupt any libxl operation (just like libxl_childproc_reaped).
 */
void libxl_childproc_sigchld_occurred(libxl_ctx *ctx)
                           LIBXL_EXTERNAL_CALLERS_ONLY;


/*
 * An application which initialises a libxl_ctx in a parent process
 * and then forks a child which does not quickly exec, must
 * instead libxl_postfork_child_noexec in the child.  One call
 * on any existing (or specially made) ctx is sufficient; after
 * this all previously existing libxl_ctx's are invalidated and
 * must not be used - or even freed.  It is harmless to call this
 * postfork function and then exec anyway.
 *
 * Until libxl_postfork_child_noexec has returned:
 *  - No other libxl calls may be made.
 *  - If any libxl ctx was configured handle the process's SIGCHLD,
 *    the child may not create further (grand)child processes, nor
 *    manipulate SIGCHLD.
 *
 * libxl_postfork_child_noexec may not reclaim all the resources
 * associated with the libxl ctx.  This includes but is not limited
 * to: ordinary memory; files on disk and in /var/run; file
 * descriptors; memory mapped into the process from domains being
 * managed (grant maps); Xen event channels.  Use of libxl in
 * processes which fork long-lived children is not recommended for
 * this reason.  libxl_postfork_child_noexec is provided so that
 * an application can make further libxl calls in a child which
 * is going to exec or exit soon.
 */
void libxl_postfork_child_noexec(libxl_ctx *ctx);


#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
