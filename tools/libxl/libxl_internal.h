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

#ifndef LIBXL_INTERNAL_H
#define LIBXL_INTERNAL_H

#include "libxl_osdeps.h" /* must come before any other headers */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <xenstore.h>
#include <xenctrl.h>
#include <xenguest.h>

#include "xentoollog.h"

#include <xen/io/xenbus.h>

#ifdef LIBXL_H
# error libxl.h should be included via libxl_internal.h, not separately
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
# define LIBXL_EXTERNAL_CALLERS_ONLY \
    __attribute__((warning("may not be called from within libxl")))
#endif

#include "libxl.h"
#include "_paths.h"
#include "_libxl_save_msgs_callout.h"

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define _hidden __attribute__((visibility("hidden")))
#define _protected __attribute__((visibility("protected")))
#else
#define _hidden
#define _protected
#endif

#include "flexarray.h"
#include "libxl_utils.h"

#include "libxl_json.h"

#include "_libxl_types_internal.h"
#include "_libxl_types_internal_json.h"

#define LIBXL_INIT_TIMEOUT 10
#define LIBXL_DESTROY_TIMEOUT 10
#define LIBXL_HOTPLUG_TIMEOUT 10
#define LIBXL_DEVICE_MODEL_START_TIMEOUT 10
#define LIBXL_QEMU_BODGE_TIMEOUT 2
#define LIBXL_XENCONSOLE_LIMIT 1048576
#define LIBXL_XENCONSOLE_PROTOCOL "vt100"
#define LIBXL_MAXMEM_CONSTANT 1024
#define LIBXL_PV_EXTRA_MEMORY 1024
#define LIBXL_HVM_EXTRA_MEMORY 2048
#define LIBXL_MIN_DOM0_MEM (128*1024)
/* use 0 as the domid of the toolstack domain for now */
#define LIBXL_TOOLSTACK_DOMID 0
#define QEMU_SIGNATURE "DeviceModelRecord0002"
#define STUBDOM_CONSOLE_LOGGING 0
#define STUBDOM_CONSOLE_SAVE 1
#define STUBDOM_CONSOLE_RESTORE 2
#define STUBDOM_CONSOLE_SERIAL 3
#define STUBDOM_SPECIAL_CONSOLES 3
#define TAP_DEVICE_SUFFIX "-emu"
#define DISABLE_UDEV_PATH "libxl/disable_udev"
#define DOMID_XS_PATH "domid"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define LIBXL__LOGGING_ENABLED

#ifdef LIBXL__LOGGING_ENABLED
#define LIBXL__LOG(ctx, loglevel, _f, _a...)   libxl__log(ctx, loglevel, -1, __FILE__, __LINE__, __func__, _f, ##_a)
#define LIBXL__LOG_ERRNO(ctx, loglevel, _f, _a...)   libxl__log(ctx, loglevel, errno, __FILE__, __LINE__, __func__, _f, ##_a)
#define LIBXL__LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)   libxl__log(ctx, loglevel, errnoval, __FILE__, __LINE__, __func__, _f, ##_a)
#else
#define LIBXL__LOG(ctx, loglevel, _f, _a...)
#define LIBXL__LOG_ERRNO(ctx, loglevel, _f, _a...)
#define LIBXL__LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)
#endif
  /* all of these macros preserve errno (saving and restoring) */

/* logging */
_hidden void libxl__logv(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
             const char *file /* may be 0 */, int line /* ignored if !file */,
             const char *func /* may be 0 */,
             const char *fmt, va_list al)
     __attribute__((format(printf,7,0)));

_hidden void libxl__log(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
            const char *file /* may be 0 */, int line /* ignored if !file */,
            const char *func /* may be 0 */,
            const char *fmt, ...)
     __attribute__((format(printf,7,8)));

     /* these functions preserve errno (saving and restoring) */

typedef struct libxl__gc libxl__gc;
typedef struct libxl__egc libxl__egc;
typedef struct libxl__ao libxl__ao;
typedef struct libxl__aop_occurred libxl__aop_occurred;
typedef struct libxl__osevent_hook_nexus libxl__osevent_hook_nexus;
typedef struct libxl__osevent_hook_nexi libxl__osevent_hook_nexi;

_hidden void libxl__alloc_failed(libxl_ctx *, const char *func,
                         size_t nmemb, size_t size) __attribute__((noreturn));
  /* func, size and nmemb are used only in the log message.
   * You may pass size==0 if size and nmemb are not meaningful
   * and should not be printed. */

typedef struct libxl__ev_fd libxl__ev_fd;
typedef void libxl__ev_fd_callback(libxl__egc *egc, libxl__ev_fd *ev,
                                   int fd, short events, short revents);
  /* Note that revents may contain POLLERR or POLLHUP regardless of
   * events; otherwise revents contains only bits in events.  Contrary
   * to the documentation for poll(2), POLLERR and POLLHUP can occur
   * even if only POLLIN was set in events.  (POLLNVAL is a fatal
   * error and will cause libxl event machinery to fail an assertion.)
   *
   * It is not permitted to listen for the same or overlapping events
   * on the same fd using multiple different libxl__ev_fd's.
   */
struct libxl__ev_fd {
    /* caller should include this in their own struct */
    /* read-only for caller, who may read only when registered: */
    int fd;
    short events;
    libxl__ev_fd_callback *func;
    /* remainder is private for libxl__ev_fd... */
    LIBXL_LIST_ENTRY(libxl__ev_fd) entry;
    libxl__osevent_hook_nexus *nexus;
};


typedef struct libxl__ev_time libxl__ev_time;
typedef void libxl__ev_time_callback(libxl__egc *egc, libxl__ev_time *ev,
                                     const struct timeval *requested_abs);
struct libxl__ev_time {
    /* caller should include this in their own struct */
    /* read-only for caller, who may read only when registered: */
    libxl__ev_time_callback *func;
    /* remainder is private for libxl__ev_time... */
    int infinite; /* not registered in list or with app if infinite */
    LIBXL_TAILQ_ENTRY(libxl__ev_time) entry;
    struct timeval abs;
    libxl__osevent_hook_nexus *nexus;
};

typedef struct libxl__ev_xswatch libxl__ev_xswatch;
typedef void libxl__ev_xswatch_callback(libxl__egc *egc, libxl__ev_xswatch*,
                            const char *watch_path, const char *event_path);
struct libxl__ev_xswatch {
    /* caller should include this in their own struct */
    /* read-only for caller, who may read only when registered: */
    char *path;
    libxl__ev_xswatch_callback *callback;
    /* remainder is private for libxl__ev_xswatch... */
    int slotnum; /* registered iff slotnum >= 0 */
    uint32_t counterval;
};

typedef struct libxl__ev_evtchn libxl__ev_evtchn;
typedef void libxl__ev_evtchn_callback(libxl__egc *egc, libxl__ev_evtchn*);
struct libxl__ev_evtchn {
    /* caller must fill these in, and they must all remain valid */
    libxl__ev_evtchn_callback *callback;
    int port;
    /* remainder is private for libxl__ev_evtchn_... */
    bool waiting;
    LIBXL_LIST_ENTRY(libxl__ev_evtchn) entry;
};

/*
 * An entry in the watch_slots table is either:
 *  1. an entry in the free list, ie NULL or pointer to next free list entry
 *  2. an pointer to a libxl__ev_xswatch
 *
 * But we don't want to use unions or type-punning because the
 * compiler might "prove" that our code is wrong and misoptimise it.
 *
 * The rules say that all struct pointers have identical
 * representation and alignment requirements (C99+TC1+TC2 6.2.5p26) so
 * what we do is simply declare our array as containing only the free
 * list pointers, and explicitly convert from and to our actual
 * xswatch pointers when we store and retrieve them.
 */
typedef struct libxl__ev_watch_slot {
    LIBXL_SLIST_ENTRY(struct libxl__ev_watch_slot) empty;
} libxl__ev_watch_slot;
    
_hidden libxl__ev_xswatch *libxl__watch_slot_contents(libxl__gc *gc,
                                                      int slotnum);


typedef struct libxl__ev_child libxl__ev_child;
typedef void libxl__ev_child_callback(libxl__egc *egc, libxl__ev_child*,
                                      pid_t pid, int status);
struct libxl__ev_child {
    /* caller should include this in their own struct */
    /* read-only for caller: */
    pid_t pid; /* -1 means unused ("unregistered", ie Idle) */
    libxl__ev_child_callback *callback;
    /* remainder is private for libxl__ev_... */
    LIBXL_LIST_ENTRY(struct libxl__ev_child) entry;
};


/*
 * evgen structures, which are the state we use for generating
 * events for the caller.
 *
 * In general in each case there's an internal and an external
 * version of the _evdisable_FOO function; the internal one is
 * used during cleanup.
 */
struct libxl__evgen_domain_death {
    uint32_t domid;
    unsigned shutdown_reported:1, death_reported:1;
    LIBXL_TAILQ_ENTRY(libxl_evgen_domain_death) entry;
        /* on list .death_reported ? CTX->death_list : CTX->death_reported */
    libxl_ev_user user;
};
_hidden void
libxl__evdisable_domain_death(libxl__gc*, libxl_evgen_domain_death*);

struct libxl__evgen_disk_eject {
    libxl__ev_xswatch watch;
    uint32_t domid;
    LIBXL_LIST_ENTRY(libxl_evgen_disk_eject) entry;
    libxl_ev_user user;
    char *vdev;
};
_hidden void
libxl__evdisable_disk_eject(libxl__gc*, libxl_evgen_disk_eject*);

typedef struct libxl__poller libxl__poller;
struct libxl__poller {
    /*
     * These are used to allow other threads to wake up a thread which
     * may be stuck in poll, because whatever it was waiting for
     * hadn't happened yet.  Threads which generate events will write
     * a byte to each pipe.  A thread which is waiting will empty its
     * own pipe, and put its poller on the pollers_event list, before
     * releasing the ctx lock and going into poll; when it comes out
     * of poll it will take the poller off the pollers_event list.
     *
     * A thread which is waiting for completion of a synchronous ao
     * will allocate a poller and record it in the ao, so that other
     * threads can wake it up.
     *
     * When a thread is done with a poller it should put it onto
     * pollers_idle, where it can be reused later.
     *
     * The "poller_app" is never idle, but is sometimes on
     * pollers_event.
     */
    LIBXL_LIST_ENTRY(libxl__poller) entry;

    struct pollfd *fd_polls;
    int fd_polls_allocd;

    int fd_rindices_allocd;
    int (*fd_rindices)[3]; /* see libxl_event.c:beforepoll_internal */

    int wakeup_pipe[2]; /* 0 means no fd allocated */
};

struct libxl__gc {
    /* mini-GC */
    int alloc_maxsize; /* -1 means this is the dummy non-gc gc */
    void **alloc_ptrs;
    libxl_ctx *owner;
};

struct libxl__ctx {
    xentoollog_logger *lg;
    xc_interface *xch;
    struct xs_handle *xsh;
    libxl__gc nogc_gc;

    const libxl_event_hooks *event_hooks;
    void *event_hooks_user;

    pthread_mutex_t lock; /* protects data structures hanging off the ctx */
      /* Always use libxl__ctx_lock and _unlock (or the convenience
       * macors CTX_LOCK and CTX_UNLOCK) to manipulate this.
       *
       * You may acquire this mutex recursively if it is convenient to
       * do so.  You may not acquire this lock at the same time as any
       * other lock.  If you need to call application code outside
       * libxl (ie, a callback) with this lock held then it is
       * necessaray to impose restrictions on the caller to maintain a
       * proper lock hierarchy, and these restrictions must then be
       * documented in the libxl public interface.
       */

    LIBXL_TAILQ_HEAD(libxl__event_list, libxl_event) occurred;

    int osevent_in_hook;
    const libxl_osevent_hooks *osevent_hooks;
    void *osevent_user;
      /* See the comment for OSEVENT_HOOK_INTERN in libxl_event.c
       * for restrictions on the use of the osevent fields. */

    libxl__poller poller_app; /* libxl_osevent_beforepoll and _afterpoll */
    LIBXL_LIST_HEAD(, libxl__poller) pollers_event, pollers_idle;

    LIBXL_SLIST_HEAD(libxl__osevent_hook_nexi, libxl__osevent_hook_nexus)
        hook_fd_nexi_idle, hook_timeout_nexi_idle;
    LIBXL_LIST_HEAD(, libxl__ev_fd) efds;
    LIBXL_TAILQ_HEAD(, libxl__ev_time) etimes;

    libxl__ev_watch_slot *watch_slots;
    int watch_nslots;
    LIBXL_SLIST_HEAD(, libxl__ev_watch_slot) watch_freeslots;
    uint32_t watch_counter; /* helps disambiguate slot reuse */
    libxl__ev_fd watch_efd;

    xc_evtchn *xce; /* waiting must be done only with libxl__ev_evtchn* */
    LIBXL_LIST_HEAD(, libxl__ev_evtchn) evtchns_waiting;
    libxl__ev_fd evtchn_efd;

    LIBXL_TAILQ_HEAD(libxl__evgen_domain_death_list, libxl_evgen_domain_death)
        death_list /* sorted by domid */,
        death_reported;
    libxl__ev_xswatch death_watch;
    
    LIBXL_LIST_HEAD(, libxl_evgen_disk_eject) disk_eject_evgens;

    const libxl_childproc_hooks *childproc_hooks;
    void *childproc_user;
    int sigchld_selfpipe[2]; /* [0]==-1 means handler not installed */
    libxl__ev_fd sigchld_selfpipe_efd;
    LIBXL_LIST_HEAD(, libxl__ev_child) children;
    bool sigchld_user_registered;
    LIBXL_LIST_ENTRY(libxl_ctx) sigchld_users_entry;

    libxl_version_info version_info;
};

typedef struct {
    uint32_t backend_devid;
    uint32_t backend_domid;
    uint32_t devid;
    uint32_t domid;
    libxl__device_kind backend_kind;
    libxl__device_kind kind;
} libxl__device;

/* Used to know if backend of given device is QEMU */
#define QEMU_BACKEND(dev) (\
    (dev)->backend_kind == LIBXL__DEVICE_KIND_QDISK || \
    (dev)->backend_kind == LIBXL__DEVICE_KIND_VFB || \
    (dev)->backend_kind == LIBXL__DEVICE_KIND_VKBD)

#define XC_PCI_BDF             "0x%x, 0x%x, 0x%x, 0x%x"
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)         ((devfn) & 0x07)
#define AUTO_PHP_SLOT          0x100

#define PROC_PCI_NUM_RESOURCES 7
#define PCI_BAR_IO             0x01

#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))

struct libxl__egc {
    /* For event-generating functions only.
     * The egc and its gc may be accessed only on the creating thread. */
    struct libxl__gc gc;
    struct libxl__event_list occurred_for_callback;
    LIBXL_TAILQ_HEAD(, libxl__ao) aos_for_callback;
    LIBXL_TAILQ_HEAD(, libxl__aop_occurred) aops_for_callback;
};

struct libxl__aop_occurred {
    /*
     * An aop belongs to, and may be accessed only on, the thread
     * which created it.  It normally lives in that thread's egc.
     *
     * While an aop exists, it corresponds to one refcount in
     * ao->progress_reports_outstanding, preventing ao destruction.
     */
    LIBXL_TAILQ_ENTRY(libxl__aop_occurred) entry;
    libxl__ao *ao;
    libxl_event *ev;
    const libxl_asyncprogress_how *how;
};

#define LIBXL__AO_MAGIC              0xA0FACE00ul
#define LIBXL__AO_MAGIC_DESTROYED    0xA0DEAD00ul

struct libxl__ao {
    /*
     * An ao and its gc may be accessed only with the ctx lock held.
     *
     * Special exception: If an ao has been added to
     * egc->aos_for_callback, the thread owning the egc may remove the
     * ao from that list and make the callback without holding the
     * lock.
     *
     * Corresponding restriction: An ao may be added only to one
     * egc->aos_for_callback, once; rc and how must already have been
     * set and may not be subsequently modified.  (This restriction is
     * easily and obviously met since the ao is queued for callback
     * only in libxl__ao_complete.)
     */
    uint32_t magic;
    unsigned constructing:1, in_initiator:1, complete:1, notified:1, nested:1;
    int progress_reports_outstanding;
    int rc;
    libxl__gc gc;
    libxl_asyncop_how how;
    libxl__poller *poller;
    uint32_t domid;
    LIBXL_TAILQ_ENTRY(libxl__ao) entry_for_callback;
};

#define LIBXL_INIT_GC(gc,ctx) do{               \
        (gc).alloc_maxsize = 0;                 \
        (gc).alloc_ptrs = 0;                    \
        (gc).owner = (ctx);                     \
    } while(0)
    /* NB, also, a gc struct ctx->nogc_gc is initialised in libxl_ctx_alloc */

static inline libxl_ctx *libxl__gc_owner(libxl__gc *gc)
{
    return gc->owner;
}

static inline int libxl__gc_is_real(const libxl__gc *gc)
{
    return gc->alloc_maxsize >= 0;
}

/*
 * Memory allocation tracking/helpers
 *
 * See comment "libxl memory management" in libxl.h for a description
 * of the framework which these calls belong to.
 *
 * These functions deal with memory allocations of type (a) and (d) in
 * that description.
 *
 * All pointers returned by these functions are registered for garbage
 * collection on exit from the outermost libxl callframe.
 *
 * However, where the argument is stated to be "gc_opt", &ctx->nogc_gc
 * may be passed instead, in which case no garbage collection will
 * occur; the pointer must later be freed with free().  (Passing NULL
 * for gc_opt is not permitted.)  This is for memory allocations of
 * types (b) and (c).  The convenience macro NOGC should be used where
 * possible.
 *
 * NOGC (and ctx->nogc_gc) may ONLY be used with functions which
 * explicitly declare that it's OK.  Use with nonconsenting functions
 * may result in leaks of those functions' internal allocations on the
 * psuedo-gc.
 */
/* register ptr in gc for free on exit from outermost libxl callframe. */

#define NN1 __attribute__((nonnull(1)))
 /* It used to be legal to pass NULL for gc_opt.  Get the compiler to
  * warn about this if any slip through. */

_hidden void libxl__ptr_add(libxl__gc *gc_opt, void *ptr /* may be NULL */) NN1;
/* if this is the outermost libxl callframe then free all pointers in @gc */
_hidden void libxl__free_all(libxl__gc *gc);
/* allocate @size bytes. (a gc'd malloc(3)) */
_hidden void *libxl__malloc(libxl__gc *gc_opt, size_t size) NN1;
/* allocate and zero @size. (similar to a gc'd malloc(3)+memzero()) */
_hidden void *libxl__zalloc(libxl__gc *gc_opt, size_t size) NN1;
/* allocate and zero memory for an array of @nmemb members of @size each.
 * (similar to a gc'd calloc(3)). */
_hidden void *libxl__calloc(libxl__gc *gc_opt, size_t nmemb, size_t size) NN1;
/* change the size of the memory block pointed to by @ptr to @new_size bytes.
 * unlike other allocation functions here any additional space between the
 * oldsize and @new_size is not initialised (similar to a gc'd realloc(3)). */
_hidden void *libxl__realloc(libxl__gc *gc_opt, void *ptr, size_t new_size) NN1;
/* print @fmt into an allocated string large enoughto contain the result.
 * (similar to gc'd asprintf(3)). */
_hidden char *libxl__sprintf(libxl__gc *gc_opt, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3) NN1;
/* duplicate the string @c (similar to a gc'd strdup(3)). */
_hidden char *libxl__strdup(libxl__gc *gc_opt, const char *c) NN1;
/* duplicate at most @n bytes of string @c (similar to a gc'd strndup(3)). */
_hidden char *libxl__strndup(libxl__gc *gc_opt, const char *c, size_t n) NN1;
/* strip the last path component from @s and return as a newly allocated
 * string. (similar to a gc'd dirname(3)). */
_hidden char *libxl__dirname(libxl__gc *gc_opt, const char *s) NN1;

/* Make a pipe and set both ends nonblocking.  On error, nothing
 * is left open and both fds[]==-1, and a message is logged.
 * Useful for self-pipes. */
_hidden int libxl__pipe_nonblock(libxl_ctx *ctx, int fds[2]);
/* Closes the pipe fd(s).  Either or both of fds[] may be -1 meaning
 * `not open'.  Ignores any errors.  Sets fds[] to -1. */
_hidden void libxl__pipe_close(int fds[2]);


/* Each of these logs errors and returns a libxl error code.
 * They do not mind if path is already removed.
 * For _file, path must not be a directory; for _directory it must be. */
_hidden int libxl__remove_file(libxl__gc *gc, const char *path);
_hidden int libxl__remove_directory(libxl__gc *gc, const char *path);
_hidden int libxl__remove_file_or_directory(libxl__gc *gc, const char *path);


_hidden char **libxl__xs_kvs_of_flexarray(libxl__gc *gc, flexarray_t *array, int length);

/* treats kvs as pairs of keys and values and writes each to dir. */
_hidden int libxl__xs_writev(libxl__gc *gc, xs_transaction_t t,
                             const char *dir, char **kvs);
/* as writev but also sets the permissions on each path */
_hidden int libxl__xs_writev_perms(libxl__gc *gc, xs_transaction_t t,
                                   const char *dir, char *kvs[],
                                   struct xs_permissions *perms,
                                   unsigned int num_perms);
/* _atonce creates a transaction and writes all keys at once */
_hidden int libxl__xs_writev_atonce(libxl__gc *gc,
                             const char *dir, char **kvs);

_hidden int libxl__xs_write(libxl__gc *gc, xs_transaction_t t,
               const char *path, const char *fmt, ...) PRINTF_ATTRIBUTE(4, 5);
   /* Each fn returns 0 on success.
    * On error: returns -1, sets errno (no logging) */

_hidden char *libxl__xs_get_dompath(libxl__gc *gc, uint32_t domid);
   /* On error: logs, returns NULL, sets errno. */

_hidden char *libxl__xs_read(libxl__gc *gc, xs_transaction_t t,
                             const char *path);
_hidden char **libxl__xs_directory(libxl__gc *gc, xs_transaction_t t,
                                   const char *path, unsigned int *nb);
   /* On error: returns NULL, sets errno (no logging) */
_hidden bool libxl__xs_mkdir(libxl__gc *gc, xs_transaction_t t,
                             const char *path, struct xs_permissions *perms,
			     unsigned int num_perms);

_hidden char *libxl__xs_libxl_path(libxl__gc *gc, uint32_t domid);


/*----- "checked" xenstore access functions -----*/
/* Each of these functions will check that it succeeded; if it
 * fails it logs and returns ERROR_FAIL.
 */

/* On success, *result_out came from the gc.
 * On error, *result_out is undefined.
 * ENOENT counts as success but sets *result_out=0
 */
int libxl__xs_read_checked(libxl__gc *gc, xs_transaction_t t,
                           const char *path, const char **result_out);

/* Does not include a trailing null.
 * May usefully be combined with GCSPRINTF if the format string
 * behaviour of libxl__xs_write is desirable. */
int libxl__xs_write_checked(libxl__gc *gc, xs_transaction_t t,
                            const char *path, const char *string);

/* ENOENT is not an error (even if the parent directories don't exist) */
int libxl__xs_rm_checked(libxl__gc *gc, xs_transaction_t t, const char *path);

/* Transaction functions, best used together.
 * The caller should initialise *t to 0 (XBT_NULL) before calling start.
 * Each function leaves *t!=0 iff the transaction needs cleaning up.
 *
 * libxl__xs_transaction_commit returns:
 *   <0  failure - a libxl error code
 *   +1  commit conflict; transaction has been destroyed and caller
 *        must go round again (call _start again and retry)
 *    0  committed successfully
 *
 * The intended usage pattern looks like this:
 *    int some_function()
 *    {
 *        int rc;
 *        xs_transaction_t t = 0;
 *        // other initialisations
 *
 *        // do whatever you need to do before the xenstore stuff
 *        // errors?  set rc and goto out.
 *
 *        for (;;) {
 *            rc = libxl__xs_transaction_start(gc, &t);
 *            if (rc) goto out;
 *
 *            // do your work here, including all xenstore reads and writes
 *            // libxl__xs_*_checked are useful; pass them t.
 *            // errors?  set rc and goto out.
 *
 *            rc = libxl__xs_transaction_commit(gc, &t);
 *            if (!rc) break;
 *            if (rc<0) goto out;
 *        }
 *
 *        // now the xenstore transaction succeeded
 *        // do whatever else you need to do
 *        // errors?  set rc and goto out.
 *
 *        return something;
 *
 *     out:
 *        // other cleanups
 *        libxl__xs_transaction_abort(gc, &t);
 *        // other cleanups
 *        return rc;
 *    }
 *
 * Formally the states of *t are:
 *
 *  name     value of *t  description
 *   Idle         0         no transaction exists
 *   Ready        non-0     ready for work, nothing done yet
 *   Busy         non-0     writes have been made but we are not finished
 *   Uncommitted  non-0     writes have been made and should be committed
 *
 * libxl__xs_transaction_start:  Idle -> Ready (on error: Idle)
 *
 * The transaction goes from Ready to Busy, and from Busy to
 * Uncommitted, by the use of xenstore read and write operations
 * (libxl__xs_..., xs_...) made by libxl__xs_transaction's caller.
 *
 * libxl__xs_transaction_commit:  Ready/Uncommitted -> Idle
 *     on success (returns 0): xenstore has been updated
 *     on error (<0) or conflict (+1): updates discarded
 *
 * libxl__xs_transaction_abort:  Any -> Idle  (any updates discarded)
 */
int libxl__xs_transaction_start(libxl__gc *gc, xs_transaction_t *t);
int libxl__xs_transaction_commit(libxl__gc *gc, xs_transaction_t *t);
void libxl__xs_transaction_abort(libxl__gc *gc, xs_transaction_t *t);



/*
 * This is a recursive delete, from top to bottom. What this function does
 * is remove empty folders that contained the deleted entry.
 *
 * It mimics xenstore-rm -t behaviour.
 */
_hidden int libxl__xs_path_cleanup(libxl__gc *gc, xs_transaction_t t,
                                   const char *user_path);

/*
 * Event generation functions provided by the libxl event core to the
 * rest of libxl.  Implemented in terms of _beforepoll/_afterpoll
 * and/or the fd registration machinery, as provided by the
 * application.
 *
 * Semantics are similar to those of the fd and timeout registration
 * functions provided to libxl_osevent_register_hooks.
 *
 * Non-0 returns from libxl__ev_{modify,deregister} have already been
 * logged by the core and should be returned unmodified to libxl's
 * caller; NB that they may be valid libxl error codes but they may
 * also be positive numbers supplied by the caller.
 *
 * In each case, there is a libxl__ev_FOO structure which can be in
 * one of three states:
 *
 *   Undefined   - Might contain anything.  All-bits-zero is
 *                 an undefined state.
 *
 *   Idle        - Struct contents are defined enough to pass to any
 *                 libxl__ev_FOO function but not registered and
 *                 callback will not be called.  The struct does not
 *                 contain references to any allocated resources so
 *                 can be thrown away.
 *
 *   Active      - Request for events has been registered and events
 *                 may be generated.  _deregister must be called to
 *                 reclaim resources.
 *
 * These functions are provided for each kind of event KIND:
 *
 *   int libxl__ev_KIND_register(libxl__gc *gc, libxl__ev_KIND *GEN,
 *                              libxl__ev_KIND_callback *FUNC,
 *                              DETAILS);
 *      On entry *GEN must be in state Undefined or Idle.
 *      Returns a libxl error code; on error return *GEN is Idle.
 *      On successful return *GEN is Active and FUNC wil be
 *      called by the event machinery in future.  FUNC will
 *      not be called from within the call to _register.
 *      FUNC will be called with the context locked (with CTX_LOCK).
 *
 *  void libxl__ev_KIND_deregister(libxl__gc *gc, libxl__ev_KIND *GEN_upd);
 *      On entry *GEN must be in state Active or Idle.
 *      On return it is Idle.  (Idempotent.)
 *
 *  void libxl__ev_KIND_init(libxl__ev_KIND *GEN);
 *      Provided for initialising an Undefined KIND.
 *      On entry *GEN must be in state Idle or Undefined.
 *      On return it is Idle.  (Idempotent.)
 *
 *  int libxl__ev_KIND_isregistered(const libxl__ev_KIND *GEN);
 *      On entry *GEN must be Idle or Active.
 *      Returns nonzero if it is Active, zero otherwise.
 *      Cannot fail.
 *
 *  int libxl__ev_KIND_modify(libxl__gc*, libxl__ev_KIND *GEN,
 *                            DETAILS);
 *      Only provided for some kinds of generator.
 *      On entry *GEN must be Active and on return, whether successful
 *      or not, it will be Active.
 *      Returns a libxl error code; on error the modification
 *      is not effective.
 *
 * All of these functions are fully threadsafe and may be called by
 * general code in libxl even from within event callback FUNCs.
 * The ctx will be locked on entry to each FUNC and FUNC should not
 * unlock it.
 *
 * Callers of libxl__ev_KIND_register must ensure that the
 * registration is undone, with _deregister, in libxl_ctx_free.
 * This means that normally each kind of libxl__evgen (ie each
 * application-requested event source) needs to be on a list so that
 * it can be automatically deregistered as promised in libxl_event.h.
 */


_hidden int libxl__ev_fd_register(libxl__gc*, libxl__ev_fd *ev_out,
                                  libxl__ev_fd_callback*,
                                  int fd, short events /* as for poll(2) */);
_hidden int libxl__ev_fd_modify(libxl__gc*, libxl__ev_fd *ev,
                                short events);
_hidden void libxl__ev_fd_deregister(libxl__gc*, libxl__ev_fd *ev);
static inline void libxl__ev_fd_init(libxl__ev_fd *efd)
                    { efd->fd = -1; }
static inline int libxl__ev_fd_isregistered(const libxl__ev_fd *efd)
                    { return efd->fd >= 0; }

_hidden int libxl__ev_time_register_rel(libxl__gc*, libxl__ev_time *ev_out,
                                        libxl__ev_time_callback*,
                                        int milliseconds /* as for poll(2) */);
_hidden int libxl__ev_time_register_abs(libxl__gc*, libxl__ev_time *ev_out,
                                        libxl__ev_time_callback*,
                                        struct timeval);
_hidden int libxl__ev_time_modify_rel(libxl__gc*, libxl__ev_time *ev,
                                      int milliseconds /* as for poll(2) */);
_hidden int libxl__ev_time_modify_abs(libxl__gc*, libxl__ev_time *ev,
                                      struct timeval);
_hidden void libxl__ev_time_deregister(libxl__gc*, libxl__ev_time *ev);
static inline void libxl__ev_time_init(libxl__ev_time *ev)
                { ev->func = 0; }
static inline int libxl__ev_time_isregistered(const libxl__ev_time *ev)
                { return !!ev->func; }


_hidden int libxl__ev_xswatch_register(libxl__gc*, libxl__ev_xswatch *xsw_out,
                                       libxl__ev_xswatch_callback*,
                                       const char *path /* copied */);
_hidden void libxl__ev_xswatch_deregister(libxl__gc *gc, libxl__ev_xswatch*);

static inline void libxl__ev_xswatch_init(libxl__ev_xswatch *xswatch_out)
                { xswatch_out->slotnum = -1; }
static inline int libxl__ev_xswatch_isregistered(const libxl__ev_xswatch *xw)
                { return xw->slotnum >= 0; }


/*
 * The evtchn facility is one-shot per call to libxl__ev_evtchn_wait.
 * You should call some suitable xc bind function on (or to obtain)
 * the port, then libxl__ev_evtchn_wait.
 *
 * When the event is signaled then the callback will be made, once.
 * Then you must call libxl__ev_evtchn_wait again, if desired.
 *
 * You must NOT call xc_evtchn_unmask.  wait will do that for you.
 *
 * Calling libxl__ev_evtchn_cancel will arrange for libxl to disregard
 * future occurrences of event.  Both libxl__ev_evtchn_wait and
 * libxl__ev_evtchn_cancel are idempotent.
 *
 * (Note of course that an event channel becomes signaled when it is
 * first bound, so you will get one call to libxl__ev_evtchn_wait
 * "right away"; unless you have won a very fast race, the condition
 * you were waiting for won't exist yet so when you check for it
 * you'll find you need to call wait again.)
 *
 * You must not wait on the same port twice at once (that is, with
 * two separate libxl__ev_evtchn's).
 */
_hidden int libxl__ev_evtchn_wait(libxl__gc*, libxl__ev_evtchn *evev);
_hidden void libxl__ev_evtchn_cancel(libxl__gc *gc, libxl__ev_evtchn *evev);

static inline void libxl__ev_evtchn_init(libxl__ev_evtchn *evev)
                { evev->waiting = 0; }
static inline bool libxl__ev_evtchn_iswaiting(const libxl__ev_evtchn *evev)
                { return evev->waiting; }

_hidden int libxl__ctx_evtchn_init(libxl__gc *gc); /* for libxl_ctx_alloc */

/*
 * For making subprocesses.  This is the only permitted mechanism for
 * code in libxl to do so.
 *
 * In the parent, returns the pid, filling in childw_out.
 * In the child, returns 0.
 * If it fails, returns a libxl error (all of which are -ve).
 *
 * The child should go on to exec (or exit) soon.  The child may not
 * make any further calls to libxl infrastructure, except for memory
 * allocation and logging.  If the child needs to use xenstore it
 * must open its own xs handle and use it directly, rather than via
 * the libxl event machinery.
 *
 * The parent may signal the child but it must not reap it.  That will
 * be done by the event machinery.
 *
 * It is not possible to "deregister" the child death event source.
 * It will generate exactly one event callback; until then the childw
 * is Active and may not be reused.
 */
_hidden pid_t libxl__ev_child_fork(libxl__gc *gc, libxl__ev_child *childw_out,
                                 libxl__ev_child_callback *death);
static inline void libxl__ev_child_init(libxl__ev_child *childw_out)
                { childw_out->pid = -1; }
static inline int libxl__ev_child_inuse(const libxl__ev_child *childw_out)
                { return childw_out->pid >= 0; }

/* Useable (only) in the child to once more make the ctx useable for
 * xenstore operations.  logs failure in the form "what: <error
 * message>". */
_hidden int libxl__ev_child_xenstore_reopen(libxl__gc *gc, const char *what);


/*
 * Other event-handling support provided by the libxl event core to
 * the rest of libxl.
 */

_hidden void libxl__event_occurred(libxl__egc*, libxl_event *event);
  /* Arranges to notify the application that the event has occurred.
   * event should be suitable for passing to libxl_event_free. */

_hidden libxl_event *libxl__event_new(libxl__egc*, libxl_event_type,
                                      uint32_t domid,
                                      libxl_ev_user for_user);
  /* Convenience function.
   * Allocates a new libxl_event, fills in domid and type.
   * Cannot fail. */

#define NEW_EVENT(egc, type, domid, user)                        \
    libxl__event_new((egc), LIBXL_EVENT_TYPE_##type, (domid), (user))
    /* Convenience macro. */

/*
 * In general, call this via the macro LIBXL__EVENT_DISASTER.
 *
 * Event-generating functions may call this if they might have wanted
 * to generate an event (either an internal one ie a
 * libxl__ev_FOO_callback or an application event), but are prevented
 * from doing so due to eg lack of memory.
 *
 * NB that this function may return and the caller isn't supposed to
 * then crash, although it may fail (and henceforth leave things in a
 * state where many or all calls fail).
 */
_hidden void libxl__event_disaster(libxl__egc*, const char *msg, int errnoval,
                                   libxl_event_type type /* may be 0 */,
                                   const char *file, int line,
                                   const char *func);
#define LIBXL__EVENT_DISASTER(egc, msg, errnoval, type) \
    libxl__event_disaster(egc, msg, errnoval, type, __FILE__,__LINE__,__func__)


/* Fills in, or disposes of, the resources held by, a poller whose
 * space the caller has allocated.  ctx must be locked. */
_hidden int libxl__poller_init(libxl__gc *gc, libxl__poller *p);
_hidden void libxl__poller_dispose(libxl__poller *p);

/* Obtain a fresh poller from malloc or the idle list, and put it
 * away again afterwards.  _get can fail, returning NULL.
 * ctx must be locked. */
_hidden libxl__poller *libxl__poller_get(libxl__gc *gc);
_hidden void libxl__poller_put(libxl_ctx*, libxl__poller *p /* may be NULL */);

/* Notifies whoever is polling using p that they should wake up.
 * ctx must be locked. */
_hidden void libxl__poller_wakeup(libxl__egc *egc, libxl__poller *p);

/* Internal to fork and child reaping machinery */
extern const libxl_childproc_hooks libxl__childproc_default_hooks;
int libxl__sigchld_needed(libxl__gc*); /* non-reentrant idempotent, logs errs */
void libxl__sigchld_notneeded(libxl__gc*); /* non-reentrant idempotent */
void libxl__sigchld_check_stale_handler(void);
int libxl__self_pipe_wakeup(int fd); /* returns 0 or -1 setting errno */
int libxl__self_pipe_eatall(int fd); /* returns 0 or -1 setting errno */


_hidden int libxl__atfork_init(libxl_ctx *ctx);


/* File references */
typedef struct {
    /*
     * Path is always set if the file reference is valid. However if
     * mapped is true then the actual file may already be unlinked.
     */
    const char * path;
    int mapped;
    void * data;
    size_t size;
} libxl__file_reference;
_hidden int libxl__file_reference_map(libxl__file_reference *f);
_hidden int libxl__file_reference_unmap(libxl__file_reference *f);

/* from xl_dom */
_hidden libxl_domain_type libxl__domain_type(libxl__gc *gc, uint32_t domid);
_hidden int libxl__domain_shutdown_reason(libxl__gc *gc, uint32_t domid);
_hidden int libxl__domain_cpupool(libxl__gc *gc, uint32_t domid);
_hidden libxl_scheduler libxl__domain_scheduler(libxl__gc *gc, uint32_t domid);
_hidden int libxl__sched_set_params(libxl__gc *gc, uint32_t domid,
                                    libxl_domain_sched_params *scparams);

typedef struct {
    uint32_t store_port;
    uint32_t store_domid;
    unsigned long store_mfn;

    uint32_t console_port;
    uint32_t console_domid;
    unsigned long console_mfn;

    unsigned long vm_generationid_addr;

    char *saved_state;

    libxl__file_reference pv_kernel;
    libxl__file_reference pv_ramdisk;
    const char * pv_cmdline;
    bool pvh_enabled;
} libxl__domain_build_state;

_hidden int libxl__build_pre(libxl__gc *gc, uint32_t domid,
              libxl_domain_config * const d_config,
              libxl__domain_build_state *state);
_hidden int libxl__build_post(libxl__gc *gc, uint32_t domid,
               libxl_domain_build_info *info, libxl__domain_build_state *state,
               char **vms_ents, char **local_ents);

_hidden int libxl__build_pv(libxl__gc *gc, uint32_t domid,
             libxl_domain_build_info *info, libxl__domain_build_state *state);
_hidden int libxl__build_hvm(libxl__gc *gc, uint32_t domid,
              libxl_domain_build_info *info,
              libxl__domain_build_state *state);

_hidden int libxl__qemu_traditional_cmd(libxl__gc *gc, uint32_t domid,
                                        const char *cmd);
_hidden int libxl__domain_rename(libxl__gc *gc, uint32_t domid,
                                 const char *old_name, const char *new_name,
                                 xs_transaction_t trans);

_hidden int libxl__toolstack_restore(uint32_t domid, const uint8_t *buf,
                                     uint32_t size, void *data);
_hidden int libxl__domain_resume_device_model(libxl__gc *gc, uint32_t domid);

_hidden void libxl__userdata_destroyall(libxl__gc *gc, uint32_t domid);

_hidden int libxl__domain_resume(libxl__gc *gc, uint32_t domid,
                                 int suspend_cancel);

/* returns 0 or 1, or a libxl error code */
_hidden int libxl__domain_pvcontrol_available(libxl__gc *gc, uint32_t domid);

_hidden const char *libxl__domain_pvcontrol_xspath(libxl__gc*, uint32_t domid);
_hidden char * libxl__domain_pvcontrol_read(libxl__gc *gc,
                                            xs_transaction_t t, uint32_t domid);
_hidden int libxl__domain_pvcontrol_write(libxl__gc *gc, xs_transaction_t t,
                                          uint32_t domid, const char *cmd);

/* from xl_device */
_hidden char *libxl__device_disk_string_of_backend(libxl_disk_backend backend);
_hidden char *libxl__device_disk_string_of_format(libxl_disk_format format);
_hidden int libxl__device_disk_set_backend(libxl__gc*, libxl_device_disk*);

_hidden int libxl__device_physdisk_major_minor(const char *physpath, int *major, int *minor);
_hidden int libxl__device_disk_dev_number(const char *virtpath,
                                          int *pdisk, int *ppartition);

_hidden int libxl__device_console_add(libxl__gc *gc, uint32_t domid,
                                      libxl__device_console *console,
                                      libxl__domain_build_state *state);

_hidden int libxl__device_generic_add(libxl__gc *gc, xs_transaction_t t,
        libxl__device *device, char **bents, char **fents, char **ro_fents);
_hidden char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device);
_hidden char *libxl__device_frontend_path(libxl__gc *gc, libxl__device *device);
_hidden int libxl__parse_backend_path(libxl__gc *gc, const char *path,
                                      libxl__device *dev);
_hidden int libxl__device_destroy(libxl__gc *gc, libxl__device *dev);
_hidden int libxl__wait_for_backend(libxl__gc *gc, const char *be_path,
                                    const char *state);
_hidden int libxl__nic_type(libxl__gc *gc, libxl__device *dev,
                            libxl_nic_type *nictype);

/*
 * For each aggregate type which can be used as an input we provide:
 *
 * int libxl__<type>_setdefault(gc, <type> *p):
 *
 *     Idempotently sets any members of "p" which is currently set to
 *     a special value indicating that the defaults should be used
 *     (per libxl_<type>_init) to a specific value.
 *
 *     All libxl API functions are expected to have arranged for this
 *     to be called before using any values within these structures.
 */
_hidden int libxl__domain_create_info_setdefault(libxl__gc *gc,
                                        libxl_domain_create_info *c_info);
_hidden int libxl__domain_build_info_setdefault(libxl__gc *gc,
                                        libxl_domain_build_info *b_info);
_hidden int libxl__device_disk_setdefault(libxl__gc *gc,
                                          libxl_device_disk *disk);
_hidden int libxl__device_nic_setdefault(libxl__gc *gc, libxl_device_nic *nic,
                                         uint32_t domid);
_hidden int libxl__device_vtpm_setdefault(libxl__gc *gc, libxl_device_vtpm *vtpm);
_hidden int libxl__device_vfb_setdefault(libxl__gc *gc, libxl_device_vfb *vfb);
_hidden int libxl__device_vkb_setdefault(libxl__gc *gc, libxl_device_vkb *vkb);
_hidden int libxl__device_pci_setdefault(libxl__gc *gc, libxl_device_pci *pci);

_hidden const char *libxl__device_nic_devname(libxl__gc *gc,
                                              uint32_t domid,
                                              uint32_t devid,
                                              libxl_nic_type type);

_hidden int libxl__get_domid(libxl__gc *gc, uint32_t *domid);

/*
 * libxl__ev_devstate - waits a given time for a device to
 * reach a given state.  Follows the libxl_ev_* conventions.
 * Will generate only one event, and after that is automatically
 * cancelled.
 */
typedef struct libxl__ev_devstate libxl__ev_devstate;
typedef void libxl__ev_devstate_callback(libxl__egc *egc, libxl__ev_devstate*,
                                         int rc);
  /* rc will be 0, ERROR_TIMEDOUT, ERROR_INVAL (meaning path was removed),
   * or ERROR_FAIL if other stuff went wrong (in which latter case, logged) */

struct libxl__ev_devstate {
    /* read-only for caller, who may read only when waiting: */
    int wanted;
    libxl__ev_devstate_callback *callback;
    /* as for the remainder, read-only public parts may also be
     * read by the caller (notably, watch.path), but only when waiting: */
    libxl__ev_xswatch watch;
    libxl__ev_time timeout;
};

static inline void libxl__ev_devstate_init(libxl__ev_devstate *ds)
{
    libxl__ev_time_init(&ds->timeout);
    libxl__ev_xswatch_init(&ds->watch);
}

static inline void libxl__ev_devstate_cancel(libxl__gc *gc,
                                             libxl__ev_devstate *ds)
{
    libxl__ev_time_deregister(gc,&ds->timeout);
    libxl__ev_xswatch_deregister(gc,&ds->watch);
}

_hidden int libxl__ev_devstate_wait(libxl__gc *gc, libxl__ev_devstate *ds,
                                    libxl__ev_devstate_callback cb,
                                    const char *state_path,
                                    int state, int milliseconds);

/*
 * libxl__ev_domaindeathcheck_register - arranges to call back (once)
 * if the domain is destroyed.  If the domain dies, we log a message
 * of the form "<what>: <explanation of the situation, including the domid>".
 */

typedef struct libxl__domaindeathcheck libxl__domaindeathcheck;
typedef void libxl___domaindeathcheck_callback(libxl__egc *egc,
                                         libxl__domaindeathcheck*);

struct libxl__domaindeathcheck {
    /* must be filled in by caller, and remain valid: */
    const char *what;
    uint32_t domid;
    libxl___domaindeathcheck_callback *callback;
    /* private */
    libxl__ev_xswatch watch;
};

_hidden int libxl__domaindeathcheck_start(libxl__gc *gc,
                                          libxl__domaindeathcheck *dc);

static inline void libxl__domaindeathcheck_init
 (libxl__domaindeathcheck *dc) { libxl__ev_xswatch_init(&dc->watch); }
static inline void libxl__domaindeathcheck_stop(libxl__gc *gc,
  libxl__domaindeathcheck *dc) { libxl__ev_xswatch_deregister(gc,&dc->watch); }


/*
 * libxl__try_phy_backend - Check if there's support for the passed
 * type of file using the PHY backend
 * st_mode: mode_t of the file, as returned by stat function
 *
 * Returns 1 on success, and 0 if not suitable for phy backend.
 */
_hidden int libxl__try_phy_backend(mode_t st_mode);


_hidden char *libxl__devid_to_localdev(libxl__gc *gc, int devid);

/* from libxl_pci */

_hidden int libxl__device_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting);
_hidden int libxl__create_pci_backend(libxl__gc *gc, uint32_t domid,
                                      libxl_device_pci *pcidev, int num);
_hidden int libxl__device_pci_destroy_all(libxl__gc *gc, uint32_t domid);

/*----- xswait: wait for a xenstore node to be suitable -----*/

typedef struct libxl__xswait_state libxl__xswait_state;

/*
 * rc describes the circumstances of this callback:
 *
 * rc==0
 *
 *     The xenstore path (may have) changed.  It has been read for
 *     you.  The result is in data (allocated from the ao gc).
 *     data may be NULL, which means that the xenstore read gave
 *     ENOENT.
 *
 *     If you are satisfied, you MUST call libxl__xswait_stop.
 *     Otherwise, xswait will continue waiting and watching and
 *     will call you back later.
 *
 * rc==ERROR_TIMEDOUT
 *
 *     The specified timeout was reached.
 *     This has NOT been logged (except to the debug log).
 *     xswait will not continue (but calling libxl__xswait_stop is OK).
 *
 * rc!=0, !=ERROR_TIMEDOUT
 *
 *     Some other error occurred.
 *     This HAS been logged.
 *     xswait will not continue (but calling libxl__xswait_stop is OK).
 *
 * xswait.path may start with with '@', in which case no read is done
 * and the callback will always get data==0.
 */
typedef void libxl__xswait_callback(libxl__egc *egc,
      libxl__xswait_state *xswa, int rc, const char *data);

struct libxl__xswait_state {
    /* caller must fill these in, and they must all remain valid */
    libxl__ao *ao;
    const char *what; /* for error msgs: noun phrase, what we're waiting for */
    const char *path;
    int timeout_ms; /* as for poll(2) */
    libxl__xswait_callback *callback;
    /* remaining fields are private to xswait */
    libxl__ev_time time_ev;
    libxl__ev_xswatch watch_ev;
};

void libxl__xswait_init(libxl__xswait_state*);
void libxl__xswait_stop(libxl__gc*, libxl__xswait_state*); /*idempotent*/
bool libxl__xswait_inuse(const libxl__xswait_state *ss);

int libxl__xswait_start(libxl__gc*, libxl__xswait_state*);

/*
 *----- spawn -----
 *
 * Higher-level double-fork and separate detach eg as for device models
 *
 * Each libxl__spawn_state is in one of these states
 *    Undefined, Idle, Attached, Detaching
 */

typedef struct libxl__obsolete_spawn_starting libxl__spawn_starting;
/* this type is never defined, so no objects of this type exist
 * fixme-ao  This should go away completely.  */

typedef struct libxl__spawn_state libxl__spawn_state;

/* Clears out a spawn state; idempotent. */
_hidden void libxl__spawn_init(libxl__spawn_state*);

/*
 * libxl__spawn_spawn - Create a new process which will become daemonic
 * Forks twice, to allow the child to detach entirely from the parent.
 *
 * We call the two generated processes the "middle child" (result of
 * the first fork) and the "inner child" (result of the second fork
 * which takes place in the middle child).
 *
 * The inner child must soon exit or exec.  It must also soon exit or
 * notify the parent of its successful startup by writing to the
 * xenstore path xspath.
 *
 * The user (in the parent) will be called back (confirm_cb) every
 * time that xenstore path is modified.
 *
 * In both children, the ctx is not fully usable: gc and logging
 * operations are OK, but operations on Xen and xenstore are not.
 * (The restrictions are the same as those which apply to children
 * made with libxl__ev_child_fork.)
 *
 * midproc_cb will be called in the middle child, with the pid of the
 * inner child; this could for example record the pid.  midproc_cb
 * should be fast, and should return.  It will be called (reentrantly)
 * within libxl__spawn_init.
 *
 * failure_cb will be called in the parent on failure of the
 * intermediate or final child; an error message will have been
 * logged.
 *
 * confirm_cb, failure_cb and detached_cb will not be called
 * reentrantly from within libxl__spawn_spawn.
 *
 * what: string describing the spawned process, used for logging
 *
 * Logs errors.  A copy of "what" is taken. 
 * Return values:
 *  < 0   error, *spawn is now Idle and need not be detached
 *   +1   caller is the parent, *spawn is Attached and must be detached
 *    0   caller is now the inner child, should probably call libxl__exec
 *
 * The spawn state must be Undefined or Idle on entry.
 */
_hidden int libxl__spawn_spawn(libxl__egc *egc, libxl__spawn_state *spawn);

/*
 * libxl__spawn_request_detach - Detaches the daemonic child.
 *
 * Works by killing the intermediate process from spawn_spawn.
 * After this function returns, failures of either child are no
 * longer reported via failure_cb.
 *
 * This is not synchronous: there will be a further callback when
 * the detach is complete.
 *
 * If called before the inner child has been created, this may prevent
 * it from running at all.  Thus this should be called only when the
 * inner child has notified that it is ready.  Normally it will be
 * called from within confirm_cb.
 *
 * Logs errors.
 *
 * The spawn state must be Attached entry and will be Detaching
 * on return.
 */
_hidden void libxl__spawn_initiate_detach(libxl__gc *gc, libxl__spawn_state*);

/*
 * If successful, this should return 0.
 *
 * Otherwise it should return a signal number, which will be
 * sent to the inner child; the overall spawn will then fail.
 */
typedef int /* signal number */
libxl__spawn_midproc_cb(libxl__gc*, libxl__spawn_state*, pid_t inner);

/*
 * Called if the spawn failed.  The reason will have been logged.
 * The spawn state will be Idle on entry to the callback (and
 * it may be reused immediately if desired).
 */
typedef void libxl__spawn_failure_cb(libxl__egc*, libxl__spawn_state*);

/*
 * Called when the xspath watch triggers.  xspath will have been read
 * and the result placed in xsdata; if that failed because the key
 * didn't exist, xspath==0.  (If it failed for some other reason,
 * the spawn machinery calls failure_cb instead.)
 *
 * If the child has indicated its successful startup, or a failure
 * has occurred, this should call libxl__spawn_detach.
 *
 * If the child is still starting up, should simply return, doing
 * nothing.
 *
 * The spawn state will be Active on entry to the callback; there
 * are no restrictions on the state on return; it may even have
 * been detached and reused.
 */
typedef void libxl__spawn_confirm_cb(libxl__egc*, libxl__spawn_state*,
                                     const char *xsdata);

/*
 * Called when the detach (requested by libxl__spawn_initiate_detach) has
 * completed.  On entry to the callback the spawn state is Idle.
 */
typedef void libxl__spawn_detached_cb(libxl__egc*, libxl__spawn_state*);

struct libxl__spawn_state {
    /* must be filled in by user and remain valid */
    libxl__ao *ao;
    const char *what;
    const char *xspath;
    const char *pidpath; /* only used by libxl__spawn_midproc_record_pid */
    int timeout_ms; /* -1 means forever */
    libxl__spawn_midproc_cb *midproc_cb;
    libxl__spawn_failure_cb *failure_cb;
    libxl__spawn_confirm_cb *confirm_cb;
    libxl__spawn_detached_cb *detached_cb;

    /* remaining fields are private to libxl_spawn_... */
    int detaching; /* we are in Detaching */
    int failed; /* might be true whenever we are not Idle */
    libxl__ev_child mid; /* always in use whenever we are not Idle */
    libxl__xswait_state xswait;
};

static inline int libxl__spawn_inuse(const libxl__spawn_state *ss)
    { return libxl__ev_child_inuse(&ss->mid); }

/*
 * libxl_spawner_record_pid - Record given pid in xenstore
 *
 * This function can be passed directly as an intermediate_hook to
 * libxl__spawn_spawn.  On failure, returns the value SIGTERM.
 */
_hidden int libxl__spawn_record_pid(libxl__gc*, libxl__spawn_state*,
                                    pid_t innerchild);

/*
 * libxl__xenstore_child_wait_deprecated - Wait for daemonic child IPC
 *
 * This is a NOT function for waiting for ordinary child processes.
 * If you want to run (fork/exec/wait) subprocesses from libxl:
 *  - Make your libxl entrypoint use the ao machinery
 *  - Use libxl__ev_fork, and use the callback programming style
 *
 * This function is intended for interprocess communication with a
 * service process.  If the service process does not respond quickly,
 * the whole caller may be blocked.  Therefore this function is
 * deprecated.  This function is currently used only by
 * libxl__wait_for_device_model_deprecated.
 *
 * gc: allocation pool
 * domid: guest to work with
 * timeout: how many seconds to wait for the state to appear
 * what: string describing the spawned process
 * path: path to the state file in xenstore
 * state: expected string to wait for in path (optional)
 * spawning: malloc'd pointer to libxl__spawn_starting (optional)
 * check_callback: (optional)
 * check_callback_userdata: data to pass to the callback function
 *
 * Returns 0 on success, and < 0 on error.
 *
 * This function waits the given timeout for the given path to appear
 * in xenstore, and optionally for state in path.
 * If path appears and state matches, check_callback is called.
 * If check_callback returns > 0, waiting for path or state continues.
 * Otherwise libxl__xenstore_child_wait_deprecated returns.
 */
_hidden int libxl__xenstore_child_wait_deprecated(libxl__gc *gc,
                                 uint32_t domid,
                                 uint32_t timeout, char *what,
                                 char *path, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata);


 /* low-level stuff, for synchronous subprocesses etc. */

/*
 * env should be passed using the following format,
 *
 * env[0]: name of env variable
 * env[1]: value of env variable
 * env[n]: ...
 *
 * So it efectively becomes something like:
 * export env[n]=env[n+1]
 * (where n%2 = 0)
 *
 * The last entry of the array always has to be NULL.
 *
 * stdinfd, stdoutfd, stderrfd will be dup2'd onto the corresponding
 * fd in the child, if they are not -1.  The original copy of the
 * descriptor will be closed in the child (unless it's 0, 1 or 2
 * ie the source descriptor is itself stdin, stdout or stderr).
 *
 * Logs errors, never returns.
 */
_hidden  void libxl__exec(libxl__gc *gc, int stdinfd, int stdoutfd,
                          int stderrfd, const char *arg0, char *const args[],
                          char *const env[]);

/* from xl_create */

 /* on entry, libxl_domid_valid_guest(domid) must be false;
  * on exit (even error exit), domid may be valid and refer to a domain */
_hidden int libxl__domain_make(libxl__gc *gc,
                               libxl_domain_create_info *info,
                               uint32_t *domid);

_hidden int libxl__domain_build(libxl__gc *gc,
                                libxl_domain_config *d_config,
                                uint32_t domid,
                                libxl__domain_build_state *state);

/* for device model creation */
_hidden const char *libxl__domain_device_model(libxl__gc *gc,
                                        const libxl_domain_build_info *info);
_hidden int libxl__need_xenpv_qemu(libxl__gc *gc,
        int nr_consoles, libxl__device_console *consoles,
        int nr_vfbs, libxl_device_vfb *vfbs,
        int nr_disks, libxl_device_disk *disks);

/*
 * This function will cause the whole libxl process to hang
 * if the device model does not respond.  It is deprecated.
 *
 * Instead of calling this function:
 *  - Make your libxl entrypoint use the ao machinery
 *  - Use libxl__ev_xswatch_register, and use the callback programming
 *    style
 */
_hidden int libxl__wait_for_device_model_deprecated(libxl__gc *gc,
                                uint32_t domid, char *state,
                                libxl__spawn_starting *spawning
                                                    /* NULL allowed */,
                                int (*check_callback)(libxl__gc *gc,
                                                      uint32_t domid,
                                                      const char *state,
                                                      void *userdata),
                                void *check_callback_userdata);

_hidden int libxl__destroy_device_model(libxl__gc *gc, uint32_t domid);

_hidden const libxl_vnc_info *libxl__dm_vnc(const libxl_domain_config *g_cfg);

_hidden char *libxl__abs_path(libxl__gc *gc, const char *s, const char *path);

#define LIBXL__LOG_DEBUG   XTL_DEBUG
#define LIBXL__LOG_INFO    XTL_INFO
#define LIBXL__LOG_WARNING XTL_WARN
#define LIBXL__LOG_ERROR   XTL_ERROR

_hidden char *libxl__domid_to_name(libxl__gc *gc, uint32_t domid);
_hidden char *libxl__cpupoolid_to_name(libxl__gc *gc, uint32_t poolid);

_hidden int libxl__enum_from_string(const libxl_enum_string_table *t,
                                    const char *s, int *e);

_hidden yajl_gen_status libxl__yajl_gen_asciiz(yajl_gen hand, const char *str);

_hidden yajl_gen_status libxl__string_gen_json(yajl_gen hand, const char *p);

typedef yajl_gen_status (*libxl__gen_json_callback)(yajl_gen hand, void *);
_hidden char *libxl__object_to_json(libxl_ctx *ctx, const char *type,
                                    libxl__gen_json_callback gen, void *p);

  /* holds the CPUID response for a single CPUID leaf
   * input contains the value of the EAX and ECX register,
   * and each policy string contains a filter to apply to
   * the host given values for that particular leaf.
   */
struct libxl__cpuid_policy {
    uint32_t input[2];
    char *policy[4];
};

/*
 * blktap2 support
 */

/* libxl__blktap_enabled:
 *    return true if blktap/blktap2 support is available.
 */
_hidden int libxl__blktap_enabled(libxl__gc *gc);

/* libxl__blktap_devpath:
 *    Argument: path and disk image as specified in config file.
 *      The type specifies whether this is aio, qcow, qcow2, etc.
 *    returns device path xenstore wants to have. returns NULL
 *      if no device corresponds to the disk.
 */
_hidden char *libxl__blktap_devpath(libxl__gc *gc,
                                    const char *disk,
                                    libxl_disk_format format);

/* libxl__device_destroy_tapdisk:
 *   Destroys any tapdisk process associated with the backend represented
 *   by be_path.
 *   Always logs on failure.
 */
_hidden int libxl__device_destroy_tapdisk(libxl__gc *gc, const char *params);

_hidden int libxl__device_from_disk(libxl__gc *gc, uint32_t domid,
                                   libxl_device_disk *disk,
                                   libxl__device *device);

_hidden char *libxl__uuid2string(libxl__gc *gc, const libxl_uuid uuid);

struct libxl__xen_console_reader {
    char *buffer;
    unsigned int size;
    unsigned int count;
    unsigned int clear;
    unsigned int incremental;
    unsigned int index;
};

/* parse the string @s as a sequence of 6 colon separated bytes in to @mac */
_hidden int libxl__parse_mac(const char *s, libxl_mac mac);
/* compare mac address @a and @b. 0 if the same, -ve if a<b and +ve if a>b */
_hidden int libxl__compare_macs(libxl_mac *a, libxl_mac *b);
/* init a recursive mutex */
_hidden int libxl__init_recursive_mutex(libxl_ctx *ctx, pthread_mutex_t *lock);

_hidden int libxl__gettimeofday(libxl__gc *gc, struct timeval *now_r);

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

/* from libxl_qmp */
typedef struct libxl__qmp_handler libxl__qmp_handler;

/* Initialise and connect to the QMP socket.
 *   Return an handler or NULL if there is an error
 */
_hidden libxl__qmp_handler *libxl__qmp_initialize(libxl__gc *gc,
                                                  uint32_t domid);
/* ask to QEMU the serial port information and store it in xenstore. */
_hidden int libxl__qmp_query_serial(libxl__qmp_handler *qmp);
_hidden int libxl__qmp_pci_add(libxl__gc *gc, int d, libxl_device_pci *pcidev);
_hidden int libxl__qmp_pci_del(libxl__gc *gc, int domid,
                               libxl_device_pci *pcidev);
/* Resume hvm domain */
_hidden int libxl__qmp_system_wakeup(libxl__gc *gc, int domid);
/* Suspend QEMU. */
_hidden int libxl__qmp_stop(libxl__gc *gc, int domid);
/* Resume QEMU. */
_hidden int libxl__qmp_resume(libxl__gc *gc, int domid);
/* Save current QEMU state into fd. */
_hidden int libxl__qmp_save(libxl__gc *gc, int domid, const char *filename);
/* Set dirty bitmap logging status */
_hidden int libxl__qmp_set_global_dirty_log(libxl__gc *gc, int domid, bool enable);
_hidden int libxl__qmp_insert_cdrom(libxl__gc *gc, int domid, const libxl_device_disk *disk);
/* Add a virtual CPU */
_hidden int libxl__qmp_cpu_add(libxl__gc *gc, int domid, int index);
/* close and free the QMP handler */
_hidden void libxl__qmp_close(libxl__qmp_handler *qmp);
/* remove the socket file, if the file has already been removed,
 * nothing happen */
_hidden void libxl__qmp_cleanup(libxl__gc *gc, uint32_t domid);

/* this helper calls qmp_initialize, query_serial and qmp_close */
_hidden int libxl__qmp_initializations(libxl__gc *gc, uint32_t domid,
                                       const libxl_domain_config *guest_config);

/* on failure, logs */
int libxl__sendmsg_fds(libxl__gc *gc, int carrier,
                       const void *data, size_t datalen,
                       int nfds, const int fds[], const char *what);

/* Insists on receiving exactly nfds and datalen.  On failure, logs
 * and leaves *fds untouched. */
int libxl__recvmsg_fds(libxl__gc *gc, int carrier,
                       void *databuf, size_t datalen,
                       int nfds, int fds[], const char *what);

/* from libxl_json */
#include <yajl/yajl_gen.h>

_hidden yajl_gen_status libxl__yajl_gen_asciiz(yajl_gen hand, const char *str);
_hidden yajl_gen_status libxl__yajl_gen_enum(yajl_gen hand, const char *str);

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_INTEGER,
    JSON_DOUBLE,
    /* number is store in string, it's too big to be a long long or a double */
    JSON_NUMBER,
    JSON_STRING,
    JSON_MAP,
    JSON_ARRAY,
    JSON_ANY
} libxl__json_node_type;

typedef struct libxl__json_object {
    libxl__json_node_type type;
    union {
        bool b;
        long long i;
        double d;
        char *string;
        /* List of libxl__json_object */
        flexarray_t *array;
        /* List of libxl__json_map_node */
        flexarray_t *map;
    } u;
    struct libxl__json_object *parent;
} libxl__json_object;

typedef struct {
    char *map_key;
    libxl__json_object *obj;
} libxl__json_map_node;

typedef struct libxl__yajl_ctx libxl__yajl_ctx;

static inline bool libxl__json_object_is_bool(const libxl__json_object *o)
{
    return o != NULL && o->type == JSON_BOOL;
}
static inline bool libxl__json_object_is_string(const libxl__json_object *o)
{
    return o != NULL && o->type == JSON_STRING;
}
static inline bool libxl__json_object_is_integer(const libxl__json_object *o)
{
    return o != NULL && o->type == JSON_INTEGER;
}
static inline bool libxl__json_object_is_map(const libxl__json_object *o)
{
    return o != NULL && o->type == JSON_MAP;
}
static inline bool libxl__json_object_is_array(const libxl__json_object *o)
{
    return o != NULL && o->type == JSON_ARRAY;
}

static inline bool libxl__json_object_get_bool(const libxl__json_object *o)
{
    if (libxl__json_object_is_bool(o))
        return o->u.b;
    else
        return false;
}
static inline
const char *libxl__json_object_get_string(const libxl__json_object *o)
{
    if (libxl__json_object_is_string(o))
        return o->u.string;
    else
        return NULL;
}
static inline
flexarray_t *libxl__json_object_get_map(const libxl__json_object *o)
{
    if (libxl__json_object_is_map(o))
        return o->u.map;
    else
        return NULL;
}
static inline
flexarray_t *libxl__json_object_get_array(const libxl__json_object *o)
{
    if (libxl__json_object_is_array(o))
        return o->u.array;
    else
        return NULL;
}
static inline long long libxl__json_object_get_integer(const libxl__json_object *o)
{
    if (libxl__json_object_is_integer(o))
        return o->u.i;
    else
        return -1;
}

/*
 * NOGC can be used with those json_object functions, but the
 * libxl__json_object* will need to be freed with libxl__json_object_free.
 */
_hidden libxl__json_object *libxl__json_object_alloc(libxl__gc *gc_opt,
                                                     libxl__json_node_type type);
_hidden int libxl__json_object_append_to(libxl__gc *gc_opt,
                                         libxl__json_object *obj,
                                         libxl__json_object *dst);
_hidden libxl__json_object *libxl__json_array_get(const libxl__json_object *o,
                                                  int i);
_hidden
libxl__json_map_node *libxl__json_map_node_get(const libxl__json_object *o,
                                               int i);
_hidden const libxl__json_object *libxl__json_map_get(const char *key,
                                          const libxl__json_object *o,
                                          libxl__json_node_type expected_type);
_hidden yajl_status libxl__json_object_to_yajl_gen(libxl__gc *gc_opt,
                                                   yajl_gen hand,
                                                   libxl__json_object *param);
_hidden void libxl__json_object_free(libxl__gc *gc_opt,
                                     libxl__json_object *obj);

_hidden libxl__json_object *libxl__json_parse(libxl__gc *gc_opt, const char *s);

  /* Based on /local/domain/$domid/dm-version xenstore key
   * default is qemu xen traditional */
_hidden int libxl__device_model_version_running(libxl__gc *gc, uint32_t domid);
  /* Return the system-wide default device model */
_hidden libxl_device_model_version libxl__default_device_model(libxl__gc *gc);

/* Check how executes hotplug script currently */
int libxl__hotplug_settings(libxl__gc *gc, xs_transaction_t t);

/*
 * Calling context and GC for event-generating functions:
 *
 * These are for use by parts of libxl which directly or indirectly
 * call libxl__event_occurred.  These contain a gc but also a list of
 * deferred events.
 *
 * You should never need to initialise an egc unless you are part of
 * the event machinery itself.  Otherwise you will always be given an
 * egc if you need one.  Even functions which generate specific kinds
 * of events don't need to - rather, they will be passed an egc into
 * their own callback function and should just use the one they're
 * given.
 *
 * Functions using LIBXL__INIT_EGC may *not* generally be called from
 * within libxl, because libxl__egc_cleanup may call back into the
 * application.  This should be enforced by declaring all such
 * functions in libxl.h or libxl_event.h with
 * LIBXL_EXTERNAL_CALLERS_ONLY.  You should in any case not find it
 * necessary to call egc-creators from within libxl.
 *
 * The callbacks must all take place with the ctx unlocked because
 * the application is entitled to reenter libxl from them.  This
 * would be bad not because the lock is not recursive (it is) but
 * because the application might make blocking libxl calls which
 * would hold the lock unreasonably long.
 *
 * For the same reason libxl__egc_cleanup (or EGC_FREE) must be called
 * with the ctx *unlocked*.  So the right pattern has the EGC_...
 * macro calls on the outside of the CTX_... ones.
 */

/* useful for all functions which take an egc: */

#define EGC_GC                                  \
    libxl__gc *const gc __attribute__((unused)) = &egc->gc

/* egc initialisation and destruction: */

#define LIBXL_INIT_EGC(egc,ctx) do{                     \
        LIBXL_INIT_GC((egc).gc,ctx);                    \
        LIBXL_TAILQ_INIT(&(egc).occurred_for_callback); \
        LIBXL_TAILQ_INIT(&(egc).aos_for_callback);      \
        LIBXL_TAILQ_INIT(&(egc).aops_for_callback);     \
    } while(0)

_hidden void libxl__egc_cleanup(libxl__egc *egc);
  /* Frees memory allocated within this egc's gc, and and report all
   * occurred events via callback, if applicable.  May reenter the
   * application; see restrictions above.  The ctx must be UNLOCKED. */

/* convenience macros: */

#define EGC_INIT(ctx)                       \
    libxl__egc egc[1]; LIBXL_INIT_EGC(egc[0],ctx);      \
    EGC_GC

#define EGC_FREE           libxl__egc_cleanup(egc)


/*
 * Machinery for asynchronous operations ("ao")
 *
 * All "slow" functions (see below for the exact definition) need to
 * use the asynchronous operation ("ao") machinery.  The function
 * should take a parameter const libxl_asyncop_how *ao_how and must
 * start with a call to AO_INITIATOR_ENTRY.  These functions MAY NOT
 * be called from inside libxl, because they can cause reentrancy
 * callbacks.
 *
 * For the same reason functions taking an ao_how may make themselves
 * an egc with EGC_INIT (and they will generally want to, to be able
 * to immediately complete an ao during its setup).
 *
 *
 * "Slow" functions includes any that might block on a guest or an
 * external script.  More broadly, it includes any operations which
 * are sufficiently slow that an application might reasonably want to
 * initiate them, and then carry on doing something else, while the
 * operation completes.  That is, a "fast" function must be fast
 * enough that we do not mind blocking all other management operations
 * on the same host while it completes.
 *
 * There are certain primitive functions which make a libxl operation
 * necessarily "slow" for API reasons.  These are:
 *  - awaiting xenstore watches (although read-modify-write xenstore
 *    transactions are OK for fast functions)
 *  - spawning subprocesses
 *  - anything with a timeout
 *
 *
 * Lifecycle of an ao:
 *
 * - Created by libxl__ao_create (or the AO_CREATE convenience macro).
 *
 * - After creation, can be used by code which implements
 *   the operation as follows:
 *      - the ao's gc, for allocating memory for the lifetime
 *        of the operation (possibly with the help of the AO_GC
 *        macro to introduce the gc into scope)
 *      - the ao itself may be passed about to sub-functions
 *        so that they can stash it away etc.
 *      - in particular, the ao pointer must be stashed in some
 *        per-operation structure which is also passed as a user
 *        pointer to the internal event generation request routines
 *        libxl__evgen_FOO, so that at some point a CALLBACK will be
 *        made when the operation is complete.
 *      - if the operation provides progress reports, the aop_how(s)
 *        must be copied into the per-operation structure using
 *        libxl__ao_progress_gethow.
 *
 * - If initiation is successful, the initiating function needs
 *   to run libxl__ao_inprogress right before unlocking and
 *   returning, and return whatever it returns (AO_INPROGRESS macro).
 *
 * - If the initiation is unsuccessful, the initiating function must
 *   call libxl__ao_abort before unlocking and returning whatever
 *   error code is appropriate (AO_ABORT macro).
 *
 * - If the operation supports progress reports, it may generate
 *   suitable events with NEW_EVENT and report them with
 *   libxl__ao_progress_report (with the ctx locked).
 *
 * - Later, some callback function, whose callback has been requested
 *   directly or indirectly, should call libxl__ao_complete (with the
 *   ctx locked, as it will generally already be in any event callback
 *   function).  This must happen exactly once for each ao (and not if
 *   the ao has been destroyed, obviously).
 *
 * - Note that during callback functions, two gcs are available:
 *    - The one in egc, whose lifetime is only this callback
 *    - The one in ao, whose lifetime is the asynchronous operation
 *   Usually callback function should use CONTAINER_OF to obtain its
 *   own state structure, containing a pointer to the ao.  It should
 *   then obtain the ao and use the ao's gc; this is most easily done
 *   using the convenience macro STATE_AO_GC.
 */

#define AO_CREATE(ctx, domid, ao_how)                           \
    libxl__ctx_lock(ctx);                                       \
    libxl__ao *ao = libxl__ao_create(ctx, domid, ao_how,        \
                               __FILE__, __LINE__, __func__);   \
    if (!ao) { libxl__ctx_unlock(ctx); return ERROR_NOMEM; }    \
    libxl__egc egc[1]; LIBXL_INIT_EGC(egc[0],ctx);              \
    AO_GC;

#define AO_INPROGRESS ({                                        \
        libxl_ctx *ao__ctx = libxl__gc_owner(&ao->gc);          \
        CTX_UNLOCK;                                             \
        EGC_FREE;                                               \
        CTX_LOCK;                                               \
        int ao__rc = libxl__ao_inprogress(ao,                   \
                               __FILE__, __LINE__, __func__);   \
        libxl__ctx_unlock(ao__ctx); /* gc is now invalid */     \
        (ao__rc);                                               \
   })

#define AO_ABORT(rc) ({                                         \
        libxl_ctx *ao__ctx = libxl__gc_owner(&ao->gc);          \
        assert(rc);                                             \
        libxl__ao_abort(ao);                                    \
        libxl__ctx_unlock(ao__ctx); /* gc is now invalid */     \
        EGC_FREE;                                               \
        (rc);                                                   \
    })

#define AO_GC                                   \
    libxl__gc *const gc __attribute__((unused)) = &ao->gc

#define STATE_AO_GC(op_ao)                      \
    libxl__ao *const ao = (op_ao);              \
    libxl__gc *const gc __attribute__((unused)) = libxl__ao_inprogress_gc(ao)


/* All of these MUST be called with the ctx locked.
 * libxl__ao_inprogress MUST be called with the ctx locked exactly once. */
_hidden libxl__ao *libxl__ao_create(libxl_ctx*, uint32_t domid,
                                    const libxl_asyncop_how*,
       const char *file, int line, const char *func);
_hidden int libxl__ao_inprogress(libxl__ao *ao,
       const char *file, int line, const char *func); /* temporarily unlocks */
_hidden void libxl__ao_abort(libxl__ao *ao);
_hidden void libxl__ao_complete(libxl__egc *egc, libxl__ao *ao, int rc);
_hidden libxl__gc *libxl__ao_inprogress_gc(libxl__ao *ao);

/* Can be called at any time.  Use is essential for any aop user. */
_hidden void libxl__ao_progress_gethow(libxl_asyncprogress_how *in_state,
                                       const libxl_asyncprogress_how *from_app);

/* Must be called with the ctx locked.  Will fill in ev->for_user,
 * so caller need not do that. */
_hidden void libxl__ao_progress_report(libxl__egc *egc, libxl__ao *ao,
   const libxl_asyncprogress_how *how, libxl_event *ev /* consumed */);

/* For use by ao machinery ONLY */
_hidden void libxl__ao__destroy(libxl_ctx*, libxl__ao *ao);
_hidden void libxl__ao_complete_check_progress_reports(libxl__egc*, libxl__ao*);


/*
 * Short-lived sub-ao, aka "nested ao".
 *
 * Some asynchronous operations are very long-running.  Generally,
 * since an ao has a gc, any allocations made in that ao will live
 * until the ao is completed.  When this is not desirable, these
 * functions may be used to manage a "sub-ao".
 *
 * The returned sub-ao is suitable for passing to gc-related functions
 * and macros such as libxl__ao_inprogress_gc, AO_GC, and STATE_AO_GC.
 *
 * It MUST NOT be used with AO_INPROGRESS, AO_ABORT,
 * libxl__ao_complete, libxl__ao_progress_report, and so on.
 *
 * The caller must ensure that all of the sub-ao's are freed before
 * the parent is.  Multiple levels of nesting are OK (although
 * hopefully they won't be necessary).
 */

_hidden libxl__ao *libxl__nested_ao_create(libxl__ao *parent); /* cannot fail */
_hidden void libxl__nested_ao_free(libxl__ao *child);


/*
 * File descriptors and CLOEXEC
 */

/*
 * For libxl functions which create file descriptors, at least one
 * of the following must be true:
 *  (a) libxl does not care if copies of this open-file are inherited
 *      by random children and might remain open indefinitely
 *  (b) libxl must take extra care for the fd (the actual descriptor,
 *      not the open-file) as below.  We call this a "carefd".
 *
 * The rules for opening a carefd are:
 *  (i)   Before bringing any carefds into existence,
 *        libxl code must call libxl__carefd_begin.
 *  (ii)  Then for each carefd brought into existence,
 *        libxl code must call libxl__carefd_record
 *        and remember the libxl__carefd_record*.
 *  (iii) Then it must call libxl__carefd_unlock.
 *  (iv)  When in a child process the fd is to be passed across
 *        exec by libxl, the libxl code must unset FD_CLOEXEC
 *        on the fd eg by using libxl_fd_set_cloexec.
 *  (v)   Later, when the fd is to be closed in the same process,
 *        libxl code must not call close.  Instead, it must call
 *        libxl__carefd_close.
 * Steps (ii) and (iii) can be combined by calling the convenience
 * function libxl__carefd_opened.
 */
/* libxl__carefd_begin and _unlock (or _opened) must be called always
 * in pairs.  They may be called with the CTX lock held.  In between
 * _begin and _unlock, the following are prohibited:
 *   - anything which might block
 *   - any callbacks to the application
 *   - nested calls to libxl__carefd_begin
 *   - fork (libxl__fork)
 * In general nothing should be done before _unlock that could be done
 * afterwards.
 */
typedef struct libxl__carefd libxl__carefd;

_hidden void libxl__carefd_begin(void);
_hidden void libxl__carefd_unlock(void);

/* fd may be -1, in which case this returns a dummy libxl__fd_record
 * on which it _carefd_close is a no-op.  Cannot fail. */
_hidden libxl__carefd *libxl__carefd_record(libxl_ctx *ctx, int fd);

/* Combines _record and _unlock in a single call.  If fd==-1,
 * still does the unlock, but returns 0.  Cannot fail. */
_hidden libxl__carefd *libxl__carefd_opened(libxl_ctx *ctx, int fd);

/* Works just like close(2).  You may pass NULL, in which case it's
 * a successful no-op. */
_hidden int libxl__carefd_close(libxl__carefd*);

/* You may pass NULL in which case the answer is -1. */
_hidden int libxl__carefd_fd(const libxl__carefd*);

/* common paths */
_hidden const char *libxl__libexec_path(void);
_hidden const char *libxl__private_bindir_path(void);
_hidden const char *libxl__xenfirmwaredir_path(void);
_hidden const char *libxl__xen_config_dir_path(void);
_hidden const char *libxl__xen_script_dir_path(void);
_hidden const char *libxl__lock_dir_path(void);
_hidden const char *libxl__run_dir_path(void);

/*----- device addition/removal -----*/

typedef struct libxl__ao_device libxl__ao_device;
typedef struct libxl__multidev libxl__multidev;
typedef void libxl__device_callback(libxl__egc*, libxl__ao_device*);

/* This functions sets the necessary libxl__ao_device struct values to use
 * safely inside functions. It marks the operation as "active"
 * since we need to be sure that all device status structs are set
 * to active before start queueing events, or we might call
 * ao_complete before all devices had finished
 *
 * libxl__initiate_device_{remove/addition} should not be called without
 * calling libxl__prepare_ao_device first, since it initializes the private
 * fields of the struct libxl__ao_device to what this functions expect.
 *
 * Once _prepare has been called on a libxl__ao_device, it is safe to just
 * discard this struct, there's no need to call any destroy function.
 * _prepare can also be called multiple times with the same libxl__ao_device.
 */
_hidden void libxl__prepare_ao_device(libxl__ao *ao, libxl__ao_device *aodev);

struct libxl__ao_device {
    /* filled in by user */
    libxl__ao *ao;
    libxl__device_action action;
    libxl__device *dev;
    int force;
    libxl__device_callback *callback;
    /* return value, zeroed by user on entry, is valid on callback */
    int rc;
    /* private for multidev */
    int active;
    libxl__multidev *multidev; /* reference to the containing multidev */
    /* private for add/remove implementation */
    libxl__ev_devstate backend_ds;
    /* Bodge for Qemu devices, also used for timeout of hotplug execution */
    libxl__ev_time timeout;
    /* xenstore watch for backend path of driver domains */
    libxl__ev_xswatch xs_watch;
    /* device hotplug execution */
    const char *what;
    int num_exec;
    libxl__ev_child child;
};

/*
 * Multiple devices "multidev" handling.
 *
 * Firstly, you should
 *    libxl__multidev_begin
 *    multidev->callback = ...
 * Then zero or more times
 *    libxl__multidev_prepare
 *    libxl__initiate_device_{remove/addition}
 *       (or some other thing which will eventually call aodev->callback)
 * Finally, once
 *    libxl__multidev_prepared
 * which will result (perhaps reentrantly) in one call to callback().
 */

/* Starts preparing to add/remove a bunch of devices. */
_hidden void libxl__multidev_begin(libxl__ao *ao, libxl__multidev*);

/* Prepares to add/remove one of many devices.  Returns a libxl__ao_device
 * which has had libxl__prepare_ao_device called, and which has also
 * had ->callback set.  The user should not mess with aodev->callback. */
_hidden libxl__ao_device *libxl__multidev_prepare(libxl__multidev*);

/* Notifies the multidev machinery that we have now finished preparing
 * and initiating devices.  multidev->callback may then be called as
 * soon as there are no prepared but not completed operations
 * outstanding, perhaps reentrantly.  If rc!=0 (error should have been
 * logged) multidev->callback will get a non-zero rc.
 * callback may be set by the user at any point before prepared. */
_hidden void libxl__multidev_prepared(libxl__egc*, libxl__multidev*, int rc);

typedef void libxl__devices_callback(libxl__egc*, libxl__multidev*, int rc);
struct libxl__multidev {
    /* set by user: */
    libxl__devices_callback *callback;
    /* for private use by libxl__...ao_devices... machinery: */
    libxl__ao *ao;
    libxl__ao_device **array;
    int used, allocd;
    libxl__ao_device *preparation;
};

/*
 * Algorithm for handling device removal (including domain
 * destruction).  This is somewhat subtle because we may already have
 * killed the domain and caused the death of qemu.
 *
 * In current versions of qemu there is no mechanism for ensuring that
 * the resources used by its devices (both emulated and any PV devices
 * provided by qemu) are freed (eg, fds closed) before it shuts down,
 * and no confirmation from a terminating qemu back to the toolstack.
 *
 * This will need to be fixed in Xen 4.3.  In the meantime (Xen 4.2)
 * we implement a bodge.
 *
 *      WE WANT TO UNPLUG         WE WANT TO SHUT DOWN OR DESTROY
 *                    |                           |
 *                    |             LIBXL SENDS SIGHUP TO QEMU
 *                    |      .....................|........................
 *                    |      : XEN 4.3+ PLANNED   |                       :
 *                    |      :      QEMU TEARS DOWN ALL DEVICES           :
 *                    |      :      FREES RESOURCES (closing fds)         :
 *                    |      :      SETS PV BACKENDS TO STATE 5,          :
 *                    |      :       waits for PV frontends to shut down  :
 *                    |      :       SETS PV BACKENDS TO STATE 6          :
 *                    |      :                    |                       :
 *                    |      :      QEMU NOTIFIES TOOLSTACK (via          :
 *                    |      :       xenstore) that it is exiting         :
 *                    |      :      QEMU EXITS (parent may be init)       :
 *                    |      :                    |                       :
 *                    |      :        TOOLSTACK WAITS FOR QEMU            :
 *                    |      :        notices qemu has finished           :
 *                    |      :....................|.......................:
 *                    |      .--------------------'
 *                    V      V
 *                  for each device
 *                 we want to unplug/remove
 *       ..................|...........................................
 *       :                 V                       XEN 4.2 RACY BODGE :
 *       :      device is provided by    qemu                         :
 *       :            |            `-----------.                      :
 *       :   something|                        V                      :
 *       :    else, eg|             domain (that is domain for which  :
 *       :     blkback|              this PV device is the backend,   :
 *       :            |              which might be the stub dm)      :
 *       :            |                is still alive?                :
 *       :            |                  |        |                   :
 *       :            |                  |alive   |dead               :
 *       :            |<-----------------'        |                   :
 *       :            |    hopefully qemu is      |                   :
 *       :            |       still running       |                   :
 *       :............|.................          |                   :
 *             ,----->|                :     we may be racing         :
 *             |    backend state?     :      with qemu's death       :
 *             ^      |         |      :          |                   :
 *     xenstore|      |other    |6     :      WAIT 2.0s               :
 *     conflict|      |         |      :       TIMEOUT                :
 *             |   WRITE B.E.   |      :          |                   :
 *             |    STATE:=5    |      :     hopefully qemu has       :
 *             `---'  |         |      :      gone by now and         :
 *                    |ok       |      :      freed its resources     :
 *                    |         |      :          |                   :
 *              WAIT FOR        |      :     SET B.E.                 :
 *              STATE==6        |      :      STATE:=6                :
 *              /     |         |      :..........|...................:
 *      timeout/    ok|         |                 |
 *            /       |         |                 |
 *           |    RUN HOTPLUG <-'<----------------'
 *           |      SCRIPT
 *           |        |
 *           `---> NUKE
 *                  BACKEND
 *                    |
 *                   DONE.
 */

/* AO operation to connect a disk device, called by
 * libxl_device_disk_add and libxl__add_disks. This function calls
 * libxl__wait_device_connection to wait for the device to
 * finish the connection (might involve executing hotplug scripts).
 *
 * Once finished, aodev->callback will be executed.
 */
_hidden void libxl__device_disk_add(libxl__egc *egc, uint32_t domid,
                                    libxl_device_disk *disk,
                                    libxl__ao_device *aodev);

/* AO operation to connect a nic device */
_hidden void libxl__device_nic_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_nic *nic,
                                   libxl__ao_device *aodev);

_hidden void libxl__device_vtpm_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_vtpm *vtpm,
                                   libxl__ao_device *aodev);

/* Internal function to connect a vkb device */
_hidden int libxl__device_vkb_add(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vkb *vkb);

/* Internal function to connect a vfb device */
_hidden int libxl__device_vfb_add(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vfb *vfb);

/* Waits for the passed device to reach state XenbusStateInitWait.
 * This is not really useful by itself, but is important when executing
 * hotplug scripts, since we need to be sure the device is in the correct
 * state before executing them.
 *
 * Once finished, aodev->callback will be executed.
 */
_hidden void libxl__wait_device_connection(libxl__egc*,
                                           libxl__ao_device *aodev);

/* Arranges that dev will be removed to the guest, and the
 * hotplug scripts will be executed (if necessary). When
 * this is done (or an error happens), the callback in
 * aodev->callback will be called.
 *
 * The libxl__ao_device passed to this function should be
 * prepared using libxl__prepare_ao_device prior to calling
 * this function.
 *
 * Once finished, aodev->callback will be executed.
 */
_hidden void libxl__initiate_device_remove(libxl__egc *egc,
                                           libxl__ao_device *aodev);

/*
 * libxl__get_hotplug_script_info returns the args and env that should
 * be passed to the hotplug script for the requested device.
 *
 * Since a device might not need to execute any hotplug script, this function
 * can return the following values:
 * < 0: Error
 * 0: No need to execute hotplug script
 * 1: Execute hotplug script
 *
 * The last parameter, "num_exec" refeers to the number of times hotplug
 * scripts have been called for this device.
 *
 * The main body of libxl will, for each device, keep calling
 * libxl__get_hotplug_script_info, with incrementing values of
 * num_exec, and executing the resulting script accordingly,
 * until libxl__get_hotplug_script_info returns<=0.
 */
_hidden int libxl__get_hotplug_script_info(libxl__gc *gc, libxl__device *dev,
                                           char ***args, char ***env,
                                           libxl__device_action action,
                                           int num_exec);

/*----- local disk attach: attach a disk locally to run the bootloader -----*/

typedef struct libxl__disk_local_state libxl__disk_local_state;
typedef void libxl__disk_local_state_callback(libxl__egc*,
                                              libxl__disk_local_state*,
                                              int rc);

/* A libxl__disk_local_state may be in the following states:
 * Undefined, Idle, Attaching, Attached, Detaching.
 */
struct libxl__disk_local_state {
    /* filled by the user */
    libxl__ao *ao;
    const libxl_device_disk *in_disk;
    libxl_device_disk disk;
    const char *blkdev_start;
    libxl__disk_local_state_callback *callback;
    /* filled by libxl__device_disk_local_initiate_attach */
    char *diskpath;
    /* private for implementation of local detach */
    libxl__ao_device aodev;
    int rc;
};

/*
 * Prepares a dls for use.
 * State Undefined -> Idle
 */
static inline void libxl__device_disk_local_init(libxl__disk_local_state *dls)
{
    dls->rc = 0;
}

/* Make a disk available in this (the control) domain. Always calls
 * dls->callback when finished.
 * State Idle -> Attaching
 *
 * The state of dls on entry to the callback depends on the value
 * of rc passed to the callback:
 *     rc == 0: Attached if rc == 0
 *     rc != 0: Idle
 */
_hidden void libxl__device_disk_local_initiate_attach(libxl__egc *egc,
                                                libxl__disk_local_state *dls);

/* Disconnects a disk device form the control domain. If the passed
 * dls is not attached (or has already been detached),
 * libxl__device_disk_local_initiate_detach will just call the callback
 * directly.
 * State Idle/Attached -> Detaching
 *
 * The state of dls on entry to the callback is Idle.
 */
_hidden void libxl__device_disk_local_initiate_detach(libxl__egc *egc,
                                                libxl__disk_local_state *dls);

/*----- datacopier: copies data from one fd to another -----*/

typedef struct libxl__datacopier_state libxl__datacopier_state;
typedef struct libxl__datacopier_buf libxl__datacopier_buf;

/* onwrite==1 means failure happened when writing, logged, errnoval is valid
 * onwrite==0 means failure happened when reading
 *     errnoval==0 means we got eof and all data was written
 *     errnoval!=0 means we had a read error, logged
 * onwrite==-1 means some other internal failure, errnoval not valid, logged
 * If we get POLLHUP, we call callback_pollhup(..., onwrite, -1);
 * or if callback_pollhup==0 this is an internal failure, as above.
 * In all cases copier is killed before calling this callback */
typedef void libxl__datacopier_callback(libxl__egc *egc,
     libxl__datacopier_state *dc, int onwrite, int errnoval);

struct libxl__datacopier_buf {
    /* private to datacopier */
    LIBXL_TAILQ_ENTRY(libxl__datacopier_buf) entry;
    int used;
    char buf[1000];
};

struct libxl__datacopier_state {
    /* caller must fill these in, and they must all remain valid */
    libxl__ao *ao;
    int readfd, writefd;
    ssize_t maxsz;
    const char *copywhat, *readwhat, *writewhat; /* for error msgs */
    FILE *log; /* gets a copy of everything */
    libxl__datacopier_callback *callback;
    libxl__datacopier_callback *callback_pollhup;
    /* remaining fields are private to datacopier */
    libxl__ev_fd toread, towrite;
    ssize_t used;
    LIBXL_TAILQ_HEAD(libxl__datacopier_bufs, libxl__datacopier_buf) bufs;
};

_hidden void libxl__datacopier_init(libxl__datacopier_state *dc);
_hidden void libxl__datacopier_kill(libxl__datacopier_state *dc);
_hidden int libxl__datacopier_start(libxl__datacopier_state *dc);

/* Inserts literal data into the output stream.  The data is copied.
 * May safely be used only immediately after libxl__datacopier_start
 * (before the ctx is unlocked).  But may be called multiple times.
 * NB exceeding maxsz will fail an assertion! */
_hidden void libxl__datacopier_prefixdata(libxl__egc*, libxl__datacopier_state*,
                                          const void *data, size_t len);

/*----- Save/restore helper (used by creation and suspend) -----*/

typedef struct libxl__srm_save_callbacks {
    libxl__srm_save_autogen_callbacks a;
    int (*toolstack_save)(uint32_t domid, uint8_t **buf,
                          uint32_t *len, void *data);
} libxl__srm_save_callbacks;

typedef struct libxl__srm_restore_callbacks {
    libxl__srm_restore_autogen_callbacks a;
} libxl__srm_restore_callbacks;

/* a pointer to this struct is also passed as "user" to the
 * save callout helper callback functions */
typedef struct libxl__save_helper_state {
    /* public, caller of run_helper initialises */
    libxl__ao *ao;
    uint32_t domid;
    union {
        libxl__srm_save_callbacks save;
        libxl__srm_restore_callbacks restore;
    } callbacks;
    int (*recv_callback)(const unsigned char *msg, uint32_t len, void *user);
    void (*completion_callback)(libxl__egc *egc, void *caller_state,
                                int rc, int retval, int errnoval);
    void *caller_state;
    int need_results; /* set to 0 or 1 by caller of run_helper;
                       * if set to 1 then the ultimate caller's
                       * results function must set it to 0 */
    /* private */
    int rc;
    int completed; /* retval/errnoval valid iff completed */
    int retval, errnoval; /* from xc_domain_save / xc_domain_restore */
    libxl__carefd *pipes[2]; /* 0 = helper's stdin, 1 = helper's stdout */
    libxl__ev_fd readable;
    libxl__ev_child child;
    const char *stdin_what, *stdout_what;
    FILE *toolstack_data_file;

    libxl__egc *egc; /* valid only for duration of each event callback;
                      * is here in this struct for the benefit of the
                      * marshalling and xc callback functions */
} libxl__save_helper_state;


/*----- Domain suspend (save) state structure -----*/

typedef struct libxl__domain_suspend_state libxl__domain_suspend_state;

typedef void libxl__domain_suspend_cb(libxl__egc*,
                                      libxl__domain_suspend_state*, int rc);
typedef void libxl__save_device_model_cb(libxl__egc*,
                                         libxl__domain_suspend_state*, int rc);

typedef struct libxl__logdirty_switch {
    const char *cmd;
    const char *cmd_path;
    const char *ret_path;
    libxl__ev_xswatch watch;
    libxl__ev_time timeout;
} libxl__logdirty_switch;

struct libxl__domain_suspend_state {
    /* set by caller of libxl__domain_suspend */
    libxl__ao *ao;
    libxl__domain_suspend_cb *callback;

    uint32_t domid;
    int fd;
    libxl_domain_type type;
    int live;
    int debug;
    const libxl_domain_remus_info *remus;
    /* private */
    libxl__ev_evtchn guest_evtchn;
    int guest_evtchn_lockfd;
    int hvm;
    int xcflags;
    int guest_responded;
    libxl__xswait_state pvcontrol;
    libxl__ev_xswatch guest_watch;
    libxl__ev_time guest_timeout;
    const char *dm_savefile;
    int interval; /* checkpoint interval (for Remus) */
    libxl__save_helper_state shs;
    libxl__logdirty_switch logdirty;
    void (*callback_common_done)(libxl__egc*,
                                 struct libxl__domain_suspend_state*, int ok);
    /* private for libxl__domain_save_device_model */
    libxl__save_device_model_cb *save_dm_callback;
    libxl__datacopier_state save_dm_datacopier;
};


/*----- openpty -----*/

/*
 * opens count (>0) ptys like count calls to openpty, and then
 * calls back.  On entry, all op[].master and op[].slave must be
 * 0.  On callback, either rc==0 and master and slave are non-0,
 * or rc is a libxl error and they are both 0.  If libxl__openpty
 * returns non-0 no callback will happen and everything is left
 * cleaned up.
 */

typedef struct libxl__openpty_state libxl__openpty_state;
typedef struct libxl__openpty_result libxl__openpty_result;
typedef void libxl__openpty_callback(libxl__egc *egc, libxl__openpty_state *op);

struct libxl__openpty_state {
    /* caller must fill these in, and they must all remain valid */
    libxl__ao *ao;
    libxl__openpty_callback *callback;
    int count;
    libxl__openpty_result *results; /* actual size is count, out parameter */
    /* public, result, caller may only read in callback */
    int rc;
    /* private for implementation */
    libxl__ev_child child;
};

struct libxl__openpty_result {
    libxl__carefd *master, *slave;
};

int libxl__openptys(libxl__openpty_state *op,
                    struct termios *termp,
                    struct winsize *winp);


/*----- bootloader -----*/

typedef struct libxl__bootloader_state libxl__bootloader_state;
typedef void libxl__run_bootloader_callback(libxl__egc*,
                                libxl__bootloader_state*, int rc);
typedef void libxl__bootloader_console_callback(libxl__egc*,
                                libxl__bootloader_state*);

struct libxl__bootloader_state {
    /* caller must fill these in, and they must all remain valid */
    libxl__ao *ao;
    libxl__run_bootloader_callback *callback;
    libxl__bootloader_console_callback *console_available;
    const libxl_domain_build_info *info;
    libxl_device_disk *disk;
    /* Should be zeroed by caller on entry.  Will be filled in by
     * bootloader machinery; represents the local attachment of the
     * disk for the benefit of the bootloader.  Must be detached by
     * the caller using libxl__device_disk_local_initiate_detach.
     * (This is safe to do after ->callback() has happened since
     * the domain's kernel and initramfs will have been copied
     * out of the guest's disk into a temporary directory, mapped
     * as file references, and deleted. */
    libxl__disk_local_state dls;
    uint32_t domid;
    /* outputs:
     *  - caller must initialise kernel and ramdisk to point to file
     *    references, these will be updated and mapped;
     *  - caller must initialise cmdline to NULL, it will be updated with a
     *    string allocated from the gc;
     */
    libxl__file_reference *kernel, *ramdisk;
    const char *cmdline;
    /* private to libxl__run_bootloader */
    char *outputpath, *outputdir, *logfile;
    libxl__openpty_state openpty;
    libxl__openpty_result ptys[2];  /* [0] is for bootloader */
    libxl__ev_child child;
    libxl__domaindeathcheck deathcheck;
    int nargs, argsspace;
    const char **args;
    libxl__datacopier_state keystrokes, display;
    int rc, got_pollhup;
};

_hidden void libxl__bootloader_init(libxl__bootloader_state *bl);

/* Will definitely call st->callback, perhaps reentrantly.
 * If callback is passed rc==0, will have updated st->info appropriately */
_hidden void libxl__bootloader_run(libxl__egc*, libxl__bootloader_state *st);

/*----- Domain destruction -----*/

/* Domain destruction has been split into two functions:
 *
 * libxl__domain_destroy is the main destroy function, which detects
 * stubdoms and calls libxl__destroy_domid on the domain and its
 * stubdom if present, creating a different libxl__destroy_domid_state
 * for each one of them.
 *
 * libxl__destroy_domid actually destroys the domain, but it
 * doesn't check for stubdomains, since that would involve
 * recursion, which we want to avoid.
 */

typedef struct libxl__domain_destroy_state libxl__domain_destroy_state;
typedef struct libxl__destroy_domid_state libxl__destroy_domid_state;
typedef struct libxl__devices_remove_state libxl__devices_remove_state;

typedef void libxl__domain_destroy_cb(libxl__egc *egc,
                                      libxl__domain_destroy_state *dds,
                                      int rc);

typedef void libxl__domid_destroy_cb(libxl__egc *egc,
                                     libxl__destroy_domid_state *dis,
                                     int rc);

typedef void libxl__devices_remove_callback(libxl__egc *egc,
                                            libxl__devices_remove_state *drs,
                                            int rc);

struct libxl__devices_remove_state {
    /* filled in by user */
    libxl__ao *ao;
    uint32_t domid;
    libxl__devices_remove_callback *callback;
    int force; /* libxl_device_TYPE_destroy rather than _remove */
    /* private */
    libxl__multidev multidev;
    int num_devices;
};

struct libxl__destroy_domid_state {
    /* filled in by user */
    libxl__ao *ao;
    uint32_t domid;
    libxl__domid_destroy_cb *callback;
    /* private to implementation */
    libxl__devices_remove_state drs;
};

struct libxl__domain_destroy_state {
    /* filled by the user */
    libxl__ao *ao;
    uint32_t domid;
    libxl__domain_destroy_cb *callback;
    /* Private */
    int rc;
    uint32_t stubdomid;
    libxl__destroy_domid_state stubdom;
    int stubdom_finished;
    libxl__destroy_domid_state domain;
    int domain_finished;
};

/*
 * Entry point for domain destruction
 * This function checks for stubdom presence and then calls
 * libxl__destroy_domid on the passed domain and its stubdom if found.
 */
_hidden void libxl__domain_destroy(libxl__egc *egc,
                                   libxl__domain_destroy_state *dds);

/* Used to destroy a domain with the passed id (it doesn't check for stubs) */
_hidden void libxl__destroy_domid(libxl__egc *egc,
                                  libxl__destroy_domid_state *dis);

/* Entry point for devices destruction */
_hidden void libxl__devices_destroy(libxl__egc *egc,
                                    libxl__devices_remove_state *drs);

/* Helper function to add a bunch of disks. This should be used when
 * the caller is inside an async op. "multidev" will NOT be prepared by
 * this function, so the caller must make sure to call
 * libxl__multidev_begin before calling this function.
 *
 * The "callback" will be called for each device, and the user is responsible
 * for calling libxl__ao_device_check_last on the callback.
 */
_hidden void libxl__add_disks(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                              libxl_domain_config *d_config,
                              libxl__multidev *multidev);

_hidden void libxl__add_nics(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                             libxl_domain_config *d_config,
                             libxl__multidev *multidev);

_hidden void libxl__add_vtpms(libxl__egc *egc, libxl__ao *ao, uint32_t domid,
                             libxl_domain_config *d_config,
                             libxl__multidev *multidev);

/*----- device model creation -----*/

/* First layer; wraps libxl__spawn_spawn. */

typedef struct libxl__dm_spawn_state libxl__dm_spawn_state;

typedef void libxl__dm_spawn_cb(libxl__egc *egc, libxl__dm_spawn_state*,
                                int rc /* if !0, error was logged */);

struct libxl__dm_spawn_state {
    /* mixed - spawn.ao must be initialised by user; rest is private: */
    libxl__spawn_state spawn;
    /* filled in by user, must remain valid: */
    uint32_t guest_domid; /* domain being served */
    libxl_domain_config *guest_config;
    libxl__domain_build_state *build_state; /* relates to guest_domid */
    libxl__dm_spawn_cb *callback;
};

_hidden void libxl__spawn_local_dm(libxl__egc *egc, libxl__dm_spawn_state*);

/* Stubdom device models. */

typedef struct {
    /* Mixed - user must fill in public parts EXCEPT callback,
     * which may be undefined on entry.  (See above for details) */
    libxl__dm_spawn_state dm; /* the stub domain device model */
    /* filled in by user, must remain valid: */
    libxl__dm_spawn_cb *callback; /* called as callback(,&sdss->dm,) */
    /* private to libxl__spawn_stub_dm: */
    libxl_domain_config dm_config;
    libxl__domain_build_state dm_state;
    libxl__dm_spawn_state pvqemu;
    libxl__destroy_domid_state dis;
    libxl__multidev multidev;
} libxl__stub_dm_spawn_state;

_hidden void libxl__spawn_stub_dm(libxl__egc *egc, libxl__stub_dm_spawn_state*);

_hidden char *libxl__stub_dm_name(libxl__gc *gc, const char * guest_name);

/* Qdisk backend launch helpers */

_hidden void libxl__spawn_qdisk_backend(libxl__egc *egc,
                                        libxl__dm_spawn_state *dmss);
_hidden int libxl__destroy_qdisk_backend(libxl__gc *gc, uint32_t domid);

/*----- Domain creation -----*/

typedef struct libxl__domain_create_state libxl__domain_create_state;

typedef void libxl__domain_create_cb(libxl__egc *egc,
                                     libxl__domain_create_state*,
                                     int rc, uint32_t domid);

struct libxl__domain_create_state {
    /* filled in by user */
    libxl__ao *ao;
    libxl_domain_config *guest_config;
    int restore_fd;
    libxl__domain_create_cb *callback;
    libxl_asyncprogress_how aop_console_how;
    /* private to domain_create */
    int guest_domid;
    int checkpointed_stream;
    libxl__domain_build_state build_state;
    libxl__bootloader_state bl;
    libxl__stub_dm_spawn_state dmss;
        /* If we're not doing stubdom, we use only dmss.dm,
         * for the non-stubdom device model. */
    libxl__save_helper_state shs;
    /* necessary if the domain creation failed and we have to destroy it */
    libxl__domain_destroy_state dds;
    libxl__multidev multidev;
};

/*----- Domain suspend (save) functions -----*/

/* calls dss->callback when done */
_hidden void libxl__domain_suspend(libxl__egc *egc,
                                   libxl__domain_suspend_state *dss);


/* calls libxl__xc_domain_suspend_done when done */
_hidden void libxl__xc_domain_save(libxl__egc*, libxl__domain_suspend_state*,
                                   unsigned long vm_generationid_addr);
/* If rc==0 then retval is the return value from xc_domain_save
 * and errnoval is the errno value it provided.
 * If rc!=0, retval and errnoval are undefined. */
_hidden void libxl__xc_domain_save_done(libxl__egc*, void *dss_void,
                                        int rc, int retval, int errnoval);

/* Used by asynchronous callbacks: ie ones which xc regards as
 * returning a value, but which we want to handle asynchronously.
 * Such functions' actual callback function return void in libxl
 * When they are ready to indicate completion, they call this. */
void libxl__xc_domain_saverestore_async_callback_done(libxl__egc *egc,
                           libxl__save_helper_state *shs, int return_value);


_hidden void libxl__domain_suspend_common_switch_qemu_logdirty
                               (int domid, unsigned int enable, void *data);
_hidden int libxl__toolstack_save(uint32_t domid, uint8_t **buf,
        uint32_t *len, void *data);


/* calls libxl__xc_domain_restore_done when done */
_hidden void libxl__xc_domain_restore(libxl__egc *egc,
                                      libxl__domain_create_state *dcs,
                                      int hvm, int pae, int superpages,
                                      int no_incr_generationid);
/* If rc==0 then retval is the return value from xc_domain_save
 * and errnoval is the errno value it provided.
 * If rc!=0, retval and errnoval are undefined. */
_hidden void libxl__xc_domain_restore_done(libxl__egc *egc, void *dcs_void,
                                           int rc, int retval, int errnoval);

/* Each time the dm needs to be saved, we must call suspend and then save */
_hidden int libxl__domain_suspend_device_model(libxl__gc *gc,
                                           libxl__domain_suspend_state *dss);
_hidden void libxl__domain_save_device_model(libxl__egc *egc,
                                     libxl__domain_suspend_state *dss,
                                     libxl__save_device_model_cb *callback);

_hidden const char *libxl__device_model_savefile(libxl__gc *gc, uint32_t domid);


/*
 * Convenience macros.
 */

/*
 * CONTAINER_OF work like this.  Given:
 *    typedef struct {
 *      ...
 *      member_type member_name;
 *      ...
 *    } outer_type;
 *    outer_type outer, *outer_var;
 *    member_type *inner_ptr = &outer->member_name;
 *
 * Then, effectively:
 *    outer_type *CONTAINER_OF(member_type *inner_ptr,
 *                             *outer_var, // or type name for outer_type
 *                             member_name);
 *
 * So that:
 *    CONTAINER_OF(inner_ptr, *outer_var, member_name) == &outer
 *    CONTAINER_OF(inner_ptr, outer_type, member_name) == &outer
 */
#define CONTAINER_OF(inner_ptr, outer, member_name)                     \
    ({                                                                  \
        typeof(outer) *container_of_;                                   \
        container_of_ = (void*)((char*)(inner_ptr) -                    \
                                offsetof(typeof(outer), member_name));  \
        (void)(&container_of_->member_name ==                           \
               (typeof(inner_ptr))0) /* type check */;                  \
        container_of_;                                                  \
    })


/*
 * All of these assume (or define)
 *    libxl__gc *gc;
 * as a local variable.
 */

#define GC_INIT(ctx)  libxl__gc gc[1]; LIBXL_INIT_GC(gc[0],ctx)
#define GC_FREE       libxl__free_all(gc)
#define CTX           libxl__gc_owner(gc)
#define NOGC          (&CTX->nogc_gc) /* pass only to consenting functions */

/* Allocation macros all of which use the gc. */

#define ARRAY_SIZE_OK(ptr, nmemb) ((nmemb) < INT_MAX / (sizeof(*(ptr)) * 2))

/*
 * Expression statement  <type> *GCNEW(<type> *var);
 * Uses                  libxl__gc *gc;
 *
 * Allocates a new object of type <type> from the gc and zeroes it
 * with memset.  Sets var to point to the new object or zero (setting
 * errno).  Returns the new value of var.
 */
#define GCNEW(var)                                      \
    (((var) = libxl__zalloc((gc),sizeof(*(var)))))

/*
 * Expression statement  <type> *GCNEW_ARRAY(<type> *var, ssize_t nmemb);
 * Uses                  libxl__gc *gc;
 *
 * Like GCNEW but allocates an array of nmemb elements, as if from
 * calloc.  Does check for integer overflow due to large nmemb.  If
 * nmemb is 0 may succeed by returning 0.
 */
#define GCNEW_ARRAY(var, nmemb)                                 \
    ((var) = libxl__calloc((gc), (nmemb), sizeof(*(var))))
    
/*
 * Expression statement  <type> *GCREALLOC_ARRAY(<type> *var, size_t nmemb);
 * Uses                  libxl__gc *gc;
 *
 * Reallocates the array var to be of size nmemb elements.  Updates
 * var and returns the new value of var.  Does check for integer
 * overflow due to large nmemb.
 *
 * Do not pass nmemb==0.  old may be 0 on entry.
 */
#define GCREALLOC_ARRAY(var, nmemb)                                     \
    (assert(nmemb > 0),                                                 \
     assert(ARRAY_SIZE_OK((var), (nmemb))),                             \
     (var) = libxl__realloc((gc), (var), (nmemb)*sizeof(*(var))))


/*
 * Expression            char *GCSPRINTF(const char *fmt, ...);
 * Uses                  libxl__gc *gc;
 *
 * Trivial convenience wrapper for libxl__sprintf.
 */
#define GCSPRINTF(fmt, ...) (libxl__sprintf((gc), (fmt), __VA_ARGS__))


/*
 * Expression statements
 *    void LOG(<xtl_level_suffix>, const char *fmt, ...);
 *    void LOGE(<xtl_level_suffix>, const char *fmt, ...);
 *    void LOGEV(<xtl_level_suffix>, int errnoval, const char *fmt, ...);
 * Use
 *    libxl__gc *gc;
 *
 * Trivial convenience wrappers for LIBXL__LOG, LIBXL__LOG_ERRNO and
 * LIBXL__LOG_ERRNOVAL, respectively (and thus for libxl__log).
 *
 * XTL_<xtl_level_suffix> should exist and be an xentoollog.h log level
 * So <xtl_level_suffix> should be one of
 *   DEBUG VERBOSE DETAIL PROGRESS INFO NOTICE WARN ERROR ERROR CRITICAL
 * Of these, most of libxl uses
 *   DEBUG INFO WARN ERROR
 */
#define LOG(l,f, ...)     LIBXL__LOG(CTX,XTL_##l,(f),##__VA_ARGS__)
#define LOGE(l,f, ...)    LIBXL__LOG_ERRNO(CTX,XTL_##l,(f),##__VA_ARGS__)
#define LOGEV(l,e,f, ...) LIBXL__LOG_ERRNOVAL(CTX,XTL_##l,(e),(f),##__VA_ARGS__)


/* Locking functions.  See comment for "lock" member of libxl__ctx. */

static inline void libxl__ctx_lock(libxl_ctx *ctx) {
    int r = pthread_mutex_lock(&ctx->lock);
    assert(!r);
}

static inline void libxl__ctx_unlock(libxl_ctx *ctx) {
    int r = pthread_mutex_unlock(&ctx->lock);
    assert(!r);
}

#define CTX_LOCK (libxl__ctx_lock(CTX))
#define CTX_UNLOCK (libxl__ctx_unlock(CTX))

/*
 * Automatic NUMA placement
 *
 * These functions and data structures deal with the initial placement of a
 * domain onto the host NUMA nodes.
 *
 * The key concept here is the one of "NUMA placement candidate", which is
 * basically a set of nodes whose characteristics have been successfully
 * checked against some specific requirements. More precisely, a candidate
 * is the nodemap associated with one of the possible subset of the host
 * NUMA nodes providing a certain amount of free memory, or a given number
 * of cpus, or even both (depending in what the caller wants). For
 * convenience of use, some of this information are stored within the
 * candidate itself, instead of always being dynamically computed. A single
 * node can be valid placement candidate, as well as it is possible for a
 * candidate to contain all the nodes of the host. The fewer nodes there
 * are in a candidate, the better performance a domain placed onto it
 * should get (at least from a NUMA point of view). For instance, looking
 * for a numa candidates with 2GB of free memory means we want the subsets
 * of the host NUMA nodes with, cumulatively, at least 2GB of free memory.
 * This condition can be satisfied by just one particular node, or it may
 * require more nodes, depending on the characteristics of the host, on how
 * many domains have been created already, on how big they are, etc.
 *
 * The intended usage is as follows:
 *  1. first of all, call libxl__get_numa_candidates(), and specify the
 *     proper constraints to it (e.g., the amount of memory a domain need
 *     as the minimum amount of free memory for the candidates). If a
 *     candidate comparison function is provided, the candidate with fewer
 *     nodes that is found to be best according to what such fucntion says
 *     is returned. If no comparison function is passed, the very first
 *     candidate is.
 *  2. The chosen candidate's nodemap should be utilized for computing the
 *     actual affinity of the domain which, given the current NUMA support
 *     in the hypervisor, is what determines the placement of the domain's
 *     vcpus and memory.
 */

typedef struct {
    int nr_cpus, nr_nodes;
    int nr_vcpus;
    uint32_t free_memkb;
    libxl_bitmap nodemap;
} libxl__numa_candidate;

/* Signature for the comparison function between two candidates */
typedef int (*libxl__numa_candidate_cmpf)(const libxl__numa_candidate *c1,
                                          const libxl__numa_candidate *c2);

/*
 * This looks for the best NUMA placement candidate satisfying some
 * specific conditions. If min_nodes and/or max_nodes are not 0, their
 * value is used to determine the minimum and maximum number of nodes the
 * candidate can have. If they are 0, it means the candidate can contain
 * from 1 node (min_nodes=0) to the total number of nodes of the host
 * (max_ndoes=0). If min_free_memkb and/or min_cpus are not 0, the caller
 * only wants candidates with at least the amount of free memory and the
 * number of cpus they specify, respectively. If they are 0, the
 * candidates' free memory and/or number of cpus won't be checked at all.
 *
 * Candidates are compared among each others by calling numa_cmpf(), which
 * is where the heuristics for determining which candidate is the best
 * one is actually implemented. The only bit of it that is hardcoded in
 * this function is the fact that candidates with fewer nodes are always
 * preferrable.
 *
 * If at least one suitable candidate is found, it is returned in cndt_out,
 * cndt_found is set to one, and the function returns successfully. On the
 * other hand, if not even one single candidate can be found, the function
 * still returns successfully but cndt_found will be zero.
 *
 * Finally, suitable_cpumap is useful for telling that only the cpus in that
 * mask should be considered when generating placement candidates (for
 * example because of cpupools).
 *
 * It is up to the function to properly allocate cndt_out (by calling
 * libxl__numa_candidate_alloc()), while it is the caller that should init
 * (libxl__numa_candidate_init()) and free (libxl__numa_candidate_dispose())
 * it.
 */
_hidden int libxl__get_numa_candidate(libxl__gc *gc,
                                      uint32_t min_free_memkb, int min_cpus,
                                      int min_nodes, int max_nodes,
                                      const libxl_bitmap *suitable_cpumap,
                                      libxl__numa_candidate_cmpf numa_cmpf,
                                      libxl__numa_candidate *cndt_out,
                                      int *cndt_found);

/* Initialization, allocation and deallocation for placement candidates */
static inline void libxl__numa_candidate_init(libxl__numa_candidate *cndt)
{
    cndt->free_memkb = 0;
    cndt->nr_cpus = cndt->nr_nodes = cndt->nr_vcpus = 0;
    libxl_bitmap_init(&cndt->nodemap);
}

static inline int libxl__numa_candidate_alloc(libxl__gc *gc,
                                              libxl__numa_candidate *cndt)
{
    return libxl_node_bitmap_alloc(CTX, &cndt->nodemap, 0);
}
static inline void libxl__numa_candidate_dispose(libxl__numa_candidate *cndt)
{
    libxl_bitmap_dispose(&cndt->nodemap);
}

/* Retrieve (in nodemap) the node map associated to placement candidate cndt */
static inline
void libxl__numa_candidate_get_nodemap(libxl__gc *gc,
                                       const libxl__numa_candidate *cndt,
                                       libxl_bitmap *nodemap)
{
    libxl_bitmap_copy(CTX, nodemap, &cndt->nodemap);
}
/* Set the node map of placement candidate cndt to match nodemap */
static inline
void libxl__numa_candidate_put_nodemap(libxl__gc *gc,
                                       libxl__numa_candidate *cndt,
                                       const libxl_bitmap *nodemap)
{
    libxl_bitmap_copy(CTX, &cndt->nodemap, nodemap);
}

/*
 * Inserts "elm_new" into the sorted list "head".
 *
 * "elm_search" must be a loop search variable of the same type as
 * "elm_new".  "new_after_search_p" must be an expression which is
 * true iff the element "elm_new" sorts after the element
 * "elm_search".
 *
 * "search_body" can be empty, or some declaration(s) and statement(s)
 * needed for "new_after_search_p".
 */
#define LIBXL_TAILQ_INSERT_SORTED(head, entry, elm_new, elm_search,     \
                                  search_body, new_after_search_p)      \
    do {                                                                \
        for ((elm_search) = LIBXL_TAILQ_FIRST((head));                  \
             (elm_search);                                              \
             (elm_search) = LIBXL_TAILQ_NEXT((elm_search), entry)) {    \
            search_body;                                                \
            if (!(new_after_search_p))                                  \
                break;                                                  \
        }                                                               \
        /* now elm_search is either the element before which we want    \
         * to place elm_new, or NULL meaning we want to put elm_new at  \
         * the end */                                                   \
        if ((elm_search))                                               \
            LIBXL_TAILQ_INSERT_BEFORE((elm_search), (elm_new), entry);  \
        else                                                            \
            LIBXL_TAILQ_INSERT_TAIL((head), (elm_new), entry);          \
    } while(0)


/*
 * int CTYPE(ISFOO, char c);
 * int CTYPE(toupper, char c);
 * int CTYPE(tolower, char c);
 *
 * This is necessary because passing a simple char to a ctype.h
 * is forbidden.  ctype.h macros take ints derived from _unsigned_ chars.
 *
 * If you have a char which might be EOF then you should already have
 * it in an int representing an unsigned char, and you can use the
 * <ctype.h> macros directly.  This generally happens only with values
 * from fgetc et al.
 *
 * For any value known to be a character (eg, anything that came from
 * a char[]), use CTYPE.
 */
#define CTYPE(isfoo,c) (isfoo((unsigned char)(c)))


#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
