/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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
 * libxl API compatibility
 *
 * From Xen 4.2 onwards the API of libxl will be maintained in a
 * stable manner. This means that it should be possible to write an
 * application against the API provided by libxl in Xen 4.2 and expect
 * that it will continue to compile against future versions of Xen
 * without source modification.
 *
 * In order to make such compatibility possible it is required that
 * application which want to be exposed to a particular API #define
 * LIBXL_API_VERSION before including libxl.h or any other libxl
 * header. The syntax of the LIBXL_API_VERSION is:
 *    0xVVSSEE
 * where ($(XEN_xxx) from xen/Makefile):
 *   VV is the Xen major release number, $(XEN_VERSION)
 *   SS is the Xen sub version number, $(XEN_SUBVERSION)
 *   EE is the Xen extra version digit, first numeric part of
 *     $(XEN_EXTRAVERSION) not including the leading "."
 * For example the first stable API version, supported by Xen 4.2.0,
 * is 0x040200.
 *
 * Lack of LIBXL_API_VERSION means "the latest" which will
 * change. Specifying an unknown LIBXL_API_VERSION will result in a
 * compile time error.
 *
 * Identical versions of the libxl API will represented by the version
 * containing the earliest instance of that API. e.g. if 4.2.0 and
 * 4.3.0 contain an identical libxl API then only LIBXL_API_VERSION
 * 0x040200 will be valid.
 *
 * We will try especially hard to avoid changing the API during a
 * stable series, i.e. it should be unusual for the last byte of
 * LIBXL_API_VERSION to be non-zero.
 *
 * In the event that a change is required which cannot be made
 * backwards compatible in this manner a #define of the form
 * LIBXL_HAVE_<interface> will always be added in order to make it
 * possible to write applciations which build against any version of
 * libxl. Such changes are expected to be exceptional and used as a
 * last resort. The barrier for backporting such a change to a stable
 * branch will be very high.
 *
 * These guarantees apply only to stable releases of Xen. When an
 * incompatible change is made in the unstable tree then
 * LIBXL_API_VERSION will be bumped to the next expected stable
 * release number on the first such change only. Applications which
 * want to support building against Xen unstable are expected to track
 * API changes in that tree until it is released as a stable release.
 *
 * API compatibility will be maintained for all versions of Xen using
 * the same $(XEN_VERSION) (e.g. throughout a major release).
 */

/*
 * libxl ABI compatibility
 *
 * The only guarantee which libxl makes regarding ABI compatibility
 * across releases is that the SONAME will always be bumped whenever
 * the ABI is changed in an incompatible way.
 *
 * This applies within stable branches as well as
 * development branches. It is possible that a new stable release of
 * Xen may require a rebuild of applications using the
 * library. However per the API compatibility gaurantees such a
 * rebuild should not normally require any source level changes.
 *
 * As with the API compatiblity the SONAME will only be bumped for the
 * first ABI incompatible change in a development branch.
 */

/*
 * libxl memory management
 *
 * From the point of view of the application (ie, libxl's caller),
 * struct libxl_ctx* is threadsafe, and all returned allocated
 * structures are obtained from malloc(), and must be freed by the
 * caller either directly or by calling an appropriate free function
 * provided by libxl.  Ie the application does not get automatic
 * assistance from libxl in managing these allocations.
 *
 * Specific details are in the header comments which should be found
 * in libxl.h or libxlutil.h, next to the relevant function
 * declarations.
 *
 * Internally, libxl has a garbage collection scheme which allows much libxl
 * code to allocate strings etc. for internal use without needing to
 * free them.  These are called "temporary allocations".
 *
 * The pool for these temporary allocations, along with any other
 * thread-specific data which is private to libxl but shared between
 * libxl functions (such as the current xenstore transaction), is
 * stored in the "gc context" which is a special enhanced context
 * structure allocated automatically by convenience macros at every
 * entry to libxl.
 *
 * Every libxl function falls into one of these categories:
 *
 * 1. Public functions (declared in libxl.h, libxlutil.h), which may
 *    be called by libxl applications.  If a public function returns
 *    any allocated object to its caller, that object must have come
 *    from malloc.
 *
 *    The definitions of public functions MUST use the gc context
 *    initialisation macros (or do the equivalent work themselves).
 *    These macros will ensure that all temporary allocations will be
 *    automatically freed before the function returns to its caller.
 *
 *    A public function may be called from within libxl; the call
 *    context initialisation macros will make sure that the internal
 *    caller's context is reused (eg, so that the same xenstore
 *    transaction is used).  But in-libxl callers of libxl public
 *    functions should note that any libxl public function may cause
 *    recursively reentry into libxl via the application's event
 *    callback hook.
 *
 *    Public functions have names like libxl_foobar.
 *
 * 2. Private functions, which may not be called by libxl
 *    applications; they are not declared in libxl.h or libxlutil.h
 *    and they may not be called other than by other libxl functions.
 *
 *    Private functions should not use the gc context initialisation
 *    macros.
 *
 *    Private functions have names like libxl__foobar (NB, two underscores).
 *    Also the declaration of such functions must be preceeded by the _hidden
 *    macro.
 *
 * Allocations made by a libxl function fall into one of the following
 * categories (where "object" includes any memory allocation):
 *
 * (a) Objects which are not returned to the function's caller.
 *     These should be allocated from the temporary pool.
 *
 * (b) Objects which are intended for return to the calling
 *     application.  This includes all allocated objects returned by
 *     any public function.
 *
 *     It may also include objects allocated by an internal function
 *     specifically for eventual return by the function's external
 *     callers, but this situation should be clearly documented in
 *     comments.
 *
 *     These should be allocated from malloc() et al. and comments
 *     near the function declaration should explain the memory
 *     ownership.  If a simple free() by the application is not
 *     sufficient, a suitable public freeing function should be
 *     provided.
 *
 * (c) Internal objects whose size and/or lifetime dictate explicit
 *     memory management within libxl.  This includes objects which
 *     will be embedded in opaque structures which will be returned to
 *     the libxl caller (more generally, any internal object whose
 *     lifetime exceeds the libxl entrypoint which creates it) and
 *     objects which are so large or numerous that explicit memory
 *     management is required.
 *
 *     These should be allocated from malloc() et al., and freed
 *     explicitly at the appropriate point.  The situation should be
 *     documented in comments.
 *
 * (d) Objects which are allocated by internal-only functions and
 *     returned to the function's (therefore, internal) caller but are
 *     strictly for internal use by other parts of libxl.  These
 *     should be allocated from the temporary pool.
 *
 *     Where a function's primary purpose is to return such an object,
 *     it should have a libxl__gc * as it's first argument.
 *
 *     Note that there are two ways to change an allocation from this
 *     category to the "public" category. Either the implementation
 *     is kept internal and a wrapper function duplicates all memory
 *     allocations so that they are suitable for return to external
 *     callers or the implementation uses plain malloc() et al calls
 *     and an internal wrapper adds the relevant pointers to the gc.
 *     The latter method is preferred for obvious performance reasons.
 *
 * No temporary objects allocated from the pool may be explicitly freed.
 * Therefore public functions which initialize a libxl__gc MUST call
 * libxl__free_all() before returning.
 *
 * Memory allocation failures are not handled gracefully.  If malloc
 * (or realloc) fails, libxl will cause the entire process to print
 * a message to stderr and exit with status 255.
 */
/*
 * libxl types
 *
 * Most libxl types are defined by the libxl IDL (see
 * libxl_types.idl). The library provides a common set of methods for
 * initialising and freeing these types.
 *
 * void libxl_<type>_init(<type> *p):
 *
 *    Initialises the members of "p" to all defaults. These may either
 *    be special value which indicates to the library that it should
 *    select an appropriate default when using this field or actual
 *    default values.
 *
 *    Some fields within a data type (e.g. unions) cannot be sensibly
 *    initialised without further information. In these cases a
 *    separate subfield initialisation function is provided (see
 *    below).
 *
 *    An instance which has been initialised using this method can
 *    always be safely passed to the dispose function (see
 *    below). This is true even if the data type contains fields which
 *    require a separate call to a subfield initialisation function.
 *
 *    This method is provided for any aggregate type which is used as
 *    an input parameter.
 *
 * void libxl_<type>_init_<subfield>(<type> *p, subfield):
 *
 *    Initialise those parts of "p" which are not initialised by the
 *    main init function due to the unknown value of "subfield". Sets
 *    p->subfield as well as initialising any fields to their default
 *    values.
 *
 *    p->subfield must not have been previously initialised.
 *
 *    This method is provided for any aggregate type.
 *
 * void libxl_<type>_dispose(instance *p):
 *
 *    Frees any dynamically allocated memory used by the members of
 *    "p" but not the storage used by "p" itself (this allows for the
 *    allocation of arrays of types and for the composition of types).
 */
#ifndef LIBXL_H
#define LIBXL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/wait.h> /* for pid_t */

#include <xentoollog.h>

#include <libxl_uuid.h>
#include <_libxl_list.h>

/* API compatibility. Only 0x040200 is supported at this time. */
#ifdef LIBXL_API_VERSION
#if LIBXL_API_VERSION != 0x040200
#error Unknown LIBXL_API_VERSION
#endif
#endif

typedef uint8_t libxl_mac[6];
#define LIBXL_MAC_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define LIBXL_MAC_FMTLEN ((2*6)+5) /* 6 hex bytes plus 5 colons */
#define LIBXL_MAC_BYTES(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

typedef char **libxl_string_list;
void libxl_string_list_dispose(libxl_string_list *sl);
int libxl_string_list_length(const libxl_string_list *sl);

typedef char **libxl_key_value_list;
void libxl_key_value_list_dispose(libxl_key_value_list *kvl);

typedef uint32_t libxl_hwcap[8];

typedef uint64_t libxl_ev_user;

typedef struct {
    uint32_t size;          /* number of bytes in map */
    uint8_t *map;
} libxl_cpumap;
void libxl_cpumap_dispose(libxl_cpumap *map);

/* libxl_cpuid_policy_list is a dynamic array storing CPUID policies
 * for multiple leafs. It is terminated with an entry holding
 * XEN_CPUID_INPUT_UNUSED in input[0]
 */
typedef struct libxl__cpuid_policy libxl_cpuid_policy;
typedef libxl_cpuid_policy * libxl_cpuid_policy_list;
void libxl_cpuid_dispose(libxl_cpuid_policy_list *cpuid_list);

#define LIBXL_PCI_FUNC_ALL (~0U)

typedef uint32_t libxl_domid;

/*
 * Formatting Enumerations.
 *
 * Each enumeration type libxl_E declares an associated lookup table
 * libxl_E_string_table and a lookup function libxl_E_from_string.
 */
typedef struct {
    const char *s;
    int v;
} libxl_enum_string_table;

struct libxl_event;
typedef LIBXL_TAILQ_ENTRY(struct libxl_event) libxl_ev_link;

/*
 * A boolean variable with an explicit default state.
 *
 * Users should treat this struct as opaque and use the following
 * defined macros and accessor functions.
 *
 * To allow users of the library to naively select all defaults this
 * state is represented as 0. False is < 0 and True is > 0.
 */
typedef struct {
    int val;
} libxl_defbool;

void libxl_defbool_set(libxl_defbool *db, bool b);
/* Resets to default */
void libxl_defbool_unset(libxl_defbool *db);
/* Sets db only if it is currently == default */
void libxl_defbool_setdefault(libxl_defbool *db, bool b);
bool libxl_defbool_is_default(libxl_defbool db);
/* db must not be == default */
bool libxl_defbool_val(libxl_defbool db);

const char *libxl_defbool_to_string(libxl_defbool b);

typedef struct libxl__ctx libxl_ctx;

#define LIBXL_TIMER_MODE_DEFAULT -1
#define LIBXL_MEMKB_DEFAULT ~0ULL

#include "_libxl_types.h"

const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);

typedef struct {
#define XL_SUSPEND_DEBUG 1
#define XL_SUSPEND_LIVE 2
    int flags;
    int (*suspend_callback)(void *, int);
} libxl_domain_suspend_info;

enum {
    ERROR_NONSPECIFIC = -1,
    ERROR_VERSION = -2,
    ERROR_FAIL = -3,
    ERROR_NI = -4,
    ERROR_NOMEM = -5,
    ERROR_INVAL = -6,
    ERROR_BADFAIL = -7,
    ERROR_GUEST_TIMEDOUT = -8,
    ERROR_TIMEDOUT = -9,
    ERROR_NOPARAVIRT = -10,
    ERROR_NOT_READY = -11,
    ERROR_OSEVENT_REG_FAIL = -12,
    ERROR_BUFFERFULL = -13,
    ERROR_UNKNOWN_CHILD = -14,
};


/*
 * Some libxl operations can take a long time.  These functions take a
 * parameter to control their concurrency:
 *     libxl_asyncop_how *ao_how
 *
 * If ao_how==NULL, the function will be synchronous.
 *
 * If ao_how!=NULL, the function will set the operation going, and if
 * this is successful will return 0.  In this case the zero error
 * response does NOT mean that the operation was successful; it just
 * means that it has been successfully started.  It will finish later,
 * perhaps with an error.
 *
 * If ao_how->callback!=NULL, the callback will be called when the
 * operation completes.  The same rules as for libxl_event_hooks
 * apply, including the reentrancy rules and the possibility of
 * "disaster", except that libxl calls ao_how->callback instead of
 * libxl_event_hooks.event_occurs.  (See libxl_event.h.)
 *
 * If ao_how->callback==NULL, a libxl_event will be generated which
 * can be obtained from libxl_event_wait or libxl_event_check.  The
 * event will have type OPERATION_COMPLETE (which is not used
 * elsewhere).
 *
 * Note that it is possible for an asynchronous operation which is to
 * result in a callback to complete during its initiating function
 * call.  In this case the initiating function will return 0
 * indicating the at the operation is "in progress", even though by
 * the time it returns the operation is complete and the callback has
 * already happened.
 *
 * The application must set and use ao_how->for_event (which will be
 * copied into libxl_event.for_user) or ao_how->for_callback (passed
 * to the callback) to determine which operation finished, and it must
 * of course check the rc value for errors.
 *
 * *ao_how does not need to remain valid after the initiating function
 * returns. All other parameters must remain valid for the lifetime of
 * the asynchronous operation, unless otherwise specified.
 *
 * Callbacks may occur on any thread in which the application calls
 * libxl.
 */

typedef struct {
    void (*callback)(libxl_ctx *ctx, int rc, void *for_callback);
    union {
        libxl_ev_user for_event; /* used if callback==NULL */
        void *for_callback; /* passed to callback */
    } u;
} libxl_asyncop_how;

/*
 * Some more complex asynchronous operations can report intermediate
 * progress.  How this is to be reported is controlled, for each
 * function, by a parameter
 *    libxl_asyncprogress_how *aop_FOO_how;
 * for each kind of progress FOO supported by that function.  Each
 * such kind of progress is associated with an event type.
 *
 * The function description will document whether, when, and how
 * many times, the intermediate progress will be reported, and
 * what the corresponding event type(s) are.
 *
 * If aop_FOO_how==NULL, intermediate progress reports are discarded.
 *
 * If aop_FOO_how->callback==NULL, intermediate progress reports
 * generate libxl events which can be obtained from libxl_event_wait
 * or libxl_event_check.
 *
 * If aop_FOO_how->callback!=NULL, libxl will report intermediate
 * progress by calling callback(ctx, &event, for_callback).
 *
 * The rules for these events are otherwise the same as those for
 * ordinary events.  The reentrancy and threading rules for the
 * callback are the same as those for ao completion callbacks.
 *
 * Note that the callback, if provided, is responsible for freeing
 * the event.
 *
 * If callbacks are requested, they will be made, and returned, before
 * the long-running libxl operation is considered finished (so if the
 * long-running libxl operation was invoked with ao_how==NULL then any
 * callbacks will occur strictly before the long-running operation
 * returns).  However, the callbacks may occur on any thread.
 *
 * In general, otherwise, no promises are made about the relative
 * order of callbacks in a multithreaded program.  In particular
 * different callbacks relating to the same long-running operation may
 * be delivered out of order.
 */

typedef struct {
    void (*callback)(libxl_ctx *ctx, libxl_event*, void *for_callback);
    libxl_ev_user for_event; /* always used */
    void *for_callback; /* passed to callback */
} libxl_asyncprogress_how;

#define LIBXL_VERSION 0

typedef struct {
    libxl_domain_create_info c_info;
    libxl_domain_build_info b_info;

    int num_disks, num_vifs, num_pcidevs, num_vfbs, num_vkbs;

    libxl_device_disk *disks;
    libxl_device_nic *vifs;
    libxl_device_pci *pcidevs;
    libxl_device_vfb *vfbs;
    libxl_device_vkb *vkbs;

    libxl_action_on_shutdown on_poweroff;
    libxl_action_on_shutdown on_reboot;
    libxl_action_on_shutdown on_watchdog;
    libxl_action_on_shutdown on_crash;
} libxl_domain_config;
char *libxl_domain_config_to_json(libxl_ctx *ctx, libxl_domain_config *p);

/* context functions */
int libxl_ctx_alloc(libxl_ctx **pctx, int version,
                    unsigned flags /* none currently defined */,
                    xentoollog_logger *lg);
int libxl_ctx_free(libxl_ctx *ctx /* 0 is OK */);

/* domain related functions */

int libxl_domain_create_new(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how);
int libxl_domain_create_restore(libxl_ctx *ctx, libxl_domain_config *d_config,
                                uint32_t *domid, int restore_fd,
                                const libxl_asyncop_how *ao_how,
                                const libxl_asyncprogress_how *aop_console_how);
  /* A progress report will be made via ao_console_how, of type
   * domain_create_console_available, when the domain's primary
   * console is available and can be connected to.
   */

void libxl_domain_config_init(libxl_domain_config *d_config);
void libxl_domain_config_dispose(libxl_domain_config *d_config);
int libxl_domain_remus_start(libxl_ctx *ctx, libxl_domain_remus_info *info,
                             uint32_t domid, int send_fd, int recv_fd);
int libxl_domain_suspend(libxl_ctx *ctx, libxl_domain_suspend_info *info,
                          uint32_t domid, int fd);

/* @param suspend_cancel [from xenctrl.h:xc_domain_resume( @param fast )]
 *   If this parameter is true, use co-operative resume. The guest
 *   must support this.
 */
int libxl_domain_resume(libxl_ctx *ctx, uint32_t domid, int suspend_cancel);
int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_reboot(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_destroy(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_preserve(libxl_ctx *ctx, uint32_t domid, libxl_domain_create_info *info, const char *name_suffix, libxl_uuid new_uuid);

/* get max. number of cpus supported by hypervisor */
int libxl_get_max_cpus(libxl_ctx *ctx);

int libxl_domain_rename(libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name);

  /* if old_name is NULL, any old name is OK; otherwise we check
   * transactionally that the domain has the old old name; if
   * trans is not 0 we use caller's transaction and caller must do retries */

int libxl_domain_pause(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_unpause(libxl_ctx *ctx, uint32_t domid);

int libxl_domain_core_dump(libxl_ctx *ctx, uint32_t domid,
                           const char *filename,
                           const libxl_asyncop_how *ao_how);

int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint32_t target_memkb);
int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid, int32_t target_memkb, int relative, int enforce);
int libxl_get_memory_target(libxl_ctx *ctx, uint32_t domid, uint32_t *out_target);
/* how much free memory in the system a domain needs to be built */
int libxl_domain_need_memory(libxl_ctx *ctx, libxl_domain_build_info *b_info,
                             uint32_t *need_memkb);
/* how much free memory is available in the system */
int libxl_get_free_memory(libxl_ctx *ctx, uint32_t *memkb);
/* wait for a given amount of memory to be free in the system */
int libxl_wait_for_free_memory(libxl_ctx *ctx, uint32_t domid, uint32_t memory_kb, int wait_secs);
/* wait for the memory target of a domain to be reached */
int libxl_wait_for_memory_target(libxl_ctx *ctx, uint32_t domid, int wait_secs);

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass);
int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num, libxl_console_type type);
/* libxl_primary_console_exec finds the domid and console number
 * corresponding to the primary console of the given vm, then calls
 * libxl_console_exec with the right arguments (domid might be different
 * if the guest is using stubdoms).
 * This function can be called after creating the device model, in
 * case of HVM guests, and before libxl_run_bootloader in case of PV
 * guests using pygrub. */
int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm);

/* May be called with info_r == NULL to check for domain's existance */
int libxl_domain_info(libxl_ctx*, libxl_dominfo *info_r,
                      uint32_t domid);
libxl_dominfo * libxl_list_domain(libxl_ctx*, int *nb_domain);
void libxl_dominfo_list_free(libxl_dominfo *list, int nr);
libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx*, int *nb_pool);
void libxl_cpupoolinfo_list_free(libxl_cpupoolinfo *list, int nr);
libxl_vminfo * libxl_list_vm(libxl_ctx *ctx, int *nb_vm);
void libxl_vminfo_list_free(libxl_vminfo *list, int nr);

/*
 * Devices
 * =======
 *
 * Each device is represented by a libxl_device_<TYPE> data structure
 * which is defined via the IDL. In addition some devices have an
 * additional data type libxl_device_<TYPE>_getinfo which contains
 * further runtime information about the device.
 *
 * In addition to the general methods available for libxl types (see
 * "libxl types" above) a common set of methods are available for each
 * device type. These are described below.
 *
 * Querying
 * --------
 *
 * libxl_device_<type>_list(ctx, domid, nr):
 *
 *   Returns an array of libxl_device_<type> length nr representing
 *   the devices attached to the specified domain.
 *
 * libxl_device_<type>_getinfo(ctx, domid, device, info):
 *
 *   Initialises info with details of the given device which must be
 *   attached to the specified domain.
 *
 * Creation / Control
 * ------------------
 *
 * libxl_device_<type>_add(ctx, domid, device):
 *
 *   Adds the given device to the specified domain. This can be called
 *   while the guest is running (hotplug) or before boot (coldplug).
 *
 *   This function only sets up the device but does not wait for the
 *   domain to connect to the device and therefore cannot block on the
 *   guest.
 *
 * libxl_device_<type>_remove(ctx, domid, device):
 *
 *   Removes the given device from the specified domain by performing
 *   an orderly unplug with guest co-operation. This requires that the
 *   guest is running.
 *
 *   This method is currently synchronous and therefore can block
 *   while interacting with the guest.
 *
 * libxl_device_<type>_destroy(ctx, domid, device):
 *
 *   Removes the given device from the specified domain without guest
 *   co-operation. It is guest specific what affect this will have on
 *   a running guest.
 *
 *   This function does not interact with the guest and therefore
 *   cannot block on the guest.
 */

/* Disks */
int libxl_device_disk_add(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);
int libxl_device_disk_remove(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_disk *disk,
                             const libxl_asyncop_how *ao_how);
int libxl_device_disk_destroy(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk);

libxl_device_disk *libxl_device_disk_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk, libxl_diskinfo *diskinfo);

/*
 * Insert a CD-ROM device. A device corresponding to disk must already
 * be attached to the guest.
 */
int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);

/* Network Interfaces */
int libxl_device_nic_add(libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic);
int libxl_device_nic_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_nic *nic,
                            const libxl_asyncop_how *ao_how);
int libxl_device_nic_destroy(libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic);

libxl_device_nic *libxl_device_nic_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_nic_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_nic *nic, libxl_nicinfo *nicinfo);

/* Keyboard */
int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb);
int libxl_device_vkb_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_vkb *vkb,
                            const libxl_asyncop_how *ao_how);
int libxl_device_vkb_destroy(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb);

/* Framebuffer */
int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb);
int libxl_device_vfb_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_vfb *vfb,
                            const libxl_asyncop_how *ao_how);
int libxl_device_vfb_destroy(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb);

/* PCI Passthrough */
int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_destroy(libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
libxl_device_pci *libxl_device_pci_list(libxl_ctx *ctx, uint32_t domid, int *num);

/*
 * Functions related to making devices assignable -- that is, bound to
 * the pciback driver, ready to be given to a guest via
 * libxl_pci_device_add.
 *
 * - ..._add() will unbind the device from its current driver (if
 * already bound) and re-bind it to pciback; at that point it will be
 * ready to be assigned to a VM.  If rebind is set, it will store the
 * path to the old driver in xenstore so that it can be handed back to
 * dom0 on restore.
 *
 * - ..._remove() will unbind the device from pciback, and if
 * rebind is non-zero, attempt to assign it back to the driver
 * from whence it came.
 *
 * - ..._list() will return a list of the PCI devices available to be
 * assigned.
 *
 * add and remove are idempotent: if the device in question is already
 * added or is not bound, the functions will emit a warning but return
 * SUCCESS.
 */
int libxl_device_pci_assignable_add(libxl_ctx *ctx, libxl_device_pci *pcidev, int rebind);
int libxl_device_pci_assignable_remove(libxl_ctx *ctx, libxl_device_pci *pcidev, int rebind);
libxl_device_pci *libxl_device_pci_assignable_list(libxl_ctx *ctx, int *num);

/* CPUID handling */
int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str);
int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str);
void libxl_cpuid_apply_policy(libxl_ctx *ctx, uint32_t domid);
void libxl_cpuid_set(libxl_ctx *ctx, uint32_t domid,
                     libxl_cpuid_policy_list cpuid);

/*
 * Functions for allowing users of libxl to store private data
 * relating to a domain.  The data is an opaque sequence of bytes and
 * is not interpreted or used by libxl.
 *
 * Data is indexed by the userdata userid, which is a short printable
 * ASCII string.  The following list is a registry of userdata userids
 * (the registry may be updated by posting a patch to xen-devel):
 *
 *  userid        Data contents
 *  "xl"          domain config file in xl format, Unix line endings
 *  "libvirt-xml" domain config file in libvirt XML format.  See
 *                http://libvirt.org/formatdomain.html
 *
 * libxl does not enforce the registration of userdata userids or the
 * semantics of the data.  For specifications of the data formats
 * see the code or documentation for the libxl caller in question.
 */
int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen);
  /* If datalen==0, data is not used and the user data for
   * that domain and userdata_userid is deleted. */
int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r);
  /* On successful return, *data_r is from malloc.
   * If there is no data for that domain and userdata_userid,
   * *data_r and *datalen_r will be set to 0.
   * data_r and datalen_r may be 0.
   * On error return, *data_r and *datalen_r are undefined.
   */

int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo);
#define LIBXL_CPUTOPOLOGY_INVALID_ENTRY (~(uint32_t)0)
libxl_cputopology *libxl_get_cpu_topology(libxl_ctx *ctx, int *nr);
void libxl_cputopology_list_free(libxl_cputopology *, int nr);
libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
                                       int *nb_vcpu, int *nrcpus);
void libxl_vcpuinfo_list_free(libxl_vcpuinfo *, int nr);
int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           libxl_cpumap *cpumap);
int libxl_set_vcpuaffinity_all(libxl_ctx *ctx, uint32_t domid,
                               unsigned int max_vcpus, libxl_cpumap *cpumap);
int libxl_set_vcpuonline(libxl_ctx *ctx, uint32_t domid, libxl_cpumap *cpumap);

libxl_scheduler libxl_get_scheduler(libxl_ctx *ctx);

/* Per-scheduler parameters */
int libxl_sched_credit_params_get(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo);
int libxl_sched_credit_params_set(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo);

/* Scheduler Per-domain parameters */

#define LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT    -1
#define LIBXL_DOMAIN_SCHED_PARAM_CAP_DEFAULT       -1
#define LIBXL_DOMAIN_SCHED_PARAM_PERIOD_DEFAULT    -1
#define LIBXL_DOMAIN_SCHED_PARAM_SLICE_DEFAULT     -1
#define LIBXL_DOMAIN_SCHED_PARAM_LATENCY_DEFAULT   -1
#define LIBXL_DOMAIN_SCHED_PARAM_EXTRATIME_DEFAULT -1

int libxl_domain_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                  libxl_domain_sched_params *params);
int libxl_domain_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                  const libxl_domain_sched_params *params);

int libxl_send_trigger(libxl_ctx *ctx, uint32_t domid,
                       libxl_trigger trigger, uint32_t vcpuid);
int libxl_send_sysrq(libxl_ctx *ctx, uint32_t domid, char sysrq);
int libxl_send_debug_keys(libxl_ctx *ctx, char *keys);

typedef struct libxl__xen_console_reader libxl_xen_console_reader;

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear);
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r);
void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr);

uint32_t libxl_vm_get_start_time(libxl_ctx *ctx, uint32_t domid);

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long);
int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name,
                   uint32_t set);
int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid, char* uuid,
                           int auth);
int libxl_tmem_freeable(libxl_ctx *ctx);

int libxl_get_freecpus(libxl_ctx *ctx, libxl_cpumap *cpumap);
int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
                         libxl_scheduler sched,
                         libxl_cpumap cpumap, libxl_uuid *uuid,
                         uint32_t *poolid);
int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid);
int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid);
int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu);
int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu);
int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid);
int libxl_cpupool_info(libxl_ctx *ctx, libxl_cpupoolinfo *info, uint32_t poolid);

int libxl_domid_valid_guest(uint32_t domid);

int libxl_flask_context_to_sid(libxl_ctx *ctx, char *buf, size_t len,
                               uint32_t *ssidref);
int libxl_flask_sid_to_context(libxl_ctx *ctx, uint32_t ssidref, char **buf,
                               size_t *len);
int libxl_flask_getenforce(libxl_ctx *ctx);
int libxl_flask_setenforce(libxl_ctx *ctx, int mode);
int libxl_flask_loadpolicy(libxl_ctx *ctx, void *policy, uint32_t size);

/* misc */

/* Each of these sets or clears the flag according to whether the
 * 2nd parameter is nonzero.  On failure, they log, and
 * return ERROR_FAIL, but also leave errno valid. */
int libxl_fd_set_cloexec(libxl_ctx *ctx, int fd, int cloexec);
int libxl_fd_set_nonblock(libxl_ctx *ctx, int fd, int nonblock);

#include <libxl_event.h>

#endif /* LIBXL_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
