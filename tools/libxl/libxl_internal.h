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

#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <xs.h>
#include <xenctrl.h>

#include "xentoollog.h"

#include <xen/io/xenbus.h>

#include "libxl.h"

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

#define LIBXL_DESTROY_TIMEOUT 10
#define LIBXL_DEVICE_MODEL_START_TIMEOUT 10
#define LIBXL_XENCONSOLE_LIMIT 1048576
#define LIBXL_XENCONSOLE_PROTOCOL "vt100"
#define LIBXL_MAXMEM_CONSTANT 1024
#define LIBXL_PV_EXTRA_MEMORY 1024
#define LIBXL_HVM_EXTRA_MEMORY 2048
#define LIBXL_MIN_DOM0_MEM (128*1024)
#define QEMU_SIGNATURE "DeviceModelRecord0002"
#define STUBDOM_CONSOLE_LOGGING 0
#define STUBDOM_CONSOLE_SAVE 1
#define STUBDOM_CONSOLE_RESTORE 2
#define STUBDOM_CONSOLE_SERIAL 3
#define STUBDOM_SPECIAL_CONSOLES 3

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

struct libxl__ctx {
    xentoollog_logger *lg;
    xc_interface *xch;
    struct xs_handle *xsh;

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

    /* for callers who reap children willy-nilly; caller must only
     * set this after libxl_init and before any other call - or
     * may leave them untouched */
    int (*waitpid_instead)(pid_t pid, int *status, int flags);
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

#define XC_PCI_BDF             "0x%x, 0x%x, 0x%x, 0x%x"
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)         ((devfn) & 0x07)
#define AUTO_PHP_SLOT          0x100
#define SYSFS_PCI_DEV          "/sys/bus/pci/devices"
#define SYSFS_PCIBACK_DRIVER   "/sys/bus/pci/drivers/pciback"
#define XENSTORE_PID_FILE      "/var/run/xenstored.pid"

#define PROC_PCI_NUM_RESOURCES 7
#define PCI_BAR_IO             0x01

#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))

typedef struct {
    /* mini-GC */
    int alloc_maxsize;
    void **alloc_ptrs;
    libxl_ctx *owner;
} libxl__gc;

#define LIBXL_INIT_GC(gc,ctx) do{               \
        (gc).alloc_maxsize = 0;                 \
        (gc).alloc_ptrs = 0;                    \
        (gc).owner = (ctx);                     \
    } while(0)

static inline libxl_ctx *libxl__gc_owner(libxl__gc *gc)
{
    return gc->owner;
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
 */
/* register @ptr in @gc for free on exit from outermost libxl callframe. */
_hidden int libxl__ptr_add(libxl__gc *gc, void *ptr);
/* if this is the outermost libxl callframe then free all pointers in @gc */
_hidden void libxl__free_all(libxl__gc *gc);
/* allocate and zero @bytes. (similar to a gc'd malloc(3)+memzero()) */
_hidden void *libxl__zalloc(libxl__gc *gc, int bytes);
/* allocate and zero memory for an array of @nmemb members of @size each.
 * (similar to a gc'd calloc(3)). */
_hidden void *libxl__calloc(libxl__gc *gc, size_t nmemb, size_t size);
/* change the size of the memory block pointed to by @ptr to @new_size bytes.
 * unlike other allocation functions here any additional space between the
 * oldsize and @new_size is not initialised (similar to a gc'd realloc(3)). */
_hidden void *libxl__realloc(libxl__gc *gc, void *ptr, size_t new_size);
/* print @fmt into an allocated string large enoughto contain the result.
 * (similar to gc'd asprintf(3)). */
_hidden char *libxl__sprintf(libxl__gc *gc, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
/* duplicate the string @c (similar to a gc'd strdup(3)). */
_hidden char *libxl__strdup(libxl__gc *gc, const char *c);
/* duplicate at most @n bytes of string @c (similar to a gc'd strndup(3)). */
_hidden char *libxl__strndup(libxl__gc *gc, const char *c, size_t n);
/* strip the last path component from @s and return as a newly allocated
 * string. (similar to a gc'd dirname(3)). */
_hidden char *libxl__dirname(libxl__gc *gc, const char *s);

_hidden char **libxl__xs_kvs_of_flexarray(libxl__gc *gc, flexarray_t *array, int length);

_hidden int libxl__xs_writev(libxl__gc *gc, xs_transaction_t t,
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

/* from xl_dom */
_hidden libxl_domain_type libxl__domain_type(libxl__gc *gc, uint32_t domid);
_hidden int libxl__domain_shutdown_reason(libxl__gc *gc, uint32_t domid);
#define LIBXL__DOMAIN_IS_TYPE(gc, domid, type) \
    libxl__domain_type((gc), (domid)) == LIBXL_DOMAIN_TYPE_##type
typedef struct {
    uint32_t store_port;
    unsigned long store_mfn;

    uint32_t console_port;
    unsigned long console_mfn;
    unsigned long vm_generationid_addr;
} libxl__domain_build_state;

_hidden int libxl__build_pre(libxl__gc *gc, uint32_t domid,
              libxl_domain_build_info *info, libxl__domain_build_state *state);
_hidden int libxl__build_post(libxl__gc *gc, uint32_t domid,
               libxl_domain_build_info *info, libxl__domain_build_state *state,
               char **vms_ents, char **local_ents);

_hidden int libxl__build_pv(libxl__gc *gc, uint32_t domid,
             libxl_domain_build_info *info, libxl__domain_build_state *state);
_hidden int libxl__build_hvm(libxl__gc *gc, uint32_t domid,
              libxl_domain_build_info *info,
              libxl_device_model_info *dm_info,
              libxl__domain_build_state *state);

_hidden int libxl__domain_rename(libxl__gc *gc, uint32_t domid,
                                 const char *old_name, const char *new_name,
                                 xs_transaction_t trans);

_hidden int libxl__domain_restore_common(libxl__gc *gc, uint32_t domid,
                                         libxl_domain_build_info *info,
                                         libxl__domain_build_state *state,
                                         int fd);
_hidden int libxl__domain_suspend_common(libxl__gc *gc, uint32_t domid, int fd,
                                         libxl_domain_type type,
                                         int live, int debug);
_hidden const char *libxl__device_model_savefile(libxl__gc *gc, uint32_t domid);
_hidden int libxl__domain_save_device_model(libxl__gc *gc, uint32_t domid, int fd);
_hidden void libxl__userdata_destroyall(libxl__gc *gc, uint32_t domid);

_hidden int libxl__domain_pvcontrol_available(libxl__gc *gc, uint32_t domid);
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
                                      libxl_device_console *console,
                                      libxl__domain_build_state *state);

_hidden int libxl__device_generic_add(libxl__gc *gc, libxl__device *device,
                             char **bents, char **fents);
_hidden char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device);
_hidden char *libxl__device_frontend_path(libxl__gc *gc, libxl__device *device);
_hidden int libxl__parse_backend_path(libxl__gc *gc, const char *path,
                                      libxl__device *dev);
_hidden int libxl__device_remove(libxl__gc *gc, libxl__device *dev, int wait);
_hidden int libxl__device_destroy(libxl__gc *gc, libxl__device *dev);
_hidden int libxl__devices_destroy(libxl__gc *gc, uint32_t domid);
_hidden int libxl__wait_for_backend(libxl__gc *gc, char *be_path, char *state);

/* Handler for the libxl__wait_for_device_state callback */
/*
 * libxl__device_state_handler - Handler for the libxl__wait_for_device_state
 * gc: allocation pool
 * l1: array containing the path and token
 * state: string that contains the state of the device
 *
 * Returns 0 on success, and < 0 on error.
 */
typedef int libxl__device_state_handler(libxl__gc *gc, char **l1, char *state);

/*
 * libxl__wait_for_device_state - waits a given time for a device to
 * reach a given state
 * gc: allocation pool
 * tv: timeval struct containing the maximum time to wait
 * state: state to wait for (check xen/io/xenbus.h)
 * handler: callback function to execute when state is reached
 *
 * Returns 0 on success, and < 0 on error.
 */
_hidden int libxl__wait_for_device_state(libxl__gc *gc, struct timeval *tv,
                                         XenbusState state,
                                         libxl__device_state_handler handler);

/*
 * libxl__try_phy_backend - Check if there's support for the passed
 * type of file using the PHY backend
 * st_mode: mode_t of the file, as returned by stat function
 *
 * Returns 0 on success, and < 0 on error.
 */
_hidden int libxl__try_phy_backend(mode_t st_mode);

/* from libxl_pci */

_hidden int libxl__device_pci_add(libxl__gc *gc, uint32_t domid, libxl_device_pci *pcidev, int starting);
_hidden int libxl__create_pci_backend(libxl__gc *gc, uint32_t domid,
                                      libxl_device_pci *pcidev, int num);
_hidden int libxl__device_pci_destroy_all(libxl__gc *gc, uint32_t domid);

/* xl_exec */

 /* higher-level double-fork and separate detach eg as for device models */

typedef struct {
    /* put this in your own status structure as returned to application */
    /* all fields are private to libxl_spawn_... */
    pid_t intermediate;
    int fd;
    char *what; /* malloc'd in spawn_spawn */
} libxl__spawn_starting;

typedef struct {
    char *dom_path; /* from libxl_malloc, only for libxl_spawner_record_pid */
    const char *pid_path; /* only for libxl_spawner_record_pid */
    int domid;
    libxl__spawn_starting *for_spawn;
} libxl__spawner_starting;

/*
 * libxl__spawn_spawn - Create a new process
 * gc: allocation pool
 * for_spawn: malloc'd pointer to libxl__spawn_starting (optional)
 * what: string describing the spawned process
 * intermediate_hook: helper to record pid, such as libxl_spawner_record_pid
 * hook_data: data to pass to the hook function
 *
 * Logs errors.  A copy of "what" is taken. 
 * Return values:
 *  < 0   error, for_spawn need not be detached
 *   +1   caller is the parent, must call detach on *for_spawn eventually
 *    0   caller is now the inner child, should probably call libxl__exec
 * Caller, may pass 0 for for_spawn, in which case no need to detach.
 */
_hidden int libxl__spawn_spawn(libxl__gc *gc,
                      libxl__spawn_starting *for_spawn,
                      const char *what,
                      void (*intermediate_hook)(void *for_spawn, pid_t innerchild),
                      void *hook_data);

/*
 * libxl_spawner_record_pid - Record given pid in xenstore
 * for_spawn: malloc'd pointer to libxl__spawn_starting (optional)
 * innerchild: pid of the child
 *
 * This function is passed as intermediate_hook to libxl__spawn_spawn.
 */
_hidden void libxl_spawner_record_pid(void *for_spawn, pid_t innerchild);

/*
 * libxl__spawn_confirm_offspring_startup - Wait for child state
 * gc: allocation pool
 * timeout: how many seconds to wait for the child
 * what: string describing the spawned process
 * path: path to the state file in xenstore
 * state: expected string to wait for in path (optional)
 * starting: malloc'd pointer to libxl__spawner_starting
 *
 * Returns 0 on success, and < 0 on error.
 *
 * This function waits the given timeout for the given path to appear
 * in xenstore, and optionally for state in path.
 * The intermediate process created in libxl__spawn_spawn is killed.
 * The memory referenced by starting->for_spawn and starting is free'd.
 */
_hidden int libxl__spawn_confirm_offspring_startup(libxl__gc *gc,
                                       uint32_t timeout, char *what,
                                       char *path, char *state,
                                       libxl__spawner_starting *starting);

/*
 * libxl__wait_for_offspring - Wait for child state
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
 * Otherwise libxl__wait_for_offspring returns.
 */
_hidden int libxl__wait_for_offspring(libxl__gc *gc,
                                 uint32_t domid,
                                 uint32_t timeout, char *what,
                                 char *path, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata);

/*
 * libxl__spawn_detach - Kill intermediate process from spawn_spawn
 * gc: allocation pool
 * for_spawn: malloc'd pointer to libxl__spawn_starting (optional)
 *
 * Returns 0 on success, and < 0 on error.
 *
 * Logs errors.  Idempotent, but only permitted after successful
 * call to libxl__spawn_spawn, and no point calling it again if it fails.
 */
_hidden int libxl__spawn_detach(libxl__gc *gc,
                       libxl__spawn_starting *for_spawn);

/*
 * libxl__spawn_check - Check intermediate child process
 * gc: allocation pool
 * for_spawn: malloc'd pointer to libxl__spawn_starting (optional)
 *
 * Returns 0 on success, and < 0 on error.
 *
 * Logs errors but also returns them.
 * Caller must still call detach.
 */
_hidden int libxl__spawn_check(libxl__gc *gc,
                       libxl__spawn_starting *for_spawn);

 /* low-level stuff, for synchronous subprocesses etc. */

_hidden void libxl__exec(int stdinfd, int stdoutfd, int stderrfd,
               const char *arg0, char **args); // logs errors, never returns

/* from xl_create */
_hidden int libxl__domain_make(libxl__gc *gc, libxl_domain_create_info *info, uint32_t *domid);
_hidden int libxl__domain_build(libxl__gc *gc,
                                libxl_domain_build_info *info,
                                libxl_device_model_info *dm_info,
                                uint32_t domid,
                                libxl__domain_build_state *state);

/* for device model creation */
_hidden const char *libxl__domain_device_model(libxl__gc *gc,
                                               libxl_device_model_info *info);
_hidden int libxl__create_device_model(libxl__gc *gc,
                              libxl_device_model_info *info,
                              libxl_device_disk *disk, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl__spawner_starting **starting_r);
_hidden int libxl__create_xenpv_qemu(libxl__gc *gc, uint32_t domid,
                              libxl_device_model_info *dm_info,
                              libxl_device_vfb *vfb,
                              libxl__spawner_starting **starting_r);
_hidden int libxl__need_xenpv_qemu(libxl__gc *gc,
        int nr_consoles, libxl_device_console *consoles,
        int nr_vfbs, libxl_device_vfb *vfbs,
        int nr_disks, libxl_device_disk *disks);
  /* Caller must either: pass starting_r==0, or on successful
   * return pass *starting_r (which will be non-0) to
   * libxl__confirm_device_model_startup or libxl__detach_device_model. */
_hidden int libxl__confirm_device_model_startup(libxl__gc *gc,
                              libxl_device_model_info *dm_info,
                              libxl__spawner_starting *starting);
_hidden int libxl__detach_device_model(libxl__gc *gc, libxl__spawner_starting *starting);
_hidden int libxl__wait_for_device_model(libxl__gc *gc,
                                uint32_t domid, char *state,
                                libxl__spawn_starting *spawning,
                                int (*check_callback)(libxl__gc *gc,
                                                      uint32_t domid,
                                                      const char *state,
                                                      void *userdata),
                                void *check_callback_userdata);

_hidden int libxl__destroy_device_model(libxl__gc *gc, uint32_t domid);

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
 */
_hidden void libxl__device_destroy_tapdisk(libxl__gc *gc, char *be_path);

_hidden char *libxl__uuid2string(libxl__gc *gc, const libxl_uuid uuid);

struct libxl__xen_console_reader {
    char *buffer;
    unsigned int size;
    unsigned int count;
    unsigned int clear;
    unsigned int incremental;
    unsigned int index;
};

_hidden int libxl__error_set(libxl__gc *gc, int code);

_hidden int libxl__file_reference_map(libxl_file_reference *f);
_hidden int libxl__file_reference_unmap(libxl_file_reference *f);

_hidden int libxl__e820_alloc(libxl__gc *gc, uint32_t domid, libxl_domain_config *d_config);

/* parse the string @s as a sequence of 6 colon separated bytes in to @mac */
_hidden int libxl__parse_mac(const char *s, libxl_mac mac);
/* compare mac address @a and @b. 0 if the same, -ve if a<b and +ve if a>b */
_hidden int libxl__compare_macs(libxl_mac *a, libxl_mac *b);

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

/* from libxl_qmp */
typedef struct libxl__qmp_handler libxl__qmp_handler;

/* Initialise and connect to the QMP socket.
 *   Return an handler or NULL if there is an error
 */
_hidden libxl__qmp_handler *libxl__qmp_initialize(libxl_ctx *ctx,
                                                  uint32_t domid);
/* ask to QEMU the serial port information and store it in xenstore. */
_hidden int libxl__qmp_query_serial(libxl__qmp_handler *qmp);
_hidden int libxl__qmp_pci_add(libxl__gc *gc, int d, libxl_device_pci *pcidev);
_hidden int libxl__qmp_pci_del(libxl__gc *gc, int domid,
                               libxl_device_pci *pcidev);
/* Save current QEMU state into fd. */
_hidden int libxl__qmp_migrate(libxl__gc *gc, int domid, int fd);
/* close and free the QMP handler */
_hidden void libxl__qmp_close(libxl__qmp_handler *qmp);
/* remove the socket file, if the file has already been removed,
 * nothing happen */
_hidden void libxl__qmp_cleanup(libxl__gc *gc, uint32_t domid);

/* this helper calls qmp_initialize, query_serial and qmp_close */
_hidden int libxl__qmp_initializations(libxl_ctx *ctx, uint32_t domid);

/* from libxl_json */
#include <yajl/yajl_gen.h>

_hidden yajl_gen_status libxl__yajl_gen_asciiz(yajl_gen hand, const char *str);
_hidden yajl_gen_status libxl__yajl_gen_enum(yajl_gen hand, const char *str);

typedef enum {
    JSON_ERROR,
    JSON_NULL,
    JSON_TRUE,
    JSON_FALSE,
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

_hidden libxl__json_object *libxl__json_array_get(const libxl__json_object *o,
                                                  int i);
_hidden
libxl__json_map_node *libxl__json_map_node_get(const libxl__json_object *o,
                                               int i);
_hidden const libxl__json_object *libxl__json_map_get(const char *key,
                                          const libxl__json_object *o,
                                          libxl__json_node_type expected_type);
_hidden void libxl__json_object_free(libxl__gc *gc, libxl__json_object *obj);

_hidden libxl__json_object *libxl__json_parse(libxl__gc *gc, const char *s);

  /* Based on /local/domain/$domid/dm-version xenstore key
   * default is qemu xen traditional */
_hidden libxl_device_model_version
libxl__device_model_version_running(libxl__gc *gc, uint32_t domid);


/*
 * Convenience macros.
 */


/*
 * All of these assume (or define)
 *    libxl__gc *gc;
 * as a local variable.
 */

#define GC_INIT(ctx)  libxl__gc gc[1]; LIBXL_INIT_GC(gc[0],ctx)
#define GC_FREE       libxl__free_all(gc)
#define CTX           libxl__gc_owner(gc)


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


#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
