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

#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

#include <xs.h>
#include <xenctrl.h>
#include "xentoollog.h"

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define _hidden __attribute__((visibility("hidden")))
#define _protected __attribute__((visibility("protected")))
#else
#define _hidden
#define _protected
#endif

#include "flexarray.h"
#include "libxl_utils.h"

#define LIBXL_DESTROY_TIMEOUT 10
#define LIBXL_DEVICE_MODEL_START_TIMEOUT 10
#define LIBXL_XENCONSOLE_LIMIT 1048576
#define LIBXL_XENCONSOLE_PROTOCOL "vt100"
#define LIBXL_MAXMEM_CONSTANT 1024
#define QEMU_SIGNATURE "QemuDeviceModelRecord"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define XL_LOGGING_ENABLED

#ifdef XL_LOGGING_ENABLED
#define XL_LOG(ctx, loglevel, _f, _a...)   xl_log(ctx, loglevel, -1, __FILE__, __LINE__, __func__, _f, ##_a)
#define XL_LOG_ERRNO(ctx, loglevel, _f, _a...)   xl_log(ctx, loglevel, errno, __FILE__, __LINE__, __func__, _f, ##_a)
#define XL_LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)   xl_log(ctx, loglevel, errnoval, __FILE__, __LINE__, __func__, _f, ##_a)
#else
#define XL_LOG(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNO(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)
#endif
  /* all of these macros preserve errno (saving and restoring) */

/* logging */
_hidden void xl_logv(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
             const char *file /* may be 0 */, int line /* ignored if !file */,
             const char *func /* may be 0 */,
             char *fmt, va_list al)
     __attribute__((format(printf,7,0)));

_hidden void xl_log(libxl_ctx *ctx, xentoollog_level msglevel, int errnoval,
            const char *file /* may be 0 */, int line /* ignored if !file */,
            const char *func /* may be 0 */,
            char *fmt, ...)
     __attribute__((format(printf,7,8)));

     /* these functions preserve errno (saving and restoring) */


typedef enum {
    DEVICE_VIF = 1,
    DEVICE_VIF2,
    DEVICE_VBD,
    DEVICE_TAP,
    DEVICE_PCI,
    DEVICE_VFB,
    DEVICE_VKBD,
    DEVICE_CONSOLE,
} libxl_device_kinds;

#define is_valid_device_kind(kind) (((kind) >= DEVICE_VIF) && ((kind) <= DEVICE_CONSOLE))

typedef struct {
    uint32_t backend_devid;
    uint32_t backend_domid;
    uint32_t devid;
    uint32_t domid;
    libxl_device_kinds backend_kind;
    libxl_device_kinds kind;
} libxl_device;

#define XC_PCI_BDF             "0x%x, 0x%x, 0x%x, 0x%x"
#define AUTO_PHP_SLOT          0x100
#define SYSFS_PCI_DEV          "/sys/bus/pci/devices"
#define SYSFS_PCIBACK_DRIVER   "/sys/bus/pci/drivers/pciback"

#define PROC_PCI_NUM_RESOURCES 7
#define PCI_BAR_IO             0x01

#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))

_hidden int xs_writev(struct xs_handle *xsh, xs_transaction_t t, char *dir, char *kvs[]);

typedef struct {
    /* mini-GC */
    int alloc_maxsize;
    void **alloc_ptrs;
    libxl_ctx *owner;
} libxl_gc;

#define LIBXL_INIT_GC(ctx) (libxl_gc){ .alloc_maxsize = 0, .alloc_ptrs = 0, .owner = ctx }
static inline libxl_ctx *libxl_gc_owner(libxl_gc *gc)
{
    return gc->owner;
}

/* memory allocation tracking/helpers */
_hidden int libxl_ptr_add(libxl_gc *gc, void *ptr);
_hidden void libxl_free_all(libxl_gc *gc);
_hidden void *libxl_zalloc(libxl_gc *gc, int bytes);
_hidden void *libxl_calloc(libxl_gc *gc, size_t nmemb, size_t size);
_hidden char *libxl_sprintf(libxl_gc *gc, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
_hidden char *libxl_strdup(libxl_gc *gc, const char *c);
_hidden char *libxl_dirname(libxl_gc *gc, const char *s);

_hidden char **libxl_xs_kvs_of_flexarray(libxl_gc *gc, flexarray_t *array, int length);
_hidden int libxl_xs_writev(libxl_gc *gc, xs_transaction_t t,
                    char *dir, char **kvs);
_hidden int libxl_xs_write(libxl_gc *gc, xs_transaction_t t,
                   char *path, char *fmt, ...) PRINTF_ATTRIBUTE(4, 5);
_hidden char *libxl_xs_get_dompath(libxl_gc *gc, uint32_t domid); // logs errs
_hidden char *libxl_xs_read(libxl_gc *gc, xs_transaction_t t, char *path);
_hidden char **libxl_xs_directory(libxl_gc *gc, xs_transaction_t t, char *path, unsigned int *nb);

/* from xl_dom */
_hidden int is_hvm(libxl_ctx *ctx, uint32_t domid);
_hidden int get_shutdown_reason(libxl_ctx *ctx, uint32_t domid);
#define dominfo_get_shutdown_reason(info) (((info)->flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask)

_hidden int build_pre(libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state);
_hidden int build_post(libxl_ctx *ctx, uint32_t domid,
               libxl_domain_build_info *info, libxl_domain_build_state *state,
               char **vms_ents, char **local_ents);

_hidden int build_pv(libxl_ctx *ctx, uint32_t domid,
             libxl_domain_build_info *info, libxl_domain_build_state *state);
_hidden int build_hvm(libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state);

_hidden int restore_common(libxl_ctx *ctx, uint32_t domid,
                   libxl_domain_build_info *info, libxl_domain_build_state *state, int fd);
_hidden int core_suspend(libxl_ctx *ctx, uint32_t domid, int fd, int hvm, int live, int debug);
_hidden int save_device_model(libxl_ctx *ctx, uint32_t domid, int fd);
_hidden void libxl__userdata_destroyall(libxl_ctx *ctx, uint32_t domid);

/* from xl_device */
_hidden char *device_disk_backend_type_of_phystype(libxl_disk_phystype phystype);
_hidden char *device_disk_string_of_phystype(libxl_disk_phystype phystype);

_hidden int device_physdisk_major_minor(const char *physpath, int *major, int *minor);
_hidden int device_disk_dev_number(char *virtpath);

_hidden int libxl_device_generic_add(libxl_ctx *ctx, libxl_device *device,
                             char **bents, char **fents);
_hidden int libxl_device_del(libxl_ctx *ctx, libxl_device *dev, int wait);
_hidden int libxl_device_destroy(libxl_ctx *ctx, char *be_path, int force);
_hidden int libxl_devices_destroy(libxl_ctx *ctx, uint32_t domid, int force);
_hidden int libxl_wait_for_device_model(libxl_ctx *ctx,
                                uint32_t domid, char *state,
                                int (*check_callback)(libxl_ctx *ctx,
                                                      uint32_t domid,
                                                      const char *state,
                                                      void *userdata),
                                void *check_callback_userdata);
_hidden int libxl_wait_for_backend(libxl_ctx *ctx, char *be_path, char *state);

/* from xenguest (helper */
_hidden int hvm_build_set_params(xc_interface *handle, uint32_t domid,
                         libxl_domain_build_info *info,
                         int store_evtchn, unsigned long *store_mfn,
                         int console_evtchn, unsigned long *console_mfn);

/* xl_exec */

 /* higher-level double-fork and separate detach eg as for device models */

typedef struct {
    /* put this in your own status structure as returned to application */
    /* all fields are private to libxl_spawn_... */
    pid_t intermediate;
    char *what; /* malloc'd in spawn_spawn */
}  libxl_spawn_starting;

struct libxl__device_model_starting {
    libxl_spawn_starting *for_spawn; /* first! */
    char *dom_path; /* from libxl_malloc, only for dm_xenstore_record_pid */
    int domid;
};

_hidden int libxl_spawn_spawn(libxl_ctx *ctx,
                      libxl_device_model_starting *starting,
                      const char *what,
                      void (*intermediate_hook)(void *for_spawn, pid_t innerchild));
  /* Logs errors.  A copy of "what" is taken.  Return values:
   *  < 0   error, for_spawn need not be detached
   *   +1   caller is the parent, must call detach on *for_spawn eventually
   *    0   caller is now the inner child, should probably call libxl_exec
   * Caller, may pass 0 for for_spawn, in which case no need to detach.
   */
_hidden int libxl_spawn_detach(libxl_ctx *ctx,
                       libxl_spawn_starting *for_spawn);
  /* Logs errors.  Idempotent, but only permitted after successful
   * call to libxl_spawn_spawn, and no point calling it again if it fails. */
_hidden int libxl_spawn_check(libxl_ctx *ctx,
                      void *for_spawn);
  /* Logs errors but also returns them.
   * for_spawn must actually be a  libxl_spawn_starting*  but
   * we take void* so you can pass this function directly to
   * libxl_wait_for_device_model.  Caller must still call detach. */

 /* low-level stuff, for synchronous subprocesses etc. */

_hidden void libxl_exec(int stdinfd, int stdoutfd, int stderrfd, char *arg0, char **args); // logs errors, never returns
_hidden void libxl_log_child_exitstatus(libxl_gc *gc,
                                const char *what, pid_t pid, int status);

_hidden char *libxl_abs_path(libxl_gc *gc, char *s, const char *path);

#define XL_LOG_DEBUG   XTL_DEBUG
#define XL_LOG_INFO    XTL_INFO
#define XL_LOG_WARNING XTL_WARN
#define XL_LOG_ERROR   XTL_ERROR

_hidden char *_libxl_domid_to_name(libxl_gc *gc, uint32_t domid);
_hidden char *_libxl_poolid_to_name(libxl_gc *gc, uint32_t poolid);

/*
 * blktap2 support
 */

/* libxl_blktap_enabled:
 *    return true if blktap/blktap2 support is available.
 */
int libxl_blktap_enabled(libxl_gc *gc);

/* libxl_blktap_devpath:
 *    Argument: path and disk image as specified in config file.
 *      The type specifies whether this is aio, qcow, qcow2, etc.
 *    returns device path xenstore wants to have. returns NULL
 *      if no device corresponds to the disk.
 */
const char *libxl_blktap_devpath(libxl_gc *gc,
                                 const char *disk,
                                 libxl_disk_phystype phystype);

_hidden char *libxl_uuid2string(libxl_gc *gc, const libxl_uuid uuid);

struct libxl__xen_console_reader {
    char *buffer;
    unsigned int size;
    unsigned int count;
    unsigned int clear;
    unsigned int incremental;
    unsigned int index;
};

_hidden int libxl_error_set(libxl_ctx *ctx, int code);

_hidden int libxl__file_reference_map(libxl_file_reference *f);
_hidden int libxl__file_reference_unmap(libxl_file_reference *f);

#endif
