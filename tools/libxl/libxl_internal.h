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
#define XL_LOG_ERRNOVAL(ctx, errnoval, loglevel, _f, _a...)   xl_log(ctx, loglevel, errnoval, __FILE__, __LINE__, __func__, _f, ##_a)
#else
#define XL_LOG(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNO(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)
#endif

#define XL_LOG_DEBUG 3
#define XL_LOG_INFO 2
#define XL_LOG_WARNING 1
#define XL_LOG_ERROR 0

/* logging */
void xl_logv(struct libxl_ctx *ctx, int errnoval, int loglevel, const char *file, int line, const char *func, char *fmt, va_list al);
void xl_log(struct libxl_ctx *ctx, int errnoval, int loglevel, const char *file, int line, const char *func, char *fmt, ...);


typedef enum {
    DEVICE_VIF = 1,
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
#define PROC_PCI_NUM_RESOURCES 7
#define PCI_BAR_IO             0x01

#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define string_of_uuid(ctx, u) \
    libxl_sprintf(ctx, UUID_FMT, \
                (u)[0], (u)[1], (u)[2], (u)[3], (u)[4], (u)[5], (u)[6], (u)[7], \
                (u)[8], (u)[9], (u)[10], (u)[11], (u)[12], (u)[13], (u)[14], (u)[15])

int xs_writev(struct xs_handle *xsh, xs_transaction_t t, char *dir, char *kvs[]);

/* memory allocation tracking/helpers */
int libxl_ptr_add(struct libxl_ctx *ctx, void *ptr);
int libxl_free(struct libxl_ctx *ctx, void *ptr);
int libxl_free_all(struct libxl_ctx *ctx);
void *libxl_zalloc(struct libxl_ctx *ctx, int bytes);
void *libxl_calloc(struct libxl_ctx *ctx, size_t nmemb, size_t size);
char *libxl_sprintf(struct libxl_ctx *ctx, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
char *libxl_dirname(struct libxl_ctx *ctx, const char *s);

char **libxl_xs_kvs_of_flexarray(struct libxl_ctx *ctx, flexarray_t *array, int length);
int libxl_xs_writev(struct libxl_ctx *ctx, xs_transaction_t t,
                    char *dir, char **kvs);
int libxl_xs_write(struct libxl_ctx *ctx, xs_transaction_t t,
                   char *path, char *fmt, ...);
char *libxl_xs_get_dompath(struct libxl_ctx *ctx, uint32_t domid); // logs errs
char *libxl_xs_read(struct libxl_ctx *ctx, xs_transaction_t t, char *path);
char **libxl_xs_directory(struct libxl_ctx *ctx, xs_transaction_t t, char *path, unsigned int *nb);

/* from xl_dom */
int is_hvm(struct libxl_ctx *ctx, uint32_t domid);
int get_shutdown_reason(struct libxl_ctx *ctx, uint32_t domid);
#define dominfo_get_shutdown_reason(info) (((info)->flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask)

int build_pre(struct libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state);
int build_post(struct libxl_ctx *ctx, uint32_t domid,
               libxl_domain_build_info *info, libxl_domain_build_state *state,
               char **vms_ents, char **local_ents);

int build_pv(struct libxl_ctx *ctx, uint32_t domid,
             libxl_domain_build_info *info, libxl_domain_build_state *state);
int build_hvm(struct libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state);

int restore_common(struct libxl_ctx *ctx, uint32_t domid,
                   libxl_domain_build_info *info, libxl_domain_build_state *state, int fd);
int core_suspend(struct libxl_ctx *ctx, uint32_t domid, int fd, int hvm, int live, int debug);
int save_device_model(struct libxl_ctx *ctx, uint32_t domid, int fd);

/* from xl_device */
char *device_disk_backend_type_of_phystype(libxl_disk_phystype phystype);
char *device_disk_string_of_phystype(libxl_disk_phystype phystype);

int device_physdisk_major_minor(char *physpath, int *major, int *minor);
int device_virtdisk_major_minor(char *virtpath, int *major, int *minor);
int device_disk_dev_number(char *virtpath);

int libxl_device_generic_add(struct libxl_ctx *ctx, libxl_device *device,
                             char **bents, char **fents);
int libxl_device_del(struct libxl_ctx *ctx, libxl_device *dev, int wait);
int libxl_device_destroy(struct libxl_ctx *ctx, char *be_path, int force);
int libxl_devices_destroy(struct libxl_ctx *ctx, uint32_t domid, int force);
int libxl_wait_for_device_model(struct libxl_ctx *ctx,
                                uint32_t domid, char *state,
                                int (*check_callback)(struct libxl_ctx *ctx,
                                                      void *userdata),
                                void *check_callback_userdata);
int libxl_wait_for_backend(struct libxl_ctx *ctx, char *be_path, char *state);
int libxl_device_pci_flr(struct libxl_ctx *ctx, unsigned int domain, unsigned int bus,
                         unsigned int dev, unsigned int func);

/* from xenguest (helper */
int hvm_build_set_params(int handle, uint32_t domid,
                         int apic, int acpi, int pae, int nx, int viridian,
                         int vcpus, int store_evtchn, unsigned long *store_mfn);

/* xl_exec */

 /* higher-level double-fork and separate detach eg as for device models */

struct libxl_spawn_starting {
    /* put this in your own stateu structure as returned to application */
    /* all fields are private to libxl_spawn_... */
    pid_t intermediate;
    char *what; /* malloc'd in spawn_spawn */
};

struct libxl_device_model_starting {
    struct libxl_spawn_starting *for_spawn; /* first! */
    char *dom_path; /* from libxl_malloc, only for dm_xenstore_record_pid */
    int domid;
};

int libxl_spawn_spawn(struct libxl_ctx *ctx,
                      libxl_device_model_starting *starting,
                      const char *what,
                      void (*intermediate_hook)(void *for_spawn, pid_t innerchild));
  /* Logs errors.  A copy of "what" is taken.  Return values:
   *  < 0   error, for_spawn need not be detached
   *   +1   caller is now the inner child, should probably call libxl_exec
   *    0   caller is the parent, must call detach on *for_spawn eventually
   * Caller, may pass 0 for for_spawn, in which case no need to detach.
   */
int libxl_spawn_detach(struct libxl_ctx *ctx,
                       struct libxl_spawn_starting *for_spawn);
  /* Logs errors.  Idempotent, but only permitted after successful
   * call to libxl_spawn_spawn, and no point calling it again if it fails. */
int libxl_spawn_check(struct libxl_ctx *ctx,
                      void *for_spawn);
  /* Logs errors but also returns them.
   * for_spawn must actually be a  struct libxl_spawn_starting*  but
   * we take void* so you can pass this function directly to
   * libxl_wait_for_device_model.  Caller must still call detach. */

 /* low-level stuff, for synchronous subprocesses etc. */

void libxl_exec(int stdinfd, int stdoutfd, int stderrfd, char *arg0, char **args); // logs errors, never returns
void libxl_log_child_exitstatus(struct libxl_ctx *ctx,
                                const char *what, pid_t pid, int status);

#endif

