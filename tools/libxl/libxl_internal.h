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
# define LIBXL_INTERNAL_H

#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

#include <xs.h>
#include <xenctrl.h>

#include "flexarray.h"
#include "libxl_utils.h"

#define LIBXL_DESTROY_TIMEOUT 10

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))


#define XL_LOGGING_ENABLED

#ifdef XL_LOGGING_ENABLED
#define XL_LOG(ctx, loglevel, _f, _a...)   xl_log(ctx, loglevel, __FILE__, __LINE__, __func__, _f, ##_a)
#else
#define XL_LOG(ctx, loglevel, _f, _a...)
#endif

#define XL_LOG_DEBUG 3
#define XL_LOG_INFO 2
#define XL_LOG_WARNING 1
#define XL_LOG_ERROR 0

void xl_log(struct libxl_ctx *ctx, int loglevel, const char *file, int line, const char *func, char *fmt, ...);

typedef struct {
    uint32_t store_port;
    unsigned long store_mfn;
    uint32_t console_port;
    unsigned long console_mfn;
} libxl_domain_build_state;

typedef enum {
    DEVICE_VIF,
    DEVICE_VBD,
    DEVICE_TAP,
    DEVICE_PCI,
    DEVICE_VFB,
    DEVICE_VKBD,
} libxl_device_kinds;

typedef struct {
    uint32_t backend_devid;
    uint32_t backend_domid;
    uint32_t devid;
    uint32_t domid;
    libxl_device_kinds backend_kind;
    libxl_device_kinds kind;
} libxl_device;

#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))

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
char *libxl_xs_get_dompath(struct libxl_ctx *ctx, uint32_t domid);
char *libxl_xs_read(struct libxl_ctx *ctx, xs_transaction_t t, char *path);
char **libxl_xs_directory(struct libxl_ctx *ctx, xs_transaction_t t, char *path, unsigned int *nb);

/* from xd_dom */
int is_hvm(struct libxl_ctx *ctx, uint32_t domid);
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

/* from xd_device */
char *device_disk_backend_type_of_phystype(libxl_disk_phystype phystype);
char *device_disk_string_of_phystype(libxl_disk_phystype phystype);

int device_disk_major_minor(char *virtpath, int *major, int *minor);
int device_disk_dev_number(char *virtpath);

int libxl_device_generic_add(struct libxl_ctx *ctx, libxl_device *device,
                             char **bents, char **fents);
int libxl_device_destroy(struct libxl_ctx *ctx, char *be_path, int force);
int libxl_devices_destroy(struct libxl_ctx *ctx, uint32_t domid, int force);

/* from xenguest (helper */
int hvm_build_set_params(int handle, uint32_t domid,
                         int apic, int acpi, int pae, int nx, int viridian,
                         int vcpus, int store_evtchn, unsigned long *store_mfn);

/* xd_exec */
int libxl_exec(struct libxl_ctx *ctx, int stdinfd, int stdoutfd, int stderrfd,
               char *arg0, char **args);

#endif

