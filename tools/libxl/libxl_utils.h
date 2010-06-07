/*
 * Copyright (C) 2009      Citrix Ltd.
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

#ifndef LIBXL_UTILS_H
#define LIBXL_UTILS_H

#include "libxl.h"

unsigned long libxl_get_required_shadow_memory(unsigned long maxmem_kb, unsigned int smp_cpus);
int libxl_name_to_domid(struct libxl_ctx *ctx, const char *name, uint32_t *domid);
char *libxl_domid_to_name(struct libxl_ctx *ctx, uint32_t domid);
int libxl_name_to_poolid(struct libxl_ctx *ctx, const char *name, uint32_t *poolid);
char *libxl_poolid_to_name(struct libxl_ctx *ctx, uint32_t poolid);
int libxl_get_stubdom_id(struct libxl_ctx *ctx, int guest_domid);
int libxl_is_stubdom(struct libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid);
int libxl_create_logfile(struct libxl_ctx *ctx, char *name, char **full_name);
int libxl_string_to_phystype(struct libxl_ctx *ctx, char *s, libxl_disk_phystype *phystype);

int libxl_read_file_contents(struct libxl_ctx *ctx, const char *filename,
                             void **data_r, int *datalen_r);
  /* Reads the contents of the plain file filename into a mallocd
   * buffer.  Returns 0 or errno.  Any errors other than ENOENT are logged.
   * If the file is empty, *data_r and *datalen_r are set to 0.
   * On error, *data_r and *datalen_r are undefined.
   * data_r and/or datalen_r may be 0.
   */

int libxl_read_exactly(struct libxl_ctx *ctx, int fd, void *data, ssize_t sz,
                       const char *filename, const char *what);
int libxl_write_exactly(struct libxl_ctx *ctx, int fd, const void *data,
                        ssize_t sz, const char *filename, const char *what);
  /* Returns 0 or errno.  If file is truncated on reading, returns
   * EPROTO and you have no way to tell how much was read.  Errors are
   * logged using filename (which is only used for logging) and what
   * (which may be 0). */
    
pid_t libxl_fork(struct libxl_ctx *ctx);
int libxl_pipe(struct libxl_ctx *ctx, int pipes[2]);
  /* Just like fork(2), pipe(2), but log errors. */

void libxl_report_child_exitstatus(struct libxl_ctx *ctx, xentoollog_level,
                                   const char *what, pid_t pid, int status);
    /* treats all exit statuses as errors; if that's not what you want,
     * check status yourself first */

int libxl_mac_to_device_nic(struct libxl_ctx *ctx, uint32_t domid,
                            const char *mac, libxl_device_nic *nic);
int libxl_devid_to_device_nic(struct libxl_ctx *ctx, uint32_t domid,
                              const char *devid, libxl_device_nic *nic);

int libxl_devid_to_device_disk(struct libxl_ctx *ctx, uint32_t domid,
                               const char *devid, libxl_device_disk *disk);

int libxl_strtomac(const char *mac_s, uint8_t *mac);

#endif

