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

const char *libxl_basename(const char *name); /* returns string from strdup */
unsigned long libxl_get_required_shadow_memory(unsigned long maxmem_kb, unsigned int smp_cpus);
int libxl_name_to_domid(libxl_ctx *ctx, const char *name, uint32_t *domid);
char *libxl_domid_to_name(libxl_ctx *ctx, uint32_t domid);
int libxl_name_to_cpupoolid(libxl_ctx *ctx, const char *name, uint32_t *poolid);
char *libxl_cpupoolid_to_name(libxl_ctx *ctx, uint32_t poolid);
int libxl_name_to_schedid(libxl_ctx *ctx, const char *name);
char *libxl_schedid_to_name(libxl_ctx *ctx, int schedid);
int libxl_get_stubdom_id(libxl_ctx *ctx, int guest_domid);
int libxl_is_stubdom(libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid);
int libxl_create_logfile(libxl_ctx *ctx, char *name, char **full_name);
int libxl_string_to_backend(libxl_ctx *ctx, char *s, libxl_disk_backend *backend);

int libxl_read_file_contents(libxl_ctx *ctx, const char *filename,
                             void **data_r, int *datalen_r);
  /* Reads the contents of the plain file filename into a mallocd
   * buffer.  Returns 0 or errno.  Any errors other than ENOENT are logged.
   * If the file is empty, *data_r and *datalen_r are set to 0.
   * On error, *data_r and *datalen_r are unchanged.
   * data_r and/or datalen_r may be 0.
   */

int libxl_read_exactly(libxl_ctx *ctx, int fd, void *data, ssize_t sz,
                       const char *filename, const char *what);
int libxl_write_exactly(libxl_ctx *ctx, int fd, const void *data,
                        ssize_t sz, const char *filename, const char *what);
  /* Returns 0 or errno.  If file is truncated on reading, returns
   * EPROTO and you have no way to tell how much was read.  Errors are
   * logged using filename (which is only used for logging) and what
   * (which may be 0). */

pid_t libxl_fork(libxl_ctx *ctx);
int libxl_pipe(libxl_ctx *ctx, int pipes[2]);
  /* Just like fork(2), pipe(2), but log errors. */

void libxl_report_child_exitstatus(libxl_ctx *ctx, xentoollog_level,
                                   const char *what, pid_t pid, int status);
    /* treats all exit statuses as errors; if that's not what you want,
     * check status yourself first */

int libxl_mac_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                            const char *mac, libxl_device_nic *nic);
int libxl_devid_to_device_nic(libxl_ctx *ctx, uint32_t domid, int devid,
                              libxl_device_nic *nic);

int libxl_devid_to_device_disk(libxl_ctx *ctx, uint32_t domid, int devid,
                               libxl_device_disk *disk);

int libxl_cpumap_alloc(libxl_ctx *ctx, libxl_cpumap *cpumap);
int libxl_cpumap_test(libxl_cpumap *cpumap, int cpu);
void libxl_cpumap_set(libxl_cpumap *cpumap, int cpu);
void libxl_cpumap_reset(libxl_cpumap *cpumap, int cpu);
#define libxl_for_each_cpu(var, map) for (var = 0; var < (map).size * 8; var++)
#define libxl_for_each_set_cpu(v, m) for (v = 0; v < (m).size * 8; v++) \
                                             if (libxl_cpumap_test(&(m), v))

int libxl_cpuarray_alloc(libxl_ctx *ctx, libxl_cpuarray *cpuarray);

static inline uint32_t libxl__sizekb_to_mb(uint32_t s) {
    return (s + 1023) / 1024;
}

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
