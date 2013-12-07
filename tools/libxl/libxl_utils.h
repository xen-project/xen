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
int libxl_domain_qualifier_to_domid(libxl_ctx *ctx, const char *name, uint32_t *domid);
char *libxl_domid_to_name(libxl_ctx *ctx, uint32_t domid);
int libxl_name_to_cpupoolid(libxl_ctx *ctx, const char *name, uint32_t *poolid);
char *libxl_cpupoolid_to_name(libxl_ctx *ctx, uint32_t poolid);
int libxl_cpupoolid_is_valid(libxl_ctx *ctx, uint32_t poolid);
int libxl_get_stubdom_id(libxl_ctx *ctx, int guest_domid);
int libxl_is_stubdom(libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid);
int libxl_create_logfile(libxl_ctx *ctx, const char *name, char **full_name);
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

int libxl_pipe(libxl_ctx *ctx, int pipes[2]);
  /* Just like pipe(2), but log errors. */

void libxl_report_child_exitstatus(libxl_ctx *ctx, xentoollog_level,
                                   const char *what, pid_t pid, int status);
    /* treats all exit statuses as errors; if that's not what you want,
     * check status yourself first */

int libxl_mac_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                            const char *mac, libxl_device_nic *nic);
int libxl_devid_to_device_nic(libxl_ctx *ctx, uint32_t domid, int devid,
                              libxl_device_nic *nic);

int libxl_vdev_to_device_disk(libxl_ctx *ctx, uint32_t domid, const char *vdev,
                               libxl_device_disk *disk);

int libxl_uuid_to_device_vtpm(libxl_ctx *ctx, uint32_t domid,
                               libxl_uuid *uuid, libxl_device_vtpm *vtpm);
int libxl_devid_to_device_vtpm(libxl_ctx *ctx, uint32_t domid,
                               int devid, libxl_device_vtpm *vtpm);

int libxl_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *bitmap, int n_bits);
    /* Allocated bimap is from malloc, libxl_bitmap_dispose() to be
     * called by the application when done. */
void libxl_bitmap_copy(libxl_ctx *ctx, libxl_bitmap *dptr,
                       const libxl_bitmap *sptr);
int libxl_bitmap_is_full(const libxl_bitmap *bitmap);
int libxl_bitmap_is_empty(const libxl_bitmap *bitmap);
int libxl_bitmap_test(const libxl_bitmap *bitmap, int bit);
void libxl_bitmap_set(libxl_bitmap *bitmap, int bit);
void libxl_bitmap_reset(libxl_bitmap *bitmap, int bit);
int libxl_bitmap_count_set(const libxl_bitmap *cpumap);
char *libxl_bitmap_to_hex_string(libxl_ctx *ctx, const libxl_bitmap *cpumap);
static inline void libxl_bitmap_set_any(libxl_bitmap *bitmap)
{
    memset(bitmap->map, -1, bitmap->size);
}
static inline void libxl_bitmap_set_none(libxl_bitmap *bitmap)
{
    memset(bitmap->map, 0, bitmap->size);
}
static inline int libxl_bitmap_cpu_valid(libxl_bitmap *bitmap, int bit)
{
    return bit >= 0 && bit < (bitmap->size * 8);
}
#define libxl_for_each_bit(var, map) for (var = 0; var < (map).size * 8; var++)
#define libxl_for_each_set_bit(v, m) for (v = 0; v < (m).size * 8; v++) \
                                             if (libxl_bitmap_test(&(m), v))

int libxl_cpu_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *cpumap, int max_cpus);
int libxl_node_bitmap_alloc(libxl_ctx *ctx, libxl_bitmap *nodemap,
                            int max_nodes);

/* Populate cpumap with the cpus spanned by the nodes in nodemap */
int libxl_nodemap_to_cpumap(libxl_ctx *ctx,
                            const libxl_bitmap *nodemap,
                            libxl_bitmap *cpumap);
/* Populate cpumap with the cpus spanned by node */
int libxl_node_to_cpumap(libxl_ctx *ctx, int node,
                         libxl_bitmap *cpumap);
/* Populate nodemap with the nodes of the cpus in cpumap */
int libxl_cpumap_to_nodemap(libxl_ctx *ctx,
                            const libxl_bitmap *cpuemap,
                            libxl_bitmap *nodemap);

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
