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
int libxl_name_to_domid(struct libxl_ctx *ctx, char *name, uint32_t *domid);
char *libxl_domid_to_name(struct libxl_ctx *ctx, uint32_t domid);
int libxl_get_stubdom_id(struct libxl_ctx *ctx, int guest_domid);
int libxl_is_stubdom(struct libxl_ctx *ctx, int domid);
int libxl_create_logfile(struct libxl_ctx *ctx, char *name, char **full_name);
int libxl_string_to_phystype(struct libxl_ctx *ctx, char *s, libxl_disk_phystype *phystype);

#endif

