/* xen-interface.h
 *
 * Copyright (C) International Business Machines Corp., 2005
 * Authors: Josh Triplett <josht@us.ibm.com>
 *          Judy Fischbach <jfisch@us.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdint.h>

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#include "dom0_ops.h"
#include "version.h"

/* Opaque handles */
typedef struct xi_handle xi_handle;

/* Initialize for xen-interface.  Returns a handle to be used with subsequent
 * calls to the xen-interface functions or NULL if an error occurs. */
xi_handle *xi_init();

/* Release the handle to libxc, free resources, etc. */
void xi_uninit(xi_handle *handle);

/* Obtain xen version information from hypervisor */
int xi_get_xen_version(xi_handle *, long *vnum, xen_extraversion_t *ver);

/* Obtain physinfo data from dom0 */
int xi_get_physinfo(xi_handle *, dom0_physinfo_t *);

/* Obtain domain data from dom0 */
int xi_get_domaininfolist(xi_handle *, dom0_getdomaininfo_t *, unsigned int,
                          unsigned int);

/* Returns cpu usage data from dom0 */
long long xi_get_vcpu_usage(xi_handle *, unsigned int, unsigned int);
