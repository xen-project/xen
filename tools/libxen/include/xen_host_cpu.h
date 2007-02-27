/*
 * Copyright (c) 2006-2007, XenSource Inc.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef XEN_HOST_CPU_H
#define XEN_HOST_CPU_H

#include "xen_common.h"
#include "xen_host_cpu_decl.h"
#include "xen_host_decl.h"


/*
 * The host_cpu class.
 * 
 * A physical CPU.
 */


/**
 * Free the given xen_host_cpu.  The given handle must have been
 * allocated by this library.
 */
extern void
xen_host_cpu_free(xen_host_cpu host_cpu);


typedef struct xen_host_cpu_set
{
    size_t size;
    xen_host_cpu *contents[];
} xen_host_cpu_set;

/**
 * Allocate a xen_host_cpu_set of the given size.
 */
extern xen_host_cpu_set *
xen_host_cpu_set_alloc(size_t size);

/**
 * Free the given xen_host_cpu_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_host_cpu_set_free(xen_host_cpu_set *set);


typedef struct xen_host_cpu_record
{
    xen_host_cpu handle;
    char *uuid;
    struct xen_host_record_opt *host;
    int64_t number;
    char *vendor;
    int64_t speed;
    char *modelname;
    char *stepping;
    char *flags;
    double utilisation;
} xen_host_cpu_record;

/**
 * Allocate a xen_host_cpu_record.
 */
extern xen_host_cpu_record *
xen_host_cpu_record_alloc(void);

/**
 * Free the given xen_host_cpu_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_host_cpu_record_free(xen_host_cpu_record *record);


typedef struct xen_host_cpu_record_opt
{
    bool is_record;
    union
    {
        xen_host_cpu handle;
        xen_host_cpu_record *record;
    } u;
} xen_host_cpu_record_opt;

/**
 * Allocate a xen_host_cpu_record_opt.
 */
extern xen_host_cpu_record_opt *
xen_host_cpu_record_opt_alloc(void);

/**
 * Free the given xen_host_cpu_record_opt, and all referenced values. 
 * The given record_opt must have been allocated by this library.
 */
extern void
xen_host_cpu_record_opt_free(xen_host_cpu_record_opt *record_opt);


typedef struct xen_host_cpu_record_set
{
    size_t size;
    xen_host_cpu_record *contents[];
} xen_host_cpu_record_set;

/**
 * Allocate a xen_host_cpu_record_set of the given size.
 */
extern xen_host_cpu_record_set *
xen_host_cpu_record_set_alloc(size_t size);

/**
 * Free the given xen_host_cpu_record_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_host_cpu_record_set_free(xen_host_cpu_record_set *set);



typedef struct xen_host_cpu_record_opt_set
{
    size_t size;
    xen_host_cpu_record_opt *contents[];
} xen_host_cpu_record_opt_set;

/**
 * Allocate a xen_host_cpu_record_opt_set of the given size.
 */
extern xen_host_cpu_record_opt_set *
xen_host_cpu_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_host_cpu_record_opt_set, and all referenced
 * values.  The given set must have been allocated by this library.
 */
extern void
xen_host_cpu_record_opt_set_free(xen_host_cpu_record_opt_set *set);


/**
 * Get a record containing the current state of the given host_cpu.
 */
extern bool
xen_host_cpu_get_record(xen_session *session, xen_host_cpu_record **result, xen_host_cpu host_cpu);


/**
 * Get a reference to the host_cpu instance with the specified UUID.
 */
extern bool
xen_host_cpu_get_by_uuid(xen_session *session, xen_host_cpu *result, char *uuid);


/**
 * Get the uuid field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_uuid(xen_session *session, char **result, xen_host_cpu host_cpu);


/**
 * Get the host field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_host(xen_session *session, xen_host *result, xen_host_cpu host_cpu);


/**
 * Get the number field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_number(xen_session *session, int64_t *result, xen_host_cpu host_cpu);


/**
 * Get the vendor field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_vendor(xen_session *session, char **result, xen_host_cpu host_cpu);


/**
 * Get the speed field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_speed(xen_session *session, int64_t *result, xen_host_cpu host_cpu);


/**
 * Get the modelname field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_modelname(xen_session *session, char **result, xen_host_cpu host_cpu);


/**
 * Get the stepping field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_stepping(xen_session *session, char **result, xen_host_cpu host_cpu);


/**
 * Get the flags field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_flags(xen_session *session, char **result, xen_host_cpu host_cpu);


/**
 * Get the utilisation field of the given host_cpu.
 */
extern bool
xen_host_cpu_get_utilisation(xen_session *session, double *result, xen_host_cpu host_cpu);


#endif
