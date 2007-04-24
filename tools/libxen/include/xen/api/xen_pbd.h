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

#ifndef XEN_PBD_H
#define XEN_PBD_H

#include <xen/api/xen_common.h>
#include <xen/api/xen_host_decl.h>
#include <xen/api/xen_pbd_decl.h>
#include <xen/api/xen_sr_decl.h>
#include <xen/api/xen_string_string_map.h>


/*
 * The PBD class.
 * 
 * The physical block devices through which hosts access SRs.
 */


/**
 * Free the given xen_pbd.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_pbd_free(xen_pbd pbd);


typedef struct xen_pbd_set
{
    size_t size;
    xen_pbd *contents[];
} xen_pbd_set;

/**
 * Allocate a xen_pbd_set of the given size.
 */
extern xen_pbd_set *
xen_pbd_set_alloc(size_t size);

/**
 * Free the given xen_pbd_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_pbd_set_free(xen_pbd_set *set);


typedef struct xen_pbd_record
{
    xen_pbd handle;
    char *uuid;
    struct xen_host_record_opt *host;
    struct xen_sr_record_opt *sr;
    xen_string_string_map *device_config;
    bool currently_attached;
} xen_pbd_record;

/**
 * Allocate a xen_pbd_record.
 */
extern xen_pbd_record *
xen_pbd_record_alloc(void);

/**
 * Free the given xen_pbd_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_pbd_record_free(xen_pbd_record *record);


typedef struct xen_pbd_record_opt
{
    bool is_record;
    union
    {
        xen_pbd handle;
        xen_pbd_record *record;
    } u;
} xen_pbd_record_opt;

/**
 * Allocate a xen_pbd_record_opt.
 */
extern xen_pbd_record_opt *
xen_pbd_record_opt_alloc(void);

/**
 * Free the given xen_pbd_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_pbd_record_opt_free(xen_pbd_record_opt *record_opt);


typedef struct xen_pbd_record_set
{
    size_t size;
    xen_pbd_record *contents[];
} xen_pbd_record_set;

/**
 * Allocate a xen_pbd_record_set of the given size.
 */
extern xen_pbd_record_set *
xen_pbd_record_set_alloc(size_t size);

/**
 * Free the given xen_pbd_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_pbd_record_set_free(xen_pbd_record_set *set);



typedef struct xen_pbd_record_opt_set
{
    size_t size;
    xen_pbd_record_opt *contents[];
} xen_pbd_record_opt_set;

/**
 * Allocate a xen_pbd_record_opt_set of the given size.
 */
extern xen_pbd_record_opt_set *
xen_pbd_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_pbd_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_pbd_record_opt_set_free(xen_pbd_record_opt_set *set);


/**
 * Get a record containing the current state of the given PBD.
 */
extern bool
xen_pbd_get_record(xen_session *session, xen_pbd_record **result, xen_pbd pbd);


/**
 * Get a reference to the PBD instance with the specified UUID.
 */
extern bool
xen_pbd_get_by_uuid(xen_session *session, xen_pbd *result, char *uuid);


/**
 * Create a new PBD instance, and return its handle.
 */
extern bool
xen_pbd_create(xen_session *session, xen_pbd *result, xen_pbd_record *record);


/**
 * Destroy the specified PBD instance.
 */
extern bool
xen_pbd_destroy(xen_session *session, xen_pbd pbd);


/**
 * Get the uuid field of the given PBD.
 */
extern bool
xen_pbd_get_uuid(xen_session *session, char **result, xen_pbd pbd);


/**
 * Get the host field of the given PBD.
 */
extern bool
xen_pbd_get_host(xen_session *session, xen_host *result, xen_pbd pbd);


/**
 * Get the SR field of the given PBD.
 */
extern bool
xen_pbd_get_sr(xen_session *session, xen_sr *result, xen_pbd pbd);


/**
 * Get the device_config field of the given PBD.
 */
extern bool
xen_pbd_get_device_config(xen_session *session, xen_string_string_map **result, xen_pbd pbd);


/**
 * Get the currently_attached field of the given PBD.
 */
extern bool
xen_pbd_get_currently_attached(xen_session *session, bool *result, xen_pbd pbd);


/**
 * Return a list of all the PBDs known to the system.
 */
extern bool
xen_pbd_get_all(xen_session *session, struct xen_pbd_set **result);


#endif
