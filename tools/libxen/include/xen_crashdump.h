/*
 * Copyright (c) 2006, XenSource Inc.
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

#ifndef XEN_CRASHDUMP_H
#define XEN_CRASHDUMP_H

#include "xen_common.h"
#include "xen_crashdump_decl.h"
#include "xen_vdi_decl.h"
#include "xen_vm_decl.h"


/*
 * The crashdump class.
 * 
 * A VM crashdump.
 */


/**
 * Free the given xen_crashdump.  The given handle must have been
 * allocated by this library.
 */
extern void
xen_crashdump_free(xen_crashdump crashdump);


typedef struct xen_crashdump_set
{
    size_t size;
    xen_crashdump *contents[];
} xen_crashdump_set;

/**
 * Allocate a xen_crashdump_set of the given size.
 */
extern xen_crashdump_set *
xen_crashdump_set_alloc(size_t size);

/**
 * Free the given xen_crashdump_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_crashdump_set_free(xen_crashdump_set *set);


typedef struct xen_crashdump_record
{
    xen_crashdump handle;
    char *uuid;
    struct xen_vm_record_opt *vm;
    struct xen_vdi_record_opt *vdi;
} xen_crashdump_record;

/**
 * Allocate a xen_crashdump_record.
 */
extern xen_crashdump_record *
xen_crashdump_record_alloc(void);

/**
 * Free the given xen_crashdump_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_crashdump_record_free(xen_crashdump_record *record);


typedef struct xen_crashdump_record_opt
{
    bool is_record;
    union
    {
        xen_crashdump handle;
        xen_crashdump_record *record;
    } u;
} xen_crashdump_record_opt;

/**
 * Allocate a xen_crashdump_record_opt.
 */
extern xen_crashdump_record_opt *
xen_crashdump_record_opt_alloc(void);

/**
 * Free the given xen_crashdump_record_opt, and all referenced values. 
 * The given record_opt must have been allocated by this library.
 */
extern void
xen_crashdump_record_opt_free(xen_crashdump_record_opt *record_opt);


typedef struct xen_crashdump_record_set
{
    size_t size;
    xen_crashdump_record *contents[];
} xen_crashdump_record_set;

/**
 * Allocate a xen_crashdump_record_set of the given size.
 */
extern xen_crashdump_record_set *
xen_crashdump_record_set_alloc(size_t size);

/**
 * Free the given xen_crashdump_record_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_crashdump_record_set_free(xen_crashdump_record_set *set);



typedef struct xen_crashdump_record_opt_set
{
    size_t size;
    xen_crashdump_record_opt *contents[];
} xen_crashdump_record_opt_set;

/**
 * Allocate a xen_crashdump_record_opt_set of the given size.
 */
extern xen_crashdump_record_opt_set *
xen_crashdump_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_crashdump_record_opt_set, and all referenced
 * values.  The given set must have been allocated by this library.
 */
extern void
xen_crashdump_record_opt_set_free(xen_crashdump_record_opt_set *set);


/**
 * Get a record containing the current state of the given crashdump.
 */
extern bool
xen_crashdump_get_record(xen_session *session, xen_crashdump_record **result, xen_crashdump crashdump);


/**
 * Get a reference to the crashdump instance with the specified UUID.
 */
extern bool
xen_crashdump_get_by_uuid(xen_session *session, xen_crashdump *result, char *uuid);


/**
 * Create a new crashdump instance, and return its handle.
 */
extern bool
xen_crashdump_create(xen_session *session, xen_crashdump *result, xen_crashdump_record *record);


/**
 * Destroy the specified crashdump instance.
 */
extern bool
xen_crashdump_destroy(xen_session *session, xen_crashdump crashdump);


/**
 * Get the uuid field of the given crashdump.
 */
extern bool
xen_crashdump_get_uuid(xen_session *session, char **result, xen_crashdump crashdump);


/**
 * Get the VM field of the given crashdump.
 */
extern bool
xen_crashdump_get_vm(xen_session *session, xen_vm *result, xen_crashdump crashdump);


/**
 * Get the VDI field of the given crashdump.
 */
extern bool
xen_crashdump_get_vdi(xen_session *session, xen_vdi *result, xen_crashdump crashdump);


/**
 * Return a list of all the crashdumps known to the system.
 */
extern bool
xen_crashdump_get_all(xen_session *session, struct xen_crashdump_set **result);


#endif
