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

#ifndef XEN_VM_GUEST_METRICS_H
#define XEN_VM_GUEST_METRICS_H

#include "xen_common.h"
#include "xen_string_string_map.h"
#include "xen_vm_decl.h"
#include "xen_vm_guest_metrics_decl.h"


/*
 * The VM_guest_metrics class.
 * 
 * The metrics reported by the guest (as opposed to inferred from outside).
 */


/**
 * Free the given xen_vm_guest_metrics.  The given handle must have
 * been allocated by this library.
 */
extern void
xen_vm_guest_metrics_free(xen_vm_guest_metrics vm_guest_metrics);


typedef struct xen_vm_guest_metrics_set
{
    size_t size;
    xen_vm_guest_metrics *contents[];
} xen_vm_guest_metrics_set;

/**
 * Allocate a xen_vm_guest_metrics_set of the given size.
 */
extern xen_vm_guest_metrics_set *
xen_vm_guest_metrics_set_alloc(size_t size);

/**
 * Free the given xen_vm_guest_metrics_set.  The given set must have
 * been allocated by this library.
 */
extern void
xen_vm_guest_metrics_set_free(xen_vm_guest_metrics_set *set);


typedef struct xen_vm_guest_metrics_record
{
    xen_vm_guest_metrics handle;
    char *uuid;
    struct xen_vm_record_opt *vm;
    xen_string_string_map *os_version;
    xen_string_string_map *pv_drivers_version;
    xen_string_string_map *memory;
    xen_string_string_map *disks;
    xen_string_string_map *networks;
    xen_string_string_map *other;
} xen_vm_guest_metrics_record;

/**
 * Allocate a xen_vm_guest_metrics_record.
 */
extern xen_vm_guest_metrics_record *
xen_vm_guest_metrics_record_alloc(void);

/**
 * Free the given xen_vm_guest_metrics_record, and all referenced
 * values.  The given record must have been allocated by this library.
 */
extern void
xen_vm_guest_metrics_record_free(xen_vm_guest_metrics_record *record);


typedef struct xen_vm_guest_metrics_record_opt
{
    bool is_record;
    union
    {
        xen_vm_guest_metrics handle;
        xen_vm_guest_metrics_record *record;
    } u;
} xen_vm_guest_metrics_record_opt;

/**
 * Allocate a xen_vm_guest_metrics_record_opt.
 */
extern xen_vm_guest_metrics_record_opt *
xen_vm_guest_metrics_record_opt_alloc(void);

/**
 * Free the given xen_vm_guest_metrics_record_opt, and all referenced
 * values.  The given record_opt must have been allocated by this library.
 */
extern void
xen_vm_guest_metrics_record_opt_free(xen_vm_guest_metrics_record_opt *record_opt);


typedef struct xen_vm_guest_metrics_record_set
{
    size_t size;
    xen_vm_guest_metrics_record *contents[];
} xen_vm_guest_metrics_record_set;

/**
 * Allocate a xen_vm_guest_metrics_record_set of the given size.
 */
extern xen_vm_guest_metrics_record_set *
xen_vm_guest_metrics_record_set_alloc(size_t size);

/**
 * Free the given xen_vm_guest_metrics_record_set, and all referenced
 * values.  The given set must have been allocated by this library.
 */
extern void
xen_vm_guest_metrics_record_set_free(xen_vm_guest_metrics_record_set *set);



typedef struct xen_vm_guest_metrics_record_opt_set
{
    size_t size;
    xen_vm_guest_metrics_record_opt *contents[];
} xen_vm_guest_metrics_record_opt_set;

/**
 * Allocate a xen_vm_guest_metrics_record_opt_set of the given size.
 */
extern xen_vm_guest_metrics_record_opt_set *
xen_vm_guest_metrics_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_vm_guest_metrics_record_opt_set, and all
 * referenced values.  The given set must have been allocated by this library.
 */
extern void
xen_vm_guest_metrics_record_opt_set_free(xen_vm_guest_metrics_record_opt_set *set);


/**
 * Get a record containing the current state of the given
 * VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_record(xen_session *session, xen_vm_guest_metrics_record **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get a reference to the VM_guest_metrics instance with the specified
 * UUID.
 */
extern bool
xen_vm_guest_metrics_get_by_uuid(xen_session *session, xen_vm_guest_metrics *result, char *uuid);


/**
 * Get the uuid field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_uuid(xen_session *session, char **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the VM field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_vm(xen_session *session, xen_vm *result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the os_version field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_os_version(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the PV_drivers_version field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_pv_drivers_version(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the memory field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_memory(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the disks field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_disks(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the networks field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_networks(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Get the other field of the given VM_guest_metrics.
 */
extern bool
xen_vm_guest_metrics_get_other(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics);


/**
 * Return a list of all the VM_guest_metrics instances known to the system.
 */
extern bool
xen_vm_guest_metrics_get_all(xen_session *session, struct xen_vm_guest_metrics_set **result);


#endif
