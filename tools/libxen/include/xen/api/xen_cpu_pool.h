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

#ifndef XEN_CPU_POOL_H
#define XEN_CPU_POOL_H

#include <stddef.h>
#include <stdlib.h>

#include <xen/api/xen_common.h>
#include <xen/api/xen_string_set.h>
#include <xen/api/xen_string_string_map.h>
#include <xen/api/xen_host_cpu_decl.h>
#include <xen/api/xen_host.h>
#include <xen/api/xen_vm_decl.h>
#include <xen/api/xen_vm.h>
#include <xen/api/xen_cpu_pool_decl.h>

/*
 * The cpu_pool class.
 *
 * Management of CPU pools.
 */


/**
 * Free the given xen_cpu_pool.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_cpu_pool_free(xen_cpu_pool cpu_pool);


typedef struct xen_cpu_pool_set
{
    size_t size;
    xen_cpu_pool *contents[];
} xen_cpu_pool_set;

/**
 * Allocate a xen_cpu_pool_set of the given size.
 */
extern xen_cpu_pool_set *
xen_cpu_pool_set_alloc(size_t size);

/**
 * Free the given xen_cpu_pool_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_cpu_pool_set_free(xen_cpu_pool_set *set);


typedef struct xen_cpu_pool_record
{
    xen_cpu_pool handle;
    char *uuid;
    char *name_label;
    char *name_description;
    struct xen_host_record_opt *resident_on;
    bool auto_power_on;
    struct xen_vm_record_opt_set *started_vms;
    int64_t ncpu;
    char *sched_policy;
    struct xen_string_set *proposed_cpus;
    struct xen_host_cpu_record_opt_set *host_cpus;
    bool activated;
    xen_string_string_map *other_config;
} xen_cpu_pool_record;

/**
 * Allocate a xen_cpu_pool_record.
 */
extern xen_cpu_pool_record *
xen_cpu_pool_record_alloc(void);

/**
 * Free the given xen_cpu_pool_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_cpu_pool_record_free(xen_cpu_pool_record *record);


typedef struct xen_cpu_pool_record_opt
{
    bool is_record;
    union
    {
        xen_cpu_pool handle;
        xen_cpu_pool_record *record;
    } u;
} xen_cpu_pool_record_opt;

/**
 * Allocate a xen_cpu_pool_record_opt.
 */
extern xen_cpu_pool_record_opt *
xen_cpu_pool_record_opt_alloc(void);

/**
 * Free the given xen_cpu_pool_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_cpu_pool_record_opt_free(xen_cpu_pool_record_opt *record_opt);


typedef struct xen_cpu_pool_record_set
{
    size_t size;
    xen_cpu_pool_record *contents[];
} xen_cpu_pool_record_set;

/**
 * Allocate a xen_cpu_pool_record_set of the given size.
 */
extern xen_cpu_pool_record_set *
xen_cpu_pool_record_set_alloc(size_t size);

/**
 * Free the given xen_cpu_pool_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_cpu_pool_record_set_free(xen_cpu_pool_record_set *set);



typedef struct xen_cpu_pool_record_opt_set
{
    size_t size;
    xen_cpu_pool_record_opt *contents[];
} xen_cpu_pool_record_opt_set;

/**
 * Allocate a xen_cpu_pool_record_opt_set of the given size.
 */
extern xen_cpu_pool_record_opt_set *
xen_cpu_pool_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_cpu_pool_record_opt_set, and all referenced values.
 * The given set must have been allocated by this library.
 */
extern void
xen_cpu_pool_record_opt_set_free(xen_cpu_pool_record_opt_set *set);


/**
 * Get a record containing the current state of the given cpu_pool.
 */
extern bool
xen_cpu_pool_get_record(xen_session *session, xen_cpu_pool_record **result,
    xen_cpu_pool cpu_pool);


/**
 * Get a reference to the cpu_pool instance with the specified UUID.
 */
extern bool
xen_cpu_pool_get_by_uuid(xen_session *session, xen_cpu_pool *result, char *uuid);


/**
 * Create a new cpu_pool instance, and return its handle.
 */
extern bool
xen_cpu_pool_create(xen_session *session, xen_cpu_pool *result,
    xen_cpu_pool_record *record);


/**
 * Destroy the specified VBD instance.
 */
extern bool
xen_cpu_pool_destroy(xen_session *session, xen_cpu_pool cpu_pool);


/**
 * Get the uuid field of the given cpu_pool.
 */
extern bool
xen_cpu_pool_get_uuid(xen_session *session, char **result, xen_cpu_pool cpu_pool);


/**
 * Deactivate the given cpu_pool.
 */
extern bool
xen_cpu_pool_deactivate(xen_session *session, xen_cpu_pool cpu_pool);


/**
 * Activate the given cpu_pool.
 */
extern bool
xen_cpu_pool_activate(xen_session *session, xen_cpu_pool cpu_pool);


/**
 * Add a physical cpu to the active pool.
 */
extern bool
xen_cpu_pool_add_host_CPU_live(xen_session *session, xen_cpu_pool cpu_pool,
    xen_host_cpu host_cpu);


/**
 * Remove a physical cpu from the active pool.
 */
extern bool
xen_cpu_pool_remove_host_CPU_live(xen_session *session, xen_cpu_pool cpu_pool,
    xen_host_cpu host_cpu);


/**
 * Return a list of all the cpu_pools known to the system.
 */
extern bool
xen_cpu_pool_get_all(xen_session *session, struct xen_cpu_pool_set **result);


/**
 * Get the uuid field of the cpu_pool with given name.
 */
extern bool
xen_cpu_pool_get_by_name_label(xen_session *session,
    struct xen_cpu_pool_set **result, char *label);


/**
 * Get activation state of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_activated(xen_session *session, bool *result,
    xen_cpu_pool cpu_pool);


/**
 * Get auto_power_on option of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_auto_power_on(xen_session *session, bool *result,
    xen_cpu_pool cpu_pool);


/**
 * Get host_cpu refs of all physical cpus of cpu_pool.
 */
extern bool
xen_cpu_pool_get_host_CPUs(xen_session *session, struct xen_host_cpu_set **result,
    xen_cpu_pool cpu_pool);


/**
 * Get name description field of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_name_description(xen_session *session, char **result,
    xen_cpu_pool cpu_pool);


/**
 * Get name label field of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_name_label(xen_session *session, char **result,
    xen_cpu_pool cpu_pool);


/**
 * Get count of physical cpus to attach to cpu_pool on activation.
 */
extern bool
xen_cpu_pool_get_ncpu(xen_session *session, int64_t *result,
    xen_cpu_pool cpu_pool);


/**
 * Get proposed_CPUs field of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_proposed_CPUs(xen_session *session, struct xen_string_set **result,
    xen_cpu_pool cpu_pool);


/**
 * Get the other_config field of the given cpu_pool.
 */
extern bool
xen_cpu_pool_get_other_config(xen_session *session, xen_string_string_map **result,
    xen_cpu_pool cpu_pool);


/**
 * Get host the cpu_pool is resident on.
 */
extern bool
xen_cpu_pool_get_resident_on(xen_session *session, xen_host *result,
    xen_cpu_pool cpu_pool);


/**
 * Get sched_policy field of given cpu_pool.
 */
extern bool
xen_cpu_pool_get_sched_policy(xen_session *session, char **result,
    xen_cpu_pool cpu_pool);


/**
 * Get set of started vms in given cpu_pool.
 */
extern bool
xen_cpu_pool_get_started_VMs(xen_session *session, xen_vm_set **result,
    xen_cpu_pool cpu_pool);


/**
 *  Set auto_power_on field of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_auto_power_on(xen_session *session, xen_cpu_pool cpu_pool,
    bool auto_power_on);


/**
 * Set proposed_CPUs field of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    xen_string_set *proposed_cpus);


/**
 * Add a proposed cpu to proposed_CPUs field of given cpu_pool.
 */
extern bool
xen_cpu_pool_add_to_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    char* proposed_cpu);


/**
 * Remove a proposed cpu from proposed_CPUs field of given cpu_pool.
 */
extern bool
xen_cpu_pool_remove_from_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    char* proposed_cpu);


/**
 * Set name_label field of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_name_label(xen_session *session, xen_cpu_pool cpu_pool,
    char *label);


/**
 * Set name_description field of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_name_description(xen_session *session, xen_cpu_pool cpu_pool,
    char *descr);


/**
 * Set ncpu field of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_ncpu(xen_session *session, xen_cpu_pool cpu_pool, int64_t ncpu);


/**
 * Set the other_config field of the given cpu_pool.
 */
extern bool
xen_cpu_pool_set_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    xen_string_string_map *other_config);


/**
 * Add the given key-value pair to the other_config field of the given
 * cpu_pool.
 */
extern bool
xen_cpu_pool_add_to_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * other_config field of the given cpu_pool. If the key is not in that Map, then
 * do nothing.
 */
extern bool
xen_cpu_pool_remove_from_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    char *key);

/**
 * Set sched_policy of given cpu_pool.
 */
extern bool
xen_cpu_pool_set_sched_policy(xen_session *session, xen_cpu_pool cpu_pool,
    char *sched_policy);


#endif
