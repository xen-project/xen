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

#ifndef XEN_HOST_H
#define XEN_HOST_H

#include "xen_common.h"
#include "xen_host_cpu_decl.h"
#include "xen_host_decl.h"
#include "xen_host_metrics_decl.h"
#include "xen_pbd_decl.h"
#include "xen_pif_decl.h"
#include "xen_sr_decl.h"
#include "xen_string_string_map.h"
#include "xen_vm_decl.h"


/*
 * The host class.
 * 
 * A physical host.
 */


/**
 * Free the given xen_host.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_host_free(xen_host host);


typedef struct xen_host_set
{
    size_t size;
    xen_host *contents[];
} xen_host_set;

/**
 * Allocate a xen_host_set of the given size.
 */
extern xen_host_set *
xen_host_set_alloc(size_t size);

/**
 * Free the given xen_host_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_host_set_free(xen_host_set *set);


typedef struct xen_host_record
{
    xen_host handle;
    char *uuid;
    char *name_label;
    char *name_description;
    xen_string_string_map *software_version;
    xen_string_string_map *other_config;
    struct xen_vm_record_opt_set *resident_vms;
    xen_string_string_map *logging;
    struct xen_pif_record_opt_set *pifs;
    struct xen_sr_record_opt *suspend_image_sr;
    struct xen_sr_record_opt *crash_dump_sr;
    struct xen_pbd_record_opt_set *pbds;
    struct xen_host_cpu_record_opt_set *host_cpus;
    struct xen_host_metrics_record_opt *metrics;
} xen_host_record;

/**
 * Allocate a xen_host_record.
 */
extern xen_host_record *
xen_host_record_alloc(void);

/**
 * Free the given xen_host_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_host_record_free(xen_host_record *record);


typedef struct xen_host_record_opt
{
    bool is_record;
    union
    {
        xen_host handle;
        xen_host_record *record;
    } u;
} xen_host_record_opt;

/**
 * Allocate a xen_host_record_opt.
 */
extern xen_host_record_opt *
xen_host_record_opt_alloc(void);

/**
 * Free the given xen_host_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_host_record_opt_free(xen_host_record_opt *record_opt);


typedef struct xen_host_record_set
{
    size_t size;
    xen_host_record *contents[];
} xen_host_record_set;

/**
 * Allocate a xen_host_record_set of the given size.
 */
extern xen_host_record_set *
xen_host_record_set_alloc(size_t size);

/**
 * Free the given xen_host_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_host_record_set_free(xen_host_record_set *set);



typedef struct xen_host_record_opt_set
{
    size_t size;
    xen_host_record_opt *contents[];
} xen_host_record_opt_set;

/**
 * Allocate a xen_host_record_opt_set of the given size.
 */
extern xen_host_record_opt_set *
xen_host_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_host_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_host_record_opt_set_free(xen_host_record_opt_set *set);


/**
 * Get a record containing the current state of the given host.
 */
extern bool
xen_host_get_record(xen_session *session, xen_host_record **result, xen_host host);


/**
 * Get a reference to the host instance with the specified UUID.
 */
extern bool
xen_host_get_by_uuid(xen_session *session, xen_host *result, char *uuid);


/**
 * Create a new host instance, and return its handle.
 */
extern bool
xen_host_create(xen_session *session, xen_host *result, xen_host_record *record);


/**
 * Destroy the specified host instance.
 */
extern bool
xen_host_destroy(xen_session *session, xen_host host);


/**
 * Get all the host instances with the given label.
 */
extern bool
xen_host_get_by_name_label(xen_session *session, struct xen_host_set **result, char *label);


/**
 * Get the uuid field of the given host.
 */
extern bool
xen_host_get_uuid(xen_session *session, char **result, xen_host host);


/**
 * Get the name/label field of the given host.
 */
extern bool
xen_host_get_name_label(xen_session *session, char **result, xen_host host);


/**
 * Get the name/description field of the given host.
 */
extern bool
xen_host_get_name_description(xen_session *session, char **result, xen_host host);


/**
 * Get the software_version field of the given host.
 */
extern bool
xen_host_get_software_version(xen_session *session, xen_string_string_map **result, xen_host host);


/**
 * Get the other_config field of the given host.
 */
extern bool
xen_host_get_other_config(xen_session *session, xen_string_string_map **result, xen_host host);


/**
 * Get the resident_VMs field of the given host.
 */
extern bool
xen_host_get_resident_vms(xen_session *session, struct xen_vm_set **result, xen_host host);


/**
 * Get the logging field of the given host.
 */
extern bool
xen_host_get_logging(xen_session *session, xen_string_string_map **result, xen_host host);


/**
 * Get the PIFs field of the given host.
 */
extern bool
xen_host_get_pifs(xen_session *session, struct xen_pif_set **result, xen_host host);


/**
 * Get the suspend_image_sr field of the given host.
 */
extern bool
xen_host_get_suspend_image_sr(xen_session *session, xen_sr *result, xen_host host);


/**
 * Get the crash_dump_sr field of the given host.
 */
extern bool
xen_host_get_crash_dump_sr(xen_session *session, xen_sr *result, xen_host host);


/**
 * Get the PBDs field of the given host.
 */
extern bool
xen_host_get_pbds(xen_session *session, struct xen_pbd_set **result, xen_host host);


/**
 * Get the host_CPUs field of the given host.
 */
extern bool
xen_host_get_host_cpus(xen_session *session, struct xen_host_cpu_set **result, xen_host host);


/**
 * Get the metrics field of the given host.
 */
extern bool
xen_host_get_metrics(xen_session *session, xen_host_metrics *result, xen_host host);


/**
 * Set the name/label field of the given host.
 */
extern bool
xen_host_set_name_label(xen_session *session, xen_host host, char *label);


/**
 * Set the name/description field of the given host.
 */
extern bool
xen_host_set_name_description(xen_session *session, xen_host host, char *description);


/**
 * Set the other_config field of the given host.
 */
extern bool
xen_host_set_other_config(xen_session *session, xen_host host, xen_string_string_map *other_config);


/**
 * Add the given key-value pair to the other_config field of the given
 * host.
 */
extern bool
xen_host_add_to_other_config(xen_session *session, xen_host host, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * other_config field of the given host.  If the key is not in that Map, then
 * do nothing.
 */
extern bool
xen_host_remove_from_other_config(xen_session *session, xen_host host, char *key);


/**
 * Set the logging field of the given host.
 */
extern bool
xen_host_set_logging(xen_session *session, xen_host host, xen_string_string_map *logging);


/**
 * Add the given key-value pair to the logging field of the given host.
 */
extern bool
xen_host_add_to_logging(xen_session *session, xen_host host, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the logging
 * field of the given host.  If the key is not in that Map, then do nothing.
 */
extern bool
xen_host_remove_from_logging(xen_session *session, xen_host host, char *key);


/**
 * Set the suspend_image_sr field of the given host.
 */
extern bool
xen_host_set_suspend_image_sr(xen_session *session, xen_host host, xen_sr suspend_image_sr);


/**
 * Set the crash_dump_sr field of the given host.
 */
extern bool
xen_host_set_crash_dump_sr(xen_session *session, xen_host host, xen_sr crash_dump_sr);


/**
 * Puts the host into a state in which no new VMs can be started.
 * Currently active VMs on the host continue to execute.
 */
extern bool
xen_host_disable(xen_session *session, xen_host host);


/**
 * Puts the host into a state in which new VMs can be started.
 */
extern bool
xen_host_enable(xen_session *session, xen_host host);


/**
 * Shutdown the host. (This function can only be called if there are no
 * currently running VMs on the host and it is disabled.)
 */
extern bool
xen_host_shutdown(xen_session *session, xen_host host);


/**
 * Reboot the host. (This function can only be called if there are no
 * currently running VMs on the host and it is disabled.)
 */
extern bool
xen_host_reboot(xen_session *session, xen_host host);


/**
 * Get the host xen dmesg.
 */
extern bool
xen_host_dmesg(xen_session *session, char **result, xen_host host);


/**
 * Return a list of all the hosts known to the system.
 */
extern bool
xen_host_get_all(xen_session *session, struct xen_host_set **result);


#endif
