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

#ifndef XEN_VIF_H
#define XEN_VIF_H

#include <xen/api/xen_common.h>
#include <xen/api/xen_network_decl.h>
#include <xen/api/xen_string_set.h>
#include <xen/api/xen_string_string_map.h>
#include <xen/api/xen_vif_decl.h>
#include <xen/api/xen_vif_metrics_decl.h>
#include <xen/api/xen_vm_decl.h>


/*
 * The VIF class.
 * 
 * A virtual network interface.
 */


/**
 * Free the given xen_vif.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_vif_free(xen_vif vif);


typedef struct xen_vif_set
{
    size_t size;
    xen_vif *contents[];
} xen_vif_set;

/**
 * Allocate a xen_vif_set of the given size.
 */
extern xen_vif_set *
xen_vif_set_alloc(size_t size);

/**
 * Free the given xen_vif_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_vif_set_free(xen_vif_set *set);


typedef struct xen_vif_record
{
    xen_vif handle;
    char *uuid;
    char *device;
    struct xen_network_record_opt *network;
    struct xen_vm_record_opt *vm;
    char *mac;
    int64_t mtu;
    bool currently_attached;
    int64_t status_code;
    char *status_detail;
    xen_string_string_map *runtime_properties;
    char *qos_algorithm_type;
    xen_string_string_map *qos_algorithm_params;
    struct xen_string_set *qos_supported_algorithms;
    struct xen_vif_metrics_record_opt *metrics;
} xen_vif_record;

/**
 * Allocate a xen_vif_record.
 */
extern xen_vif_record *
xen_vif_record_alloc(void);

/**
 * Free the given xen_vif_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_vif_record_free(xen_vif_record *record);


typedef struct xen_vif_record_opt
{
    bool is_record;
    union
    {
        xen_vif handle;
        xen_vif_record *record;
    } u;
} xen_vif_record_opt;

/**
 * Allocate a xen_vif_record_opt.
 */
extern xen_vif_record_opt *
xen_vif_record_opt_alloc(void);

/**
 * Free the given xen_vif_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_vif_record_opt_free(xen_vif_record_opt *record_opt);


typedef struct xen_vif_record_set
{
    size_t size;
    xen_vif_record *contents[];
} xen_vif_record_set;

/**
 * Allocate a xen_vif_record_set of the given size.
 */
extern xen_vif_record_set *
xen_vif_record_set_alloc(size_t size);

/**
 * Free the given xen_vif_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_vif_record_set_free(xen_vif_record_set *set);



typedef struct xen_vif_record_opt_set
{
    size_t size;
    xen_vif_record_opt *contents[];
} xen_vif_record_opt_set;

/**
 * Allocate a xen_vif_record_opt_set of the given size.
 */
extern xen_vif_record_opt_set *
xen_vif_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_vif_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_vif_record_opt_set_free(xen_vif_record_opt_set *set);


/**
 * Get a record containing the current state of the given VIF.
 */
extern bool
xen_vif_get_record(xen_session *session, xen_vif_record **result, xen_vif vif);


/**
 * Get a reference to the VIF instance with the specified UUID.
 */
extern bool
xen_vif_get_by_uuid(xen_session *session, xen_vif *result, char *uuid);


/**
 * Create a new VIF instance, and return its handle.
 */
extern bool
xen_vif_create(xen_session *session, xen_vif *result, xen_vif_record *record);


/**
 * Destroy the specified VIF instance.
 */
extern bool
xen_vif_destroy(xen_session *session, xen_vif vif);


/**
 * Get the uuid field of the given VIF.
 */
extern bool
xen_vif_get_uuid(xen_session *session, char **result, xen_vif vif);


/**
 * Get the device field of the given VIF.
 */
extern bool
xen_vif_get_device(xen_session *session, char **result, xen_vif vif);


/**
 * Get the network field of the given VIF.
 */
extern bool
xen_vif_get_network(xen_session *session, xen_network *result, xen_vif vif);


/**
 * Get the VM field of the given VIF.
 */
extern bool
xen_vif_get_vm(xen_session *session, xen_vm *result, xen_vif vif);


/**
 * Get the MAC field of the given VIF.
 */
extern bool
xen_vif_get_mac(xen_session *session, char **result, xen_vif vif);


/**
 * Get the MTU field of the given VIF.
 */
extern bool
xen_vif_get_mtu(xen_session *session, int64_t *result, xen_vif vif);


/**
 * Get the currently_attached field of the given VIF.
 */
extern bool
xen_vif_get_currently_attached(xen_session *session, bool *result, xen_vif vif);


/**
 * Get the status_code field of the given VIF.
 */
extern bool
xen_vif_get_status_code(xen_session *session, int64_t *result, xen_vif vif);


/**
 * Get the status_detail field of the given VIF.
 */
extern bool
xen_vif_get_status_detail(xen_session *session, char **result, xen_vif vif);


/**
 * Get the runtime_properties field of the given VIF.
 */
extern bool
xen_vif_get_runtime_properties(xen_session *session, xen_string_string_map **result, xen_vif vif);


/**
 * Get the qos/algorithm_type field of the given VIF.
 */
extern bool
xen_vif_get_qos_algorithm_type(xen_session *session, char **result, xen_vif vif);


/**
 * Get the qos/algorithm_params field of the given VIF.
 */
extern bool
xen_vif_get_qos_algorithm_params(xen_session *session, xen_string_string_map **result, xen_vif vif);


/**
 * Get the qos/supported_algorithms field of the given VIF.
 */
extern bool
xen_vif_get_qos_supported_algorithms(xen_session *session, struct xen_string_set **result, xen_vif vif);


/**
 * Get the metrics field of the given VIF.
 */
extern bool
xen_vif_get_metrics(xen_session *session, xen_vif_metrics *result, xen_vif vif);


/**
 * Set the device field of the given VIF.
 */
extern bool
xen_vif_set_device(xen_session *session, xen_vif vif, char *device);


/**
 * Set the MAC field of the given VIF.
 */
extern bool
xen_vif_set_mac(xen_session *session, xen_vif vif, char *mac);


/**
 * Set the MTU field of the given VIF.
 */
extern bool
xen_vif_set_mtu(xen_session *session, xen_vif vif, int64_t mtu);


/**
 * Set the qos/algorithm_type field of the given VIF.
 */
extern bool
xen_vif_set_qos_algorithm_type(xen_session *session, xen_vif vif, char *algorithm_type);


/**
 * Set the qos/algorithm_params field of the given VIF.
 */
extern bool
xen_vif_set_qos_algorithm_params(xen_session *session, xen_vif vif, xen_string_string_map *algorithm_params);


/**
 * Add the given key-value pair to the qos/algorithm_params field of
 * the given VIF.
 */
extern bool
xen_vif_add_to_qos_algorithm_params(xen_session *session, xen_vif vif, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * qos/algorithm_params field of the given VIF.  If the key is not in that
 * Map, then do nothing.
 */
extern bool
xen_vif_remove_from_qos_algorithm_params(xen_session *session, xen_vif vif, char *key);


/**
 * Hotplug the specified VIF, dynamically attaching it to the running
 * VM.
 */
extern bool
xen_vif_plug(xen_session *session, xen_vif self);


/**
 * Hot-unplug the specified VIF, dynamically unattaching it from the
 * running VM.
 */
extern bool
xen_vif_unplug(xen_session *session, xen_vif self);


/**
 * Return a list of all the VIFs known to the system.
 */
extern bool
xen_vif_get_all(xen_session *session, struct xen_vif_set **result);


#endif
