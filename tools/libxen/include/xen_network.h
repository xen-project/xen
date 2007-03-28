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

#ifndef XEN_NETWORK_H
#define XEN_NETWORK_H

#include "xen_common.h"
#include "xen_network_decl.h"
#include "xen_pif_decl.h"
#include "xen_string_string_map.h"
#include "xen_vif_decl.h"


/*
 * The network class.
 * 
 * A virtual network.
 */


/**
 * Free the given xen_network.  The given handle must have been
 * allocated by this library.
 */
extern void
xen_network_free(xen_network network);


typedef struct xen_network_set
{
    size_t size;
    xen_network *contents[];
} xen_network_set;

/**
 * Allocate a xen_network_set of the given size.
 */
extern xen_network_set *
xen_network_set_alloc(size_t size);

/**
 * Free the given xen_network_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_network_set_free(xen_network_set *set);


typedef struct xen_network_record
{
    xen_network handle;
    char *uuid;
    char *name_label;
    char *name_description;
    struct xen_vif_record_opt_set *vifs;
    struct xen_pif_record_opt_set *pifs;
    xen_string_string_map *other_config;
} xen_network_record;

/**
 * Allocate a xen_network_record.
 */
extern xen_network_record *
xen_network_record_alloc(void);

/**
 * Free the given xen_network_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_network_record_free(xen_network_record *record);


typedef struct xen_network_record_opt
{
    bool is_record;
    union
    {
        xen_network handle;
        xen_network_record *record;
    } u;
} xen_network_record_opt;

/**
 * Allocate a xen_network_record_opt.
 */
extern xen_network_record_opt *
xen_network_record_opt_alloc(void);

/**
 * Free the given xen_network_record_opt, and all referenced values. 
 * The given record_opt must have been allocated by this library.
 */
extern void
xen_network_record_opt_free(xen_network_record_opt *record_opt);


typedef struct xen_network_record_set
{
    size_t size;
    xen_network_record *contents[];
} xen_network_record_set;

/**
 * Allocate a xen_network_record_set of the given size.
 */
extern xen_network_record_set *
xen_network_record_set_alloc(size_t size);

/**
 * Free the given xen_network_record_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_network_record_set_free(xen_network_record_set *set);



typedef struct xen_network_record_opt_set
{
    size_t size;
    xen_network_record_opt *contents[];
} xen_network_record_opt_set;

/**
 * Allocate a xen_network_record_opt_set of the given size.
 */
extern xen_network_record_opt_set *
xen_network_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_network_record_opt_set, and all referenced
 * values.  The given set must have been allocated by this library.
 */
extern void
xen_network_record_opt_set_free(xen_network_record_opt_set *set);


/**
 * Get a record containing the current state of the given network.
 */
extern bool
xen_network_get_record(xen_session *session, xen_network_record **result, xen_network network);


/**
 * Get a reference to the network instance with the specified UUID.
 */
extern bool
xen_network_get_by_uuid(xen_session *session, xen_network *result, char *uuid);


/**
 * Create a new network instance, and return its handle.
 */
extern bool
xen_network_create(xen_session *session, xen_network *result, xen_network_record *record);


/**
 * Destroy the specified network instance.
 */
extern bool
xen_network_destroy(xen_session *session, xen_network network);


/**
 * Get all the network instances with the given label.
 */
extern bool
xen_network_get_by_name_label(xen_session *session, struct xen_network_set **result, char *label);


/**
 * Get the uuid field of the given network.
 */
extern bool
xen_network_get_uuid(xen_session *session, char **result, xen_network network);


/**
 * Get the name/label field of the given network.
 */
extern bool
xen_network_get_name_label(xen_session *session, char **result, xen_network network);


/**
 * Get the name/description field of the given network.
 */
extern bool
xen_network_get_name_description(xen_session *session, char **result, xen_network network);


/**
 * Get the VIFs field of the given network.
 */
extern bool
xen_network_get_vifs(xen_session *session, struct xen_vif_set **result, xen_network network);


/**
 * Get the PIFs field of the given network.
 */
extern bool
xen_network_get_pifs(xen_session *session, struct xen_pif_set **result, xen_network network);


/**
 * Get the other_config field of the given network.
 */
extern bool
xen_network_get_other_config(xen_session *session, xen_string_string_map **result, xen_network network);


/**
 * Set the name/label field of the given network.
 */
extern bool
xen_network_set_name_label(xen_session *session, xen_network network, char *label);


/**
 * Set the name/description field of the given network.
 */
extern bool
xen_network_set_name_description(xen_session *session, xen_network network, char *description);


/**
 * Set the other_config field of the given network.
 */
extern bool
xen_network_set_other_config(xen_session *session, xen_network network, xen_string_string_map *other_config);


/**
 * Add the given key-value pair to the other_config field of the given
 * network.
 */
extern bool
xen_network_add_to_other_config(xen_session *session, xen_network network, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * other_config field of the given network.  If the key is not in that Map,
 * then do nothing.
 */
extern bool
xen_network_remove_from_other_config(xen_session *session, xen_network network, char *key);


/**
 * Return a list of all the networks known to the system.
 */
extern bool
xen_network_get_all(xen_session *session, struct xen_network_set **result);


#endif
