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

#ifndef XEN_PIF_H
#define XEN_PIF_H

#include "xen_common.h"
#include "xen_host_decl.h"
#include "xen_network_decl.h"
#include "xen_pif_decl.h"
#include "xen_pif_metrics_decl.h"


/*
 * The PIF class.
 * 
 * A physical network interface (note separate VLANs are represented as
 * several PIFs).
 */


/**
 * Free the given xen_pif.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_pif_free(xen_pif pif);


typedef struct xen_pif_set
{
    size_t size;
    xen_pif *contents[];
} xen_pif_set;

/**
 * Allocate a xen_pif_set of the given size.
 */
extern xen_pif_set *
xen_pif_set_alloc(size_t size);

/**
 * Free the given xen_pif_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_pif_set_free(xen_pif_set *set);


typedef struct xen_pif_record
{
    xen_pif handle;
    char *uuid;
    char *device;
    struct xen_network_record_opt *network;
    struct xen_host_record_opt *host;
    char *mac;
    int64_t mtu;
    int64_t vlan;
    struct xen_pif_metrics_record_opt *metrics;
} xen_pif_record;

/**
 * Allocate a xen_pif_record.
 */
extern xen_pif_record *
xen_pif_record_alloc(void);

/**
 * Free the given xen_pif_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_pif_record_free(xen_pif_record *record);


typedef struct xen_pif_record_opt
{
    bool is_record;
    union
    {
        xen_pif handle;
        xen_pif_record *record;
    } u;
} xen_pif_record_opt;

/**
 * Allocate a xen_pif_record_opt.
 */
extern xen_pif_record_opt *
xen_pif_record_opt_alloc(void);

/**
 * Free the given xen_pif_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_pif_record_opt_free(xen_pif_record_opt *record_opt);


typedef struct xen_pif_record_set
{
    size_t size;
    xen_pif_record *contents[];
} xen_pif_record_set;

/**
 * Allocate a xen_pif_record_set of the given size.
 */
extern xen_pif_record_set *
xen_pif_record_set_alloc(size_t size);

/**
 * Free the given xen_pif_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_pif_record_set_free(xen_pif_record_set *set);



typedef struct xen_pif_record_opt_set
{
    size_t size;
    xen_pif_record_opt *contents[];
} xen_pif_record_opt_set;

/**
 * Allocate a xen_pif_record_opt_set of the given size.
 */
extern xen_pif_record_opt_set *
xen_pif_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_pif_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_pif_record_opt_set_free(xen_pif_record_opt_set *set);


/**
 * Get a record containing the current state of the given PIF.
 */
extern bool
xen_pif_get_record(xen_session *session, xen_pif_record **result, xen_pif pif);


/**
 * Get a reference to the PIF instance with the specified UUID.
 */
extern bool
xen_pif_get_by_uuid(xen_session *session, xen_pif *result, char *uuid);


/**
 * Get the uuid field of the given PIF.
 */
extern bool
xen_pif_get_uuid(xen_session *session, char **result, xen_pif pif);


/**
 * Get the device field of the given PIF.
 */
extern bool
xen_pif_get_device(xen_session *session, char **result, xen_pif pif);


/**
 * Get the network field of the given PIF.
 */
extern bool
xen_pif_get_network(xen_session *session, xen_network *result, xen_pif pif);


/**
 * Get the host field of the given PIF.
 */
extern bool
xen_pif_get_host(xen_session *session, xen_host *result, xen_pif pif);


/**
 * Get the MAC field of the given PIF.
 */
extern bool
xen_pif_get_mac(xen_session *session, char **result, xen_pif pif);


/**
 * Get the MTU field of the given PIF.
 */
extern bool
xen_pif_get_mtu(xen_session *session, int64_t *result, xen_pif pif);


/**
 * Get the VLAN field of the given PIF.
 */
extern bool
xen_pif_get_vlan(xen_session *session, int64_t *result, xen_pif pif);


/**
 * Get the metrics field of the given PIF.
 */
extern bool
xen_pif_get_metrics(xen_session *session, xen_pif_metrics *result, xen_pif pif);


/**
 * Set the device field of the given PIF.
 */
extern bool
xen_pif_set_device(xen_session *session, xen_pif pif, char *device);


/**
 * Set the MAC field of the given PIF.
 */
extern bool
xen_pif_set_mac(xen_session *session, xen_pif pif, char *mac);


/**
 * Set the MTU field of the given PIF.
 */
extern bool
xen_pif_set_mtu(xen_session *session, xen_pif pif, int64_t mtu);


/**
 * Set the VLAN field of the given PIF.
 */
extern bool
xen_pif_set_vlan(xen_session *session, xen_pif pif, int64_t vlan);


/**
 * Create a VLAN interface from an existing physical interface
 */
extern bool
xen_pif_create_vlan(xen_session *session, xen_pif *result, char *device, xen_network network, xen_host host, int64_t vlan);


/**
 * Destroy the interface (provided it is a synthetic interface like a
 * VLAN; fail if it is a physical interface)
 */
extern bool
xen_pif_destroy(xen_session *session, xen_pif self);


/**
 * Return a list of all the PIFs known to the system.
 */
extern bool
xen_pif_get_all(xen_session *session, struct xen_pif_set **result);


#endif
