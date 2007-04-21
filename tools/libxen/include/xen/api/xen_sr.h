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

#ifndef XEN_SR_H
#define XEN_SR_H

#include <xen/api/xen_common.h>
#include <xen/api/xen_pbd_decl.h>
#include <xen/api/xen_sr_decl.h>
#include <xen/api/xen_string_set.h>
#include <xen/api/xen_vdi_decl.h>


/*
 * The SR class.
 * 
 * A storage repository.
 */


/**
 * Free the given xen_sr.  The given handle must have been allocated by
 * this library.
 */
extern void
xen_sr_free(xen_sr sr);


typedef struct xen_sr_set
{
    size_t size;
    xen_sr *contents[];
} xen_sr_set;

/**
 * Allocate a xen_sr_set of the given size.
 */
extern xen_sr_set *
xen_sr_set_alloc(size_t size);

/**
 * Free the given xen_sr_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_sr_set_free(xen_sr_set *set);


typedef struct xen_sr_record
{
    xen_sr handle;
    char *uuid;
    char *name_label;
    char *name_description;
    struct xen_vdi_record_opt_set *vdis;
    struct xen_pbd_record_opt_set *pbds;
    int64_t virtual_allocation;
    int64_t physical_utilisation;
    int64_t physical_size;
    char *type;
    char *content_type;
} xen_sr_record;

/**
 * Allocate a xen_sr_record.
 */
extern xen_sr_record *
xen_sr_record_alloc(void);

/**
 * Free the given xen_sr_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_sr_record_free(xen_sr_record *record);


typedef struct xen_sr_record_opt
{
    bool is_record;
    union
    {
        xen_sr handle;
        xen_sr_record *record;
    } u;
} xen_sr_record_opt;

/**
 * Allocate a xen_sr_record_opt.
 */
extern xen_sr_record_opt *
xen_sr_record_opt_alloc(void);

/**
 * Free the given xen_sr_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_sr_record_opt_free(xen_sr_record_opt *record_opt);


typedef struct xen_sr_record_set
{
    size_t size;
    xen_sr_record *contents[];
} xen_sr_record_set;

/**
 * Allocate a xen_sr_record_set of the given size.
 */
extern xen_sr_record_set *
xen_sr_record_set_alloc(size_t size);

/**
 * Free the given xen_sr_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_sr_record_set_free(xen_sr_record_set *set);



typedef struct xen_sr_record_opt_set
{
    size_t size;
    xen_sr_record_opt *contents[];
} xen_sr_record_opt_set;

/**
 * Allocate a xen_sr_record_opt_set of the given size.
 */
extern xen_sr_record_opt_set *
xen_sr_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_sr_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_sr_record_opt_set_free(xen_sr_record_opt_set *set);


/**
 * Get a record containing the current state of the given SR.
 */
extern bool
xen_sr_get_record(xen_session *session, xen_sr_record **result, xen_sr sr);


/**
 * Get a reference to the SR instance with the specified UUID.
 */
extern bool
xen_sr_get_by_uuid(xen_session *session, xen_sr *result, char *uuid);


/**
 * Get all the SR instances with the given label.
 */
extern bool
xen_sr_get_by_name_label(xen_session *session, struct xen_sr_set **result, char *label);


/**
 * Get the uuid field of the given SR.
 */
extern bool
xen_sr_get_uuid(xen_session *session, char **result, xen_sr sr);


/**
 * Get the name/label field of the given SR.
 */
extern bool
xen_sr_get_name_label(xen_session *session, char **result, xen_sr sr);


/**
 * Get the name/description field of the given SR.
 */
extern bool
xen_sr_get_name_description(xen_session *session, char **result, xen_sr sr);


/**
 * Get the VDIs field of the given SR.
 */
extern bool
xen_sr_get_vdis(xen_session *session, struct xen_vdi_set **result, xen_sr sr);


/**
 * Get the PBDs field of the given SR.
 */
extern bool
xen_sr_get_pbds(xen_session *session, struct xen_pbd_set **result, xen_sr sr);


/**
 * Get the virtual_allocation field of the given SR.
 */
extern bool
xen_sr_get_virtual_allocation(xen_session *session, int64_t *result, xen_sr sr);


/**
 * Get the physical_utilisation field of the given SR.
 */
extern bool
xen_sr_get_physical_utilisation(xen_session *session, int64_t *result, xen_sr sr);


/**
 * Get the physical_size field of the given SR.
 */
extern bool
xen_sr_get_physical_size(xen_session *session, int64_t *result, xen_sr sr);


/**
 * Get the type field of the given SR.
 */
extern bool
xen_sr_get_type(xen_session *session, char **result, xen_sr sr);


/**
 * Get the content_type field of the given SR.
 */
extern bool
xen_sr_get_content_type(xen_session *session, char **result, xen_sr sr);


/**
 * Set the name/label field of the given SR.
 */
extern bool
xen_sr_set_name_label(xen_session *session, xen_sr sr, char *label);


/**
 * Set the name/description field of the given SR.
 */
extern bool
xen_sr_set_name_description(xen_session *session, xen_sr sr, char *description);


/**
 * Return a set of all the SR types supported by the system.
 */
extern bool
xen_sr_get_supported_types(xen_session *session, struct xen_string_set **result);


/**
 * Return a list of all the SRs known to the system.
 */
extern bool
xen_sr_get_all(xen_session *session, struct xen_sr_set **result);


#endif
