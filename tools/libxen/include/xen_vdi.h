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

#ifndef XEN_VDI_H
#define XEN_VDI_H

#include "xen_common.h"
#include "xen_crashdump_decl.h"
#include "xen_sr_decl.h"
#include "xen_vbd_decl.h"
#include "xen_vdi_decl.h"
#include "xen_vdi_type.h"


/*
 * The VDI class.
 * 
 * A virtual disk image.
 */


/**
 * Free the given xen_vdi.  The given handle must have been allocated
 * by this library.
 */
extern void
xen_vdi_free(xen_vdi vdi);


typedef struct xen_vdi_set
{
    size_t size;
    xen_vdi *contents[];
} xen_vdi_set;

/**
 * Allocate a xen_vdi_set of the given size.
 */
extern xen_vdi_set *
xen_vdi_set_alloc(size_t size);

/**
 * Free the given xen_vdi_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_vdi_set_free(xen_vdi_set *set);


typedef struct xen_vdi_record
{
    xen_vdi handle;
    char *uuid;
    char *name_label;
    char *name_description;
    struct xen_sr_record_opt *sr;
    struct xen_vbd_record_opt_set *vbds;
    struct xen_crashdump_record_opt_set *crash_dumps;
    int64_t virtual_size;
    int64_t physical_utilisation;
    int64_t sector_size;
    char *location;
    enum xen_vdi_type type;
    bool sharable;
    bool read_only;
} xen_vdi_record;

/**
 * Allocate a xen_vdi_record.
 */
extern xen_vdi_record *
xen_vdi_record_alloc(void);

/**
 * Free the given xen_vdi_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_vdi_record_free(xen_vdi_record *record);


typedef struct xen_vdi_record_opt
{
    bool is_record;
    union
    {
        xen_vdi handle;
        xen_vdi_record *record;
    } u;
} xen_vdi_record_opt;

/**
 * Allocate a xen_vdi_record_opt.
 */
extern xen_vdi_record_opt *
xen_vdi_record_opt_alloc(void);

/**
 * Free the given xen_vdi_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_vdi_record_opt_free(xen_vdi_record_opt *record_opt);


typedef struct xen_vdi_record_set
{
    size_t size;
    xen_vdi_record *contents[];
} xen_vdi_record_set;

/**
 * Allocate a xen_vdi_record_set of the given size.
 */
extern xen_vdi_record_set *
xen_vdi_record_set_alloc(size_t size);

/**
 * Free the given xen_vdi_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_vdi_record_set_free(xen_vdi_record_set *set);



typedef struct xen_vdi_record_opt_set
{
    size_t size;
    xen_vdi_record_opt *contents[];
} xen_vdi_record_opt_set;

/**
 * Allocate a xen_vdi_record_opt_set of the given size.
 */
extern xen_vdi_record_opt_set *
xen_vdi_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_vdi_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_vdi_record_opt_set_free(xen_vdi_record_opt_set *set);


/**
 * Get a record containing the current state of the given VDI.
 */
extern bool
xen_vdi_get_record(xen_session *session, xen_vdi_record **result, xen_vdi vdi);


/**
 * Get a reference to the VDI instance with the specified UUID.
 */
extern bool
xen_vdi_get_by_uuid(xen_session *session, xen_vdi *result, char *uuid);


/**
 * Create a new VDI instance, and return its handle.
 */
extern bool
xen_vdi_create(xen_session *session, xen_vdi *result, xen_vdi_record *record);


/**
 * Destroy the specified VDI instance.
 */
extern bool
xen_vdi_destroy(xen_session *session, xen_vdi vdi);


/**
 * Get all the VDI instances with the given label.
 */
extern bool
xen_vdi_get_by_name_label(xen_session *session, struct xen_vdi_set **result, char *label);


/**
 * Get the uuid field of the given VDI.
 */
extern bool
xen_vdi_get_uuid(xen_session *session, char **result, xen_vdi vdi);


/**
 * Get the name/label field of the given VDI.
 */
extern bool
xen_vdi_get_name_label(xen_session *session, char **result, xen_vdi vdi);


/**
 * Get the name/description field of the given VDI.
 */
extern bool
xen_vdi_get_name_description(xen_session *session, char **result, xen_vdi vdi);


/**
 * Get the SR field of the given VDI.
 */
extern bool
xen_vdi_get_sr(xen_session *session, xen_sr *result, xen_vdi vdi);


/**
 * Get the VBDs field of the given VDI.
 */
extern bool
xen_vdi_get_vbds(xen_session *session, struct xen_vbd_set **result, xen_vdi vdi);


/**
 * Get the crash_dumps field of the given VDI.
 */
extern bool
xen_vdi_get_crash_dumps(xen_session *session, struct xen_crashdump_set **result, xen_vdi vdi);


/**
 * Get the virtual_size field of the given VDI.
 */
extern bool
xen_vdi_get_virtual_size(xen_session *session, int64_t *result, xen_vdi vdi);


/**
 * Get the physical_utilisation field of the given VDI.
 */
extern bool
xen_vdi_get_physical_utilisation(xen_session *session, int64_t *result, xen_vdi vdi);


/**
 * Get the sector_size field of the given VDI.
 */
extern bool
xen_vdi_get_sector_size(xen_session *session, int64_t *result, xen_vdi vdi);


/**
 * Get the type field of the given VDI.
 */
extern bool
xen_vdi_get_type(xen_session *session, enum xen_vdi_type *result, xen_vdi vdi);


/**
 * Get the sharable field of the given VDI.
 */
extern bool
xen_vdi_get_sharable(xen_session *session, bool *result, xen_vdi vdi);


/**
 * Get the read_only field of the given VDI.
 */
extern bool
xen_vdi_get_read_only(xen_session *session, bool *result, xen_vdi vdi);


/**
 * Set the name/label field of the given VDI.
 */
extern bool
xen_vdi_set_name_label(xen_session *session, xen_vdi vdi, char *label);


/**
 * Set the name/description field of the given VDI.
 */
extern bool
xen_vdi_set_name_description(xen_session *session, xen_vdi vdi, char *description);


/**
 * Set the SR field of the given VDI.
 */
extern bool
xen_vdi_set_sr(xen_session *session, xen_vdi vdi, xen_sr sr);


/**
 * Set the virtual_size field of the given VDI.
 */
extern bool
xen_vdi_set_virtual_size(xen_session *session, xen_vdi vdi, int64_t virtual_size);


/**
 * Set the sharable field of the given VDI.
 */
extern bool
xen_vdi_set_sharable(xen_session *session, xen_vdi vdi, bool sharable);


/**
 * Set the read_only field of the given VDI.
 */
extern bool
xen_vdi_set_read_only(xen_session *session, xen_vdi vdi, bool read_only);


/**
 * Take an exact copy of the VDI; the snapshot lives in the same
 * Storage Repository as its parent.
 */
extern bool
xen_vdi_snapshot(xen_session *session, xen_vdi *result, xen_vdi vdi);


/**
 * Resize the vdi to the size.
 */
extern bool
xen_vdi_resize(xen_session *session, xen_vdi vdi, int64_t size);


/**
 * Return a list of all the VDIs known to the system.
 */
extern bool
xen_vdi_get_all(xen_session *session, struct xen_vdi_set **result);


#endif
