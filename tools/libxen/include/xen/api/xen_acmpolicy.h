/*
 * Copyright (c) 2007, IBM Corp.
 * Copyright (c) 2007, XenSource Inc.
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

#ifndef XEN_ACMPOLICY_H
#define XEN_ACMPOLICY_H

#include "xen_common.h"
#include "xen_string_string_map.h"
#include "xen_xspolicy_decl.h"
#include "xen_vm_decl.h"

/*
 * Data structures.
 */

typedef struct xen_acmpolicy_record
{
    xen_xspolicy handle;
    char *uuid;
    char *repr;
    xs_instantiationflags flags;
    xs_type type;
} xen_acmpolicy_record;

/**
 * Allocate a xen_acmpolicy_record.
 */
extern xen_acmpolicy_record *
xen_acmpolicy_record_alloc(void);

/**
 * Free the given xen_xspolicy_record, and all referenced values.  The
 * given record must have been allocated by this library.
 */
extern void
xen_acmpolicy_record_free(xen_acmpolicy_record *record);


/**
 * Data structures for the policy's header
 */
typedef struct xen_acm_header
{
    char *policyname;
    char *policyurl;
    char *date;
    char *reference;
    char *namespaceurl;
    char *version;
} xen_acm_header;

extern xen_acm_header *
xen_acm_header_alloc(void);

extern void
xen_acm_header_free(xen_acm_header *hdr);

/**
 * Get the referenced policy's record.
 */
extern bool
xen_acmpolicy_get_record(xen_session *session, xen_acmpolicy_record **result,
                         xen_xspolicy xspolicy);

/**
 * Get the header of a  policy.
 */
extern bool
xen_acmpolicy_get_header(xen_session *session, xen_acm_header **hdr,
                         xen_xspolicy xspolicy);


/**
 * Get the XML representation of the policy.
 */
extern bool
xen_acmpolicy_get_xml(xen_session *session, char **xml,
                      xen_xspolicy xspolicy);

/**
 * Get the mapping file of the policy.
 */
extern bool
xen_acmpolicy_get_map(xen_session *session, char **map,
                      xen_xspolicy xspolicy);

/**
 * Get the binary representation (base64-encoded) of the policy.
 */
extern bool
xen_acmpolicy_get_binary(xen_session *session, char **binary,
                         xen_xspolicy xspolicy);

/**
 * Get the binary representation (base64-encoded) of the currently
 * enforced policy.
 */
extern bool
xen_acmpolicy_get_enforced_binary(xen_session *session, char **binary,
                                  xen_xspolicy xspolicy);

/**
 * Get the ACM ssidref of the given VM.
 */
extern bool
xen_acmpolicy_get_VM_ssidref(xen_session *session, int64_t *result,
                             xen_vm vm);

/**
 * Get the UUID field of the given policy.
 */
extern bool
xen_acmpolicy_get_uuid(xen_session *session, char **result,
                       xen_xspolicy xspolicy);

#endif
