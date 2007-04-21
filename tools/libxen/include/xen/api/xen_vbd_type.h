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

#ifndef XEN_VBD_TYPE_H
#define XEN_VBD_TYPE_H


#include <xen/api/xen_common.h>


enum xen_vbd_type
{
    /**
     * VBD will appear to guest as CD
     */
    XEN_VBD_TYPE_CD,

    /**
     * VBD will appear to guest as disk
     */
    XEN_VBD_TYPE_DISK
};


typedef struct xen_vbd_type_set
{
    size_t size;
    enum xen_vbd_type contents[];
} xen_vbd_type_set;

/**
 * Allocate a xen_vbd_type_set of the given size.
 */
extern xen_vbd_type_set *
xen_vbd_type_set_alloc(size_t size);

/**
 * Free the given xen_vbd_type_set.  The given set must have been
 * allocated by this library.
 */
extern void
xen_vbd_type_set_free(xen_vbd_type_set *set);


/**
 * Return the name corresponding to the given code.  This string must
 * not be modified or freed.
 */
extern const char *
xen_vbd_type_to_string(enum xen_vbd_type val);


/**
 * Return the correct code for the given string, or set the session
 * object to failure and return an undefined value if the given string does
 * not match a known code.
 */
extern enum xen_vbd_type
xen_vbd_type_from_string(xen_session *session, const char *str);


#endif
