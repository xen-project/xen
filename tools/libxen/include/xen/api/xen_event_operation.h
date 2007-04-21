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

#ifndef XEN_EVENT_OPERATION_H
#define XEN_EVENT_OPERATION_H


#include <xen/api/xen_common.h>


enum xen_event_operation
{
    /**
     * An object has been created
     */
    XEN_EVENT_OPERATION_ADD,

    /**
     * An object has been deleted
     */
    XEN_EVENT_OPERATION_DEL,

    /**
     * An object has been modified
     */
    XEN_EVENT_OPERATION_MOD
};


typedef struct xen_event_operation_set
{
    size_t size;
    enum xen_event_operation contents[];
} xen_event_operation_set;

/**
 * Allocate a xen_event_operation_set of the given size.
 */
extern xen_event_operation_set *
xen_event_operation_set_alloc(size_t size);

/**
 * Free the given xen_event_operation_set.  The given set must have
 * been allocated by this library.
 */
extern void
xen_event_operation_set_free(xen_event_operation_set *set);


/**
 * Return the name corresponding to the given code.  This string must
 * not be modified or freed.
 */
extern const char *
xen_event_operation_to_string(enum xen_event_operation val);


/**
 * Return the correct code for the given string, or set the session
 * object to failure and return an undefined value if the given string does
 * not match a known code.
 */
extern enum xen_event_operation
xen_event_operation_from_string(xen_session *session, const char *str);


#endif
