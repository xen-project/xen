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

#include <string.h>

#include "xen_internal.h"
#include "xen_event_operation.h"
#include "xen_event_operation_internal.h"


/*
 * Maintain this in the same order as the enum declaration!
 */
static const char *lookup_table[] =
{
    "add",
    "del",
    "mod"
};


extern xen_event_operation_set *
xen_event_operation_set_alloc(size_t size)
{
    return calloc(1, sizeof(xen_event_operation_set) +
                  size * sizeof(enum xen_event_operation));
}


extern void
xen_event_operation_set_free(xen_event_operation_set *set)
{
    free(set);
}


const char *
xen_event_operation_to_string(enum xen_event_operation val)
{
    return lookup_table[val];
}


extern enum xen_event_operation
xen_event_operation_from_string(xen_session *session, const char *str)
{
    return ENUM_LOOKUP(session, str, lookup_table);
}


const abstract_type xen_event_operation_abstract_type_ =
    {
        .typename = ENUM,
        .enum_marshaller =
             (const char *(*)(int))&xen_event_operation_to_string,
        .enum_demarshaller =
             (int (*)(xen_session *, const char *))&xen_event_operation_from_string
    };


