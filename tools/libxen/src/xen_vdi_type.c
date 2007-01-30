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

#include <string.h>

#include "xen_internal.h"
#include "xen_vdi_type.h"
#include "xen_vdi_type_internal.h"


/*
 * Maintain this in the same order as the enum declaration!
 */
static const char *lookup_table[] =
{
    "system",
    "user",
    "ephemeral",
    "suspend",
    "crashdump"
};


extern xen_vdi_type_set *
xen_vdi_type_set_alloc(size_t size)
{
    return calloc(1, sizeof(xen_vdi_type_set) +
                  size * sizeof(enum xen_vdi_type));
}


extern void
xen_vdi_type_set_free(xen_vdi_type_set *set)
{
    free(set);
}


const char *
xen_vdi_type_to_string(enum xen_vdi_type val)
{
    return lookup_table[val];
}


extern enum xen_vdi_type
xen_vdi_type_from_string(xen_session *session, const char *str)
{
    return ENUM_LOOKUP(session, str, lookup_table);
}


const abstract_type xen_vdi_type_abstract_type_ =
    {
        .typename = ENUM,
        .enum_marshaller =
             (const char *(*)(int))&xen_vdi_type_to_string,
        .enum_demarshaller =
             (int (*)(xen_session *, const char *))&xen_vdi_type_from_string
    };


const abstract_type xen_vdi_type_set_abstract_type_ =
    {
        .typename = SET,
        .child = &xen_vdi_type_abstract_type_
    };


