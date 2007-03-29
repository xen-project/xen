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


#include <stddef.h>
#include <stdlib.h>

#include "xen_common.h"
#include "xen_event.h"
#include "xen_event_operation_internal.h"
#include "xen_internal.h"


XEN_ALLOC(xen_event_record)
XEN_SET_ALLOC_FREE(xen_event_record)


static const struct_member xen_event_record_struct_members[] =
    {
        { .key = "id",
          .type = &abstract_type_int,
          .offset = offsetof(xen_event_record, id) },
        { .key = "timestamp",
          .type = &abstract_type_datetime,
          .offset = offsetof(xen_event_record, timestamp) },
        { .key = "class",
          .type = &abstract_type_string,
          .offset = offsetof(xen_event_record, class) },
        { .key = "operation",
          .type = &xen_event_operation_abstract_type_,
          .offset = offsetof(xen_event_record, operation) },
        { .key = "ref",
          .type = &abstract_type_string,
          .offset = offsetof(xen_event_record, ref) },
        { .key = "obj_uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_event_record, obj_uuid) }
    };

const abstract_type xen_event_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_event_record),
       .member_count =
           sizeof(xen_event_record_struct_members) / sizeof(struct_member),
       .members = xen_event_record_struct_members
    };


const abstract_type xen_event_record_set_abstract_type_ =
    {
       .typename = SET,
        .child = &xen_event_record_abstract_type_
    };


void
xen_event_record_free(xen_event_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->class);
    free(record->ref);
    free(record->obj_uuid);
    free(record);
}


bool
xen_event_register(xen_session *session, struct xen_string_set *classes)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string_set,
              .u.set_val = (arbitrary_set *)classes }
        };

    xen_call_(session, "event.register", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_event_unregister(xen_session *session, struct xen_string_set *classes)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string_set,
              .u.set_val = (arbitrary_set *)classes }
        };

    xen_call_(session, "event.unregister", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_event_next(xen_session *session, struct xen_event_record_set **result)
{

    abstract_type result_type = xen_event_record_set_abstract_type_;

    *result = NULL;
    xen_call_(session, "event.next", NULL, 0, &result_type, result);
    return session->ok;
}
