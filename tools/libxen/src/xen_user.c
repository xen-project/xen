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

#include "xen_internal.h"
#include <xen/api/xen_common.h>
#include <xen/api/xen_user.h>


XEN_FREE(xen_user)
XEN_SET_ALLOC_FREE(xen_user)
XEN_ALLOC(xen_user_record)
XEN_SET_ALLOC_FREE(xen_user_record)
XEN_ALLOC(xen_user_record_opt)
XEN_RECORD_OPT_FREE(xen_user)
XEN_SET_ALLOC_FREE(xen_user_record_opt)


static const struct_member xen_user_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_user_record, uuid) },
        { .key = "short_name",
          .type = &abstract_type_string,
          .offset = offsetof(xen_user_record, short_name) },
        { .key = "fullname",
          .type = &abstract_type_string,
          .offset = offsetof(xen_user_record, fullname) }
    };

const abstract_type xen_user_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_user_record),
       .member_count =
           sizeof(xen_user_record_struct_members) / sizeof(struct_member),
       .members = xen_user_record_struct_members
    };


void
xen_user_record_free(xen_user_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->short_name);
    free(record->fullname);
    free(record);
}


bool
xen_user_get_record(xen_session *session, xen_user_record **result, xen_user user)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user }
        };

    abstract_type result_type = xen_user_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("user.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_user_get_by_uuid(xen_session *session, xen_user *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("user.get_by_uuid");
    return session->ok;
}


bool
xen_user_create(xen_session *session, xen_user *result, xen_user_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_user_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("user.create");
    return session->ok;
}


bool
xen_user_destroy(xen_session *session, xen_user user)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user }
        };

    xen_call_(session, "user.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_user_get_short_name(xen_session *session, char **result, xen_user user)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("user.get_short_name");
    return session->ok;
}


bool
xen_user_get_fullname(xen_session *session, char **result, xen_user user)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("user.get_fullname");
    return session->ok;
}


bool
xen_user_set_fullname(xen_session *session, xen_user user, char *fullname)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user },
            { .type = &abstract_type_string,
              .u.string_val = fullname }
        };

    xen_call_(session, "user.set_fullname", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_user_get_uuid(xen_session *session, char **result, xen_user user)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = user }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("user.get_uuid");
    return session->ok;
}
