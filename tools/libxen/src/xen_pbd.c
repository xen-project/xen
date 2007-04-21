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
#include <xen/api/xen_host.h>
#include <xen/api/xen_pbd.h>
#include <xen/api/xen_sr.h>
#include <xen/api/xen_string_string_map.h>


XEN_FREE(xen_pbd)
XEN_SET_ALLOC_FREE(xen_pbd)
XEN_ALLOC(xen_pbd_record)
XEN_SET_ALLOC_FREE(xen_pbd_record)
XEN_ALLOC(xen_pbd_record_opt)
XEN_RECORD_OPT_FREE(xen_pbd)
XEN_SET_ALLOC_FREE(xen_pbd_record_opt)


static const struct_member xen_pbd_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_pbd_record, uuid) },
        { .key = "host",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_pbd_record, host) },
        { .key = "SR",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_pbd_record, sr) },
        { .key = "device_config",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_pbd_record, device_config) },
        { .key = "currently_attached",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_pbd_record, currently_attached) }
    };

const abstract_type xen_pbd_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_pbd_record),
       .member_count =
           sizeof(xen_pbd_record_struct_members) / sizeof(struct_member),
       .members = xen_pbd_record_struct_members
    };


void
xen_pbd_record_free(xen_pbd_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_host_record_opt_free(record->host);
    xen_sr_record_opt_free(record->sr);
    xen_string_string_map_free(record->device_config);
    free(record);
}


bool
xen_pbd_get_record(xen_session *session, xen_pbd_record **result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = xen_pbd_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("PBD.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_pbd_get_by_uuid(xen_session *session, xen_pbd *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("PBD.get_by_uuid");
    return session->ok;
}


bool
xen_pbd_create(xen_session *session, xen_pbd *result, xen_pbd_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_pbd_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("PBD.create");
    return session->ok;
}


bool
xen_pbd_destroy(xen_session *session, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    xen_call_(session, "PBD.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_pbd_get_host(xen_session *session, xen_host *result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("PBD.get_host");
    return session->ok;
}


bool
xen_pbd_get_sr(xen_session *session, xen_sr *result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("PBD.get_SR");
    return session->ok;
}


bool
xen_pbd_get_device_config(xen_session *session, xen_string_string_map **result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("PBD.get_device_config");
    return session->ok;
}


bool
xen_pbd_get_currently_attached(xen_session *session, bool *result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("PBD.get_currently_attached");
    return session->ok;
}


bool
xen_pbd_get_all(xen_session *session, struct xen_pbd_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "PBD.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_pbd_get_uuid(xen_session *session, char **result, xen_pbd pbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = pbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("PBD.get_uuid");
    return session->ok;
}
