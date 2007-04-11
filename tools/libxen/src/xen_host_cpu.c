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
#include "xen_host.h"
#include "xen_host_cpu.h"
#include "xen_internal.h"


XEN_FREE(xen_host_cpu)
XEN_SET_ALLOC_FREE(xen_host_cpu)
XEN_ALLOC(xen_host_cpu_record)
XEN_SET_ALLOC_FREE(xen_host_cpu_record)
XEN_ALLOC(xen_host_cpu_record_opt)
XEN_RECORD_OPT_FREE(xen_host_cpu)
XEN_SET_ALLOC_FREE(xen_host_cpu_record_opt)


static const struct_member xen_host_cpu_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, uuid) },
        { .key = "host",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_host_cpu_record, host) },
        { .key = "number",
          .type = &abstract_type_int,
          .offset = offsetof(xen_host_cpu_record, number) },
        { .key = "vendor",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, vendor) },
        { .key = "speed",
          .type = &abstract_type_int,
          .offset = offsetof(xen_host_cpu_record, speed) },
        { .key = "modelname",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, modelname) },
        { .key = "stepping",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, stepping) },
        { .key = "flags",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, flags) },
        { .key = "features",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_cpu_record, features) },
        { .key = "utilisation",
          .type = &abstract_type_float,
          .offset = offsetof(xen_host_cpu_record, utilisation) }
    };

const abstract_type xen_host_cpu_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_host_cpu_record),
       .member_count =
           sizeof(xen_host_cpu_record_struct_members) / sizeof(struct_member),
       .members = xen_host_cpu_record_struct_members
    };


void
xen_host_cpu_record_free(xen_host_cpu_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_host_record_opt_free(record->host);
    free(record->vendor);
    free(record->modelname);
    free(record->stepping);
    free(record->flags);
    free(record->features);
    free(record);
}


bool
xen_host_cpu_get_record(xen_session *session, xen_host_cpu_record **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = xen_host_cpu_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("host_cpu.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_host_cpu_get_by_uuid(xen_session *session, xen_host_cpu *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_by_uuid");
    return session->ok;
}


bool
xen_host_cpu_get_host(xen_session *session, xen_host *result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_host");
    return session->ok;
}


bool
xen_host_cpu_get_number(xen_session *session, int64_t *result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("host_cpu.get_number");
    return session->ok;
}


bool
xen_host_cpu_get_vendor(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_vendor");
    return session->ok;
}


bool
xen_host_cpu_get_speed(xen_session *session, int64_t *result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("host_cpu.get_speed");
    return session->ok;
}


bool
xen_host_cpu_get_modelname(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_modelname");
    return session->ok;
}


bool
xen_host_cpu_get_stepping(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_stepping");
    return session->ok;
}


bool
xen_host_cpu_get_flags(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_flags");
    return session->ok;
}


bool
xen_host_cpu_get_features(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_features");
    return session->ok;
}


bool
xen_host_cpu_get_utilisation(xen_session *session, double *result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_float;

    XEN_CALL_("host_cpu.get_utilisation");
    return session->ok;
}


bool
xen_host_cpu_get_all(xen_session *session, struct xen_host_cpu_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "host_cpu.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_host_cpu_get_uuid(xen_session *session, char **result, xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host_cpu }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host_cpu.get_uuid");
    return session->ok;
}
