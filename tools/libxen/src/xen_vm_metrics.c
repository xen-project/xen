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
#include "xen_int_float_map.h"
#include "xen_internal.h"
#include "xen_vm_metrics.h"


XEN_FREE(xen_vm_metrics)
XEN_SET_ALLOC_FREE(xen_vm_metrics)
XEN_ALLOC(xen_vm_metrics_record)
XEN_SET_ALLOC_FREE(xen_vm_metrics_record)
XEN_ALLOC(xen_vm_metrics_record_opt)
XEN_RECORD_OPT_FREE(xen_vm_metrics)
XEN_SET_ALLOC_FREE(xen_vm_metrics_record_opt)


static const struct_member xen_vm_metrics_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_metrics_record, uuid) },
        { .key = "memory_actual",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_metrics_record, memory_actual) },
        { .key = "VCPUs_number",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_metrics_record, vcpus_number) },
        { .key = "VCPUs_utilisation",
          .type = &abstract_type_int_float_map,
          .offset = offsetof(xen_vm_metrics_record, vcpus_utilisation) },
        { .key = "last_updated",
          .type = &abstract_type_datetime,
          .offset = offsetof(xen_vm_metrics_record, last_updated) }
    };

const abstract_type xen_vm_metrics_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vm_metrics_record),
       .member_count =
           sizeof(xen_vm_metrics_record_struct_members) / sizeof(struct_member),
       .members = xen_vm_metrics_record_struct_members
    };


void
xen_vm_metrics_record_free(xen_vm_metrics_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_int_float_map_free(record->vcpus_utilisation);
    free(record);
}


bool
xen_vm_metrics_get_record(xen_session *session, xen_vm_metrics_record **result, xen_vm_metrics vm_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_metrics }
        };

    abstract_type result_type = xen_vm_metrics_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM_metrics.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vm_metrics_get_by_uuid(xen_session *session, xen_vm_metrics *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM_metrics.get_by_uuid");
    return session->ok;
}


bool
xen_vm_metrics_get_memory_actual(xen_session *session, int64_t *result, xen_vm_metrics vm_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_metrics }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM_metrics.get_memory_actual");
    return session->ok;
}


bool
xen_vm_metrics_get_vcpus_number(xen_session *session, int64_t *result, xen_vm_metrics vm_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_metrics }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM_metrics.get_VCPUs_number");
    return session->ok;
}


bool
xen_vm_metrics_get_vcpus_utilisation(xen_session *session, xen_int_float_map **result, xen_vm_metrics vm_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_metrics }
        };

    abstract_type result_type = abstract_type_int_float_map;

    *result = NULL;
    XEN_CALL_("VM_metrics.get_VCPUs_utilisation");
    return session->ok;
}


bool
xen_vm_metrics_get_last_updated(xen_session *session, time_t *result, xen_vm_metrics vm_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_metrics }
        };

    abstract_type result_type = abstract_type_datetime;

    XEN_CALL_("VM_metrics.get_last_updated");
    return session->ok;
}


bool
xen_vm_metrics_get_all(xen_session *session, struct xen_vm_metrics_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "VM_metrics.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_vm_metrics_get_uuid(xen_session *session, char **result, xen_vm_metrics vm_metrics)
{
    *result = session->ok ? xen_strdup_((char *)vm_metrics) : NULL;
    return session->ok;
}
