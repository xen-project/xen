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
#include "xen_internal.h"
#include "xen_string_string_map.h"
#include "xen_vm_guest_metrics.h"


XEN_FREE(xen_vm_guest_metrics)
XEN_SET_ALLOC_FREE(xen_vm_guest_metrics)
XEN_ALLOC(xen_vm_guest_metrics_record)
XEN_SET_ALLOC_FREE(xen_vm_guest_metrics_record)
XEN_ALLOC(xen_vm_guest_metrics_record_opt)
XEN_RECORD_OPT_FREE(xen_vm_guest_metrics)
XEN_SET_ALLOC_FREE(xen_vm_guest_metrics_record_opt)


static const struct_member xen_vm_guest_metrics_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_guest_metrics_record, uuid) },
        { .key = "os_version",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, os_version) },
        { .key = "PV_drivers_version",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, pv_drivers_version) },
        { .key = "memory",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, memory) },
        { .key = "disks",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, disks) },
        { .key = "networks",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, networks) },
        { .key = "other",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_guest_metrics_record, other) }
    };

const abstract_type xen_vm_guest_metrics_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vm_guest_metrics_record),
       .member_count =
           sizeof(xen_vm_guest_metrics_record_struct_members) / sizeof(struct_member),
       .members = xen_vm_guest_metrics_record_struct_members
    };


void
xen_vm_guest_metrics_record_free(xen_vm_guest_metrics_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_string_string_map_free(record->os_version);
    xen_string_string_map_free(record->pv_drivers_version);
    xen_string_string_map_free(record->memory);
    xen_string_string_map_free(record->disks);
    xen_string_string_map_free(record->networks);
    xen_string_string_map_free(record->other);
    free(record);
}


bool
xen_vm_guest_metrics_get_record(xen_session *session, xen_vm_guest_metrics_record **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = xen_vm_guest_metrics_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vm_guest_metrics_get_by_uuid(xen_session *session, xen_vm_guest_metrics *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_by_uuid");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_os_version(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_os_version");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_pv_drivers_version(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_PV_drivers_version");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_memory(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_memory");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_disks(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_disks");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_networks(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_networks");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_other(xen_session *session, xen_string_string_map **result, xen_vm_guest_metrics vm_guest_metrics)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm_guest_metrics }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM_guest_metrics.get_other");
    return session->ok;
}


bool
xen_vm_guest_metrics_get_all(xen_session *session, struct xen_vm_guest_metrics_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "VM_guest_metrics.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_vm_guest_metrics_get_uuid(xen_session *session, char **result, xen_vm_guest_metrics vm_guest_metrics)
{
    *result = session->ok ? xen_strdup_((char *)vm_guest_metrics) : NULL;
    return session->ok;
}
