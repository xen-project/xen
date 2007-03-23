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
#include "xen_crashdump.h"
#include "xen_internal.h"
#include "xen_vdi.h"
#include "xen_vm.h"


XEN_FREE(xen_crashdump)
XEN_SET_ALLOC_FREE(xen_crashdump)
XEN_ALLOC(xen_crashdump_record)
XEN_SET_ALLOC_FREE(xen_crashdump_record)
XEN_ALLOC(xen_crashdump_record_opt)
XEN_RECORD_OPT_FREE(xen_crashdump)
XEN_SET_ALLOC_FREE(xen_crashdump_record_opt)


static const struct_member xen_crashdump_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_crashdump_record, uuid) },
        { .key = "VM",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_crashdump_record, vm) },
        { .key = "VDI",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_crashdump_record, vdi) }
    };

const abstract_type xen_crashdump_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_crashdump_record),
       .member_count =
           sizeof(xen_crashdump_record_struct_members) / sizeof(struct_member),
       .members = xen_crashdump_record_struct_members
    };


void
xen_crashdump_record_free(xen_crashdump_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_vm_record_opt_free(record->vm);
    xen_vdi_record_opt_free(record->vdi);
    free(record);
}


bool
xen_crashdump_get_record(xen_session *session, xen_crashdump_record **result, xen_crashdump crashdump)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = crashdump }
        };

    abstract_type result_type = xen_crashdump_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("crashdump.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_crashdump_get_by_uuid(xen_session *session, xen_crashdump *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("crashdump.get_by_uuid");
    return session->ok;
}


bool
xen_crashdump_get_vm(xen_session *session, xen_vm *result, xen_crashdump crashdump)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = crashdump }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("crashdump.get_VM");
    return session->ok;
}


bool
xen_crashdump_get_vdi(xen_session *session, xen_vdi *result, xen_crashdump crashdump)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = crashdump }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("crashdump.get_VDI");
    return session->ok;
}


bool
xen_crashdump_destroy(xen_session *session, xen_crashdump self)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self }
        };

    xen_call_(session, "crashdump.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_crashdump_get_all(xen_session *session, struct xen_crashdump_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "crashdump.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_crashdump_get_uuid(xen_session *session, char **result, xen_crashdump crashdump)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = crashdump }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("crashdump.get_uuid");
    return session->ok;
}
