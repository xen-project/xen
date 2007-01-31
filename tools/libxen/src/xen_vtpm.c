/*
 * Copyright (c) 2006, XenSource Inc.
 * Copyright (c) 2006, IBM Corp.
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
#include "xen_vm.h"
#include "xen_vtpm.h"


XEN_FREE(xen_vtpm)
XEN_SET_ALLOC_FREE(xen_vtpm)
XEN_ALLOC(xen_vtpm_record)
XEN_SET_ALLOC_FREE(xen_vtpm_record)
XEN_ALLOC(xen_vtpm_record_opt)
XEN_RECORD_OPT_FREE(xen_vtpm)
XEN_SET_ALLOC_FREE(xen_vtpm_record_opt)


static const struct_member xen_vtpm_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vtpm_record, uuid) },
        { .key = "VM",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vtpm_record, vm) },
        { .key = "backend",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vtpm_record, backend) },
    };

const abstract_type xen_vtpm_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vtpm_record),
       .member_count =
           sizeof(xen_vtpm_record_struct_members) / sizeof(struct_member),
       .members = xen_vtpm_record_struct_members
    };


void
xen_vtpm_record_free(xen_vtpm_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_vm_record_opt_free(record->vm);
    xen_vm_record_opt_free(record->backend);
    free(record);
}


bool
xen_vtpm_get_record(xen_session *session, xen_vtpm_record **result, xen_vtpm vtpm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vtpm }
        };

    abstract_type result_type = xen_vtpm_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VTPM.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vtpm_get_by_uuid(xen_session *session, xen_vtpm *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VTPM.get_by_uuid");
    return session->ok;
}


bool
xen_vtpm_create(xen_session *session, xen_vtpm *result, xen_vtpm_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_vtpm_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VTPM.create");
    return session->ok;
}


bool
xen_vtpm_destroy(xen_session *session, xen_vtpm vtpm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vtpm }
        };

    xen_call_(session, "VTPM.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vtpm_get_vm(xen_session *session, xen_vm *result, xen_vtpm vtpm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vtpm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VTPM.get_VM");
    return session->ok;
}


bool
xen_vtpm_get_backend(xen_session *session, xen_vm *result, xen_vtpm vtpm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vtpm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VTPM.get_backend");
    return session->ok;
}


bool
xen_vtpm_get_uuid(xen_session *session, char **result, xen_vtpm vtpm)
{
    *result = session->ok ? xen_strdup_((char *)vtpm) : NULL;
    return session->ok;
}
