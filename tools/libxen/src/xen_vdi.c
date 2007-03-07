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


#include <stddef.h>
#include <stdlib.h>

#include "xen_common.h"
#include "xen_crashdump.h"
#include "xen_internal.h"
#include "xen_sr.h"
#include "xen_vbd.h"
#include "xen_vdi.h"
#include "xen_vdi_type_internal.h"


XEN_FREE(xen_vdi)
XEN_SET_ALLOC_FREE(xen_vdi)
XEN_ALLOC(xen_vdi_record)
XEN_SET_ALLOC_FREE(xen_vdi_record)
XEN_ALLOC(xen_vdi_record_opt)
XEN_RECORD_OPT_FREE(xen_vdi)
XEN_SET_ALLOC_FREE(xen_vdi_record_opt)


static const struct_member xen_vdi_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vdi_record, uuid) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vdi_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vdi_record, name_description) },
        { .key = "SR",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vdi_record, sr) },
        { .key = "VBDs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vdi_record, vbds) },
        { .key = "crash_dumps",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vdi_record, crash_dumps) },
        { .key = "virtual_size",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vdi_record, virtual_size) },
        { .key = "physical_utilisation",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vdi_record, physical_utilisation) },
        { .key = "sector_size",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vdi_record, sector_size) },
        { .key = "location",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vdi_record, location) },
        { .key = "type",
          .type = &xen_vdi_type_abstract_type_,
          .offset = offsetof(xen_vdi_record, type) },
        { .key = "sharable",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vdi_record, sharable) },
        { .key = "read_only",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vdi_record, read_only) }
    };

const abstract_type xen_vdi_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vdi_record),
       .member_count =
           sizeof(xen_vdi_record_struct_members) / sizeof(struct_member),
       .members = xen_vdi_record_struct_members
    };


void
xen_vdi_record_free(xen_vdi_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    xen_sr_record_opt_free(record->sr);
    xen_vbd_record_opt_set_free(record->vbds);
    xen_crashdump_record_opt_set_free(record->crash_dumps);
    free(record);
}


bool
xen_vdi_get_record(xen_session *session, xen_vdi_record **result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = xen_vdi_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VDI.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vdi_get_by_uuid(xen_session *session, xen_vdi *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.get_by_uuid");
    return session->ok;
}


bool
xen_vdi_create(xen_session *session, xen_vdi *result, xen_vdi_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_vdi_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.create");
    return session->ok;
}


bool
xen_vdi_destroy(xen_session *session, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    xen_call_(session, "VDI.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_get_by_name_label(xen_session *session, struct xen_vdi_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VDI.get_by_name_label");
    return session->ok;
}


bool
xen_vdi_get_name_label(xen_session *session, char **result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.get_name_label");
    return session->ok;
}


bool
xen_vdi_get_name_description(xen_session *session, char **result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.get_name_description");
    return session->ok;
}


bool
xen_vdi_get_sr(xen_session *session, xen_sr *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.get_SR");
    return session->ok;
}


bool
xen_vdi_get_vbds(xen_session *session, struct xen_vbd_set **result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VDI.get_VBDs");
    return session->ok;
}


bool
xen_vdi_get_crash_dumps(xen_session *session, struct xen_crashdump_set **result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VDI.get_crash_dumps");
    return session->ok;
}


bool
xen_vdi_get_virtual_size(xen_session *session, int64_t *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VDI.get_virtual_size");
    return session->ok;
}


bool
xen_vdi_get_physical_utilisation(xen_session *session, int64_t *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VDI.get_physical_utilisation");
    return session->ok;
}


bool
xen_vdi_get_sector_size(xen_session *session, int64_t *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VDI.get_sector_size");
    return session->ok;
}


bool
xen_vdi_get_type(xen_session *session, enum xen_vdi_type *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = xen_vdi_type_abstract_type_;
    XEN_CALL_("VDI.get_type");
    return session->ok;
}


bool
xen_vdi_get_sharable(xen_session *session, bool *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VDI.get_sharable");
    return session->ok;
}


bool
xen_vdi_get_read_only(xen_session *session, bool *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VDI.get_read_only");
    return session->ok;
}


bool
xen_vdi_set_name_label(xen_session *session, xen_vdi vdi, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "VDI.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_set_name_description(xen_session *session, xen_vdi vdi, char *description)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_string,
              .u.string_val = description }
        };

    xen_call_(session, "VDI.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_set_sr(xen_session *session, xen_vdi vdi, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    xen_call_(session, "VDI.set_SR", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_set_virtual_size(xen_session *session, xen_vdi vdi, int64_t virtual_size)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_int,
              .u.int_val = virtual_size }
        };

    xen_call_(session, "VDI.set_virtual_size", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_set_sharable(xen_session *session, xen_vdi vdi, bool sharable)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_bool,
              .u.bool_val = sharable }
        };

    xen_call_(session, "VDI.set_sharable", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_set_read_only(xen_session *session, xen_vdi vdi, bool read_only)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_bool,
              .u.bool_val = read_only }
        };

    xen_call_(session, "VDI.set_read_only", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_snapshot(xen_session *session, xen_vdi *result, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VDI.snapshot");
    return session->ok;
}


bool
xen_vdi_resize(xen_session *session, xen_vdi vdi, int64_t size)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vdi },
            { .type = &abstract_type_int,
              .u.int_val = size }
        };

    xen_call_(session, "VDI.resize", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vdi_get_all(xen_session *session, struct xen_vdi_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "VDI.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_vdi_get_uuid(xen_session *session, char **result, xen_vdi vdi)
{
    *result = session->ok ? xen_strdup_((char *)vdi) : NULL;
    return session->ok;
}
