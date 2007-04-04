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
#include "xen_pbd.h"
#include "xen_sr.h"
#include "xen_vdi.h"


XEN_FREE(xen_sr)
XEN_SET_ALLOC_FREE(xen_sr)
XEN_ALLOC(xen_sr_record)
XEN_SET_ALLOC_FREE(xen_sr_record)
XEN_ALLOC(xen_sr_record_opt)
XEN_RECORD_OPT_FREE(xen_sr)
XEN_SET_ALLOC_FREE(xen_sr_record_opt)


static const struct_member xen_sr_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_sr_record, uuid) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_sr_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_sr_record, name_description) },
        { .key = "VDIs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_sr_record, vdis) },
        { .key = "PBDs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_sr_record, pbds) },
        { .key = "virtual_allocation",
          .type = &abstract_type_int,
          .offset = offsetof(xen_sr_record, virtual_allocation) },
        { .key = "physical_utilisation",
          .type = &abstract_type_int,
          .offset = offsetof(xen_sr_record, physical_utilisation) },
        { .key = "physical_size",
          .type = &abstract_type_int,
          .offset = offsetof(xen_sr_record, physical_size) },
        { .key = "type",
          .type = &abstract_type_string,
          .offset = offsetof(xen_sr_record, type) },
        { .key = "content_type",
          .type = &abstract_type_string,
          .offset = offsetof(xen_sr_record, content_type) }
    };

const abstract_type xen_sr_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_sr_record),
       .member_count =
           sizeof(xen_sr_record_struct_members) / sizeof(struct_member),
       .members = xen_sr_record_struct_members
    };


void
xen_sr_record_free(xen_sr_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    xen_vdi_record_opt_set_free(record->vdis);
    xen_pbd_record_opt_set_free(record->pbds);
    free(record->type);
    free(record->content_type);
    free(record);
}


bool
xen_sr_get_record(xen_session *session, xen_sr_record **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = xen_sr_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("SR.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_sr_get_by_uuid(xen_session *session, xen_sr *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_by_uuid");
    return session->ok;
}


bool
xen_sr_get_by_name_label(xen_session *session, struct xen_sr_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("SR.get_by_name_label");
    return session->ok;
}


bool
xen_sr_get_name_label(xen_session *session, char **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_name_label");
    return session->ok;
}


bool
xen_sr_get_name_description(xen_session *session, char **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_name_description");
    return session->ok;
}


bool
xen_sr_get_vdis(xen_session *session, struct xen_vdi_set **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("SR.get_VDIs");
    return session->ok;
}


bool
xen_sr_get_pbds(xen_session *session, struct xen_pbd_set **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("SR.get_PBDs");
    return session->ok;
}


bool
xen_sr_get_virtual_allocation(xen_session *session, int64_t *result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("SR.get_virtual_allocation");
    return session->ok;
}


bool
xen_sr_get_physical_utilisation(xen_session *session, int64_t *result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("SR.get_physical_utilisation");
    return session->ok;
}


bool
xen_sr_get_physical_size(xen_session *session, int64_t *result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("SR.get_physical_size");
    return session->ok;
}


bool
xen_sr_get_type(xen_session *session, char **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_type");
    return session->ok;
}


bool
xen_sr_get_content_type(xen_session *session, char **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_content_type");
    return session->ok;
}


bool
xen_sr_set_name_label(xen_session *session, xen_sr sr, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "SR.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_sr_set_name_description(xen_session *session, xen_sr sr, char *description)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr },
            { .type = &abstract_type_string,
              .u.string_val = description }
        };

    xen_call_(session, "SR.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_sr_get_supported_types(xen_session *session, struct xen_string_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "SR.get_supported_types", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_sr_get_all(xen_session *session, struct xen_sr_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "SR.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_sr_get_uuid(xen_session *session, char **result, xen_sr sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = sr }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("SR.get_uuid");
    return session->ok;
}
