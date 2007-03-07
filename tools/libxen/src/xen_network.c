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
#include "xen_network.h"
#include "xen_pif.h"
#include "xen_vif.h"


XEN_FREE(xen_network)
XEN_SET_ALLOC_FREE(xen_network)
XEN_ALLOC(xen_network_record)
XEN_SET_ALLOC_FREE(xen_network_record)
XEN_ALLOC(xen_network_record_opt)
XEN_RECORD_OPT_FREE(xen_network)
XEN_SET_ALLOC_FREE(xen_network_record_opt)


static const struct_member xen_network_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_network_record, uuid) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_network_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_network_record, name_description) },
        { .key = "VIFs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_network_record, vifs) },
        { .key = "PIFs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_network_record, pifs) }
    };

const abstract_type xen_network_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_network_record),
       .member_count =
           sizeof(xen_network_record_struct_members) / sizeof(struct_member),
       .members = xen_network_record_struct_members
    };


void
xen_network_record_free(xen_network_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    xen_vif_record_opt_set_free(record->vifs);
    xen_pif_record_opt_set_free(record->pifs);
    free(record);
}


bool
xen_network_get_record(xen_session *session, xen_network_record **result, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    abstract_type result_type = xen_network_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("network.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_network_get_by_uuid(xen_session *session, xen_network *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("network.get_by_uuid");
    return session->ok;
}


bool
xen_network_create(xen_session *session, xen_network *result, xen_network_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_network_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("network.create");
    return session->ok;
}


bool
xen_network_destroy(xen_session *session, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    xen_call_(session, "network.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_network_get_by_name_label(xen_session *session, struct xen_network_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("network.get_by_name_label");
    return session->ok;
}


bool
xen_network_get_name_label(xen_session *session, char **result, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("network.get_name_label");
    return session->ok;
}


bool
xen_network_get_name_description(xen_session *session, char **result, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("network.get_name_description");
    return session->ok;
}


bool
xen_network_get_vifs(xen_session *session, struct xen_vif_set **result, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("network.get_VIFs");
    return session->ok;
}


bool
xen_network_get_pifs(xen_session *session, struct xen_pif_set **result, xen_network network)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("network.get_PIFs");
    return session->ok;
}


bool
xen_network_set_name_label(xen_session *session, xen_network network, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "network.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_network_set_name_description(xen_session *session, xen_network network, char *description)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = network },
            { .type = &abstract_type_string,
              .u.string_val = description }
        };

    xen_call_(session, "network.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_network_get_all(xen_session *session, struct xen_network_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "network.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_network_get_uuid(xen_session *session, char **result, xen_network network)
{
    *result = session->ok ? xen_strdup_((char *)network) : NULL;
    return session->ok;
}
