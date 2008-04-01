/*
 * Copyright (c) 2007, IBM Corp.
 * Copyright (c) 2007, XenSource Inc.
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
#include "xen/api/xen_common.h"
#include "xen/api/xen_xspolicy.h"


XEN_FREE(xen_xspolicy)
XEN_SET_ALLOC_FREE(xen_xspolicy)
XEN_RECORD_OPT_FREE(xen_xspolicy)

static const struct_member xen_xspolicy_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_xspolicy_record, uuid) },
        { .key = "flags",
          .type = &abstract_type_int,
          .offset = offsetof(xen_xspolicy_record, flags) },
        { .key = "repr",
          .type = &abstract_type_string,
          .offset = offsetof(xen_xspolicy_record, repr) },
        { .key = "type",
          .type = &abstract_type_int,
          .offset = offsetof(xen_xspolicy_record, type) },
    };

const abstract_type xen_xspolicy_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_xspolicy_record),
       .member_count =
           sizeof(xen_xspolicy_record_struct_members) / sizeof(struct_member),
       .members = xen_xspolicy_record_struct_members
    };


static const struct_member xen_xs_policystate_struct_members[] =
    {
        { .key = "xs_ref",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_xs_policystate, xs_ref) },
        { .key = "xserr",
          .type = &abstract_type_int,
          .offset = offsetof(xen_xs_policystate, xserr) },
        { .key = "repr",
          .type = &abstract_type_string,
          .offset = offsetof(xen_xs_policystate, repr) },
        { .key = "type",
          .type = &abstract_type_int,
          .offset = offsetof(xen_xs_policystate, type) },
        { .key = "flags",
          .type = &abstract_type_int,
          .offset = offsetof(xen_xs_policystate, flags) },
        { .key = "version",
          .type = &abstract_type_string,
          .offset = offsetof(xen_xs_policystate, version) },
        { .key = "errors",
          .type = &abstract_type_string,
          .offset = offsetof(xen_xs_policystate, errors) },
    };

const abstract_type xen_xs_policystate_abstract_type_ =
    {
        .typename = STRUCT,
        .struct_size = sizeof(xen_xs_policystate),
        .member_count =
            sizeof(xen_xs_policystate_struct_members) /
            sizeof(struct_member),
        .members = xen_xs_policystate_struct_members,
    };




void
xen_xs_policystate_free(xen_xs_policystate *state)
{
    if (state == NULL)
    {
        return;
    }
    xen_xspolicy_record_opt_free(state->xs_ref);
    free(state->repr);
    free(state->errors);
    free(state->version);
    free(state);
}


void
xen_xspolicy_record_free(xen_xspolicy_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->repr);
    free(record);
}


bool
xen_xspolicy_get_record(xen_session *session, xen_xspolicy_record **result,
                        xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy }
        };

    abstract_type result_type = xen_xspolicy_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("XSPolicy.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_xspolicy_get_uuid(xen_session *session, char **result,
                      xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("XSPolicy.get_uuid");
    return session->ok;
}


bool
xen_xspolicy_get_by_uuid(xen_session *session, xen_xspolicy *result,
                         char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("XSPolicy.get_by_uuid");
    return session->ok;
}


bool
xen_xspolicy_get_xstype(xen_session *session, xs_type *result)
{
    abstract_value param_values[] =
        {
        };

    abstract_type result_type = abstract_type_int;

    *result = 0;
    XEN_CALL_("XSPolicy.get_xstype");
    return session->ok;
}


bool
xen_xspolicy_set_xspolicy(xen_session *session, xen_xs_policystate **result,
                          xs_type type, char *repr,
                          xs_instantiationflags flags,
                          bool overwrite)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_int,
              .u.int_val = type },
            { .type = &abstract_type_string,
              .u.string_val = repr },
            { .type = &abstract_type_int,
              .u.int_val = flags },
            { .type = &abstract_type_bool,
              .u.bool_val = overwrite }
        };

    abstract_type result_type = xen_xs_policystate_abstract_type_;

    *result = NULL;
    XEN_CALL_("XSPolicy.set_xspolicy");
    return session->ok;
}


bool
xen_xspolicy_reset_xspolicy(xen_session *session, xen_xs_policystate **result,
                            xs_type type)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_int,
              .u.int_val = type },
        };

    abstract_type result_type = xen_xs_policystate_abstract_type_;

    *result = NULL;
    XEN_CALL_("XSPolicy.reset_xspolicy");
    return session->ok;
}


bool
xen_xspolicy_get_xspolicy(xen_session *session, xen_xs_policystate **result)
{
    abstract_value param_values[] =
        {
        };

    abstract_type result_type = xen_xs_policystate_abstract_type_;

    *result = NULL;
    XEN_CALL_("XSPolicy.get_xspolicy");
    return session->ok;
}


bool
xen_xspolicy_get_labeled_resources(xen_session *session,
                                   xen_string_string_map **result)
{
    abstract_value param_values[] =
        {
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("XSPolicy.get_labeled_resources");
    return session->ok;
}


bool
xen_xspolicy_set_resource_label(xen_session *session,
                                char *resource, char *label,
                                char *oldlabel)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = resource },
            { .type = &abstract_type_string,
              .u.string_val = label },
            { .type = &abstract_type_string,
              .u.string_val = oldlabel },
        };

    xen_call_(session, "XSPolicy.set_resource_label", param_values, 3,
                       NULL, NULL);
    return session->ok;
}


bool
xen_xspolicy_get_resource_label(xen_session *session, char **result,
                                char *resource)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = resource },
        };

    abstract_type result_type = abstract_type_string;
    XEN_CALL_("XSPolicy.get_resource_label");
    return session->ok;
}


bool
xen_xspolicy_rm_xsbootpolicy(xen_session *session)
{
    abstract_value param_values[] =
        {
        };

    xen_call_(session, "XSPolicy.rm_xsbootpolicy", param_values, 0,
                       NULL, NULL);
    return session->ok;
}


bool
xen_xspolicy_activate_xspolicy(xen_session *session,
                               xs_instantiationflags *result,
                               xen_xspolicy xspolicy,
                               xs_instantiationflags flags)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
            { .type = &abstract_type_int,
              .u.int_val = flags },
        };

    abstract_type result_type = abstract_type_int;

    *result = 0;
    XEN_CALL_("XSPolicy.activate_xspolicy");
    return session->ok;
}


bool
xen_xspolicy_can_run(xen_session *session, int64_t *result,
                     char *security_label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = security_label }
        };

    abstract_type result_type = abstract_type_int;

    *result = 0;
    XEN_CALL_("XSPolicy.can_run");
    return session->ok;
}
