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
#include "xen/api/xen_acmpolicy.h"


static const struct_member xen_acmpolicy_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acmpolicy_record, uuid) },
        { .key = "flags",
          .type = &abstract_type_int,
          .offset = offsetof(xen_acmpolicy_record, flags) },
        { .key = "repr",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acmpolicy_record, repr) },
        { .key = "type",
          .type = &abstract_type_int,
          .offset = offsetof(xen_acmpolicy_record, type) },
    };

const abstract_type xen_acmpolicy_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_acmpolicy_record),
       .member_count =
          sizeof(xen_acmpolicy_record_struct_members) / sizeof(struct_member),
       .members = xen_acmpolicy_record_struct_members
    };


static const struct_member xen_acm_header_struct_members[] =
    {
        { .key = "policyname",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, policyname) },
        { .key = "policyurl",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, policyurl) },
        { .key = "date",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, date) },
        { .key = "reference",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, reference) },
        { .key = "namespaceurl",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, namespaceurl) },
        { .key = "version",
          .type = &abstract_type_string,
          .offset = offsetof(xen_acm_header, version) },
    };

const abstract_type xen_acm_header_abstract_type_ =
    {
        .typename = STRUCT,
        .struct_size = sizeof(xen_acm_header),
        .member_count =
            sizeof(xen_acm_header_struct_members) /
            sizeof(struct_member),
        .members = xen_acm_header_struct_members,
    };

void
xen_acm_header_free(xen_acm_header *shdr)
{
    if (shdr == NULL)
    {
        return;
    }
    free(shdr->policyname);
    free(shdr->policyurl);
    free(shdr->date);
    free(shdr->reference);
    free(shdr->namespaceurl);
    free(shdr->version);
    free(shdr);
}


void
xen_acmpolicy_record_free(xen_acmpolicy_record *record)
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
xen_acmpolicy_get_record(xen_session *session, xen_acmpolicy_record **result,
                         xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy }
        };

    abstract_type result_type = xen_acmpolicy_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_acmpolicy_get_header(xen_session *session,
                         xen_acm_header **result,
                         xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
        };

    abstract_type result_type = xen_acm_header_abstract_type_;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_header");
    return session->ok;
}


bool
xen_acmpolicy_get_xml(xen_session *session,
                      char **result,
                      xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_xml");
    return session->ok;
}


bool
xen_acmpolicy_get_map(xen_session *session,
                      char **result,
                      xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_map");
    return session->ok;
}


bool
xen_acmpolicy_get_binary(xen_session *session, char **result,
                         xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_binary");
    return session->ok;
}


bool
xen_acmpolicy_get_enforced_binary(xen_session *session, char **result,
                                  xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy },
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_enforced_binary");
    return session->ok;
}


bool
xen_acmpolicy_get_VM_ssidref(xen_session *session,
                             int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("ACMPolicy.get_VM_ssidref");
    return session->ok;
}


bool
xen_acmpolicy_get_uuid(xen_session *session, char **result,
                       xen_xspolicy xspolicy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = xspolicy }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("ACMPolicy.get_uuid");
    return session->ok;
}
