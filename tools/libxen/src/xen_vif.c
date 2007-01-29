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
#include "xen_internal.h"
#include "xen_network.h"
#include "xen_vif.h"
#include "xen_vm.h"


XEN_FREE(xen_vif)
XEN_SET_ALLOC_FREE(xen_vif)
XEN_ALLOC(xen_vif_record)
XEN_SET_ALLOC_FREE(xen_vif_record)
XEN_ALLOC(xen_vif_record_opt)
XEN_RECORD_OPT_FREE(xen_vif)
XEN_SET_ALLOC_FREE(xen_vif_record_opt)


static const struct_member xen_vif_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vif_record, uuid) },
        { .key = "device",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vif_record, device) },
        { .key = "network",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vif_record, network) },
        { .key = "VM",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vif_record, vm) },
        { .key = "MAC",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vif_record, mac) },
        { .key = "MTU",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vif_record, mtu) },
        { .key = "io_read_kbs",
          .type = &abstract_type_float,
          .offset = offsetof(xen_vif_record, io_read_kbs) },
        { .key = "io_write_kbs",
          .type = &abstract_type_float,
          .offset = offsetof(xen_vif_record, io_write_kbs) }
    };

const abstract_type xen_vif_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vif_record),
       .member_count =
           sizeof(xen_vif_record_struct_members) / sizeof(struct_member),
       .members = xen_vif_record_struct_members
    };


void
xen_vif_record_free(xen_vif_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->device);
    xen_network_record_opt_free(record->network);
    xen_vm_record_opt_free(record->vm);
    free(record->mac);
    free(record);
}


bool
xen_vif_get_record(xen_session *session, xen_vif_record **result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = xen_vif_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VIF.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vif_get_by_uuid(xen_session *session, xen_vif *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.get_by_uuid");
    return session->ok;
}


bool
xen_vif_create(xen_session *session, xen_vif *result, xen_vif_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_vif_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.create");
    return session->ok;
}


bool
xen_vif_destroy(xen_session *session, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    xen_call_(session, "VIF.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vif_get_device(xen_session *session, char **result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.get_device");
    return session->ok;
}


bool
xen_vif_get_network(xen_session *session, xen_network *result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.get_network");
    return session->ok;
}


bool
xen_vif_get_vm(xen_session *session, xen_vm *result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.get_VM");
    return session->ok;
}


bool
xen_vif_get_mac(xen_session *session, char **result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VIF.get_MAC");
    return session->ok;
}


bool
xen_vif_get_mtu(xen_session *session, int64_t *result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VIF.get_MTU");
    return session->ok;
}


bool
xen_vif_get_io_read_kbs(xen_session *session, double *result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_float;

    XEN_CALL_("VIF.get_io_read_kbs");
    return session->ok;
}


bool
xen_vif_get_io_write_kbs(xen_session *session, double *result, xen_vif vif)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif }
        };

    abstract_type result_type = abstract_type_float;

    XEN_CALL_("VIF.get_io_write_kbs");
    return session->ok;
}


bool
xen_vif_set_device(xen_session *session, xen_vif vif, char *device)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif },
            { .type = &abstract_type_string,
              .u.string_val = device }
        };

    xen_call_(session, "VIF.set_device", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vif_set_mac(xen_session *session, xen_vif vif, char *mac)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif },
            { .type = &abstract_type_string,
              .u.string_val = mac }
        };

    xen_call_(session, "VIF.set_MAC", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vif_set_mtu(xen_session *session, xen_vif vif, int64_t mtu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vif },
            { .type = &abstract_type_int,
              .u.int_val = mtu }
        };

    xen_call_(session, "VIF.set_MTU", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vif_get_uuid(xen_session *session, char **result, xen_vif vif)
{
    *result = session->ok ? xen_strdup_((char *)vif) : NULL;
    return session->ok;
}
