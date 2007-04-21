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

#include "xen_internal.h"
#include "xen_vbd_mode_internal.h"
#include "xen_vbd_type_internal.h"
#include <xen/api/xen_common.h>
#include <xen/api/xen_string_string_map.h>
#include <xen/api/xen_vbd.h>
#include <xen/api/xen_vbd_metrics.h>
#include <xen/api/xen_vdi.h>
#include <xen/api/xen_vm.h>


XEN_FREE(xen_vbd)
XEN_SET_ALLOC_FREE(xen_vbd)
XEN_ALLOC(xen_vbd_record)
XEN_SET_ALLOC_FREE(xen_vbd_record)
XEN_ALLOC(xen_vbd_record_opt)
XEN_RECORD_OPT_FREE(xen_vbd)
XEN_SET_ALLOC_FREE(xen_vbd_record_opt)


static const struct_member xen_vbd_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vbd_record, uuid) },
        { .key = "VM",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vbd_record, vm) },
        { .key = "VDI",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vbd_record, vdi) },
        { .key = "device",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vbd_record, device) },
        { .key = "bootable",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vbd_record, bootable) },
        { .key = "mode",
          .type = &xen_vbd_mode_abstract_type_,
          .offset = offsetof(xen_vbd_record, mode) },
        { .key = "type",
          .type = &xen_vbd_type_abstract_type_,
          .offset = offsetof(xen_vbd_record, type) },
        { .key = "currently_attached",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vbd_record, currently_attached) },
        { .key = "status_code",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vbd_record, status_code) },
        { .key = "status_detail",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vbd_record, status_detail) },
        { .key = "runtime_properties",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vbd_record, runtime_properties) },
        { .key = "qos_algorithm_type",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vbd_record, qos_algorithm_type) },
        { .key = "qos_algorithm_params",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vbd_record, qos_algorithm_params) },
        { .key = "qos_supported_algorithms",
          .type = &abstract_type_string_set,
          .offset = offsetof(xen_vbd_record, qos_supported_algorithms) },
        { .key = "metrics",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vbd_record, metrics) }
    };

const abstract_type xen_vbd_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vbd_record),
       .member_count =
           sizeof(xen_vbd_record_struct_members) / sizeof(struct_member),
       .members = xen_vbd_record_struct_members
    };


void
xen_vbd_record_free(xen_vbd_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    xen_vm_record_opt_free(record->vm);
    xen_vdi_record_opt_free(record->vdi);
    free(record->device);
    free(record->status_detail);
    xen_string_string_map_free(record->runtime_properties);
    free(record->qos_algorithm_type);
    xen_string_string_map_free(record->qos_algorithm_params);
    xen_string_set_free(record->qos_supported_algorithms);
    xen_vbd_metrics_record_opt_free(record->metrics);
    free(record);
}


bool
xen_vbd_get_record(xen_session *session, xen_vbd_record **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = xen_vbd_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VBD.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vbd_get_by_uuid(xen_session *session, xen_vbd *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_by_uuid");
    return session->ok;
}


bool
xen_vbd_create(xen_session *session, xen_vbd *result, xen_vbd_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_vbd_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.create");
    return session->ok;
}


bool
xen_vbd_destroy(xen_session *session, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    xen_call_(session, "VBD.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_get_vm(xen_session *session, xen_vm *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_VM");
    return session->ok;
}


bool
xen_vbd_get_vdi(xen_session *session, xen_vdi *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_VDI");
    return session->ok;
}


bool
xen_vbd_get_device(xen_session *session, char **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_device");
    return session->ok;
}


bool
xen_vbd_get_bootable(xen_session *session, bool *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VBD.get_bootable");
    return session->ok;
}


bool
xen_vbd_get_mode(xen_session *session, enum xen_vbd_mode *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = xen_vbd_mode_abstract_type_;
    XEN_CALL_("VBD.get_mode");
    return session->ok;
}


bool
xen_vbd_get_type(xen_session *session, enum xen_vbd_type *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = xen_vbd_type_abstract_type_;
    XEN_CALL_("VBD.get_type");
    return session->ok;
}


bool
xen_vbd_get_currently_attached(xen_session *session, bool *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VBD.get_currently_attached");
    return session->ok;
}


bool
xen_vbd_get_status_code(xen_session *session, int64_t *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VBD.get_status_code");
    return session->ok;
}


bool
xen_vbd_get_status_detail(xen_session *session, char **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_status_detail");
    return session->ok;
}


bool
xen_vbd_get_runtime_properties(xen_session *session, xen_string_string_map **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VBD.get_runtime_properties");
    return session->ok;
}


bool
xen_vbd_get_qos_algorithm_type(xen_session *session, char **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_qos_algorithm_type");
    return session->ok;
}


bool
xen_vbd_get_qos_algorithm_params(xen_session *session, xen_string_string_map **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VBD.get_qos_algorithm_params");
    return session->ok;
}


bool
xen_vbd_get_qos_supported_algorithms(xen_session *session, struct xen_string_set **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VBD.get_qos_supported_algorithms");
    return session->ok;
}


bool
xen_vbd_get_metrics(xen_session *session, xen_vbd_metrics *result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_metrics");
    return session->ok;
}


bool
xen_vbd_set_device(xen_session *session, xen_vbd vbd, char *device)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string,
              .u.string_val = device }
        };

    xen_call_(session, "VBD.set_device", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_set_bootable(xen_session *session, xen_vbd vbd, bool bootable)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_bool,
              .u.bool_val = bootable }
        };

    xen_call_(session, "VBD.set_bootable", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_set_mode(xen_session *session, xen_vbd vbd, enum xen_vbd_mode mode)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &xen_vbd_mode_abstract_type_,
              .u.string_val = xen_vbd_mode_to_string(mode) }
        };

    xen_call_(session, "VBD.set_mode", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_set_type(xen_session *session, xen_vbd vbd, enum xen_vbd_type type)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &xen_vbd_type_abstract_type_,
              .u.string_val = xen_vbd_type_to_string(type) }
        };

    xen_call_(session, "VBD.set_type", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_set_qos_algorithm_type(xen_session *session, xen_vbd vbd, char *algorithm_type)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string,
              .u.string_val = algorithm_type }
        };

    xen_call_(session, "VBD.set_qos_algorithm_type", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_set_qos_algorithm_params(xen_session *session, xen_vbd vbd, xen_string_string_map *algorithm_params)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)algorithm_params }
        };

    xen_call_(session, "VBD.set_qos_algorithm_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_add_to_qos_algorithm_params(xen_session *session, xen_vbd vbd, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "VBD.add_to_qos_algorithm_params", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_remove_from_qos_algorithm_params(xen_session *session, xen_vbd vbd, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "VBD.remove_from_qos_algorithm_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_media_change(xen_session *session, xen_vbd vbd, xen_vdi vdi)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd },
            { .type = &abstract_type_string,
              .u.string_val = vdi }
        };

    xen_call_(session, "VBD.media_change", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_plug(xen_session *session, xen_vbd self)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self }
        };

    xen_call_(session, "VBD.plug", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_unplug(xen_session *session, xen_vbd self)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self }
        };

    xen_call_(session, "VBD.unplug", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vbd_get_all(xen_session *session, struct xen_vbd_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "VBD.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_vbd_get_uuid(xen_session *session, char **result, xen_vbd vbd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vbd }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VBD.get_uuid");
    return session->ok;
}
