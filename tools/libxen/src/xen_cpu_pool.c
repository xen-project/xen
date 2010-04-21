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
#include <xen/api/xen_common.h>
#include <xen/api/xen_cpu_pool.h>
#include <xen/api/xen_host_cpu.h>

XEN_FREE(xen_cpu_pool)
XEN_SET_ALLOC_FREE(xen_cpu_pool)
XEN_ALLOC(xen_cpu_pool_record)
XEN_SET_ALLOC_FREE(xen_cpu_pool_record)
XEN_ALLOC(xen_cpu_pool_record_opt)
XEN_RECORD_OPT_FREE(xen_cpu_pool)
XEN_SET_ALLOC_FREE(xen_cpu_pool_record_opt)


static const struct_member xen_cpu_pool_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_cpu_pool_record, uuid) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_cpu_pool_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_cpu_pool_record, name_description) },
        { .key = "resident_on",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_cpu_pool_record, resident_on) },
        { .key = "auto_power_on",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_cpu_pool_record, auto_power_on) },
        { .key = "started_VMs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_cpu_pool_record, started_vms) },
        { .key = "ncpu",
          .type = &abstract_type_int,
          .offset = offsetof(xen_cpu_pool_record, ncpu) },
        { .key = "sched_policy",
          .type = &abstract_type_string,
          .offset = offsetof(xen_cpu_pool_record, sched_policy) },
        { .key = "proposed_CPUs",
          .type = &abstract_type_string_set,
          .offset = offsetof(xen_cpu_pool_record, proposed_cpus) },
        { .key = "host_CPUs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_cpu_pool_record, host_cpus) },
        { .key = "activated",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_cpu_pool_record, activated) },
        { .key = "other_config",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_cpu_pool_record, other_config) },
    };


const abstract_type xen_cpu_pool_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_cpu_pool_record),
       .member_count =
           sizeof(xen_cpu_pool_record_struct_members) / sizeof(struct_member),
       .members = xen_cpu_pool_record_struct_members
    };


void
xen_cpu_pool_record_free(xen_cpu_pool_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    xen_host_record_opt_free(record->resident_on);
    xen_vm_record_opt_set_free(record->started_vms);
    free(record->sched_policy);
    xen_string_set_free(record->proposed_cpus);
    xen_host_cpu_record_opt_set_free(record->host_cpus);
    xen_string_string_map_free(record->other_config);
    free(record);
}


bool
xen_cpu_pool_get_record(xen_session *session, xen_cpu_pool_record **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = xen_cpu_pool_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_cpu_pool_get_by_uuid(xen_session *session, xen_cpu_pool *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_by_uuid");
    return session->ok;
}


bool
xen_cpu_pool_create(xen_session *session, xen_cpu_pool *result,
    xen_cpu_pool_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_cpu_pool_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.create");
    return session->ok;
}


bool
xen_cpu_pool_destroy(xen_session *session, xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    xen_call_(session, "cpu_pool.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_get_uuid(xen_session *session, char **result, xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_uuid");
    return session->ok;
}


bool
xen_cpu_pool_deactivate(xen_session *session, xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
        };

    xen_call_(session, "cpu_pool.deactivate", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_activate(xen_session *session, xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
        };

    xen_call_(session, "cpu_pool.activate", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_add_host_CPU_live(xen_session *session, xen_cpu_pool cpu_pool,
    xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = host_cpu },
        };

    xen_call_(session, "cpu_pool.add_host_CPU_live", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_remove_host_CPU_live(xen_session *session, xen_cpu_pool cpu_pool,
    xen_host_cpu host_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = host_cpu },
        };

    xen_call_(session, "cpu_pool.remove_host_CPU_live", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_get_all(xen_session *session, struct xen_cpu_pool_set **result)
{
    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "cpu_pool.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_cpu_pool_get_by_name_label(xen_session *session,
    struct xen_cpu_pool_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_by_name_label");
    return session->ok;
}


bool
xen_cpu_pool_get_activated(xen_session *session, bool *result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("cpu_pool.get_activated");
    return session->ok;
}


bool
xen_cpu_pool_get_auto_power_on(xen_session *session, bool *result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("cpu_pool.get_auto_power_on");
    return session->ok;
}


bool
xen_cpu_pool_get_host_CPUs(xen_session *session, struct xen_host_cpu_set **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_host_CPUs");
    return session->ok;
}


bool
xen_cpu_pool_get_name_description(xen_session *session, char **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_name_description");
    return session->ok;
}


bool
xen_cpu_pool_get_name_label(xen_session *session, char **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_name_label");
    return session->ok;
}


bool
xen_cpu_pool_get_ncpu(xen_session *session, int64_t *result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("cpu_pool.get_ncpu");
    return session->ok;
}


bool
xen_cpu_pool_get_proposed_CPUs(xen_session *session, struct xen_string_set **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_proposed_CPUs");
    return session->ok;
}


bool
xen_cpu_pool_get_other_config(xen_session *session, xen_string_string_map **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_other_config");
    return session->ok;
}


bool
xen_cpu_pool_get_resident_on(xen_session *session, xen_host *result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_resident_on");
    return session->ok;
}


bool
xen_cpu_pool_get_sched_policy(xen_session *session, char **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_sched_policy");
    return session->ok;
}


bool
xen_cpu_pool_get_started_VMs(xen_session *session, xen_vm_set **result,
    xen_cpu_pool cpu_pool)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("cpu_pool.get_started_VMs");
    return session->ok;
}


bool
xen_cpu_pool_set_auto_power_on(xen_session *session, xen_cpu_pool cpu_pool,
    bool auto_power_on)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_bool,
              .u.bool_val = auto_power_on }
        };

    xen_call_(session, "cpu_pool.set_auto_power_on", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    xen_string_set *proposed_cpus)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string_set,
              .u.set_val = (arbitrary_set *)proposed_cpus }
        };

    xen_call_(session, "cpu_pool.set_proposed_CPUs", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_add_to_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    char* proposed_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = proposed_cpu }
        };

    xen_call_(session, "cpu_pool.add_to_proposed_CPUs", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_remove_from_proposed_CPUs(xen_session *session, xen_cpu_pool cpu_pool,
    char* proposed_cpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = proposed_cpu }
        };

    xen_call_(session, "cpu_pool.remove_from_proposed_CPUs", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_name_label(xen_session *session, xen_cpu_pool cpu_pool,
    char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "cpu_pool.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_name_description(xen_session *session, xen_cpu_pool cpu_pool,
    char *descr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = descr }
        };

    xen_call_(session, "cpu_pool.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_ncpu(xen_session *session, xen_cpu_pool cpu_pool, int64_t ncpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_int,
              .u.int_val = ncpu }
        };

    xen_call_(session, "cpu_pool.set_ncpu", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    xen_string_string_map *other_config)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)other_config }
        };

    xen_call_(session, "cpu_pool.set_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_add_to_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "cpu_pool.add_to_other_config", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_remove_from_other_config(xen_session *session, xen_cpu_pool cpu_pool,
    char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "cpu_pool.remove_from_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_cpu_pool_set_sched_policy(xen_session *session, xen_cpu_pool cpu_pool,
    char *sched_policy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = cpu_pool },
            { .type = &abstract_type_string,
              .u.string_val = sched_policy }
        };

    xen_call_(session, "cpu_pool.set_sched_policy", param_values, 2, NULL, NULL);
    return session->ok;
}

