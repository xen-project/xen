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
#include <xen/api/xen_host.h>
#include <xen/api/xen_host_cpu.h>
#include <xen/api/xen_host_metrics.h>
#include <xen/api/xen_pbd.h>
#include <xen/api/xen_pif.h>
#include <xen/api/xen_sr.h>
#include <xen/api/xen_string_string_map.h>
#include <xen/api/xen_vm.h>
#include <xen/api/xen_cpu_pool.h>


XEN_FREE(xen_host)
XEN_SET_ALLOC_FREE(xen_host)
XEN_ALLOC(xen_host_record)
XEN_SET_ALLOC_FREE(xen_host_record)
XEN_ALLOC(xen_host_record_opt)
XEN_RECORD_OPT_FREE(xen_host)
XEN_SET_ALLOC_FREE(xen_host_record_opt)


static const struct_member xen_host_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_record, uuid) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_record, name_description) },
        { .key = "API_version_major",
          .type = &abstract_type_int,
          .offset = offsetof(xen_host_record, api_version_major) },
        { .key = "API_version_minor",
          .type = &abstract_type_int,
          .offset = offsetof(xen_host_record, api_version_minor) },
        { .key = "API_version_vendor",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_record, api_version_vendor) },
        { .key = "API_version_vendor_implementation",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_host_record, api_version_vendor_implementation) },
        { .key = "enabled",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_host_record, enabled) },
        { .key = "software_version",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_host_record, software_version) },
        { .key = "other_config",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_host_record, other_config) },
        { .key = "capabilities",
          .type = &abstract_type_string_set,
          .offset = offsetof(xen_host_record, capabilities) },
        { .key = "cpu_configuration",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_host_record, cpu_configuration) },
        { .key = "sched_policy",
          .type = &abstract_type_string,
          .offset = offsetof(xen_host_record, sched_policy) },
        { .key = "supported_bootloaders",
          .type = &abstract_type_string_set,
          .offset = offsetof(xen_host_record, supported_bootloaders) },
        { .key = "resident_VMs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_host_record, resident_vms) },
        { .key = "logging",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_host_record, logging) },
        { .key = "PIFs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_host_record, pifs) },
        { .key = "suspend_image_sr",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_host_record, suspend_image_sr) },
        { .key = "crash_dump_sr",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_host_record, crash_dump_sr) },
        { .key = "PBDs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_host_record, pbds) },
        { .key = "host_CPUs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_host_record, host_cpus) },
        { .key = "metrics",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_host_record, metrics) },
        { .key = "resident_cpu_pools",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_host_record, resident_cpu_pools) }
    };

const abstract_type xen_host_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_host_record),
       .member_count =
           sizeof(xen_host_record_struct_members) / sizeof(struct_member),
       .members = xen_host_record_struct_members
    };


void
xen_host_record_free(xen_host_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    free(record->api_version_vendor);
    xen_string_string_map_free(record->api_version_vendor_implementation);
    xen_string_string_map_free(record->software_version);
    xen_string_string_map_free(record->other_config);
    xen_string_set_free(record->capabilities);
    xen_string_string_map_free(record->cpu_configuration);
    free(record->sched_policy);
    xen_string_set_free(record->supported_bootloaders);
    xen_vm_record_opt_set_free(record->resident_vms);
    xen_string_string_map_free(record->logging);
    xen_pif_record_opt_set_free(record->pifs);
    xen_sr_record_opt_free(record->suspend_image_sr);
    xen_sr_record_opt_free(record->crash_dump_sr);
    xen_pbd_record_opt_set_free(record->pbds);
    xen_host_cpu_record_opt_set_free(record->host_cpus);
    xen_host_metrics_record_opt_free(record->metrics);
    xen_cpu_pool_record_opt_set_free(record->resident_cpu_pools);
    free(record);
}


bool
xen_host_get_record(xen_session *session, xen_host_record **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = xen_host_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("host.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_host_get_by_uuid(xen_session *session, xen_host *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_by_uuid");
    return session->ok;
}


bool
xen_host_get_by_name_label(xen_session *session, struct xen_host_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_by_name_label");
    return session->ok;
}


bool
xen_host_get_name_label(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_name_label");
    return session->ok;
}


bool
xen_host_get_name_description(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_name_description");
    return session->ok;
}


bool
xen_host_get_api_version_major(xen_session *session, int64_t *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("host.get_API_version_major");
    return session->ok;
}


bool
xen_host_get_api_version_minor(xen_session *session, int64_t *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("host.get_API_version_minor");
    return session->ok;
}


bool
xen_host_get_api_version_vendor(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_API_version_vendor");
    return session->ok;
}


bool
xen_host_get_api_version_vendor_implementation(xen_session *session, xen_string_string_map **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("host.get_API_version_vendor_implementation");
    return session->ok;
}


bool
xen_host_get_enabled(xen_session *session, bool *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("host.get_enabled");
    return session->ok;
}


bool
xen_host_get_software_version(xen_session *session, xen_string_string_map **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("host.get_software_version");
    return session->ok;
}


bool
xen_host_get_other_config(xen_session *session, xen_string_string_map **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("host.get_other_config");
    return session->ok;
}


bool
xen_host_get_capabilities(xen_session *session, struct xen_string_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_capabilities");
    return session->ok;
}


bool
xen_host_get_cpu_configuration(xen_session *session, xen_string_string_map **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("host.get_cpu_configuration");
    return session->ok;
}


bool
xen_host_get_sched_policy(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_sched_policy");
    return session->ok;
}


bool
xen_host_get_supported_bootloaders(xen_session *session, struct xen_string_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_supported_bootloaders");
    return session->ok;
}


bool
xen_host_get_resident_vms(xen_session *session, struct xen_vm_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_resident_VMs");
    return session->ok;
}


bool
xen_host_get_logging(xen_session *session, xen_string_string_map **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("host.get_logging");
    return session->ok;
}


bool
xen_host_get_pifs(xen_session *session, struct xen_pif_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_PIFs");
    return session->ok;
}


bool
xen_host_get_suspend_image_sr(xen_session *session, xen_sr *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_suspend_image_sr");
    return session->ok;
}


bool
xen_host_get_crash_dump_sr(xen_session *session, xen_sr *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_crash_dump_sr");
    return session->ok;
}


bool
xen_host_get_pbds(xen_session *session, struct xen_pbd_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_PBDs");
    return session->ok;
}


bool
xen_host_get_host_cpus(xen_session *session, struct xen_host_cpu_set **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_host_CPUs");
    return session->ok;
}


bool
xen_host_get_metrics(xen_session *session, xen_host_metrics *result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_metrics");
    return session->ok;
}


bool
xen_host_set_name_label(xen_session *session, xen_host host, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "host.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_set_name_description(xen_session *session, xen_host host, char *description)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = description }
        };

    xen_call_(session, "host.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_set_other_config(xen_session *session, xen_host host, xen_string_string_map *other_config)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)other_config }
        };

    xen_call_(session, "host.set_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_add_to_other_config(xen_session *session, xen_host host, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "host.add_to_other_config", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_host_remove_from_other_config(xen_session *session, xen_host host, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "host.remove_from_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_set_logging(xen_session *session, xen_host host, xen_string_string_map *logging)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)logging }
        };

    xen_call_(session, "host.set_logging", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_add_to_logging(xen_session *session, xen_host host, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "host.add_to_logging", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_host_remove_from_logging(xen_session *session, xen_host host, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "host.remove_from_logging", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_set_suspend_image_sr(xen_session *session, xen_host host, xen_sr suspend_image_sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = suspend_image_sr }
        };

    xen_call_(session, "host.set_suspend_image_sr", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_set_crash_dump_sr(xen_session *session, xen_host host, xen_sr crash_dump_sr)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = crash_dump_sr }
        };

    xen_call_(session, "host.set_crash_dump_sr", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_disable(xen_session *session, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    xen_call_(session, "host.disable", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_host_enable(xen_session *session, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    xen_call_(session, "host.enable", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_host_shutdown(xen_session *session, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    xen_call_(session, "host.shutdown", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_host_reboot(xen_session *session, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    xen_call_(session, "host.reboot", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_host_dmesg(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.dmesg");
    return session->ok;
}


bool
xen_host_dmesg_clear(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.dmesg_clear");
    return session->ok;
}


bool
xen_host_get_log(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_log");
    return session->ok;
}


bool
xen_host_send_debug_keys(xen_session *session, xen_host host, char *keys)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host },
            { .type = &abstract_type_string,
              .u.string_val = keys }
        };

    xen_call_(session, "host.send_debug_keys", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_host_list_methods(xen_session *session, struct xen_string_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "host.list_methods", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_host_get_all(xen_session *session, struct xen_host_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "host.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_host_get_uuid(xen_session *session, char **result, xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("host.get_uuid");
    return session->ok;
}


bool
xen_host_get_resident_cpu_pools(xen_session *session, struct xen_cpu_pool_set **result,
        xen_host host)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = host }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("host.get_resident_cpu_pools");
    return session->ok;
}

