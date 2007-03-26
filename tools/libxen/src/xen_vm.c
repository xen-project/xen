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
#include "xen_console.h"
#include "xen_crashdump.h"
#include "xen_host.h"
#include "xen_internal.h"
#include "xen_on_crash_behaviour_internal.h"
#include "xen_on_normal_exit_internal.h"
#include "xen_string_string_map.h"
#include "xen_vbd.h"
#include "xen_vdi.h"
#include "xen_vif.h"
#include "xen_vm.h"
#include "xen_vm_guest_metrics.h"
#include "xen_vm_metrics.h"
#include "xen_vm_power_state_internal.h"
#include "xen_vtpm.h"


XEN_FREE(xen_vm)
XEN_SET_ALLOC_FREE(xen_vm)
XEN_ALLOC(xen_vm_record)
XEN_SET_ALLOC_FREE(xen_vm_record)
XEN_ALLOC(xen_vm_record_opt)
XEN_RECORD_OPT_FREE(xen_vm)
XEN_SET_ALLOC_FREE(xen_vm_record_opt)


static const struct_member xen_vm_record_struct_members[] =
    {
        { .key = "uuid",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, uuid) },
        { .key = "power_state",
          .type = &xen_vm_power_state_abstract_type_,
          .offset = offsetof(xen_vm_record, power_state) },
        { .key = "name_label",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, name_label) },
        { .key = "name_description",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, name_description) },
        { .key = "user_version",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, user_version) },
        { .key = "is_a_template",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, is_a_template) },
        { .key = "auto_power_on",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, auto_power_on) },
        { .key = "suspend_VDI",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vm_record, suspend_vdi) },
        { .key = "resident_on",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vm_record, resident_on) },
        { .key = "memory_static_max",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_static_max) },
        { .key = "memory_dynamic_max",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_dynamic_max) },
        { .key = "memory_dynamic_min",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_dynamic_min) },
        { .key = "memory_static_min",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_static_min) },
        { .key = "VCPUs_params",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, vcpus_params) },
        { .key = "VCPUs_max",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, vcpus_max) },
        { .key = "VCPUs_at_startup",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, vcpus_at_startup) },
        { .key = "actions_after_shutdown",
          .type = &xen_on_normal_exit_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_shutdown) },
        { .key = "actions_after_reboot",
          .type = &xen_on_normal_exit_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_reboot) },
        { .key = "actions_after_crash",
          .type = &xen_on_crash_behaviour_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_crash) },
        { .key = "consoles",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, consoles) },
        { .key = "VIFs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, vifs) },
        { .key = "VBDs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, vbds) },
        { .key = "crash_dumps",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, crash_dumps) },
        { .key = "VTPMs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, vtpms) },
        { .key = "PV_bootloader",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pv_bootloader) },
        { .key = "PV_kernel",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pv_kernel) },
        { .key = "PV_ramdisk",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pv_ramdisk) },
        { .key = "PV_args",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pv_args) },
        { .key = "PV_bootloader_args",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pv_bootloader_args) },
        { .key = "HVM_boot_policy",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, hvm_boot_policy) },
        { .key = "HVM_boot_params",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, hvm_boot_params) },
        { .key = "platform",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, platform) },
        { .key = "PCI_bus",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pci_bus) },
        { .key = "other_config",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, other_config) },
        { .key = "domid",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, domid) },
        { .key = "is_control_domain",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, is_control_domain) },
        { .key = "metrics",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vm_record, metrics) },
        { .key = "guest_metrics",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vm_record, guest_metrics) }
    };

const abstract_type xen_vm_record_abstract_type_ =
    {
       .typename = STRUCT,
       .struct_size = sizeof(xen_vm_record),
       .member_count =
           sizeof(xen_vm_record_struct_members) / sizeof(struct_member),
       .members = xen_vm_record_struct_members
    };


void
xen_vm_record_free(xen_vm_record *record)
{
    if (record == NULL)
    {
        return;
    }
    free(record->handle);
    free(record->uuid);
    free(record->name_label);
    free(record->name_description);
    xen_vdi_record_opt_free(record->suspend_vdi);
    xen_host_record_opt_free(record->resident_on);
    xen_string_string_map_free(record->vcpus_params);
    xen_console_record_opt_set_free(record->consoles);
    xen_vif_record_opt_set_free(record->vifs);
    xen_vbd_record_opt_set_free(record->vbds);
    xen_crashdump_record_opt_set_free(record->crash_dumps);
    xen_vtpm_record_opt_set_free(record->vtpms);
    free(record->pv_bootloader);
    free(record->pv_kernel);
    free(record->pv_ramdisk);
    free(record->pv_args);
    free(record->pv_bootloader_args);
    free(record->hvm_boot_policy);
    xen_string_string_map_free(record->hvm_boot_params);
    xen_string_string_map_free(record->platform);
    free(record->pci_bus);
    xen_string_string_map_free(record->other_config);
    xen_vm_metrics_record_opt_free(record->metrics);
    xen_vm_guest_metrics_record_opt_free(record->guest_metrics);
    free(record);
}


bool
xen_vm_get_record(xen_session *session, xen_vm_record **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_vm_record_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM.get_record");

    if (session->ok)
    {
       (*result)->handle = xen_strdup_((*result)->uuid);
    }

    return session->ok;
}


bool
xen_vm_get_by_uuid(xen_session *session, xen_vm *result, char *uuid)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = uuid }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_by_uuid");
    return session->ok;
}


bool
xen_vm_create(xen_session *session, xen_vm *result, xen_vm_record *record)
{
    abstract_value param_values[] =
        {
            { .type = &xen_vm_record_abstract_type_,
              .u.struct_val = record }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.create");
    return session->ok;
}


bool
xen_vm_destroy(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.destroy", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_get_by_name_label(xen_session *session, struct xen_vm_set **result, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_by_name_label");
    return session->ok;
}


bool
xen_vm_get_power_state(xen_session *session, enum xen_vm_power_state *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_vm_power_state_abstract_type_;
    XEN_CALL_("VM.get_power_state");
    return session->ok;
}


bool
xen_vm_get_name_label(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_name_label");
    return session->ok;
}


bool
xen_vm_get_name_description(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_name_description");
    return session->ok;
}


bool
xen_vm_get_user_version(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_user_version");
    return session->ok;
}


bool
xen_vm_get_is_a_template(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_is_a_template");
    return session->ok;
}


bool
xen_vm_get_auto_power_on(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_auto_power_on");
    return session->ok;
}


bool
xen_vm_get_suspend_vdi(xen_session *session, xen_vdi *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_suspend_VDI");
    return session->ok;
}


bool
xen_vm_get_resident_on(xen_session *session, xen_host *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_resident_on");
    return session->ok;
}


bool
xen_vm_get_memory_static_max(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_memory_static_max");
    return session->ok;
}


bool
xen_vm_get_memory_dynamic_max(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_memory_dynamic_max");
    return session->ok;
}


bool
xen_vm_get_memory_dynamic_min(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_memory_dynamic_min");
    return session->ok;
}


bool
xen_vm_get_memory_static_min(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_memory_static_min");
    return session->ok;
}


bool
xen_vm_get_vcpus_params(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_params");
    return session->ok;
}


bool
xen_vm_get_vcpus_max(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_VCPUs_max");
    return session->ok;
}


bool
xen_vm_get_vcpus_at_startup(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_VCPUs_at_startup");
    return session->ok;
}


bool
xen_vm_get_actions_after_shutdown(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_on_normal_exit_abstract_type_;
    XEN_CALL_("VM.get_actions_after_shutdown");
    return session->ok;
}


bool
xen_vm_get_actions_after_reboot(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_on_normal_exit_abstract_type_;
    XEN_CALL_("VM.get_actions_after_reboot");
    return session->ok;
}


bool
xen_vm_get_actions_after_crash(xen_session *session, enum xen_on_crash_behaviour *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_on_crash_behaviour_abstract_type_;
    XEN_CALL_("VM.get_actions_after_crash");
    return session->ok;
}


bool
xen_vm_get_consoles(xen_session *session, struct xen_console_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_consoles");
    return session->ok;
}


bool
xen_vm_get_vifs(xen_session *session, struct xen_vif_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_VIFs");
    return session->ok;
}


bool
xen_vm_get_vbds(xen_session *session, struct xen_vbd_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_VBDs");
    return session->ok;
}


bool
xen_vm_get_crash_dumps(xen_session *session, struct xen_crashdump_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_crash_dumps");
    return session->ok;
}


bool
xen_vm_get_vtpms(xen_session *session, struct xen_vtpm_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    XEN_CALL_("VM.get_VTPMs");
    return session->ok;
}


bool
xen_vm_get_pv_bootloader(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PV_bootloader");
    return session->ok;
}


bool
xen_vm_get_pv_kernel(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PV_kernel");
    return session->ok;
}


bool
xen_vm_get_pv_ramdisk(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PV_ramdisk");
    return session->ok;
}


bool
xen_vm_get_pv_args(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PV_args");
    return session->ok;
}


bool
xen_vm_get_pv_bootloader_args(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PV_bootloader_args");
    return session->ok;
}


bool
xen_vm_get_hvm_boot_policy(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_HVM_boot_policy");
    return session->ok;
}


bool
xen_vm_get_hvm_boot_params(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_HVM_boot_params");
    return session->ok;
}


bool
xen_vm_get_platform(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_platform");
    return session->ok;
}


bool
xen_vm_get_pci_bus(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_PCI_bus");
    return session->ok;
}


bool
xen_vm_get_other_config(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_other_config");
    return session->ok;
}


bool
xen_vm_get_domid(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_domid");
    return session->ok;
}


bool
xen_vm_get_is_control_domain(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_is_control_domain");
    return session->ok;
}


bool
xen_vm_get_metrics(xen_session *session, xen_vm_metrics *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_metrics");
    return session->ok;
}


bool
xen_vm_get_guest_metrics(xen_session *session, xen_vm_guest_metrics *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_guest_metrics");
    return session->ok;
}


bool
xen_vm_set_name_label(xen_session *session, xen_vm vm, char *label)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = label }
        };

    xen_call_(session, "VM.set_name_label", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_name_description(xen_session *session, xen_vm vm, char *description)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = description }
        };

    xen_call_(session, "VM.set_name_description", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_user_version(xen_session *session, xen_vm vm, int64_t user_version)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = user_version }
        };

    xen_call_(session, "VM.set_user_version", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_is_a_template(xen_session *session, xen_vm vm, bool is_a_template)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = is_a_template }
        };

    xen_call_(session, "VM.set_is_a_template", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_auto_power_on(xen_session *session, xen_vm vm, bool auto_power_on)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = auto_power_on }
        };

    xen_call_(session, "VM.set_auto_power_on", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_memory_static_max(xen_session *session, xen_vm vm, int64_t static_max)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = static_max }
        };

    xen_call_(session, "VM.set_memory_static_max", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_memory_dynamic_max(xen_session *session, xen_vm vm, int64_t dynamic_max)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = dynamic_max }
        };

    xen_call_(session, "VM.set_memory_dynamic_max", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_memory_dynamic_min(xen_session *session, xen_vm vm, int64_t dynamic_min)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = dynamic_min }
        };

    xen_call_(session, "VM.set_memory_dynamic_min", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_memory_static_min(xen_session *session, xen_vm vm, int64_t static_min)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = static_min }
        };

    xen_call_(session, "VM.set_memory_static_min", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_params(xen_session *session, xen_vm vm, xen_string_string_map *params)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)params }
        };

    xen_call_(session, "VM.set_VCPUs_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_add_to_vcpus_params(xen_session *session, xen_vm vm, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "VM.add_to_VCPUs_params", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_vm_remove_from_vcpus_params(xen_session *session, xen_vm vm, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "VM.remove_from_VCPUs_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_max(xen_session *session, xen_vm vm, int64_t max)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = max }
        };

    xen_call_(session, "VM.set_VCPUs_max", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_at_startup(xen_session *session, xen_vm vm, int64_t at_startup)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_int,
              .u.int_val = at_startup }
        };

    xen_call_(session, "VM.set_VCPUs_at_startup", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_actions_after_shutdown(xen_session *session, xen_vm vm, enum xen_on_normal_exit after_shutdown)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_on_normal_exit_abstract_type_,
              .u.string_val = xen_on_normal_exit_to_string(after_shutdown) }
        };

    xen_call_(session, "VM.set_actions_after_shutdown", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_actions_after_reboot(xen_session *session, xen_vm vm, enum xen_on_normal_exit after_reboot)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_on_normal_exit_abstract_type_,
              .u.string_val = xen_on_normal_exit_to_string(after_reboot) }
        };

    xen_call_(session, "VM.set_actions_after_reboot", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_actions_after_crash(xen_session *session, xen_vm vm, enum xen_on_crash_behaviour after_crash)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_on_crash_behaviour_abstract_type_,
              .u.string_val = xen_on_crash_behaviour_to_string(after_crash) }
        };

    xen_call_(session, "VM.set_actions_after_crash", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pv_bootloader(xen_session *session, xen_vm vm, char *bootloader)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = bootloader }
        };

    xen_call_(session, "VM.set_PV_bootloader", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pv_kernel(xen_session *session, xen_vm vm, char *kernel)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = kernel }
        };

    xen_call_(session, "VM.set_PV_kernel", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pv_ramdisk(xen_session *session, xen_vm vm, char *ramdisk)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = ramdisk }
        };

    xen_call_(session, "VM.set_PV_ramdisk", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pv_args(xen_session *session, xen_vm vm, char *args)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = args }
        };

    xen_call_(session, "VM.set_PV_args", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pv_bootloader_args(xen_session *session, xen_vm vm, char *bootloader_args)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = bootloader_args }
        };

    xen_call_(session, "VM.set_PV_bootloader_args", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_hvm_boot_policy(xen_session *session, xen_vm vm, char *boot_policy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = boot_policy }
        };

    xen_call_(session, "VM.set_HVM_boot_policy", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_hvm_boot_params(xen_session *session, xen_vm vm, xen_string_string_map *boot_params)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)boot_params }
        };

    xen_call_(session, "VM.set_HVM_boot_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_add_to_hvm_boot_params(xen_session *session, xen_vm vm, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "VM.add_to_HVM_boot_params", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_vm_remove_from_hvm_boot_params(xen_session *session, xen_vm vm, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "VM.remove_from_HVM_boot_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform(xen_session *session, xen_vm vm, xen_string_string_map *platform)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)platform }
        };

    xen_call_(session, "VM.set_platform", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_add_to_platform(xen_session *session, xen_vm vm, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "VM.add_to_platform", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_vm_remove_from_platform(xen_session *session, xen_vm vm, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "VM.remove_from_platform", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_pci_bus(xen_session *session, xen_vm vm, char *pci_bus)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = pci_bus }
        };

    xen_call_(session, "VM.set_PCI_bus", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_other_config(xen_session *session, xen_vm vm, xen_string_string_map *other_config)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)other_config }
        };

    xen_call_(session, "VM.set_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_add_to_other_config(xen_session *session, xen_vm vm, char *key, char *value)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key },
            { .type = &abstract_type_string,
              .u.string_val = value }
        };

    xen_call_(session, "VM.add_to_other_config", param_values, 3, NULL, NULL);
    return session->ok;
}


bool
xen_vm_remove_from_other_config(xen_session *session, xen_vm vm, char *key)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = key }
        };

    xen_call_(session, "VM.remove_from_other_config", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_clone(xen_session *session, xen_vm *result, xen_vm vm, char *new_name)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = new_name }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.clone");
    return session->ok;
}


bool
xen_vm_start(xen_session *session, xen_vm vm, bool start_paused)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = start_paused }
        };

    xen_call_(session, "VM.start", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_pause(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.pause", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_unpause(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.unpause", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_clean_shutdown(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.clean_shutdown", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_clean_reboot(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.clean_reboot", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_hard_shutdown(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.hard_shutdown", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_hard_reboot(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.hard_reboot", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_suspend(xen_session *session, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    xen_call_(session, "VM.suspend", param_values, 1, NULL, NULL);
    return session->ok;
}


bool
xen_vm_resume(xen_session *session, xen_vm vm, bool start_paused)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = start_paused }
        };

    xen_call_(session, "VM.resume", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_number_live(xen_session *session, xen_vm self, int64_t nvcpu)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = self },
            { .type = &abstract_type_int,
              .u.int_val = nvcpu }
        };

    xen_call_(session, "VM.set_VCPUs_number_live", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_get_all(xen_session *session, struct xen_vm_set **result)
{

    abstract_type result_type = abstract_type_string_set;

    *result = NULL;
    xen_call_(session, "VM.get_all", NULL, 0, &result_type, result);
    return session->ok;
}


bool
xen_vm_get_uuid(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_uuid");
    return session->ok;
}
