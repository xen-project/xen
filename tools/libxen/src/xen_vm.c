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

#include "xen_boot_type_internal.h"
#include "xen_common.h"
#include "xen_console.h"
#include "xen_cpu_feature.h"
#include "xen_cpu_feature_internal.h"
#include "xen_host.h"
#include "xen_int_float_map.h"
#include "xen_internal.h"
#include "xen_on_crash_behaviour_internal.h"
#include "xen_on_normal_exit_internal.h"
#include "xen_string_string_map.h"
#include "xen_vbd.h"
#include "xen_vif.h"
#include "xen_vm.h"
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
        { .key = "resident_on",
          .type = &abstract_type_ref,
          .offset = offsetof(xen_vm_record, resident_on) },
        { .key = "memory_static_max",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_static_max) },
        { .key = "memory_dynamic_max",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_dynamic_max) },
        { .key = "memory_actual",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_actual) },
        { .key = "memory_dynamic_min",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_dynamic_min) },
        { .key = "memory_static_min",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, memory_static_min) },
        { .key = "VCPUs_policy",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, vcpus_policy) },
        { .key = "VCPUs_params",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, vcpus_params) },
        { .key = "VCPUs_number",
          .type = &abstract_type_int,
          .offset = offsetof(xen_vm_record, vcpus_number) },
        { .key = "VCPUs_utilisation",
          .type = &abstract_type_int_float_map,
          .offset = offsetof(xen_vm_record, vcpus_utilisation) },
        { .key = "VCPUs_features_required",
          .type = &xen_cpu_feature_set_abstract_type_,
          .offset = offsetof(xen_vm_record, vcpus_features_required) },
        { .key = "VCPUs_features_can_use",
          .type = &xen_cpu_feature_set_abstract_type_,
          .offset = offsetof(xen_vm_record, vcpus_features_can_use) },
        { .key = "VCPUs_features_force_on",
          .type = &xen_cpu_feature_set_abstract_type_,
          .offset = offsetof(xen_vm_record, vcpus_features_force_on) },
        { .key = "VCPUs_features_force_off",
          .type = &xen_cpu_feature_set_abstract_type_,
          .offset = offsetof(xen_vm_record, vcpus_features_force_off) },
        { .key = "actions_after_shutdown",
          .type = &xen_on_normal_exit_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_shutdown) },
        { .key = "actions_after_reboot",
          .type = &xen_on_normal_exit_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_reboot) },
        { .key = "actions_after_suspend",
          .type = &xen_on_normal_exit_abstract_type_,
          .offset = offsetof(xen_vm_record, actions_after_suspend) },
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
        { .key = "VTPMs",
          .type = &abstract_type_ref_set,
          .offset = offsetof(xen_vm_record, vtpms) },
        { .key = "bios_boot",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, bios_boot) },
        { .key = "platform_std_VGA",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, platform_std_vga) },
        { .key = "platform_serial",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, platform_serial) },
        { .key = "platform_localtime",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, platform_localtime) },
        { .key = "platform_clock_offset",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, platform_clock_offset) },
        { .key = "platform_enable_audio",
          .type = &abstract_type_bool,
          .offset = offsetof(xen_vm_record, platform_enable_audio) },
        { .key = "builder",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, builder) },
        { .key = "boot_method",
          .type = &xen_boot_type_abstract_type_,
          .offset = offsetof(xen_vm_record, boot_method) },
        { .key = "kernel_kernel",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, kernel_kernel) },
        { .key = "kernel_initrd",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, kernel_initrd) },
        { .key = "kernel_args",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, kernel_args) },
        { .key = "grub_cmdline",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, grub_cmdline) },
        { .key = "PCI_bus",
          .type = &abstract_type_string,
          .offset = offsetof(xen_vm_record, pci_bus) },
        { .key = "tools_version",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, tools_version) },
        { .key = "otherConfig",
          .type = &abstract_type_string_string_map,
          .offset = offsetof(xen_vm_record, otherconfig) }
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
    xen_host_record_opt_free(record->resident_on);
    free(record->vcpus_policy);
    free(record->vcpus_params);
    xen_int_float_map_free(record->vcpus_utilisation);
    xen_cpu_feature_set_free(record->vcpus_features_required);
    xen_cpu_feature_set_free(record->vcpus_features_can_use);
    xen_cpu_feature_set_free(record->vcpus_features_force_on);
    xen_cpu_feature_set_free(record->vcpus_features_force_off);
    xen_console_record_opt_set_free(record->consoles);
    xen_vif_record_opt_set_free(record->vifs);
    xen_vbd_record_opt_set_free(record->vbds);
    xen_vtpm_record_opt_set_free(record->vtpms);
    free(record->bios_boot);
    free(record->platform_serial);
    free(record->builder);
    free(record->kernel_kernel);
    free(record->kernel_initrd);
    free(record->kernel_args);
    free(record->grub_cmdline);
    free(record->pci_bus);
    xen_string_string_map_free(record->tools_version);
    xen_string_string_map_free(record->otherconfig);
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
    char *result_str = NULL;
    XEN_CALL_("VM.get_power_state");
    *result = xen_vm_power_state_from_string(session, result_str);
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
xen_vm_get_memory_actual(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_memory_actual");
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
xen_vm_get_vcpus_policy(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_policy");
    return session->ok;
}


bool
xen_vm_get_vcpus_params(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_params");
    return session->ok;
}


bool
xen_vm_get_vcpus_number(xen_session *session, int64_t *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int;

    XEN_CALL_("VM.get_VCPUs_number");
    return session->ok;
}


bool
xen_vm_get_vcpus_utilisation(xen_session *session, xen_int_float_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_int_float_map;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_utilisation");
    return session->ok;
}


bool
xen_vm_get_vcpus_features_required(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_cpu_feature_set_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_features_required");
    return session->ok;
}


bool
xen_vm_get_vcpus_features_can_use(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_cpu_feature_set_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_features_can_use");
    return session->ok;
}


bool
xen_vm_get_vcpus_features_force_on(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_cpu_feature_set_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_features_force_on");
    return session->ok;
}


bool
xen_vm_get_vcpus_features_force_off(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_cpu_feature_set_abstract_type_;

    *result = NULL;
    XEN_CALL_("VM.get_VCPUs_features_force_off");
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
    char *result_str = NULL;
    XEN_CALL_("VM.get_actions_after_shutdown");
    *result = xen_on_normal_exit_from_string(session, result_str);
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
    char *result_str = NULL;
    XEN_CALL_("VM.get_actions_after_reboot");
    *result = xen_on_normal_exit_from_string(session, result_str);
    return session->ok;
}


bool
xen_vm_get_actions_after_suspend(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_on_normal_exit_abstract_type_;
    char *result_str = NULL;
    XEN_CALL_("VM.get_actions_after_suspend");
    *result = xen_on_normal_exit_from_string(session, result_str);
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
    char *result_str = NULL;
    XEN_CALL_("VM.get_actions_after_crash");
    *result = xen_on_crash_behaviour_from_string(session, result_str);
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
xen_vm_get_bios_boot(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_bios_boot");
    return session->ok;
}


bool
xen_vm_get_platform_std_vga(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_platform_std_VGA");
    return session->ok;
}


bool
xen_vm_get_platform_serial(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_platform_serial");
    return session->ok;
}


bool
xen_vm_get_platform_localtime(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_platform_localtime");
    return session->ok;
}


bool
xen_vm_get_platform_clock_offset(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_platform_clock_offset");
    return session->ok;
}


bool
xen_vm_get_platform_enable_audio(xen_session *session, bool *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_bool;

    XEN_CALL_("VM.get_platform_enable_audio");
    return session->ok;
}


bool
xen_vm_get_builder(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_builder");
    return session->ok;
}


bool
xen_vm_get_boot_method(xen_session *session, enum xen_boot_type *result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = xen_boot_type_abstract_type_;
    char *result_str = NULL;
    XEN_CALL_("VM.get_boot_method");
    *result = xen_boot_type_from_string(session, result_str);
    return session->ok;
}


bool
xen_vm_get_kernel_kernel(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_kernel_kernel");
    return session->ok;
}


bool
xen_vm_get_kernel_initrd(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_kernel_initrd");
    return session->ok;
}


bool
xen_vm_get_kernel_args(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_kernel_args");
    return session->ok;
}


bool
xen_vm_get_grub_cmdline(xen_session *session, char **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string;

    *result = NULL;
    XEN_CALL_("VM.get_grub_cmdline");
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
xen_vm_get_tools_version(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_tools_version");
    return session->ok;
}


bool
xen_vm_get_otherconfig(xen_session *session, xen_string_string_map **result, xen_vm vm)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm }
        };

    abstract_type result_type = abstract_type_string_string_map;

    *result = NULL;
    XEN_CALL_("VM.get_otherConfig");
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
xen_vm_set_vcpus_policy(xen_session *session, xen_vm vm, char *policy)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = policy }
        };

    xen_call_(session, "VM.set_VCPUs_policy", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_params(xen_session *session, xen_vm vm, char *params)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = params }
        };

    xen_call_(session, "VM.set_VCPUs_params", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_features_force_on(xen_session *session, xen_vm vm, struct xen_cpu_feature_set *force_on)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_cpu_feature_set_abstract_type_,
              .u.set_val = (arbitrary_set *)force_on }
        };

    xen_call_(session, "VM.set_VCPUs_features_force_on", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_vcpus_features_force_off(xen_session *session, xen_vm vm, struct xen_cpu_feature_set *force_off)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_cpu_feature_set_abstract_type_,
              .u.set_val = (arbitrary_set *)force_off }
        };

    xen_call_(session, "VM.set_VCPUs_features_force_off", param_values, 2, NULL, NULL);
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
xen_vm_set_actions_after_suspend(xen_session *session, xen_vm vm, enum xen_on_normal_exit after_suspend)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_on_normal_exit_abstract_type_,
              .u.string_val = xen_on_normal_exit_to_string(after_suspend) }
        };

    xen_call_(session, "VM.set_actions_after_suspend", param_values, 2, NULL, NULL);
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
xen_vm_set_bios_boot(xen_session *session, xen_vm vm, char *boot)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = boot }
        };

    xen_call_(session, "VM.set_bios_boot", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform_std_vga(xen_session *session, xen_vm vm, bool std_vga)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = std_vga }
        };

    xen_call_(session, "VM.set_platform_std_vga", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform_serial(xen_session *session, xen_vm vm, char *serial)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = serial }
        };

    xen_call_(session, "VM.set_platform_serial", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform_localtime(xen_session *session, xen_vm vm, bool localtime)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = localtime }
        };

    xen_call_(session, "VM.set_platform_localtime", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform_clock_offset(xen_session *session, xen_vm vm, bool clock_offset)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = clock_offset }
        };

    xen_call_(session, "VM.set_platform_clock_offset", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_platform_enable_audio(xen_session *session, xen_vm vm, bool enable_audio)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_bool,
              .u.bool_val = enable_audio }
        };

    xen_call_(session, "VM.set_platform_enable_audio", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_builder(xen_session *session, xen_vm vm, char *builder)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = builder }
        };

    xen_call_(session, "VM.set_builder", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_boot_method(xen_session *session, xen_vm vm, enum xen_boot_type boot_method)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &xen_boot_type_abstract_type_,
              .u.string_val = xen_boot_type_to_string(boot_method) }
        };

    xen_call_(session, "VM.set_boot_method", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_kernel_kernel(xen_session *session, xen_vm vm, char *kernel)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = kernel }
        };

    xen_call_(session, "VM.set_kernel_kernel", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_kernel_initrd(xen_session *session, xen_vm vm, char *initrd)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = initrd }
        };

    xen_call_(session, "VM.set_kernel_initrd", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_kernel_args(xen_session *session, xen_vm vm, char *args)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = args }
        };

    xen_call_(session, "VM.set_kernel_args", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_grub_cmdline(xen_session *session, xen_vm vm, char *cmdline)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string,
              .u.string_val = cmdline }
        };

    xen_call_(session, "VM.set_grub_cmdline", param_values, 2, NULL, NULL);
    return session->ok;
}


bool
xen_vm_set_otherconfig(xen_session *session, xen_vm vm, xen_string_string_map *otherconfig)
{
    abstract_value param_values[] =
        {
            { .type = &abstract_type_string,
              .u.string_val = vm },
            { .type = &abstract_type_string_string_map,
              .u.set_val = (arbitrary_set *)otherconfig }
        };

    xen_call_(session, "VM.set_otherconfig", param_values, 2, NULL, NULL);
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
    *result = session->ok ? xen_strdup_((char *)vm) : NULL;
    return session->ok;
}
