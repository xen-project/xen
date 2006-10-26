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

#ifndef XEN_VM_H
#define XEN_VM_H

#include "xen_boot_type.h"
#include "xen_common.h"
#include "xen_cpu_feature.h"
#include "xen_host_decl.h"
#include "xen_int_float_map.h"
#include "xen_on_crash_behaviour.h"
#include "xen_on_normal_exit.h"
#include "xen_string_string_map.h"
#include "xen_vbd_decl.h"
#include "xen_vif_decl.h"
#include "xen_vm_decl.h"
#include "xen_vm_power_state.h"
#include "xen_vtpm_decl.h"


/*
 * The VM class. 
 *  
 * A virtual machine (or 'guest').
 */


/**
 * Free the given xen_vm.  The given handle must have been allocated by
 * this library.
 */
extern void
xen_vm_free(xen_vm vm);


typedef struct xen_vm_set
{
    size_t size;
    xen_vm *contents[];
} xen_vm_set;

/**
 * Allocate a xen_vm_set of the given size.
 */
extern xen_vm_set *
xen_vm_set_alloc(size_t size);

/**
 * Free the given xen_vm_set.  The given set must have been allocated
 * by this library.
 */
extern void
xen_vm_set_free(xen_vm_set *set);


typedef struct xen_vm_record
{
    xen_vm handle;
    char *uuid;
    enum xen_vm_power_state power_state;
    char *name_label;
    char *name_description;
    uint64_t user_version;
    bool is_a_template;
    struct xen_host_record_opt *resident_on;
    uint64_t memory_static_max;
    uint64_t memory_dynamic_max;
    uint64_t memory_actual;
    uint64_t memory_dynamic_min;
    uint64_t memory_static_min;
    char *vcpus_policy;
    char *vcpus_params;
    uint64_t vcpus_number;
    xen_int_float_map *vcpus_utilisation;
    struct xen_cpu_feature_set *vcpus_features_required;
    struct xen_cpu_feature_set *vcpus_features_can_use;
    struct xen_cpu_feature_set *vcpus_features_force_on;
    struct xen_cpu_feature_set *vcpus_features_force_off;
    enum xen_on_normal_exit actions_after_shutdown;
    enum xen_on_normal_exit actions_after_reboot;
    enum xen_on_normal_exit actions_after_suspend;
    enum xen_on_crash_behaviour actions_after_crash;
    struct xen_vif_record_opt_set *vifs;
    struct xen_vbd_record_opt_set *vbds;
    struct xen_vtpm_record_opt_set *vtpms;
    char *bios_boot;
    bool platform_std_vga;
    char *platform_serial;
    bool platform_localtime;
    bool platform_clock_offset;
    bool platform_enable_audio;
    char *builder;
    enum xen_boot_type boot_method;
    char *kernel_kernel;
    char *kernel_initrd;
    char *kernel_args;
    char *grub_cmdline;
    char *pci_bus;
    xen_string_string_map *tools_version;
    xen_string_string_map *otherconfig;
} xen_vm_record;

/**
 * Allocate a xen_vm_record.
 */
extern xen_vm_record *
xen_vm_record_alloc(void);

/**
 * Free the given xen_vm_record, and all referenced values.  The given
 * record must have been allocated by this library.
 */
extern void
xen_vm_record_free(xen_vm_record *record);


typedef struct xen_vm_record_opt
{
    bool is_record;
    union
    {
        xen_vm handle;
        xen_vm_record *record;
    } u;
} xen_vm_record_opt;

/**
 * Allocate a xen_vm_record_opt.
 */
extern xen_vm_record_opt *
xen_vm_record_opt_alloc(void);

/**
 * Free the given xen_vm_record_opt, and all referenced values.  The
 * given record_opt must have been allocated by this library.
 */
extern void
xen_vm_record_opt_free(xen_vm_record_opt *record_opt);


typedef struct xen_vm_record_set
{
    size_t size;
    xen_vm_record *contents[];
} xen_vm_record_set;

/**
 * Allocate a xen_vm_record_set of the given size.
 */
extern xen_vm_record_set *
xen_vm_record_set_alloc(size_t size);

/**
 * Free the given xen_vm_record_set, and all referenced values.  The
 * given set must have been allocated by this library.
 */
extern void
xen_vm_record_set_free(xen_vm_record_set *set);



typedef struct xen_vm_record_opt_set
{
    size_t size;
    xen_vm_record_opt *contents[];
} xen_vm_record_opt_set;

/**
 * Allocate a xen_vm_record_opt_set of the given size.
 */
extern xen_vm_record_opt_set *
xen_vm_record_opt_set_alloc(size_t size);

/**
 * Free the given xen_vm_record_opt_set, and all referenced values. 
 * The given set must have been allocated by this library.
 */
extern void
xen_vm_record_opt_set_free(xen_vm_record_opt_set *set);


/**
 * Get the current state of the given VM.  !!!
 */
extern bool
xen_vm_get_record(xen_session *session, xen_vm_record **result, xen_vm vm);


/**
 * Get a reference to the object with the specified UUID.  !!!
 */
extern bool
xen_vm_get_by_uuid(xen_session *session, xen_vm *result, char *uuid);


/**
 * Create a new VM instance, and return its handle.
 */
extern bool
xen_vm_create(xen_session *session, xen_vm *result, xen_vm_record *record);


/**
 * Get a reference to the object with the specified label.
 */
extern bool
xen_vm_get_by_name_label(xen_session *session, xen_vm *result, char *label);


/**
 * Get the uuid field of the given VM.
 */
extern bool
xen_vm_get_uuid(xen_session *session, char **result, xen_vm vm);


/**
 * Get the power_state field of the given VM.
 */
extern bool
xen_vm_get_power_state(xen_session *session, enum xen_vm_power_state *result, xen_vm vm);


/**
 * Get the name/label field of the given VM.
 */
extern bool
xen_vm_get_name_label(xen_session *session, char **result, xen_vm vm);


/**
 * Get the name/description field of the given VM.
 */
extern bool
xen_vm_get_name_description(xen_session *session, char **result, xen_vm vm);


/**
 * Get the user_version field of the given VM.
 */
extern bool
xen_vm_get_user_version(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the is_a_template field of the given VM.
 */
extern bool
xen_vm_get_is_a_template(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the resident_on field of the given VM.
 */
extern bool
xen_vm_get_resident_on(xen_session *session, xen_host *result, xen_vm vm);


/**
 * Get the memory/static_max field of the given VM.
 */
extern bool
xen_vm_get_memory_static_max(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the memory/dynamic_max field of the given VM.
 */
extern bool
xen_vm_get_memory_dynamic_max(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the memory/actual field of the given VM.
 */
extern bool
xen_vm_get_memory_actual(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the memory/dynamic_min field of the given VM.
 */
extern bool
xen_vm_get_memory_dynamic_min(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the memory/static_min field of the given VM.
 */
extern bool
xen_vm_get_memory_static_min(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the VCPUs/policy field of the given VM.
 */
extern bool
xen_vm_get_vcpus_policy(xen_session *session, char **result, xen_vm vm);


/**
 * Get the VCPUs/params field of the given VM.
 */
extern bool
xen_vm_get_vcpus_params(xen_session *session, char **result, xen_vm vm);


/**
 * Get the VCPUs/number field of the given VM.
 */
extern bool
xen_vm_get_vcpus_number(xen_session *session, uint64_t *result, xen_vm vm);


/**
 * Get the VCPUs/utilisation field of the given VM.
 */
extern bool
xen_vm_get_vcpus_utilisation(xen_session *session, xen_int_float_map **result, xen_vm vm);


/**
 * Get the VCPUs/features/required field of the given VM.
 */
extern bool
xen_vm_get_vcpus_features_required(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm);


/**
 * Get the VCPUs/features/can_use field of the given VM.
 */
extern bool
xen_vm_get_vcpus_features_can_use(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm);


/**
 * Get the VCPUs/features/force_on field of the given VM.
 */
extern bool
xen_vm_get_vcpus_features_force_on(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm);


/**
 * Get the VCPUs/features/force_off field of the given VM.
 */
extern bool
xen_vm_get_vcpus_features_force_off(xen_session *session, struct xen_cpu_feature_set **result, xen_vm vm);


/**
 * Get the actions/after_shutdown field of the given VM.
 */
extern bool
xen_vm_get_actions_after_shutdown(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm);


/**
 * Get the actions/after_reboot field of the given VM.
 */
extern bool
xen_vm_get_actions_after_reboot(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm);


/**
 * Get the actions/after_suspend field of the given VM.
 */
extern bool
xen_vm_get_actions_after_suspend(xen_session *session, enum xen_on_normal_exit *result, xen_vm vm);


/**
 * Get the actions/after_crash field of the given VM.
 */
extern bool
xen_vm_get_actions_after_crash(xen_session *session, enum xen_on_crash_behaviour *result, xen_vm vm);


/**
 * Get the VIFs field of the given VM.
 */
extern bool
xen_vm_get_vifs(xen_session *session, xen_vif *result, xen_vm vm);


/**
 * Get the VBDs field of the given VM.
 */
extern bool
xen_vm_get_vbds(xen_session *session, xen_vbd *result, xen_vm vm);


/**
 * Get the VTPMs field of the given VM.
 */
extern bool
xen_vm_get_vtpms(xen_session *session, xen_vtpm *result, xen_vm vm);


/**
 * Get the bios/boot field of the given VM.
 */
extern bool
xen_vm_get_bios_boot(xen_session *session, char **result, xen_vm vm);


/**
 * Get the platform/std_VGA field of the given VM.
 */
extern bool
xen_vm_get_platform_std_vga(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the platform/serial field of the given VM.
 */
extern bool
xen_vm_get_platform_serial(xen_session *session, char **result, xen_vm vm);


/**
 * Get the platform/localtime field of the given VM.
 */
extern bool
xen_vm_get_platform_localtime(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the platform/clock_offset field of the given VM.
 */
extern bool
xen_vm_get_platform_clock_offset(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the platform/enable_audio field of the given VM.
 */
extern bool
xen_vm_get_platform_enable_audio(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the builder field of the given VM.
 */
extern bool
xen_vm_get_builder(xen_session *session, char **result, xen_vm vm);


/**
 * Get the boot_method field of the given VM.
 */
extern bool
xen_vm_get_boot_method(xen_session *session, enum xen_boot_type *result, xen_vm vm);


/**
 * Get the kernel/kernel field of the given VM.
 */
extern bool
xen_vm_get_kernel_kernel(xen_session *session, char **result, xen_vm vm);


/**
 * Get the kernel/initrd field of the given VM.
 */
extern bool
xen_vm_get_kernel_initrd(xen_session *session, char **result, xen_vm vm);


/**
 * Get the kernel/args field of the given VM.
 */
extern bool
xen_vm_get_kernel_args(xen_session *session, char **result, xen_vm vm);


/**
 * Get the grub/cmdline field of the given VM.
 */
extern bool
xen_vm_get_grub_cmdline(xen_session *session, char **result, xen_vm vm);


/**
 * Get the PCI_bus field of the given VM.
 */
extern bool
xen_vm_get_pci_bus(xen_session *session, char **result, xen_vm vm);


/**
 * Get the tools_version field of the given VM.
 */
extern bool
xen_vm_get_tools_version(xen_session *session, xen_string_string_map **result, xen_vm vm);


/**
 * Get the otherConfig field of the given VM.
 */
extern bool
xen_vm_get_otherconfig(xen_session *session, xen_string_string_map **result, xen_vm vm);


/**
 * Set the name/label field of the given VM.
 */
extern bool
xen_vm_set_name_label(xen_session *session, xen_vm xen_vm, char *label);


/**
 * Set the name/description field of the given VM.
 */
extern bool
xen_vm_set_name_description(xen_session *session, xen_vm xen_vm, char *description);


/**
 * Set the user_version field of the given VM.
 */
extern bool
xen_vm_set_user_version(xen_session *session, xen_vm xen_vm, uint64_t user_version);


/**
 * Set the is_a_template field of the given VM.
 */
extern bool
xen_vm_set_is_a_template(xen_session *session, xen_vm xen_vm, bool is_a_template);


/**
 * Set the memory/dynamic_max field of the given VM.
 */
extern bool
xen_vm_set_memory_dynamic_max(xen_session *session, xen_vm xen_vm, uint64_t dynamic_max);


/**
 * Set the memory/dynamic_min field of the given VM.
 */
extern bool
xen_vm_set_memory_dynamic_min(xen_session *session, xen_vm xen_vm, uint64_t dynamic_min);


/**
 * Set the VCPUs/policy field of the given VM.
 */
extern bool
xen_vm_set_vcpus_policy(xen_session *session, xen_vm xen_vm, char *policy);


/**
 * Set the VCPUs/params field of the given VM.
 */
extern bool
xen_vm_set_vcpus_params(xen_session *session, xen_vm xen_vm, char *params);


/**
 * Set the VCPUs/features/force_on field of the given VM.
 */
extern bool
xen_vm_set_vcpus_features_force_on(xen_session *session, xen_vm xen_vm, struct xen_cpu_feature_set *force_on);


/**
 * Set the VCPUs/features/force_off field of the given VM.
 */
extern bool
xen_vm_set_vcpus_features_force_off(xen_session *session, xen_vm xen_vm, struct xen_cpu_feature_set *force_off);


/**
 * Set the actions/after_shutdown field of the given VM.
 */
extern bool
xen_vm_set_actions_after_shutdown(xen_session *session, xen_vm xen_vm, enum xen_on_normal_exit after_shutdown);


/**
 * Set the actions/after_reboot field of the given VM.
 */
extern bool
xen_vm_set_actions_after_reboot(xen_session *session, xen_vm xen_vm, enum xen_on_normal_exit after_reboot);


/**
 * Set the actions/after_suspend field of the given VM.
 */
extern bool
xen_vm_set_actions_after_suspend(xen_session *session, xen_vm xen_vm, enum xen_on_normal_exit after_suspend);


/**
 * Set the actions/after_crash field of the given VM.
 */
extern bool
xen_vm_set_actions_after_crash(xen_session *session, xen_vm xen_vm, enum xen_on_crash_behaviour after_crash);


/**
 * Set the bios/boot field of the given VM.
 */
extern bool
xen_vm_set_bios_boot(xen_session *session, xen_vm xen_vm, char *boot);


/**
 * Set the platform/std_VGA field of the given VM.
 */
extern bool
xen_vm_set_platform_std_vga(xen_session *session, xen_vm xen_vm, bool std_vga);


/**
 * Set the platform/serial field of the given VM.
 */
extern bool
xen_vm_set_platform_serial(xen_session *session, xen_vm xen_vm, char *serial);


/**
 * Set the platform/localtime field of the given VM.
 */
extern bool
xen_vm_set_platform_localtime(xen_session *session, xen_vm xen_vm, bool localtime);


/**
 * Set the platform/clock_offset field of the given VM.
 */
extern bool
xen_vm_set_platform_clock_offset(xen_session *session, xen_vm xen_vm, bool clock_offset);


/**
 * Set the platform/enable_audio field of the given VM.
 */
extern bool
xen_vm_set_platform_enable_audio(xen_session *session, xen_vm xen_vm, bool enable_audio);


/**
 * Set the builder field of the given VM.
 */
extern bool
xen_vm_set_builder(xen_session *session, xen_vm xen_vm, char *builder);


/**
 * Set the boot_method field of the given VM.
 */
extern bool
xen_vm_set_boot_method(xen_session *session, xen_vm xen_vm, enum xen_boot_type boot_method);


/**
 * Set the kernel/kernel field of the given VM.
 */
extern bool
xen_vm_set_kernel_kernel(xen_session *session, xen_vm xen_vm, char *kernel);


/**
 * Set the kernel/initrd field of the given VM.
 */
extern bool
xen_vm_set_kernel_initrd(xen_session *session, xen_vm xen_vm, char *initrd);


/**
 * Set the kernel/args field of the given VM.
 */
extern bool
xen_vm_set_kernel_args(xen_session *session, xen_vm xen_vm, char *args);


/**
 * Set the grub/cmdline field of the given VM.
 */
extern bool
xen_vm_set_grub_cmdline(xen_session *session, xen_vm xen_vm, char *cmdline);


/**
 * Set the otherConfig field of the given VM.
 */
extern bool
xen_vm_set_otherconfig(xen_session *session, xen_vm xen_vm, xen_string_string_map *otherconfig);


/**
 * Clones the specified VM, making a new VM. Clone automatically
 * exploits the capabilities of the underlying storage repository in which the
 * VM's disk images are stored (e.g. Copy on Write).   This function can only
 * be called when the VM is in the Halted State.
 */
extern bool
xen_vm_clone(xen_session *session, xen_vm *result, xen_vm vm, char *new_name);


/**
 * Start the specified VM.  This function can only be called with the
 * VM is in the Halted State.
 */
extern bool
xen_vm_start(xen_session *session, xen_vm vm, bool start_paused);


/**
 * Pause the specified VM. This can only be called when the specified
 * VM is in the Running state.
 */
extern bool
xen_vm_pause(xen_session *session, xen_vm vm);


/**
 * Resume the specified VM. This can only be called when the specified
 * VM is in the Paused state.
 */
extern bool
xen_vm_unpause(xen_session *session, xen_vm vm);


/**
 * Attempt to cleanly shutdown the specified VM. (Note: this may not be
 * supported---e.g. if a guest agent is not installed). 
 *  
 * Once shutdown has been completed perform poweroff action specified in guest
 * configuration.
 */
extern bool
xen_vm_clean_shutdown(xen_session *session, xen_vm vm);


/**
 * Attempt to cleanly shutdown the specified VM (Note: this may not be
 * supported---e.g. if a guest agent is not installed). 
 *  
 * Once shutdown has been completed perform reboot action specified in guest
 * configuration.
 */
extern bool
xen_vm_clean_reboot(xen_session *session, xen_vm vm);


/**
 * Stop executing the specified VM without attempting a clean shutdown.
 * Then perform poweroff action specified in VM configuration.
 */
extern bool
xen_vm_hard_shutdown(xen_session *session, xen_vm vm);


/**
 * Stop executing the specified VM without attempting a clean shutdown.
 * Then perform reboot action specified in VM configuration
 */
extern bool
xen_vm_hard_reboot(xen_session *session, xen_vm vm);


/**
 * Suspend the specified VM to disk.
 */
extern bool
xen_vm_suspend(xen_session *session, xen_vm vm);


/**
 * Awaken the specified VM and resume it.
 */
extern bool
xen_vm_resume(xen_session *session, xen_vm vm, bool start_paused);


/**
 * Return a list of all the VMs known to the system.
 */
extern bool
xen_vm_get_all(xen_session *session, xen_vm *result);


#endif
