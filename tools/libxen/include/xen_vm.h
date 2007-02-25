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

#ifndef XEN_VM_H
#define XEN_VM_H

#include "xen_common.h"
#include "xen_console_decl.h"
#include "xen_crashdump_decl.h"
#include "xen_host_decl.h"
#include "xen_on_crash_behaviour.h"
#include "xen_on_normal_exit.h"
#include "xen_string_string_map.h"
#include "xen_vbd_decl.h"
#include "xen_vdi_decl.h"
#include "xen_vif_decl.h"
#include "xen_vm_decl.h"
#include "xen_vm_metrics_decl.h"
#include "xen_vm_power_state.h"
#include "xen_vtpm_decl.h"


/*
 * The VM class.
 * 
 * A virtual machine (or 'guest').
 * 
 * VM booting is controlled by setting one of the two mutually exclusive
 * groups: "PV", and "HVM".  If HVM.boot_policy is the empty string, then
 * paravirtual domain building and booting will be used; otherwise the VM will
 * be loaded as an HVM domain, and booted using an emulated BIOS.
 * 
 * When paravirtual booting is in use, the PV/bootloader field indicates the
 * bootloader to use.  It may be "pygrub", in which case the platform's
 * default installation of pygrub will be used, or a full path within the
 * control domain to some other bootloader.  The other fields, PV/kernel,
 * PV/ramdisk, PV/args and PV/bootloader_args will be passed to the bootloader
 * unmodified, and interpretation of those fields is then specific to the
 * bootloader itself, including the possibility that the bootloader will
 * ignore some or all of those given values. Finally the paths of all bootable
 * disks are added to the bootloader commandline (a disk is bootable if its
 * VBD has the bootable flag set). There may be zero, one or many bootable
 * disks; the bootloader decides which disk (if any) to boot from.
 * 
 * If the bootloader is pygrub, then the menu.lst is parsed if present in the
 * guest's filesystem, otherwise the specified kernel and ramdisk are used, or
 * an autodetected kernel is used if nothing is specified and autodetection is
 * possible.  PV/args is appended to the kernel command line, no matter which
 * mechanism is used for finding the kernel.
 * 
 * If PV/bootloader is empty but PV/kernel is specified, then the kernel and
 * ramdisk values will be treated as paths within the control domain.  If both
 * PV/bootloader and PV/kernel are empty, then the behaviour is as if
 * PV/bootloader was specified as "pygrub".
 * 
 * When using HVM booting, HVM/boot_policy and HVM/boot_params specify the
 * boot handling.  Only one policy is currently defined: "BIOS order".  In
 * this case, HVM/boot_params should contain one key-value pair "order" = "N"
 * where N is the string that will be passed to QEMU..
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
    int64_t user_version;
    bool is_a_template;
    bool auto_power_on;
    struct xen_vdi_record_opt *suspend_vdi;
    struct xen_host_record_opt *resident_on;
    int64_t memory_static_max;
    int64_t memory_dynamic_max;
    int64_t memory_dynamic_min;
    int64_t memory_static_min;
    char *vcpus_policy;
    xen_string_string_map *vcpus_params;
    int64_t vcpus_max;
    int64_t vcpus_at_startup;
    enum xen_on_normal_exit actions_after_shutdown;
    enum xen_on_normal_exit actions_after_reboot;
    enum xen_on_crash_behaviour actions_after_crash;
    struct xen_console_record_opt_set *consoles;
    struct xen_vif_record_opt_set *vifs;
    struct xen_vbd_record_opt_set *vbds;
    struct xen_crashdump_record_opt_set *crash_dumps;
    struct xen_vtpm_record_opt_set *vtpms;
    char *pv_bootloader;
    char *pv_kernel;
    char *pv_ramdisk;
    char *pv_args;
    char *pv_bootloader_args;
    char *hvm_boot_policy;
    xen_string_string_map *hvm_boot_params;
    bool platform_std_vga;
    char *platform_serial;
    bool platform_localtime;
    bool platform_clock_offset;
    bool platform_enable_audio;
    char *pci_bus;
    xen_string_string_map *tools_version;
    xen_string_string_map *other_config;
    bool is_control_domain;
    struct xen_vm_metrics_record_opt *metrics;
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
 * Get a record containing the current state of the given VM.
 */
extern bool
xen_vm_get_record(xen_session *session, xen_vm_record **result, xen_vm vm);


/**
 * Get a reference to the VM instance with the specified UUID.
 */
extern bool
xen_vm_get_by_uuid(xen_session *session, xen_vm *result, char *uuid);


/**
 * Create a new VM instance, and return its handle.
 */
extern bool
xen_vm_create(xen_session *session, xen_vm *result, xen_vm_record *record);


/**
 * Destroy the specified VM.  The VM is completely removed from the
 * system.  This function can only be called when the VM is in the Halted
 * State.
 */
extern bool
xen_vm_destroy(xen_session *session, xen_vm vm);


/**
 * Get all the VM instances with the given label.
 */
extern bool
xen_vm_get_by_name_label(xen_session *session, struct xen_vm_set **result, char *label);


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
xen_vm_get_user_version(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the is_a_template field of the given VM.
 */
extern bool
xen_vm_get_is_a_template(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the auto_power_on field of the given VM.
 */
extern bool
xen_vm_get_auto_power_on(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the suspend_VDI field of the given VM.
 */
extern bool
xen_vm_get_suspend_vdi(xen_session *session, xen_vdi *result, xen_vm vm);


/**
 * Get the resident_on field of the given VM.
 */
extern bool
xen_vm_get_resident_on(xen_session *session, xen_host *result, xen_vm vm);


/**
 * Get the memory/static_max field of the given VM.
 */
extern bool
xen_vm_get_memory_static_max(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the memory/dynamic_max field of the given VM.
 */
extern bool
xen_vm_get_memory_dynamic_max(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the memory/dynamic_min field of the given VM.
 */
extern bool
xen_vm_get_memory_dynamic_min(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the memory/static_min field of the given VM.
 */
extern bool
xen_vm_get_memory_static_min(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the VCPUs/policy field of the given VM.
 */
extern bool
xen_vm_get_vcpus_policy(xen_session *session, char **result, xen_vm vm);


/**
 * Get the VCPUs/params field of the given VM.
 */
extern bool
xen_vm_get_vcpus_params(xen_session *session, xen_string_string_map **result, xen_vm vm);


/**
 * Get the VCPUs/max field of the given VM.
 */
extern bool
xen_vm_get_vcpus_max(xen_session *session, int64_t *result, xen_vm vm);


/**
 * Get the VCPUs/at_startup field of the given VM.
 */
extern bool
xen_vm_get_vcpus_at_startup(xen_session *session, int64_t *result, xen_vm vm);


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
 * Get the actions/after_crash field of the given VM.
 */
extern bool
xen_vm_get_actions_after_crash(xen_session *session, enum xen_on_crash_behaviour *result, xen_vm vm);


/**
 * Get the consoles field of the given VM.
 */
extern bool
xen_vm_get_consoles(xen_session *session, struct xen_console_set **result, xen_vm vm);


/**
 * Get the VIFs field of the given VM.
 */
extern bool
xen_vm_get_vifs(xen_session *session, struct xen_vif_set **result, xen_vm vm);


/**
 * Get the VBDs field of the given VM.
 */
extern bool
xen_vm_get_vbds(xen_session *session, struct xen_vbd_set **result, xen_vm vm);


/**
 * Get the crash_dumps field of the given VM.
 */
extern bool
xen_vm_get_crash_dumps(xen_session *session, struct xen_crashdump_set **result, xen_vm vm);


/**
 * Get the VTPMs field of the given VM.
 */
extern bool
xen_vm_get_vtpms(xen_session *session, struct xen_vtpm_set **result, xen_vm vm);


/**
 * Get the PV/bootloader field of the given VM.
 */
extern bool
xen_vm_get_pv_bootloader(xen_session *session, char **result, xen_vm vm);


/**
 * Get the PV/kernel field of the given VM.
 */
extern bool
xen_vm_get_pv_kernel(xen_session *session, char **result, xen_vm vm);


/**
 * Get the PV/ramdisk field of the given VM.
 */
extern bool
xen_vm_get_pv_ramdisk(xen_session *session, char **result, xen_vm vm);


/**
 * Get the PV/args field of the given VM.
 */
extern bool
xen_vm_get_pv_args(xen_session *session, char **result, xen_vm vm);


/**
 * Get the PV/bootloader_args field of the given VM.
 */
extern bool
xen_vm_get_pv_bootloader_args(xen_session *session, char **result, xen_vm vm);


/**
 * Get the HVM/boot_policy field of the given VM.
 */
extern bool
xen_vm_get_hvm_boot_policy(xen_session *session, char **result, xen_vm vm);


/**
 * Get the HVM/boot_params field of the given VM.
 */
extern bool
xen_vm_get_hvm_boot_params(xen_session *session, xen_string_string_map **result, xen_vm vm);


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
 * Get the other_config field of the given VM.
 */
extern bool
xen_vm_get_other_config(xen_session *session, xen_string_string_map **result, xen_vm vm);


/**
 * Get the is_control_domain field of the given VM.
 */
extern bool
xen_vm_get_is_control_domain(xen_session *session, bool *result, xen_vm vm);


/**
 * Get the metrics field of the given VM.
 */
extern bool
xen_vm_get_metrics(xen_session *session, xen_vm_metrics *result, xen_vm vm);


/**
 * Set the name/label field of the given VM.
 */
extern bool
xen_vm_set_name_label(xen_session *session, xen_vm vm, char *label);


/**
 * Set the name/description field of the given VM.
 */
extern bool
xen_vm_set_name_description(xen_session *session, xen_vm vm, char *description);


/**
 * Set the user_version field of the given VM.
 */
extern bool
xen_vm_set_user_version(xen_session *session, xen_vm vm, int64_t user_version);


/**
 * Set the is_a_template field of the given VM.
 */
extern bool
xen_vm_set_is_a_template(xen_session *session, xen_vm vm, bool is_a_template);


/**
 * Set the auto_power_on field of the given VM.
 */
extern bool
xen_vm_set_auto_power_on(xen_session *session, xen_vm vm, bool auto_power_on);


/**
 * Set the memory/static_max field of the given VM.
 */
extern bool
xen_vm_set_memory_static_max(xen_session *session, xen_vm vm, int64_t static_max);


/**
 * Set the memory/dynamic_max field of the given VM.
 */
extern bool
xen_vm_set_memory_dynamic_max(xen_session *session, xen_vm vm, int64_t dynamic_max);


/**
 * Set the memory/dynamic_min field of the given VM.
 */
extern bool
xen_vm_set_memory_dynamic_min(xen_session *session, xen_vm vm, int64_t dynamic_min);


/**
 * Set the memory/static_min field of the given VM.
 */
extern bool
xen_vm_set_memory_static_min(xen_session *session, xen_vm vm, int64_t static_min);


/**
 * Set the VCPUs/policy field of the given VM.
 */
extern bool
xen_vm_set_vcpus_policy(xen_session *session, xen_vm vm, char *policy);


/**
 * Set the VCPUs/params field of the given VM.
 */
extern bool
xen_vm_set_vcpus_params(xen_session *session, xen_vm vm, xen_string_string_map *params);


/**
 * Add the given key-value pair to the VCPUs/params field of the given
 * VM.
 */
extern bool
xen_vm_add_to_vcpus_params(xen_session *session, xen_vm vm, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * VCPUs/params field of the given VM.  If the key is not in that Map, then do
 * nothing.
 */
extern bool
xen_vm_remove_from_vcpus_params(xen_session *session, xen_vm vm, char *key);


/**
 * Set the VCPUs/max field of the given VM.
 */
extern bool
xen_vm_set_vcpus_max(xen_session *session, xen_vm vm, int64_t max);


/**
 * Set the VCPUs/at_startup field of the given VM.
 */
extern bool
xen_vm_set_vcpus_at_startup(xen_session *session, xen_vm vm, int64_t at_startup);


/**
 * Set the actions/after_shutdown field of the given VM.
 */
extern bool
xen_vm_set_actions_after_shutdown(xen_session *session, xen_vm vm, enum xen_on_normal_exit after_shutdown);


/**
 * Set the actions/after_reboot field of the given VM.
 */
extern bool
xen_vm_set_actions_after_reboot(xen_session *session, xen_vm vm, enum xen_on_normal_exit after_reboot);


/**
 * Set the actions/after_crash field of the given VM.
 */
extern bool
xen_vm_set_actions_after_crash(xen_session *session, xen_vm vm, enum xen_on_crash_behaviour after_crash);


/**
 * Set the PV/bootloader field of the given VM.
 */
extern bool
xen_vm_set_pv_bootloader(xen_session *session, xen_vm vm, char *bootloader);


/**
 * Set the PV/kernel field of the given VM.
 */
extern bool
xen_vm_set_pv_kernel(xen_session *session, xen_vm vm, char *kernel);


/**
 * Set the PV/ramdisk field of the given VM.
 */
extern bool
xen_vm_set_pv_ramdisk(xen_session *session, xen_vm vm, char *ramdisk);


/**
 * Set the PV/args field of the given VM.
 */
extern bool
xen_vm_set_pv_args(xen_session *session, xen_vm vm, char *args);


/**
 * Set the PV/bootloader_args field of the given VM.
 */
extern bool
xen_vm_set_pv_bootloader_args(xen_session *session, xen_vm vm, char *bootloader_args);


/**
 * Set the HVM/boot_policy field of the given VM.
 */
extern bool
xen_vm_set_hvm_boot_policy(xen_session *session, xen_vm vm, char *boot_policy);


/**
 * Set the HVM/boot_params field of the given VM.
 */
extern bool
xen_vm_set_hvm_boot_params(xen_session *session, xen_vm vm, xen_string_string_map *boot_params);


/**
 * Add the given key-value pair to the HVM/boot_params field of the
 * given VM.
 */
extern bool
xen_vm_add_to_hvm_boot_params(xen_session *session, xen_vm vm, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * HVM/boot_params field of the given VM.  If the key is not in that Map, then
 * do nothing.
 */
extern bool
xen_vm_remove_from_hvm_boot_params(xen_session *session, xen_vm vm, char *key);


/**
 * Set the platform/std_VGA field of the given VM.
 */
extern bool
xen_vm_set_platform_std_vga(xen_session *session, xen_vm vm, bool std_vga);


/**
 * Set the platform/serial field of the given VM.
 */
extern bool
xen_vm_set_platform_serial(xen_session *session, xen_vm vm, char *serial);


/**
 * Set the platform/localtime field of the given VM.
 */
extern bool
xen_vm_set_platform_localtime(xen_session *session, xen_vm vm, bool localtime);


/**
 * Set the platform/clock_offset field of the given VM.
 */
extern bool
xen_vm_set_platform_clock_offset(xen_session *session, xen_vm vm, bool clock_offset);


/**
 * Set the platform/enable_audio field of the given VM.
 */
extern bool
xen_vm_set_platform_enable_audio(xen_session *session, xen_vm vm, bool enable_audio);


/**
 * Set the other_config field of the given VM.
 */
extern bool
xen_vm_set_other_config(xen_session *session, xen_vm vm, xen_string_string_map *other_config);


/**
 * Add the given key-value pair to the other_config field of the given
 * VM.
 */
extern bool
xen_vm_add_to_other_config(xen_session *session, xen_vm vm, char *key, char *value);


/**
 * Remove the given key and its corresponding value from the
 * other_config field of the given VM.  If the key is not in that Map, then do
 * nothing.
 */
extern bool
xen_vm_remove_from_other_config(xen_session *session, xen_vm vm, char *key);


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
 * 
 * This can only be called when the specified VM is in the Running state.
 */
extern bool
xen_vm_clean_shutdown(xen_session *session, xen_vm vm);


/**
 * Attempt to cleanly shutdown the specified VM (Note: this may not be
 * supported---e.g. if a guest agent is not installed).
 * 
 * Once shutdown has been completed perform reboot action specified in guest
 * configuration.
 * 
 * This can only be called when the specified VM is in the Running state.
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
 * Suspend the specified VM to disk.  This can only be called when the
 * specified VM is in the Running state.
 */
extern bool
xen_vm_suspend(xen_session *session, xen_vm vm);


/**
 * Awaken the specified VM and resume it.  This can only be called when
 * the specified VM is in the Suspended state.
 */
extern bool
xen_vm_resume(xen_session *session, xen_vm vm, bool start_paused);


/**
 * Return a list of all the VMs known to the system.
 */
extern bool
xen_vm_get_all(xen_session *session, struct xen_vm_set **result);


#endif
