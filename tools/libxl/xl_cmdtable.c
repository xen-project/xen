/*
 * Author Yang Hongyang <yanghy@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "xl_cmdtable.h"

struct cmd_spec cmd_table[] = {
    { "create", &main_create, "create a domain from config file <filename>" },
    { "list", &main_list, "list information about all domains" },
    { "destroy", &main_destroy, "terminate a domain immediately" },
    { "pci-attach", &main_pciattach, "insert a new pass-through pci device" },
    { "pci-detach", &main_pcidetach, "remove a domain's pass-through pci device" },
    { "pci-list", &main_pcilist, "list pass-through pci devices for a domain" },
    { "pause", &main_pause, "pause execution of a domain" },
    { "unpause", &main_unpause, "unpause a paused domain" },
    { "console", &main_console, "attach to domain's console" },
    { "save", &main_save, "save a domain state to restore later" },
    { "restore", &main_restore, "restore a domain from a saved state" },
    { "cd-insert", &main_cd_insert, "insert a cdrom into a guest's cd drive" },
    { "cd-eject", &main_cd_eject, "eject a cdrom from a guest's cd drive" },
    { "mem-set", &main_memset, "set the current memory usage for a domain" },
    { "button-press", &main_button_press, "indicate an ACPI button press to the domain" },
    { "vcpu-list", &main_vcpulist, "list the VCPUs for all/some domains" },
    { "vcpu-pin", &main_vcpupin, "set which CPUs a VCPU can use" },
    { "vcpu-set", &main_vcpuset, "set the number of active VCPUs allowed for the domain" },
    { "list-vm", &main_list_vm, "list the VMs,without DOM0" },
    { "info", &main_info, "get information about Xen host" },
    { "sched-credit", &main_sched_credit, "get/set credit scheduler parameters" },
    { "domid", &main_domid, "convert a domain name to domain id"},
};

int cmdtable_len = sizeof(cmd_table)/sizeof(struct cmd_spec);
