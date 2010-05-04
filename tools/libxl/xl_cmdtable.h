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

#include "xl_cmdimpl.h"

struct cmd_spec {
    char *cmd_name;
    int (*cmd_impl)(int argc, char **argv);
};

struct cmd_spec cmd_table[] = {
    { "create", &main_create },
    { "list", &main_list },
    { "destroy", &main_destroy },
    { "pci-attach", &main_pciattach },
    { "pci-detach", &main_pcidetach },
    { "pci-list", &main_pcilist },
    { "pause", &main_pause },
    { "unpause", &main_unpause },
    { "console", &main_console },
    { "save", &main_save },
    { "restore", &main_restore },
    { "cd-insert", &main_cd_insert },
    { "cd-eject", &main_cd_eject },
    { "mem-set", &main_memset },
    { "button-press", &main_button_press },
    { "vcpu-list", &main_vcpulist },
    { "vcpu-pin", &main_vcpupin },
    { "vcpu-set", &main_vcpuset },
    { "list-vm", &main_list_vm },
    { "info", &main_info },
    { "sched-credit", &main_sched_credit },
};

int cmdtable_len = sizeof(cmd_table)/sizeof(struct cmd_spec);
