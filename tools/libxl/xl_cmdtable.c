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
    { "create",
      &main_create,
      "Create a domain from config file <filename>",
      "<ConfigFile> [options] [vars]",
      "-h  Print this help.\n"
      "-p  Leave the domain paused after it is created.\n"
      "-c  Connect to the console after the domain is created.\n"
      "-d  Enable debug messages.\n"
      "-e  Do not wait in the background for the death of the domain."
    },
    { "list",
      &main_list,
      "List information about all/some domains",
      "[-v] [Domain]",
    },
    { "destroy",
      &main_destroy,
      "Terminate a domain immediately",
      "<Domain>",
    },
    { "pci-attach",
      &main_pciattach,
      "Insert a new pass-through pci device",
      "<Domain> <BDF> [Virtual Slot]",
    },
    { "pci-detach",
      &main_pcidetach,
      "Remove a domain's pass-through pci device",
      "<Domain> <BDF>",
    },
    { "pci-list",
      &main_pcilist,
      "List pass-through pci devices for a domain",
      "<Domain>",
    },
    { "pause",
      &main_pause,
      "Pause execution of a domain",
      "<Domain>",
    },
    { "unpause",
      &main_unpause,
      "Unpause a paused domain",
      "<Domain>",
    },
    { "console",
      &main_console,
      "Attach to domain's console",
      "<Domain>",
    },
    { "save",
      &main_save,
      "Save a domain state to restore later",
      "[options] <Domain> <CheckpointFile> [<ConfigFile>]",
      "-h  Print this help.\n"
      "-c  Leave domain running after creating the snapshot."
    },
    { "migrate",
      &main_migrate,
      "Save a domain state to restore later",
      "[options] <Domain> <host>",
      "-h              Print this help.\n"
      "-C <config>     Send <config> instead of config file from creation.\n"
      "-s <sshcommand> Use <sshcommand> instead of ssh.  String will be passed\n"
      "                to sh. If empty, run <host> instead of ssh <host> xl\n"
      "                migrate-receive [-d -e]\n"
      "-e              Do not wait in the background (on <host>) for the death\n"
      "                of the domain."
    },
    { "restore",
      &main_restore,
      "Restore a domain from a saved state",
      "[options] [<ConfigFile>] <CheckpointFile>",
      "-h  Print this help.\n"
      "-p  Do not unpause domain after restoring it.\n"
      "-e  Do not wait in the background for the death of the domain.\n"
      "-d  Enable debug messages."
    },
    { "migrate-receive",
      &main_migrate_receive,
      "Restore a domain from a saved state",
      "- for internal use only",
    },
    { "cd-insert",
      &main_cd_insert,
      "Insert a cdrom into a guest's cd drive",
      "<Domain> <VirtualDevice> <type:path>",
    },
    { "cd-eject",
      &main_cd_eject,
      "Eject a cdrom from a guest's cd drive",
      "<Domain> <VirtualDevice>",
    },
    { "mem-set",
      &main_memset,
      "Set the current memory usage for a domain",
      "<Domain> <MemKB>",
    },
    { "button-press",
      &main_button_press,
      "Indicate an ACPI button press to the domain",
      "<Domain> <Button>",
      "<Button> may be 'power' or 'sleep'."
    },
    { "vcpu-list",
      &main_vcpulist,
      "List the VCPUs for all/some domains",
      "[Domain, ...]",
    },
    { "vcpu-pin",
      &main_vcpupin,
      "Set which CPUs a VCPU can use",
      "<Domain> <VCPU|all> <CPUs|all>",
    },
    { "vcpu-set",
      &main_vcpuset,
      "Set the number of active VCPUs allowed for the domain",
      "<Domain> <vCPUs>",
    },
    { "list-vm",
      &main_list_vm,
      "List the VMs,without DOM0",
      "",
    },
    { "info",
      &main_info,
      "Get information about Xen host",
      "",
    },
    { "sched-credit",
      &main_sched_credit,
      "Get/set credit scheduler parameters",
      "[-d <Domain> [-w[=WEIGHT]|-c[=CAP]]]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-w WEIGHT, --weight=WEIGHT     Weight (int)\n"
      "-c CAP, --cap=CAP              Cap (int)"
    },
    { "domid",
      &main_domid,
      "Convert a domain name to domain id",
      "<DomainName>",
    },
    { "domname",
      &main_domname,
      "Convert a domain id to domain name",
      "<DomainId>",
    },
    { "rename",
      &main_rename,
      "Rename a domain",
      "<Domain> <NewDomainName>",
    },
    { "trigger",
      &main_trigger,
      "Send a trigger to a domain",
      "<Domain> <nmi|reset|init|power|sleep> [<VCPU>]",
    },
};

int cmdtable_len = sizeof(cmd_table)/sizeof(struct cmd_spec);
