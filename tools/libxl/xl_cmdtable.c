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

#include <string.h>

#include "libxl.h"
#include "xl.h"

struct cmd_spec cmd_table[] = {
    { "create",
      &main_create,
      "Create a domain from config file <filename>",
      "<ConfigFile> [options] [vars]",
      "-h                      Print this help.\n"
      "-p                      Leave the domain paused after it is created.\n"
      "-c                      Connect to the console after the domain is created.\n"
      "-d                      Enable debug messages.\n"
      "-f=FILE, --defconfig=FILE\n                     Use the given configuration file.\n"
      "-q, --quiet             Quiet.\n"
      "-n, --dryrun            Dry run - prints the resulting configuration.\n"
      "-d                      Enable debug messages.\n"
      "-e                      Do not wait in the background for the death of the domain."
    },
    { "list",
      &main_list,
      "List information about all/some domains",
      "[options] [Domain]\n",
      "-l, --long                              Output all VM details"
      "-v, --verbose                   Prints out UUIDs",
    },
    { "destroy",
      &main_destroy,
      "Terminate a domain immediately",
      "<Domain>",
    },
    { "shutdown",
      &main_shutdown,
      "Issue a shutdown signal to a domain",
      "<Domain>",
    },
    { "reboot",
      &main_reboot,
      "Issue a reboot signal to a domain",
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
    { "pci-list-assignable-devices",
      &main_pcilist_assignable,
      "List all the assignable pci devices",
      "",
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
    { "vncviewer",
      &main_vncviewer,
      "Attach to domain's VNC server.",
      "[options] <Domain>\n"
      "--autopass               Pass VNC password to viewer via stdin and\n"
      "                         -autopass\n"
      "--vncviewer-autopass     (consistency alias for --autopass)"
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
    { "dump-core",
      &main_dump_core,
      "Core dump a domain",
      "<Domain> <filename>"
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
    { "mem-max",
      &main_memmax,
      "Set the maximum amount reservation for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
    },
    { "mem-set",
      &main_memset,
      "Set the current memory usage for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
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
    { "sysrq",
      &main_sysrq,
      "Send a sysrq to a domain",
      "<Domain> <letter>",
    },
    { "debug-keys",
      &main_debug_keys,
      "Send debug keys to Xen",
      "<Keys>",
    },
    { "dmesg",
      &main_dmesg,
      "Read and/or clear dmesg buffer",
      "[-c]",
      "  -c                        Clear dmesg buffer as well as printing it",
    },
    { "top",
      &main_top,
      "Monitor a host and the domains in real time",
      "",
    },
    { "network-attach",
      &main_networkattach,
      "Create a new virtual network device",
      "<Domain> [type=<type>] [mac=<mac>] [bridge=<bridge>] "
      "[ip=<ip>] [script=<script>] [backend=<BackDomain>] [vifname=<name>] "
      "[rate=<rate>] [model=<model>][accel=<accel>]",
    },
    { "network-list",
      &main_networklist,
      "List virtual network interfaces for a domain",
      "<Domain(s)>",
    },
    { "network-detach",
      &main_networkdetach,
      "Destroy a domain's virtual network device",
      "<Domain> <DevId|mac>",
    },
    { "block-attach",
      &main_blockattach,
      "Create a new virtual block device",
      "<Domain> <BackDev> <FrontDev> [<Mode>] [BackDomain]",
    },
    { "block-list",
      &main_blocklist,
      "List virtual block devices for a domain",
      "<Domain(s)>",
    },
    { "block-detach",
      &main_blockdetach,
      "Destroy a domain's virtual block device",
      "<Domain> <DevId>",
    },
    { "uptime",
      &main_uptime,
      "Print uptime for all/some domains",
      "[-s] [Domain]",
    },
    { "tmem-list",
      &main_tmem_list,
      "List tmem pools",
      "[-l] [<Domain>|-a]",
      "  -l                             List tmem stats",
    },
    { "tmem-freeze",
      &main_tmem_freeze,
      "Freeze tmem pools",
      "[<Domain>|-a]",
      "  -a                             Freeze all tmem",
    },
    { "tmem-destroy",
      &main_tmem_destroy,
      "Destroy tmem pools",
      "[<Domain>|-a]",
      "  -a                             Destroy all tmem",
    },
    { "tmem-thaw",
      &main_tmem_thaw,
      "Thaw tmem pools",
      "[<Domain>|-a]",
      "  -a                             Thaw all tmem",
    },
    { "tmem-set",
      &main_tmem_set,
      "Change tmem settings",
      "[<Domain>|-a] [-w[=WEIGHT]|-c[=CAP]|-p[=COMPRESS]]",
      "  -a                             Operate on all tmem\n"
      "  -w WEIGHT                      Weight (int)\n"
      "  -c CAP                         Cap (int)\n"
      "  -p COMPRESS                    Compress (int)",
    },
    { "tmem-shared-auth",
      &main_tmem_shared_auth,
      "De/authenticate shared tmem pool",
      "[<Domain>|-a] [-u[=UUID] [-A[=AUTH]",
      "  -a                             Authenticate for all tmem pools\n"
      "  -u UUID                        Specify uuid\n"
      "                                 (abcdef01-2345-6789-1234-567890abcdef)\n"
      "  -A AUTH                        0=auth,1=deauth",
    },
    { "tmem-freeable",
      &main_tmem_freeable,
      "Get information about how much freeable memory (MB) is in-use by tmem",
      "",
    },
    { "network2-attach",
      &main_network2attach,
      "Create a new version 2 virtual network device",
      "<Domain> [front_mac=<mac>] [back_mac=<mac>] [backend=<BackDomain>]"
      " [trusted=<0|1>] [back_trusted=<0|1>] [bridge=<bridge>]"
      " [filter_mac=<0|1>] [front_filter_mac=<0|1>] [pdev=<PDEV>]"
      " [max_bypasses=n]",
    },
    { "network2-list",
      &main_network2list,
      "list version 2 virtual network interfaces for a domain",
      "<Domain(s)>",
    },
    { "network2-detach",
      &main_network2detach,
      "destroy a domain's version 2 virtual network device",
      "<Domain> <DevId>",
    },
};

int cmdtable_len = sizeof(cmd_table)/sizeof(struct cmd_spec);

/* Look up a command in the table, allowing unambiguous truncation */
struct cmd_spec *cmdtable_lookup(const char *s)
{
    struct cmd_spec *cmd = NULL;
    size_t len;
    int i, count = 0;

    if (!s) 
        return NULL;
    len = strlen(s);
    for (i = 0; i < cmdtable_len; i++) {
        if (!strncmp(s, cmd_table[i].cmd_name, len)) {
            cmd = &cmd_table[i];
            /* Take an exact match, even if it also prefixes another command */
            if (len == strlen(cmd->cmd_name))
                return cmd;
            count++;
        }
    }
    return (count == 1) ? cmd : NULL;
}
