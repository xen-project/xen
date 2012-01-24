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
      &main_create, 1,
      "Create a domain from config file <filename>",
      "<ConfigFile> [options] [vars]",
      "-h                      Print this help.\n"
      "-p                      Leave the domain paused after it is created.\n"
      "-c                      Connect to the console after the domain is created.\n"
      "-f=FILE, --defconfig=FILE\n                     Use the given configuration file.\n"
      "-q, --quiet             Quiet.\n"
      "-n, --dryrun            Dry run - prints the resulting configuration\n"
      "                         (deprecated in favour of global -N option).\n"
      "-d                      Enable debug messages.\n"
      "-e                      Do not wait in the background for the death of the domain."
    },
    { "list",
      &main_list, 0,
      "List information about all/some domains",
      "[options] [Domain]\n",
      "-l, --long              Output all VM details\n"
      "-v, --verbose           Prints out UUIDs and security context\n"
      "-Z, --context           Prints out security context"
    },
    { "destroy",
      &main_destroy, 0,
      "Terminate a domain immediately",
      "<Domain>",
    },
    { "shutdown",
      &main_shutdown, 0,
      "Issue a shutdown signal to a domain",
      "<Domain>",
    },
    { "reboot",
      &main_reboot, 0,
      "Issue a reboot signal to a domain",
      "<Domain>",
    },
    { "pci-attach",
      &main_pciattach, 0,
      "Insert a new pass-through pci device",
      "<Domain> <BDF> [Virtual Slot]",
    },
    { "pci-detach",
      &main_pcidetach, 0,
      "Remove a domain's pass-through pci device",
      "<Domain> <BDF>",
    },
    { "pci-list",
      &main_pcilist, 0,
      "List pass-through pci devices for a domain",
      "<Domain>",
    },
    { "pci-list-assignable-devices",
      &main_pcilist_assignable, 0,
      "List all the assignable pci devices",
      "",
    },
    { "pause",
      &main_pause, 0,
      "Pause execution of a domain",
      "<Domain>",
    },
    { "unpause",
      &main_unpause, 0,
      "Unpause a paused domain",
      "<Domain>",
    },
    { "console",
      &main_console, 0,
      "Attach to domain's console",
      "[options] <Domain>\n"
      "-t <type>       console type, pv or serial\n"
      "-n <number>     console number"
    },
    { "vncviewer",
      &main_vncviewer, 0,
      "Attach to domain's VNC server.",
      "[options] <Domain>\n"
      "--autopass               Pass VNC password to viewer via stdin and\n"
      "                         -autopass\n"
      "--vncviewer-autopass     (consistency alias for --autopass)"
    },
    { "save",
      &main_save, 0,
      "Save a domain state to restore later",
      "[options] <Domain> <CheckpointFile> [<ConfigFile>]",
      "-h  Print this help.\n"
      "-c  Leave domain running after creating the snapshot."
    },
    { "migrate",
      &main_migrate, 0,
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
      &main_dump_core, 0,
      "Core dump a domain",
      "<Domain> <filename>"
    },
    { "restore",
      &main_restore, 0,
      "Restore a domain from a saved state",
      "[options] [<ConfigFile>] <CheckpointFile>",
      "-h  Print this help.\n"
      "-p  Do not unpause domain after restoring it.\n"
      "-e  Do not wait in the background for the death of the domain.\n"
      "-d  Enable debug messages."
    },
    { "migrate-receive",
      &main_migrate_receive, 0,
      "Restore a domain from a saved state",
      "- for internal use only",
    },
    { "cd-insert",
      &main_cd_insert, 0,
      "Insert a cdrom into a guest's cd drive",
      "<Domain> <VirtualDevice> <type:path>",
    },
    { "cd-eject",
      &main_cd_eject, 0,
      "Eject a cdrom from a guest's cd drive",
      "<Domain> <VirtualDevice>",
    },
    { "mem-max",
      &main_memmax, 0,
      "Set the maximum amount reservation for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
    },
    { "mem-set",
      &main_memset, 0,
      "Set the current memory usage for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
    },
    { "button-press",
      &main_button_press, 0,
      "Indicate an ACPI button press to the domain",
      "<Domain> <Button>",
      "<Button> may be 'power' or 'sleep'."
    },
    { "vcpu-list",
      &main_vcpulist, 0,
      "List the VCPUs for all/some domains",
      "[Domain, ...]",
    },
    { "vcpu-pin",
      &main_vcpupin, 0,
      "Set which CPUs a VCPU can use",
      "<Domain> <VCPU|all> <CPUs|all>",
    },
    { "vcpu-set",
      &main_vcpuset, 0,
      "Set the number of active VCPUs allowed for the domain",
      "<Domain> <vCPUs>",
    },
    { "list-vm",
      &main_list_vm, 0,
      "List the VMs,without DOM0",
      "",
    },
    { "info",
      &main_info, 0,
      "Get information about Xen host",
      "-n, --numa         List host NUMA topology information",
    },
    { "sched-credit",
      &main_sched_credit, 0,
      "Get/set credit scheduler parameters",
      "[-d <Domain> [-w[=WEIGHT]|-c[=CAP]]] [-p CPUPOOL]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-w WEIGHT, --weight=WEIGHT     Weight (int)\n"
      "-c CAP, --cap=CAP              Cap (int)\n"
      "-p CPUPOOL, --cpupool=CPUPOOL  Restrict output to CPUPOOL"
    },
    { "sched-credit2",
      &main_sched_credit2, 0,
      "Get/set credit2 scheduler parameters",
      "[-d <Domain> [-w[=WEIGHT]]] [-p CPUPOOL]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-w WEIGHT, --weight=WEIGHT     Weight (int)\n"
      "-p CPUPOOL, --cpupool=CPUPOOL  Restrict output to CPUPOOL"
    },
    { "sched-sedf",
      &main_sched_sedf, 0,
      "Get/set sedf scheduler parameters",
      "[options]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-p MS, --period=MS             Relative deadline(ms)\n"
      "-s MS, --slice=MS              Worst-case execution time(ms).\n"
      "                               (slice < period)\n"
      "-l MS, --latency=MS            Scaled period (ms) when domain\n"
      "                               performs heavy I/O\n"
      "-e FLAG, --extra=FLAG          Flag (0 or 1) controls if domain\n"
      "                               can run in extra time\n"
      "-w FLOAT, --weight=FLOAT       CPU Period/slice (do not set with\n"
      "                               --period/--slice)\n"
      "-c CPUPOOL, --cpupool=CPUPOOL  Restrict output to CPUPOOL"
    },
    { "domid",
      &main_domid, 0,
      "Convert a domain name to domain id",
      "<DomainName>",
    },
    { "domname",
      &main_domname, 0,
      "Convert a domain id to domain name",
      "<DomainId>",
    },
    { "rename",
      &main_rename, 0,
      "Rename a domain",
      "<Domain> <NewDomainName>",
    },
    { "trigger",
      &main_trigger, 0,
      "Send a trigger to a domain",
      "<Domain> <nmi|reset|init|power|sleep|s3resume> [<VCPU>]",
    },
    { "sysrq",
      &main_sysrq, 0,
      "Send a sysrq to a domain",
      "<Domain> <letter>",
    },
    { "debug-keys",
      &main_debug_keys, 0,
      "Send debug keys to Xen",
      "<Keys>",
    },
    { "dmesg",
      &main_dmesg, 0,
      "Read and/or clear dmesg buffer",
      "[-c]",
      "  -c                        Clear dmesg buffer as well as printing it",
    },
    { "top",
      &main_top, 0,
      "Monitor a host and the domains in real time",
      "",
    },
    { "network-attach",
      &main_networkattach, 0,
      "Create a new virtual network device",
      "<Domain> [type=<type>] [mac=<mac>] [bridge=<bridge>] "
      "[ip=<ip>] [script=<script>] [backend=<BackDomain>] [vifname=<name>] "
      "[rate=<rate>] [model=<model>] [accel=<accel>]",
    },
    { "network-list",
      &main_networklist, 0,
      "List virtual network interfaces for a domain",
      "<Domain(s)>",
    },
    { "network-detach",
      &main_networkdetach, 0,
      "Destroy a domain's virtual network device",
      "<Domain> <DevId|mac>",
    },
    { "block-attach",
      &main_blockattach, 1,
      "Create a new virtual block device",
      "<Domain> <disk-spec-component(s)>...",
    },
    { "block-list",
      &main_blocklist, 0,
      "List virtual block devices for a domain",
      "<Domain(s)>",
    },
    { "block-detach",
      &main_blockdetach, 0,
      "Destroy a domain's virtual block device",
      "<Domain> <DevId>",
    },
    { "uptime",
      &main_uptime, 0,
      "Print uptime for all/some domains",
      "[-s] [Domain]",
    },
    { "tmem-list",
      &main_tmem_list, 0,
      "List tmem pools",
      "[-l] [<Domain>|-a]",
      "  -l                             List tmem stats",
    },
    { "tmem-freeze",
      &main_tmem_freeze, 0,
      "Freeze tmem pools",
      "[<Domain>|-a]",
      "  -a                             Freeze all tmem",
    },
    { "tmem-destroy",
      &main_tmem_destroy, 0,
      "Destroy tmem pools",
      "[<Domain>|-a]",
      "  -a                             Destroy all tmem",
    },
    { "tmem-thaw",
      &main_tmem_thaw, 0,
      "Thaw tmem pools",
      "[<Domain>|-a]",
      "  -a                             Thaw all tmem",
    },
    { "tmem-set",
      &main_tmem_set, 0,
      "Change tmem settings",
      "[<Domain>|-a] [-w[=WEIGHT]|-c[=CAP]|-p[=COMPRESS]]",
      "  -a                             Operate on all tmem\n"
      "  -w WEIGHT                      Weight (int)\n"
      "  -c CAP                         Cap (int)\n"
      "  -p COMPRESS                    Compress (int)",
    },
    { "tmem-shared-auth",
      &main_tmem_shared_auth, 0,
      "De/authenticate shared tmem pool",
      "[<Domain>|-a] [-u[=UUID] [-A[=AUTH]",
      "  -a                             Authenticate for all tmem pools\n"
      "  -u UUID                        Specify uuid\n"
      "                                 (abcdef01-2345-6789-1234-567890abcdef)\n"
      "  -A AUTH                        0=auth,1=deauth",
    },
    { "tmem-freeable",
      &main_tmem_freeable, 0,
      "Get information about how much freeable memory (MB) is in-use by tmem",
      "",
    },
    { "cpupool-create",
      &main_cpupoolcreate, 1,
      "Create a CPU pool based an ConfigFile",
      "[options] <ConfigFile> [vars]",
      "-h, --help                   Print this help.\n"
      "-f=FILE, --defconfig=FILE    Use the given configuration file.\n"
      "-n, --dryrun                 Dry run - prints the resulting configuration.\n"
      "                              (deprecated in favour of global -N option)."
    },
    { "cpupool-list",
      &main_cpupoollist, 0,
      "List CPU pools on host",
      "[-c|--cpus] [<CPU Pool>]",
      "-c, --cpus                     Output list of CPUs used by a pool"
    },
    { "cpupool-destroy",
      &main_cpupooldestroy, 0,
      "Deactivates a CPU pool",
      "<CPU Pool>",
    },
    { "cpupool-rename",
      &main_cpupoolrename, 0,
      "Renames a CPU pool",
      "<CPU Pool> <new name>",
    },
    { "cpupool-cpu-add",
      &main_cpupoolcpuadd, 0,
      "Adds a CPU to a CPU pool",
      "<CPU Pool> <CPU nr>|node:<node nr>",
    },
    { "cpupool-cpu-remove",
      &main_cpupoolcpuremove, 0,
      "Removes a CPU from a CPU pool",
      "<CPU Pool> <CPU nr>|node:<node nr>",
    },
    { "cpupool-migrate",
      &main_cpupoolmigrate, 0,
      "Moves a domain into a CPU pool",
      "<Domain> <CPU Pool>",
    },
    { "cpupool-numa-split",
      &main_cpupoolnumasplit, 0,
      "Splits up the machine into one CPU pool per NUMA node",
      "",
    },
    { "getenforce",
      &main_getenforce, 0,
      "Returns the current enforcing mode of the Flask Xen security module",
      "",
    },
    { "setenforce",
      &main_setenforce, 0,
      "Sets the current enforcing mode of the Flask Xen security module",
      "<1|0|Enforcing|Permissive>",
    },
    { "loadpolicy",
      &main_loadpolicy, 0,
      "Loads a new policy int the Flask Xen security module",
      "<policy file>",
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

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
