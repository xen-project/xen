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
      &main_create, 1, 1,
      "Create a domain from config file <filename>",
      "<ConfigFile> [options] [vars]",
      "-h                      Print this help.\n"
      "-p                      Leave the domain paused after it is created.\n"
      "-c                      Connect to the console after the domain is created.\n"
      "-f FILE, --defconfig=FILE\n                     Use the given configuration file.\n"
      "-q, --quiet             Quiet.\n"
      "-n, --dryrun            Dry run - prints the resulting configuration\n"
      "                         (deprecated in favour of global -N option).\n"
      "-d                      Enable debug messages.\n"
      "-F                      Run in foreground until death of the domain.\n"
      "-e                      Do not wait in the background for the death of the domain.\n"
      "-V, --vncviewer         Connect to the VNC display after the domain is created.\n"
      "-A, --vncviewer-autopass\n"
      "                        Pass VNC password to viewer via stdin."
    },
    { "config-update",
      &main_config_update, 1, 1,
      "Update a running domain's saved configuration, used when rebuilding "
      "the domain after reboot.\n"
      "WARNING: xl now has better capability to manage domain configuration, "
      "avoid using this command when possible",
      "<Domain> <ConfigFile> [options] [vars]",
      "-h                      Print this help.\n"
      "-f FILE, --defconfig=FILE\n                     Use the given configuration file.\n"
      "-d                      Enable debug messages.\n"
    },
    { "list",
      &main_list, 0, 0,
      "List information about all/some domains",
      "[options] [Domain]\n",
      "-l, --long              Output all VM details\n"
      "-v, --verbose           Prints out UUIDs and security context\n"
      "-Z, --context           Prints out security context\n"
      "-c, --cpupool           Prints the cpupool the domain is in\n"
      "-n, --numa              Prints out NUMA node affinity"
    },
    { "destroy",
      &main_destroy, 0, 1,
      "Terminate a domain immediately",
      "[options] <Domain>\n",
      "-f                      Permit destroying domain 0, which will only succeed\n"
      "                        when run from disaggregated toolstack domain with a\n"
      "                        hardware domain distinct from domain 0."
    },
    { "shutdown",
      &main_shutdown, 0, 1,
      "Issue a shutdown signal to a domain",
      "[options] <-a|Domain>",
      "-a, --all               Shutdown all guest domains.\n"
      "-h                      Print this help.\n"
      "-F                      Fallback to ACPI power event for HVM guests with\n"
      "                        no PV drivers.\n"
      "-w, --wait              Wait for guest(s) to shutdown.\n"
    },
    { "reboot",
      &main_reboot, 0, 1,
      "Issue a reboot signal to a domain",
      "[options] <-a|Domain>",
      "-a, --all               Shutdown all guest domains.\n"
      "-h                      Print this help.\n"
      "-F                      Fallback to ACPI reset event for HVM guests with\n"
      "                        no PV drivers.\n"
      "-w, --wait              Wait for guest(s) to reboot.\n"
    },
    { "pci-attach",
      &main_pciattach, 0, 1,
      "Insert a new pass-through pci device",
      "<Domain> <BDF> [Virtual Slot]",
    },
    { "pci-detach",
      &main_pcidetach, 0, 1,
      "Remove a domain's pass-through pci device",
      "<Domain> <BDF>",
    },
    { "pci-list",
      &main_pcilist, 0, 0,
      "List pass-through pci devices for a domain",
      "<Domain>",
    },
    { "pci-assignable-add",
      &main_pciassignable_add, 0, 1,
      "Make a device assignable for pci-passthru",
      "<BDF>",
      "-h                      Print this help.\n"
    },
    { "pci-assignable-remove",
      &main_pciassignable_remove, 0, 1,
      "Remove a device from being assignable",
      "[options] <BDF>",
      "-h                      Print this help.\n"
      "-r                      Attempt to re-assign the device to the\n"
      "                        original driver"
    },
    { "pci-assignable-list",
      &main_pciassignable_list, 0, 0,
      "List all the assignable pci devices",
      "",
    },
    { "pause",
      &main_pause, 0, 1,
      "Pause execution of a domain",
      "<Domain>",
    },
    { "unpause",
      &main_unpause, 0, 1,
      "Unpause a paused domain",
      "<Domain>",
    },
    { "console",
      &main_console, 0, 0,
      "Attach to domain's console",
      "[options] <Domain>\n"
      "-t <type>       console type, pv or serial\n"
      "-n <number>     console number"
    },
    { "vncviewer",
      &main_vncviewer, 0, 0,
      "Attach to domain's VNC server.",
      "[options] <Domain>\n"
      "--autopass               Pass VNC password to viewer via stdin and\n"
      "                         -autopass\n"
      "--vncviewer-autopass     (consistency alias for --autopass)"
    },
#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
    { "save",
      &main_save, 0, 1,
      "Save a domain state to restore later",
      "[options] <Domain> <CheckpointFile> [<ConfigFile>]",
      "-h  Print this help.\n"
      "-c  Leave domain running after creating the snapshot.\n"
      "-p  Leave domain paused after creating the snapshot."
    },
    { "migrate",
      &main_migrate, 0, 1,
      "Migrate a domain to another host",
      "[options] <Domain> <host>",
      "-h              Print this help.\n"
      "-C <config>     Send <config> instead of config file from creation.\n"
      "-s <sshcommand> Use <sshcommand> instead of ssh.  String will be passed\n"
      "                to sh. If empty, run <host> instead of ssh <host> xl\n"
      "                migrate-receive [-d -e]\n"
      "-e              Do not wait in the background (on <host>) for the death\n"
      "                of the domain.\n"
      "--debug         Print huge (!) amount of debug during the migration process.\n"
      "-p              Do not unpause domain after migrating it."
    },
    { "restore",
      &main_restore, 0, 1,
      "Restore a domain from a saved state",
      "[options] [<ConfigFile>] <CheckpointFile>",
      "-h                       Print this help.\n"
      "-p                       Do not unpause domain after restoring it.\n"
      "-e                       Do not wait in the background for the death of the domain.\n"
      "-d                       Enable debug messages.\n"
      "-V, --vncviewer          Connect to the VNC display after the domain is created.\n"
      "-A, --vncviewer-autopass Pass VNC password to viewer via stdin."
    },
    { "migrate-receive",
      &main_migrate_receive, 0, 1,
      "Restore a domain from a saved state",
      "- for internal use only",
    },
#endif
    { "dump-core",
      &main_dump_core, 0, 1,
      "Core dump a domain",
      "<Domain> <filename>"
    },
    { "cd-insert",
      &main_cd_insert, 1, 1,
      "Insert a cdrom into a guest's cd drive",
      "<Domain> <VirtualDevice> <path>",
    },
    { "cd-eject",
      &main_cd_eject, 1, 1,
      "Eject a cdrom from a guest's cd drive",
      "<Domain> <VirtualDevice>",
    },
    { "mem-max",
      &main_memmax, 0, 1,
      "Set the maximum amount reservation for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
    },
    { "mem-set",
      &main_memset, 0, 1,
      "Set the current memory usage for a domain",
      "<Domain> <MemMB['b'[bytes]|'k'[KB]|'m'[MB]|'g'[GB]|'t'[TB]]>",
    },
    { "button-press",
      &main_button_press, 0, 1,
      "Indicate an ACPI button press to the domain",
      "<Domain> <Button>",
      "<Button> may be 'power' or 'sleep'."
    },
    { "vcpu-list",
      &main_vcpulist, 0, 0,
      "List the VCPUs for all/some domains",
      "[Domain, ...]",
    },
    { "vcpu-pin",
      &main_vcpupin, 1, 1,
      "Set which CPUs a VCPU can use",
      "[option] <Domain> <VCPU|all> <Hard affinity|-|all> <Soft affinity|-|all>",
      "-f, --force        undo an override pinning done by the kernel",
    },
    { "vcpu-set",
      &main_vcpuset, 0, 1,
      "Set the number of active VCPUs allowed for the domain",
      "[option] <Domain> <vCPUs>",
      "-i, --ignore-host  Don't limit the vCPU based on the host CPU count",
    },
    { "vm-list",
      &main_vm_list, 0, 0,
      "List guest domains, excluding dom0, stubdoms, etc.",
      "",
    },
    { "info",
      &main_info, 0, 0,
      "Get information about Xen host",
      "-n, --numa         List host NUMA topology information",
    },
    { "sharing",
      &main_sharing, 0, 0,
      "Get information about page sharing",
      "[Domain]", 
    },
    { "sched-credit",
      &main_sched_credit, 0, 1,
      "Get/set credit scheduler parameters",
      "[-d <Domain> [-w[=WEIGHT]|-c[=CAP]]] [-s [-t TSLICE] [-r RATELIMIT]] [-p CPUPOOL]",
      "-d DOMAIN, --domain=DOMAIN        Domain to modify\n"
      "-w WEIGHT, --weight=WEIGHT        Weight (int)\n"
      "-c CAP, --cap=CAP                 Cap (int)\n"
      "-s         --schedparam           Query / modify scheduler parameters\n"
      "-t TSLICE, --tslice_ms=TSLICE     Set the timeslice, in milliseconds\n"
      "-r RLIMIT, --ratelimit_us=RLIMIT  Set the scheduling rate limit, in microseconds\n"
      "-p CPUPOOL, --cpupool=CPUPOOL     Restrict output to CPUPOOL"
    },
    { "sched-credit2",
      &main_sched_credit2, 0, 1,
      "Get/set credit2 scheduler parameters",
      "[-d <Domain> [-w[=WEIGHT]]] [-p CPUPOOL]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-w WEIGHT, --weight=WEIGHT     Weight (int)\n"
      "-s         --schedparam        Query / modify scheduler parameters\n"
      "-r RLIMIT, --ratelimit_us=RLIMIT Set the scheduling rate limit, in microseconds\n"
      "-p CPUPOOL, --cpupool=CPUPOOL  Restrict output to CPUPOOL"
    },
    { "sched-rtds",
      &main_sched_rtds, 0, 1,
      "Get/set rtds scheduler parameters",
      "[-d <Domain> [-v[=VCPUID/all]] [-p[=PERIOD]] [-b[=BUDGET]]]",
      "-d DOMAIN, --domain=DOMAIN     Domain to modify\n"
      "-v VCPUID/all, --vcpuid=VCPUID/all    VCPU to modify or output;\n"
      "               Using '-v all' to modify/output all vcpus\n"
      "-p PERIOD, --period=PERIOD     Period (us)\n"
      "-b BUDGET, --budget=BUDGET     Budget (us)\n"
    },
    { "domid",
      &main_domid, 0, 0,
      "Convert a domain name to domain id",
      "<DomainName>",
    },
    { "domname",
      &main_domname, 0, 0,
      "Convert a domain id to domain name",
      "<DomainId>",
    },
    { "rename",
      &main_rename, 0, 1,
      "Rename a domain",
      "<Domain> <NewDomainName>",
    },
    { "trigger",
      &main_trigger, 0, 1,
      "Send a trigger to a domain",
      "<Domain> <nmi|reset|init|power|sleep|s3resume> [<VCPU>]",
    },
    { "sysrq",
      &main_sysrq, 0, 1,
      "Send a sysrq to a domain",
      "<Domain> <letter>",
    },
    { "debug-keys",
      &main_debug_keys, 0, 1,
      "Send debug keys to Xen",
      "<Keys>",
    },
    { "dmesg",
      &main_dmesg, 0, 0,
      "Read and/or clear dmesg buffer",
      "[-c]",
      "  -c                        Clear dmesg buffer as well as printing it",
    },
    { "top",
      &main_top, 0, 0,
      "Monitor a host and the domains in real time",
      "",
    },
    { "network-attach",
      &main_networkattach, 1, 1,
      "Create a new virtual network device",
      "<Domain> [type=<type>] [mac=<mac>] [bridge=<bridge>] "
      "[ip=<ip>] [script=<script>] [backend=<BackDomain>] [vifname=<name>] "
      "[rate=<rate>] [model=<model>] [accel=<accel>]",
    },
    { "network-list",
      &main_networklist, 0, 0,
      "List virtual network interfaces for a domain",
      "<Domain(s)>",
    },
    { "network-detach",
      &main_networkdetach, 0, 1,
      "Destroy a domain's virtual network device",
      "<Domain> <DevId|mac>",
    },
    { "channel-list",
      &main_channellist, 0, 0,
      "List virtual channel devices for a domain",
      "<Domain(s)>",
    },
    { "block-attach",
      &main_blockattach, 1, 1,
      "Create a new virtual block device",
      "<Domain> <disk-spec-component(s)>...",
    },
    { "block-list",
      &main_blocklist, 0, 0,
      "List virtual block devices for a domain",
      "<Domain(s)>",
    },
    { "block-detach",
      &main_blockdetach, 0, 1,
      "Destroy a domain's virtual block device",
      "<Domain> <DevId>",
    },
    { "vtpm-attach",
      &main_vtpmattach, 1, 1,
      "Create a new virtual TPM device",
      "<Domain> [uuid=<uuid>] [backend=<BackDomain>]",
    },
    { "vtpm-list",
      &main_vtpmlist, 0, 0,
      "List virtual TPM devices for a domain",
      "<Domain(s)>",
    },
    { "vtpm-detach",
      &main_vtpmdetach, 0, 1,
      "Destroy a domain's virtual TPM device",
      "<Domain> <DevId|uuid>",
    },
    { "uptime",
      &main_uptime, 0, 0,
      "Print uptime for all/some domains",
      "[-s] [Domain]",
    },
    { "claims",
      &main_claims, 0, 0,
      "List outstanding claim information about all domains",
      "",
      "",
    },
    { "tmem-list",
      &main_tmem_list, 0, 0,
      "List tmem pools",
      "[-l] [<Domain>|-a]",
      "  -l                             List tmem stats",
    },
    { "tmem-freeze",
      &main_tmem_freeze, 0, 1,
      "Freeze tmem pools",
      "[<Domain>|-a]",
      "  -a                             Freeze all tmem",
    },
    { "tmem-thaw",
      &main_tmem_thaw, 0, 1,
      "Thaw tmem pools",
      "[<Domain>|-a]",
      "  -a                             Thaw all tmem",
    },
    { "tmem-set",
      &main_tmem_set, 0, 1,
      "Change tmem settings",
      "[<Domain>|-a] [-w[=WEIGHT]|-c[=CAP]|-p[=COMPRESS]]",
      "  -a                             Operate on all tmem\n"
      "  -w WEIGHT                      Weight (int)\n"
      "  -p COMPRESS                    Compress (int)",
    },
    { "tmem-shared-auth",
      &main_tmem_shared_auth, 0, 1,
      "De/authenticate shared tmem pool",
      "[<Domain>|-a] [-u[=UUID] [-A[=AUTH]",
      "  -a                             Authenticate for all tmem pools\n"
      "  -u UUID                        Specify uuid\n"
      "                                 (abcdef01-2345-6789-1234-567890abcdef)\n"
      "  -A AUTH                        0=auth,1=deauth",
    },
    { "tmem-freeable",
      &main_tmem_freeable, 0, 0,
      "Get information about how much freeable memory (MB) is in-use by tmem",
      "",
    },
    { "cpupool-create",
      &main_cpupoolcreate, 1, 1,
      "Create a new CPU pool",
      "[options] [<ConfigFile>] [Variable=value ...]",
      "-h, --help                   Print this help.\n"
      "-f FILE, --defconfig=FILE    Use the given configuration file.\n"
      "-n, --dryrun                 Dry run - prints the resulting configuration.\n"
      "                              (deprecated in favour of global -N option).\n"
      "\nSee the xlcpupool.cfg(5) manpage for more information.",

    },
    { "cpupool-list",
      &main_cpupoollist, 0, 0,
      "List CPU pools on host",
      "[-c|--cpus] [<CPU Pool>]",
      "-c, --cpus                     Output list of CPUs used by a pool"
    },
    { "cpupool-destroy",
      &main_cpupooldestroy, 0, 1,
      "Deactivates a CPU pool",
      "<CPU Pool>",
    },
    { "cpupool-rename",
      &main_cpupoolrename, 0, 1,
      "Renames a CPU pool",
      "<CPU Pool> <new name>",
    },
    { "cpupool-cpu-add",
      &main_cpupoolcpuadd, 0, 1,
      "Adds a CPU to a CPU pool",
      "<CPU Pool> <CPU nr>|node:<node nr>",
    },
    { "cpupool-cpu-remove",
      &main_cpupoolcpuremove, 0, 1,
      "Removes a CPU from a CPU pool",
      "<CPU Pool> <CPU nr>|node:<node nr>",
    },
    { "cpupool-migrate",
      &main_cpupoolmigrate, 0, 1,
      "Moves a domain into a CPU pool",
      "<Domain> <CPU Pool>",
    },
    { "cpupool-numa-split",
      &main_cpupoolnumasplit, 0, 1,
      "Splits up the machine into one CPU pool per NUMA node",
      "",
    },
    { "getenforce",
      &main_getenforce, 0, 0,
      "Returns the current enforcing mode of the Flask Xen security module",
      "",
    },
    { "setenforce",
      &main_setenforce, 0, 1,
      "Sets the current enforcing mode of the Flask Xen security module",
      "<1|0|Enforcing|Permissive>",
    },
    { "loadpolicy",
      &main_loadpolicy, 0, 1,
      "Loads a new policy int the Flask Xen security module",
      "<policy file>",
    },
#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
    { "remus",
      &main_remus, 0, 1,
      "Enable Remus HA for domain",
      "[options] <Domain> [<host>]",
      "-i MS                   Checkpoint domain memory every MS milliseconds (def. 200ms).\n"
      "-u                      Disable memory checkpoint compression.\n"
      "-s <sshcommand>         Use <sshcommand> instead of ssh.  String will be passed\n"
      "                        to sh. If empty, run <host> instead of \n"
      "                        ssh <host> xl migrate-receive -r [-e]\n"
      "-e                      Do not wait in the background (on <host>) for the death\n"
      "                        of the domain.\n"
      "-N <netbufscript>       Use netbufscript to setup network buffering instead of the\n"
      "                        default script (/etc/xen/scripts/remus-netbuf-setup).\n"
      "-F                      Enable unsafe configurations [-b|-n|-d flags]. Use this option\n"
      "                        with caution as failover may not work as intended.\n"
      "-b                      Replicate memory checkpoints to /dev/null (blackhole).\n"
      "                        Works only in unsafe mode.\n"
      "-n                      Disable network output buffering. Works only in unsafe mode.\n"
      "-d                      Disable disk replication. Works only in unsafe mode.\n"
      "-c                      Enable COLO HA. It is conflict with -i and -b, and memory\n"
      "                        checkpoint must be disabled"
    },
#endif
    { "devd",
      &main_devd, 0, 1,
      "Daemon that listens for devices and launches backends",
      "[options]",
      "-F                      Run in the foreground.\n"
      "-p, --pidfile [FILE]    Write PID to pidfile when daemonizing.",
    },
#ifdef LIBXL_HAVE_PSR_CMT
    { "psr-hwinfo",
      &main_psr_hwinfo, 0, 1,
      "Show hardware information for Platform Shared Resource",
      "[options]",
      "-m, --cmt       Show Cache Monitoring Technology (CMT) hardware info\n"
      "-a, --cat       Show Cache Allocation Technology (CAT) hardware info\n"
    },
    { "psr-cmt-attach",
      &main_psr_cmt_attach, 0, 1,
      "Attach Cache Monitoring Technology service to a domain",
      "<Domain>",
    },
    { "psr-cmt-detach",
      &main_psr_cmt_detach, 0, 1,
      "Detach Cache Monitoring Technology service from a domain",
      "<Domain>",
    },
    { "psr-cmt-show",
      &main_psr_cmt_show, 0, 1,
      "Show Cache Monitoring Technology information",
      "<PSR-CMT-Type> <Domain>",
      "Available monitor types:\n"
      "\"cache-occupancy\":         Show L3 cache occupancy(KB)\n"
      "\"total-mem-bandwidth\":     Show total memory bandwidth(KB/s)\n"
      "\"local-mem-bandwidth\":     Show local memory bandwidth(KB/s)\n",
    },
#endif
#ifdef LIBXL_HAVE_PSR_CAT
    { "psr-cat-cbm-set",
      &main_psr_cat_cbm_set, 0, 1,
      "Set cache capacity bitmasks(CBM) for a domain",
      "[options] <Domain> <CBM>",
      "-s <socket>       Specify the socket to process, otherwise all sockets are processed\n"
      "-c                Set code CBM if CDP is supported\n"
      "-d                Set data CBM if CDP is supported\n"
    },
    { "psr-cat-show",
      &main_psr_cat_show, 0, 1,
      "Show Cache Allocation Technology information",
      "<Domain>",
    },

#endif
    { "usbctrl-attach",
      &main_usbctrl_attach, 0, 1,
      "Create a virtual USB controller for a domain",
      "<Domain> [type=pv] [version=<version>] [ports=<number>]",
    },
    { "usbctrl-detach",
      &main_usbctrl_detach, 0, 1,
      "Remove the virtual USB controller specified by <DevId> for a domain",
      "<Domain> <DevId>",
    },
    { "usbdev-attach",
      &main_usbdev_attach, 0, 1,
      "Attach a USB device to a domain",
      "<Domain> hostbus=<busnum> hostaddr=<devnum> [controller=<DevId> [port=<port>]]",
    },
    { "usbdev-detach",
      &main_usbdev_detach, 0, 1,
      "Detach a USB device from a domain",
      "<Domain> <controller> <port>",
    },
    { "usb-list",
      &main_usblist, 0, 0,
      "List information about all USB controllers and devices for a domain",
      "<Domain>",
    },
    { "qemu-monitor-command",
      &main_qemu_monitor_command, 0, 1,
      "Issue a qemu monitor command to the device model of a domain",
      "<Domain> <Command>",
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
