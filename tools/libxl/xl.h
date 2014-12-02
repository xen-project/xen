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

#ifndef XL_H
#define XL_H

#include <assert.h>

#include "_paths.h"
#include "xentoollog.h"

struct cmd_spec {
    char *cmd_name;
    int (*cmd_impl)(int argc, char **argv);
    int can_dryrun;
    int modifies;
    char *cmd_desc;
    char *cmd_usage;
    char *cmd_option;
};

int main_vcpulist(int argc, char **argv);
int main_info(int argc, char **argv);
int main_sharing(int argc, char **argv);
int main_cd_eject(int argc, char **argv);
int main_cd_insert(int argc, char **argv);
int main_console(int argc, char **argv);
int main_vncviewer(int argc, char **argv);
int main_pcilist(int argc, char **argv);
int main_pcidetach(int argc, char **argv);
int main_pciattach(int argc, char **argv);
int main_pciassignable_add(int argc, char **argv);
int main_pciassignable_remove(int argc, char **argv);
int main_pciassignable_list(int argc, char **argv);
#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
int main_restore(int argc, char **argv);
int main_migrate_receive(int argc, char **argv);
int main_save(int argc, char **argv);
int main_migrate(int argc, char **argv);
#endif
int main_dump_core(int argc, char **argv);
int main_pause(int argc, char **argv);
int main_unpause(int argc, char **argv);
int main_destroy(int argc, char **argv);
int main_shutdown(int argc, char **argv);
int main_reboot(int argc, char **argv);
int main_list(int argc, char **argv);
int main_vm_list(int argc, char **argv);
int main_create(int argc, char **argv);
int main_config_update(int argc, char **argv);
int main_button_press(int argc, char **argv);
int main_vcpupin(int argc, char **argv);
int main_vcpuset(int argc, char **argv);
int main_memmax(int argc, char **argv);
int main_memset(int argc, char **argv);
int main_sched_credit(int argc, char **argv);
int main_sched_credit2(int argc, char **argv);
int main_sched_sedf(int argc, char **argv);
int main_sched_rtds(int argc, char **argv);
int main_domid(int argc, char **argv);
int main_domname(int argc, char **argv);
int main_rename(int argc, char **argv);
int main_trigger(int argc, char **argv);
int main_sysrq(int argc, char **argv);
int main_debug_keys(int argc, char **argv);
int main_dmesg(int argc, char **argv);
int main_top(int argc, char **argv);
int main_networkattach(int argc, char **argv);
int main_networklist(int argc, char **argv);
int main_networkdetach(int argc, char **argv);
int main_channellist(int argc, char **argv);
int main_blockattach(int argc, char **argv);
int main_blocklist(int argc, char **argv);
int main_blockdetach(int argc, char **argv);
int main_vtpmattach(int argc, char **argv);
int main_vtpmlist(int argc, char **argv);
int main_vtpmdetach(int argc, char **argv);
int main_uptime(int argc, char **argv);
int main_claims(int argc, char **argv);
int main_tmem_list(int argc, char **argv);
int main_tmem_freeze(int argc, char **argv);
int main_tmem_thaw(int argc, char **argv);
int main_tmem_set(int argc, char **argv);
int main_tmem_shared_auth(int argc, char **argv);
int main_tmem_freeable(int argc, char **argv);
int main_network2attach(int argc, char **argv);
int main_network2list(int argc, char **argv);
int main_network2detach(int argc, char **argv);
int main_cpupoolcreate(int argc, char **argv);
int main_cpupoollist(int argc, char **argv);
int main_cpupooldestroy(int argc, char **argv);
int main_cpupoolrename(int argc, char **argv);
int main_cpupoolcpuadd(int argc, char **argv);
int main_cpupoolcpuremove(int argc, char **argv);
int main_cpupoolmigrate(int argc, char **argv);
int main_cpupoolnumasplit(int argc, char **argv);
int main_getenforce(int argc, char **argv);
int main_setenforce(int argc, char **argv);
int main_loadpolicy(int argc, char **argv);
#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME
int main_remus(int argc, char **argv);
#endif
int main_devd(int argc, char **argv);
#ifdef LIBXL_HAVE_PSR_CMT
int main_psr_cmt_attach(int argc, char **argv);
int main_psr_cmt_detach(int argc, char **argv);
int main_psr_cmt_show(int argc, char **argv);
#endif

void help(const char *command);

extern struct cmd_spec cmd_table[];
extern int cmdtable_len;
/* Look up a command in the table, allowing unambiguous truncation */
struct cmd_spec *cmdtable_lookup(const char *s);

extern libxl_ctx *ctx;
extern xentoollog_logger_stdiostream *logger;

void xl_ctx_alloc(void);

/* child processes */

typedef struct {
    /* every struct like this must be in XLCHILD_LIST */
    pid_t pid; /* 0: not in use */
    int reaped; /* valid iff pid!=0 */
    int status; /* valid iff reaped */
    const char *description; /* valid iff pid!=0 */
} xlchild;

typedef enum {
    child_console, child_waitdaemon, child_migration, child_vncviewer,
    child_max
} xlchildnum;

extern xlchild children[child_max];

pid_t xl_fork(xlchildnum, const char *description);
    /* like fork, but prints and dies if it fails */
void postfork(void); /* needed only if we aren't going to exec right away */

/* Handles EINTR.  Clears out the xlchild so it can be reused. */
pid_t xl_waitpid(xlchildnum, int *status, int flags);

int xl_child_pid(xlchildnum); /* returns 0 if child struct is not in use */

void xl_report_child_exitstatus(xentoollog_level level,
                                xlchildnum child, pid_t pid, int status);
    /* like libxl_report_child_exitstatus, but uses children[].description */

int child_report(xlchildnum child);
    /* waits and expects child to exit status 0.
     * otherwise, logs and returns ERROR_FAIL */

/* global options */
extern int autoballoon;
extern int run_hotplug_scripts;
extern int dryrun_only;
extern int claim_mode;
extern bool progress_use_cr;
extern xentoollog_level minmsglevel;
#define minmsglevel_default XTL_PROGRESS
extern char *lockfile;
extern char *default_vifscript;
extern char *default_bridge;
extern char *default_gatewaydev;
extern char *default_vifbackend;
extern char *default_remus_netbufscript;
extern char *blkdev_start;

enum output_format {
    OUTPUT_FORMAT_JSON,
    OUTPUT_FORMAT_SXP,
};
extern enum output_format default_output_format;

extern void printf_info_sexp(int domid, libxl_domain_config *d_config, FILE *fh);

#define XL_GLOBAL_CONFIG XEN_CONFIG_DIR "/xl.conf"
#define XL_LOCK_FILE XEN_LOCK_DIR "/xl"

#endif /* XL_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
