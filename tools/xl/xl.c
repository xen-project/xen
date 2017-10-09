/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h>
#include <regex.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>
#include "xl.h"

xentoollog_logger_stdiostream *logger;
int dryrun_only;
int force_execution;
int autoballoon = -1;
char *blkdev_start;
int run_hotplug_scripts = 1;
char *lockfile;
char *default_vifscript = NULL;
char *default_bridge = NULL;
char *default_gatewaydev = NULL;
char *default_vifbackend = NULL;
char *default_remus_netbufscript = NULL;
char *default_colo_proxy_script = NULL;
enum output_format default_output_format = OUTPUT_FORMAT_JSON;
int claim_mode = 1;
bool progress_use_cr = 0;
int max_grant_frames = -1;
int max_maptrack_frames = -1;

xentoollog_level minmsglevel = minmsglevel_default;

int logfile = 2;

/* every libxl action in xl uses this same libxl context */
libxl_ctx *ctx;

xlchild children[child_max];

const char *common_domname;

/* Get autoballoon option based on presence of dom0_mem Xen command
   line option. */
static int auto_autoballoon(void)
{
    const libxl_version_info *info;
    regex_t regex;
    int ret;

    info = libxl_get_version_info(ctx);
    if (!info)
        return 1; /* default to on */

    ret = regcomp(&regex,
                  "(^| )dom0_mem=((|min:|max:)[0-9]+[bBkKmMgG]?,?)+($| )",
                  REG_NOSUB | REG_EXTENDED);
    if (ret)
        return 1;

    ret = regexec(&regex, info->commandline, 0, NULL, 0);
    regfree(&regex);
    return ret == REG_NOMATCH;
}

static void parse_global_config(const char *configfile,
                              const char *configfile_data,
                              int configfile_len)
{
    long l;
    XLU_Config *config;
    int e;
    const char *buf;
    libxl_physinfo physinfo;

    config = xlu_cfg_init(stderr, configfile);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        exit(1);
    }

    e = xlu_cfg_readdata(config, configfile_data, configfile_len);
    if (e) {
        fprintf(stderr, "Failed to parse config file: %s\n", strerror(e));
        exit(1);
    }

    if (!xlu_cfg_get_string(config, "autoballoon", &buf, 0)) {
        if (!strcmp(buf, "on") || !strcmp(buf, "1"))
            autoballoon = 1;
        else if (!strcmp(buf, "off") || !strcmp(buf, "0"))
            autoballoon = 0;
        else if (!strcmp(buf, "auto"))
            autoballoon = -1;
        else
            fprintf(stderr, "invalid autoballoon option");
    }
    if (autoballoon == -1)
        autoballoon = auto_autoballoon();

    if (!xlu_cfg_get_long (config, "run_hotplug_scripts", &l, 0))
        run_hotplug_scripts = l;

    if (!xlu_cfg_get_string (config, "lockfile", &buf, 0))
        lockfile = strdup(buf);
    else {
        lockfile = strdup(XL_LOCK_FILE);
    }

    if (!lockfile) {
        fprintf(stderr, "failed to allocate lockfile\n");
        exit(1);
    }

    /*
     * For global options that are related to a specific type of device
     * we use the following nomenclature:
     *
     * <device type>.default.<option name>
     *
     * This allows us to keep the default options classified for the
     * different device kinds.
     */

    if (!xlu_cfg_get_string (config, "vifscript", &buf, 0)) {
        fprintf(stderr, "the global config option vifscript is deprecated, "
                        "please switch to vif.default.script\n");
        free(default_vifscript);
        default_vifscript = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.script", &buf, 0)) {
        free(default_vifscript);
        default_vifscript = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "defaultbridge", &buf, 0)) {
        fprintf(stderr, "the global config option defaultbridge is deprecated, "
                        "please switch to vif.default.bridge\n");
        free(default_bridge);
        default_bridge = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.bridge", &buf, 0)) {
        free(default_bridge);
        default_bridge = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.gatewaydev", &buf, 0))
        default_gatewaydev = strdup(buf);

    if (!xlu_cfg_get_string (config, "vif.default.backend", &buf, 0))
        default_vifbackend = strdup(buf);

    if (!xlu_cfg_get_string (config, "output_format", &buf, 0)) {
        if (!strcmp(buf, "json"))
            default_output_format = OUTPUT_FORMAT_JSON;
        else if (!strcmp(buf, "sxp"))
            default_output_format = OUTPUT_FORMAT_SXP;
        else {
            fprintf(stderr, "invalid default output format \"%s\"\n", buf);
        }
    }
    if (!xlu_cfg_get_string (config, "blkdev_start", &buf, 0))
        blkdev_start = strdup(buf);

    if (!xlu_cfg_get_long (config, "claim_mode", &l, 0))
        claim_mode = l;

    xlu_cfg_replace_string (config, "remus.default.netbufscript",
        &default_remus_netbufscript, 0);
    xlu_cfg_replace_string (config, "colo.default.proxyscript",
        &default_colo_proxy_script, 0);

    if (!xlu_cfg_get_long (config, "max_grant_frames", &l, 0))
        max_grant_frames = l;
    else {
        libxl_physinfo_init(&physinfo);
        max_grant_frames = (libxl_get_physinfo(ctx, &physinfo) != 0 ||
                            !(physinfo.max_possible_mfn >> 32))
                           ? 32 : 64;
        libxl_physinfo_dispose(&physinfo);
    }
    if (!xlu_cfg_get_long (config, "max_maptrack_frames", &l, 0))
        max_maptrack_frames = l;

    xlu_cfg_destroy(config);
}

void postfork(void)
{
    libxl_postfork_child_noexec(ctx); /* in case we don't exit/exec */
    ctx = 0;

    xl_ctx_alloc();
}

pid_t xl_fork(xlchildnum child, const char *description) {
    xlchild *ch = &children[child];
    int i;

    assert(!ch->pid);
    ch->reaped = 0;
    ch->description = description;

    ch->pid = fork();
    if (ch->pid == -1) {
        perror("fork failed");
        exit(-1);
    }

    if (!ch->pid) {
        /* We are in the child now.  So all these children are not ours. */
        for (i=0; i<child_max; i++)
            children[i].pid = 0;
    }

    return ch->pid;
}

pid_t xl_waitpid(xlchildnum child, int *status, int flags)
{
    xlchild *ch = &children[child];
    pid_t got = ch->pid;
    assert(got);
    if (ch->reaped) {
        *status = ch->status;
        ch->pid = 0;
        return got;
    }
    for (;;) {
        got = waitpid(ch->pid, status, flags);
        if (got < 0 && errno == EINTR) continue;
        if (got > 0) {
            assert(got == ch->pid);
            ch->pid = 0;
        }
        return got;
    }
}

int xl_child_pid(xlchildnum child)
{
    xlchild *ch = &children[child];
    return ch->pid;
}

void xl_report_child_exitstatus(xentoollog_level level,
                                xlchildnum child, pid_t pid, int status)
{
    libxl_report_child_exitstatus(ctx, level, children[child].description,
                                  pid, status);
}

static int xl_reaped_callback(pid_t got, int status, void *user)
{
    int i;
    assert(got);
    for (i=0; i<child_max; i++) {
        xlchild *ch = &children[i];
        if (ch->pid == got) {
            ch->reaped = 1;
            ch->status = status;
            return 0;
        }
    }
    return ERROR_UNKNOWN_CHILD;
}

static const libxl_childproc_hooks childproc_hooks = {
    .chldowner = libxl_sigchld_owner_libxl,
    .reaped_callback = xl_reaped_callback,
};

void xl_ctx_alloc(void) {
    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (xentoollog_logger*)logger)) {
        fprintf(stderr, "cannot init xl context\n");
        exit(1);
    }

    libxl_childproc_setmode(ctx, &childproc_hooks, 0);
}

static void xl_ctx_free(void)
{
    if (ctx) {
        libxl_ctx_free(ctx);
        ctx = NULL;
    }
    if (logger) {
        xtl_logger_destroy((xentoollog_logger*)logger);
        logger = NULL;
    }
    if (lockfile) {
        free(lockfile);
        lockfile = NULL;
    }
}

int main(int argc, char **argv)
{
    int opt = 0;
    char *cmd = 0;
    struct cmd_spec *cspec;
    int ret;
    void *config_data = 0;
    int config_len = 0;

    while ((opt = getopt(argc, argv, "+vftN")) >= 0) {
        switch (opt) {
        case 'v':
            if (minmsglevel > 0) minmsglevel--;
            break;
        case 'N':
            dryrun_only = 1;
            break;
        case 'f':
            force_execution = 1;
            break;
        case 't':
            progress_use_cr = 1;
            break;
        default:
            fprintf(stderr, "unknown global option\n");
            exit(EXIT_FAILURE);
        }
    }

    cmd = argv[optind];

    if (!cmd) {
        help(NULL);
        exit(EXIT_FAILURE);
    }
    opterr = 0;

    logger = xtl_createlogger_stdiostream(stderr, minmsglevel,
        (progress_use_cr ? XTL_STDIOSTREAM_PROGRESS_USE_CR : 0));
    if (!logger) exit(EXIT_FAILURE);

    atexit(xl_ctx_free);

    xl_ctx_alloc();

    ret = libxl_read_file_contents(ctx, XL_GLOBAL_CONFIG,
            &config_data, &config_len);
    if (ret)
        fprintf(stderr, "Failed to read config file: %s: %s\n",
                XL_GLOBAL_CONFIG, strerror(errno));
    parse_global_config(XL_GLOBAL_CONFIG, config_data, config_len);
    free(config_data);

    /* Reset options for per-command use of getopt. */
    argv += optind;
    argc -= optind;
    optind = 1;

    cspec = cmdtable_lookup(cmd);
    if (cspec) {
        if (dryrun_only && !cspec->can_dryrun) {
            fprintf(stderr, "command does not implement -N (dryrun) option\n");
            ret = EXIT_FAILURE;
            goto xit;
        }
        ret = cspec->cmd_impl(argc, argv);
    } else if (!strcmp(cmd, "help")) {
        help(argv[1]);
        ret = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "command not implemented\n");
        ret = EXIT_FAILURE;
    }

 xit:
    return ret;
}

int child_report(xlchildnum child)
{
    int status;
    pid_t got = xl_waitpid(child, &status, 0);
    if (got < 0) {
        fprintf(stderr, "xl: warning, failed to waitpid for %s: %s\n",
                children[child].description, strerror(errno));
        return ERROR_FAIL;
    } else if (status) {
        xl_report_child_exitstatus(XTL_ERROR, child, got, status);
        return ERROR_FAIL;
    } else {
        return 0;
    }
}

void help(const char *command)
{
    int i;
    struct cmd_spec *cmd;

    if (!command || !strcmp(command, "help")) {
        printf("Usage xl [-vfN] <subcommand> [args]\n\n");
        printf("xl full list of subcommands:\n\n");
        for (i = 0; i < cmdtable_len; i++) {
            printf(" %-19s ", cmd_table[i].cmd_name);
            if (strlen(cmd_table[i].cmd_name) > 19)
                printf("\n %-19s ", "");
            printf("%s\n", cmd_table[i].cmd_desc);
        }
    } else {
        cmd = cmdtable_lookup(command);
        if (cmd) {
            printf("Usage: xl [-v%s%s] %s %s\n\n%s.\n\n",
                   cmd->modifies ? "f" : "",
                   cmd->can_dryrun ? "N" : "",
                   cmd->cmd_name,
                   cmd->cmd_usage,
                   cmd->cmd_desc);
            if (cmd->cmd_option)
                printf("Options:\n\n%s\n", cmd->cmd_option);
        }
        else {
            printf("command \"%s\" not implemented\n", command);
        }
    }
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
