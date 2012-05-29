/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include "libxl_osdeps.h"

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

#include "libxl.h"
#include "libxl_utils.h"
#include "libxlutil.h"
#include "xl.h"

#define XEND_LOCK { "/var/lock/subsys/xend", "/var/lock/xend" }

xentoollog_logger_stdiostream *logger;
int dryrun_only;
int force_execution;
int autoballoon = 1;
char *blkdev_start;
char *lockfile;
char *default_vifscript = NULL;
char *default_bridge = NULL;
enum output_format default_output_format = OUTPUT_FORMAT_JSON;

static xentoollog_level minmsglevel = XTL_PROGRESS;

static void parse_global_config(const char *configfile,
                              const char *configfile_data,
                              int configfile_len)
{
    long l;
    XLU_Config *config;
    int e;
    const char *buf;

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

    if (!xlu_cfg_get_long (config, "autoballoon", &l, 0))
        autoballoon = l;

    if (!xlu_cfg_get_string (config, "lockfile", &buf, 0))
        lockfile = strdup(buf);
    else {
        e = asprintf(&lockfile, "%s/xl", (char *)libxl_lock_dir_path());
        if (e < 0) {
            fprintf(stderr, "asprintf memory allocation failed\n");
            exit(1);
        }
    }

    if (!xlu_cfg_get_string (config, "vifscript", &buf, 0))
        default_vifscript = strdup(buf);

    if (!xlu_cfg_get_string (config, "defaultbridge", &buf, 0))
	default_bridge = strdup(buf);

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
    xlu_cfg_destroy(config);
}

void postfork(void)
{
    libxl_postfork_child_noexec(ctx); /* in case we don't exit/exec */
    ctx = 0;

    xl_ctx_alloc();
}

pid_t xl_fork(xlchildnum child) {
    xlchild *ch = &children[child];
    int i;

    assert(!ch->pid);
    ch->reaped = 0;

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

int main(int argc, char **argv)
{
    int opt = 0;
    char *cmd = 0;
    struct cmd_spec *cspec;
    int ret;
    char *config_file;
    void *config_data = 0;
    int config_len = 0;
    const char *locks[] = XEND_LOCK;

    while ((opt = getopt(argc, argv, "+vfN")) >= 0) {
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
        default:
            fprintf(stderr, "unknown global option\n");
            exit(2);
        }
    }

    cmd = argv[optind];

    if (!cmd) {
        help(NULL);
        exit(1);
    }
    opterr = 0;

    logger = xtl_createlogger_stdiostream(stderr, minmsglevel,  0);
    if (!logger) exit(1);

    xl_ctx_alloc();

    /* Read global config file options */
    ret = asprintf(&config_file, "%s/xl.conf", libxl_xen_config_dir_path());
    if (ret < 0) {
        fprintf(stderr, "memory allocation failed ret=%d, errno=%d\n", ret, errno);
        exit(1);
    }

    ret = libxl_read_file_contents(ctx, config_file,
            &config_data, &config_len);
    if (ret)
        fprintf(stderr, "Failed to read config file: %s: %s\n",
                config_file, strerror(errno));
    parse_global_config(config_file, config_data, config_len);
    free(config_file);
    free(config_data);

    /* Reset options for per-command use of getopt. */
    argv += optind;
    argc -= optind;
    optind = 1;

    cspec = cmdtable_lookup(cmd);
    if (cspec) {
        if (dryrun_only && !cspec->can_dryrun) {
            fprintf(stderr, "command does not implement -N (dryrun) option\n");
            ret = 1;
            goto xit;
        }
        if (cspec->modifies && !dryrun_only) {
            for (int i = 0; i < sizeof(locks)/sizeof(locks[0]); i++) {
                if (!access(locks[i], F_OK) && !force_execution) {
                    fprintf(stderr,
"xend is running, which prevents xl from working correctly.\n"
"If you still want to force the execution of xl please use the -f\n"
"option.\n"
                            );
                    ret = 1;
                    goto xit;
                }
            }
        }
        ret = cspec->cmd_impl(argc, argv);
    } else if (!strcmp(cmd, "help")) {
        help(argv[1]);
        ret = 0;
    } else {
        fprintf(stderr, "command not implemented\n");
        ret = 1;
    }

 xit:
    libxl_ctx_free(ctx);
    xtl_logger_destroy((xentoollog_logger*)logger);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
