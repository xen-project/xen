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

xentoollog_logger_stdiostream *logger;
int dryrun_only;
int autoballoon = 1;
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
    xlu_cfg_destroy(config);
}

void postfork(void)
{
    libxl_postfork_child_noexec(ctx); /* in case we don't exit/exec */
    ctx = 0;

    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (xentoollog_logger*)logger)) {
        fprintf(stderr, "cannot reinit xl context after fork\n");
        exit(-1);
    }
}

pid_t xl_fork(libxl_ctx *ctx) {
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        perror("fork failed");
        exit(-1);
    }

    return pid;
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

    while ((opt = getopt(argc, argv, "+vN")) >= 0) {
        switch (opt) {
        case 'v':
            if (minmsglevel > 0) minmsglevel--;
            break;
        case 'N':
            dryrun_only = 1;
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

    if (libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (xentoollog_logger*)logger)) {
        fprintf(stderr, "cannot init xl context\n");
        exit(1);
    }

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
