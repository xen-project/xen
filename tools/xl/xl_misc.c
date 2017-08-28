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

#include <limits.h>
#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

static void button_press(uint32_t domid, const char *b)
{
    libxl_trigger trigger;

    if (!strcmp(b, "power")) {
        trigger = LIBXL_TRIGGER_POWER;
    } else if (!strcmp(b, "sleep")) {
        trigger = LIBXL_TRIGGER_SLEEP;
    } else {
        fprintf(stderr, "%s is an invalid button identifier\n", b);
        exit(EXIT_FAILURE);
    }

    libxl_send_trigger(ctx, domid, trigger, 0);
}

int main_button_press(int argc, char **argv)
{
    int opt;

    fprintf(stderr, "WARNING: \"button-press\" is deprecated. "
            "Please use \"trigger\"\n");


    SWITCH_FOREACH_OPT(opt, "", NULL, "button-press", 2) {
        /* No options */
    }

    button_press(find_domain(argv[optind]), argv[optind + 1]);

    return 0;
}

int main_rename(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *dom, *new_name;

    SWITCH_FOREACH_OPT(opt, "", NULL, "rename", 2) {
        /* No options */
    }

    dom = argv[optind++];
    new_name = argv[optind];

    domid = find_domain(dom);
    if (libxl_domain_rename(ctx, domid, common_domname, new_name)) {
        fprintf(stderr, "Can't rename domain '%s'.\n", dom);
        return 1;
    }

    return 0;
}

int main_trigger(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    char *endptr = NULL;
    int vcpuid = 0;
    const char *trigger_name = NULL;
    libxl_trigger trigger;

    SWITCH_FOREACH_OPT(opt, "", NULL, "trigger", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    trigger_name = argv[optind++];
    if (libxl_trigger_from_string(trigger_name, &trigger)) {
        fprintf(stderr, "Invalid trigger \"%s\"\n", trigger_name);
        return EXIT_FAILURE;
    }

    if (argv[optind]) {
        vcpuid = strtol(argv[optind], &endptr, 10);
        if (vcpuid == 0 && !strcmp(endptr, argv[optind])) {
            fprintf(stderr, "Invalid vcpuid, using default vcpuid=0.\n\n");
        }
    }

    libxl_send_trigger(ctx, domid, trigger, vcpuid);

    return EXIT_SUCCESS;
}

int main_sysrq(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *sysrq = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "sysrq", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    sysrq = argv[optind];

    if (sysrq[1] != '\0') {
        fprintf(stderr, "Invalid sysrq.\n\n");
        help("sysrq");
        return EXIT_FAILURE;
    }

    libxl_send_sysrq(ctx, domid, sysrq[0]);

    return EXIT_SUCCESS;
}

int main_debug_keys(int argc, char **argv)
{
    int opt;
    char *keys;

    SWITCH_FOREACH_OPT(opt, "", NULL, "debug-keys", 1) {
        /* No options */
    }

    keys = argv[optind];

    if (libxl_send_debug_keys(ctx, keys)) {
        fprintf(stderr, "cannot send debug keys: %s\n", keys);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_set_parameters(int argc, char **argv)
{
    int opt;
    char *params;

    SWITCH_FOREACH_OPT(opt, "", NULL, "set-parameters", 1) {
        /* No options */
    }

    params = argv[optind];

    if (libxl_set_parameters(ctx, params)) {
        fprintf(stderr, "cannot set parameters: %s\n", params);
        fprintf(stderr, "Use \"xl dmesg\" to look for possible reason.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_devd(int argc, char **argv)
{
    int ret = 0, opt = 0, daemonize = 1;
    const char *pidfile = NULL;
    static const struct option opts[] = {
        {"pidfile", 1, 0, 'p'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "Fp:", opts, "devd", 0) {
    case 'F':
        daemonize = 0;
        break;
    case 'p':
        pidfile = optarg;
        break;
    }

    if (daemonize) {
        ret = do_daemonize("xldevd", pidfile);
        if (ret) {
            ret = (ret == 1) ? 0 : ret;
            goto out;
        }
    }

    ret = libxl_device_events_handler(ctx, 0) ? EXIT_FAILURE : EXIT_SUCCESS;

out:
    return ret;
}

int main_qemu_monitor_command(int argc, char **argv)
{
    int opt;
    uint32_t domid;
    char *cmd;
    char *output;
    int ret;

    SWITCH_FOREACH_OPT(opt, "", NULL, "qemu-monitor-command", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    cmd = argv[optind + 1];

    if (argc - optind > 2) {
        fprintf(stderr, "Invalid arguments.\n");
        return EXIT_FAILURE;
    }

    ret = libxl_qemu_monitor_command(ctx, domid, cmd, &output);
    if (!ret && output) {
        printf("%s\n", output);
        free(output);
    }

    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void core_dump_domain(uint32_t domid, const char *filename)
{
    int rc;

    rc=libxl_domain_core_dump(ctx, domid, filename, NULL);
    if (rc) { fprintf(stderr,"core dump failed (rc=%d)\n",rc);exit(EXIT_FAILURE); }
}

int main_dump_core(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "dump-core", 2) {
        /* No options */
    }

    core_dump_domain(find_domain(argv[optind]), argv[optind + 1]);
    return EXIT_SUCCESS;
}

extern void printf_info(enum output_format output_format,
                        int domid,
                        libxl_domain_config *d_config, FILE *fh);
int main_config_update(int argc, char **argv)
{
    uint32_t domid;
    const char *filename = NULL;
    char *extra_config = NULL;
    void *config_data = 0;
    int config_len = 0;
    libxl_domain_config d_config;
    int opt, rc;
    int debug = 0;
    static struct option opts[] = {
        {"defconfig", 1, 0, 'f'},
        COMMON_LONG_OPTS
    };

    if (argc < 2) {
        fprintf(stderr, "xl config-update requires a domain argument\n");
        help("config-update");
        exit(1);
    }

    fprintf(stderr, "WARNING: xl now has better capability to manage domain configuration, "
            "avoid using this command when possible\n");

    domid = find_domain(argv[1]);
    argc--; argv++;

    if (argv[1] && argv[1][0] != '-' && !strchr(argv[1], '=')) {
        filename = argv[1];
        argc--; argv++;
    }

    SWITCH_FOREACH_OPT(opt, "dqf:", opts, "config_update", 0) {
    case 'd':
        debug = 1;
        break;
    case 'f':
        filename = optarg;
        break;
    }

    for (; optind < argc; optind++) {
        if (strchr(argv[optind], '=') != NULL) {
            string_realloc_append(&extra_config, argv[optind]);
            string_realloc_append(&extra_config, "\n");
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("create");
            free(extra_config);
            return 2;
        }
    }
    if (filename) {
        free(config_data);  config_data = 0;
        rc = libxl_read_file_contents(ctx, filename,
                                      &config_data, &config_len);
        if (rc) { fprintf(stderr, "Failed to read config file: %s: %s\n",
                           filename, strerror(errno));
                  free(extra_config); return ERROR_FAIL; }
        if (extra_config && strlen(extra_config)) {
            if (config_len > INT_MAX - (strlen(extra_config) + 2 + 1)) {
                fprintf(stderr, "Failed to attach extra configuration\n");
                exit(1);
            }
            /* allocate space for the extra config plus two EOLs plus \0 */
            config_data = realloc(config_data, config_len
                + strlen(extra_config) + 2 + 1);
            if (!config_data) {
                fprintf(stderr, "Failed to realloc config_data\n");
                exit(1);
            }
            config_len += sprintf(config_data + config_len, "\n%s\n",
                extra_config);
        }
    } else {
        fprintf(stderr, "Config file not specified\n");
        exit(1);
    }

    libxl_domain_config_init(&d_config);

    parse_config_data(filename, config_data, config_len, &d_config);

    if (debug || dryrun_only)
        printf_info(default_output_format, -1, &d_config, stdout);

    if (!dryrun_only) {
        fprintf(stderr, "setting dom%u configuration\n", domid);
        rc = libxl_userdata_store(ctx, domid, "xl",
                                   config_data, config_len);
        if (rc) {
            fprintf(stderr, "failed to update configuration\n");
            exit(1);
        }
    }

    libxl_domain_config_dispose(&d_config);

    free(config_data);
    free(extra_config);
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
