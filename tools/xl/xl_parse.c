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

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <xen/hvm/e820.h>
#include <xen/hvm/params.h>
#include <xen/io/sndif.h>
#include <xen/io/kbdif.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

extern void set_default_nic_values(libxl_device_nic *nic);

#define ARRAY_EXTEND_INIT__CORE(array,count,initfn,more)                \
    ({                                                                  \
        typeof((count)) array_extend_old_count = (count);               \
        (count)++;                                                      \
        (array) = xrealloc((array), sizeof(*array) * (count));          \
        (initfn)(&(array)[array_extend_old_count]);                     \
        more;                                                           \
        &(array)[array_extend_old_count];                               \
    })

#define ARRAY_EXTEND_INIT(array,count,initfn)                           \
    ARRAY_EXTEND_INIT__CORE((array),(count),(initfn), ({                \
        (array)[array_extend_old_count].devid = array_extend_old_count; \
        }))

#define ARRAY_EXTEND_INIT_NODEVID(array,count,initfn) \
    ARRAY_EXTEND_INIT__CORE((array),(count),(initfn), /* nothing */ )

static const char *action_on_shutdown_names[] = {
    [LIBXL_ACTION_ON_SHUTDOWN_DESTROY] = "destroy",

    [LIBXL_ACTION_ON_SHUTDOWN_RESTART] = "restart",
    [LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME] = "rename-restart",

    [LIBXL_ACTION_ON_SHUTDOWN_PRESERVE] = "preserve",

    [LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY] = "coredump-destroy",
    [LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART] = "coredump-restart",

    [LIBXL_ACTION_ON_SHUTDOWN_SOFT_RESET] = "soft-reset",
};

const char *get_action_on_shutdown_name(libxl_action_on_shutdown a)
{
    return action_on_shutdown_names[a];
}

static int parse_action_on_shutdown(const char *buf, libxl_action_on_shutdown *a)
{
    int i;
    const char *n;

    for (i = 0; i < sizeof(action_on_shutdown_names) / sizeof(action_on_shutdown_names[0]); i++) {
        n = action_on_shutdown_names[i];

        if (!n) continue;

        if (strcmp(buf, n) == 0) {
            *a = i;
            return 1;
        }
    }
    return 0;
}

#define DSTATE_INITIAL   0
#define DSTATE_TAP       1
#define DSTATE_PHYSPATH  2
#define DSTATE_VIRTPATH  3
#define DSTATE_VIRTTYPE  4
#define DSTATE_RW        5
#define DSTATE_TERMINAL  6

void parse_disk_config_multistring(XLU_Config **config,
                                   int nspecs, const char *const *specs,
                                   libxl_device_disk *disk)
{
    int e;

    libxl_device_disk_init(disk);

    if (!*config) {
        *config = xlu_cfg_init(stderr, "command line");
        if (!*config) { perror("xlu_cfg_init"); exit(-1); }
    }

    e = xlu_disk_parse(*config, nspecs, specs, disk);
    if (e == EINVAL) exit(EXIT_FAILURE);
    if (e) {
        fprintf(stderr,"xlu_disk_parse failed: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void parse_disk_config(XLU_Config **config, const char *spec,
                       libxl_device_disk *disk)
{
    parse_disk_config_multistring(config, 1, &spec, disk);
}

static void parse_vif_rate(XLU_Config **config, const char *rate,
                           libxl_device_nic *nic)
{
    int e;

    e = xlu_vif_parse_rate(*config, rate, nic);
    if (e == EINVAL || e == EOVERFLOW) exit(EXIT_FAILURE);
    if (e) {
        fprintf(stderr,"xlu_vif_parse_rate failed: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int parse_range(const char *str, unsigned long *a, unsigned long *b)
{
    const char *nstr;
    char *endptr;

    *a = *b = strtoul(str, &endptr, 10);
    if (endptr == str || *a == ULONG_MAX)
        return 1;

    if (*endptr == '-') {
        nstr = endptr + 1;

        *b = strtoul(nstr, &endptr, 10);
        if (endptr == nstr || *b == ULONG_MAX || *b < *a)
            return 1;
    }

    /* Valid value or range so far, but we also don't want junk after that */
    if (*endptr != '\0')
        return 1;

    return 0;
}

/*
 * Add or removes a specific set of cpus (specified in str, either as
 * single cpus or as entire NUMA nodes) to/from cpumap.
 */
static int update_cpumap_range(const char *str, libxl_bitmap *cpumap)
{
    unsigned long ida, idb;
    libxl_bitmap node_cpumap;
    bool is_not = false, is_nodes = false;
    int rc = 0;

    libxl_bitmap_init(&node_cpumap);

    rc = libxl_node_bitmap_alloc(ctx, &node_cpumap, 0);
    if (rc) {
        fprintf(stderr, "libxl_node_bitmap_alloc failed.\n");
        goto out;
    }

    /* Are we adding or removing cpus/nodes? */
    if (STR_SKIP_PREFIX(str, "^")) {
        is_not = true;
    }

    /* Are we dealing with cpus or full nodes? */
    if (STR_SKIP_PREFIX(str, "node:") || STR_SKIP_PREFIX(str, "nodes:")) {
        is_nodes = true;
    }

    if (strcmp(str, "all") == 0) {
        /* We do not accept "^all" or "^nodes:all" */
        if (is_not) {
            fprintf(stderr, "Can't combine \"^\" and \"all\".\n");
            rc = ERROR_INVAL;
        } else
            libxl_bitmap_set_any(cpumap);
        goto out;
    }

    rc = parse_range(str, &ida, &idb);
    if (rc) {
        fprintf(stderr, "Invalid pcpu range: %s.\n", str);
        goto out;
    }

    /* Add or remove the specified cpus in the range */
    while (ida <= idb) {
        if (is_nodes) {
            /* Add/Remove all the cpus of a NUMA node */
            int i;

            rc = libxl_node_to_cpumap(ctx, ida, &node_cpumap);
            if (rc) {
                fprintf(stderr, "libxl_node_to_cpumap failed.\n");
                goto out;
            }

            /* Add/Remove all the cpus in the node cpumap */
            libxl_for_each_set_bit(i, node_cpumap) {
                is_not ? libxl_bitmap_reset(cpumap, i) :
                         libxl_bitmap_set(cpumap, i);
            }
        } else {
            /* Add/Remove this cpu */
            is_not ? libxl_bitmap_reset(cpumap, ida) :
                     libxl_bitmap_set(cpumap, ida);
        }
        ida++;
    }

 out:
    libxl_bitmap_dispose(&node_cpumap);
    return rc;
}

/*
 * Takes a string representing a set of cpus (specified either as
 * single cpus or as eintire NUMA nodes) and turns it into the
 * corresponding libxl_bitmap (in cpumap).
 */
int parse_cpurange(const char *cpu, libxl_bitmap *cpumap)
{
    char *ptr, *saveptr = NULL, *buf = xstrdup(cpu);
    int rc = 0;

    for (ptr = strtok_r(buf, ",", &saveptr); ptr;
         ptr = strtok_r(NULL, ",", &saveptr)) {
        rc = update_cpumap_range(ptr, cpumap);
        if (rc)
            break;
    }
    free(buf);

    return rc;
}

static void parse_top_level_vnc_options(XLU_Config *config,
                                        libxl_vnc_info *vnc)
{
    long l;

    xlu_cfg_get_defbool(config, "vnc", &vnc->enable, 0);
    xlu_cfg_replace_string (config, "vnclisten", &vnc->listen, 0);
    xlu_cfg_replace_string (config, "vncpasswd", &vnc->passwd, 0);
    if (!xlu_cfg_get_long (config, "vncdisplay", &l, 0))
        vnc->display = l;
    xlu_cfg_get_defbool(config, "vncunused", &vnc->findunused, 0);
}

static void parse_top_level_sdl_options(XLU_Config *config,
                                        libxl_sdl_info *sdl)
{
    xlu_cfg_get_defbool(config, "sdl", &sdl->enable, 0);
    xlu_cfg_get_defbool(config, "opengl", &sdl->opengl, 0);
    xlu_cfg_replace_string (config, "display", &sdl->display, 0);
    xlu_cfg_replace_string (config, "xauthority", &sdl->xauthority, 0);
}

static char *parse_cmdline(XLU_Config *config)
{
    char *cmdline = NULL;
    const char *root = NULL, *extra = NULL, *buf = NULL;

    xlu_cfg_get_string (config, "cmdline", &buf, 0);
    xlu_cfg_get_string (config, "root", &root, 0);
    xlu_cfg_get_string (config, "extra", &extra, 0);

    if (buf) {
        cmdline = strdup(buf);
        if (root || extra)
            fprintf(stderr, "Warning: ignoring root= and extra= "
                    "in favour of cmdline=\n");
    } else {
        if (root && extra) {
            xasprintf(&cmdline, "root=%s %s", root, extra);
        } else if (root) {
            xasprintf(&cmdline, "root=%s", root);
        } else if (extra) {
            cmdline = strdup(extra);
        }
    }

    if ((buf || root || extra) && !cmdline) {
        fprintf(stderr, "Failed to allocate memory for cmdline\n");
        exit(EXIT_FAILURE);
    }

    return cmdline;
}

static void parse_vcpu_affinity(libxl_domain_build_info *b_info,
                                XLU_ConfigList *cpus, const char *buf,
                                int num_cpus, bool is_hard)
{
    libxl_bitmap *vcpu_affinity_array;

    /*
     * If we are here, and buf is !NULL, we're dealing with a string. What
     * we do in this case is parse it, and copy the result in _all_ (up to
     * b_info->max_vcpus) the elements of the vcpu affinity array.
     *
     * If buf is NULL, we have a list, and what we do is putting in the
     * i-eth element of the vcpu affinity array the result of the parsing
     * of the i-eth entry of the list. If there are more vcpus than
     * entries, it is fine to just not touch the last array elements.
     */

    /* Silently ignore values corresponding to non existing vcpus */
    if (buf || num_cpus > b_info->max_vcpus)
        num_cpus = b_info->max_vcpus;

    if (is_hard) {
        b_info->num_vcpu_hard_affinity = num_cpus;
        b_info->vcpu_hard_affinity = xmalloc(num_cpus * sizeof(libxl_bitmap));
        vcpu_affinity_array = b_info->vcpu_hard_affinity;
    } else {
        b_info->num_vcpu_soft_affinity = num_cpus;
        b_info->vcpu_soft_affinity = xmalloc(num_cpus * sizeof(libxl_bitmap));
        vcpu_affinity_array = b_info->vcpu_soft_affinity;
    }

    if (!buf) {
        int j = 0;

        while ((buf = xlu_cfg_get_listitem(cpus, j)) != NULL && j < num_cpus) {
            libxl_bitmap_init(&vcpu_affinity_array[j]);
            if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[j], 0)) {
                fprintf(stderr, "Unable to allocate cpumap for vcpu %d\n", j);
                exit(EXIT_FAILURE);
            }

            if (parse_cpurange(buf, &vcpu_affinity_array[j]))
                exit(EXIT_FAILURE);

            j++;
        }

        /* When we have a list of cpumaps, always disable automatic placement */
        libxl_defbool_set(&b_info->numa_placement, false);
    } else {
        int i;

        libxl_bitmap_init(&vcpu_affinity_array[0]);
        if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[0], 0)) {
            fprintf(stderr, "Unable to allocate cpumap for vcpu 0\n");
            exit(EXIT_FAILURE);
        }

        if (parse_cpurange(buf, &vcpu_affinity_array[0]))
            exit(EXIT_FAILURE);

        for (i = 1; i < b_info->max_vcpus; i++) {
            libxl_bitmap_init(&vcpu_affinity_array[i]);
            if (libxl_cpu_bitmap_alloc(ctx, &vcpu_affinity_array[i], 0)) {
                fprintf(stderr, "Unable to allocate cpumap for vcpu %d\n", i);
                exit(EXIT_FAILURE);
            }
            libxl_bitmap_copy(ctx, &vcpu_affinity_array[i],
                              &vcpu_affinity_array[0]);
        }

        /* We have soft affinity already, disable automatic placement */
        if (!is_hard)
            libxl_defbool_set(&b_info->numa_placement, false);
    }
}

static unsigned long parse_ulong(const char *str)
{
    char *endptr;
    unsigned long val;

    val = strtoul(str, &endptr, 10);
    if (endptr == str || val == ULONG_MAX) {
        fprintf(stderr, "xl: failed to convert \"%s\" to number\n", str);
        exit(EXIT_FAILURE);
    }
    return val;
}

void replace_string(char **str, const char *val)
{
    free(*str);
    *str = xstrdup(val);
}

int match_option_size(const char *prefix, size_t len,
                      char *arg, char **argopt)
{
    int rc = strncmp(prefix, arg, len);
    if (!rc) *argopt = arg+len;
    return !rc;
}

/* Parses network data and adds info into nic
 * Returns 1 if the input token does not match one of the keys
 * or parsed values are not correct. Successful parse returns 0 */
int parse_nic_config(libxl_device_nic *nic, XLU_Config **config, char *token)
{
    char *endptr, *oparg;
    int i;
    unsigned int val;

    if (MATCH_OPTION("type", token, oparg)) {
        if (!strcmp("vif", oparg)) {
            nic->nictype = LIBXL_NIC_TYPE_VIF;
        } else if (!strcmp("ioemu", oparg)) {
            nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
        } else {
            fprintf(stderr, "Invalid parameter `type'.\n");
            return 1;
        }
    } else if (MATCH_OPTION("mac", token, oparg)) {
        for (i = 0; i < 6; i++) {
            val = strtoul(oparg, &endptr, 16);
            if ((oparg == endptr) || (val > 255)) {
                fprintf(stderr, "Invalid parameter `mac'.\n");
                return 1;
            }
            nic->mac[i] = val;
            oparg = endptr + 1;
        }
    } else if (MATCH_OPTION("bridge", token, oparg)) {
        replace_string(&nic->bridge, oparg);
    } else if (MATCH_OPTION("netdev", token, oparg)) {
        fprintf(stderr, "the netdev parameter is deprecated, "
                        "please use gatewaydev instead\n");
        replace_string(&nic->gatewaydev, oparg);
    } else if (MATCH_OPTION("gatewaydev", token, oparg)) {
        replace_string(&nic->gatewaydev, oparg);
    } else if (MATCH_OPTION("ip", token, oparg)) {
        replace_string(&nic->ip, oparg);
    } else if (MATCH_OPTION("script", token, oparg)) {
        replace_string(&nic->script, oparg);
    } else if (MATCH_OPTION("backend", token, oparg)) {
        replace_string(&nic->backend_domname, oparg);
    } else if (MATCH_OPTION("vifname", token, oparg)) {
        replace_string(&nic->ifname, oparg);
    } else if (MATCH_OPTION("model", token, oparg)) {
        replace_string(&nic->model, oparg);
    } else if (MATCH_OPTION("rate", token, oparg)) {
        parse_vif_rate(config, oparg, nic);
    } else if (MATCH_OPTION("forwarddev", token, oparg)) {
        replace_string(&nic->coloft_forwarddev, oparg);
    } else if (MATCH_OPTION("colo_sock_mirror_id", token, oparg)) {
        replace_string(&nic->colo_sock_mirror_id, oparg);
    } else if (MATCH_OPTION("colo_sock_mirror_ip", token, oparg)) {
        replace_string(&nic->colo_sock_mirror_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_mirror_port", token, oparg)) {
        replace_string(&nic->colo_sock_mirror_port, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_sec_in_id", token, oparg)) {
        replace_string(&nic->colo_sock_compare_sec_in_id, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_sec_in_ip", token, oparg)) {
        replace_string(&nic->colo_sock_compare_sec_in_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_sec_in_port", token, oparg)) {
        replace_string(&nic->colo_sock_compare_sec_in_port, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector0_id", token, oparg)) {
        replace_string(&nic->colo_sock_redirector0_id, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector0_ip", token, oparg)) {
        replace_string(&nic->colo_sock_redirector0_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector0_port", token, oparg)) {
        replace_string(&nic->colo_sock_redirector0_port, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector1_id", token, oparg)) {
        replace_string(&nic->colo_sock_redirector1_id, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector1_ip", token, oparg)) {
        replace_string(&nic->colo_sock_redirector1_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector1_port", token, oparg)) {
        replace_string(&nic->colo_sock_redirector1_port, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector2_id", token, oparg)) {
        replace_string(&nic->colo_sock_redirector2_id, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector2_ip", token, oparg)) {
        replace_string(&nic->colo_sock_redirector2_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_redirector2_port", token, oparg)) {
        replace_string(&nic->colo_sock_redirector2_port, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_pri_in_id", token, oparg)) {
        replace_string(&nic->colo_sock_compare_pri_in_id, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_pri_in_ip", token, oparg)) {
        replace_string(&nic->colo_sock_compare_pri_in_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_pri_in_port", token, oparg)) {
        replace_string(&nic->colo_sock_compare_pri_in_port, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_notify_id", token, oparg)) {
        replace_string(&nic->colo_sock_compare_notify_id, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_notify_ip", token, oparg)) {
        replace_string(&nic->colo_sock_compare_notify_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_compare_notify_port", token, oparg)) {
        replace_string(&nic->colo_sock_compare_notify_port, oparg);
    } else if (MATCH_OPTION("colo_filter_mirror_queue", token, oparg)) {
        replace_string(&nic->colo_filter_mirror_queue, oparg);
    } else if (MATCH_OPTION("colo_filter_mirror_outdev", token, oparg)) {
        replace_string(&nic->colo_filter_mirror_outdev, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector0_queue", token, oparg)) {
        replace_string(&nic->colo_filter_redirector0_queue, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector0_indev", token, oparg)) {
        replace_string(&nic->colo_filter_redirector0_indev, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector0_outdev", token, oparg)) {
        replace_string(&nic->colo_filter_redirector0_outdev, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector1_queue", token, oparg)) {
        replace_string(&nic->colo_filter_redirector1_queue, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector1_indev", token, oparg)) {
        replace_string(&nic->colo_filter_redirector1_indev, oparg);
    } else if (MATCH_OPTION("colo_filter_redirector1_outdev", token, oparg)) {
        replace_string(&nic->colo_filter_redirector1_outdev, oparg);
    } else if (MATCH_OPTION("colo_compare_pri_in", token, oparg)) {
        replace_string(&nic->colo_compare_pri_in, oparg);
    } else if (MATCH_OPTION("colo_compare_sec_in", token, oparg)) {
        replace_string(&nic->colo_compare_sec_in, oparg);
    } else if (MATCH_OPTION("colo_compare_out", token, oparg)) {
        replace_string(&nic->colo_compare_out, oparg);
    } else if (MATCH_OPTION("colo_compare_notify_dev", token, oparg)) {
        replace_string(&nic->colo_compare_notify_dev, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector0_id", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector0_id, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector0_ip", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector0_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector0_port", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector0_port, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector1_id", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector1_id, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector1_ip", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector1_ip, oparg);
    } else if (MATCH_OPTION("colo_sock_sec_redirector1_port", token, oparg)) {
        replace_string(&nic->colo_sock_sec_redirector1_port, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector0_queue", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector0_queue, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector0_indev", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector0_indev, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector0_outdev", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector0_outdev, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector1_queue", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector1_queue, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector1_indev", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector1_indev, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_redirector1_outdev", token, oparg)) {
        replace_string(&nic->colo_filter_sec_redirector1_outdev, oparg);
    } else if (MATCH_OPTION("colo_filter_sec_rewriter0_queue", token, oparg)) {
        replace_string(&nic->colo_filter_sec_rewriter0_queue, oparg);
    } else if (MATCH_OPTION("colo_checkpoint_host", token, oparg)) {
        replace_string(&nic->colo_checkpoint_host, oparg);
    } else if (MATCH_OPTION("colo_checkpoint_port", token, oparg)) {
        replace_string(&nic->colo_checkpoint_port, oparg);
    } else if (MATCH_OPTION("accel", token, oparg)) {
        fprintf(stderr, "the accel parameter for vifs is currently not supported\n");
    } else if (MATCH_OPTION("devid", token, oparg)) {
        nic->devid = parse_ulong(oparg);
    } else {
        fprintf(stderr, "unrecognized argument `%s'\n", token);
        return 1;
    }
    return 0;
}

static void parse_vnuma_config(const XLU_Config *config,
                               libxl_domain_build_info *b_info)
{
    libxl_physinfo physinfo;
    uint32_t nr_nodes;
    XLU_ConfigList *vnuma;
    int i, j, len, num_vnuma;
    unsigned long max_vcpus = 0, max_memkb = 0;
    /* Temporary storage for parsed vcpus information to avoid
     * parsing config twice. This array has num_vnuma elements.
     */
    libxl_bitmap *vcpu_parsed;

    libxl_physinfo_init(&physinfo);
    if (libxl_get_physinfo(ctx, &physinfo) != 0) {
        libxl_physinfo_dispose(&physinfo);
        fprintf(stderr, "libxl_get_physinfo failed\n");
        exit(EXIT_FAILURE);
    }

    nr_nodes = physinfo.nr_nodes;
    libxl_physinfo_dispose(&physinfo);

    if (xlu_cfg_get_list(config, "vnuma", &vnuma, &num_vnuma, 1))
        return;

    if (!num_vnuma)
        return;

    b_info->num_vnuma_nodes = num_vnuma;
    b_info->vnuma_nodes = xcalloc(num_vnuma, sizeof(libxl_vnode_info));
    vcpu_parsed = xcalloc(num_vnuma, sizeof(libxl_bitmap));
    for (i = 0; i < num_vnuma; i++) {
        libxl_bitmap_init(&vcpu_parsed[i]);
        if (libxl_cpu_bitmap_alloc(ctx, &vcpu_parsed[i], b_info->max_vcpus)) {
            fprintf(stderr, "libxl_node_bitmap_alloc failed.\n");
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];

        libxl_vnode_info_init(p);
        p->distances = xcalloc(b_info->num_vnuma_nodes,
                               sizeof(*p->distances));
        p->num_distances = b_info->num_vnuma_nodes;
    }

    for (i = 0; i < num_vnuma; i++) {
        XLU_ConfigValue *vnode_spec, *conf_option;
        XLU_ConfigList *vnode_config_list;
        int conf_count;
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];

        vnode_spec = xlu_cfg_get_listitem2(vnuma, i);
        assert(vnode_spec);

        xlu_cfg_value_get_list(config, vnode_spec, &vnode_config_list, 0);
        if (!vnode_config_list) {
            fprintf(stderr, "xl: cannot get vnode config option list\n");
            exit(EXIT_FAILURE);
        }

        for (conf_count = 0;
             (conf_option =
              xlu_cfg_get_listitem2(vnode_config_list, conf_count));
             conf_count++) {

            if (xlu_cfg_value_type(conf_option) == XLU_STRING) {
                char *buf, *option_untrimmed, *value_untrimmed;
                char *option, *value;
                unsigned long val;

                xlu_cfg_value_get_string(config, conf_option, &buf, 0);

                if (!buf) continue;

                if (split_string_into_pair(buf, "=",
                                           &option_untrimmed,
                                           &value_untrimmed)) {
                    fprintf(stderr, "xl: failed to split \"%s\" into pair\n",
                            buf);
                    exit(EXIT_FAILURE);
                }
                trim(isspace, option_untrimmed, &option);
                trim(isspace, value_untrimmed, &value);

                if (!strcmp("pnode", option)) {
                    val = parse_ulong(value);
                    if (val >= nr_nodes) {
                        fprintf(stderr,
                                "xl: invalid pnode number: %lu\n", val);
                        exit(EXIT_FAILURE);
                    }
                    p->pnode = val;
                    libxl_defbool_set(&b_info->numa_placement, false);
                } else if (!strcmp("size", option)) {
                    val = parse_ulong(value);
                    p->memkb = val << 10;
                    max_memkb += p->memkb;
                } else if (!strcmp("vcpus", option)) {
                    libxl_string_list cpu_spec_list;
                    unsigned long s, e;

                    split_string_into_string_list(value, ",", &cpu_spec_list);
                    len = libxl_string_list_length(&cpu_spec_list);

                    for (j = 0; j < len; j++) {
                        parse_range(cpu_spec_list[j], &s, &e);
                        for (; s <= e; s++) {
                            /*
                             * Note that if we try to set a bit beyond
                             * the size of bitmap, libxl_bitmap_set
                             * has no effect. The resulted bitmap
                             * doesn't reflect what user wants. The
                             * fallout is dealt with later after
                             * parsing.
                             */
                            libxl_bitmap_set(&vcpu_parsed[i], s);
                            max_vcpus++;
                        }
                    }

                    libxl_string_list_dispose(&cpu_spec_list);
                } else if (!strcmp("vdistances", option)) {
                    libxl_string_list vdist;

                    split_string_into_string_list(value, ",", &vdist);
                    len = libxl_string_list_length(&vdist);

                    for (j = 0; j < len; j++) {
                        val = parse_ulong(vdist[j]);
                        p->distances[j] = val;
                    }
                    libxl_string_list_dispose(&vdist);
                }
                free(option);
                free(value);
                free(option_untrimmed);
                free(value_untrimmed);
            }
        }
    }

    /* User has specified maxvcpus= */
    if (b_info->max_vcpus != 0) {
        if (b_info->max_vcpus != max_vcpus) {
            fprintf(stderr, "xl: vnuma vcpus and maxvcpus= mismatch\n");
            exit(EXIT_FAILURE);
        }
    } else {
        int host_cpus = libxl_get_online_cpus(ctx);

        if (host_cpus < 0) {
            fprintf(stderr, "Failed to get online cpus\n");
            exit(EXIT_FAILURE);
        }

        if (host_cpus < max_vcpus) {
            fprintf(stderr, "xl: vnuma specifies more vcpus than pcpus, "\
                    "use maxvcpus= to override this check.\n");
            exit(EXIT_FAILURE);
        }

        b_info->max_vcpus = max_vcpus;
    }

    /* User has specified maxmem= */
    if (b_info->max_memkb != LIBXL_MEMKB_DEFAULT &&
        b_info->max_memkb != max_memkb) {
        fprintf(stderr, "xl: maxmem and vnuma memory size mismatch\n");
        exit(EXIT_FAILURE);
    } else
        b_info->max_memkb = max_memkb;

    for (i = 0; i < b_info->num_vnuma_nodes; i++) {
        libxl_vnode_info *p = &b_info->vnuma_nodes[i];

        libxl_bitmap_copy_alloc(ctx, &p->vcpus, &vcpu_parsed[i]);
        libxl_bitmap_dispose(&vcpu_parsed[i]);
    }

    free(vcpu_parsed);
}

/* Parses usbctrl data and adds info into usbctrl
 * Returns 1 if the input token does not match one of the keys
 * or parsed values are not correct. Successful parse returns 0 */
int parse_usbctrl_config(libxl_device_usbctrl *usbctrl, char *token)
{
    char *oparg;

    if (MATCH_OPTION("type", token, oparg)) {
        if (libxl_usbctrl_type_from_string(oparg, &usbctrl->type)) {
            fprintf(stderr, "Invalid usb controller type '%s'\n", oparg);
            return 1;
        }
    } else if (MATCH_OPTION("version", token, oparg)) {
        usbctrl->version = atoi(oparg);
    } else if (MATCH_OPTION("ports", token, oparg)) {
        usbctrl->ports = atoi(oparg);
    } else {
        fprintf(stderr, "Unknown string `%s' in usbctrl spec\n", token);
        return 1;
    }

    return 0;
}

/* Parses usbdev data and adds info into usbdev
 * Returns 1 if the input token does not match one of the keys
 * or parsed values are not correct. Successful parse returns 0 */
int parse_usbdev_config(libxl_device_usbdev *usbdev, char *token)
{
    char *oparg;

    if (MATCH_OPTION("type", token, oparg)) {
        if (libxl_usbdev_type_from_string(oparg, &usbdev->type)) {
            fprintf(stderr, "Invalid usb device type: %s\n", optarg);
            return 1;
        }
    } else if (MATCH_OPTION("hostbus", token, oparg)) {
        usbdev->u.hostdev.hostbus = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION("hostaddr", token, oparg)) {
        usbdev->u.hostdev.hostaddr = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION("controller", token, oparg)) {
        usbdev->ctrl = atoi(oparg);
    } else if (MATCH_OPTION("port", token, oparg)) {
        usbdev->port = atoi(oparg);
    } else {
        fprintf(stderr, "Unknown string `%s' in usbdev spec\n", token);
        return 1;
    }

    return 0;
}

int parse_vdispl_config(libxl_device_vdispl *vdispl, char *token)
{
    char *oparg;
    libxl_string_list connectors = NULL;
    int i;
    int rc;

    if (MATCH_OPTION("backend", token, oparg)) {
        vdispl->backend_domname = strdup(oparg);
    } else if (MATCH_OPTION("be-alloc", token, oparg)) {
        vdispl->be_alloc = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION("connectors", token, oparg)) {
        split_string_into_string_list(oparg, ";", &connectors);

        vdispl->num_connectors = libxl_string_list_length(&connectors);
        vdispl->connectors = xcalloc(vdispl->num_connectors,
                                     sizeof(*vdispl->connectors));

        for(i = 0; i < vdispl->num_connectors; i++)
        {
            char *resolution;

            rc = split_string_into_pair(connectors[i], ":",
                                        &vdispl->connectors[i].unique_id,
                                        &resolution);

            rc= sscanf(resolution, "%ux%u", &vdispl->connectors[i].width,
                       &vdispl->connectors[i].height);
            free(resolution);

            if (rc != 2) {
                fprintf(stderr, "Can't parse connector resolution\n");
                goto out;
            }
        }
    } else {
        fprintf(stderr, "Unknown string \"%s\" in vdispl spec\n", token);
        rc = 1; goto out;
    }

    rc = 0;

out:
    libxl_string_list_dispose(&connectors);
    return rc;
}

static int parse_vsnd_params(libxl_vsnd_params *params, char *token)
{
    char *oparg;
    int i;

    if (MATCH_OPTION(XENSND_FIELD_SAMPLE_RATES, token, oparg)) {
        libxl_string_list rates = NULL;

        split_string_into_string_list(oparg, ";", &rates);

        params->num_sample_rates = libxl_string_list_length(&rates);
        params->sample_rates = xcalloc(params->num_sample_rates,
                                       sizeof(*params->sample_rates));

        for (i = 0; i < params->num_sample_rates; i++) {
            params->sample_rates[i] = strtoul(rates[i], NULL, 0);
        }

        libxl_string_list_dispose(&rates);
    } else if (MATCH_OPTION(XENSND_FIELD_SAMPLE_FORMATS, token, oparg)) {
        libxl_string_list formats = NULL;

        split_string_into_string_list(oparg, ";", &formats);

        params->num_sample_formats = libxl_string_list_length(&formats);
        params->sample_formats = xcalloc(params->num_sample_formats,
                                         sizeof(*params->sample_formats));

        for (i = 0; i < params->num_sample_formats; i++) {
            libxl_vsnd_pcm_format format;

            if (libxl_vsnd_pcm_format_from_string(formats[i], &format)) {
                fprintf(stderr, "Invalid pcm format: %s\n", formats[i]);
                exit(EXIT_FAILURE);
            }

            params->sample_formats[i] = format;
        }

        libxl_string_list_dispose(&formats);
    } else if (MATCH_OPTION(XENSND_FIELD_CHANNELS_MIN, token, oparg)) {
        params->channels_min = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENSND_FIELD_CHANNELS_MAX, token, oparg)) {
        params->channels_max = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENSND_FIELD_BUFFER_SIZE, token, oparg)) {
        params->buffer_size = strtoul(oparg, NULL, 0);
    } else {
        return 1;
    }

    return 0;
}

static int parse_vsnd_pcm_stream(libxl_device_vsnd *vsnd, char *param)
{
    if (vsnd->num_vsnd_pcms == 0) {
        fprintf(stderr, "No vsnd pcm device\n");
        return -1;
    }

    libxl_vsnd_pcm *pcm = &vsnd->pcms[vsnd->num_vsnd_pcms - 1];

    if (pcm->num_vsnd_streams == 0) {
        fprintf(stderr, "No vsnd stream\n");
        return -1;
    }

    libxl_vsnd_stream *stream = &pcm->streams[pcm->num_vsnd_streams - 1];

    if (parse_vsnd_params(&stream->params, param)) {
        char *oparg;

        if (MATCH_OPTION(XENSND_FIELD_STREAM_UNIQUE_ID, param, oparg)) {
            stream->unique_id = strdup(oparg);
        } else if (MATCH_OPTION(XENSND_FIELD_TYPE, param, oparg)) {
            if (libxl_vsnd_stream_type_from_string(oparg, &stream->type)) {
                fprintf(stderr, "Invalid stream type: %s\n", oparg);
                return -1;
            }
        } else {
            fprintf(stderr, "Invalid parameter: %s\n", param);
            return -1;
        }
    }

    return 0;
}

static int parse_vsnd_pcm_param(libxl_device_vsnd *vsnd, char *param)
{
    if (vsnd->num_vsnd_pcms == 0) {
        fprintf(stderr, "No pcm device\n");
        return -1;
    }

    libxl_vsnd_pcm *pcm = &vsnd->pcms[vsnd->num_vsnd_pcms - 1];

    if (parse_vsnd_params(&pcm->params, param)) {
        char *oparg;

        if (MATCH_OPTION(XENSND_FIELD_DEVICE_NAME, param, oparg)) {
            pcm->name = strdup(oparg);
        } else {
            fprintf(stderr, "Invalid parameter: %s\n", param);
            return -1;
        }
    }

    return 0;
}

static int parse_vsnd_card_param(libxl_device_vsnd *vsnd, char *param)
{
    if (parse_vsnd_params(&vsnd->params, param)) {
        char *oparg;

        if (MATCH_OPTION("backend", param, oparg)) {
            vsnd->backend_domname = strdup(oparg);
        } else if (MATCH_OPTION(XENSND_FIELD_VCARD_SHORT_NAME, param, oparg)) {
            vsnd->short_name = strdup(oparg);
        } else if (MATCH_OPTION(XENSND_FIELD_VCARD_LONG_NAME, param, oparg)) {
            vsnd->long_name = strdup(oparg);
        } else {
            fprintf(stderr, "Invalid parameter: %s\n", param);
            return -1;
        }
    }

    return 0;
}

static int parse_vsnd_create_item(libxl_device_vsnd *vsnd, const char *key)
{
    if (strcasecmp(key, "card") == 0) {

    } else if (strcasecmp(key, "pcm") == 0) {
        ARRAY_EXTEND_INIT_NODEVID(vsnd->pcms, vsnd->num_vsnd_pcms,
                                  libxl_vsnd_pcm_init);
    } else if (strcasecmp(key, "stream") == 0) {
        if (vsnd->num_vsnd_pcms == 0) {
            ARRAY_EXTEND_INIT_NODEVID(vsnd->pcms, vsnd->num_vsnd_pcms,
                                      libxl_vsnd_pcm_init);
        }

        libxl_vsnd_pcm *pcm =  &vsnd->pcms[vsnd->num_vsnd_pcms - 1];

        ARRAY_EXTEND_INIT_NODEVID(pcm->streams, pcm->num_vsnd_streams,
                                  libxl_vsnd_stream_init);
    } else {
        fprintf(stderr, "Invalid key: %s\n", key);
        return -1;
    }

    return 0;
}

int parse_vsnd_item(libxl_device_vsnd *vsnd, const char *spec)
{
    char *buf = strdup(spec);
    char *token = strtok(buf, ",");
    char *key = NULL;
    int ret;

    while (token) {
        while (*token == ' ') token++;

        if (!key) {
            key = token;
            ret = parse_vsnd_create_item(vsnd, key);
            if (ret) goto out;
        } else {
            if (strcasecmp(key, "card") == 0) {
                ret = parse_vsnd_card_param(vsnd, token);
                if (ret) goto out;
            } else if (strcasecmp(key, "pcm") == 0) {
                ret = parse_vsnd_pcm_param(vsnd, token);
                if (ret) goto out;
            } else if (strcasecmp(key, "stream") == 0) {
                ret = parse_vsnd_pcm_stream(vsnd, token);
                if (ret) goto out;
            }
        }
        token = strtok (NULL, ",");
    }

    ret = 0;

out:
    free(buf);
    return ret;
}

static void parse_vsnd_card_config(const XLU_Config *config,
                                   XLU_ConfigValue *card_value,
                                   libxl_domain_config *d_config)
{
    int ret;
    XLU_ConfigList *card_list;
    libxl_device_vsnd *vsnd;
    const char *card_item;
    int item = 0;

    ret = xlu_cfg_value_get_list(config, card_value,  &card_list, 0);

    if (ret) {
        fprintf(stderr, "Failed to get vsnd card list: %s\n", strerror(ret));
        goto out;
    }

    vsnd = ARRAY_EXTEND_INIT(d_config->vsnds,
                             d_config->num_vsnds,
                             libxl_device_vsnd_init);

    while ((card_item = xlu_cfg_get_listitem(card_list, item++)) != NULL) {
        ret = parse_vsnd_item(vsnd, card_item);
        if (ret) goto out;
    }

    ret = 0;

out:

    if (ret) exit(EXIT_FAILURE);
}

static void parse_vsnd_config(const XLU_Config *config,
                              libxl_domain_config *d_config)
{
    XLU_ConfigList *vsnds;

    if (!xlu_cfg_get_list(config, "vsnd", &vsnds, 0, 0)) {
        XLU_ConfigValue *card_value;

        d_config->num_vsnds = 0;
        d_config->vsnds = NULL;

        while ((card_value = xlu_cfg_get_listitem2(vsnds, d_config->num_vsnds))
               != NULL) {
            parse_vsnd_card_config(config, card_value, d_config);
        }
    }
}

int parse_vkb_config(libxl_device_vkb *vkb, char *token)
{
    char *oparg;

    if (MATCH_OPTION("backend", token, oparg)) {
        vkb->backend_domname = strdup(oparg);
    } else if (MATCH_OPTION("backend-type", token, oparg)) {
        libxl_vkb_backend backend_type;
        if (libxl_vkb_backend_from_string(oparg, &backend_type)) {
            fprintf(stderr, "Unknown backend_type \"%s\" in vkb spec\n",
                            oparg);
            return -1;
        }
        vkb->backend_type = backend_type;
    } else if (MATCH_OPTION(XENKBD_FIELD_UNIQUE_ID, token, oparg)) {
        vkb->unique_id = strdup(oparg);
    } else if (MATCH_OPTION(XENKBD_FIELD_FEAT_DSBL_KEYBRD, token, oparg)) {
        vkb->feature_disable_keyboard = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_FEAT_DSBL_POINTER, token, oparg)) {
        vkb->feature_disable_pointer = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_FEAT_ABS_POINTER, token, oparg)) {
        vkb->feature_abs_pointer = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_FEAT_RAW_POINTER, token, oparg)) {
        vkb->feature_raw_pointer = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_FEAT_MTOUCH, token, oparg)) {
        vkb->feature_multi_touch = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_MT_WIDTH, token, oparg)) {
        vkb->multi_touch_width = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_MT_HEIGHT, token, oparg)) {
        vkb->multi_touch_height = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_MT_NUM_CONTACTS, token, oparg)) {
        vkb->multi_touch_num_contacts = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_WIDTH, token, oparg)) {
        vkb->width = strtoul(oparg, NULL, 0);
    } else if (MATCH_OPTION(XENKBD_FIELD_HEIGHT, token, oparg)) {
        vkb->height = strtoul(oparg, NULL, 0);
    } else {
        fprintf(stderr, "Unknown string \"%s\" in vkb spec\n", token);
        return -1;
    }

    return 0;
}

static void parse_vkb_list(const XLU_Config *config,
                           libxl_domain_config *d_config)
{
    XLU_ConfigList *vkbs;
    const char *item;
    char *buf = NULL;
    int rc;

    if (!xlu_cfg_get_list (config, "vkb", &vkbs, 0, 0)) {
        int entry = 0;
        while ((item = xlu_cfg_get_listitem(vkbs, entry)) != NULL) {
            libxl_device_vkb *vkb;
            char *p;

            vkb = ARRAY_EXTEND_INIT(d_config->vkbs,
                                    d_config->num_vkbs,
                                    libxl_device_vkb_init);

            buf = strdup(item);

            p = strtok (buf, ",");
            while (p != NULL)
            {
                while (*p == ' ') p++;

                rc = parse_vkb_config(vkb, p);
                if (rc) goto out;

                p = strtok (NULL, ",");
            }

            if (vkb->backend_type == LIBXL_VKB_BACKEND_UNKNOWN) {
                fprintf(stderr, "backend-type should be set in vkb spec\n");
                rc = ERROR_FAIL; goto out;
            }

            if (vkb->multi_touch_height || vkb->multi_touch_width ||
                vkb->multi_touch_num_contacts) {
                vkb->feature_multi_touch = true;
            }

            if (vkb->feature_multi_touch && !(vkb->multi_touch_height ||
                vkb->multi_touch_width || vkb->multi_touch_num_contacts)) {
                fprintf(stderr, XENKBD_FIELD_MT_WIDTH", "XENKBD_FIELD_MT_HEIGHT", "
                                XENKBD_FIELD_MT_NUM_CONTACTS" should be set for "
                                "multi touch in vkb spec\n");
                rc = ERROR_FAIL; goto out;
            }

            entry++;
        }
    }

    rc = 0;

out:
    free(buf);
    if (rc) exit(EXIT_FAILURE);
}

void parse_config_data(const char *config_source,
                       const char *config_data,
                       int config_len,
                       libxl_domain_config *d_config)
{
    libxl_physinfo physinfo;
    const char *buf;
    long l, vcpus = 0;
    XLU_Config *config;
    XLU_ConfigList *cpus, *vbds, *nics, *pcis, *cvfbs, *cpuids, *vtpms,
                   *usbctrls, *usbdevs, *p9devs, *vdispls, *pvcallsifs_devs;
    XLU_ConfigList *channels, *ioports, *irqs, *iomem, *viridian, *dtdevs,
                   *mca_caps;
    int num_ioports, num_irqs, num_iomem, num_cpus, num_viridian, num_mca_caps;
    int pci_power_mgmt = 0;
    int pci_msitranslate = 0;
    int pci_permissive = 0;
    int pci_seize = 0;
    int i, e;
    char *kernel_basename;

    libxl_domain_create_info *c_info = &d_config->c_info;
    libxl_domain_build_info *b_info = &d_config->b_info;

    libxl_physinfo_init(&physinfo);
    if (libxl_get_physinfo(ctx, &physinfo) != 0) {
        libxl_physinfo_dispose(&physinfo);
        fprintf(stderr, "libxl_get_physinfo failed\n");
        exit(EXIT_FAILURE);
    }

    libxl_physinfo_dispose(&physinfo);

    config= xlu_cfg_init(stderr, config_source);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        exit(1);
    }

    e= xlu_cfg_readdata(config, config_data, config_len);
    if (e) {
        fprintf(stderr, "Failed to parse config: %s\n", strerror(e));
        exit(1);
    }

    if (!xlu_cfg_get_string (config, "init_seclabel", &buf, 0))
        xlu_cfg_replace_string(config, "init_seclabel",
                               &c_info->ssid_label, 0);

    if (!xlu_cfg_get_string (config, "seclabel", &buf, 0)) {
        if (c_info->ssid_label)
            xlu_cfg_replace_string(config, "seclabel",
                                   &b_info->exec_ssid_label, 0);
        else
            xlu_cfg_replace_string(config, "seclabel",
                                   &c_info->ssid_label, 0);
    }

    libxl_defbool_set(&c_info->run_hotplug_scripts, run_hotplug_scripts);

    if (!xlu_cfg_get_string(config, "type", &buf, 0)) {
        if (!strncmp(buf, "hvm", strlen(buf)))
            c_info->type = LIBXL_DOMAIN_TYPE_HVM;
        else if (!strncmp(buf, "pv", strlen(buf)))
            c_info->type = LIBXL_DOMAIN_TYPE_PV;
        else if (!strncmp(buf, "pvh", strlen(buf)))
            c_info->type = LIBXL_DOMAIN_TYPE_PVH;
        else {
            fprintf(stderr, "Invalid domain type %s.\n", buf);
            exit(1);
        }
    }

    /* Deprecated since Xen 4.10. */
    if (!xlu_cfg_get_string(config, "builder", &buf, 0)) {
        libxl_domain_type builder_type;

        if (!strncmp(buf, "hvm", strlen(buf)))
            builder_type = LIBXL_DOMAIN_TYPE_HVM;
        else if (!strncmp(buf, "generic", strlen(buf)))
            builder_type = LIBXL_DOMAIN_TYPE_PV;
        else {
            fprintf(stderr, "Invalid domain type %s.\n", buf);
            exit(1);
        }

        if (c_info->type != LIBXL_DOMAIN_TYPE_INVALID &&
            c_info->type != builder_type) {
            fprintf(stderr,
            "Contradicting \"builder\" and \"type\" options specified.\n");
            exit(1);
        }
        c_info->type = builder_type;
    }

    if (c_info->type == LIBXL_DOMAIN_TYPE_INVALID)
#if defined(__arm__) || defined(__aarch64__)
        c_info->type = LIBXL_DOMAIN_TYPE_PVH;
#else
        c_info->type = LIBXL_DOMAIN_TYPE_PV;
#endif

    xlu_cfg_get_defbool(config, "hap", &c_info->hap, 0);

    if (xlu_cfg_replace_string (config, "name", &c_info->name, 0)) {
        fprintf(stderr, "Domain name must be specified.\n");
        exit(1);
    }

    if (!xlu_cfg_get_string (config, "uuid", &buf, 0) ) {
        if ( libxl_uuid_from_string(&c_info->uuid, buf) ) {
            fprintf(stderr, "Failed to parse UUID: %s\n", buf);
            exit(1);
        }
    }else{
        libxl_uuid_generate(&c_info->uuid);
    }

    xlu_cfg_get_defbool(config, "oos", &c_info->oos, 0);

    if (!xlu_cfg_get_string (config, "pool", &buf, 0))
        xlu_cfg_replace_string(config, "pool", &c_info->pool_name, 0);

    libxl_domain_build_info_init_type(b_info, c_info->type);

    if (b_info->type == LIBXL_DOMAIN_TYPE_PVH) {
        xlu_cfg_get_defbool(config, "pvshim", &b_info->u.pvh.pvshim, 0);
        if (!xlu_cfg_get_string(config, "pvshim_path", &buf, 0))
            xlu_cfg_replace_string(config, "pvshim_path",
                                   &b_info->u.pvh.pvshim_path, 0);
        if (!xlu_cfg_get_string(config, "pvshim_cmdline", &buf, 0))
            xlu_cfg_replace_string(config, "pvshim_cmdline",
                                   &b_info->u.pvh.pvshim_cmdline, 0);
        if (!xlu_cfg_get_string(config, "pvshim_extra", &buf, 0))
            xlu_cfg_replace_string(config, "pvshim_extra",
                                   &b_info->u.pvh.pvshim_extra, 0);
    }

    if (blkdev_start)
        b_info->blkdev_start = strdup(blkdev_start);

    /* the following is the actual config parsing with overriding
     * values in the structures */
    if (!xlu_cfg_get_long (config, "cpu_weight", &l, 0))
        b_info->sched_params.weight = l;
    if (!xlu_cfg_get_long (config, "cap", &l, 0))
        b_info->sched_params.cap = l;
    if (!xlu_cfg_get_long (config, "period", &l, 0))
        b_info->sched_params.period = l;
    if (!xlu_cfg_get_long (config, "slice", &l, 0))
        b_info->sched_params.slice = l;
    if (!xlu_cfg_get_long (config, "latency", &l, 0))
        b_info->sched_params.latency = l;
    if (!xlu_cfg_get_long (config, "extratime", &l, 0))
        b_info->sched_params.extratime = l;

    if (!xlu_cfg_get_long (config, "memory", &l, 0))
        b_info->target_memkb = l * 1024;

    if (!xlu_cfg_get_long (config, "maxmem", &l, 0))
        b_info->max_memkb = l * 1024;

    if (!xlu_cfg_get_long (config, "vcpus", &l, 0)) {
        vcpus = l;
        if (libxl_cpu_bitmap_alloc(ctx, &b_info->avail_vcpus, l)) {
            fprintf(stderr, "Unable to allocate cpumap\n");
            exit(1);
        }
        libxl_bitmap_set_none(&b_info->avail_vcpus);
        while (l-- > 0)
            libxl_bitmap_set((&b_info->avail_vcpus), l);
    }

    if (!xlu_cfg_get_long (config, "maxvcpus", &l, 0))
        b_info->max_vcpus = l;

    if (!xlu_cfg_get_string(config, "vuart", &buf, 0)) {
        if (libxl_vuart_type_from_string(buf, &b_info->arch_arm.vuart)) {
            fprintf(stderr, "ERROR: invalid value \"%s\" for \"vuart\"\n",
                    buf);
            exit(1);
        }
    }

    parse_vnuma_config(config, b_info);

    /* Set max_memkb to target_memkb and max_vcpus to avail_vcpus if
     * they are not set by user specified config option or vnuma.
     */
    if (b_info->max_memkb == LIBXL_MEMKB_DEFAULT)
        b_info->max_memkb = b_info->target_memkb;
    if (b_info->max_vcpus == 0)
        b_info->max_vcpus = vcpus;

    if (b_info->max_vcpus < vcpus) {
        fprintf(stderr, "xl: maxvcpus < vcpus\n");
        exit(1);
    }

    buf = NULL;
    if (!xlu_cfg_get_list (config, "cpus", &cpus, &num_cpus, 1) ||
        !xlu_cfg_get_string (config, "cpus", &buf, 0))
        parse_vcpu_affinity(b_info, cpus, buf, num_cpus, /* is_hard */ true);

    buf = NULL;
    if (!xlu_cfg_get_list (config, "cpus_soft", &cpus, &num_cpus, 1) ||
        !xlu_cfg_get_string (config, "cpus_soft", &buf, 0))
        parse_vcpu_affinity(b_info, cpus, buf, num_cpus, false);

    if (!xlu_cfg_get_long (config, "max_grant_frames", &l, 0))
        b_info->max_grant_frames = l;
    else
        b_info->max_grant_frames = max_grant_frames;
    if (!xlu_cfg_get_long (config, "max_maptrack_frames", &l, 0))
        b_info->max_maptrack_frames = l;
    else if (max_maptrack_frames != -1)
        b_info->max_maptrack_frames = max_maptrack_frames;

    libxl_defbool_set(&b_info->claim_mode, claim_mode);

    if (xlu_cfg_get_string (config, "on_poweroff", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_poweroff)) {
        fprintf(stderr, "Unknown on_poweroff action \"%s\" specified\n", buf);
        exit(1);
    }

    if (xlu_cfg_get_string (config, "on_reboot", &buf, 0))
        buf = "restart";
    if (!parse_action_on_shutdown(buf, &d_config->on_reboot)) {
        fprintf(stderr, "Unknown on_reboot action \"%s\" specified\n", buf);
        exit(1);
    }

    if (xlu_cfg_get_string (config, "on_watchdog", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_watchdog)) {
        fprintf(stderr, "Unknown on_watchdog action \"%s\" specified\n", buf);
        exit(1);
    }


    if (xlu_cfg_get_string (config, "on_crash", &buf, 0))
        buf = "destroy";
    if (!parse_action_on_shutdown(buf, &d_config->on_crash)) {
        fprintf(stderr, "Unknown on_crash action \"%s\" specified\n", buf);
        exit(1);
    }

    if (xlu_cfg_get_string (config, "on_soft_reset", &buf, 0))
        buf = "soft-reset";
    if (!parse_action_on_shutdown(buf, &d_config->on_soft_reset)) {
        fprintf(stderr, "Unknown on_soft_reset action \"%s\" specified\n", buf);
        exit(1);
    }

    if (!xlu_cfg_get_list (config, "pci", &pcis, 0, 0)) {
        d_config->num_pcidevs = 0;
        d_config->pcidevs = NULL;
        for(i = 0; (buf = xlu_cfg_get_listitem (pcis, i)) != NULL; i++) {
            libxl_device_pci *pcidev;

            pcidev = ARRAY_EXTEND_INIT_NODEVID(d_config->pcidevs,
                                               d_config->num_pcidevs,
                                               libxl_device_pci_init);
            pcidev->msitranslate = pci_msitranslate;
            pcidev->power_mgmt = pci_power_mgmt;
            pcidev->permissive = pci_permissive;
            pcidev->seize = pci_seize;
            /*
             * Like other pci option, the per-device policy always follows
             * the global policy by default.
             */
            pcidev->rdm_policy = b_info->u.hvm.rdm.policy;
            e = xlu_pci_parse_bdf(config, pcidev, buf);
            if (e) {
                fprintf(stderr,
                        "unable to parse PCI BDF `%s' for passthrough\n",
                        buf);
                exit(-e);
            }
        }
        if (d_config->num_pcidevs && c_info->type == LIBXL_DOMAIN_TYPE_PV)
            libxl_defbool_set(&b_info->u.pv.e820_host, true);
    }

    if (!xlu_cfg_get_list (config, "dtdev", &dtdevs, 0, 0)) {
        d_config->num_dtdevs = 0;
        d_config->dtdevs = NULL;
        for (i = 0; (buf = xlu_cfg_get_listitem(dtdevs, i)) != NULL; i++) {
            libxl_device_dtdev *dtdev;

            dtdev = ARRAY_EXTEND_INIT_NODEVID(d_config->dtdevs,
                                              d_config->num_dtdevs,
                                              libxl_device_dtdev_init);

            dtdev->path = strdup(buf);
            if (dtdev->path == NULL) {
                fprintf(stderr, "unable to duplicate string for dtdevs\n");
                exit(-1);
            }
        }
    }

    if (!xlu_cfg_get_string(config, "passthrough", &buf, 0)) {
        if (libxl_passthrough_from_string(buf, &c_info->passthrough)) {
            fprintf(stderr,
                    "ERROR: unknown passthrough option '%s'\n",
                    buf);
            exit(1);
        }
    }

    if (!xlu_cfg_get_long(config, "shadow_memory", &l, 0))
        b_info->shadow_memkb = l * 1024;

    xlu_cfg_get_defbool(config, "nomigrate", &b_info->disable_migrate, 0);

    if (!xlu_cfg_get_long(config, "tsc_mode", &l, 1)) {
        const char *s = libxl_tsc_mode_to_string(l);
        fprintf(stderr, "WARNING: specifying \"tsc_mode\" as an integer is deprecated. "
                "Please use the named parameter variant. %s%s%s\n",
                s ? "e.g. tsc_mode=\"" : "",
                s ? s : "",
                s ? "\"" : "");

        if (l < LIBXL_TSC_MODE_DEFAULT ||
            l > LIBXL_TSC_MODE_NATIVE_PARAVIRT) {
            fprintf(stderr, "ERROR: invalid value %ld for \"tsc_mode\"\n", l);
            exit (1);
        }
        b_info->tsc_mode = l;
    } else if (!xlu_cfg_get_string(config, "tsc_mode", &buf, 0)) {
        fprintf(stderr, "got a tsc mode string: \"%s\"\n", buf);
        if (libxl_tsc_mode_from_string(buf, &b_info->tsc_mode)) {
            fprintf(stderr, "ERROR: invalid value \"%s\" for \"tsc_mode\"\n",
                    buf);
            exit (1);
        }
    }

    if (!xlu_cfg_get_long(config, "rtc_timeoffset", &l, 0))
        b_info->rtc_timeoffset = l;

    if (!xlu_cfg_get_long(config, "vncviewer", &l, 0))
        fprintf(stderr, "WARNING: ignoring \"vncviewer\" option. "
                "Use \"-V\" option of \"xl create\" to automatically spawn vncviewer.\n");

    xlu_cfg_get_defbool(config, "localtime", &b_info->localtime, 0);

    if (!xlu_cfg_get_long (config, "videoram", &l, 0))
        b_info->video_memkb = l * 1024;

    if (!xlu_cfg_get_long(config, "max_event_channels", &l, 0))
        b_info->event_channels = l;

    xlu_cfg_replace_string (config, "kernel", &b_info->kernel, 0);
    xlu_cfg_replace_string (config, "ramdisk", &b_info->ramdisk, 0);
    xlu_cfg_replace_string (config, "device_tree", &b_info->device_tree, 0);
    b_info->cmdline = parse_cmdline(config);

    xlu_cfg_get_defbool(config, "driver_domain", &c_info->driver_domain, 0);
    xlu_cfg_get_defbool(config, "acpi", &b_info->acpi, 0);

    xlu_cfg_replace_string (config, "bootloader", &b_info->bootloader, 0);
    switch (xlu_cfg_get_list_as_string_list(config, "bootloader_args",
                                            &b_info->bootloader_args, 1)) {
    case 0:
        break; /* Success */
    case ESRCH: break; /* Option not present */
    case EINVAL:
        if (!xlu_cfg_get_string(config, "bootloader_args", &buf, 0)) {

            fprintf(stderr, "WARNING: Specifying \"bootloader_args\""
                    " as a string is deprecated. "
                    "Please use a list of arguments.\n");
            split_string_into_string_list(buf, " \t\n",
                                          &b_info->bootloader_args);
        }
        break;
    default:
        fprintf(stderr,"xl: Unable to parse bootloader_args.\n");
        exit(-ERROR_FAIL);
    }

    if (!xlu_cfg_get_long(config, "timer_mode", &l, 1)) {
        const char *s = libxl_timer_mode_to_string(l);

        if (b_info->type == LIBXL_DOMAIN_TYPE_PV) {
            fprintf(stderr,
            "ERROR: \"timer_mode\" option is not supported for PV guests.\n");
            exit(-ERROR_FAIL);
        }

        fprintf(stderr,
        "WARNING: specifying \"timer_mode\" as an integer is deprecated. "
        "Please use the named parameter variant. %s%s%s\n",
                s ? "e.g. timer_mode=\"" : "",
                s ? s : "",
                s ? "\"" : "");

        if (l < LIBXL_TIMER_MODE_DELAY_FOR_MISSED_TICKS ||
            l > LIBXL_TIMER_MODE_ONE_MISSED_TICK_PENDING) {
            fprintf(stderr, "ERROR: invalid value %ld for \"timer_mode\"\n",
                    l);
            exit (1);
        }
        b_info->timer_mode = l;
    } else if (!xlu_cfg_get_string(config, "timer_mode", &buf, 0)) {
        if (b_info->type == LIBXL_DOMAIN_TYPE_PV) {
            fprintf(stderr,
            "ERROR: \"timer_mode\" option is not supported for PV guests.\n");
            exit(-ERROR_FAIL);
        }

        if (libxl_timer_mode_from_string(buf, &b_info->timer_mode)) {
            fprintf(stderr,
                    "ERROR: invalid value \"%s\" for \"timer_mode\"\n", buf);
            exit (1);
        }
    }

    xlu_cfg_get_defbool(config, "nestedhvm", &b_info->nested_hvm, 0);

    switch(b_info->type) {
    case LIBXL_DOMAIN_TYPE_HVM:
        kernel_basename = libxl_basename(b_info->kernel);
        if (!strcmp(kernel_basename, "hvmloader")) {
            fprintf(stderr, "WARNING: you seem to be using \"kernel\" "
                    "directive to override HVM guest firmware. Ignore "
                    "that. Use \"firmware_override\" instead if you "
                    "really want a non-default firmware\n");
            b_info->kernel = NULL;
        }
        free(kernel_basename);

        xlu_cfg_replace_string (config, "firmware_override",
                                &b_info->u.hvm.firmware, 0);
        xlu_cfg_replace_string (config, "bios_path_override",
                                &b_info->u.hvm.system_firmware, 0);
        if (!xlu_cfg_get_string(config, "bios", &buf, 0)) {
            if (libxl_bios_type_from_string(buf, &b_info->u.hvm.bios)) {
                fprintf(stderr, "ERROR: invalid value \"%s\" for \"bios\"\n",
                    buf);
                exit (1);
            }
        } else if (b_info->u.hvm.system_firmware)
            fprintf(stderr, "WARNING: "
                    "bios_path_override given without specific bios name\n");

        xlu_cfg_get_defbool(config, "pae", &b_info->u.hvm.pae, 0);
        xlu_cfg_get_defbool(config, "acpi_s3", &b_info->u.hvm.acpi_s3, 0);
        xlu_cfg_get_defbool(config, "acpi_s4", &b_info->u.hvm.acpi_s4, 0);
        xlu_cfg_get_defbool(config, "acpi_laptop_slate", &b_info->u.hvm.acpi_laptop_slate, 0);
        xlu_cfg_get_defbool(config, "nx", &b_info->u.hvm.nx, 0);
        xlu_cfg_get_defbool(config, "hpet", &b_info->u.hvm.hpet, 0);
        xlu_cfg_get_defbool(config, "vpt_align", &b_info->u.hvm.vpt_align, 0);
        xlu_cfg_get_defbool(config, "apic", &b_info->apic, 0);

        switch (xlu_cfg_get_list(config, "viridian",
                                 &viridian, &num_viridian, 1))
        {
        case 0: /* Success */
            if (num_viridian) {
                libxl_bitmap_alloc(ctx, &b_info->u.hvm.viridian_enable,
                                   LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH);
                libxl_bitmap_alloc(ctx, &b_info->u.hvm.viridian_disable,
                                   LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH);
            }
            for (i = 0; i < num_viridian; i++) {
                libxl_viridian_enlightenment v;

                buf = xlu_cfg_get_listitem(viridian, i);
                if (strcmp(buf, "all") == 0)
                    libxl_bitmap_set_any(&b_info->u.hvm.viridian_enable);
                else if (strcmp(buf, "defaults") == 0)
                    libxl_defbool_set(&b_info->u.hvm.viridian, true);
                else {
                    libxl_bitmap *s = &b_info->u.hvm.viridian_enable;
                    libxl_bitmap *r = &b_info->u.hvm.viridian_disable;

                    if (*buf == '!') {
                        s = &b_info->u.hvm.viridian_disable;
                        r = &b_info->u.hvm.viridian_enable;
                        buf++;
                    }

                    e = libxl_viridian_enlightenment_from_string(buf, &v);
                    if (e) {
                        fprintf(stderr,
                                "xl: unknown viridian enlightenment '%s'\n",
                                buf);
                        exit(-ERROR_FAIL);
                    }

                    libxl_bitmap_set(s, v);
                    libxl_bitmap_reset(r, v);
                }
            }
            break;
        case ESRCH: break; /* Option not present */
        case EINVAL:
            xlu_cfg_get_defbool(config, "viridian", &b_info->u.hvm.viridian, 1);
            break;
        default:
            fprintf(stderr,"xl: Unable to parse viridian enlightenments.\n");
            exit(-ERROR_FAIL);
        }

        if (!xlu_cfg_get_long(config, "mmio_hole", &l, 0)) {
            uint64_t mmio_hole_size;

            b_info->u.hvm.mmio_hole_memkb = l * 1024;
            mmio_hole_size = b_info->u.hvm.mmio_hole_memkb * 1024;
            if (mmio_hole_size < HVM_BELOW_4G_MMIO_LENGTH ||
                mmio_hole_size > HVM_BELOW_4G_MMIO_START) {
                fprintf(stderr,
                        "ERROR: invalid value %ld for \"mmio_hole\"\n", l);
                exit (1);
            }
        }

        if (!xlu_cfg_get_defbool(config, "altp2mhvm", &b_info->u.hvm.altp2m, 0))
            fprintf(stderr, "WARNING: Specifying \"altp2mhvm\" is deprecated. "
                    "Please use \"altp2m\" instead.\n");

        xlu_cfg_replace_string(config, "smbios_firmware",
                               &b_info->u.hvm.smbios_firmware, 0);
        xlu_cfg_replace_string(config, "acpi_firmware",
                               &b_info->u.hvm.acpi_firmware, 0);

        if (!xlu_cfg_get_string(config, "ms_vm_genid", &buf, 0)) {
            if (!strcmp(buf, "generate")) {
                e = libxl_ms_vm_genid_generate(ctx, &b_info->u.hvm.ms_vm_genid);
                if (e) {
                    fprintf(stderr, "ERROR: failed to generate a VM Generation ID\n");
                    exit(1);
                }
            } else if (!strcmp(buf, "none")) {
                ;
            } else {
                    fprintf(stderr, "ERROR: \"ms_vm_genid\" option must be \"generate\" or \"none\"\n");
                    exit(1);
            }
        }

        if (!xlu_cfg_get_long (config, "rdm_mem_boundary", &l, 0))
            b_info->u.hvm.rdm_mem_boundary_memkb = l * 1024;

        switch (xlu_cfg_get_list(config, "mca_caps",
                                 &mca_caps, &num_mca_caps, 1))
        {
        case 0: /* Success */
            for (i = 0; i < num_mca_caps; i++) {
                buf = xlu_cfg_get_listitem(mca_caps, i);
                if (!strcmp(buf, "lmce"))
                    b_info->u.hvm.mca_caps |= XEN_HVM_MCA_CAP_LMCE;
                else {
                    fprintf(stderr, "ERROR: unrecognized MCA capability '%s'.\n",
                            buf);
                    exit(-ERROR_FAIL);
                }
            }
            break;

        case ESRCH: /* Option not present */
            break;

        default:
            fprintf(stderr, "ERROR: unable to parse mca_caps.\n");
            exit(-ERROR_FAIL);
        }

        /*
         * The firmware config option can be used as a simplification
         * instead of setting bios or firmware_override. It has the
         * following meanings for HVM guests:
         *
         *  - ovmf | seabios | rombios: maps directly into the "bios"
         *    option.
         *  - uefi | bios: maps into one of the above options and is set
         *    in the bios field.
         *  - Anything else is treated as a path that is copied into
         *    firmware.
         */
        if (!xlu_cfg_get_string (config, "firmware", &buf, 0) &&
            libxl_bios_type_from_string(buf, &b_info->u.hvm.bios)) {
            if (!strncmp(buf, "uefi", strlen(buf)))
                b_info->u.hvm.bios = LIBXL_BIOS_TYPE_OVMF;
            else if (strncmp(buf, "bios", strlen(buf)))
                /* Assume it's a path to a custom firmware. */
                xlu_cfg_replace_string(config, "firmware",
                                       &b_info->u.hvm.firmware, 0);
            /*
             * BIOS is the default, and will be chosen by libxl based on
             * the device model specified.
             */
        }

        break;
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_PV:
    {
        /*
         * The firmware config option can be used as a simplification
         * instead of directly setting kernel. It will be translated to
         * XENFIRMWAREDIR/<string>.bin
         */
        if (!xlu_cfg_get_string (config, "firmware", &buf, 0)) {
            if (b_info->kernel) {
                fprintf(stderr,
                        "ERROR: both kernel and firmware specified\n");
                exit(1);
            }
            if (strncmp(buf, "pvgrub32", strlen(buf)) &&
                strncmp(buf, "pvgrub64", strlen(buf))) {
                fprintf(stderr,
            "ERROR: only pvgrub{32|64} supported as firmware options\n");
                exit(1);
            }

            xasprintf(&b_info->kernel, XENFIRMWAREDIR "/%s.bin", buf);
        }
        if (!b_info->bootloader && !b_info->kernel) {
            fprintf(stderr, "Neither kernel nor bootloader specified\n");
            exit(1);
        }

        break;
    }
    default:
        abort();
    }

    if (!xlu_cfg_get_long(config, "altp2m", &l, 1)) {
        if (l < LIBXL_ALTP2M_MODE_DISABLED ||
            l > LIBXL_ALTP2M_MODE_LIMITED) {
            fprintf(stderr, "ERROR: invalid value %ld for \"altp2m\"\n", l);
            exit (1);
        }

        b_info->altp2m = l;
    } else if (!xlu_cfg_get_string(config, "altp2m", &buf, 0)) {
        if (libxl_altp2m_mode_from_string(buf, &b_info->altp2m)) {
            fprintf(stderr, "ERROR: invalid value \"%s\" for \"altp2m\"\n",
                    buf);
            exit (1);
        }
    }

    if (!xlu_cfg_get_list(config, "ioports", &ioports, &num_ioports, 0)) {
        b_info->num_ioports = num_ioports;
        b_info->ioports = calloc(num_ioports, sizeof(*b_info->ioports));
        if (b_info->ioports == NULL) {
            fprintf(stderr, "unable to allocate memory for ioports\n");
            exit(-1);
        }

        for (i = 0; i < num_ioports; i++) {
            const char *buf2;
            char *ep;
            uint32_t start, end;
            unsigned long ul;

            buf = xlu_cfg_get_listitem (ioports, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element #%d in ioport list\n", i);
                exit(1);
            }
            ul = strtoul(buf, &ep, 16);
            if (ep == buf) {
                fprintf(stderr, "xl: Invalid argument parsing ioport: %s\n",
                        buf);
                exit(1);
            }
            if (ul >= UINT32_MAX) {
                fprintf(stderr, "xl: ioport %lx too big\n", ul);
                exit(1);
            }
            start = end = ul;

            if (*ep == '-') {
                buf2 = ep + 1;
                ul = strtoul(buf2, &ep, 16);
                if (ep == buf2 || *ep != '\0' || start > end) {
                    fprintf(stderr,
                            "xl: Invalid argument parsing ioport: %s\n", buf);
                    exit(1);
                }
                if (ul >= UINT32_MAX) {
                    fprintf(stderr, "xl: ioport %lx too big\n", ul);
                    exit(1);
                }
                end = ul;
            } else if ( *ep != '\0' )
                fprintf(stderr,
                        "xl: Invalid argument parsing ioport: %s\n", buf);
            b_info->ioports[i].first = start;
            b_info->ioports[i].number = end - start + 1;
        }
    }

    if (!xlu_cfg_get_list(config, "irqs", &irqs, &num_irqs, 0)) {
        b_info->num_irqs = num_irqs;
        b_info->irqs = calloc(num_irqs, sizeof(*b_info->irqs));
        if (b_info->irqs == NULL) {
            fprintf(stderr, "unable to allocate memory for ioports\n");
            exit(-1);
        }
        for (i = 0; i < num_irqs; i++) {
            char *ep;
            unsigned long ul;
            buf = xlu_cfg_get_listitem (irqs, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element %d in irq list\n", i);
                exit(1);
            }
            ul = strtoul(buf, &ep, 10);
            if (ep == buf || *ep != '\0') {
                fprintf(stderr,
                        "xl: Invalid argument parsing irq: %s\n", buf);
                exit(1);
            }
            if (ul >= UINT32_MAX) {
                fprintf(stderr, "xl: irq %lx too big\n", ul);
                exit(1);
            }
            b_info->irqs[i] = ul;
        }
    }

    if (!xlu_cfg_get_list(config, "iomem", &iomem, &num_iomem, 0)) {
        int ret;
        b_info->num_iomem = num_iomem;
        b_info->iomem = calloc(num_iomem, sizeof(*b_info->iomem));
        if (b_info->iomem == NULL) {
            fprintf(stderr, "unable to allocate memory for iomem\n");
            exit(-1);
        }
        for (i = 0; i < num_iomem; i++) {
            int used;

            buf = xlu_cfg_get_listitem (iomem, i);
            if (!buf) {
                fprintf(stderr,
                        "xl: Unable to get element %d in iomem list\n", i);
                exit(1);
            }
            libxl_iomem_range_init(&b_info->iomem[i]);
            ret = sscanf(buf, "%" SCNx64",%" SCNx64"%n@%" SCNx64"%n",
                         &b_info->iomem[i].start,
                         &b_info->iomem[i].number, &used,
                         &b_info->iomem[i].gfn, &used);
            if (ret < 2 || buf[used] != '\0') {
                fprintf(stderr,
                        "xl: Invalid argument parsing iomem: %s\n", buf);
                exit(1);
            }
        }
    }



    if (!xlu_cfg_get_list (config, "disk", &vbds, 0, 0)) {
        d_config->num_disks = 0;
        d_config->disks = NULL;
        while ((buf = xlu_cfg_get_listitem (vbds, d_config->num_disks)) != NULL) {
            libxl_device_disk *disk;
            char *buf2 = strdup(buf);

            disk = ARRAY_EXTEND_INIT_NODEVID(d_config->disks,
                                             d_config->num_disks,
                                             libxl_device_disk_init);
            parse_disk_config(&config, buf2, disk);

            free(buf2);
        }
    }

    if (!xlu_cfg_get_list(config, "p9", &p9devs, 0, 0)) {
        libxl_device_p9 *p9;
        char *security_model = NULL;
        char *path = NULL;
        char *tag = NULL;
        char *backend = NULL;
        char *p, *p2, *buf2;

        d_config->num_p9s = 0;
        d_config->p9s = NULL;
        while ((buf = xlu_cfg_get_listitem (p9devs, d_config->num_p9s)) != NULL) {
            p9 = ARRAY_EXTEND_INIT(d_config->p9s,
                                   d_config->num_p9s,
                                   libxl_device_p9_init);
            libxl_device_p9_init(p9);

            buf2 = strdup(buf);
            p = strtok(buf2, ",");
            if(p) {
               do {
                  while(*p == ' ')
                     ++p;
                  if ((p2 = strchr(p, '=')) == NULL)
                     break;
                  *p2 = '\0';
                  if (!strcmp(p, "security_model")) {
                     security_model = strdup(p2 + 1);
                  } else if(!strcmp(p, "path")) {
                     path = strdup(p2 + 1);
                  } else if(!strcmp(p, "tag")) {
                     tag = strdup(p2 + 1);
                  } else if(!strcmp(p, "backend")) {
                     backend = strdup(p2 + 1);
                  } else {
                     fprintf(stderr, "Unknown string `%s' in 9pfs spec\n", p);
                     exit(1);
                  }
               } while ((p = strtok(NULL, ",")) != NULL);
            }
            if (!path || !security_model || !tag) {
               fprintf(stderr, "9pfs spec missing required field!\n");
               exit(1);
            }
            free(buf2);

            replace_string(&p9->tag, tag);
            replace_string(&p9->security_model, security_model);
            replace_string(&p9->path, path);
            if (backend)
                    replace_string(&p9->backend_domname, backend);
        }
    }

    if (!xlu_cfg_get_list(config, "vtpm", &vtpms, 0, 0)) {
        d_config->num_vtpms = 0;
        d_config->vtpms = NULL;
        while ((buf = xlu_cfg_get_listitem (vtpms, d_config->num_vtpms)) != NULL) {
            libxl_device_vtpm *vtpm;
            char * buf2 = strdup(buf);
            char *p, *p2;
            bool got_backend = false;

            vtpm = ARRAY_EXTEND_INIT(d_config->vtpms,
                                     d_config->num_vtpms,
                                     libxl_device_vtpm_init);

            p = strtok(buf2, ",");
            if(p) {
               do {
                  while(*p == ' ')
                     ++p;
                  if ((p2 = strchr(p, '=')) == NULL)
                     break;
                  *p2 = '\0';
                  if (!strcmp(p, "backend")) {
                     vtpm->backend_domname = strdup(p2 + 1);
                     got_backend = true;
                  } else if(!strcmp(p, "uuid")) {
                     if( libxl_uuid_from_string(&vtpm->uuid, p2 + 1) ) {
                        fprintf(stderr,
                              "Failed to parse vtpm UUID: %s\n", p2 + 1);
                        exit(1);
                    }
                  } else {
                     fprintf(stderr, "Unknown string `%s' in vtpm spec\n", p);
                     exit(1);
                  }
               } while ((p = strtok(NULL, ",")) != NULL);
            }
            if(!got_backend) {
               fprintf(stderr, "vtpm spec missing required backend field!\n");
               exit(1);
            }
            free(buf2);
        }
    }

    if (!xlu_cfg_get_list(config, "vdispl", &vdispls, 0, 0)) {
        d_config->num_vdispls = 0;
        d_config->vdispls = NULL;
        while ((buf = xlu_cfg_get_listitem(vdispls, d_config->num_vdispls)) != NULL) {
            libxl_device_vdispl *vdispl;
            char * buf2 = strdup(buf);
            char *p;
            vdispl = ARRAY_EXTEND_INIT(d_config->vdispls,
                                       d_config->num_vdispls,
                                       libxl_device_vdispl_init);
            p = strtok (buf2, ",");
            while (p != NULL)
            {
                while (*p == ' ') p++;
                if (parse_vdispl_config(vdispl, p)) {
                    free(buf2);
                    exit(1);
                }
                p = strtok (NULL, ",");
            }
            free(buf2);
            if (vdispl->num_connectors == 0) {
                fprintf(stderr, "At least one connector should be specified.\n");
                exit(1);
            }
        }
    }

    if (!xlu_cfg_get_list(config, "pvcalls", &pvcallsifs_devs, 0, 0)) {
        d_config->num_pvcallsifs = 0;
        d_config->pvcallsifs = NULL;
        while ((buf = xlu_cfg_get_listitem (pvcallsifs_devs, d_config->num_pvcallsifs)) != NULL) {
            libxl_device_pvcallsif *pvcallsif;
            char *backend = NULL;
            char *p, *p2, *buf2;
            pvcallsif = ARRAY_EXTEND_INIT(d_config->pvcallsifs,
                                          d_config->num_pvcallsifs,
                                          libxl_device_pvcallsif_init);

            buf2 = strdup(buf);
            p = strtok(buf2, ",");
            if (p) {
               do {
                  while (*p == ' ')
                     ++p;
                  if ((p2 = strchr(p, '=')) == NULL)
                     break;
                  *p2 = '\0';
                  if(!strcmp(p, "backend")) {
                     backend = strdup(p2 + 1);
                  } else {
                     fprintf(stderr, "Unknown string `%s' in pvcalls spec\n", p);
                     exit(1);
                  }
               } while ((p = strtok(NULL, ",")) != NULL);
            }
            free(buf2);

            if (backend)
                    replace_string(&pvcallsif->backend_domname, backend);
        }
    }

    parse_vsnd_config(config, d_config);

    if (!xlu_cfg_get_list (config, "channel", &channels, 0, 0)) {
        d_config->num_channels = 0;
        d_config->channels = NULL;
        while ((buf = xlu_cfg_get_listitem (channels,
                d_config->num_channels)) != NULL) {
            libxl_device_channel *chn;
            libxl_string_list pairs;
            char *path = NULL;
            int len;

            chn = ARRAY_EXTEND_INIT(d_config->channels, d_config->num_channels,
                                   libxl_device_channel_init);

            split_string_into_string_list(buf, ",", &pairs);
            len = libxl_string_list_length(&pairs);
            for (i = 0; i < len; i++) {
                char *key, *key_untrimmed, *value, *value_untrimmed;
                int rc;
                rc = split_string_into_pair(pairs[i], "=",
                                            &key_untrimmed,
                                            &value_untrimmed);
                if (rc != 0) {
                    fprintf(stderr, "failed to parse channel configuration: %s",
                            pairs[i]);
                    exit(1);
                }
                trim(isspace, key_untrimmed, &key);
                trim(isspace, value_untrimmed, &value);

                if (!strcmp(key, "backend")) {
                    replace_string(&chn->backend_domname, value);
                } else if (!strcmp(key, "name")) {
                    replace_string(&chn->name, value);
                } else if (!strcmp(key, "path")) {
                    replace_string(&path, value);
                } else if (!strcmp(key, "connection")) {
                    if (!strcmp(value, "pty")) {
                        chn->connection = LIBXL_CHANNEL_CONNECTION_PTY;
                    } else if (!strcmp(value, "socket")) {
                        chn->connection = LIBXL_CHANNEL_CONNECTION_SOCKET;
                    } else {
                        fprintf(stderr, "unknown channel connection '%s'\n",
                                value);
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "unknown channel parameter '%s',"
                                  " ignoring\n", key);
                }
                free(key);
                free(key_untrimmed);
                free(value);
                free(value_untrimmed);
            }
            switch (chn->connection) {
            case LIBXL_CHANNEL_CONNECTION_UNKNOWN:
                fprintf(stderr, "channel has unknown 'connection'\n");
                exit(1);
            case LIBXL_CHANNEL_CONNECTION_SOCKET:
                if (!path) {
                    fprintf(stderr, "channel connection 'socket' requires path=..\n");
                    exit(1);
                }
                chn->u.socket.path = xstrdup(path);
                break;
            case LIBXL_CHANNEL_CONNECTION_PTY:
                /* Nothing to do since PTY has no arguments */
                break;
            default:
                fprintf(stderr, "unknown channel connection: %d",
                        chn->connection);
                exit(1);
            }
            libxl_string_list_dispose(&pairs);
            free(path);
        }
    }

    if (!xlu_cfg_get_list (config, "vif", &nics, 0, 0)) {
        d_config->num_nics = 0;
        d_config->nics = NULL;
        while ((buf = xlu_cfg_get_listitem (nics, d_config->num_nics)) != NULL) {
            libxl_device_nic *nic;
            char *buf2 = strdup(buf);
            char *p;

            nic = ARRAY_EXTEND_INIT(d_config->nics,
                                    d_config->num_nics,
                                    libxl_device_nic_init);
            set_default_nic_values(nic);

            p = strtok(buf2, ",");
            if (!p)
                goto skip_nic;
            do {
                while (*p == ' ')
                    p++;
                parse_nic_config(nic, &config, p);
            } while ((p = strtok(NULL, ",")) != NULL);
skip_nic:
            free(buf2);
        }
    }

    if (!xlu_cfg_get_list(config, "vif2", NULL, 0, 0)) {
        fprintf(stderr, "WARNING: vif2: netchannel2 is deprecated and not supported by xl\n");
    }

    d_config->num_vfbs = 0;
    d_config->num_vkbs = 0;
    d_config->vfbs = NULL;
    d_config->vkbs = NULL;

    if (!xlu_cfg_get_list (config, "vfb", &cvfbs, 0, 0)) {
        while ((buf = xlu_cfg_get_listitem (cvfbs, d_config->num_vfbs)) != NULL) {
            libxl_device_vfb *vfb;
            libxl_device_vkb *vkb;

            char *buf2 = strdup(buf);
            char *p, *p2;

            vfb = ARRAY_EXTEND_INIT(d_config->vfbs, d_config->num_vfbs,
                                    libxl_device_vfb_init);

            vkb = ARRAY_EXTEND_INIT(d_config->vkbs, d_config->num_vkbs,
                                    libxl_device_vkb_init);

            p = strtok(buf2, ",");
            if (!p)
                goto skip_vfb;
            do {
                while (*p == ' ')
                    p++;
                if ((p2 = strchr(p, '=')) == NULL)
                    break;
                *p2 = '\0';
                if (!strcmp(p, "vnc")) {
                    libxl_defbool_set(&vfb->vnc.enable, atoi(p2 + 1));
                } else if (!strcmp(p, "vnclisten")) {
                    free(vfb->vnc.listen);
                    vfb->vnc.listen = strdup(p2 + 1);
                } else if (!strcmp(p, "vncpasswd")) {
                    free(vfb->vnc.passwd);
                    vfb->vnc.passwd = strdup(p2 + 1);
                } else if (!strcmp(p, "vncdisplay")) {
                    vfb->vnc.display = atoi(p2 + 1);
                } else if (!strcmp(p, "vncunused")) {
                    libxl_defbool_set(&vfb->vnc.findunused, atoi(p2 + 1));
                } else if (!strcmp(p, "keymap")) {
                    free(vfb->keymap);
                    vfb->keymap = strdup(p2 + 1);
                } else if (!strcmp(p, "sdl")) {
                    libxl_defbool_set(&vfb->sdl.enable, atoi(p2 + 1));
                } else if (!strcmp(p, "opengl")) {
                    libxl_defbool_set(&vfb->sdl.opengl, atoi(p2 + 1));
                } else if (!strcmp(p, "display")) {
                    free(vfb->sdl.display);
                    vfb->sdl.display = strdup(p2 + 1);
                } else if (!strcmp(p, "xauthority")) {
                    free(vfb->sdl.xauthority);
                    vfb->sdl.xauthority = strdup(p2 + 1);
                }
            } while ((p = strtok(NULL, ",")) != NULL);

skip_vfb:
            free(buf2);
        }
    }

    if (!xlu_cfg_get_long (config, "pci_msitranslate", &l, 0))
        pci_msitranslate = l;

    if (!xlu_cfg_get_long (config, "pci_power_mgmt", &l, 0))
        pci_power_mgmt = l;

    if (!xlu_cfg_get_long (config, "pci_permissive", &l, 0))
        pci_permissive = l;

    if (!xlu_cfg_get_long (config, "pci_seize", &l, 0))
        pci_seize = l;

    /* To be reworked (automatically enabled) once the auto ballooning
     * after guest starts is done (with PCI devices passed in). */
    if (c_info->type == LIBXL_DOMAIN_TYPE_PV) {
        xlu_cfg_get_defbool(config, "e820_host", &b_info->u.pv.e820_host, 0);
    }

    if (!xlu_cfg_get_string(config, "rdm", &buf, 0)) {
        libxl_rdm_reserve rdm;
        if (!xlu_rdm_parse(config, &rdm, buf)) {
            b_info->u.hvm.rdm.strategy = rdm.strategy;
            b_info->u.hvm.rdm.policy = rdm.policy;
        }
    }

    if (!xlu_cfg_get_list(config, "usbctrl", &usbctrls, 0, 0)) {
        d_config->num_usbctrls = 0;
        d_config->usbctrls = NULL;
        while ((buf = xlu_cfg_get_listitem(usbctrls, d_config->num_usbctrls))
               != NULL) {
            libxl_device_usbctrl *usbctrl;
            char *buf2 = strdup(buf);
            char *p;

            usbctrl = ARRAY_EXTEND_INIT(d_config->usbctrls,
                                        d_config->num_usbctrls,
                                        libxl_device_usbctrl_init);
            p = strtok(buf2, ",");
            if (!p)
                goto skip_usbctrl;
            do {
                while (*p == ' ')
                    p++;
                if (parse_usbctrl_config(usbctrl, p))
                    exit(1);
            } while ((p = strtok(NULL, ",")) != NULL);
skip_usbctrl:
            free(buf2);
        }
    }

    if (!xlu_cfg_get_list(config, "usbdev", &usbdevs, 0, 0)) {
        d_config->num_usbdevs = 0;
        d_config->usbdevs = NULL;
        while ((buf = xlu_cfg_get_listitem(usbdevs, d_config->num_usbdevs))
               != NULL) {
            libxl_device_usbdev *usbdev;
            char *buf2 = strdup(buf);
            char *p;

            usbdev = ARRAY_EXTEND_INIT_NODEVID(d_config->usbdevs,
                                               d_config->num_usbdevs,
                                               libxl_device_usbdev_init);
            p = strtok(buf2, ",");
            if (!p)
                goto skip_usbdev;
            do {
                while (*p == ' ')
                    p++;
                if (parse_usbdev_config(usbdev, p))
                    exit(1);
            } while ((p = strtok(NULL, ",")) != NULL);
skip_usbdev:
            free(buf2);
        }
    }

    switch (xlu_cfg_get_list(config, "cpuid", &cpuids, 0, 1)) {
    case 0:
        {
            const char *errstr;

            for (i = 0; (buf = xlu_cfg_get_listitem(cpuids, i)) != NULL; i++) {
                e = libxl_cpuid_parse_config_xend(&b_info->cpuid, buf);
                switch (e) {
                case 0: continue;
                case 1:
                    errstr = "illegal leaf number";
                    break;
                case 2:
                    errstr = "illegal subleaf number";
                    break;
                case 3:
                    errstr = "missing colon";
                    break;
                case 4:
                    errstr = "invalid register name (must be e[abcd]x)";
                    break;
                case 5:
                    errstr = "policy string must be exactly 32 characters long";
                    break;
                default:
                    errstr = "unknown error";
                    break;
                }
                fprintf(stderr, "while parsing CPUID line: \"%s\":\n", buf);
                fprintf(stderr, "  error #%i: %s\n", e, errstr);
            }
        }
        break;
    case EINVAL:    /* config option is not a list, parse as a string */
        if (!xlu_cfg_get_string(config, "cpuid", &buf, 0)) {
            char *buf2, *p, *strtok_ptr = NULL;
            const char *errstr;

            buf2 = strdup(buf);
            p = strtok_r(buf2, ",", &strtok_ptr);
            if (p == NULL) {
                free(buf2);
                break;
            }
            if (strcmp(p, "host")) {
                fprintf(stderr, "while parsing CPUID string: \"%s\":\n", buf);
                fprintf(stderr, "  error: first word must be \"host\"\n");
                free(buf2);
                break;
            }
            for (p = strtok_r(NULL, ",", &strtok_ptr); p != NULL;
                 p = strtok_r(NULL, ",", &strtok_ptr)) {
                e = libxl_cpuid_parse_config(&b_info->cpuid, p);
                switch (e) {
                case 0: continue;
                case 1:
                    errstr = "missing \"=\" in key=value";
                    break;
                case 2:
                    errstr = "unknown CPUID flag name";
                    break;
                case 3:
                    errstr = "illegal CPUID value (must be: [0|1|x|k|s])";
                    break;
                default:
                    errstr = "unknown error";
                    break;
                }
                fprintf(stderr, "while parsing CPUID flag: \"%s\":\n", p);
                fprintf(stderr, "  error #%i: %s\n", e, errstr);
            }
            free(buf2);
        }
        break;
    default:
        break;
    }

    /* parse device model arguments, this works for pv, hvm and stubdom */
    if (!xlu_cfg_get_string (config, "device_model", &buf, 0)) {
        fprintf(stderr,
                "WARNING: ignoring device_model directive.\n"
                "WARNING: Use \"device_model_override\" instead if you"
                " really want a non-default device_model\n");
        if (strstr(buf, "stubdom-dm")) {
            if (c_info->type == LIBXL_DOMAIN_TYPE_HVM)
                fprintf(stderr, "WARNING: Or use"
                        " \"device_model_stubdomain_override\" if you "
                        " want to enable stubdomains\n");
            else
                fprintf(stderr, "WARNING: ignoring"
                        " \"device_model_stubdomain_override\" directive"
                        " for pv guest\n");
        }
    }


    xlu_cfg_replace_string (config, "device_model_override",
                            &b_info->device_model, 0);
    if (!xlu_cfg_get_string (config, "device_model_version", &buf, 0)) {
        if (!strcmp(buf, "qemu-xen-traditional")) {
            b_info->device_model_version
                = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
        } else if (!strcmp(buf, "qemu-xen")) {
            b_info->device_model_version
                = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
        } else {
            fprintf(stderr,
                    "Unknown device_model_version \"%s\" specified\n", buf);
            exit(1);
        }
    } else if (b_info->device_model)
        fprintf(stderr, "WARNING: device model override given without specific DM version\n");
    xlu_cfg_get_defbool (config, "device_model_stubdomain_override",
                         &b_info->device_model_stubdomain, 0);

    if (!xlu_cfg_get_string (config, "device_model_stubdomain_seclabel",
                             &buf, 0))
        xlu_cfg_replace_string(config, "device_model_stubdomain_seclabel",
                               &b_info->device_model_ssid_label, 0);

    xlu_cfg_replace_string(config, "device_model_user",
                           &b_info->device_model_user, 0);

#define parse_extra_args(type)                                            \
    e = xlu_cfg_get_list_as_string_list(config, "device_model_args"#type, \
                                    &b_info->extra##type, 0);            \
    if (e && e != ESRCH) {                                                \
        fprintf(stderr,"xl: Unable to parse device_model_args"#type".\n");\
        exit(-ERROR_FAIL);                                                \
    }

    /* parse extra args for qemu, common to both pv, hvm */
    parse_extra_args();

    /* parse extra args dedicated to pv */
    parse_extra_args(_pv);

    /* parse extra args dedicated to hvm */
    parse_extra_args(_hvm);

#undef parse_extra_args

    /* If we've already got vfb=[] for PV guest then ignore top level
     * VNC config. */
    if (c_info->type == LIBXL_DOMAIN_TYPE_PV && !d_config->num_vfbs) {
        long vnc_enabled = 0;

        if (!xlu_cfg_get_long (config, "vnc", &l, 0))
            vnc_enabled = l;

        if (vnc_enabled) {
            libxl_device_vfb *vfb;
            libxl_device_vkb *vkb;

            vfb = ARRAY_EXTEND_INIT(d_config->vfbs, d_config->num_vfbs,
                                    libxl_device_vfb_init);

            vkb = ARRAY_EXTEND_INIT(d_config->vkbs, d_config->num_vkbs,
                                    libxl_device_vkb_init);

            parse_top_level_vnc_options(config, &vfb->vnc);
            parse_top_level_sdl_options(config, &vfb->sdl);
            xlu_cfg_replace_string (config, "keymap", &vfb->keymap, 0);
        }
    } else {
        parse_top_level_vnc_options(config, &b_info->u.hvm.vnc);
        parse_top_level_sdl_options(config, &b_info->u.hvm.sdl);
    }

    xlu_cfg_get_defbool(config, "dm_restrict", &b_info->dm_restrict, 0);

    if (c_info->type == LIBXL_DOMAIN_TYPE_HVM) {
        if (!xlu_cfg_get_string (config, "vga", &buf, 0)) {
            if (!strcmp(buf, "stdvga")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_STD;
            } else if (!strcmp(buf, "cirrus")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_CIRRUS;
            } else if (!strcmp(buf, "none")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_NONE;
            } else if (!strcmp(buf, "qxl")) {
                b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_QXL;
            } else {
                fprintf(stderr, "Unknown vga \"%s\" specified\n", buf);
                exit(1);
            }
        } else if (!xlu_cfg_get_long(config, "stdvga", &l, 0))
            b_info->u.hvm.vga.kind = l ? LIBXL_VGA_INTERFACE_TYPE_STD :
                                         LIBXL_VGA_INTERFACE_TYPE_CIRRUS;

        if (!xlu_cfg_get_string(config, "hdtype", &buf, 0) &&
            libxl_hdtype_from_string(buf, &b_info->u.hvm.hdtype)) {
                fprintf(stderr, "ERROR: invalid value \"%s\" for \"hdtype\"\n",
                    buf);
                exit (1);
        }

        xlu_cfg_replace_string (config, "keymap", &b_info->u.hvm.keymap, 0);
        xlu_cfg_get_defbool (config, "spice", &b_info->u.hvm.spice.enable, 0);
        if (!xlu_cfg_get_long (config, "spiceport", &l, 0))
            b_info->u.hvm.spice.port = l;
        if (!xlu_cfg_get_long (config, "spicetls_port", &l, 0))
            b_info->u.hvm.spice.tls_port = l;
        xlu_cfg_replace_string (config, "spicehost",
                                &b_info->u.hvm.spice.host, 0);
        xlu_cfg_get_defbool(config, "spicedisable_ticketing",
                            &b_info->u.hvm.spice.disable_ticketing, 0);
        xlu_cfg_replace_string (config, "spicepasswd",
                                &b_info->u.hvm.spice.passwd, 0);
        xlu_cfg_get_defbool(config, "spiceagent_mouse",
                            &b_info->u.hvm.spice.agent_mouse, 0);
        xlu_cfg_get_defbool(config, "spicevdagent",
                            &b_info->u.hvm.spice.vdagent, 0);
        xlu_cfg_get_defbool(config, "spice_clipboard_sharing",
                            &b_info->u.hvm.spice.clipboard_sharing, 0);
        if (!xlu_cfg_get_long (config, "spiceusbredirection", &l, 0))
            b_info->u.hvm.spice.usbredirection = l;
        xlu_cfg_replace_string (config, "spice_image_compression",
                                &b_info->u.hvm.spice.image_compression, 0);
        xlu_cfg_replace_string (config, "spice_streaming_video",
                                &b_info->u.hvm.spice.streaming_video, 0);
        xlu_cfg_get_defbool(config, "nographic", &b_info->u.hvm.nographic, 0);
        if (!xlu_cfg_get_long(config, "gfx_passthru", &l, 1)) {
            libxl_defbool_set(&b_info->u.hvm.gfx_passthru, l);
        } else if (!xlu_cfg_get_string(config, "gfx_passthru", &buf, 0)) {
            if (libxl_gfx_passthru_kind_from_string(buf,
                                        &b_info->u.hvm.gfx_passthru_kind)) {
                fprintf(stderr,
                        "ERROR: invalid value \"%s\" for \"gfx_passthru\"\n",
                        buf);
                exit (1);
            }
            libxl_defbool_set(&b_info->u.hvm.gfx_passthru, true);
        }
        switch (xlu_cfg_get_list_as_string_list(config, "serial",
                                                &b_info->u.hvm.serial_list,
                                                1))
        {

        case 0: break; /* Success */
        case ESRCH: break; /* Option not present */
        case EINVAL:
            /* If it's not a valid list, try reading it as an atom,
             * falling through to an error if it fails */
            if (!xlu_cfg_replace_string(config, "serial",
                                        &b_info->u.hvm.serial, 0))
                break;
            /* FALLTHRU */
        default:
            fprintf(stderr,"xl: Unable to parse serial.\n");
            exit(-ERROR_FAIL);
        }
        xlu_cfg_replace_string (config, "boot", &b_info->u.hvm.boot, 0);
        xlu_cfg_get_defbool(config, "usb", &b_info->u.hvm.usb, 0);
        if (!xlu_cfg_get_long (config, "usbversion", &l, 0))
            b_info->u.hvm.usbversion = l;
        switch (xlu_cfg_get_list_as_string_list(config, "usbdevice",
                                                &b_info->u.hvm.usbdevice_list,
                                                1))
        {

        case 0: break; /* Success */
        case ESRCH: break; /* Option not present */
        case EINVAL:
            /* If it's not a valid list, try reading it as an atom,
             * falling through to an error if it fails */
            if (!xlu_cfg_replace_string(config, "usbdevice",
                                        &b_info->u.hvm.usbdevice, 0))
                break;
            /* FALLTHRU */
        default:
            fprintf(stderr,"xl: Unable to parse usbdevice.\n");
            exit(-ERROR_FAIL);
        }
        xlu_cfg_get_defbool(config, "vkb_device", &b_info->u.hvm.vkb_device, 0);
        xlu_cfg_replace_string (config, "soundhw", &b_info->u.hvm.soundhw, 0);
        xlu_cfg_get_defbool(config, "xen_platform_pci",
                            &b_info->u.hvm.xen_platform_pci, 0);

        if(b_info->u.hvm.vnc.listen
           && b_info->u.hvm.vnc.display
           && strchr(b_info->u.hvm.vnc.listen, ':') != NULL) {
            fprintf(stderr,
                    "ERROR: Display specified both in vnclisten"
                    " and vncdisplay!\n");
            exit (1);

        }

        if (!xlu_cfg_get_string (config, "vendor_device", &buf, 0)) {
            libxl_vendor_device d;

            e = libxl_vendor_device_from_string(buf, &d);
            if (e) {
                fprintf(stderr,
                        "xl: unknown vendor_device '%s'\n",
                        buf);
                exit(-ERROR_FAIL);
            }

            b_info->u.hvm.vendor_device = d;
        }
    }

    if (!xlu_cfg_get_string (config, "gic_version", &buf, 1)) {
        e = libxl_gic_version_from_string(buf, &b_info->arch_arm.gic_version);
        if (e) {
            fprintf(stderr,
                    "Unknown gic_version \"%s\" specified\n", buf);
            exit(-ERROR_FAIL);
        }
    }

    if (!xlu_cfg_get_string (config, "tee", &buf, 1)) {
        e = libxl_tee_type_from_string(buf, &b_info->tee);
        if (e) {
            fprintf(stderr,
                    "Unknown tee \"%s\" specified\n", buf);
            exit(-ERROR_FAIL);
        }
    }

    parse_vkb_list(config, d_config);

    xlu_cfg_destroy(config);
}

/* Returns -1 on failure; the amount of memory on success. */
int64_t parse_mem_size_kb(const char *mem)
{
    char *endptr;
    int64_t kbytes;

    kbytes = strtoll(mem, &endptr, 10);

    if (strlen(endptr) > 1)
        return -1;

    switch (tolower((uint8_t)*endptr)) {
    case 't':
        kbytes <<= 10;
        /* fallthrough */
    case 'g':
        kbytes <<= 10;
        /* fallthrough */
    case '\0':
    case 'm':
        kbytes <<= 10;
        /* fallthrough */
    case 'k':
        break;
    case 'b':
        kbytes >>= 10;
        break;
    default:
        return -1;
    }

    return kbytes;
}


void split_string_into_string_list(const char *str,
                                   const char *delim,
                                   libxl_string_list *psl)
{
    char *s, *saveptr;
    const char *p;
    libxl_string_list sl;

    int i = 0, nr = 0;

    s = strdup(str);
    if (s == NULL) {
        fprintf(stderr, "unable to allocate memory to split string\n");
        exit(-1);
    }

    /* Count number of entries */
    p = strtok_r(s, delim, &saveptr);
    do {
        nr++;
    } while ((p = strtok_r(NULL, delim, &saveptr)));

    free(s);

    s = strdup(str);

    sl = malloc((nr+1) * sizeof (char *));
    if (sl == NULL) {
        fprintf(stderr, "unable to allocate memory to split string\n");
        exit(-1);
    }

    p = strtok_r(s, delim, &saveptr);
    do {
        assert(i < nr);
        sl[i] = strdup(p);
        i++;
    } while ((p = strtok_r(NULL, delim, &saveptr)));
    sl[i] = NULL;

    *psl = sl;

    free(s);
}

void trim(char_predicate_t predicate, const char *input, char **output)
{
    const char *first, *after;

    for (first = input;
         *first && predicate((unsigned char)first[0]);
         first++)
        ;

    for (after = first + strlen(first);
         after > first && predicate((unsigned char)after[-1]);
         after--)
        ;

    size_t len_nonnull = after - first;
    char *result = xmalloc(len_nonnull + 1);

    memcpy(result, first, len_nonnull);
    result[len_nonnull] = 0;

    *output = result;
}

int split_string_into_pair(const char *str,
                           const char *delim,
                           char **a,
                           char **b)
{
    char *s, *p, *saveptr, *aa = NULL, *bb = NULL;
    int rc = 0;

    s = xstrdup(str);

    p = strtok_r(s, delim, &saveptr);
    if (p == NULL) {
        rc = ERROR_INVAL;
        goto out;
    }
    aa = xstrdup(p);
    p = strtok_r(NULL, delim, &saveptr);
    if (p == NULL) {
        rc = ERROR_INVAL;
        goto out;
    }
    bb = xstrdup(p);

    *a = aa;
    aa = NULL;
    *b = bb;
    bb = NULL;
out:
    free(s);
    free(aa);
    free(bb);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
