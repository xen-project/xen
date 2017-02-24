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
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_cpupoolcreate(int argc, char **argv)
{
    const char *filename = NULL, *config_src=NULL;
    const char *p;
    char *extra_config = NULL;
    int opt;
    static struct option opts[] = {
        {"defconfig", 1, 0, 'f'},
        {"dryrun", 0, 0, 'n'},
        COMMON_LONG_OPTS
    };
    int ret;
    char *config_data = 0;
    int config_len = 0;
    XLU_Config *config;
    const char *buf;
    char *name = NULL;
    uint32_t poolid;
    libxl_scheduler sched = 0;
    XLU_ConfigList *cpus;
    XLU_ConfigList *nodes;
    int n_cpus, n_nodes, i, n;
    libxl_bitmap freemap;
    libxl_bitmap cpumap;
    libxl_uuid uuid;
    libxl_cputopology *topology;
    int rc = EXIT_FAILURE;

    SWITCH_FOREACH_OPT(opt, "nf:", opts, "cpupool-create", 0) {
    case 'f':
        filename = optarg;
        break;
    case 'n':
        dryrun_only = 1;
        break;
    }

    libxl_bitmap_init(&freemap);
    libxl_bitmap_init(&cpumap);

    while (optind < argc) {
        if ((p = strchr(argv[optind], '='))) {
            string_realloc_append(&extra_config, "\n");
            string_realloc_append(&extra_config, argv[optind]);
        } else if (!filename) {
            filename = argv[optind];
        } else {
            help("cpupool-create");
            goto out;
        }
        optind++;
    }

    if (filename)
    {
        if (libxl_read_file_contents(ctx, filename, (void **)&config_data,
                                     &config_len)) {
            fprintf(stderr, "Failed to read config file: %s: %s\n",
                    filename, strerror(errno));
            goto out;
        }
        config_src=filename;
    }
    else
        config_src="command line";

    if (extra_config && strlen(extra_config)) {
        if (config_len > INT_MAX - (strlen(extra_config) + 2)) {
            fprintf(stderr, "Failed to attach extra configuration\n");
            goto out;
        }
        config_data = xrealloc(config_data,
                               config_len + strlen(extra_config) + 2);
        if (!config_data) {
            fprintf(stderr, "Failed to realloc config_data\n");
            goto out;
        }
        config_data[config_len] = 0;
        strcat(config_data, extra_config);
        strcat(config_data, "\n");
        config_len += strlen(extra_config) + 1;
    }

    config = xlu_cfg_init(stderr, config_src);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        goto out;
    }

    ret = xlu_cfg_readdata(config, config_data, config_len);
    if (ret) {
        fprintf(stderr, "Failed to parse config file: %s\n", strerror(ret));
        goto out_cfg;
    }

    if (!xlu_cfg_get_string (config, "name", &buf, 0))
        name = strdup(buf);
    else if (filename)
        name = libxl_basename(filename);
    else {
        fprintf(stderr, "Missing cpupool name!\n");
        goto out_cfg;
    }
    if (!libxl_name_to_cpupoolid(ctx, name, &poolid)) {
        fprintf(stderr, "Pool name \"%s\" already exists\n", name);
        goto out_cfg;
    }

    if (!xlu_cfg_get_string (config, "sched", &buf, 0)) {
        if ((libxl_scheduler_from_string(buf, &sched)) < 0) {
            fprintf(stderr, "Unknown scheduler\n");
            goto out_cfg;
        }
    } else {
        rc = libxl_get_scheduler(ctx);
        if (rc < 0) {
            fprintf(stderr, "get_scheduler sysctl failed.\n");
            goto out_cfg;
        }
        sched = rc;
    }

    if (libxl_get_freecpus(ctx, &freemap)) {
        fprintf(stderr, "libxl_get_freecpus failed\n");
        goto out_cfg;
    }
    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Failed to allocate cpumap\n");
        goto out_cfg;
    }
    if (!xlu_cfg_get_list(config, "nodes", &nodes, 0, 0)) {
        int nr;
        n_cpus = 0;
        n_nodes = 0;
        topology = libxl_get_cpu_topology(ctx, &nr);
        if (topology == NULL) {
            fprintf(stderr, "libxl_get_topologyinfo failed\n");
            goto out_cfg;
        }
        while ((buf = xlu_cfg_get_listitem(nodes, n_nodes)) != NULL) {
            n = atoi(buf);
            for (i = 0; i < nr; i++) {
                if ((topology[i].node == n) &&
                    libxl_bitmap_test(&freemap, i)) {
                    libxl_bitmap_set(&cpumap, i);
                    n_cpus++;
                }
            }
            n_nodes++;
        }

        libxl_cputopology_list_free(topology, nr);

        if (n_cpus == 0) {
            fprintf(stderr, "no free cpu found\n");
            goto out_cfg;
        }
    } else if (!xlu_cfg_get_list(config, "cpus", &cpus, 0, 1)) {
        n_cpus = 0;
        while ((buf = xlu_cfg_get_listitem(cpus, n_cpus)) != NULL) {
            i = atoi(buf);
            if ((i < 0) || !libxl_bitmap_test(&freemap, i)) {
                fprintf(stderr, "cpu %d illegal or not free\n", i);
                goto out_cfg;
            }
            libxl_bitmap_set(&cpumap, i);
            n_cpus++;
        }
    } else if (!xlu_cfg_get_string(config, "cpus", &buf, 0)) {
        if (parse_cpurange(buf, &cpumap))
            goto out_cfg;

        n_cpus = 0;
        libxl_for_each_set_bit(i, cpumap) {
            if (!libxl_bitmap_test(&freemap, i)) {
                fprintf(stderr, "cpu %d illegal or not free\n", i);
                goto out_cfg;
            }
            n_cpus++;
        }
    } else
        n_cpus = 0;

    libxl_uuid_generate(&uuid);

    printf("Using config file \"%s\"\n", config_src);
    printf("cpupool name:   %s\n", name);
    printf("scheduler:      %s\n", libxl_scheduler_to_string(sched));
    printf("number of cpus: %d\n", n_cpus);

    if (!dryrun_only) {
        poolid = LIBXL_CPUPOOL_POOLID_ANY;
        if (libxl_cpupool_create(ctx, name, sched, cpumap, &uuid, &poolid)) {
            fprintf(stderr, "error on creating cpupool\n");
            goto out_cfg;
        }
    }
    /* We made it! */
    rc = EXIT_SUCCESS;

out_cfg:
    xlu_cfg_destroy(config);
out:
    libxl_bitmap_dispose(&freemap);
    libxl_bitmap_dispose(&cpumap);
    free(name);
    free(config_data);
    free(extra_config);
    return rc;
}

int main_cpupoollist(int argc, char **argv)
{
    int opt;
    static struct option opts[] = {
        {"cpus", 0, 0, 'c'},
        COMMON_LONG_OPTS
    };
    int opt_cpus = 0;
    const char *pool = NULL;
    libxl_cpupoolinfo *poolinfo;
    int n_pools, p, c, n;
    uint32_t poolid;
    char *name;

    SWITCH_FOREACH_OPT(opt, "c", opts, "cpupool-list", 0) {
    case 'c':
        opt_cpus = 1;
        break;
    }

    if (optind < argc) {
        pool = argv[optind];
        if (libxl_name_to_cpupoolid(ctx, pool, &poolid)) {
            fprintf(stderr, "Pool \'%s\' does not exist\n", pool);
            return EXIT_FAILURE;
        }
    }

    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        return EXIT_FAILURE;
    }

    printf("%-19s", "Name");
    if (opt_cpus)
        printf("CPU list\n");
    else
        printf("CPUs   Sched     Active   Domain count\n");

    for (p = 0; p < n_pools; p++) {
        if (!pool || (poolinfo[p].poolid == poolid)) {
            name = poolinfo[p].pool_name;
            printf("%-19s", name);
            n = 0;
            libxl_for_each_bit(c, poolinfo[p].cpumap)
                if (libxl_bitmap_test(&poolinfo[p].cpumap, c)) {
                    if (n && opt_cpus) printf(",");
                    if (opt_cpus) printf("%d", c);
                    n++;
                }
            if (!opt_cpus) {
                printf("%3d %9s       y       %4d", n,
                       libxl_scheduler_to_string(poolinfo[p].sched),
                       poolinfo[p].n_dom);
            }
            printf("\n");
        }
    }

    libxl_cpupoolinfo_list_free(poolinfo, n_pools);

    return EXIT_SUCCESS;
}

int main_cpupooldestroy(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-destroy", 1) {
        /* No options */
    }

    pool = argv[optind];

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool '%s'\n", pool);
        return EXIT_FAILURE;
    }

    if (libxl_cpupool_destroy(ctx, poolid)) {
        fprintf(stderr, "Can't destroy cpupool '%s'\n", pool);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_cpupoolrename(int argc, char **argv)
{
    int opt;
    const char *pool;
    const char *new_name;
    uint32_t poolid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-rename", 2) {
        /* No options */
    }

    pool = argv[optind++];

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool '%s'\n", pool);
        return EXIT_FAILURE;
    }

    new_name = argv[optind];

    if (libxl_cpupool_rename(ctx, new_name, poolid)) {
        fprintf(stderr, "Can't rename cpupool '%s'\n", pool);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_cpupoolcpuadd(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    libxl_bitmap cpumap;
    int rc = EXIT_FAILURE;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-cpu-add", 2) {
        /* No options */
    }

    libxl_bitmap_init(&cpumap);
    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Unable to allocate cpumap");
        return EXIT_FAILURE;
    }

    pool = argv[optind++];
    if (parse_cpurange(argv[optind], &cpumap))
        goto out;

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        goto out;
    }

    if (libxl_cpupool_cpuadd_cpumap(ctx, poolid, &cpumap))
        fprintf(stderr, "some cpus may not have been added to %s\n", pool);

    rc = EXIT_SUCCESS;

out:
    libxl_bitmap_dispose(&cpumap);
    return rc;
}

int main_cpupoolcpuremove(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    libxl_bitmap cpumap;
    int rc = EXIT_FAILURE;

    libxl_bitmap_init(&cpumap);
    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Unable to allocate cpumap");
        return EXIT_FAILURE;
    }

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-cpu-remove", 2) {
        /* No options */
    }

    pool = argv[optind++];
    if (parse_cpurange(argv[optind], &cpumap))
        goto out;

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool \'%s\'\n", pool);
        goto out;
    }

    if (libxl_cpupool_cpuremove_cpumap(ctx, poolid, &cpumap)) {
        fprintf(stderr, "Some cpus may have not or only partially been removed from '%s'.\n", pool);
        fprintf(stderr, "If a cpu can't be added to another cpupool, add it to '%s' again and retry.\n", pool);
    }

    rc = EXIT_SUCCESS;

out:
    libxl_bitmap_dispose(&cpumap);
    return rc;
}

int main_cpupoolmigrate(int argc, char **argv)
{
    int opt;
    const char *pool;
    uint32_t poolid;
    const char *dom;
    uint32_t domid;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-migrate", 2) {
        /* No options */
    }

    dom = argv[optind++];
    pool = argv[optind];

    if (libxl_domain_qualifier_to_domid(ctx, dom, &domid) ||
        !libxl_domid_to_name(ctx, domid)) {
        fprintf(stderr, "unknown domain '%s'\n", dom);
        return EXIT_FAILURE;
    }

    if (libxl_cpupool_qualifier_to_cpupoolid(ctx, pool, &poolid, NULL) ||
        !libxl_cpupoolid_is_valid(ctx, poolid)) {
        fprintf(stderr, "unknown cpupool '%s'\n", pool);
        return EXIT_FAILURE;
    }

    if (libxl_cpupool_movedomain(ctx, poolid, domid))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_cpupoolnumasplit(int argc, char **argv)
{
    int rc;
    int opt;
    int p;
    int c;
    int n;
    uint32_t poolid;
    libxl_scheduler sched;
    int n_pools;
    int node;
    int n_cpus;
    char *name = NULL;
    libxl_uuid uuid;
    libxl_bitmap cpumap;
    libxl_cpupoolinfo *poolinfo;
    libxl_cputopology *topology;
    libxl_dominfo info;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cpupool-numa-split", 0) {
        /* No options */
    }

    libxl_dominfo_init(&info);

    rc = EXIT_FAILURE;

    libxl_bitmap_init(&cpumap);
    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        return EXIT_FAILURE;
    }
    poolid = poolinfo[0].poolid;
    sched = poolinfo[0].sched;
    libxl_cpupoolinfo_list_free(poolinfo, n_pools);

    if (n_pools > 1) {
        fprintf(stderr, "splitting not possible, already cpupools in use\n");
        return EXIT_FAILURE;
    }

    topology = libxl_get_cpu_topology(ctx, &n_cpus);
    if (topology == NULL) {
        fprintf(stderr, "libxl_get_topologyinfo failed\n");
        return EXIT_FAILURE;
    }

    if (libxl_cpu_bitmap_alloc(ctx, &cpumap, 0)) {
        fprintf(stderr, "Failed to allocate cpumap\n");
        goto out;
    }

    /* Reset Pool-0 to 1st node: first add cpus, then remove cpus to avoid
       a cpupool without cpus in between */

    node = topology[0].node;
    if (libxl_cpupool_cpuadd_node(ctx, 0, node, &n)) {
        fprintf(stderr, "error on adding cpu to Pool 0\n");
        goto out;
    }

    xasprintf(&name, "Pool-node%d", node);
    if (libxl_cpupool_rename(ctx, name, 0)) {
        fprintf(stderr, "error on renaming Pool 0\n");
        goto out;
    }

    n = 0;
    for (c = 0; c < n_cpus; c++) {
        if (topology[c].node == node) {
            topology[c].node = LIBXL_CPUTOPOLOGY_INVALID_ENTRY;
            libxl_bitmap_set(&cpumap, n);
            n++;
        }
    }
    if (libxl_domain_info(ctx, &info, 0)) {
        fprintf(stderr, "error on getting info for Domain-0\n");
        goto out;
    }
    if (info.vcpu_online > n && libxl_set_vcpuonline(ctx, 0, &cpumap)) {
        fprintf(stderr, "error on removing vcpus for Domain-0\n");
        goto out;
    }
    for (c = 0; c < 10; c++) {
        /* We've called libxl_dominfo_init before the loop and will
         * call libxl_dominfo_dispose after the loop when we're done
         * with info.
         */
        libxl_dominfo_dispose(&info);
        libxl_dominfo_init(&info);
        if (libxl_domain_info(ctx, &info, 0)) {
            fprintf(stderr, "error on getting info for Domain-0\n");
            goto out;
        }
        if (info.vcpu_online <= n) {
            break;
        }
        sleep(1);
    }
    if (info.vcpu_online > n) {
        fprintf(stderr, "failed to offline vcpus\n");
        goto out;
    }
    libxl_bitmap_set_none(&cpumap);

    for (c = 0; c < n_cpus; c++) {
        if (topology[c].node == LIBXL_CPUTOPOLOGY_INVALID_ENTRY) {
            continue;
        }

        node = topology[c].node;
        if (libxl_cpupool_cpuremove_node(ctx, 0, node, &n)) {
            fprintf(stderr, "error on removing cpu from Pool 0\n");
            goto out;
        }

        free(name);
        xasprintf(&name, "Pool-node%d", node);
        libxl_uuid_generate(&uuid);
        poolid = 0;
        if (libxl_cpupool_create(ctx, name, sched, cpumap, &uuid, &poolid)) {
            fprintf(stderr, "error on creating cpupool\n");
            goto out;
        }

        if (libxl_cpupool_cpuadd_node(ctx, poolid, node, &n)) {
            fprintf(stderr, "error on adding cpus to cpupool\n");
            goto out;
        }

        for (p = c; p < n_cpus; p++) {
            if (topology[p].node == node) {
                topology[p].node = LIBXL_CPUTOPOLOGY_INVALID_ENTRY;
            }
        }
    }

    rc = EXIT_SUCCESS;

out:
    libxl_cputopology_list_free(topology, n_cpus);
    libxl_bitmap_dispose(&cpumap);
    libxl_dominfo_dispose(&info);
    free(name);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
