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

#include <inttypes.h>
#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

static int sched_domain_get(libxl_scheduler sched, int domid,
                            libxl_domain_sched_params *scinfo)
{
    if (libxl_domain_sched_params_get(ctx, domid, scinfo)) {
        fprintf(stderr, "libxl_domain_sched_params_get failed.\n");
        return 1;
    }
    if (scinfo->sched != sched) {
        fprintf(stderr, "libxl_domain_sched_params_get returned %s not %s.\n",
                libxl_scheduler_to_string(scinfo->sched),
                libxl_scheduler_to_string(sched));
        return 1;
    }

    return 0;
}

static int sched_domain_set(int domid, const libxl_domain_sched_params *scinfo)
{
    if (libxl_domain_sched_params_set(ctx, domid, scinfo)) {
        fprintf(stderr, "libxl_domain_sched_params_set failed.\n");
        return 1;
    }

    return 0;
}

static int sched_vcpu_get(libxl_scheduler sched, int domid,
                          libxl_vcpu_sched_params *scinfo)
{
    int rc;

    rc = libxl_vcpu_sched_params_get(ctx, domid, scinfo);
    if (rc) {
        fprintf(stderr, "libxl_vcpu_sched_params_get failed.\n");
        exit(EXIT_FAILURE);
    }
    if (scinfo->sched != sched) {
        fprintf(stderr, "libxl_vcpu_sched_params_get returned %s not %s.\n",
                libxl_scheduler_to_string(scinfo->sched),
                libxl_scheduler_to_string(sched));
        return 1;
    }

    return 0;
}

static int sched_vcpu_get_all(libxl_scheduler sched, int domid,
                              libxl_vcpu_sched_params *scinfo)
{
    int rc;

    rc = libxl_vcpu_sched_params_get_all(ctx, domid, scinfo);
    if (rc) {
        fprintf(stderr, "libxl_vcpu_sched_params_get_all failed.\n");
        exit(EXIT_FAILURE);
    }
    if (scinfo->sched != sched) {
        fprintf(stderr, "libxl_vcpu_sched_params_get_all returned %s not %s.\n",
                libxl_scheduler_to_string(scinfo->sched),
                libxl_scheduler_to_string(sched));
        return 1;
    }

    return 0;
}

static int sched_vcpu_set(int domid, const libxl_vcpu_sched_params *scinfo)
{
    int rc;

    rc = libxl_vcpu_sched_params_set(ctx, domid, scinfo);
    if (rc) {
        fprintf(stderr, "libxl_vcpu_sched_params_set failed.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int sched_vcpu_set_all(int domid, const libxl_vcpu_sched_params *scinfo)
{
    int rc;

    rc = libxl_vcpu_sched_params_set_all(ctx, domid, scinfo);
    if (rc) {
        fprintf(stderr, "libxl_vcpu_sched_params_set_all failed.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int sched_credit_params_set(int poolid, libxl_sched_credit_params *scinfo)
{
    if (libxl_sched_credit_params_set(ctx, poolid, scinfo)) {
        fprintf(stderr, "libxl_sched_credit_params_set failed.\n");
        return 1;
    }

    return 0;
}

static int sched_credit_params_get(int poolid, libxl_sched_credit_params *scinfo)
{
    if (libxl_sched_credit_params_get(ctx, poolid, scinfo)) {
        fprintf(stderr, "libxl_sched_credit_params_get failed.\n");
        return 1;
    }

    return 0;
}

static int sched_credit_domain_output(int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;

    if (domid < 0) {
        printf("%-33s %4s %6s %4s\n", "Name", "ID", "Weight", "Cap");
        return 0;
    }

    libxl_domain_sched_params_init(&scinfo);
    if (sched_domain_get(LIBXL_SCHEDULER_CREDIT, domid, &scinfo)) {
        libxl_domain_sched_params_dispose(&scinfo);
        return 1;
    }
    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %6d %4d\n",
        domname,
        domid,
        scinfo.weight,
        scinfo.cap);
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_credit_pool_output(uint32_t poolid)
{
    libxl_sched_credit_params scparam;
    char *poolname;

    poolname = libxl_cpupoolid_to_name(ctx, poolid);
    if (sched_credit_params_get(poolid, &scparam)) {
        printf("Cpupool %s: [sched params unavailable]\n",
               poolname);
    } else {
        printf("Cpupool %s: tslice=%dms ratelimit=%dus migration-delay=%dus\n",
               poolname,
               scparam.tslice_ms,
               scparam.ratelimit_us,
               scparam.vcpu_migr_delay_us);
    }
    free(poolname);
    return 0;
}

static int sched_credit2_params_set(int poolid,
                                    libxl_sched_credit2_params *scinfo)
{
    if (libxl_sched_credit2_params_set(ctx, poolid, scinfo)) {
        fprintf(stderr, "libxl_sched_credit2_params_set failed.\n");
        return 1;
    }

    return 0;
}

static int sched_credit2_params_get(int poolid,
                                    libxl_sched_credit2_params *scinfo)
{
    if (libxl_sched_credit2_params_get(ctx, poolid, scinfo)) {
        fprintf(stderr, "libxl_sched_credit2_params_get failed.\n");
        return 1;
    }

    return 0;
}

static int sched_credit2_domain_output(int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;

    if (domid < 0) {
        printf("%-33s %4s %6s %4s\n", "Name", "ID", "Weight", "Cap");
        return 0;
    }

    libxl_domain_sched_params_init(&scinfo);
    if (sched_domain_get(LIBXL_SCHEDULER_CREDIT2, domid, &scinfo)) {
        libxl_domain_sched_params_dispose(&scinfo);
        return 1;
    }
    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %6d %4d\n",
        domname,
        domid,
        scinfo.weight,
        scinfo.cap);
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_credit2_pool_output(uint32_t poolid)
{
    libxl_sched_credit2_params scparam;
    char *poolname = libxl_cpupoolid_to_name(ctx, poolid);

    if (sched_credit2_params_get(poolid, &scparam))
        printf("Cpupool %s: [sched params unavailable]\n", poolname);
    else
        printf("Cpupool %s: ratelimit=%dus\n",
               poolname, scparam.ratelimit_us);

    free(poolname);

    return 0;
}

static int sched_rtds_domain_output(
    int domid)
{
    char *domname;
    libxl_domain_sched_params scinfo;

    if (domid < 0) {
        printf("%-33s %4s %9s %9s %10s\n", "Name", "ID", "Period", "Budget", "Extratime");
        return 0;
    }

    libxl_domain_sched_params_init(&scinfo);
    if (sched_domain_get(LIBXL_SCHEDULER_RTDS, domid, &scinfo)) {
        libxl_domain_sched_params_dispose(&scinfo);
        return 1;
    }

    domname = libxl_domid_to_name(ctx, domid);
    printf("%-33s %4d %9d %9d %10s\n",
        domname,
        domid,
        scinfo.period,
        scinfo.budget,
        scinfo.extratime ? "yes" : "no");
    free(domname);
    libxl_domain_sched_params_dispose(&scinfo);
    return 0;
}

static int sched_rtds_vcpu_output(int domid, libxl_vcpu_sched_params *scinfo)
{
    char *domname;
    int rc = 0;
    int i;

    if (domid < 0) {
        printf("%-33s %4s %4s %9s %9s %10s\n", "Name", "ID",
               "VCPU", "Period", "Budget", "Extratime");
        return 0;
    }

    rc = sched_vcpu_get(LIBXL_SCHEDULER_RTDS, domid, scinfo);
    if (rc)
        return 1;

    domname = libxl_domid_to_name(ctx, domid);
    for ( i = 0; i < scinfo->num_vcpus; i++ ) {
        printf("%-33s %4d %4d %9"PRIu32" %9"PRIu32" %10s\n",
               domname,
               domid,
               scinfo->vcpus[i].vcpuid,
               scinfo->vcpus[i].period,
               scinfo->vcpus[i].budget,
               scinfo->vcpus[i].extratime ? "yes" : "no");
    }
    free(domname);
    return 0;
}

static int sched_rtds_vcpu_output_all(int domid,
                                      libxl_vcpu_sched_params *scinfo)
{
    char *domname;
    int rc = 0;
    int i;

    if (domid < 0) {
        printf("%-33s %4s %4s %9s %9s %10s\n", "Name", "ID",
               "VCPU", "Period", "Budget", "Extratime");
        return 0;
    }

    scinfo->num_vcpus = 0;
    rc = sched_vcpu_get_all(LIBXL_SCHEDULER_RTDS, domid, scinfo);
    if (rc)
        return 1;

    domname = libxl_domid_to_name(ctx, domid);
    for ( i = 0; i < scinfo->num_vcpus; i++ ) {
        printf("%-33s %4d %4d %9"PRIu32" %9"PRIu32" %10s\n",
               domname,
               domid,
               scinfo->vcpus[i].vcpuid,
               scinfo->vcpus[i].period,
               scinfo->vcpus[i].budget,
               scinfo->vcpus[i].extratime ? "yes" : "no");
    }
    free(domname);
    return 0;
}

static int sched_rtds_pool_output(uint32_t poolid)
{
    char *poolname;

    poolname = libxl_cpupoolid_to_name(ctx, poolid);
    printf("Cpupool %s: sched=RTDS\n", poolname);

    free(poolname);
    return 0;
}

static int sched_domain_output(libxl_scheduler sched, int (*output)(int),
                               int (*pooloutput)(uint32_t), const char *cpupool)
{
    libxl_dominfo *info;
    libxl_cpupoolinfo *poolinfo = NULL;
    uint32_t poolid;
    int nb_domain, n_pools = 0, i, p;
    int rc = 0;

    if (cpupool) {
        if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool, &poolid, NULL) ||
            !libxl_cpupoolid_is_valid(ctx, poolid)) {
            fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
            return 1;
        }
    }

    info = libxl_list_domain(ctx, &nb_domain);
    if (!info) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        return 1;
    }
    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        libxl_dominfo_list_free(info, nb_domain);
        return 1;
    }

    for (p = 0; !rc && (p < n_pools); p++) {
        if ((poolinfo[p].sched != sched) ||
            (cpupool && (poolid != poolinfo[p].poolid)))
            continue;

        pooloutput(poolinfo[p].poolid);

        output(-1);
        for (i = 0; i < nb_domain; i++) {
            if (info[i].cpupool != poolinfo[p].poolid)
                continue;
            rc = output(info[i].domid);
            if (rc)
                break;
        }
    }

    libxl_cpupoolinfo_list_free(poolinfo, n_pools);
    libxl_dominfo_list_free(info, nb_domain);
    return 0;
}

static int sched_vcpu_output(libxl_scheduler sched,
                             int (*output)(int, libxl_vcpu_sched_params *),
                             int (*pooloutput)(uint32_t), const char *cpupool)
{
    libxl_dominfo *info;
    libxl_cpupoolinfo *poolinfo = NULL;
    uint32_t poolid;
    int nb_domain, n_pools = 0, i, p;
    int rc = 0;

    if (cpupool) {
        if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool, &poolid, NULL)
            || !libxl_cpupoolid_is_valid(ctx, poolid)) {
            fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
            return 1;
        }
    }

    info = libxl_list_domain(ctx, &nb_domain);
    if (!info) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        return 1;
    }
    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        fprintf(stderr, "error getting cpupool info\n");
        libxl_dominfo_list_free(info, nb_domain);
        return 1;
    }

    for (p = 0; !rc && (p < n_pools); p++) {
        if ((poolinfo[p].sched != sched) ||
            (cpupool && (poolid != poolinfo[p].poolid)))
            continue;

        pooloutput(poolinfo[p].poolid);

        output(-1, NULL);
        for (i = 0; i < nb_domain; i++) {
            libxl_vcpu_sched_params scinfo;
            if (info[i].cpupool != poolinfo[p].poolid)
                continue;
            libxl_vcpu_sched_params_init(&scinfo);
            rc = output(info[i].domid, &scinfo);
            libxl_vcpu_sched_params_dispose(&scinfo);
            if (rc)
                break;
        }
    }

    libxl_cpupoolinfo_list_free(poolinfo, n_pools);
    libxl_dominfo_list_free(info, nb_domain);
    return 0;
}

/*
 * <nothing>             : List all domain params and sched params from all pools
 * -d [domid]            : List domain params for domain
 * -d [domid] [params]   : Set domain params for domain
 * -p [pool]             : list all domains and sched params for pool
 * -s                    : List sched params for poolid 0
 * -s [params]           : Set sched params for poolid 0
 * -p [pool] -s          : List sched params for pool
 * -p [pool] -s [params] : Set sched params for pool
 * -p [pool] -d...       : Illegal
 */
int main_sched_credit(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int weight = 256, cap = 0;
    int tslice = 0, ratelimit = 0, migrdelay = 0;
    bool opt_w = false, opt_c = false;
    bool opt_t = false, opt_r = false;
    bool opt_s = false, opt_m = false;
    int opt, rc;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"weight", 1, 0, 'w'},
        {"cap", 1, 0, 'c'},
        {"schedparam", 0, 0, 's'},
        {"tslice_ms", 1, 0, 't'},
        {"ratelimit_us", 1, 0, 'r'},
        {"migration_delay_us", 1, 0, 'm'},
        {"cpupool", 1, 0, 'p'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "d:w:c:p:t:r:m:s", opts, "sched-credit", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = true;
        break;
    case 'c':
        cap = strtol(optarg, NULL, 10);
        opt_c = true;
        break;
    case 't':
        tslice = strtol(optarg, NULL, 10);
        opt_t = true;
        break;
    case 'r':
        ratelimit = strtol(optarg, NULL, 10);
        opt_r = true;
        break;
    case 'm':
        migrdelay = strtol(optarg, NULL, 10);
        opt_m = true;
        break;
    case 's':
        opt_s = true;
        break;
    case 'p':
        cpupool = optarg;
        break;
    }

    if ((cpupool || opt_s) && (dom || opt_w || opt_c)) {
        fprintf(stderr, "Specifying a cpupool or schedparam is not "
                "allowed with domain options.\n");
        return EXIT_FAILURE;
    }
    if (!dom && (opt_w || opt_c)) {
        fprintf(stderr, "Must specify a domain.\n");
        return EXIT_FAILURE;
    }
    if (!opt_s && (opt_t || opt_r || opt_m)) {
        fprintf(stderr, "Must specify schedparam to set schedule "
                "parameter values.\n");
        return EXIT_FAILURE;
    }

    if (opt_s) {
        libxl_sched_credit_params scparam;
        uint32_t poolid = 0;

        if (cpupool) {
            if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool,
                                                     &poolid, NULL) ||
                !libxl_cpupoolid_is_valid(ctx, poolid)) {
                fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
                return EXIT_FAILURE;
            }
        }

        if (!opt_t && !opt_r && !opt_m) { /* Output scheduling parameters */
            if (sched_credit_pool_output(poolid))
                return EXIT_FAILURE;
        } else { /* Set scheduling parameters*/
            if (sched_credit_params_get(poolid, &scparam))
                return EXIT_FAILURE;

            if (opt_t)
                scparam.tslice_ms = tslice;

            if (opt_r)
                scparam.ratelimit_us = ratelimit;

            if (opt_m)
                scparam.vcpu_migr_delay_us = migrdelay;

            if (sched_credit_params_set(poolid, &scparam))
                return EXIT_FAILURE;
        }
    } else if (!dom) { /* list all domain's credit scheduler info */
        if (sched_domain_output(LIBXL_SCHEDULER_CREDIT,
                                sched_credit_domain_output,
                                sched_credit_pool_output,
                                cpupool))
            return EXIT_FAILURE;
    } else {
        uint32_t domid = find_domain(dom);

        if (!opt_w && !opt_c) { /* output credit scheduler info */
            sched_credit_domain_output(-1);
            if (sched_credit_domain_output(domid))
                return EXIT_FAILURE;
        } else { /* set credit scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_CREDIT;
            if (opt_w)
                scinfo.weight = weight;
            if (opt_c)
                scinfo.cap = cap;
            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main_sched_credit2(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int ratelimit = 0;
    int weight = 256, cap = 0;
    bool opt_s = false;
    bool opt_r = false;
    bool opt_w = false;
    bool opt_c = false;
    int opt, rc;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"weight", 1, 0, 'w'},
        {"cap", 1, 0, 'c'},
        {"schedparam", 0, 0, 's'},
        {"ratelimit_us", 1, 0, 'r'},
        {"cpupool", 1, 0, 'p'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "d:w:c:p:r:s", opts, "sched-credit2", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = true;
        break;
    case 'c':
        cap = strtol(optarg, NULL, 10);
        opt_c = true;
        break;
    case 's':
        opt_s = true;
        break;
    case 'r':
        ratelimit = strtol(optarg, NULL, 10);
        opt_r = true;
        break;
    case 'p':
        cpupool = optarg;
        break;
    }

    if (cpupool && (dom || opt_w || opt_c)) {
        fprintf(stderr, "Specifying a cpupool is not allowed with other "
                "options.\n");
        return EXIT_FAILURE;
    }
    if (!dom && (opt_w || opt_c)) {
        fprintf(stderr, "Must specify a domain.\n");
        return EXIT_FAILURE;
    }

    if (opt_s) {
        libxl_sched_credit2_params scparam;
        uint32_t poolid = 0;

        if (cpupool) {
            if (libxl_cpupool_qualifier_to_cpupoolid(ctx, cpupool,
                                                     &poolid, NULL) ||
                !libxl_cpupoolid_is_valid(ctx, poolid)) {
                fprintf(stderr, "unknown cpupool \'%s\'\n", cpupool);
                return EXIT_FAILURE;
            }
        }

        if (!opt_r) { /* Output scheduling parameters */
            if (sched_credit2_pool_output(poolid))
                return EXIT_FAILURE;
        } else {      /* Set scheduling parameters (so far, just ratelimit) */
            scparam.ratelimit_us = ratelimit;
            if (sched_credit2_params_set(poolid, &scparam))
                return EXIT_FAILURE;
        }
    } else if (!dom) { /* list all domain's credit scheduler info */
        if (sched_domain_output(LIBXL_SCHEDULER_CREDIT2,
                                sched_credit2_domain_output,
                                sched_credit2_pool_output,
                                cpupool))
            return EXIT_FAILURE;
    } else {
        uint32_t domid = find_domain(dom);

        if (!opt_w && !opt_c) { /* output credit2 scheduler info */
            sched_credit2_domain_output(-1);
            if (sched_credit2_domain_output(domid))
                return EXIT_FAILURE;
        } else { /* set credit2 scheduler paramaters */
            libxl_domain_sched_params scinfo;
            libxl_domain_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_CREDIT2;
            if (opt_w)
                scinfo.weight = weight;
            if (opt_c)
                scinfo.cap = cap;
            rc = sched_domain_set(domid, &scinfo);
            libxl_domain_sched_params_dispose(&scinfo);
            if (rc)
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

/*
 * <nothing>            : List all domain paramters and sched params
 * -d [domid]           : List default domain params for domain
 * -d [domid] [params]  : Set domain params for domain
 * -d [domid] -v [vcpuid 1] -v [vcpuid 2] ...  :
 * List per-VCPU params for domain
 * -d [domid] -v all  : List all per-VCPU params for domain
 * -v all  : List all per-VCPU params for all domains
 * -d [domid] -v [vcpuid 1] [params] -v [vcpuid 2] [params] ...  :
 * Set per-VCPU params for domain
 * -d [domid] -v all [params]  : Set all per-VCPU params for domain
 */
int main_sched_rtds(int argc, char **argv)
{
    const char *dom = NULL;
    const char *cpupool = NULL;
    int *vcpus = (int *)xmalloc(sizeof(int)); /* IDs of VCPUs that change */
    int *periods = (int *)xmalloc(sizeof(int)); /* period is in microsecond */
    int *budgets = (int *)xmalloc(sizeof(int)); /* budget is in microsecond */
    bool *extratimes = (bool *)xmalloc(sizeof(bool)); /* extratime is bool */
    int v_size = 1; /* size of vcpus array */
    int p_size = 1; /* size of periods array */
    int b_size = 1; /* size of budgets array */
    int e_size = 1; /* size of extratimes array */
    int v_index = 0; /* index in vcpus array */
    int p_index =0; /* index in periods array */
    int b_index =0; /* index for in budgets array */
    int e_index = 0; /* index in extratimes array */
    bool opt_p = false;
    bool opt_b = false;
    bool opt_e = false;
    bool opt_v = false;
    bool opt_all = false; /* output per-dom parameters */
    int opt, i, rc, r;
    static struct option opts[] = {
        {"domain", 1, 0, 'd'},
        {"period", 1, 0, 'p'},
        {"budget", 1, 0, 'b'},
        {"extratime", 1, 0, 'e'},
        {"vcpuid",1, 0, 'v'},
        {"cpupool", 1, 0, 'c'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "d:p:b:e:v:c", opts, "sched-rtds", 0) {
    case 'd':
        dom = optarg;
        break;
    case 'p':
        if (p_index >= p_size) {
            /*
             * periods array is full
             * double the array size for new elements
             */
            p_size *= 2;
            periods = xrealloc(periods, p_size);
        }
        periods[p_index++] = strtol(optarg, NULL, 10);
        opt_p = 1;
        break;
    case 'b':
        if (b_index >= b_size) { /* budgets array is full */
            b_size *= 2;
            budgets = xrealloc(budgets, b_size);
        }
        budgets[b_index++] = strtol(optarg, NULL, 10);
        opt_b = 1;
        break;
    case 'e':
        if (e_index >= e_size) { /* extratime array is full */
            e_size *= 2;
            extratimes = xrealloc(extratimes, e_size);
        }
        if (strcmp(optarg, "0") && strcmp(optarg, "1"))
        {
            fprintf(stderr, "Invalid extratime.\n");
            r = EXIT_FAILURE;
            goto out;
        }
        extratimes[e_index++] = strtol(optarg, NULL, 10);
        opt_e = 1;
        break;
    case 'v':
        if (!strcmp(optarg, "all")) { /* get or set all vcpus of a domain */
            opt_all = 1;
            break;
        }
        if (v_index >= v_size) { /* vcpus array is full */
            v_size *= 2;
            vcpus = xrealloc(vcpus, v_size);
        }
        vcpus[v_index++] = strtol(optarg, NULL, 10);
        opt_v = 1;
        break;
    case 'c':
        cpupool = optarg;
        break;
    }

    if (cpupool && (dom || opt_p || opt_b || opt_e || opt_v || opt_all)) {
        fprintf(stderr, "Specifying a cpupool is not allowed with "
                "other options.\n");
        r = EXIT_FAILURE;
        goto out;
    }
    if (!dom && (opt_p || opt_b || opt_e || opt_v)) {
        fprintf(stderr, "Missing parameters.\n");
        r = EXIT_FAILURE;
        goto out;
    }
    if (dom && !opt_v && !opt_all && (opt_p || opt_b || opt_e)) {
        fprintf(stderr, "Must specify VCPU.\n");
        r = EXIT_FAILURE;
        goto out;
    }
    if (opt_v && opt_all) {
        fprintf(stderr, "Incorrect VCPU IDs.\n");
        r = EXIT_FAILURE;
        goto out;
    }
    if (((v_index > b_index) && opt_b) || ((v_index > p_index) && opt_p)
         || ((v_index > e_index) && opt_e) || p_index != b_index
         || p_index != e_index ) {
        fprintf(stderr, "Incorrect number of period, budget and extratime\n");
        r = EXIT_FAILURE;
        goto out;
    }

    if ((!dom) && opt_all) {
        /* get all domain's per-vcpu rtds scheduler parameters */
        rc = -sched_vcpu_output(LIBXL_SCHEDULER_RTDS,
                                sched_rtds_vcpu_output_all,
                                sched_rtds_pool_output,
                                cpupool);
        if (rc) {
            r = EXIT_FAILURE;
            goto out;
        }
    } else if (!dom && !opt_all) {
        /* list all domain's default scheduling parameters */
        rc = -sched_domain_output(LIBXL_SCHEDULER_RTDS,
                                  sched_rtds_domain_output,
                                  sched_rtds_pool_output,
                                  cpupool);
        if (rc) {
            r = EXIT_FAILURE;
            goto out;
        }
    } else {
        uint32_t domid = find_domain(dom);
        if (!opt_v && !opt_all) { /* output default scheduling parameters */
            sched_rtds_domain_output(-1);
            rc = -sched_rtds_domain_output(domid);
            if (rc) {
                r = EXIT_FAILURE;
                goto out;
            }
        } else if (!opt_p && !opt_b && !opt_e) {
            /* get per-vcpu rtds scheduling parameters */
            libxl_vcpu_sched_params scinfo;
            libxl_vcpu_sched_params_init(&scinfo);
            sched_rtds_vcpu_output(-1, &scinfo);
            scinfo.num_vcpus = v_index;
            if (v_index > 0) {
                scinfo.vcpus = (libxl_sched_params *)
                               xmalloc(sizeof(libxl_sched_params) * (v_index));
                for (i = 0; i < v_index; i++)
                    scinfo.vcpus[i].vcpuid = vcpus[i];
                rc = -sched_rtds_vcpu_output(domid, &scinfo);
            } else /* get params for all vcpus */
                rc = -sched_rtds_vcpu_output_all(domid, &scinfo);
            libxl_vcpu_sched_params_dispose(&scinfo);
            if (rc) {
                r = EXIT_FAILURE;
                goto out;
            }
    } else if (opt_v || opt_all) {
            /* set per-vcpu rtds scheduling parameters */
            libxl_vcpu_sched_params scinfo;
            libxl_vcpu_sched_params_init(&scinfo);
            scinfo.sched = LIBXL_SCHEDULER_RTDS;
            if (v_index > 0) {
                scinfo.num_vcpus = v_index;
                scinfo.vcpus = (libxl_sched_params *)
                               xmalloc(sizeof(libxl_sched_params) * (v_index));
                for (i = 0; i < v_index; i++) {
                    scinfo.vcpus[i].vcpuid = vcpus[i];
                    scinfo.vcpus[i].period = periods[i];
                    scinfo.vcpus[i].budget = budgets[i];
                    scinfo.vcpus[i].extratime = extratimes[i] ? 1 : 0;
                }
                rc = sched_vcpu_set(domid, &scinfo);
            } else { /* set params for all vcpus */
                scinfo.num_vcpus = 1;
                scinfo.vcpus = (libxl_sched_params *)
                               xmalloc(sizeof(libxl_sched_params));
                scinfo.vcpus[0].period = periods[0];
                scinfo.vcpus[0].budget = budgets[0];
                scinfo.vcpus[0].extratime = extratimes[0] ? 1 : 0;
                rc = sched_vcpu_set_all(domid, &scinfo);
            }

            libxl_vcpu_sched_params_dispose(&scinfo);
            if (rc) {
                r = EXIT_FAILURE;
                goto out;
            }
        }
    }

    r = EXIT_SUCCESS;
out:
    free(vcpus);
    free(periods);
    free(budgets);
    free(extratimes);
    return r;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
