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

#include <stdlib.h>
#include <limits.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

static void print_vcpuinfo(uint32_t tdomid,
                           const libxl_vcpuinfo *vcpuinfo,
                           uint32_t nr_cpus)
{
    char *domname;

    /*      NAME  ID  VCPU */
    domname = libxl_domid_to_name(ctx, tdomid);
    printf("%-32s %5u %5u",
           domname, tdomid, vcpuinfo->vcpuid);
    free(domname);
    if (!vcpuinfo->online) {
        /*      CPU STA */
        printf("%5c %3c%cp ", '-', '-', '-');
    } else {
        /*      CPU STA */
        printf("%5u %3c%c- ", vcpuinfo->cpu,
               vcpuinfo->running ? 'r' : '-',
               vcpuinfo->blocked ? 'b' : '-');
    }
    /*      TIM */
    printf("%9.1f  ", ((float)vcpuinfo->vcpu_time / 1e9));
    /* CPU HARD AND SOFT AFFINITY */
    print_bitmap(vcpuinfo->cpumap.map, nr_cpus, stdout);
    printf(" / ");
    print_bitmap(vcpuinfo->cpumap_soft.map, nr_cpus, stdout);
    printf("\n");
}

static void print_domain_vcpuinfo(uint32_t domid, uint32_t nr_cpus)
{
    libxl_vcpuinfo *vcpuinfo;
    int i, nb_vcpu, nrcpus;

    vcpuinfo = libxl_list_vcpu(ctx, domid, &nb_vcpu, &nrcpus);

    if (!vcpuinfo)
        return;

    for (i = 0; i < nb_vcpu; i++) {
        print_vcpuinfo(domid, &vcpuinfo[i], nr_cpus);
    }

    libxl_vcpuinfo_list_free(vcpuinfo, nb_vcpu);
}

void apply_global_affinity_masks(libxl_domain_type type,
                                 libxl_bitmap *vcpu_affinity_array,
                                 unsigned int size)
{
    libxl_bitmap *mask = &global_vm_affinity_mask;
    libxl_bitmap *type_mask;
    unsigned int i;

    switch (type) {
    case LIBXL_DOMAIN_TYPE_HVM:
    case LIBXL_DOMAIN_TYPE_PVH:
        type_mask = &global_hvm_affinity_mask;
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        type_mask = &global_pv_affinity_mask;
        break;
    default:
        fprintf(stderr, "Unknown guest type\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < size; i++) {
        int rc;
        libxl_bitmap *t = &vcpu_affinity_array[i];
        libxl_bitmap b1, b2;

        libxl_bitmap_init(&b1);
        libxl_bitmap_init(&b2);

        rc = libxl_bitmap_and(ctx, &b1, t, mask);
        if (rc) {
            fprintf(stderr, "libxl_bitmap_and errored\n");
            exit(EXIT_FAILURE);
        }
        rc = libxl_bitmap_and(ctx, &b2, &b1, type_mask);
        if (rc) {
            fprintf(stderr, "libxl_bitmap_and errored\n");
            exit(EXIT_FAILURE);
        }

        if (libxl_bitmap_is_empty(&b2)) {
            fprintf(stderr, "vcpu hard affinity map is empty\n");
            exit(EXIT_FAILURE);
        }

        /* Replace target bitmap with the result */
        libxl_bitmap_dispose(t);
        libxl_bitmap_init(t);
        libxl_bitmap_copy_alloc(ctx, t, &b2);

        libxl_bitmap_dispose(&b1);
        libxl_bitmap_dispose(&b2);
    }
}

static void vcpulist(int argc, char **argv)
{
    libxl_dominfo *dominfo;
    libxl_physinfo physinfo;
    int i, nb_domain;

    if (libxl_get_physinfo(ctx, &physinfo) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        goto vcpulist_out;
    }

    printf("%-32s %5s %5s %5s %5s %9s %s\n",
           "Name", "ID", "VCPU", "CPU", "State", "Time(s)",
           "Affinity (Hard / Soft)");
    if (!argc) {
        if (!(dominfo = libxl_list_domain(ctx, &nb_domain))) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            goto vcpulist_out;
        }

        for (i = 0; i<nb_domain; i++)
            print_domain_vcpuinfo(dominfo[i].domid, physinfo.max_cpu_id + 1);

        libxl_dominfo_list_free(dominfo, nb_domain);
    } else {
        for (; argc > 0; ++argv, --argc) {
            uint32_t domid = find_domain(*argv);
            print_domain_vcpuinfo(domid, physinfo.max_cpu_id + 1);
        }
    }
  vcpulist_out:
    libxl_physinfo_dispose(&physinfo);
}

int main_vcpulist(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vcpu-list", 0) {
        /* No options */
    }

    vcpulist(argc - optind, argv + optind);
    return EXIT_SUCCESS;
}

int main_vcpupin(int argc, char **argv)
{
    static struct option opts[] = {
        {"force", 0, 0, 'f'},
        {"ignore-global-affinity-masks", 0, 0, 'i'},
        COMMON_LONG_OPTS
    };
    libxl_vcpuinfo *vcpuinfo;
    libxl_bitmap cpumap_hard, cpumap_soft;;
    libxl_bitmap *soft = &cpumap_soft, *hard = &cpumap_hard;
    uint32_t domid;
    /*
     * int would be enough for vcpuid, but we don't want to
     * mess aroung range checking the return value of strtol().
     */
    long vcpuid;
    const char *vcpu, *hard_str, *soft_str;
    char *endptr;
    int opt, nb_cpu, nb_vcpu, rc = EXIT_FAILURE;
    bool force = false, ignore_masks = false;

    libxl_bitmap_init(&cpumap_hard);
    libxl_bitmap_init(&cpumap_soft);

    SWITCH_FOREACH_OPT(opt, "fi", opts, "vcpu-pin", 3) {
    case 'f':
        force = true;
        break;
    case 'i':
        ignore_masks = true;
        break;
    default:
        break;
    }

    domid = find_domain(argv[optind]);
    vcpu = argv[optind+1];
    hard_str = argv[optind+2];
    soft_str = (argc > optind+3) ? argv[optind+3] : NULL;

    /* Figure out with which vCPU we are dealing with */
    vcpuid = strtol(vcpu, &endptr, 10);
    if (vcpu == endptr || vcpuid < 0) {
        if (strcmp(vcpu, "all")) {
            fprintf(stderr, "Error: Invalid argument %s as VCPU.\n", vcpu);
            goto out;
        }
        if (force) {
            fprintf(stderr, "Error: --force and 'all' as VCPU not allowed.\n");
            goto out;
        }
        vcpuid = -1;
    }

    if (libxl_cpu_bitmap_alloc(ctx, &cpumap_hard, 0) ||
        libxl_cpu_bitmap_alloc(ctx, &cpumap_soft, 0))
        goto out;

    /*
     * Syntax is: xl vcpu-pin <domid> <vcpu> <hard> <soft>
     * We want to handle all the following cases ('-' means
     * "leave it alone"):
     *  xl vcpu-pin 0 3 3,4
     *  xl vcpu-pin 0 3 3,4 -
     *  xl vcpu-pin 0 3 - 6-9
     *  xl vcpu-pin 0 3 3,4 6-9
     */

    /*
     * Hard affinity is always present. However, if it's "-", all we need
     * is passing a NULL pointer to the libxl_set_vcpuaffinity() call below.
     */
    if (!strcmp(hard_str, "-"))
        hard = NULL;
    else if (parse_cpurange(hard_str, hard))
        goto out;
    /*
     * Soft affinity is handled similarly. Only difference: we also want
     * to pass NULL to libxl_set_vcpuaffinity() if it is not specified.
     */
    if (argc <= optind+3 || !strcmp(soft_str, "-"))
        soft = NULL;
    else if (parse_cpurange(soft_str, soft))
        goto out;

    if (dryrun_only) {
        nb_cpu = libxl_get_max_cpus(ctx);
        if (nb_cpu < 0) {
            fprintf(stderr, "libxl_get_max_cpus failed.\n");
            goto out;
        }

        fprintf(stdout, "cpumap: ");
        if (hard)
            print_bitmap(hard->map, nb_cpu, stdout);
        else
            fprintf(stdout, "-");
        if (soft) {
            fprintf(stdout, " ");
            print_bitmap(soft->map, nb_cpu, stdout);
        }
        fprintf(stdout, "\n");

        if (ferror(stdout) || fflush(stdout)) {
            perror("stdout");
            exit(EXIT_FAILURE);
        }

        rc = EXIT_SUCCESS;
        goto out;
    }

    /* Only hard affinity matters here */
    if (!ignore_masks && hard) {
        libxl_dominfo dominfo;

        if (libxl_domain_info(ctx, &dominfo, domid)) {
            fprintf(stderr, "Could not get domain info\n");
            goto out;
        }

        /* HVM and PVH domains use the same global affinity mask */
        apply_global_affinity_masks(dominfo.domain_type, hard, 1);
    }

    if (force) {
        if (libxl_set_vcpuaffinity_force(ctx, domid, vcpuid, hard, soft)) {
            fprintf(stderr, "Could not set affinity for vcpu `%ld'.\n",
                    vcpuid);
            goto out;
        }
    }
    else if (vcpuid != -1) {
        if (libxl_set_vcpuaffinity(ctx, domid, vcpuid, hard, soft)) {
            fprintf(stderr, "Could not set affinity for vcpu `%ld'.\n",
                    vcpuid);
            goto out;
        }
    } else {
        if (!(vcpuinfo = libxl_list_vcpu(ctx, domid, &nb_vcpu, &nb_cpu))) {
            fprintf(stderr, "libxl_list_vcpu failed.\n");
            goto out;
        }
        if (libxl_set_vcpuaffinity_all(ctx, domid, nb_vcpu, hard, soft))
            fprintf(stderr, "Could not set affinity.\n");
        libxl_vcpuinfo_list_free(vcpuinfo, nb_vcpu);
    }

    rc = EXIT_SUCCESS;
 out:
    libxl_bitmap_dispose(&cpumap_soft);
    libxl_bitmap_dispose(&cpumap_hard);
    return rc;
}

static int vcpuset(uint32_t domid, const char* nr_vcpus, int check_host)
{
    char *endptr;
    unsigned int i;
    unsigned long max_vcpus;
    libxl_bitmap cpumap;
    int rc;

    libxl_bitmap_init(&cpumap);
    max_vcpus = strtoul(nr_vcpus, &endptr, 10);
    if (nr_vcpus == endptr || max_vcpus > INT_MAX) {
        fprintf(stderr, "Error: Invalid argument.\n");
        return 1;
    }

    /*
     * Maximum amount of vCPUS the guest is allowed to set is limited
     * by the host's amount of pCPUs.
     */
    if (check_host) {
        unsigned int online_vcpus, host_cpu = libxl_get_max_cpus(ctx);
        libxl_dominfo dominfo;

        if (libxl_domain_info(ctx, &dominfo, domid))
            return 1;

        online_vcpus = dominfo.vcpu_online;
        libxl_dominfo_dispose(&dominfo);

        if (max_vcpus > online_vcpus && max_vcpus > host_cpu) {
            fprintf(stderr, "You are overcommmitting! You have %d physical" \
                    " CPUs and want %ld vCPUs! Aborting, use --ignore-host to" \
                    " continue\n", host_cpu, max_vcpus);
            return 1;
        }
    }
    rc = libxl_cpu_bitmap_alloc(ctx, &cpumap, max_vcpus);
    if (rc) {
        fprintf(stderr, "libxl_cpu_bitmap_alloc failed, rc: %d\n", rc);
        return 1;
    }
    for (i = 0; i < max_vcpus; i++)
        libxl_bitmap_set(&cpumap, i);

    rc = libxl_set_vcpuonline(ctx, domid, &cpumap, NULL);
    if (rc == ERROR_DOMAIN_NOTFOUND)
        fprintf(stderr, "Domain %u does not exist.\n", domid);
    else if (rc)
        fprintf(stderr, "libxl_set_vcpuonline failed domid=%u max_vcpus=%ld," \
                " rc: %d\n", domid, max_vcpus, rc);

    libxl_bitmap_dispose(&cpumap);
    return rc ? 1 : 0;
}

int main_vcpuset(int argc, char **argv)
{
    static struct option opts[] = {
        {"ignore-host", 0, 0, 'i'},
        COMMON_LONG_OPTS
    };
    int opt, check_host = 1;

    SWITCH_FOREACH_OPT(opt, "i", opts, "vcpu-set", 2) {
    case 'i':
        check_host = 0;
        break;
    default:
        break;
    }

    if (vcpuset(find_domain(argv[optind]), argv[optind + 1], check_host))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
