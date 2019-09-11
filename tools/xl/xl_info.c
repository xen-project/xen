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

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_json.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"

/* Possibly select a specific piece of `xl info` to print. */
static const char *info_name;
static int maybe_printf(const char *fmt, ...) __attribute__((format(printf,1,2)));
static int maybe_printf(const char *fmt, ...)
{
    va_list ap;
    char *str;
    int count = 0;

    va_start(ap, fmt);
    if (vasprintf(&str, fmt, ap) != -1) {
        if (info_name) {
            char *s;

            if (!strncmp(str, info_name, strlen(info_name)) &&
                (s = strchr(str, ':')) && s[1] == ' ')
                count = fputs(&s[2], stdout);
        } else
            count = fputs(str, stdout);

        free(str);
    }
    va_end(ap);

    return count;
}

static yajl_gen_status printf_info_one_json(yajl_gen hand, int domid,
                                            libxl_domain_config *d_config)
{
    yajl_gen_status s;

    s = yajl_gen_map_open(hand);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_string(hand, (const unsigned char *)"domid",
                        sizeof("domid")-1);
    if (s != yajl_gen_status_ok)
        goto out;
    if (domid != -1)
        s = yajl_gen_integer(hand, domid);
    else
        s = yajl_gen_null(hand);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_string(hand, (const unsigned char *)"config",
                        sizeof("config")-1);
    if (s != yajl_gen_status_ok)
        goto out;
    s = libxl_domain_config_gen_json(hand, d_config);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_map_close(hand);
    if (s != yajl_gen_status_ok)
        goto out;

out:
    return s;
}

void printf_info(enum output_format output_format,
                 int domid,
                 libxl_domain_config *d_config, FILE *fh);
void printf_info(enum output_format output_format,
                 int domid,
                 libxl_domain_config *d_config, FILE *fh)
{
    if (output_format == OUTPUT_FORMAT_SXP)
        return printf_info_sexp(domid, d_config, fh);

    const char *buf;
    libxl_yajl_length len = 0;
    yajl_gen_status s;
    yajl_gen hand;

    hand = libxl_yajl_gen_alloc(NULL);
    if (!hand) {
        fprintf(stderr, "unable to allocate JSON generator\n");
        return;
    }

    s = printf_info_one_json(hand, domid, d_config);
    if (s != yajl_gen_status_ok)
        goto out;

    s = yajl_gen_get_buf(hand, (const unsigned char **)&buf, &len);
    if (s != yajl_gen_status_ok)
        goto out;

    fputs(buf, fh);

out:
    yajl_gen_free(hand);

    if (s != yajl_gen_status_ok)
        fprintf(stderr,
                "unable to format domain config as JSON (YAJL:%d)\n", s);

    flush_stream(fh);
}

static void output_xeninfo(void)
{
    const libxl_version_info *info;
    libxl_scheduler sched;
    int rc;

    if (!(info = libxl_get_version_info(ctx))) {
        fprintf(stderr, "libxl_get_version_info failed.\n");
        return;
    }

    rc = libxl_get_scheduler(ctx);
    if (rc < 0) {
        fprintf(stderr, "get_scheduler sysctl failed.\n");
        return;
    }
    sched = rc;

    maybe_printf("xen_major              : %d\n", info->xen_version_major);
    maybe_printf("xen_minor              : %d\n", info->xen_version_minor);
    maybe_printf("xen_extra              : %s\n", info->xen_version_extra);
    maybe_printf("xen_version            : %d.%d%s\n", info->xen_version_major,
           info->xen_version_minor, info->xen_version_extra);
    maybe_printf("xen_caps               : %s\n", info->capabilities);
    maybe_printf("xen_scheduler          : %s\n", libxl_scheduler_to_string(sched));
    maybe_printf("xen_pagesize           : %u\n", info->pagesize);
    maybe_printf("platform_params        : virt_start=0x%"PRIx64"\n", info->virt_start);
    maybe_printf("xen_changeset          : %s\n", info->changeset);
    maybe_printf("xen_commandline        : %s\n", info->commandline);
    maybe_printf("cc_compiler            : %s\n", info->compiler);
    maybe_printf("cc_compile_by          : %s\n", info->compile_by);
    maybe_printf("cc_compile_domain      : %s\n", info->compile_domain);
    maybe_printf("cc_compile_date        : %s\n", info->compile_date);
    maybe_printf("build_id               : %s\n", info->build_id);

    return;
}

static void output_nodeinfo(void)
{
    struct utsname utsbuf;

    if (uname(&utsbuf) < 0)
        return;

    maybe_printf("host                   : %s\n", utsbuf.nodename);
    maybe_printf("release                : %s\n", utsbuf.release);
    maybe_printf("version                : %s\n", utsbuf.version);
    maybe_printf("machine                : %s\n", utsbuf.machine);
}

static void output_physinfo(void)
{
    libxl_physinfo info;
    const libxl_version_info *vinfo;
    unsigned int i;
    libxl_bitmap cpumap;
    int n = 0;

    if (libxl_get_physinfo(ctx, &info) != 0) {
        fprintf(stderr, "libxl_physinfo failed.\n");
        return;
    }
    maybe_printf("nr_cpus                : %d\n", info.nr_cpus);
    maybe_printf("max_cpu_id             : %d\n", info.max_cpu_id);
    maybe_printf("nr_nodes               : %d\n", info.nr_nodes);
    maybe_printf("cores_per_socket       : %d\n", info.cores_per_socket);
    maybe_printf("threads_per_core       : %d\n", info.threads_per_core);
    maybe_printf("cpu_mhz                : %d.%03d\n", info.cpu_khz / 1000, info.cpu_khz % 1000);

    maybe_printf("hw_caps                : %08x:%08x:%08x:%08x:%08x:%08x:%08x:%08x\n",
         info.hw_cap[0], info.hw_cap[1], info.hw_cap[2], info.hw_cap[3],
         info.hw_cap[4], info.hw_cap[5], info.hw_cap[6], info.hw_cap[7]
        );

    maybe_printf("virt_caps              :%s%s%s%s%s\n",
         info.cap_pv ? " pv" : "",
         info.cap_hvm ? " hvm" : "",
         info.cap_hvm && info.cap_hvm_directio ? " hvm_directio" : "",
         info.cap_pv && info.cap_hvm_directio ? " pv_directio" : "",
         info.cap_hap ? " hap" : ""
        );

    vinfo = libxl_get_version_info(ctx);
    if (vinfo) {
        i = (1 << 20) / vinfo->pagesize;
        maybe_printf("total_memory           : %"PRIu64"\n", info.total_pages / i);
        maybe_printf("free_memory            : %"PRIu64"\n", (info.free_pages - info.outstanding_pages) / i);
        maybe_printf("sharing_freed_memory   : %"PRIu64"\n", info.sharing_freed_pages / i);
        maybe_printf("sharing_used_memory    : %"PRIu64"\n", info.sharing_used_frames / i);
        maybe_printf("outstanding_claims     : %"PRIu64"\n", info.outstanding_pages / i);
    }
    if (!libxl_get_freecpus(ctx, &cpumap)) {
        libxl_for_each_bit(i, cpumap)
            if (libxl_bitmap_test(&cpumap, i))
                n++;
        maybe_printf("free_cpus              : %d\n", n);
        free(cpumap.map);
    }
    libxl_physinfo_dispose(&info);
    return;
}

static void output_numainfo(void)
{
    libxl_numainfo *info;
    int i, j, nr;

    info = libxl_get_numainfo(ctx, &nr);
    if (info == NULL) {
        fprintf(stderr, "libxl_get_numainfo failed.\n");
        return;
    }

    printf("numa_info              :\n");
    printf("node:    memsize    memfree    distances\n");

    for (i = 0; i < nr; i++) {
        if (info[i].size != LIBXL_NUMAINFO_INVALID_ENTRY) {
            printf("%4d:    %6"PRIu64"     %6"PRIu64"      %d", i,
                   info[i].size >> 20, info[i].free >> 20,
                   info[i].dists[0]);
            for (j = 1; j < info[i].num_dists; j++)
                printf(",%d", info[i].dists[j]);
            printf("\n");
        }
    }

    libxl_numainfo_list_free(info, nr);

    return;
}

static void output_topologyinfo(void)
{
    libxl_cputopology *cpuinfo;
    int i, nr;
    libxl_pcitopology *pciinfo;
    int valid_devs = 0;


    cpuinfo = libxl_get_cpu_topology(ctx, &nr);
    if (cpuinfo == NULL) {
        fprintf(stderr, "libxl_get_cpu_topology failed.\n");
        return;
    }

    printf("cpu_topology           :\n");
    printf("cpu:    core    socket     node\n");

    for (i = 0; i < nr; i++) {
        if (cpuinfo[i].core != LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
            printf("%3d:    %4d     %4d     %4d\n", i,
                   cpuinfo[i].core, cpuinfo[i].socket, cpuinfo[i].node);
    }

    libxl_cputopology_list_free(cpuinfo, nr);

    pciinfo = libxl_get_pci_topology(ctx, &nr);
    if (pciinfo == NULL) {
        fprintf(stderr, "libxl_get_pci_topology failed.\n");
        return;
    }

    printf("device topology        :\n");
    printf("device           node\n");
    for (i = 0; i < nr; i++) {
        if (pciinfo[i].node != LIBXL_PCITOPOLOGY_INVALID_ENTRY) {
            printf("%04x:%02x:%02x.%01x      %d\n", pciinfo[i].seg,
                   pciinfo[i].bus,
                   ((pciinfo[i].devfn >> 3) & 0x1f), (pciinfo[i].devfn & 7),
                   pciinfo[i].node);
            valid_devs++;
        }
    }

    if (valid_devs == 0)
        printf("No device topology data available\n");

    libxl_pcitopology_list_free(pciinfo, nr);

    return;
}

static void print_info(int numa)
{
    output_nodeinfo();

    output_physinfo();

    if (numa) {
        output_topologyinfo();
        output_numainfo();
    }
    output_xeninfo();

    maybe_printf("xend_config_format     : 4\n");

    return;
}

static void list_vm(void)
{
    libxl_vminfo *info;
    char *domname;
    int nb_vm, i;

    info = libxl_list_vm(ctx, &nb_vm);

    if (!info) {
        fprintf(stderr, "libxl_list_vm failed.\n");
        exit(EXIT_FAILURE);
    }
    printf("UUID                                  ID    name\n");
    for (i = 0; i < nb_vm; i++) {
        domname = libxl_domid_to_name(ctx, info[i].domid);
        printf(LIBXL_UUID_FMT "  %d    %-30s\n", LIBXL_UUID_BYTES(info[i].uuid),
            info[i].domid, domname);
        free(domname);
    }
    libxl_vminfo_list_free(info, nb_vm);
}

static void list_domains(bool verbose, bool context, bool claim, bool numa,
                         bool cpupool, const libxl_dominfo *info, int nb_domain)
{
    int i;
    static const char shutdown_reason_letters[]= "-rscwS";
    libxl_bitmap nodemap;
    libxl_physinfo physinfo;

    libxl_bitmap_init(&nodemap);
    libxl_physinfo_init(&physinfo);

    printf("Name                                        ID   Mem VCPUs\tState\tTime(s)");
    if (verbose) printf("   UUID                            Reason-Code\tSecurity Label");
    if (context && !verbose) printf("   Security Label");
    if (claim) printf("  Claimed");
    if (cpupool) printf("         Cpupool");
    if (numa) {
        if (libxl_node_bitmap_alloc(ctx, &nodemap, 0)) {
            fprintf(stderr, "libxl_node_bitmap_alloc_failed.\n");
            exit(EXIT_FAILURE);
        }
        if (libxl_get_physinfo(ctx, &physinfo) != 0) {
            fprintf(stderr, "libxl_physinfo failed.\n");
            libxl_bitmap_dispose(&nodemap);
            exit(EXIT_FAILURE);
        }

        printf(" NODE Affinity");
    }
    printf("\n");
    for (i = 0; i < nb_domain; i++) {
        char *domname;
        libxl_shutdown_reason shutdown_reason;
        domname = libxl_domid_to_name(ctx, info[i].domid);
        shutdown_reason = info[i].shutdown ? info[i].shutdown_reason : 0;
        printf("%-40s %5d %5lu %5d     %c%c%c%c%c%c  %8.1f",
                domname,
                info[i].domid,
                (unsigned long) ((info[i].current_memkb +
                    info[i].outstanding_memkb)/ 1024),
                info[i].vcpu_online,
                info[i].running ? 'r' : '-',
                info[i].blocked ? 'b' : '-',
                info[i].paused ? 'p' : '-',
                info[i].shutdown ? 's' : '-',
                (shutdown_reason >= 0 &&
                 shutdown_reason < sizeof(shutdown_reason_letters)-1
                 ? shutdown_reason_letters[shutdown_reason] : '?'),
                info[i].dying ? 'd' : '-',
                ((float)info[i].cpu_time / 1e9));
        free(domname);
        if (verbose) {
            printf(" " LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info[i].uuid));
            if (info[i].shutdown) printf(" %8x", shutdown_reason);
            else printf(" %8s", "-");
        }
        if (claim)
            printf(" %5lu", (unsigned long)info[i].outstanding_memkb / 1024);
        if (verbose || context)
            printf(" %16s", info[i].ssid_label ? : "-");
        if (cpupool) {
            char *poolname = libxl_cpupoolid_to_name(ctx, info[i].cpupool);
            printf("%16s", poolname);
            free(poolname);
        }
        if (numa) {
            libxl_domain_get_nodeaffinity(ctx, info[i].domid, &nodemap);

            putchar(' ');
            print_bitmap(nodemap.map, physinfo.nr_nodes, stdout);
        }
        putchar('\n');
    }

    libxl_bitmap_dispose(&nodemap);
    libxl_physinfo_dispose(&physinfo);
}

static void list_domains_details(const libxl_dominfo *info, int nb_domain)
{
    libxl_domain_config d_config;

    int i, rc;

    yajl_gen hand = NULL;
    yajl_gen_status s;
    const char *buf;
    libxl_yajl_length yajl_len = 0;

    if (default_output_format == OUTPUT_FORMAT_JSON) {
        hand = libxl_yajl_gen_alloc(NULL);
        if (!hand) {
            fprintf(stderr, "unable to allocate JSON generator\n");
            return;
        }

        s = yajl_gen_array_open(hand);
        if (s != yajl_gen_status_ok)
            goto out;
    } else
        s = yajl_gen_status_ok;

    for (i = 0; i < nb_domain; i++) {
        libxl_domain_config_init(&d_config);
        rc = libxl_retrieve_domain_configuration(ctx, info[i].domid, &d_config);
        if (rc)
            continue;
        if (default_output_format == OUTPUT_FORMAT_JSON)
            s = printf_info_one_json(hand, info[i].domid, &d_config);
        else
            printf_info_sexp(info[i].domid, &d_config, stdout);
        libxl_domain_config_dispose(&d_config);
        if (s != yajl_gen_status_ok)
            goto out;
    }

    if (default_output_format == OUTPUT_FORMAT_JSON) {
        s = yajl_gen_array_close(hand);
        if (s != yajl_gen_status_ok)
            goto out;

        s = yajl_gen_get_buf(hand, (const unsigned char **)&buf, &yajl_len);
        if (s != yajl_gen_status_ok)
            goto out;

        puts(buf);
    }

out:
    if (default_output_format == OUTPUT_FORMAT_JSON) {
        yajl_gen_free(hand);
        if (s != yajl_gen_status_ok)
            fprintf(stderr,
                    "unable to format domain config as JSON (YAJL:%d)\n", s);
    }
}


int main_list(int argc, char **argv)
{
    int opt;
    bool verbose = false;
    bool context = false;
    bool details = false;
    bool cpupool = false;
    bool numa = false;
    static struct option opts[] = {
        {"long", 0, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"context", 0, 0, 'Z'},
        {"cpupool", 0, 0, 'c'},
        {"numa", 0, 0, 'n'},
        COMMON_LONG_OPTS
    };

    libxl_dominfo info_buf;
    libxl_dominfo *info, *info_free=0;
    int nb_domain, rc;

    SWITCH_FOREACH_OPT(opt, "lvhZcn", opts, "list", 0) {
    case 'l':
        details = true;
        break;
    case 'v':
        verbose = true;
        break;
    case 'Z':
        context = true;
        break;
    case 'c':
        cpupool = true;
        break;
    case 'n':
        numa = true;
        break;
    }

    libxl_dominfo_init(&info_buf);

    if (optind >= argc) {
        info = libxl_list_domain(ctx, &nb_domain);
        if (!info) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            return EXIT_FAILURE;
        }
        info_free = info;
    } else if (optind == argc-1) {
        uint32_t domid = find_domain(argv[optind]);
        rc = libxl_domain_info(ctx, &info_buf, domid);
        if (rc == ERROR_DOMAIN_NOTFOUND) {
            fprintf(stderr, "Error: Domain \'%s\' does not exist.\n",
                argv[optind]);
            return EXIT_FAILURE;
        }
        if (rc) {
            fprintf(stderr, "libxl_domain_info failed (code %d).\n", rc);
            return EXIT_FAILURE;
        }
        info = &info_buf;
        nb_domain = 1;
    } else {
        help("list");
        return EXIT_FAILURE;
    }

    if (details)
        list_domains_details(info, nb_domain);
    else
        list_domains(verbose, context, false /* claim */, numa, cpupool,
                     info, nb_domain);

    if (info_free)
        libxl_dominfo_list_free(info, nb_domain);

    libxl_dominfo_dispose(&info_buf);

    return EXIT_SUCCESS;
}

int main_vm_list(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vm-list", 0) {
        /* No options */
    }

    list_vm();
    return EXIT_SUCCESS;
}

int main_info(int argc, char **argv)
{
    int opt;
    static struct option opts[] = {
        {"numa", 0, 0, 'n'},
        COMMON_LONG_OPTS
    };
    int numa = 0;

    SWITCH_FOREACH_OPT(opt, "n", opts, "info", 0) {
    case 'n':
        numa = 1;
        break;
    }

    /*
     * If an extra argument is provided, filter out a specific piece of
     * information.
     */
    if (numa == 0 && argc > optind)
        info_name = argv[optind];

    print_info(numa);
    return 0;
}

int main_domid(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *domname = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "domid", 1) {
        /* No options */
    }

    domname = argv[optind];

    if (libxl_name_to_domid(ctx, domname, &domid)) {
        fprintf(stderr, "Can't get domid of domain name '%s', maybe this domain does not exist.\n", domname);
        return EXIT_FAILURE;
    }

    printf("%u\n", domid);

    return EXIT_SUCCESS;
}

int main_domname(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    char *domname = NULL;
    char *endptr = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "domname", 1) {
        /* No options */
    }

    domid = strtol(argv[optind], &endptr, 10);
    if (domid == 0 && !strcmp(endptr, argv[optind])) {
        /*no digits at all*/
        fprintf(stderr, "Invalid domain id.\n\n");
        return EXIT_FAILURE;
    }

    domname = libxl_domid_to_name(ctx, domid);
    if (!domname) {
        fprintf(stderr, "Can't get domain name of domain id '%u', maybe this domain does not exist.\n", domid);
        return EXIT_FAILURE;
    }

    printf("%s\n", domname);
    free(domname);

    return EXIT_SUCCESS;
}

static char *uptime_to_string(unsigned long uptime, int short_mode)
{
    int sec, min, hour, day;
    char *time_string;

    day = (int)(uptime / 86400);
    uptime -= (day * 86400);
    hour = (int)(uptime / 3600);
    uptime -= (hour * 3600);
    min = (int)(uptime / 60);
    uptime -= (min * 60);
    sec = uptime;

    if (short_mode)
        if (day > 1)
            xasprintf(&time_string, "%d days, %2d:%02d", day, hour, min);
        else if (day == 1)
            xasprintf(&time_string, "%d day, %2d:%02d", day, hour, min);
        else
            xasprintf(&time_string, "%2d:%02d", hour, min);
    else
        if (day > 1)
            xasprintf(&time_string, "%d days, %2d:%02d:%02d", day, hour, min, sec);
        else if (day == 1)
            xasprintf(&time_string, "%d day, %2d:%02d:%02d", day, hour, min, sec);
        else
            xasprintf(&time_string, "%2d:%02d:%02d", hour, min, sec);

    return time_string;
}

int main_claims(int argc, char **argv)
{
    libxl_dominfo *info;
    int opt;
    int nb_domain;

    SWITCH_FOREACH_OPT(opt, "", NULL, "claims", 0) {
        /* No options */
    }

    if (!claim_mode)
        fprintf(stderr, "claim_mode not enabled (see man xl.conf).\n");

    info = libxl_list_domain(ctx, &nb_domain);
    if (!info) {
        fprintf(stderr, "libxl_list_domain failed.\n");
        return 1;
    }

    list_domains(false /* verbose */, false /* context */, true /* claim */,
                 false /* numa */, false /* cpupool */, info, nb_domain);

    libxl_dominfo_list_free(info, nb_domain);
    return 0;
}

static char *current_time_to_string(time_t now)
{
    char now_str[100];
    struct tm *tmp;

    tmp = localtime(&now);
    if (tmp == NULL) {
        fprintf(stderr, "Get localtime error");
        exit(-1);
    }
    if (strftime(now_str, sizeof(now_str), "%H:%M:%S", tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(-1);
    }
    return strdup(now_str);
}

static void print_dom0_uptime(int short_mode, time_t now)
{
    int fd;
    ssize_t nr;
    char buf[512];
    uint32_t uptime = 0;
    char *uptime_str = NULL;
    char *now_str = NULL;
    char *domname;

    fd = open("/proc/uptime", O_RDONLY);
    if (fd == -1)
        goto err;

    nr = read(fd, buf, sizeof(buf) - 1);
    if (nr == -1) {
        close(fd);
        goto err;
    }
    close(fd);

    buf[nr] = '\0';

    strtok(buf, " ");
    uptime = strtoul(buf, NULL, 10);

    domname = libxl_domid_to_name(ctx, 0);
    if (short_mode)
    {
        now_str = current_time_to_string(now);
        uptime_str = uptime_to_string(uptime, 1);
        printf(" %s up %s, %s (%d)\n", now_str, uptime_str,
               domname, 0);
    }
    else
    {
        now_str = NULL;
        uptime_str = uptime_to_string(uptime, 0);
        printf("%-33s %4d %s\n", domname,
               0, uptime_str);
    }

    free(now_str);
    free(uptime_str);
    free(domname);
    return;
err:
    fprintf(stderr, "Can not get Dom0 uptime.\n");
    exit(-1);
}

static void print_domU_uptime(uint32_t domuid, int short_mode, time_t now)
{
    uint32_t s_time = 0;
    uint32_t uptime = 0;
    char *uptime_str = NULL;
    char *now_str = NULL;
    char *domname;

    s_time = libxl_vm_get_start_time(ctx, domuid);
    if (s_time == -1)
        return;
    uptime = now - s_time;
    domname = libxl_domid_to_name(ctx, domuid);
    if (short_mode)
    {
        now_str = current_time_to_string(now);
        uptime_str = uptime_to_string(uptime, 1);
        printf(" %s up %s, %s (%d)\n", now_str, uptime_str,
               domname, domuid);
    }
    else
    {
        now_str = NULL;
        uptime_str = uptime_to_string(uptime, 0);
        printf("%-33s %4d %s\n", domname,
               domuid, uptime_str);
    }

    free(domname);
    free(now_str);
    free(uptime_str);
    return;
}

static void print_uptime(int short_mode, uint32_t doms[], int nb_doms)
{
    libxl_vminfo *info;
    time_t now;
    int nb_vm, i;

    now = time(NULL);

    if (!short_mode)
        printf("%-33s %4s %s\n", "Name", "ID", "Uptime");

    if (nb_doms == 0) {
        print_dom0_uptime(short_mode, now);
        info = libxl_list_vm(ctx, &nb_vm);
        if (info == NULL) {
            fprintf(stderr, "Could not list vms.\n");
            return;
        }
        for (i = 0; i < nb_vm; i++) {
            if (info[i].domid == 0) continue;
            print_domU_uptime(info[i].domid, short_mode, now);
        }
        libxl_vminfo_list_free(info, nb_vm);
    } else {
        for (i = 0; i < nb_doms; i++) {
            if (doms[i] == 0)
                print_dom0_uptime(short_mode, now);
            else
                print_domU_uptime(doms[i], short_mode, now);
        }
    }
}

int main_uptime(int argc, char **argv)
{
    const char *dom;
    int short_mode = 0;
    uint32_t domains[100];
    int nb_doms = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "s", NULL, "uptime", 0) {
    case 's':
        short_mode = 1;
        break;
    }

    for (;(dom = argv[optind]) != NULL; nb_doms++,optind++)
        domains[nb_doms] = find_domain(dom);

    print_uptime(short_mode, domains, nb_doms);

    return 0;
}

int main_dmesg(int argc, char **argv)
{
    unsigned int clear = 0;
    libxl_xen_console_reader *cr;
    char *line;
    int opt, ret = 1;
    static struct option opts[] = {
        {"clear", 0, 0, 'c'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "c", opts, "dmesg", 0) {
    case 'c':
        clear = 1;
        break;
    }

    cr = libxl_xen_console_read_start(ctx, clear);
    if (!cr)
        goto finish;

    while ((ret = libxl_xen_console_read_line(ctx, cr, &line)) > 0)
        printf("%s", line);

finish:
    if (cr)
        libxl_xen_console_read_finish(ctx, cr);
    return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main_top(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "top", 0) {
        /* No options */
    }

    return system("xentop");
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
