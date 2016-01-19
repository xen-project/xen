/*
 * xenpm.c: list the power information of the available processors
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */
#define MAX_NR_CPU 512

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <xenctrl.h>
#include <inttypes.h>
#include <sys/time.h>

#define MAX_PKG_RESIDENCIES 12
#define MAX_CORE_RESIDENCIES 8

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static xc_interface *xc_handle;
static unsigned int max_cpu_nr;

/* help message */
void show_help(void)
{
    fprintf(stderr,
            "xen power management control tool\n\n"
            "usage: xenpm <command> [args]\n\n"
            "xenpm command list:\n\n"
            " get-cpuidle-states    [cpuid]       list cpu idle info of CPU <cpuid> or all\n"
            " get-cpufreq-states    [cpuid]       list cpu freq info of CPU <cpuid> or all\n"
            " get-cpufreq-average   [cpuid]       average cpu frequency since last invocation\n"
            "                                     for CPU <cpuid> or all\n"
            " get-cpufreq-para      [cpuid]       list cpu freq parameter of CPU <cpuid> or all\n"
            " set-scaling-maxfreq   [cpuid] <HZ>  set max cpu frequency <HZ> on CPU <cpuid>\n"
            "                                     or all CPUs\n"
            " set-scaling-minfreq   [cpuid] <HZ>  set min cpu frequency <HZ> on CPU <cpuid>\n"
            "                                     or all CPUs\n"
            " set-scaling-speed     [cpuid] <num> set scaling speed on CPU <cpuid> or all\n"
            "                                     it is used in userspace governor.\n"
            " set-scaling-governor  [cpuid] <gov> set scaling governor on CPU <cpuid> or all\n"
            "                                     as userspace/performance/powersave/ondemand\n"
            " set-sampling-rate     [cpuid] <num> set sampling rate on CPU <cpuid> or all\n"
            "                                     it is used in ondemand governor.\n"
            " set-up-threshold      [cpuid] <num> set up threshold on CPU <cpuid> or all\n"
            "                                     it is used in ondemand governor.\n"
            " get-cpu-topology                    get thread/core/socket topology info\n"
            " set-sched-smt           enable|disable enable/disable scheduler smt power saving\n"
            " set-vcpu-migration-delay      <num> set scheduler vcpu migration delay in us\n"
            " get-vcpu-migration-delay            get scheduler vcpu migration delay\n"
            " set-max-cstate        <num>         set the C-State limitation (<num> >= 0)\n"
            " start [seconds]                     start collect Cx/Px statistics,\n"
            "                                     output after CTRL-C or SIGINT or several seconds.\n"
            " enable-turbo-mode     [cpuid]       enable Turbo Mode for processors that support it.\n"
            " disable-turbo-mode    [cpuid]       disable Turbo Mode for processors that support it.\n"
            );
}
/* wrapper function */
void help_func(int argc, char *argv[])
{
    show_help();
}

static void parse_cpuid(const char *arg, int *cpuid)
{
    if ( sscanf(arg, "%d", cpuid) != 1 || *cpuid < 0 )
    {
        if ( strcasecmp(arg, "all") )
        {
            fprintf(stderr, "Invalid CPU identifier: '%s'\n", arg);
            exit(EINVAL);
        }
        *cpuid = -1;
    }
}

static void parse_cpuid_and_int(int argc, char *argv[],
                                int *cpuid, int *val, const char *what)
{
    if ( argc > 1 )
        parse_cpuid(argv[0], cpuid);

    if ( argc == 0 || sscanf(argv[argc > 1], "%d", val) != 1 )
    {
        fprintf(stderr, argc ? "Invalid %s '%s'\n" : "Missing %s\n",
                what, argv[argc > 1]);
        exit(EINVAL);
    }
}

static void print_cxstat(int cpuid, struct xc_cx_stat *cxstat)
{
    unsigned int i;

    printf("cpu id               : %d\n", cpuid);
    printf("total C-states       : %d\n", cxstat->nr);
    printf("idle time(ms)        : %"PRIu64"\n",
           cxstat->idle_time/1000000UL);
    for ( i = 0; i < cxstat->nr; i++ )
    {
        printf("C%-20d: transition [%20"PRIu64"]\n",
               i, cxstat->triggers[i]);
        printf("                       residency  [%20"PRIu64" ms]\n",
               cxstat->residencies[i]/1000000UL);
    }
    for ( i = 0; i < MAX_PKG_RESIDENCIES && i < cxstat->nr_pc; ++i )
        if ( cxstat->pc[i] )
           printf("pc%d                  : [%20"PRIu64" ms]\n", i + 1,
                  cxstat->pc[i] / 1000000UL);
    for ( i = 0; i < MAX_CORE_RESIDENCIES && i < cxstat->nr_cc; ++i )
        if ( cxstat->cc[i] )
           printf("cc%d                  : [%20"PRIu64" ms]\n", i + 1,
                  cxstat->cc[i] / 1000000UL);
    printf("\n");
}

/* show cpu idle information on CPU cpuid */
static int get_cxstat_by_cpuid(xc_interface *xc_handle, int cpuid, struct xc_cx_stat *cxstat)
{
    int ret = 0;
    int max_cx_num = 0;

    ret = xc_pm_get_max_cx(xc_handle, cpuid, &max_cx_num);
    if ( ret )
        return -errno;

    if ( !cxstat )
        return -EINVAL;

    if ( !max_cx_num )
        return -ENODEV;

    cxstat->triggers = calloc(max_cx_num, sizeof(*cxstat->triggers));
    cxstat->residencies = calloc(max_cx_num, sizeof(*cxstat->residencies));
    cxstat->pc = calloc(MAX_PKG_RESIDENCIES, sizeof(*cxstat->pc));
    cxstat->cc = calloc(MAX_CORE_RESIDENCIES, sizeof(*cxstat->cc));
    if ( !cxstat->triggers || !cxstat->residencies ||
         !cxstat->pc || !cxstat->cc )
    {
        free(cxstat->cc);
        free(cxstat->pc);
        free(cxstat->residencies);
        free(cxstat->triggers);
        return -ENOMEM;
    }

    cxstat->nr = max_cx_num;
    cxstat->nr_pc = MAX_PKG_RESIDENCIES;
    cxstat->nr_cc = MAX_CORE_RESIDENCIES;

    ret = xc_pm_get_cxstat(xc_handle, cpuid, cxstat);
    if( ret )
    {
        ret = -errno;
        free(cxstat->triggers);
        free(cxstat->residencies);
        free(cxstat->pc);
        free(cxstat->cc);
        cxstat->triggers = NULL;
        cxstat->residencies = NULL;
        cxstat->pc = NULL;
        cxstat->cc = NULL;
    }

    return ret;
}

static int show_max_cstate(xc_interface *xc_handle)
{
    int ret = 0;
    uint32_t value;

    if ( (ret = xc_get_cpuidle_max_cstate(xc_handle, &value)) )
        return ret;

    printf("Max possible C-state: C%d\n\n", value);
    return 0;
}

static int show_cxstat_by_cpuid(xc_interface *xc_handle, int cpuid)
{
    int ret = 0;
    struct xc_cx_stat cxstatinfo;

    ret = get_cxstat_by_cpuid(xc_handle, cpuid, &cxstatinfo);
    if ( ret )
    {
        if ( ret == -ENODEV )
            fprintf(stderr,
                    "Either Xen cpuidle is disabled or no valid information is registered!\n");
        return ret;
    }

    print_cxstat(cpuid, &cxstatinfo);

    free(cxstatinfo.triggers);
    free(cxstatinfo.residencies);
    free(cxstatinfo.pc);
    free(cxstatinfo.cc);
    return 0;
}

void cxstat_func(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    show_max_cstate(xc_handle);

    if ( cpuid < 0 )
    {
        /* show cxstates on all cpus */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( show_cxstat_by_cpuid(xc_handle, i) == -ENODEV )
                break;
    }
    else
        show_cxstat_by_cpuid(xc_handle, cpuid);
}

static void print_pxstat(int cpuid, struct xc_px_stat *pxstat)
{
    int i;

    printf("cpu id               : %d\n", cpuid);
    printf("total P-states       : %d\n", pxstat->total);
    printf("usable P-states      : %d\n", pxstat->usable);
    printf("current frequency    : %"PRIu64" MHz\n",
           pxstat->pt[pxstat->cur].freq);
    for ( i = 0; i < pxstat->total; i++ )
    {
        if ( pxstat->cur == i )
            printf("*P%-9d", i);
        else
            printf("P%-10d", i);
        printf("[%4"PRIu64" MHz]", pxstat->pt[i].freq);
        printf(": transition [%20"PRIu64"]\n",
               pxstat->pt[i].count);
        printf("                       residency  [%20"PRIu64" ms]\n",
               pxstat->pt[i].residency/1000000UL);
    }
    printf("\n");
}

/* show cpu frequency information on CPU cpuid */
static int get_pxstat_by_cpuid(xc_interface *xc_handle, int cpuid, struct xc_px_stat *pxstat)
{
    int ret = 0;
    int max_px_num = 0;

    ret = xc_pm_get_max_px(xc_handle, cpuid, &max_px_num);
    if ( ret )
        return -errno;

    if ( !pxstat)
        return -EINVAL;

    pxstat->trans_pt = malloc(max_px_num * max_px_num *
                              sizeof(uint64_t));
    if ( !pxstat->trans_pt )
        return -ENOMEM;
    pxstat->pt = malloc(max_px_num * sizeof(struct xc_px_val));
    if ( !pxstat->pt )
    {
        free(pxstat->trans_pt);
        return -ENOMEM;
    }

    ret = xc_pm_get_pxstat(xc_handle, cpuid, pxstat);
    if( ret )
    {
        ret = -errno;
        free(pxstat->trans_pt);
        free(pxstat->pt);
        pxstat->trans_pt = NULL;
        pxstat->pt = NULL;
    }

    return ret;
}

/* show cpu actual average freq information on CPU cpuid */
static int get_avgfreq_by_cpuid(xc_interface *xc_handle, int cpuid, int *avgfreq)
{
    int ret = 0;

    ret = xc_get_cpufreq_avgfreq(xc_handle, cpuid, avgfreq);
    if ( ret )
        ret = -errno;

    return ret;
}

static int show_pxstat_by_cpuid(xc_interface *xc_handle, int cpuid)
{
    int ret = 0;
    struct xc_px_stat pxstatinfo;

    ret = get_pxstat_by_cpuid(xc_handle, cpuid, &pxstatinfo);
    if ( ret )
        return ret;

    print_pxstat(cpuid, &pxstatinfo);

    free(pxstatinfo.trans_pt);
    free(pxstatinfo.pt);
    return 0;
}

void pxstat_func(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    if ( cpuid < 0 )
    {
        /* show pxstates on all cpus */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( show_pxstat_by_cpuid(xc_handle, i) == -ENODEV )
                break;
    }
    else
        show_pxstat_by_cpuid(xc_handle, cpuid);
}

static int show_cpufreq_by_cpuid(xc_interface *xc_handle, int cpuid)
{
    int ret = 0;
    int average_cpufreq;

    ret = get_avgfreq_by_cpuid(xc_handle, cpuid, &average_cpufreq);
    if ( ret )
        return ret;

    printf("cpu id               : %d\n", cpuid);
    printf("average cpu frequency: %d\n", average_cpufreq);
    printf("\n");
    return 0;
}

void cpufreq_func(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    if ( cpuid < 0 )
    {
        /* show average frequency on all cpus */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( show_cpufreq_by_cpuid(xc_handle, i) == -ENODEV )
                break;
    }
    else
        show_cpufreq_by_cpuid(xc_handle, cpuid);
}

static uint64_t usec_start, usec_end;
static struct xc_cx_stat *cxstat, *cxstat_start, *cxstat_end;
static struct xc_px_stat *pxstat, *pxstat_start, *pxstat_end;
static int *avgfreq;
static uint64_t *sum, *sum_cx, *sum_px;

static void signal_int_handler(int signo)
{
    int i, j, k;
    struct timeval tv;
    int cx_cap = 0, px_cap = 0;
    xc_cputopo_t *cputopo = NULL;
    unsigned max_cpus = 0;

    if ( xc_cputopoinfo(xc_handle, &max_cpus, NULL) != 0 )
    {
        fprintf(stderr, "failed to discover number of CPUs: %s\n",
                strerror(errno));
        goto out;
    }

    cputopo = calloc(max_cpus, sizeof(*cputopo));
    if ( cputopo == NULL )
    {
	fprintf(stderr, "failed to allocate hypercall buffers\n");
	goto out;
    }

    if ( gettimeofday(&tv, NULL) )
    {
        fprintf(stderr, "failed to get timeofday\n");
        goto out;
    }
    usec_end = tv.tv_sec * 1000000UL + tv.tv_usec;

    if ( get_cxstat_by_cpuid(xc_handle, 0, NULL) != -ENODEV )
    {
        cx_cap = 1;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( !get_cxstat_by_cpuid(xc_handle, i, &cxstat_end[i]) )
                for ( j = 0; j < cxstat_end[i].nr; j++ )
                {
                    int64_t diff = (int64_t)cxstat_end[i].residencies[j] -
                        (int64_t)cxstat_start[i].residencies[j];
                    if ( diff >=0 )
                        sum_cx[i] += diff;
                }
    }

    if ( get_pxstat_by_cpuid(xc_handle, 0, NULL) != -ENODEV )
    {
        px_cap = 1;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( !get_pxstat_by_cpuid(xc_handle, i , &pxstat_end[i]) )
                for ( j = 0; j < pxstat_end[i].total; j++ )
                    sum_px[i] += pxstat_end[i].pt[j].residency -
                                 pxstat_start[i].pt[j].residency;
    }

    for ( i = 0; i < max_cpu_nr; i++ )
        get_avgfreq_by_cpuid(xc_handle, i, &avgfreq[i]);

    printf("Elapsed time (ms): %"PRIu64"\n", (usec_end - usec_start) / 1000UL);
    for ( i = 0; i < max_cpu_nr; i++ )
    {
        uint64_t res, triggers;
        double avg_res;

        printf("\nCPU%d:\tResidency(ms)\t\tAvg Res(ms)\n",i);
        if ( cx_cap && sum_cx[i] > 0 )
        {
            for ( j = 0; j < cxstat_end[i].nr; j++ )
            {
                int64_t diff = (int64_t)cxstat_end[i].residencies[j] -
                    (int64_t)cxstat_start[i].residencies[j];

                res = ( diff >= 0 ) ? diff : 0;
                triggers = cxstat_end[i].triggers[j] -
                    cxstat_start[i].triggers[j];
                /* 
                 * triggers may be zero if the CPU has been in this state for
                 * the whole sample or if it never entered the state
                 */
                if ( triggers == 0 && cxstat_end[i].last == j )
                    avg_res =  (double)sum_cx[i]/1000000.0;
                else
                    avg_res = (triggers==0) ? 0: (double)res/triggers/1000000.0;
                printf("  C%d\t%"PRIu64"\t(%5.2f%%)\t%.2f\n", j, res/1000000UL,
                        100 * res / (double)sum_cx[i], avg_res );
            }
            printf("\n");
        }
        if ( px_cap && sum_px[i]>0 )
        {
            for ( j = 0; j < pxstat_end[i].total; j++ )
            {
                res = pxstat_end[i].pt[j].residency -
                    pxstat_start[i].pt[j].residency;
                printf("  P%d\t%"PRIu64"\t(%5.2f%%)\n", j,
                        res / 1000000UL, 100UL * res / (double)sum_px[i]);
            }
        }
        if ( px_cap && avgfreq[i] )
            printf("  Avg freq\t%d\tKHz\n", avgfreq[i]);
    }

    if ( cx_cap && !xc_cputopoinfo(xc_handle, &max_cpus, cputopo) )
    {
        uint32_t socket_ids[MAX_NR_CPU];
        uint32_t core_ids[MAX_NR_CPU];
        uint32_t socket_nr = 0;
        uint32_t core_nr = 0;

        if ( max_cpus > MAX_NR_CPU )
            max_cpus = MAX_NR_CPU;
        /* check validity */
        for ( i = 0; i < max_cpus; i++ )
        {
            if ( cputopo[i].core == XEN_INVALID_CORE_ID ||
                 cputopo[i].socket == XEN_INVALID_SOCKET_ID )
                break;
        }
        if ( i >= max_cpus )
        {
            /* find socket nr & core nr per socket */
            for ( i = 0; i < max_cpus; i++ )
            {
                for ( j = 0; j < socket_nr; j++ )
                    if ( cputopo[i].socket == socket_ids[j] )
                        break;
                if ( j == socket_nr )
                {
                    socket_ids[j] = cputopo[i].socket;
                    socket_nr++;
                }

                for ( j = 0; j < core_nr; j++ )
                    if ( cputopo[i].core == core_ids[j] )
                        break;
                if ( j == core_nr )
                {
                    core_ids[j] = cputopo[i].core;
                    core_nr++;
                }
            }

            /* print out CC? and PC? */
            for ( i = 0; i < socket_nr; i++ )
            {
                unsigned int n;
                uint64_t res;

                for ( j = 0; j < max_cpus; j++ )
                {
                    if ( cputopo[j].socket == socket_ids[i] )
                        break;
                }
                printf("\nSocket %d\n", socket_ids[i]);
                for ( n = 0; n < MAX_PKG_RESIDENCIES; ++n )
                {
                    if ( n >= cxstat_end[j].nr_pc )
                        continue;
                    res = cxstat_end[j].pc[n];
                    if ( n < cxstat_start[j].nr_pc )
                        res -= cxstat_start[j].pc[n];
                    printf("\tPC%u\t%"PRIu64" ms\t%.2f%%\n",
                           n + 1, res / 1000000UL,
                           100UL * res / (double)sum_cx[j]);
                }
                for ( k = 0; k < core_nr; k++ )
                {
                    for ( j = 0; j < max_cpus; j++ )
                    {
                        if ( cputopo[j].socket == socket_ids[i] &&
                             cputopo[j].core == core_ids[k] )
                            break;
                    }
                    printf("\t Core %d CPU %d\n", core_ids[k], j);
                    for ( n = 0; n < MAX_CORE_RESIDENCIES; ++n )
                    {
                        if ( n >= cxstat_end[j].nr_cc )
                            continue;
                        res = cxstat_end[j].cc[n];
                        if ( n < cxstat_start[j].nr_cc )
                            res -= cxstat_start[j].cc[n];
                        printf("\t\tCC%u\t%"PRIu64" ms\t%.2f%%\n",
                               n + 1, res / 1000000UL,
                               100UL * res / (double)sum_cx[j]);
                    }
                }
            }
        }
    }

    /* some clean up and then exits */
    for ( i = 0; i < 2 * max_cpu_nr; i++ )
    {
        free(cxstat[i].triggers);
        free(cxstat[i].residencies);
        free(cxstat[i].pc);
        free(cxstat[i].cc);
        free(pxstat[i].trans_pt);
        free(pxstat[i].pt);
    }
    free(cxstat);
    free(pxstat);
    free(sum);
    free(avgfreq);
out:
    free(cputopo);
    xc_interface_close(xc_handle);
    exit(0);
}

void start_gather_func(int argc, char *argv[])
{
    int i;
    struct timeval tv;
    int timeout = 0;

    if ( argc == 1 )
    {
        sscanf(argv[0], "%d", &timeout);
        if ( timeout <= 0 )
            fprintf(stderr, "failed to set timeout seconds, falling back...\n");
        else
            printf("Timeout set to %d seconds\n", timeout);
    }

    if ( gettimeofday(&tv, NULL) )
    {
        fprintf(stderr, "failed to get timeofday\n");
        return ;
    }
    usec_start = tv.tv_sec * 1000000UL + tv.tv_usec;

    sum = calloc(2 * max_cpu_nr, sizeof(*sum));
    if ( sum == NULL )
        return ;
    cxstat = calloc(2 * max_cpu_nr, sizeof(*cxstat));
    if ( cxstat == NULL )
    {
        free(sum);
        return ;
    }
    pxstat = calloc(2 * max_cpu_nr, sizeof(*pxstat));
    if ( pxstat == NULL )
    {
        free(sum);
        free(cxstat);
        return ;
    }
    avgfreq = calloc(max_cpu_nr, sizeof(*avgfreq));
    if ( avgfreq == NULL )
    {
        free(sum);
        free(cxstat);
        free(pxstat);
        return ;
    }
    sum_cx = sum;
    sum_px = sum + max_cpu_nr;
    cxstat_start = cxstat;
    cxstat_end = cxstat + max_cpu_nr;
    pxstat_start = pxstat;
    pxstat_end = pxstat + max_cpu_nr;

    if ( get_cxstat_by_cpuid(xc_handle, 0, NULL) == -ENODEV &&
         get_pxstat_by_cpuid(xc_handle, 0, NULL) == -ENODEV )
    {
        fprintf(stderr, "Xen cpu idle and frequency is disabled!\n");
        return ;
    }

    for ( i = 0; i < max_cpu_nr; i++ )
    {
        get_cxstat_by_cpuid(xc_handle, i, &cxstat_start[i]);
        get_pxstat_by_cpuid(xc_handle, i, &pxstat_start[i]);
        get_avgfreq_by_cpuid(xc_handle, i, &avgfreq[i]);
    }

    if (signal(SIGINT, signal_int_handler) == SIG_ERR)
    {
        fprintf(stderr, "failed to set signal int handler\n");
        free(sum);
        free(pxstat);
        free(cxstat);
        free(avgfreq);
        return ;
    }

    if ( timeout > 0 )
    {
        if ( signal(SIGALRM, signal_int_handler) == SIG_ERR )
        {
            fprintf(stderr, "failed to set signal alarm handler\n");
            free(sum);
            free(pxstat);
            free(cxstat);
            free(avgfreq);
            return ;
        }
        alarm(timeout);
    }

    printf("Start sampling, waiting for CTRL-C or SIGINT or SIGALARM signal ...\n");

    pause();
}

/* print out parameters about cpu frequency */
static void print_cpufreq_para(int cpuid, struct xc_get_cpufreq_para *p_cpufreq)
{
    int i;

    printf("cpu id               : %d\n", cpuid);

    printf("affected_cpus        :");
    for ( i = 0; i < p_cpufreq->cpu_num; i++ )
        printf(" %d", p_cpufreq->affected_cpus[i]);
    printf("\n");

    printf("cpuinfo frequency    : max [%u] min [%u] cur [%u]\n",
           p_cpufreq->cpuinfo_max_freq,
           p_cpufreq->cpuinfo_min_freq,
           p_cpufreq->cpuinfo_cur_freq);

    printf("scaling_driver       : %s\n", p_cpufreq->scaling_driver);

    printf("scaling_avail_gov    : %s\n",
           p_cpufreq->scaling_available_governors);

    printf("current_governor     : %s\n", p_cpufreq->scaling_governor);
    if ( !strncmp(p_cpufreq->scaling_governor,
                  "userspace", CPUFREQ_NAME_LEN) )
    {
        printf("  userspace specific :\n");
        printf("    scaling_setspeed : %u\n",
               p_cpufreq->u.userspace.scaling_setspeed);
    }
    else if ( !strncmp(p_cpufreq->scaling_governor,
                       "ondemand", CPUFREQ_NAME_LEN) )
    {
        printf("  ondemand specific  :\n");
        printf("    sampling_rate    : max [%u] min [%u] cur [%u]\n",
               p_cpufreq->u.ondemand.sampling_rate_max,
               p_cpufreq->u.ondemand.sampling_rate_min,
               p_cpufreq->u.ondemand.sampling_rate);
        printf("    up_threshold     : %u\n",
               p_cpufreq->u.ondemand.up_threshold);
    }

    printf("scaling_avail_freq   :");
    for ( i = 0; i < p_cpufreq->freq_num; i++ )
        if ( p_cpufreq->scaling_available_frequencies[i] ==
             p_cpufreq->scaling_cur_freq )
            printf(" *%d", p_cpufreq->scaling_available_frequencies[i]);
        else
            printf(" %d", p_cpufreq->scaling_available_frequencies[i]);
    printf("\n");

    printf("scaling frequency    : max [%u] min [%u] cur [%u]\n",
           p_cpufreq->scaling_max_freq,
           p_cpufreq->scaling_min_freq,
           p_cpufreq->scaling_cur_freq);

    printf("turbo mode           : %s\n",
           p_cpufreq->turbo_enabled ? "enabled" : "disabled or n/a");
    printf("\n");
}

/* show cpu frequency parameters information on CPU cpuid */
static int show_cpufreq_para_by_cpuid(xc_interface *xc_handle, int cpuid)
{
    int ret = 0;
    struct xc_get_cpufreq_para cpufreq_para, *p_cpufreq = &cpufreq_para;

    p_cpufreq->cpu_num = 0;
    p_cpufreq->freq_num = 0;
    p_cpufreq->gov_num = 0;
    p_cpufreq->affected_cpus = NULL;
    p_cpufreq->scaling_available_frequencies = NULL;
    p_cpufreq->scaling_available_governors = NULL;
    p_cpufreq->turbo_enabled = 0;

    do
    {
        free(p_cpufreq->affected_cpus);
        free(p_cpufreq->scaling_available_frequencies);
        free(p_cpufreq->scaling_available_governors);

        p_cpufreq->affected_cpus = NULL;
        p_cpufreq->scaling_available_frequencies = NULL;
        p_cpufreq->scaling_available_governors = NULL;

        if (!(p_cpufreq->affected_cpus =
              malloc(p_cpufreq->cpu_num * sizeof(uint32_t))))
        {
            fprintf(stderr,
                    "[CPU%d] failed to malloc for affected_cpus\n",
                    cpuid);
            ret = -ENOMEM;
            goto out;
        }
        if (!(p_cpufreq->scaling_available_frequencies =
              malloc(p_cpufreq->freq_num * sizeof(uint32_t))))
        {
            fprintf(stderr,
                    "[CPU%d] failed to malloc for scaling_available_frequencies\n",
                    cpuid);
            ret = -ENOMEM;
            goto out;
        }
        if (!(p_cpufreq->scaling_available_governors =
              malloc(p_cpufreq->gov_num * CPUFREQ_NAME_LEN * sizeof(char))))
        {
            fprintf(stderr,
                    "[CPU%d] failed to malloc for scaling_available_governors\n",
                    cpuid);
            ret = -ENOMEM;
            goto out;
        }

        ret = xc_get_cpufreq_para(xc_handle, cpuid, p_cpufreq);
    } while ( ret && errno == EAGAIN );

    if ( ret == 0 )
        print_cpufreq_para(cpuid, p_cpufreq);
    else if ( errno == ENODEV )
    {
        ret = -ENODEV;
        fprintf(stderr, "Xen cpufreq is not enabled!\n");
    }
    else
        fprintf(stderr,
                "[CPU%d] failed to get cpufreq parameter\n",
                cpuid);

out:
    free(p_cpufreq->scaling_available_governors);
    free(p_cpufreq->scaling_available_frequencies);
    free(p_cpufreq->affected_cpus);

    return ret;
}

void cpufreq_para_func(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    if ( cpuid < 0 )
    {
        /* show cpu freqency information on all cpus */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( show_cpufreq_para_by_cpuid(xc_handle, i) == -ENODEV )
                break;
    }
    else
        show_cpufreq_para_by_cpuid(xc_handle, cpuid);
}

void scaling_max_freq_func(int argc, char *argv[])
{
    int cpuid = -1, freq = -1;

    parse_cpuid_and_int(argc, argv, &cpuid, &freq, "frequency");

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_para(xc_handle, i, SCALING_MAX_FREQ, freq) )
                fprintf(stderr,
                        "[CPU%d] failed to set scaling max freq (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_para(xc_handle, cpuid, SCALING_MAX_FREQ, freq) )
            fprintf(stderr, "failed to set scaling max freq (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void scaling_min_freq_func(int argc, char *argv[])
{
    int cpuid = -1, freq = -1;

    parse_cpuid_and_int(argc, argv, &cpuid, &freq, "frequency");

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_para(xc_handle, i, SCALING_MIN_FREQ, freq) )
                fprintf(stderr,
                        "[CPU%d] failed to set scaling min freq (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_para(xc_handle, cpuid, SCALING_MIN_FREQ, freq) )
            fprintf(stderr, "failed to set scaling min freq (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void scaling_speed_func(int argc, char *argv[])
{
    int cpuid = -1, speed = -1;

    parse_cpuid_and_int(argc, argv, &cpuid, &speed, "speed");

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_para(xc_handle, i, SCALING_SETSPEED, speed) )
                fprintf(stderr,
                        "[CPU%d] failed to set scaling speed (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_para(xc_handle, cpuid, SCALING_SETSPEED, speed) )
            fprintf(stderr, "failed to set scaling speed (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void scaling_sampling_rate_func(int argc, char *argv[])
{
    int cpuid = -1, rate = -1;

    parse_cpuid_and_int(argc, argv, &cpuid, &rate, "rate");

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_para(xc_handle, i, SAMPLING_RATE, rate) )
                fprintf(stderr,
                        "[CPU%d] failed to set scaling sampling rate (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_para(xc_handle, cpuid, SAMPLING_RATE, rate) )
            fprintf(stderr, "failed to set scaling sampling rate (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void scaling_up_threshold_func(int argc, char *argv[])
{
    int cpuid = -1, threshold = -1;

    parse_cpuid_and_int(argc, argv, &cpuid, &threshold, "threshold");

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_para(xc_handle, i, UP_THRESHOLD, threshold) )
                fprintf(stderr,
                        "[CPU%d] failed to set up scaling threshold (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_para(xc_handle, cpuid, UP_THRESHOLD, threshold) )
            fprintf(stderr, "failed to set up scaling threshold (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void scaling_governor_func(int argc, char *argv[])
{
    int cpuid = -1;
    char *name;

    if ( argc >= 2 )
    {
        parse_cpuid(argv[0], &cpuid);
        name = argv[1];
    }
    else if ( argc > 0 )
        name = argv[0];
    else
    {
        fprintf(stderr, "Missing argument(s)\n");
        exit(EINVAL);
    }

    if ( cpuid < 0 )
    {
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_set_cpufreq_gov(xc_handle, i, name) )
                fprintf(stderr, "[CPU%d] failed to set governor name (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else
    {
        if ( xc_set_cpufreq_gov(xc_handle, cpuid, name) )
            fprintf(stderr, "failed to set governor name (%d - %s)\n",
                    errno, strerror(errno));
    }
}

void cpu_topology_func(int argc, char *argv[])
{
    xc_cputopo_t *cputopo = NULL;
    unsigned max_cpus = 0;
    int i, rc;

    if ( xc_cputopoinfo(xc_handle, &max_cpus, NULL) != 0 )
    {
        rc = errno;
        fprintf(stderr, "failed to discover number of CPUs (%d - %s)\n",
                errno, strerror(errno));
        goto out;
    }

    cputopo = calloc(max_cpus, sizeof(*cputopo));
    if ( cputopo == NULL )
    {
	rc = ENOMEM;
	fprintf(stderr, "failed to allocate hypercall buffers\n");
	goto out;
    }

    if ( xc_cputopoinfo(xc_handle, &max_cpus, cputopo) )
    {
        rc = errno;
        fprintf(stderr, "Cannot get Xen CPU topology (%d - %s)\n",
                errno, strerror(errno));
        goto out;
    }

    printf("CPU\tcore\tsocket\tnode\n");
    for ( i = 0; i < max_cpus; i++ )
    {
        if ( cputopo[i].core == XEN_INVALID_CORE_ID )
            continue;
        printf("CPU%d\t %d\t %d\t %d\n",
               i, cputopo[i].core, cputopo[i].socket, cputopo[i].node);
    }
    rc = 0;
out:
    free(cputopo);
    if ( rc )
        exit(rc);
}

void set_sched_smt_func(int argc, char *argv[])
{
    int value;

    if ( argc != 1 ) {
        fprintf(stderr, "Missing or invalid argument(s)\n");
        exit(EINVAL);
    }

    if ( !strcasecmp(argv[0], "disable") )
        value = 0;
    else if ( !strcasecmp(argv[0], "enable") )
        value = 1;
    else
    {
        fprintf(stderr, "Invalid argument: %s\n", argv[0]);
        exit(EINVAL);
    }

    if ( !xc_set_sched_opt_smt(xc_handle, value) )
        printf("%s sched_smt_power_savings succeeded\n", argv[0]);
    else
        fprintf(stderr, "%s sched_smt_power_savings failed (%d - %s)\n",
                argv[0], errno, strerror(errno));
}

void set_vcpu_migration_delay_func(int argc, char *argv[])
{
    int value;

    if ( argc != 1 || (value = atoi(argv[0])) < 0 ) {
        fprintf(stderr, "Missing or invalid argument(s)\n");
        exit(EINVAL);
    }

    if ( !xc_set_vcpu_migration_delay(xc_handle, value) )
        printf("set vcpu migration delay to %d us succeeded\n", value);
    else
        fprintf(stderr, "set vcpu migration delay failed (%d - %s)\n",
                errno, strerror(errno));
}

void get_vcpu_migration_delay_func(int argc, char *argv[])
{
    uint32_t value;

    if ( argc )
        fprintf(stderr, "Ignoring argument(s)\n");

    if ( !xc_get_vcpu_migration_delay(xc_handle, &value) )
        printf("Scheduler vcpu migration delay is %d us\n", value);
    else
        fprintf(stderr,
                "Failed to get scheduler vcpu migration delay (%d - %s)\n",
                errno, strerror(errno));
}

void set_max_cstate_func(int argc, char *argv[])
{
    int value;

    if ( argc != 1 || sscanf(argv[0], "%d", &value) != 1 || value < 0 )
    {
        fprintf(stderr, "Missing or invalid argument(s)\n");
        exit(EINVAL);
    }

    if ( !xc_set_cpuidle_max_cstate(xc_handle, (uint32_t)value) )
        printf("set max_cstate to C%d succeeded\n", value);
    else
        fprintf(stderr, "set max_cstate to C%d failed (%d - %s)\n",
                value, errno, strerror(errno));
}

void enable_turbo_mode(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    if ( cpuid < 0 )
    {
        /* enable turbo modes on all cpus,
         * only make effects on dbs governor */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_enable_turbo(xc_handle, i) )
                fprintf(stderr,
                        "[CPU%d] failed to enable turbo mode (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else if ( xc_enable_turbo(xc_handle, cpuid) )
        fprintf(stderr, "failed to enable turbo mode (%d - %s)\n",
                errno, strerror(errno));
}

void disable_turbo_mode(int argc, char *argv[])
{
    int cpuid = -1;

    if ( argc > 0 )
        parse_cpuid(argv[0], &cpuid);

    if ( cpuid < 0 )
    {
        /* disable turbo modes on all cpus,
         * only make effects on dbs governor */
        int i;
        for ( i = 0; i < max_cpu_nr; i++ )
            if ( xc_disable_turbo(xc_handle, i) )
                fprintf(stderr,
                        "[CPU%d] failed to disable turbo mode (%d - %s)\n",
                        i, errno, strerror(errno));
    }
    else if ( xc_disable_turbo(xc_handle, cpuid) )
        fprintf(stderr, "failed to disable turbo mode (%d - %s)\n",
                errno, strerror(errno));
}

struct {
    const char *name;
    void (*function)(int argc, char *argv[]);
} main_options[] = {
    { "help", help_func },
    { "get-cpuidle-states", cxstat_func },
    { "get-cpufreq-states", pxstat_func },
    { "get-cpufreq-average", cpufreq_func },
    { "start", start_gather_func },
    { "get-cpufreq-para", cpufreq_para_func },
    { "set-scaling-maxfreq", scaling_max_freq_func },
    { "set-scaling-minfreq", scaling_min_freq_func },
    { "set-scaling-governor", scaling_governor_func },
    { "set-scaling-speed", scaling_speed_func },
    { "set-sampling-rate", scaling_sampling_rate_func },
    { "set-up-threshold", scaling_up_threshold_func },
    { "get-cpu-topology", cpu_topology_func},
    { "set-sched-smt", set_sched_smt_func},
    { "get-vcpu-migration-delay", get_vcpu_migration_delay_func},
    { "set-vcpu-migration-delay", set_vcpu_migration_delay_func},
    { "set-max-cstate", set_max_cstate_func},
    { "enable-turbo-mode", enable_turbo_mode },
    { "disable-turbo-mode", disable_turbo_mode },
};

int main(int argc, char *argv[])
{
    int i, ret = 0;
    xc_physinfo_t physinfo = { 0 };
    int nr_matches = 0;
    int matches_main_options[ARRAY_SIZE(main_options)];

    if ( argc < 2 )
    {
        show_help();
        return 0;
    }

    xc_handle = xc_interface_open(0,0,0);
    if ( !xc_handle )
    {
        fprintf(stderr, "failed to get the handler\n");
        return EIO;
    }

    ret = xc_physinfo(xc_handle, &physinfo);
    if ( ret )
    {
        ret = errno;
        fprintf(stderr, "failed to get processor information (%d - %s)\n",
                ret, strerror(ret));
        xc_interface_close(xc_handle);
        return ret;
    }
    max_cpu_nr = physinfo.nr_cpus;

    /* calculate how many options match with user's input */
    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
        if ( !strncmp(main_options[i].name, argv[1], strlen(argv[1])) )
            matches_main_options[nr_matches++] = i;

    if ( nr_matches > 1 )
    {
        fprintf(stderr, "Ambiguous options: ");
        for ( i = 0; i < nr_matches; i++ )
            fprintf(stderr, " %s", main_options[matches_main_options[i]].name);
        fprintf(stderr, "\n");
        ret = EINVAL;
    }
    else if ( nr_matches == 1 )
        /* dispatch to the corresponding function handler */
        main_options[matches_main_options[0]].function(argc - 2, argv + 2);
    else
    {
        show_help();
        ret = EINVAL;
    }

    xc_interface_close(xc_handle);
    return ret;
}

