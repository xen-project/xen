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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

/* to eliminate warning on `strndup' */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <xenctrl.h>
#include <inttypes.h>

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

/* help message */
void show_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "       xenpm get-cpuidle-states [cpuid]: list cpu idle information on CPU cpuid or all CPUs.\n"
            "       xenpm get-cpufreq-states [cpuid]: list cpu frequency information on CPU cpuid or all CPUs.\n"
            "       xenpm get-cpufreq-para [cpuid]: list cpu frequency information on CPU cpuid or all CPUs.\n"
            "       xenpm set-scaling-maxfreq <cpuid> <HZ>: set max cpu frequency <HZ> on CPU <cpuid>.\n"
            "       xenpm set-scaling-minfreq <cpuid> <HZ>: set min cpu frequency <HZ> on CPU <cpuid>.\n"
            "       xenpm set-scaling-governor <cpuid> <name>: set scaling governor on CPU <cpuid>.\n"
            "       xenpm set-scaling-speed <cpuid> <num>: set scaling speed on CPU <cpuid>.\n"
            "       xenpm set-sampling-rate <cpuid> <num>: set sampling rate on CPU <cpuid>.\n"
            "       xenpm set-up-threshold <cpuid> <num>: set up threshold on CPU <cpuid>.\n");
}

/* wrapper function */
int help_func(int xc_fd, int cpuid, uint32_t value)
{
    show_help();
    return 0;
}

/* show cpu idle information on CPU cpuid */
static int show_cx_cpuid(int xc_fd, int cpuid)
{
    int i, ret = 0;
    int max_cx_num = 0;
    struct xc_cx_stat cxstatinfo, *cxstat = &cxstatinfo;

    ret = xc_pm_get_max_cx(xc_fd, cpuid, &max_cx_num);
    if ( ret )
    {
        if ( errno == ENODEV )
        {
            fprintf(stderr, "Xen cpuidle is not enabled!\n");
            return -ENODEV;
        }
        else
        {
            fprintf(stderr, "[CPU%d] failed to get max C-state\n", cpuid);
            return -EINVAL;
        }
    }

    cxstat->triggers = malloc(max_cx_num * sizeof(uint64_t));
    if ( !cxstat->triggers )
    {
        fprintf(stderr, "[CPU%d] failed to malloc for C-states triggers\n", cpuid);
        return -ENOMEM;
    }
    cxstat->residencies = malloc(max_cx_num * sizeof(uint64_t));
    if ( !cxstat->residencies )
    {
        fprintf(stderr, "[CPU%d] failed to malloc for C-states residencies\n", cpuid);
        free(cxstat->triggers);
        return -ENOMEM;
    }

    ret = xc_pm_get_cxstat(xc_fd, cpuid, cxstat);
    if( ret )
    {
        fprintf(stderr, "[CPU%d] failed to get C-states statistics "
                "information\n", cpuid);
        free(cxstat->triggers);
        free(cxstat->residencies);
        return -EINVAL;
    }

    printf("cpu id               : %d\n", cpuid);
    printf("total C-states       : %d\n", cxstat->nr);
    printf("idle time(ms)        : %"PRIu64"\n",
           cxstat->idle_time/1000000UL);
    for ( i = 0; i < cxstat->nr; i++ )
    {
        printf("C%d                   : transition [%020"PRIu64"]\n",
               i, cxstat->triggers[i]);
        printf("                       residency  [%020"PRIu64" ms]\n",
               cxstat->residencies[i]/1000000UL);
    }

    free(cxstat->triggers);
    free(cxstat->residencies);

    printf("\n");
    return 0;
}

int cxstates_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret = 0;
    xc_physinfo_t physinfo = { 0 };

    if ( cpuid < 0 )
    {
        /* show cxstates on all cpu */
        ret = xc_physinfo(xc_fd, &physinfo);
        if ( ret )
        {
            fprintf(stderr, "failed to get the processor information\n");
        }
        else
        {
            int i;
            for ( i = 0; i < physinfo.nr_cpus; i++ )
            {
                if ( (ret = show_cx_cpuid(xc_fd, i)) == -ENODEV )
                    break;
            }
        }
    }
    else
        ret = show_cx_cpuid(xc_fd, cpuid);

    return ret;
}

/* show cpu frequency information on CPU cpuid */
static int show_px_cpuid(int xc_fd, int cpuid)
{
    int i, ret = 0;
    int max_px_num = 0;
    struct xc_px_stat pxstatinfo, *pxstat = &pxstatinfo;

    ret = xc_pm_get_max_px(xc_fd, cpuid, &max_px_num);
    if ( ret )
    {
        if ( errno == ENODEV )
        {
            printf("Xen cpufreq is not enabled!\n");
            return -ENODEV;
        }
        else
        {
            fprintf(stderr, "[CPU%d] failed to get max P-state\n", cpuid);
            return -EINVAL;
        }
    }

    pxstat->trans_pt = malloc(max_px_num * max_px_num *
                              sizeof(uint64_t));
    if ( !pxstat->trans_pt )
    {
        fprintf(stderr, "[CPU%d] failed to malloc for P-states transition table\n", cpuid);
        return -ENOMEM;
    }
    pxstat->pt = malloc(max_px_num * sizeof(struct xc_px_val));
    if ( !pxstat->pt )
    {
        fprintf(stderr, "[CPU%d] failed to malloc for P-states table\n", cpuid);
        free(pxstat->trans_pt);
        return -ENOMEM;
    }

    ret = xc_pm_get_pxstat(xc_fd, cpuid, pxstat);
    if( ret )
    {
        fprintf(stderr, "[CPU%d] failed to get P-states statistics information\n", cpuid);
        free(pxstat->trans_pt);
        free(pxstat->pt);
        return -ENOMEM;
    }

    printf("cpu id               : %d\n", cpuid);
    printf("total P-states       : %d\n", pxstat->total);
    printf("usable P-states      : %d\n", pxstat->usable);
    printf("current frequency    : %"PRIu64" MHz\n",
           pxstat->pt[pxstat->cur].freq);
    for ( i = 0; i < pxstat->total; i++ )
    {
        if ( pxstat->cur == i )
            printf("*P%d", i);
        else
            printf("P%d ", i);
        printf("                  : freq       [%04"PRIu64" MHz]\n",
               pxstat->pt[i].freq);
        printf("                       transition [%020"PRIu64"]\n",
               pxstat->pt[i].count);
        printf("                       residency  [%020"PRIu64" ms]\n",
               pxstat->pt[i].residency/1000000UL);
    }

    free(pxstat->trans_pt);
    free(pxstat->pt);

    printf("\n");
    return 0;
}

int pxstates_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret = 0;
    xc_physinfo_t physinfo = { 0 };

    if ( cpuid < 0 )
    {
        ret = xc_physinfo(xc_fd, &physinfo);
        if ( ret )
        {
            fprintf(stderr, "failed to get the processor information\n");
        }
        else
        {
            int i;
            for ( i = 0; i < physinfo.nr_cpus; i++ )
            {
                if ( (ret = show_px_cpuid(xc_fd, i)) == -ENODEV )
                    break;
            }
        }
    }
    else
        ret = show_px_cpuid(xc_fd, cpuid);

    return ret;
}

/* print out parameters about cpu frequency */
static void print_cpufreq_para(int cpuid, struct xc_get_cpufreq_para *p_cpufreq)
{
    int i;

    printf("cpu id               : %d\n", cpuid);

    printf("affected_cpus        :");
    for ( i = 0; i < p_cpufreq->cpu_num; i++ )
        if ( i == cpuid )
            printf(" *%d", p_cpufreq->affected_cpus[i]);
        else
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
        if ( p_cpufreq->scaling_available_frequencies[i] == p_cpufreq->scaling_cur_freq )
            printf(" *%d", p_cpufreq->scaling_available_frequencies[i]);
        else
            printf(" %d", p_cpufreq->scaling_available_frequencies[i]);
    printf("\n");

    printf("scaling frequency    : max [%u] min [%u] cur [%u]\n",
           p_cpufreq->scaling_max_freq,
           p_cpufreq->scaling_min_freq,
           p_cpufreq->scaling_cur_freq);
    printf("\n");
}

/* show cpu frequency parameters information on CPU cpuid */
static int show_cpufreq_para_cpuid(int xc_fd, int cpuid)
{
    int ret = 0;
    struct xc_get_cpufreq_para cpufreq_para, *p_cpufreq = &cpufreq_para;

    p_cpufreq->cpu_num = 0;
    p_cpufreq->freq_num = 0;
    p_cpufreq->gov_num = 0;
    p_cpufreq->affected_cpus = NULL;
    p_cpufreq->scaling_available_frequencies = NULL;
    p_cpufreq->scaling_available_governors = NULL;

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

        ret = xc_get_cpufreq_para(xc_fd, cpuid, p_cpufreq);
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

int cpufreq_para_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret = 0;
    xc_physinfo_t physinfo = { 0 };

    if ( cpuid < 0 )
    {
        ret = xc_physinfo(xc_fd, &physinfo);
        if ( ret )
        {
            fprintf(stderr, "failed to get the processor information\n");
        }
        else
        {
            int i;
            for ( i = 0; i < physinfo.nr_cpus; i++ )
            {
                if ( (ret = show_cpufreq_para_cpuid(xc_fd, i)) == -ENODEV )
                    break;
            }
        }
    }
    else
        ret = show_cpufreq_para_cpuid(xc_fd, cpuid);

    return ret;
}

int scaling_max_freq_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret = 0;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_para(xc_fd, cpuid, SCALING_MAX_FREQ, value);
    if ( ret )
    {
        fprintf(stderr, "[CPU%d] failed to set scaling max freq\n", cpuid);
    }

    return ret;
}

int scaling_min_freq_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_para(xc_fd, cpuid, SCALING_MIN_FREQ, value);
    if ( ret )
    {
        fprintf(stderr, "[CPU%d] failed to set scaling min freq\n", cpuid);
    }

    return ret;
}

int scaling_speed_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_para(xc_fd, cpuid, SCALING_SETSPEED, value);
    if ( ret )
    {
        fprintf(stderr, "[CPU%d] failed to set scaling speed\n", cpuid);
    }

    return ret;
}

int scaling_sampling_rate_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_para(xc_fd, cpuid, SAMPLING_RATE, value);
    if ( ret ) 
    {
        fprintf(stderr, "[CPU%d] failed to set scaling sampling rate\n", cpuid);
    }

    return ret;
}

int scaling_up_threshold_func(int xc_fd, int cpuid, uint32_t value)
{
    int ret;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_para(xc_fd, cpuid, UP_THRESHOLD, value);
    if ( ret )
    {
        fprintf(stderr, "[CPU%d] failed to set scaling threshold\n", cpuid);
    }

    return ret;
}

int scaling_governor_func(int xc_fd, int cpuid, char *name)
{
    int ret = 0;

    if ( cpuid < 0 )
    {
        show_help();
        return -EINVAL;
    }

    ret = xc_set_cpufreq_gov(xc_fd, cpuid, name);
    if ( ret )
    {
        fprintf(stderr, "failed to set cpufreq governor to %s\n", name);
    }

    return ret;
}

struct {
    const char *name;
    int (*function)(int xc_fd, int cpuid, uint32_t value);
} main_options[] = {
    { "help", help_func },
    { "get-cpuidle-states", cxstates_func },
    { "get-cpufreq-states", pxstates_func },
    { "get-cpufreq-para", cpufreq_para_func },
    { "set-scaling-maxfreq", scaling_max_freq_func },
    { "set-scaling-minfreq", scaling_min_freq_func },
    { "set-scaling-governor", NULL },
    { "set-scaling-speed", scaling_speed_func },
    { "set-sampling-rate", scaling_sampling_rate_func },
    { "set-up-threshold", scaling_up_threshold_func },
};

int main(int argc, char *argv[])
{
    int i, ret = -EINVAL;
    int xc_fd;
    int cpuid = -1;
    uint32_t value = 0;
    int nr_matches = 0;
    int matches_main_options[ARRAY_SIZE(main_options)];

    if ( argc < 2 )
    {
        show_help();
        return ret;
    }

    if ( argc > 2 )
    {
        if ( sscanf(argv[2], "%d", &cpuid) != 1 )
            cpuid = -1;
    }

    xc_fd = xc_interface_open();
    if ( xc_fd < 0 )
    {
        fprintf(stderr, "failed to get the handler\n");
    }

    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
    {
        if ( !strncmp(main_options[i].name, argv[1], strlen(argv[1])) )
        {
            matches_main_options[nr_matches++] = i;
        }
    }

    if ( nr_matches > 1 )
    {
        fprintf(stderr, "Ambigious options: ");
        for ( i = 0; i < nr_matches; i++ )
            fprintf(stderr, " %s", main_options[matches_main_options[i]].name);
        fprintf(stderr, "\n");
    }
    else if ( nr_matches == 1 )
    {
        if ( !strcmp("set-scaling-governor", main_options[matches_main_options[0]].name) )
        {
            char *name = strdup(argv[3]);
            ret = scaling_governor_func(xc_fd, cpuid, name);
            free(name);
        }
        else
        {
            if ( argc > 3 )
            {
                if ( sscanf(argv[3], "%d", &value) != 1 )
                    value = 0;
            }
            ret = main_options[matches_main_options[0]].function(xc_fd, cpuid, value);
        }
    }
    else
        show_help();

    xc_interface_close(xc_fd);
    return ret;
}

