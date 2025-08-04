/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Renesas Electronics Corporation
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <xenctrl.h>
#include "pcpu.h"

#define MAX_PCPUS 128

typedef struct {
    float usage_pct;
} pcpu_stat_t;

static pcpu_stat_t *pcpu_stats = NULL;
static uint64_t *prev_idle = NULL;
static int allocated_pcpus = 0;
static xc_interface *xc_handle = NULL;
static uint64_t prev_global_time = 0;

static void report_pcpu_error(const char *context)
{
    fprintf(stderr, "PCPU error: %s (%s)\n", context, strerror(errno));
}

int update_pcpu_stats(const struct timeval *now, unsigned int delay_sec)
{
    struct xen_sysctl_cpuinfo info[MAX_PCPUS];
    int detected_cpus = 0;
    int ret, i;
    uint64_t current_time = (uint64_t)now->tv_sec * 1000000ULL + now->tv_usec;
    uint64_t time_diff;

    if (!xc_handle) {
        xc_handle = xc_interface_open(NULL, NULL, 0);
        if (!xc_handle) {
            report_pcpu_error("xc_interface_open failed");
            return -1;
        }
    }

    ret = xc_getcpuinfo(xc_handle, MAX_PCPUS, info, &detected_cpus);
    if (ret < 0) {
        report_pcpu_error("xc_getcpuinfo failed");
        return -1;
    }

    /* Allocate/reallocate memory if needed */
    if (!pcpu_stats || detected_cpus > allocated_pcpus) {
        pcpu_stat_t *new_stats = realloc(pcpu_stats,
                        detected_cpus * sizeof(*pcpu_stats));
        if (!new_stats) goto alloc_error;

        pcpu_stats = new_stats;

        uint64_t *new_prev_idle = realloc(prev_idle,
                        detected_cpus * sizeof(*prev_idle));
        if (!new_prev_idle) goto alloc_error;

        prev_idle = new_prev_idle;
        allocated_pcpus = detected_cpus;

        /* Initialize new entries */
        for (i = 0; i < detected_cpus; i++) {
            prev_idle[i] = info[i].idletime / 1000; /* ns->us */
            pcpu_stats[i].usage_pct = 0.0;
        }

        /* Set initial global time reference */
        prev_global_time = current_time;
        return 0;
    }

    /* Calculate time difference since last update */
    time_diff = current_time - prev_global_time;

    /* Calculate CPU usage for each core */
    for (i = 0; i < detected_cpus; i++) {
        uint64_t current_idle = info[i].idletime / 1000;
        uint64_t idle_diff = current_idle - prev_idle[i];

        if (time_diff > 0) {
            double usage = 100.0 * (1.0 - ((double)idle_diff / time_diff));
            /* Clamp between 0-100% */
            pcpu_stats[i].usage_pct = (usage < 0) ? 0.0 :
                                     (usage > 100) ? 100.0 : usage;
        } else {
            pcpu_stats[i].usage_pct = 0.0;
        }

        prev_idle[i] = current_idle;
    }

    /* Update global time reference for next calculation */
    prev_global_time = current_time;

    return 0;

alloc_error:
    free_pcpu_stats();
    errno = ENOMEM;
    report_pcpu_error("memory allocation failed");
    return -1;
}

/* Accessor functions for xentop.c */
int get_pcpu_count(void)
{
    return allocated_pcpus;
}

float get_pcpu_usage(int cpu_index)
{
    if (!pcpu_stats || cpu_index < 0 || cpu_index >= allocated_pcpus) {
        return 0.0;
    }
    return pcpu_stats[cpu_index].usage_pct;
}

int has_pcpu_data(void)
{
    return (pcpu_stats != NULL && allocated_pcpus > 0);
}

void free_pcpu_stats(void)
{
    if (xc_handle) {
        xc_interface_close(xc_handle);
        xc_handle = NULL;
    }
    free(pcpu_stats);
    pcpu_stats = NULL;
    free(prev_idle);
    prev_idle = NULL;
    allocated_pcpus = 0;
}
