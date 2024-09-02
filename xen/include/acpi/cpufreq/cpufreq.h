/*
 *  xen/include/acpi/cpufreq/cpufreq.h
 *
 *  Copyright (C) 2001 Russell King
 *            (C) 2002 - 2003 Dominik Brodowski <linux@brodo.de>
 *
 * $Id: cpufreq.h,v 1.36 2003/01/20 17:31:48 db Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __XEN_CPUFREQ_PM_H__
#define __XEN_CPUFREQ_PM_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/cpumask.h>

#include "processor_perf.h"

DECLARE_PER_CPU(spinlock_t, cpufreq_statistic_lock);

extern bool cpufreq_verbose;

enum cpufreq_xen_opt {
    CPUFREQ_none,
    CPUFREQ_xen,
    CPUFREQ_hwp,
};
extern enum cpufreq_xen_opt cpufreq_xen_opts[2];
extern unsigned int cpufreq_xen_cnt;
struct cpufreq_governor;

struct acpi_cpufreq_data {
    struct processor_performance *acpi_data;
    struct cpufreq_frequency_table *freq_table;
    unsigned int arch_cpu_flags;
};

extern struct acpi_cpufreq_data *cpufreq_drv_data[NR_CPUS];

struct cpufreq_cpuinfo {
    unsigned int        max_freq;
    unsigned int        second_max_freq;    /* P1 if Turbo Mode is on */
    unsigned int        perf_freq; /* Scaling freq for aperf/mpref.
                                      acpi-cpufreq uses max_freq, but HWP uses
                                      base_freq.*/
    unsigned int        min_freq;
    unsigned int        transition_latency; /* in 10^(-9) s = nanoseconds */
};

struct perf_limits {
    bool no_turbo;
    bool turbo_disabled;
    uint32_t turbo_pct;
    uint32_t max_perf_pct; /* max performance in percentage */
    uint32_t min_perf_pct; /* min performance in percentage */
    uint32_t max_perf;
    uint32_t min_perf;
    uint32_t max_policy_pct;
    uint32_t min_policy_pct;
};

struct cpufreq_policy {
    cpumask_var_t       cpus;          /* affected CPUs */
    unsigned int        shared_type;   /* ANY or ALL affected CPUs
                                          should set cpufreq */
    unsigned int        cpu;           /* cpu nr of registered CPU */
    struct cpufreq_cpuinfo    cpuinfo;

    unsigned int        min;    /* in kHz */
    unsigned int        max;    /* in kHz */
    unsigned int        cur;    /* in kHz, only needed if cpufreq
                                 * governors are used */
    struct perf_limits  limits;
    struct cpufreq_governor     *governor;

    bool                resume; /* flag for cpufreq 1st run
                                 * S3 wakeup, hotplug cpu, etc */
    int8_t              turbo;  /* tristate flag: 0 for unsupported
                                 * -1 for disable, 1 for enabled
                                 * See CPUFREQ_TURBO_* below for defines */
};
DECLARE_PER_CPU(struct cpufreq_policy *, cpufreq_cpu_policy);

extern int __cpufreq_set_policy(struct cpufreq_policy *data,
                                struct cpufreq_policy *policy);

#define CPUFREQ_SHARED_TYPE_HW   XEN_CPUPERF_SHARED_TYPE_HW
#define CPUFREQ_SHARED_TYPE_ALL  XEN_CPUPERF_SHARED_TYPE_ALL
#define CPUFREQ_SHARED_TYPE_ANY  XEN_CPUPERF_SHARED_TYPE_ANY

/******************** cpufreq transition notifiers *******************/

struct cpufreq_freqs {
    unsigned int cpu;    /* cpu nr */
    unsigned int old;
    unsigned int new;
    u8 flags;            /* flags of cpufreq_driver, see below. */
};


/*********************************************************************
 *                          CPUFREQ GOVERNORS                        *
 *********************************************************************/

#define CPUFREQ_GOV_START  1
#define CPUFREQ_GOV_STOP   2
#define CPUFREQ_GOV_LIMITS 3

struct cpufreq_governor {
    char    name[CPUFREQ_NAME_LEN];
    int     (*governor)(struct cpufreq_policy *policy,
                        unsigned int event);
    bool    (*handle_option)(const char *name, const char *value);
    struct list_head governor_list;
};

extern struct cpufreq_governor *cpufreq_opt_governor;
extern struct cpufreq_governor cpufreq_gov_dbs;
extern struct cpufreq_governor cpufreq_gov_userspace;
extern struct cpufreq_governor cpufreq_gov_performance;
extern struct cpufreq_governor cpufreq_gov_powersave;

extern struct list_head cpufreq_governor_list;

extern bool cpufreq_governor_internal;

extern int cpufreq_register_governor(struct cpufreq_governor *governor);
extern struct cpufreq_governor *__find_governor(const char *governor);
#define CPUFREQ_DEFAULT_GOVERNOR &cpufreq_gov_dbs

/* pass a target to the cpufreq driver */
extern int __cpufreq_driver_target(struct cpufreq_policy *policy,
                                   unsigned int target_freq,
                                   unsigned int relation);

#define GOV_GETAVG     1
#define USR_GETAVG     2
extern int cpufreq_driver_getavg(unsigned int cpu, unsigned int flag);

#define CPUFREQ_TURBO_DISABLED      -1
#define CPUFREQ_TURBO_UNSUPPORTED   0
#define CPUFREQ_TURBO_ENABLED       1

int cpufreq_update_turbo(unsigned int cpu, int new_state);
int cpufreq_get_turbo_status(unsigned int cpu);

static inline int
__cpufreq_governor(struct cpufreq_policy *policy, unsigned int event)
{
    return policy->governor->governor(policy, event);
}


/*********************************************************************
 *                      CPUFREQ DRIVER INTERFACE                     *
 *********************************************************************/

#define CPUFREQ_RELATION_L 0  /* lowest frequency at or above target */
#define CPUFREQ_RELATION_H 1  /* highest frequency below or at target */

struct cpufreq_driver {
    const char *name;
    int    (*init)(struct cpufreq_policy *policy);
    int    (*verify)(struct cpufreq_policy *policy);
    int    (*setpolicy)(struct cpufreq_policy *policy);
    int    (*update)(unsigned int cpu, struct cpufreq_policy *policy);
    int    (*target)(struct cpufreq_policy *policy,
                     unsigned int target_freq,
                     unsigned int relation);
    unsigned int    (*get)(unsigned int cpu);
    int    (*exit)(struct cpufreq_policy *policy);
};

extern struct cpufreq_driver cpufreq_driver;

int cpufreq_register_driver(const struct cpufreq_driver *driver_data);

static inline
void cpufreq_verify_within_limits(struct cpufreq_policy *policy,
                                  unsigned int min, unsigned int max)
{
    if (policy->min < min)
        policy->min = min;
    if (policy->max < min)
        policy->max = min;
    if (policy->min > max)
        policy->min = max;
    if (policy->max > max)
        policy->max = max;
    if (policy->min > policy->max)
        policy->min = policy->max;
    return;
}


/*********************************************************************
 *                     FREQUENCY TABLE HELPERS                       *
 *********************************************************************/

#define CPUFREQ_ENTRY_INVALID ~0
#define CPUFREQ_TABLE_END     ~1

struct cpufreq_frequency_table {
    unsigned int    index;     /* any */
    unsigned int    frequency; /* kHz - doesn't need to be in ascending
                                * order */
};

int cpufreq_frequency_table_cpuinfo(struct cpufreq_policy *policy,
                   struct cpufreq_frequency_table *table);

int cpufreq_frequency_table_verify(struct cpufreq_policy *policy,
                   struct cpufreq_frequency_table *table);

int cpufreq_frequency_table_target(struct cpufreq_policy *policy,
                   struct cpufreq_frequency_table *table,
                   unsigned int target_freq,
                   unsigned int relation,
                   unsigned int *index);


/*********************************************************************
 *                     UNIFIED DEBUG HELPERS                         *
 *********************************************************************/

struct cpu_dbs_info_s {
    uint64_t prev_cpu_idle;
    uint64_t prev_cpu_wall;
    struct cpufreq_policy *cur_policy;
    struct cpufreq_frequency_table *freq_table;
    int cpu;
    unsigned int enable:1;
    unsigned int turbo_enabled:1;
    int8_t stoppable;
};

int get_cpufreq_ondemand_para(uint32_t *sampling_rate_max,
                              uint32_t *sampling_rate_min,
                              uint32_t *sampling_rate,
                              uint32_t *up_threshold);
int write_ondemand_sampling_rate(unsigned int sampling_rate);
int write_ondemand_up_threshold(unsigned int up_threshold);

int write_userspace_scaling_setspeed(unsigned int cpu, unsigned int freq);

void cpufreq_dbs_timer_suspend(void);
void cpufreq_dbs_timer_resume(void);

void intel_feature_detect(struct cpufreq_policy *policy);

int hwp_cmdline_parse(const char *s, const char *e);
int hwp_register_driver(void);
#ifdef CONFIG_INTEL
bool hwp_active(void);
#else
static inline bool hwp_active(void) { return false; }
#endif

int get_hwp_para(unsigned int cpu,
                 struct xen_cppc_para *cppc_para);
int set_hwp_para(struct cpufreq_policy *policy,
                 struct xen_set_cppc_para *set_cppc);

int acpi_cpufreq_register(void);

#endif /* __XEN_CPUFREQ_PM_H__ */
