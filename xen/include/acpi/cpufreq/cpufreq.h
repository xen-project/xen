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

extern bool cpufreq_verbose;

enum cpufreq_xen_opt {
    CPUFREQ_none,
    CPUFREQ_xen,
    CPUFREQ_hwp,
    CPUFREQ_amd_cppc,
};
extern enum cpufreq_xen_opt cpufreq_xen_opts[3];
extern unsigned int cpufreq_xen_cnt;
struct cpufreq_governor;

struct acpi_cpufreq_data {
    struct processor_performance *acpi_data;
    struct cpufreq_frequency_table *freq_table;
    unsigned int arch_cpu_flags;
};

struct hwp_drv_data {
    union {
        uint64_t hwp_caps;
        struct {
            unsigned int highest:8;
            unsigned int guaranteed:8;
            unsigned int most_efficient:8;
            unsigned int lowest:8;
            unsigned int :32;
        } hw;
    };
    union hwp_request {
        struct {
            unsigned int min_perf:8;
            unsigned int max_perf:8;
            unsigned int desired:8;
            unsigned int energy_perf:8;
            unsigned int activity_window:10;
            bool package_control:1;
            unsigned int :16;
            bool activity_window_valid:1;
            bool energy_perf_valid:1;
            bool desired_valid:1;
            bool max_perf_valid:1;
            bool min_perf_valid:1;
        };
        uint64_t raw;
    } curr_req;
    int ret;
    uint16_t activity_window;
    uint8_t minimum;
    uint8_t maximum;
    uint8_t desired;
    uint8_t energy_perf;
};

/*
 * Field highest_perf, nominal_perf, lowest_nonlinear_perf, and lowest_perf
 * contain the values read from CPPC capability MSR. They represent the limits
 * of managed performance range as well as the dynamic capability, which may
 * change during processor operation
 * Field highest_perf represents highest performance, which is the absolute
 * maximum performance an individual processor may reach, assuming ideal
 * conditions. This performance level may not be sustainable for long
 * durations and may only be achievable if other platform components
 * are in a specific state; for example, it may require other processors be
 * in an idle state. This would be equivalent to the highest frequencies
 * supported by the processor.
 * Field nominal_perf represents maximum sustained performance level of the
 * processor, assuming ideal operating conditions. All cores/processors are
 * expected to be able to sustain their nominal performance state
 * simultaneously.
 * Field lowest_nonlinear_perf represents Lowest Nonlinear Performance, which
 * is the lowest performance level at which nonlinear power savings are
 * achieved. Above this threshold, lower performance levels should be
 * generally more energy efficient than higher performance levels. So in
 * traditional terms, this represents the P-state range of performance levels.
 * Field lowest_perf represents the absolute lowest performance level of the
 * platform. Selecting it may cause an efficiency penalty but should reduce
 * the instantaneous power consumption of the processor. So in traditional
 * terms, this represents the T-state range of performance levels.
 *
 * Field max_perf, min_perf, des_perf store the values for CPPC request MSR.
 * Software passes performance goals through these fields.
 * Field max_perf conveys the maximum performance level at which the platform
 * may run. And it may be set to any performance value in the range
 * [lowest_perf, highest_perf], inclusive.
 * Field min_perf conveys the minimum performance level at which the platform
 * may run. And it may be set to any performance value in the range
 * [lowest_perf, highest_perf], inclusive but must be less than or equal to
 * max_perf.
 * Field des_perf conveys performance level Xen governor is requesting. And it
 * may be set to any performance value in the range [min_perf, max_perf],
 * inclusive. In active mode, des_perf must be zero.
 * Field epp represents energy performance preference, which only has meaning
 * when active mode is enabled. The EPP is used in the CCLK DPM controller
 * to drive the frequency that a core is going to operate during short periods
 * of activity, called minimum active frequency, It could contatin a range of
 * values from 0 to 0xff. An EPP of zero sets the min active frequency to
 * maximum frequency, while an EPP of 0xff sets the min active frequency to
 * approxiately Idle frequency.
 */
struct amd_cppc_drv_data {
    const struct xen_processor_cppc *cppc_data;
    union {
        uint64_t raw;
        struct {
            unsigned int lowest_perf:8;
            unsigned int lowest_nonlinear_perf:8;
            unsigned int nominal_perf:8;
            unsigned int highest_perf:8;
            unsigned int :32;
        };
    } caps;
    union {
        uint64_t raw;
        struct {
            unsigned int max_perf:8;
            unsigned int min_perf:8;
            unsigned int des_perf:8;
            unsigned int epp:8;
            unsigned int :32;
        };
    } req;

    uint8_t epp_init;

    int err;
};

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
    unsigned int        policy; /* CPUFREQ_POLICY_* */

    union {
        struct acpi_cpufreq_data acpi;
        struct hwp_drv_data hwp;
        struct amd_cppc_drv_data amd_cppc;
    }                   drv_data;
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

/*
 * Performance Policy
 * If cpufreq_driver->target() exists, the ->governor decides what frequency
 * within the limits is used. If cpufreq_driver->setpolicy() exists, these
 * following policies are available:
 * CPUFREQ_POLICY_PERFORMANCE represents maximum performance
 * CPUFREQ_POLICY_POWERSAVE represents least power consumption
 * CPUFREQ_POLICY_ONDEMAND represents no preference over performance or
 * powersave
 */
#define CPUFREQ_POLICY_UNKNOWN      0
#define CPUFREQ_POLICY_POWERSAVE    1
#define CPUFREQ_POLICY_PERFORMANCE  2
#define CPUFREQ_POLICY_ONDEMAND     3

unsigned int cpufreq_policy_from_governor(const struct cpufreq_governor *gov);

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

/*
 * If Energy Performance Preference(epp) is supported in the platform,
 * OSPM may write a range of values from 0(performance preference)
 * to 0xFF(energy efficiency perference) to control the platform's
 * energy efficiency and performance optimization policies
 */
#define CPPC_ENERGY_PERF_MAX_PERFORMANCE 0
#define CPPC_ENERGY_PERF_BALANCE         0x80
#define CPPC_ENERGY_PERF_MAX_POWERSAVE   0xff

int hwp_cmdline_parse(const char *s, const char *e);
int hwp_register_driver(void);
#ifdef CONFIG_INTEL
bool hwp_active(void);
#else
static inline bool hwp_active(void) { return false; }
#endif

int get_hwp_para(const struct cpufreq_policy *policy,
                 struct xen_get_cppc_para *cppc_para);
int set_hwp_para(struct cpufreq_policy *policy,
                 struct xen_set_cppc_para *set_cppc);

int acpi_cpufreq_register(void);

int amd_cppc_cmdline_parse(const char *s, const char *e);
int amd_cppc_register_driver(void);

/*
 * Governor-less cpufreq driver indicates the driver doesn't rely on Xen
 * governor to do performance tuning, mostly it has hardware built-in
 * algorithm to calculate runtime workload and adjust cores frequency
 * automatically, like Intel HWP, or CPPC in AMD.
 */
static inline bool cpufreq_is_governorless(unsigned int cpu)
{
    return processor_pminfo[cpu]->init && (hwp_active() ||
                                           cpufreq_driver.setpolicy);
}

#endif /* __XEN_CPUFREQ_PM_H__ */
