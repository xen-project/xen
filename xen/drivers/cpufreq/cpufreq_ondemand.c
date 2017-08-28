/*
 *  xen/arch/x86/acpi/cpufreq/cpufreq_ondemand.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *             Feb 2008 Liu Jinsong <jinsong.liu@intel.com>
 *             Porting cpufreq_ondemand.c from Liunx 2.6.23 to Xen hypervisor 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <xen/types.h>
#include <xen/percpu.h>
#include <xen/cpumask.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <acpi/cpufreq/cpufreq.h>

#define DEF_FREQUENCY_UP_THRESHOLD              (80)
#define MIN_FREQUENCY_UP_THRESHOLD              (11)
#define MAX_FREQUENCY_UP_THRESHOLD              (100)

#define MIN_DBS_INTERVAL                        (MICROSECS(100))
#define MIN_SAMPLING_RATE_RATIO                 (2)
#define MIN_SAMPLING_MILLISECS                  (MIN_SAMPLING_RATE_RATIO * 10)
#define MIN_STAT_SAMPLING_RATE                  \
    (MIN_SAMPLING_MILLISECS * MILLISECS(1))
#define MIN_SAMPLING_RATE                       \
    (def_sampling_rate / MIN_SAMPLING_RATE_RATIO)
#define MAX_SAMPLING_RATE                       (500 * def_sampling_rate)
#define DEF_SAMPLING_RATE_LATENCY_MULTIPLIER    (1000)
#define TRANSITION_LATENCY_LIMIT                (10 * 1000 )

static uint64_t def_sampling_rate;
static uint64_t usr_sampling_rate;

/* Sampling types */
enum {DBS_NORMAL_SAMPLE, DBS_SUB_SAMPLE};

static DEFINE_PER_CPU(struct cpu_dbs_info_s, cpu_dbs_info);

static unsigned int dbs_enable;    /* number of CPUs using this policy */

static struct dbs_tuners {
    uint64_t     sampling_rate;
    unsigned int up_threshold;
    unsigned int powersave_bias;
} dbs_tuners_ins = {
    .sampling_rate = 0,
    .up_threshold = DEF_FREQUENCY_UP_THRESHOLD,
    .powersave_bias = 0,
};

static DEFINE_PER_CPU(struct timer, dbs_timer);

int write_ondemand_sampling_rate(unsigned int sampling_rate)
{
    if ( (sampling_rate > MAX_SAMPLING_RATE / MICROSECS(1)) ||
         (sampling_rate < MIN_SAMPLING_RATE / MICROSECS(1)) )
        return -EINVAL;

    dbs_tuners_ins.sampling_rate = sampling_rate * MICROSECS(1);
    return 0;
}

int write_ondemand_up_threshold(unsigned int up_threshold)
{
    if ( (up_threshold > MAX_FREQUENCY_UP_THRESHOLD) ||
         (up_threshold < MIN_FREQUENCY_UP_THRESHOLD) )
        return -EINVAL;

    dbs_tuners_ins.up_threshold = up_threshold;
    return 0;
}

int get_cpufreq_ondemand_para(uint32_t *sampling_rate_max,
                              uint32_t *sampling_rate_min,
                              uint32_t *sampling_rate,
                              uint32_t *up_threshold)
{
    if (!sampling_rate_max || !sampling_rate_min ||
        !sampling_rate || !up_threshold)
        return -EINVAL;

    *sampling_rate_max = MAX_SAMPLING_RATE/MICROSECS(1);
    *sampling_rate_min = MIN_SAMPLING_RATE/MICROSECS(1);
    *sampling_rate = dbs_tuners_ins.sampling_rate / MICROSECS(1);
    *up_threshold = dbs_tuners_ins.up_threshold;

    return 0;
}

static void dbs_check_cpu(struct cpu_dbs_info_s *this_dbs_info)
{
    uint64_t cur_ns, total_ns;
    uint64_t max_load_freq = 0;
    struct cpufreq_policy *policy;
    unsigned int max;
    unsigned int j;

    if (!this_dbs_info->enable)
        return;

    policy = this_dbs_info->cur_policy;
    max = policy->max;

    if (unlikely(policy->resume)) {
        __cpufreq_driver_target(policy, max,CPUFREQ_RELATION_H);
        return;
    }

    cur_ns = NOW();
    total_ns = cur_ns - this_dbs_info->prev_cpu_wall;
    this_dbs_info->prev_cpu_wall = NOW();

    if (total_ns < MIN_DBS_INTERVAL)
        return;

    /* Get Idle Time */
    for_each_cpu(j, policy->cpus) {
        uint64_t idle_ns, total_idle_ns;
        uint64_t load, load_freq, freq_avg;
        struct cpu_dbs_info_s *j_dbs_info;

        j_dbs_info = &per_cpu(cpu_dbs_info, j);
        total_idle_ns = get_cpu_idle_time(j);
        idle_ns = total_idle_ns - j_dbs_info->prev_cpu_idle;
        j_dbs_info->prev_cpu_idle = total_idle_ns;

        if (unlikely(total_ns < idle_ns))
            continue;

        load = 100 * (total_ns - idle_ns) / total_ns;

        freq_avg = cpufreq_driver_getavg(j, GOV_GETAVG);

        load_freq = load * freq_avg;
        if (load_freq > max_load_freq)
            max_load_freq = load_freq;
    }

    /* Check for frequency increase */
    if (max_load_freq > (uint64_t) dbs_tuners_ins.up_threshold * policy->cur) {
        /* if we are already at full speed then break out early */
        if (policy->cur == max)
            return;
        __cpufreq_driver_target(policy, max, CPUFREQ_RELATION_H);
        return;
    }

    /* Check for frequency decrease */
    /* if we cannot reduce the frequency anymore, break out early */
    if (policy->cur == policy->min)
        return;

    /*
     * The optimal frequency is the frequency that is the lowest that
     * can support the current CPU usage without triggering the up
     * policy. To be safe, we focus 10 points under the threshold.
     */
    if (max_load_freq
        < (uint64_t) (dbs_tuners_ins.up_threshold - 10) * policy->cur) {
        uint64_t freq_next;

        freq_next = max_load_freq / (dbs_tuners_ins.up_threshold - 10);

        __cpufreq_driver_target(policy, freq_next, CPUFREQ_RELATION_L);
    }
}

static void do_dbs_timer(void *dbs)
{
    struct cpu_dbs_info_s *dbs_info = (struct cpu_dbs_info_s *)dbs;

    if (!dbs_info->enable)
        return;

    dbs_check_cpu(dbs_info);

    set_timer(&per_cpu(dbs_timer, dbs_info->cpu),
            align_timer(NOW() , dbs_tuners_ins.sampling_rate));
}

static void dbs_timer_init(struct cpu_dbs_info_s *dbs_info)
{
    dbs_info->enable = 1;

    init_timer(&per_cpu(dbs_timer, dbs_info->cpu), do_dbs_timer,
        (void *)dbs_info, dbs_info->cpu);

    set_timer(&per_cpu(dbs_timer, dbs_info->cpu), NOW()+dbs_tuners_ins.sampling_rate);

    if ( processor_pminfo[dbs_info->cpu]->perf.shared_type
            == CPUFREQ_SHARED_TYPE_HW )
    {
        dbs_info->stoppable = 1;
    }
}

static void dbs_timer_exit(struct cpu_dbs_info_s *dbs_info)
{
    dbs_info->enable = 0;
    dbs_info->stoppable = 0;
    kill_timer(&per_cpu(dbs_timer, dbs_info->cpu));
}

int cpufreq_governor_dbs(struct cpufreq_policy *policy, unsigned int event)
{
    unsigned int cpu = policy->cpu;
    struct cpu_dbs_info_s *this_dbs_info;
    unsigned int j;

    this_dbs_info = &per_cpu(cpu_dbs_info, cpu);

    switch (event) {
    case CPUFREQ_GOV_START:
        if ((!cpu_online(cpu)) || (!policy->cur))
            return -EINVAL;

        if (policy->cpuinfo.transition_latency >
            (TRANSITION_LATENCY_LIMIT * 1000)) {
            printk(KERN_WARNING "ondemand governor failed to load "
                "due to too long transition latency\n");
            return -EINVAL;
        }
        if (this_dbs_info->enable)
            /* Already enabled */
            break;

        dbs_enable++;

        for_each_cpu(j, policy->cpus) {
            struct cpu_dbs_info_s *j_dbs_info;
            j_dbs_info = &per_cpu(cpu_dbs_info, j);
            j_dbs_info->cur_policy = policy;

            j_dbs_info->prev_cpu_idle = get_cpu_idle_time(j);
            j_dbs_info->prev_cpu_wall = NOW();
        }
        this_dbs_info->cpu = cpu;
        /*
         * Start the timerschedule work, when this governor
         * is used for first time
         */
        if ((dbs_enable == 1) && !dbs_tuners_ins.sampling_rate) {
            def_sampling_rate = (uint64_t) policy->cpuinfo.transition_latency *
                DEF_SAMPLING_RATE_LATENCY_MULTIPLIER;

            if (def_sampling_rate < MIN_STAT_SAMPLING_RATE)
                def_sampling_rate = MIN_STAT_SAMPLING_RATE;

            if (!usr_sampling_rate)
                dbs_tuners_ins.sampling_rate = def_sampling_rate;
            else if (usr_sampling_rate < MIN_SAMPLING_RATE) {
                printk(KERN_WARNING "cpufreq/ondemand: "
                       "specified sampling rate too low, using %"PRIu64"\n",
                       MIN_SAMPLING_RATE);
                dbs_tuners_ins.sampling_rate = MIN_SAMPLING_RATE;
            } else if (usr_sampling_rate > MAX_SAMPLING_RATE) {
                printk(KERN_WARNING "cpufreq/ondemand: "
                       "specified sampling rate too high, using %"PRIu64"\n",
                       MAX_SAMPLING_RATE);
                dbs_tuners_ins.sampling_rate = MAX_SAMPLING_RATE;
            } else
                dbs_tuners_ins.sampling_rate = usr_sampling_rate;
        }
        dbs_timer_init(this_dbs_info);

        break;

    case CPUFREQ_GOV_STOP:
        if ( !this_dbs_info->enable )
            /* Already not enabled */
            break;

        dbs_timer_exit(this_dbs_info);
        dbs_enable--;

        break;

    case CPUFREQ_GOV_LIMITS:
        if ( this_dbs_info->cur_policy == NULL )
        {
            printk(KERN_WARNING "CPU%d ondemand governor not started yet,"
                    "unable to GOV_LIMIT\n", cpu);
            return -EINVAL;
        }
        if (policy->max < this_dbs_info->cur_policy->cur)
            __cpufreq_driver_target(this_dbs_info->cur_policy,
                policy->max, CPUFREQ_RELATION_H);
        else if (policy->min > this_dbs_info->cur_policy->cur)
            __cpufreq_driver_target(this_dbs_info->cur_policy,
                policy->min, CPUFREQ_RELATION_L);
        break;
    }
    return 0;
}

static bool_t __init cpufreq_dbs_handle_option(const char *name, const char *val)
{
    if ( !strcmp(name, "rate") && val )
    {
        usr_sampling_rate = simple_strtoull(val, NULL, 0) * MICROSECS(1);
    }
    else if ( !strcmp(name, "up_threshold") && val )
    {
        unsigned long tmp = simple_strtoul(val, NULL, 0);

        if ( tmp < MIN_FREQUENCY_UP_THRESHOLD )
        {
            printk(XENLOG_WARNING "cpufreq/ondemand: "
                   "specified threshold too low, using %d\n",
                   MIN_FREQUENCY_UP_THRESHOLD);
            tmp = MIN_FREQUENCY_UP_THRESHOLD;
        }
        else if ( tmp > MAX_FREQUENCY_UP_THRESHOLD )
        {
            printk(XENLOG_WARNING "cpufreq/ondemand: "
                   "specified threshold too high, using %d\n",
                   MAX_FREQUENCY_UP_THRESHOLD);
            tmp = MAX_FREQUENCY_UP_THRESHOLD;
        }
        dbs_tuners_ins.up_threshold = tmp;
    }
    else if ( !strcmp(name, "bias") && val )
    {
        unsigned long tmp = simple_strtoul(val, NULL, 0);

        if ( tmp > 1000 )
        {
            printk(XENLOG_WARNING "cpufreq/ondemand: "
                   "specified bias too high, using 1000\n");
            tmp = 1000;
        }
        dbs_tuners_ins.powersave_bias = tmp;
    }
    else
        return 0;
    return 1;
}

struct cpufreq_governor cpufreq_gov_dbs = {
    .name = "ondemand",
    .governor = cpufreq_governor_dbs,
    .handle_option = cpufreq_dbs_handle_option
};

static int __init cpufreq_gov_dbs_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_dbs);
}
__initcall(cpufreq_gov_dbs_init);

void cpufreq_dbs_timer_suspend(void)
{
    int cpu;

    cpu = smp_processor_id();

    if ( per_cpu(cpu_dbs_info,cpu).stoppable )
    {
        stop_timer( &per_cpu(dbs_timer, cpu) );
    }
}

void cpufreq_dbs_timer_resume(void)
{
    int cpu;
    struct timer* t;
    s_time_t now;

    cpu = smp_processor_id();

    if ( per_cpu(cpu_dbs_info,cpu).stoppable )
    {
        now = NOW();
        t = &per_cpu(dbs_timer, cpu);
        if (t->expires <= now)
        {
            t->function(t->data);
        }
        else
        {
            set_timer(t, align_timer(now , dbs_tuners_ins.sampling_rate));
        }
    }
}
