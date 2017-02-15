/*
 * cpuidle_menu - menu governor for cpu idle, main idea come from Linux.
 *            drivers/cpuidle/governors/menu.c 
 *
 *  Copyright (C) 2006-2007 Adam Belay <abelay@novell.com>
 *  Copyright (C) 2007, 2008 Intel Corporation
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/acpi.h>
#include <xen/timer.h>
#include <xen/cpuidle.h>
#include <asm/irq.h>

#define BUCKETS 6
#define RESOLUTION 1024
#define DECAY 4
#define MAX_INTERESTING 50000
#define LATENCY_MULTIPLIER 10

/*
 * Concepts and ideas behind the menu governor
 *
 * For the menu governor, there are 3 decision factors for picking a C
 * state:
 * 1) Energy break even point
 * 2) Performance impact
 * 3) Latency tolerance (TBD: from guest virtual C state)
 * These these three factors are treated independently.
 *
 * Energy break even point
 * -----------------------
 * C state entry and exit have an energy cost, and a certain amount of time in
 * the  C state is required to actually break even on this cost. CPUIDLE
 * provides us this duration in the "target_residency" field. So all that we
 * need is a good prediction of how long we'll be idle. Like the traditional
 * menu governor, we start with the actual known "next timer event" time.
 *
 * Since there are other source of wakeups (interrupts for example) than
 * the next timer event, this estimation is rather optimistic. To get a
 * more realistic estimate, a correction factor is applied to the estimate,
 * that is based on historic behavior. For example, if in the past the actual
 * duration always was 50% of the next timer tick, the correction factor will
 * be 0.5.
 *
 * menu uses a running average for this correction factor, however it uses a
 * set of factors, not just a single factor. This stems from the realization
 * that the ratio is dependent on the order of magnitude of the expected
 * duration; if we expect 500 milliseconds of idle time the likelihood of
 * getting an interrupt very early is much higher than if we expect 50 micro
 * seconds of idle time.
 * For this reason we keep an array of 6 independent factors, that gets
 * indexed based on the magnitude of the expected duration
 *
 * Limiting Performance Impact
 * ---------------------------
 * C states, especially those with large exit latencies, can have a real
 * noticable impact on workloads, which is not acceptable for most sysadmins,
 * and in addition, less performance has a power price of its own.
 *
 * As a general rule of thumb, menu assumes that the following heuristic
 * holds:
 *     The busier the system, the less impact of C states is acceptable
 *
 * This rule-of-thumb is implemented using average interrupt interval:
 * If the exit latency times multiplier is longer than the average
 * interrupt interval, the C state is not considered a candidate
 * for selection due to a too high performance impact. So the smaller
 * the average interrupt interval is, the smaller C state latency should be
 * and thus the less likely a busy CPU will hit such a deep C state.
 *
 * As an additional rule to reduce the performance impact, menu tries to
 * limit the exit latency duration to be no more than 10% of the decaying
 * measured idle time.
 */

struct perf_factor{
    s_time_t    time_stamp;
    s_time_t    duration;
    unsigned int irq_count_stamp;
    unsigned int irq_sum;
};

struct menu_device
{
    int             last_state_idx;
    unsigned int    expected_us;
    u64             predicted_us;
    u64             latency_factor;
    unsigned int    measured_us;
    unsigned int    exit_us;
    unsigned int    bucket;
    u64             correction_factor[BUCKETS];
    struct perf_factor pf;
};

static DEFINE_PER_CPU(struct menu_device, menu_devices);

static inline int which_bucket(unsigned int duration)
{
   int bucket = 0;

   if (duration < 10)
       return bucket;
   if (duration < 100)
       return bucket + 1;
   if (duration < 1000)
       return bucket + 2;
   if (duration < 10000)
       return bucket + 3;
   if (duration < 100000)
       return bucket + 4;
   return bucket + 5;
}

/*
 * Return the average interrupt interval to take I/O performance
 * requirements into account. The smaller the average interrupt
 * interval to be, the more busy I/O activity, and thus the higher
 * the barrier to go to an expensive C state.
 */

/* 5 milisec sampling period */
#define SAMPLING_PERIOD     5000000

/* for I/O interrupt, we give 8x multiplier compared to C state latency*/
#define IO_MULTIPLIER       8

static inline s_time_t avg_intr_interval_us(void)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    s_time_t    duration, now;
    s_time_t    avg_interval;
    unsigned int irq_sum;

    now = NOW();
    duration = (data->pf.duration + (now - data->pf.time_stamp)
            * (DECAY - 1)) / DECAY;

    irq_sum = (data->pf.irq_sum + (this_cpu(irq_count) - data->pf.irq_count_stamp)
            * (DECAY - 1)) / DECAY;

    if (irq_sum == 0)
        /* no irq recently, so return a big enough interval: 1 sec */
        avg_interval = 1000000;
    else
        avg_interval = duration / irq_sum / 1000; /* in us */

    if ( duration >= SAMPLING_PERIOD){
        data->pf.time_stamp = now;
        data->pf.duration = duration;
        data->pf.irq_count_stamp= this_cpu(irq_count);
        data->pf.irq_sum = irq_sum;
    }

    return avg_interval;
}

static unsigned int get_sleep_length_us(void)
{
    s_time_t us = (this_cpu(timer_deadline) - NOW()) / 1000;
    /*
     * while us < 0 or us > (u32)-1, return a large u32,
     * choose (unsigned int)-2000 to avoid wrapping while added with exit
     * latency because the latency should not larger than 2ms
     */
    return (us >> 32) ? (unsigned int)-2000 : (unsigned int)us;
}

static int menu_select(struct acpi_processor_power *power)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    int i;
    s_time_t    io_interval;

    /*  TBD: Change to 0 if C0(polling mode) support is added later*/
    data->last_state_idx = CPUIDLE_DRIVER_STATE_START;
    data->exit_us = 0;

    /* determine the expected residency time, round up */
    data->expected_us = get_sleep_length_us();

    data->bucket = which_bucket(data->expected_us);

    io_interval = avg_intr_interval_us();

    data->latency_factor = DIV_ROUND(
            data->latency_factor * (DECAY - 1) + data->measured_us,
            DECAY);

    /*
     * if the correction factor is 0 (eg first time init or cpu hotplug
     * etc), we actually want to start out with a unity factor.
     */
    if (data->correction_factor[data->bucket] == 0)
        data->correction_factor[data->bucket] = RESOLUTION * DECAY;

    /* Make sure to round up for half microseconds */
    data->predicted_us = DIV_ROUND(
            data->expected_us * data->correction_factor[data->bucket],
            RESOLUTION * DECAY);

    /* find the deepest idle state that satisfies our constraints */
    for ( i = CPUIDLE_DRIVER_STATE_START + 1; i < power->count; i++ )
    {
        struct acpi_processor_cx *s = &power->states[i];

        if (s->target_residency > data->predicted_us)
            break;
        if (s->latency * IO_MULTIPLIER > io_interval)
            break;
        if (s->latency * LATENCY_MULTIPLIER > data->latency_factor)
            break;
        /* TBD: we need to check the QoS requirment in future */
        data->exit_us = s->latency;
        data->last_state_idx = i;
    }

    return data->last_state_idx;
}

static void menu_reflect(struct acpi_processor_power *power)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    u64 new_factor;

    data->measured_us = power->last_residency;

    /*
     * We correct for the exit latency; we are assuming here that the
     * exit latency happens after the event that we're interested in.
     */
    if (data->measured_us > data->exit_us)
        data->measured_us -= data->exit_us;

    /* update our correction ratio */

    new_factor = data->correction_factor[data->bucket]
        * (DECAY - 1) / DECAY;

    if (data->expected_us > 0 && data->measured_us < MAX_INTERESTING)
        new_factor += RESOLUTION * data->measured_us / data->expected_us;
    else
        /*
         * we were idle so long that we count it as a perfect
         * prediction
         */
        new_factor += RESOLUTION;

    /*
     * We don't want 0 as factor; we always want at least
     * a tiny bit of estimated time.
     */
    if (new_factor == 0)
        new_factor = 1;

    data->correction_factor[data->bucket] = new_factor;
}

static int menu_enable_device(struct acpi_processor_power *power)
{
    if (!cpu_online(power->cpu))
        return -1;

    memset(&per_cpu(menu_devices, power->cpu), 0, sizeof(struct menu_device));

    return 0;
}

static struct cpuidle_governor menu_governor =
{
    .name =         "menu",
    .rating =       20,
    .enable =       menu_enable_device,
    .select =       menu_select,
    .reflect =      menu_reflect,
};

struct cpuidle_governor *cpuidle_current_governor = &menu_governor;
void menu_get_trace_data(u32 *expected, u32 *pred)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    *expected = data->expected_us;
    *pred = data->predicted_us;
}
