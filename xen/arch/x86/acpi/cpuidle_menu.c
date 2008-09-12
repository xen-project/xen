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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <xen/config.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/acpi.h>
#include <xen/timer.h>
#include <xen/cpuidle.h>

#define BREAK_FUZZ      4       /* 4 us */
#define USEC_PER_SEC 1000000

struct menu_device
{
    int             last_state_idx;
    unsigned int    expected_us;
    unsigned int    predicted_us;
    unsigned int    last_measured_us;
    unsigned int    elapsed_us;
};

static DEFINE_PER_CPU(struct menu_device, menu_devices);

static s_time_t get_sleep_length_ns(void)
{
    return per_cpu(timer_deadline, smp_processor_id()) - NOW();
}

static int menu_select(struct acpi_processor_power *power)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    int i;

    /* determine the expected residency time */
    data->expected_us = (u32) get_sleep_length_ns() / 1000;

    /* find the deepest idle state that satisfies our constraints */
    for ( i = 1; i < power->count; i++ )
    {
        struct acpi_processor_cx *s = &power->states[i];

        if ( s->target_residency > data->expected_us + s->latency )
            break;
        if ( s->target_residency > data->predicted_us )
            break;
        /* TBD: we need to check the QoS requirment in future */
    }

    data->last_state_idx = i - 1;
    return i - 1;
}

static void menu_reflect(struct acpi_processor_power *power)
{
    struct menu_device *data = &__get_cpu_var(menu_devices);
    struct acpi_processor_cx *target = &power->states[data->last_state_idx];
    unsigned int last_residency; 
    unsigned int measured_us;

    /*
     * Ugh, this idle state doesn't support residency measurements, so we
     * are basically lost in the dark.  As a compromise, assume we slept
     * for one full standard timer tick.  However, be aware that this
     * could potentially result in a suboptimal state transition.
     */
    if ( target->type == ACPI_STATE_C1 )
        last_residency = USEC_PER_SEC / HZ;
    else
        last_residency = power->last_residency;

    measured_us = last_residency + data->elapsed_us;

    /* if wrapping, set to max uint (-1) */
    measured_us = data->elapsed_us <= measured_us ? measured_us : -1;

    /* Predict time remaining until next break event */
    data->predicted_us = max(measured_us, data->last_measured_us);

    /* Distinguish between expected & non-expected events */
    if ( last_residency + BREAK_FUZZ
         < data->expected_us + target->latency )
    {
        data->last_measured_us = measured_us;
        data->elapsed_us = 0;
    }
    else
        data->elapsed_us = measured_us;
}

static int menu_enable_device(struct acpi_processor_power *power)
{
    struct menu_device *data = &per_cpu(menu_devices, power->cpu);

    memset(data, 0, sizeof(struct menu_device));

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
