/*
 * cpuidle.h - xen idle state module derived from Linux 
 *
 * (C) 2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *          Shaohua Li <shaohua.li@intel.com>
 *          Adam Belay <abelay@novell.com>
 *  Copyright (C) 2008 Intel Corporation
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
#ifndef _XEN_CPUIDLE_H
#define _XEN_CPUIDLE_H

#include <xen/cpumask.h>
#include <xen/spinlock.h>

#define ACPI_PROCESSOR_MAX_POWER        8
#define CPUIDLE_NAME_LEN                16

#define ACPI_CSTATE_EM_NONE     0
#define ACPI_CSTATE_EM_SYSIO    1
#define ACPI_CSTATE_EM_FFH      2
#define ACPI_CSTATE_EM_HALT     3

struct acpi_processor_cx
{
    u8 idx;
    u8 type;         /* ACPI_STATE_Cn */
    u8 entry_method; /* ACPI_CSTATE_EM_xxx */
    u32 address;
    u32 latency;
    u32 target_residency;
    u32 usage;
    u64 time;
};

struct acpi_processor_flags
{
    u8 bm_control:1;
    u8 bm_check:1;
    u8 has_cst:1;
    u8 power_setup_done:1;
    u8 bm_rld_set:1;
};

struct acpi_processor_power
{
    unsigned int cpu;
    struct acpi_processor_flags flags;
    struct acpi_processor_cx *last_state;
    struct acpi_processor_cx *safe_state;
    void *gdata; /* governor specific data */
    u64 last_state_update_tick;
    u32 last_residency;
    u32 count;
    spinlock_t stat_lock;
    struct acpi_processor_cx states[ACPI_PROCESSOR_MAX_POWER];
};

struct cpuidle_governor
{
    char                    name[CPUIDLE_NAME_LEN];
    unsigned int            rating;

    int  (*enable)          (struct acpi_processor_power *dev);
    void (*disable)         (struct acpi_processor_power *dev);

    int  (*select)          (struct acpi_processor_power *dev);
    void (*reflect)         (struct acpi_processor_power *dev);
};

extern s8 xen_cpuidle;
extern struct cpuidle_governor *cpuidle_current_governor;

bool_t cpuidle_using_deep_cstate(void);
void cpuidle_disable_deep_cstate(void);

extern void cpuidle_wakeup_mwait(cpumask_t *mask);

#define CPUIDLE_DRIVER_STATE_START  1

extern void menu_get_trace_data(u32 *expected, u32 *pred);

#endif /* _XEN_CPUIDLE_H */
