/*
 * x2APIC driver.
 *
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

#include <xen/cpumask.h>
#include <asm/apicdef.h>
#include <asm/genapic.h>
#include <xen/smp.h>
#include <asm/mach-default/mach_mpparse.h>

__init int probe_x2apic(void)
{
    return x2apic_is_available();
}

struct genapic apic_x2apic= {
    APIC_INIT("x2apic", probe_x2apic),
    GENAPIC_X2APIC
};

void init_apic_ldr_x2apic(void)
{
    /* We only use physical delivery mode. */
    return;
}

void clustered_apic_check_x2apic(void)
{
    /* We only use physical delivery mode. */
    return;
}

cpumask_t target_cpus_x2apic(void)
{
    /* Deliver interrupts only to CPU0 for now */
    return cpumask_of_cpu(0);
}

unsigned int cpu_mask_to_apicid_x2apic(cpumask_t cpumask)
{
    return cpu_physical_id(first_cpu(cpumask));
}

void send_IPI_mask_x2apic(cpumask_t cpumask, int vector)
{
    unsigned int query_cpu;
    u32 cfg, dest;
    unsigned long flags;

    ASSERT(cpus_subset(cpumask, cpu_online_map));
    ASSERT(!cpus_empty(cpumask));

    local_irq_save(flags);

    cfg = APIC_DM_FIXED | 0 /* no shorthand */ | APIC_DEST_PHYSICAL | vector;
    for_each_cpu_mask(query_cpu, cpumask)
    {
        dest =  cpu_physical_id(query_cpu);
        apic_icr_write(cfg, dest);
    }

    local_irq_restore(flags);
}

