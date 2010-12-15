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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/cpumask.h>
#include <asm/apicdef.h>
#include <asm/genapic.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <xen/smp.h>
#include <asm/mach-default/mach_mpparse.h>

static int __initdata x2apic_phys; /* By default we use logical cluster mode. */
boolean_param("x2apic_phys", x2apic_phys);

static void init_apic_ldr_x2apic_phys(void)
{
}

static void init_apic_ldr_x2apic_cluster(void)
{
    int cpu = smp_processor_id();
    cpu_2_logical_apicid[cpu] = apic_read(APIC_LDR);
}

static void clustered_apic_check_x2apic(void)
{
}

static const cpumask_t *target_cpus_x2apic(void)
{
    return &cpu_online_map;
}

static const cpumask_t *vector_allocation_cpumask_x2apic(int cpu)
{
    return cpumask_of(cpu);
}

static unsigned int cpu_mask_to_apicid_x2apic_phys(const cpumask_t *cpumask)
{
    return cpu_physical_id(cpumask_first(cpumask));
}

static unsigned int cpu_mask_to_apicid_x2apic_cluster(const cpumask_t *cpumask)
{
    return cpu_2_logical_apicid[cpumask_first(cpumask)];
}

static void __send_IPI_mask_x2apic(
    const cpumask_t *cpumask, int vector, unsigned int dest_mode)
{
    unsigned int cpu;
    unsigned long flags;
    uint64_t msr_content;

    /*
     * Ensure that any synchronisation data written in program order by this
     * CPU is seen by notified remote CPUs. The WRMSR contained within
     * apic_icr_write() can otherwise be executed early.
     * 
     * The reason mb() is sufficient here is subtle: the register arguments
     * to WRMSR must depend on a memory read executed after the barrier. This
     * is guaranteed by cpu_physical_id(), which reads from a global array (and
     * so cannot be hoisted above the barrier even by a clever compiler).
     */
    mb();

    local_irq_save(flags);

    for_each_cpu_mask ( cpu, *cpumask )
    {
        if ( !cpu_online(cpu) || (cpu == smp_processor_id()) )
            continue;
        msr_content = (dest_mode == APIC_DEST_PHYSICAL)
            ? cpu_physical_id(cpu) : cpu_2_logical_apicid[cpu];
        msr_content = (msr_content << 32) | APIC_DM_FIXED | dest_mode | vector;
        apic_wrmsr(APIC_ICR, msr_content);
    }

    local_irq_restore(flags);
}

static void send_IPI_mask_x2apic_phys(const cpumask_t *cpumask, int vector)
{
    __send_IPI_mask_x2apic(cpumask, vector, APIC_DEST_PHYSICAL);
}

static void send_IPI_mask_x2apic_cluster(const cpumask_t *cpumask, int vector)
{
    __send_IPI_mask_x2apic(cpumask, vector, APIC_DEST_LOGICAL);
}

static const struct genapic apic_x2apic_phys = {
    APIC_INIT("x2apic_phys", NULL),
    .int_delivery_mode = dest_Fixed,
    .int_dest_mode = 0 /* physical delivery */,
    .init_apic_ldr = init_apic_ldr_x2apic_phys,
    .clustered_apic_check = clustered_apic_check_x2apic,
    .target_cpus = target_cpus_x2apic,
    .vector_allocation_cpumask = vector_allocation_cpumask_x2apic,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_x2apic_phys,
    .send_IPI_mask = send_IPI_mask_x2apic_phys,
    .send_IPI_self = send_IPI_self_x2apic
};

static const struct genapic apic_x2apic_cluster = {
    APIC_INIT("x2apic_cluster", NULL),
    .int_delivery_mode = dest_LowestPrio,
    .int_dest_mode = 1 /* logical delivery */,
    .init_apic_ldr = init_apic_ldr_x2apic_cluster,
    .clustered_apic_check = clustered_apic_check_x2apic,
    .target_cpus = target_cpus_x2apic,
    .vector_allocation_cpumask = vector_allocation_cpumask_x2apic,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_x2apic_cluster,
    .send_IPI_mask = send_IPI_mask_x2apic_cluster,
    .send_IPI_self = send_IPI_self_x2apic
};

const struct genapic *__init apic_x2apic_probe(void)
{
    return x2apic_phys ? &apic_x2apic_phys : &apic_x2apic_cluster;
}
