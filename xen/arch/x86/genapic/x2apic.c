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

static int x2apic = 1;
boolean_param("x2apic", x2apic);

static int x2apic_phys = 0; /* By default we use logical cluster mode. */
boolean_param("x2apic_phys", x2apic_phys);

__init int probe_x2apic_phys(void)
{
    return x2apic && x2apic_phys && x2apic_is_available() &&
        iommu_supports_eim();
}

__init int probe_x2apic_cluster(void)
{
    return x2apic && !x2apic_phys && x2apic_is_available() &&
        iommu_supports_eim();
}

struct genapic apic_x2apic_phys= {
    APIC_INIT("x2apic_phys", probe_x2apic_phys),
    GENAPIC_X2APIC_PHYS
};

struct genapic apic_x2apic_cluster= {
    APIC_INIT("x2apic_cluster", probe_x2apic_cluster),
    GENAPIC_X2APIC_CLUSTER
};

void init_apic_ldr_x2apic_phys(void)
{
    return;
}

void init_apic_ldr_x2apic_cluster(void)
{
    int cpu = smp_processor_id();
    cpu_2_logical_apicid[cpu] = apic_read(APIC_LDR);
}
void clustered_apic_check_x2apic(void)
{
    return;
}

cpumask_t target_cpus_x2apic(void)
{
    return cpu_online_map;
}

cpumask_t vector_allocation_domain_x2apic(int cpu)
{
	return cpumask_of_cpu(cpu);
}

unsigned int cpu_mask_to_apicid_x2apic_phys(cpumask_t cpumask)
{
    return cpu_physical_id(first_cpu(cpumask));
}

unsigned int cpu_mask_to_apicid_x2apic_cluster(cpumask_t cpumask)
{
    return cpu_2_logical_apicid[first_cpu(cpumask)];
}

void send_IPI_mask_x2apic_phys(const cpumask_t *cpumask, int vector)
{
    unsigned int cpu, cfg;
    unsigned long flags;

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

    cfg = APIC_DM_FIXED | 0 /* no shorthand */ | APIC_DEST_PHYSICAL | vector;
    for_each_cpu_mask ( cpu, *cpumask )
        if ( cpu != smp_processor_id() )
            apic_wrmsr(APIC_ICR, cfg, cpu_physical_id(cpu));

    local_irq_restore(flags);
}

void send_IPI_mask_x2apic_cluster(const cpumask_t *cpumask, int vector)
{
    unsigned int cpu, cfg;
    unsigned long flags;

    mb(); /* see the comment in send_IPI_mask_x2apic_phys() */

    local_irq_save(flags);

    cfg = APIC_DM_FIXED | 0 /* no shorthand */ | APIC_DEST_LOGICAL | vector;
    for_each_cpu_mask ( cpu, *cpumask )
        if ( cpu != smp_processor_id() )
            apic_wrmsr(APIC_ICR, cfg, cpu_2_logical_apicid[cpu]);

    local_irq_restore(flags);
}
