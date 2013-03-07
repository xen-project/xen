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
#include <asm/msr.h>
#include <asm/processor.h>
#include <xen/smp.h>
#include <asm/mach-default/mach_mpparse.h>

static void init_apic_ldr_x2apic_phys(void)
{
}

static void init_apic_ldr_x2apic_cluster(void)
{
    int cpu = smp_processor_id();
    cpu_2_logical_apicid[cpu] = apic_read(APIC_LDR);
}

static void __init clustered_apic_check_x2apic(void)
{
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

    for_each_cpu ( cpu, cpumask )
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
    .target_cpus = target_cpus_all,
    .vector_allocation_cpumask = vector_allocation_cpumask_phys,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_phys,
    .send_IPI_mask = send_IPI_mask_x2apic_phys,
    .send_IPI_self = send_IPI_self_x2apic
};

static const struct genapic apic_x2apic_cluster = {
    APIC_INIT("x2apic_cluster", NULL),
    .int_delivery_mode = dest_LowestPrio,
    .int_dest_mode = 1 /* logical delivery */,
    .init_apic_ldr = init_apic_ldr_x2apic_cluster,
    .clustered_apic_check = clustered_apic_check_x2apic,
    .target_cpus = target_cpus_all,
    .vector_allocation_cpumask = vector_allocation_cpumask_phys,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_x2apic_cluster,
    .send_IPI_mask = send_IPI_mask_x2apic_cluster,
    .send_IPI_self = send_IPI_self_x2apic
};

static s8 __initdata x2apic_phys = -1; /* By default we use logical cluster mode. */
boolean_param("x2apic_phys", x2apic_phys);

const struct genapic *__init apic_x2apic_probe(void)
{
    if ( x2apic_phys < 0 )
        x2apic_phys = !!(acpi_gbl_FADT.flags & ACPI_FADT_APIC_PHYSICAL);

    return x2apic_phys ? &apic_x2apic_phys : &apic_x2apic_cluster;
}

void __init check_x2apic_preenabled(void)
{
    u32 lo, hi;

    if ( !cpu_has_x2apic )
        return;

    /* Check whether x2apic mode was already enabled by the BIOS. */
    rdmsr(MSR_IA32_APICBASE, lo, hi);
    if ( lo & MSR_IA32_APICBASE_EXTD )
    {
        printk("x2APIC mode is already enabled by BIOS.\n");
#ifndef __i386__
        x2apic_enabled = 1;
        genapic = apic_x2apic_probe();
#else
        lo &= ~(MSR_IA32_APICBASE_ENABLE | MSR_IA32_APICBASE_EXTD);
        wrmsr(MSR_IA32_APICBASE, lo, hi);
        lo |= MSR_IA32_APICBASE_ENABLE;
        wrmsr(MSR_IA32_APICBASE, lo, hi);
        printk("x2APIC disabled permanently on x86_32.\n");
#endif
    }

#ifdef __i386__
    clear_bit(X86_FEATURE_X2APIC, boot_cpu_data.x86_capability);
#endif
}
