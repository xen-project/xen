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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <asm/apicdef.h>
#include <asm/genapic.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <xen/smp.h>
#include <asm/mach-default/mach_mpparse.h>

static DEFINE_PER_CPU_READ_MOSTLY(u32, cpu_2_logical_apicid);
static DEFINE_PER_CPU_READ_MOSTLY(cpumask_t *, cluster_cpus);
static cpumask_t *cluster_cpus_spare;
static DEFINE_PER_CPU(cpumask_var_t, scratch_mask);

static inline u32 x2apic_cluster(unsigned int cpu)
{
    return per_cpu(cpu_2_logical_apicid, cpu) >> 16;
}

static void init_apic_ldr_x2apic_phys(void)
{
}

static void init_apic_ldr_x2apic_cluster(void)
{
    unsigned int cpu, this_cpu = smp_processor_id();

    per_cpu(cpu_2_logical_apicid, this_cpu) = apic_read(APIC_LDR);

    if ( per_cpu(cluster_cpus, this_cpu) )
    {
        ASSERT(cpumask_test_cpu(this_cpu, per_cpu(cluster_cpus, this_cpu)));
        return;
    }

    per_cpu(cluster_cpus, this_cpu) = cluster_cpus_spare;
    for_each_online_cpu ( cpu )
    {
        if (this_cpu == cpu || x2apic_cluster(this_cpu) != x2apic_cluster(cpu))
            continue;
        per_cpu(cluster_cpus, this_cpu) = per_cpu(cluster_cpus, cpu);
        break;
    }
    if ( per_cpu(cluster_cpus, this_cpu) == cluster_cpus_spare )
        cluster_cpus_spare = NULL;

    cpumask_set_cpu(this_cpu, per_cpu(cluster_cpus, this_cpu));
}

static void __init clustered_apic_check_x2apic(void)
{
}

static const cpumask_t *vector_allocation_cpumask_x2apic_cluster(int cpu)
{
    return per_cpu(cluster_cpus, cpu);
}

static unsigned int cpu_mask_to_apicid_x2apic_cluster(const cpumask_t *cpumask)
{
    unsigned int cpu = cpumask_any(cpumask);
    unsigned int dest = per_cpu(cpu_2_logical_apicid, cpu);
    const cpumask_t *cluster_cpus = per_cpu(cluster_cpus, cpu);

    for_each_cpu ( cpu, cluster_cpus )
        if ( cpumask_test_cpu(cpu, cpumask) )
            dest |= per_cpu(cpu_2_logical_apicid, cpu);

    return dest;
}

static void send_IPI_self_x2apic(uint8_t vector)
{
    apic_wrmsr(APIC_SELF_IPI, vector);
}

static void send_IPI_mask_x2apic_phys(const cpumask_t *cpumask, int vector)
{
    unsigned int cpu;
    unsigned long flags;
    uint64_t msr_content;

    /*
     * Ensure that any synchronisation data written in program order by this
     * CPU is seen by notified remote CPUs. The WRMSR contained within
     * apic_icr_write() can otherwise be executed early.
     * 
     * The reason smp_mb() is sufficient here is subtle: the register arguments
     * to WRMSR must depend on a memory read executed after the barrier. This
     * is guaranteed by cpu_physical_id(), which reads from a global array (and
     * so cannot be hoisted above the barrier even by a clever compiler).
     */
    smp_mb();

    local_irq_save(flags);

    for_each_cpu ( cpu, cpumask )
    {
        if ( !cpu_online(cpu) || (cpu == smp_processor_id()) )
            continue;
        msr_content = cpu_physical_id(cpu);
        msr_content = (msr_content << 32) | APIC_DM_FIXED |
                      APIC_DEST_PHYSICAL | vector;
        apic_wrmsr(APIC_ICR, msr_content);
    }

    local_irq_restore(flags);
}

static void send_IPI_mask_x2apic_cluster(const cpumask_t *cpumask, int vector)
{
    unsigned int cpu = smp_processor_id();
    cpumask_t *ipimask = per_cpu(scratch_mask, cpu);
    const cpumask_t *cluster_cpus;
    unsigned long flags;

    smp_mb(); /* See above for an explanation. */

    local_irq_save(flags);

    cpumask_andnot(ipimask, &cpu_online_map, cpumask_of(cpu));

    for ( cpumask_and(ipimask, cpumask, ipimask); !cpumask_empty(ipimask);
          cpumask_andnot(ipimask, ipimask, cluster_cpus) )
    {
        uint64_t msr_content = 0;

        cluster_cpus = per_cpu(cluster_cpus, cpumask_first(ipimask));
        for_each_cpu ( cpu, cluster_cpus )
        {
            if ( !cpumask_test_cpu(cpu, ipimask) )
                continue;
            msr_content |= per_cpu(cpu_2_logical_apicid, cpu);
        }

        BUG_ON(!msr_content);
        msr_content = (msr_content << 32) | APIC_DM_FIXED |
                      APIC_DEST_LOGICAL | vector;
        apic_wrmsr(APIC_ICR, msr_content);
    }

    local_irq_restore(flags);
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
    .vector_allocation_cpumask = vector_allocation_cpumask_x2apic_cluster,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_x2apic_cluster,
    .send_IPI_mask = send_IPI_mask_x2apic_cluster,
    .send_IPI_self = send_IPI_self_x2apic
};

static int update_clusterinfo(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int err = 0;

    switch (action) {
    case CPU_UP_PREPARE:
        per_cpu(cpu_2_logical_apicid, cpu) = BAD_APICID;
        if ( !cluster_cpus_spare )
            cluster_cpus_spare = xzalloc(cpumask_t);
        if ( !cluster_cpus_spare ||
             !alloc_cpumask_var(&per_cpu(scratch_mask, cpu)) )
            err = -ENOMEM;
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        if ( per_cpu(cluster_cpus, cpu) )
        {
            cpumask_clear_cpu(cpu, per_cpu(cluster_cpus, cpu));
            if ( cpumask_empty(per_cpu(cluster_cpus, cpu)) )
                xfree(per_cpu(cluster_cpus, cpu));
        }
        free_cpumask_var(per_cpu(scratch_mask, cpu));
        break;
    }

    return !err ? NOTIFY_DONE : notifier_from_errno(err);
}

static struct notifier_block x2apic_cpu_nfb = {
   .notifier_call = update_clusterinfo
};

static s8 __initdata x2apic_phys = -1; /* By default we use logical cluster mode. */
boolean_param("x2apic_phys", x2apic_phys);

const struct genapic *__init apic_x2apic_probe(void)
{
    if ( x2apic_phys < 0 )
        x2apic_phys = !!(acpi_gbl_FADT.flags & ACPI_FADT_APIC_PHYSICAL);

    if ( x2apic_phys )
        return &apic_x2apic_phys;

    if ( !this_cpu(cluster_cpus) )
    {
        update_clusterinfo(NULL, CPU_UP_PREPARE,
                           (void *)(long)smp_processor_id());
        init_apic_ldr_x2apic_cluster();
        register_cpu_notifier(&x2apic_cpu_nfb);
    }

    return &apic_x2apic_cluster;
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
        x2apic_enabled = 1;
        genapic = apic_x2apic_probe();
    }
}
