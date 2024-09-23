/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * x2APIC driver.
 *
 * Copyright (c) 2008, Intel Corporation.
 */

#include <xen/init.h>
#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/param.h>
#include <asm/apicdef.h>
#include <asm/genapic.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <xen/smp.h>

static DEFINE_PER_CPU_READ_MOSTLY(u32, cpu_2_logical_apicid);
static DEFINE_PER_CPU_READ_MOSTLY(cpumask_t *, cluster_cpus);
static cpumask_t *cluster_cpus_spare;
static DEFINE_PER_CPU(cpumask_var_t, scratch_mask);

static inline u32 x2apic_cluster(unsigned int cpu)
{
    return per_cpu(cpu_2_logical_apicid, cpu) >> 16;
}

static void cf_check init_apic_ldr_x2apic_cluster(void)
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
        if ( this_cpu == cpu )
            continue;
        /*
         * Guard in particular against the compiler suspecting out-of-bounds
         * array accesses below when NR_CPUS=1 (oddly enough with gcc 10 it
         * is the 1st of these alone which actually helps, not the 2nd, nor
         * are both required together there).
         */
        BUG_ON(this_cpu >= NR_CPUS);
        BUG_ON(cpu >= NR_CPUS);
        if ( x2apic_cluster(this_cpu) != x2apic_cluster(cpu) )
            continue;
        per_cpu(cluster_cpus, this_cpu) = per_cpu(cluster_cpus, cpu);
        break;
    }
    if ( per_cpu(cluster_cpus, this_cpu) == cluster_cpus_spare )
        cluster_cpus_spare = NULL;

    cpumask_set_cpu(this_cpu, per_cpu(cluster_cpus, this_cpu));
}

static void cf_check send_IPI_self_x2apic(uint8_t vector)
{
    apic_wrmsr(APIC_SELF_IPI, vector);
}

static void cf_check send_IPI_mask_x2apic_phys(
    const cpumask_t *cpumask, int vector)
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

static void cf_check send_IPI_mask_x2apic_cluster(
    const cpumask_t *cpumask, int vector)
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

        BUG_ON(!(msr_content & 0xffff));
        msr_content = (msr_content << 32) | APIC_DM_FIXED |
                      APIC_DEST_LOGICAL | vector;
        apic_wrmsr(APIC_ICR, msr_content);
    }

    local_irq_restore(flags);
}

static const struct genapic __initconst_cf_clobber apic_x2apic_phys = {
    APIC_INIT("x2apic_phys", NULL),
    .int_delivery_mode = dest_Fixed,
    .int_dest_mode = 0 /* physical delivery */,
    .init_apic_ldr = init_apic_ldr_phys,
    .vector_allocation_cpumask = vector_allocation_cpumask_phys,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_phys,
    .send_IPI_mask = send_IPI_mask_x2apic_phys,
    .send_IPI_self = send_IPI_self_x2apic
};

/*
 * Mixed x2APIC mode: use physical for external (device) interrupts, and
 * cluster for inter processor interrupts.  Such mode has the benefits of not
 * sharing the vector space with all CPUs on the cluster, while still allowing
 * IPIs to be more efficiently delivered by not having to perform an ICR write
 * for each target CPU.
 */
static const struct genapic __initconst_cf_clobber apic_x2apic_mixed = {
    APIC_INIT("x2apic_mixed", NULL),

    /*
     * The following fields are exclusively used by external interrupts and
     * hence are set to use Physical destination mode handlers.
     */
    .int_delivery_mode = dest_Fixed,
    .int_dest_mode = 0 /* physical delivery */,
    .vector_allocation_cpumask = vector_allocation_cpumask_phys,
    .cpu_mask_to_apicid = cpu_mask_to_apicid_phys,

    /*
     * The following fields are exclusively used by IPIs and hence are set to
     * use Cluster Logical destination mode handlers.  Note that init_apic_ldr
     * is not used by IPIs, but the per-CPU fields it initializes are only used
     * by the IPI hooks.
     */
    .init_apic_ldr = init_apic_ldr_x2apic_cluster,
    .send_IPI_mask = send_IPI_mask_x2apic_cluster,
    .send_IPI_self = send_IPI_self_x2apic,
};

static int cf_check update_clusterinfo(
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
             !cond_alloc_cpumask_var(&per_cpu(scratch_mask, cpu)) )
            err = -ENOMEM;
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
    case CPU_REMOVE:
        if ( park_offline_cpus == (action != CPU_REMOVE) ||
             system_state == SYS_STATE_suspend )
            break;
        if ( per_cpu(cluster_cpus, cpu) )
        {
            cpumask_clear_cpu(cpu, per_cpu(cluster_cpus, cpu));
            if ( cpumask_empty(per_cpu(cluster_cpus, cpu)) )
                XFREE(per_cpu(cluster_cpus, cpu));
        }
        FREE_CPUMASK_VAR(per_cpu(scratch_mask, cpu));
        break;
    }

    return notifier_from_errno(err);
}

static struct notifier_block x2apic_cpu_nfb = {
   .notifier_call = update_clusterinfo
};

static int8_t __initdata x2apic_phys = -1;
boolean_param("x2apic_phys", x2apic_phys);

enum {
   unset, physical, mixed
} static __initdata x2apic_mode = unset;

static int __init cf_check parse_x2apic_mode(const char *s)
{
    if ( !cmdline_strcmp(s, "physical") )
        x2apic_mode = physical;
    else if ( !cmdline_strcmp(s, "mixed") )
        x2apic_mode = mixed;
    else
        return -EINVAL;

    return 0;
}
custom_param("x2apic-mode", parse_x2apic_mode);

const struct genapic *__init apic_x2apic_probe(void)
{
    /* Honour the legacy cmdline setting if it's the only one provided. */
    if ( x2apic_mode == unset && x2apic_phys >= 0 )
        x2apic_mode = x2apic_phys ? physical : mixed;

    if ( x2apic_mode == unset )
    {
        if ( acpi_gbl_FADT.flags & ACPI_FADT_APIC_PHYSICAL )
        {
            printk(XENLOG_INFO "ACPI FADT forcing x2APIC physical mode\n");
            x2apic_mode = physical;
        }
        else
            x2apic_mode = IS_ENABLED(CONFIG_X2APIC_MIXED) ? mixed
                          : (IS_ENABLED(CONFIG_X2APIC_PHYSICAL) ? physical
                                                                : mixed);
    }

    if ( x2apic_mode == physical )
        return &apic_x2apic_phys;

    if ( !this_cpu(cluster_cpus) )
    {
        update_clusterinfo(NULL, CPU_UP_PREPARE,
                           (void *)(long)smp_processor_id());
        init_apic_ldr_x2apic_cluster();
        register_cpu_notifier(&x2apic_cpu_nfb);
    }

    return &apic_x2apic_mixed;
}

void __init check_x2apic_preenabled(void)
{
    u32 lo, hi;

    if ( !cpu_has_x2apic )
        return;

    /* Check whether x2apic mode was already enabled by the BIOS. */
    rdmsr(MSR_APIC_BASE, lo, hi);
    if ( lo & APIC_BASE_EXTD )
    {
        printk("x2APIC mode is already enabled by BIOS.\n");
        x2apic_enabled = 1;
        genapic = *apic_x2apic_probe();
    }
}
