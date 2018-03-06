/*
 * xen/arch/arm/smpboot.c
 *
 * Dummy smpboot support
 *
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/delay.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/timer.h>
#include <xen/warning.h>
#include <xen/irq.h>
#include <xen/console.h>
#include <asm/cpuerrata.h>
#include <asm/gic.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/acpi.h>

cpumask_t cpu_online_map;
cpumask_t cpu_present_map;
cpumask_t cpu_possible_map;

struct cpuinfo_arm cpu_data[NR_CPUS];

/* CPU logical map: map xen cpuid to an MPIDR */
register_t __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

/* Fake one node for now. See also include/asm-arm/numa.h */
nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

/* Xen stack for bringing up the first CPU. */
static unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
       __attribute__((__aligned__(STACK_SIZE)));

/* Initial boot cpu data */
struct init_info __initdata init_data =
{
    .stack = cpu0_boot_stack,
};

/* Shared state for coordinating CPU bringup */
unsigned long smp_up_cpu = MPIDR_INVALID;
/* Shared state for coordinating CPU teardown */
static bool cpu_is_dead;

/* ID of the PCPU we're running on */
DEFINE_PER_CPU(unsigned int, cpu_id);
/* XXX these seem awfully x86ish... */
/* representing HT siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_sibling_mask);
/* representing HT and core siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_core_mask);

/*
 * By default non-boot CPUs not identical to the boot CPU will be
 * parked.
 */
static bool __read_mostly opt_hmp_unsafe = false;
boolean_param("hmp-unsafe", opt_hmp_unsafe);

static void setup_cpu_sibling_map(int cpu)
{
    if ( !zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, cpu)) ||
         !zalloc_cpumask_var(&per_cpu(cpu_core_mask, cpu)) )
        panic("No memory for CPU sibling/core maps");

    /* A CPU is a sibling with itself and is always on its own core. */
    cpumask_set_cpu(cpu, per_cpu(cpu_sibling_mask, cpu));
    cpumask_set_cpu(cpu, per_cpu(cpu_core_mask, cpu));
}

void __init
smp_clear_cpu_maps (void)
{
    cpumask_clear(&cpu_possible_map);
    cpumask_clear(&cpu_online_map);
    cpumask_set_cpu(0, &cpu_online_map);
    cpumask_set_cpu(0, &cpu_possible_map);
    cpu_logical_map(0) = READ_SYSREG(MPIDR_EL1) & MPIDR_HWID_MASK;
}

/* Parse the device tree and build the logical map array containing
 * MPIDR values related to logical cpus
 * Code base on Linux arch/arm/kernel/devtree.c
 */
static void __init dt_smp_init_cpus(void)
{
    register_t mpidr;
    struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    struct dt_device_node *cpu;
    unsigned int i, j;
    unsigned int cpuidx = 1;
    static register_t tmp_map[NR_CPUS] __initdata =
    {
        [0 ... NR_CPUS - 1] = MPIDR_INVALID
    };
    bool bootcpu_valid = false;
    int rc;

    mpidr = boot_cpu_data.mpidr.bits & MPIDR_HWID_MASK;

    if ( !cpus )
    {
        printk(XENLOG_WARNING "WARNING: Can't find /cpus in the device tree.\n"
               "Using only 1 CPU\n");
        return;
    }

    dt_for_each_child_node( cpus, cpu )
    {
        const __be32 *prop;
        u64 addr;
        u32 reg_len;
        register_t hwid;

        if ( !dt_device_type_is_equal(cpu, "cpu") )
            continue;

        if ( dt_n_size_cells(cpu) != 0 )
            printk(XENLOG_WARNING "cpu node `%s`: #size-cells %d\n",
                   dt_node_full_name(cpu), dt_n_size_cells(cpu));

        prop = dt_get_property(cpu, "reg", &reg_len);
        if ( !prop )
        {
            printk(XENLOG_WARNING "cpu node `%s`: has no reg property\n",
                   dt_node_full_name(cpu));
            continue;
        }

        if ( reg_len < dt_cells_to_size(dt_n_addr_cells(cpu)) )
        {
            printk(XENLOG_WARNING "cpu node `%s`: reg property too short\n",
                   dt_node_full_name(cpu));
            continue;
        }

        addr = dt_read_number(prop, dt_n_addr_cells(cpu));

        hwid = addr;
        if ( hwid != addr )
        {
            printk(XENLOG_WARNING "cpu node `%s`: hwid overflow %"PRIx64"\n",
                   dt_node_full_name(cpu), addr);
            continue;
        }

        /*
         * 8 MSBs must be set to 0 in the DT since the reg property
         * defines the MPIDR[23:0]
         */
        if ( hwid & ~MPIDR_HWID_MASK )
        {
            printk(XENLOG_WARNING "cpu node `%s`: invalid hwid value (0x%"PRIregister")\n",
                   dt_node_full_name(cpu), hwid);
            continue;
        }

        /*
         * Duplicate MPIDRs are a recipe for disaster. Scan all initialized
         * entries and check for duplicates. If any found just skip the node.
         * temp values values are initialized to MPIDR_INVALID to avoid
         * matching valid MPIDR[23:0] values.
         */
        for ( j = 0; j < cpuidx; j++ )
        {
            if ( tmp_map[j] == hwid )
            {
                printk(XENLOG_WARNING
                       "cpu node `%s`: duplicate /cpu reg properties %"PRIregister" in the DT\n",
                       dt_node_full_name(cpu), hwid);
                break;
            }
        }
        if ( j != cpuidx )
            continue;

        /*
         * Build a stashed array of MPIDR values. Numbering scheme requires
         * that if detected the boot CPU must be assigned logical id 0. Other
         * CPUs get sequential indexes starting from 1. If a CPU node
         * with a reg property matching the boot CPU MPIDR is detected,
         * this is recorded and so that the logical map build from DT is
         * validated and can be used to set the map.
         */
        if ( hwid == mpidr )
        {
            i = 0;
            bootcpu_valid = true;
        }
        else
            i = cpuidx++;

        if ( cpuidx > NR_CPUS )
        {
            printk(XENLOG_WARNING
                   "DT /cpu %u node greater than max cores %u, capping them\n",
                   cpuidx, NR_CPUS);
            cpuidx = NR_CPUS;
            break;
        }

        if ( (rc = arch_cpu_init(i, cpu)) < 0 )
        {
            printk("cpu%d init failed (hwid %"PRIregister"): %d\n", i, hwid, rc);
            tmp_map[i] = MPIDR_INVALID;
        }
        else
            tmp_map[i] = hwid;
    }

    if ( !bootcpu_valid )
    {
        printk(XENLOG_WARNING "DT missing boot CPU MPIDR[23:0]\n"
               "Using only 1 CPU\n");
        return;
    }

    for ( i = 0; i < cpuidx; i++ )
    {
        if ( tmp_map[i] == MPIDR_INVALID )
            continue;
        cpumask_set_cpu(i, &cpu_possible_map);
        cpu_logical_map(i) = tmp_map[i];
    }
}

void __init smp_init_cpus(void)
{
    int rc;

    /* initialize PSCI and set a global variable */
    psci_init();

    if ( (rc = arch_smp_init()) < 0 )
    {
        printk(XENLOG_WARNING "SMP init failed (%d)\n"
               "Using only 1 CPU\n", rc);
        return;
    }

    if ( acpi_disabled )
        dt_smp_init_cpus();
    else
        acpi_smp_init_cpus();

    if ( opt_hmp_unsafe )
        warning_add("WARNING: HMP COMPUTING HAS BEEN ENABLED.\n"
                    "It has implications on the security and stability of the system,\n"
                    "unless the cpu affinity of all domains is specified.\n");
}

int __init
smp_get_max_cpus (void)
{
    int i, max_cpus = 0;

    for ( i = 0; i < nr_cpu_ids; i++ )
        if ( cpu_possible(i) )
            max_cpus++;

    return max_cpus;
}

void __init
smp_prepare_cpus (unsigned int max_cpus)
{
    cpumask_copy(&cpu_present_map, &cpu_possible_map);

    setup_cpu_sibling_map(0);
}

/* Boot the current CPU */
void start_secondary(unsigned long boot_phys_offset,
                     unsigned long fdt_paddr,
                     unsigned long hwid)
{
    unsigned int cpuid = init_data.cpuid;

    memset(get_cpu_info(), 0, sizeof (struct cpu_info));

    set_processor_id(cpuid);

    identify_cpu(&current_cpu_data);
    processor_setup();

    init_traps();

    /*
     * Currently Xen assumes the platform has only one kind of CPUs.
     * This assumption does not hold on big.LITTLE platform and may
     * result to instability and insecure platform (unless cpu affinity
     * is manually specified for all domains). Better to park them for
     * now.
     */
    if ( !opt_hmp_unsafe &&
         current_cpu_data.midr.bits != boot_cpu_data.midr.bits )
    {
        printk(XENLOG_ERR "CPU%u MIDR (0x%x) does not match boot CPU MIDR (0x%x),\n"
               "disable cpu (see big.LITTLE.txt under docs/).\n",
               smp_processor_id(), current_cpu_data.midr.bits,
               boot_cpu_data.midr.bits);
        stop_cpu();
    }

    if ( dcache_line_bytes != read_dcache_line_bytes() )
    {
        printk(XENLOG_ERR "CPU%u dcache line size (%zu) does not match the boot CPU (%zu)\n",
               smp_processor_id(), read_dcache_line_bytes(),
               dcache_line_bytes);
        stop_cpu();
    }

    mmu_init_secondary_cpu();

    gic_init_secondary_cpu();

    init_secondary_IRQ();

    init_maintenance_interrupt();
    init_timer_interrupt();

    set_current(idle_vcpu[cpuid]);

    setup_cpu_sibling_map(cpuid);

    /* Run local notifiers */
    notify_cpu_starting(cpuid);
    /*
     * Ensure that previous writes are visible before marking the cpu as
     * online.
     */
    smp_wmb();

    /* Now report this CPU is up */
    cpumask_set_cpu(cpuid, &cpu_online_map);

    local_irq_enable();
    local_abort_enable();

    check_local_cpu_errata();

    printk(XENLOG_DEBUG "CPU %u booted.\n", smp_processor_id());

    startup_cpu_idle_loop();
}

/* Shut down the current CPU */
void __cpu_disable(void)
{
    unsigned int cpu = get_processor_id();

    local_irq_disable();
    gic_disable_cpu();
    /* Allow any queued timer interrupts to get serviced */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    /* It's now safe to remove this processor from the online map */
    cpumask_clear_cpu(cpu, &cpu_online_map);

    if ( cpu_disable_scheduler(cpu) )
        BUG();
    smp_mb();

    /* Return to caller; eventually the IPI mechanism will unwind and the 
     * scheduler will drop to the idle loop, which will call stop_cpu(). */
}

void stop_cpu(void)
{
    local_irq_disable();
    cpu_is_dead = true;
    /* Make sure the write happens before we sleep forever */
    dsb(sy);
    isb();
    while ( 1 )
        wfi();
}

int __init cpu_up_send_sgi(int cpu)
{
    /* We don't know the GIC ID of the CPU until it has woken up, so just
     * signal everyone and rely on our own smp_up_cpu gate to ensure only
     * the one we want gets through. */
    send_SGI_allbutself(GIC_SGI_EVENT_CHECK);

    return 0;
}

/* Bring up a remote CPU */
int __cpu_up(unsigned int cpu)
{
    int rc;
    s_time_t deadline;

    printk("Bringing up CPU%d\n", cpu);

    rc = init_secondary_pagetables(cpu);
    if ( rc < 0 )
        return rc;

    console_start_sync(); /* Secondary may use early_printk */

    /* Tell the remote CPU which stack to boot on. */
    init_data.stack = idle_vcpu[cpu]->arch.stack;

    /* Tell the remote CPU what its logical CPU ID is. */
    init_data.cpuid = cpu;

    /* Open the gate for this CPU */
    smp_up_cpu = cpu_logical_map(cpu);
    clean_dcache(smp_up_cpu);

    rc = arch_cpu_up(cpu);

    console_end_sync();

    if ( rc < 0 )
    {
        printk("Failed to bring up CPU%d\n", cpu);
        return rc;
    }

    deadline = NOW() + MILLISECS(1000);

    while ( !cpu_online(cpu) && NOW() < deadline )
    {
        cpu_relax();
        process_pending_softirqs();
    }
    /*
     * Ensure that other cpus' initializations are visible before
     * proceeding. Corresponds to smp_wmb() in start_secondary.
     */
    smp_rmb();

    /*
     * Nuke start of day info before checking one last time if the CPU
     * actually came online. If it is not online it may still be
     * trying to come up and may show up later unexpectedly.
     *
     * This doesn't completely avoid the possibility of the supposedly
     * failed CPU trying to progress with another CPUs stack settings
     * etc, but better than nothing, hopefully.
     */
    init_data.stack = NULL;
    init_data.cpuid = ~0;
    smp_up_cpu = MPIDR_INVALID;
    clean_dcache(smp_up_cpu);

    if ( !cpu_online(cpu) )
    {
        printk("CPU%d never came online\n", cpu);
        return -EIO;
    }

    return 0;
}

/* Wait for a remote CPU to die */
void __cpu_die(unsigned int cpu)
{
    unsigned int i = 0;

    while ( !cpu_is_dead )
    {
        mdelay(100);
        cpu_relax();
        process_pending_softirqs();
        if ( (++i % 10) == 0 )
            printk(KERN_ERR "CPU %u still not dead...\n", cpu);
        smp_mb();
    }
    cpu_is_dead = false;
    smp_mb();
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
