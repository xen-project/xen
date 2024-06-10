/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/smpboot.c
 *
 * Dummy smpboot support
 *
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/acpi.h>
#include <xen/cpu.h>
#include <xen/cpumask.h>
#include <xen/delay.h>
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/param.h>
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
#include <asm/tee/tee.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

cpumask_t cpu_online_map;
cpumask_t cpu_present_map;
cpumask_t cpu_possible_map;

struct cpuinfo_arm cpu_data[NR_CPUS];

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus;
integer_param("maxcpus", max_cpus);

/* CPU logical map: map xen cpuid to an MPIDR */
register_t __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

/* Fake one node for now. See also xen/numa.h */
nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

/* Xen stack for bringing up the first CPU. */
static unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
       __attribute__((__aligned__(STACK_SIZE)));

/* Boot cpu data */
struct init_info init_data =
{
    .stack = cpu0_boot_stack,
};

/* Shared state for coordinating CPU bringup */
unsigned long __section(".data.idmap") smp_up_cpu = MPIDR_INVALID;
/* Shared state for coordinating CPU teardown */
static bool cpu_is_dead;

/* ID of the PCPU we're running on */
DEFINE_PER_CPU(unsigned int, cpu_id);
/*
 * Although multithread is part of the Arm spec, there are not many
 * processors supporting multithread and current Xen on Arm assumes there
 * is no multithread.
 */
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

static int setup_cpu_sibling_map(int cpu)
{
    if ( !zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, cpu)) ||
         !zalloc_cpumask_var(&per_cpu(cpu_core_mask, cpu)) )
        return -ENOMEM;

    /*
     * Currently we assume there is no multithread and NUMA, so
     * a CPU is a sibling with itself, and the all possible CPUs
     * are supposed to belong to the same socket (NUMA node).
     */
    cpumask_set_cpu(cpu, per_cpu(cpu_sibling_mask, cpu));
    cpumask_copy(per_cpu(cpu_core_mask, cpu), &cpu_possible_map);

    return 0;
}

static void remove_cpu_sibling_map(int cpu)
{
    free_cpumask_var(per_cpu(cpu_sibling_mask, cpu));
    free_cpumask_var(per_cpu(cpu_core_mask, cpu));
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

    mpidr = system_cpuinfo.mpidr.bits & MPIDR_HWID_MASK;

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

        addr = dt_read_paddr(prop, dt_n_addr_cells(cpu));

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

    if ( system_cpuinfo.mpidr.mt == 1 )
        warning_add("WARNING: MULTITHREADING HAS BEEN DETECTED ON THE PROCESSOR.\n"
                    "It might impact the security of the system.\n");
}

unsigned int __init smp_get_max_cpus(void)
{
    unsigned int i, cpus = 0;

    if ( ( !max_cpus ) || ( max_cpus > nr_cpu_ids ) )
        max_cpus = nr_cpu_ids;

    for ( i = 0; i < max_cpus; i++ )
        if ( cpu_possible(i) )
            cpus++;

    return cpus;
}

void __init
smp_prepare_cpus(void)
{
    int rc;

    cpumask_copy(&cpu_present_map, &cpu_possible_map);

    rc = setup_cpu_sibling_map(0);
    if ( rc )
        panic("Unable to allocate CPU sibling/core maps\n");

}

/* Boot the current CPU */
void asmlinkage start_secondary(void)
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
    if ( current_cpu_data.midr.bits != system_cpuinfo.midr.bits )
    {
        if ( !opt_hmp_unsafe )
        {
            printk(XENLOG_ERR
                   "CPU%u MIDR (0x%"PRIregister") does not match boot CPU MIDR (0x%"PRIregister"),\n"
                   XENLOG_ERR "disable cpu (see big.LITTLE.txt under docs/).\n",
                   smp_processor_id(), current_cpu_data.midr.bits,
                   system_cpuinfo.midr.bits);
            stop_cpu();
        }
        else
        {
            printk(XENLOG_ERR
                   "CPU%u MIDR (0x%"PRIregister") does not match boot CPU MIDR (0x%"PRIregister"),\n"
                   XENLOG_ERR "hmp-unsafe turned on so tainting Xen and keep core on!!\n",
                   smp_processor_id(), current_cpu_data.midr.bits,
                   system_cpuinfo.midr.bits);
            add_taint(TAINT_CPU_OUT_OF_SPEC);
         }
    }

    if ( dcache_line_bytes != read_dcache_line_bytes() )
    {
        printk(XENLOG_ERR "CPU%u dcache line size (%zu) does not match the boot CPU (%zu)\n",
               smp_processor_id(), read_dcache_line_bytes(),
               dcache_line_bytes);
        stop_cpu();
    }

    /*
     * system features must be updated only if we do not stop the core or
     * we might disable features due to a non used core (for example when
     * booting on big cores on a big.LITTLE system with hmp_unsafe)
     */
    update_system_features(&current_cpu_data);

    gic_init_secondary_cpu();

    set_current(idle_vcpu[cpuid]);

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

    /*
     * Calling request_irq() after local_irq_enable() on secondary cores
     * will make sure the assertion condition in alloc_xenheap_pages(),
     * i.e. !in_irq && local_irq_enabled() is satisfied.
     */
    init_maintenance_interrupt();
    init_timer_interrupt();
    init_tee_secondary();

    local_abort_enable();

    check_local_cpu_errata();
    check_local_cpu_features();

    printk(XENLOG_DEBUG "CPU %u booted.\n", smp_processor_id());

    startup_cpu_idle_loop();
}

/* Shut down the current CPU */
void __cpu_disable(void)
{
    unsigned int cpu = smp_processor_id();

    local_irq_disable();
    gic_disable_cpu();
    /* Allow any queued timer interrupts to get serviced */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    /* It's now safe to remove this processor from the online map */
    cpumask_clear_cpu(cpu, &cpu_online_map);

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
    call_psci_cpu_off();

    while ( 1 )
        wfi();
}

static void set_smp_up_cpu(unsigned long mpidr)
{
    /*
     * smp_up_cpu is part of the identity mapping which is read-only. So
     * We need to re-map the region so it can be updated.
     */
    void *ptr = map_domain_page(virt_to_mfn(&smp_up_cpu));

    ptr += PAGE_OFFSET(&smp_up_cpu);

    *(unsigned long *)ptr = mpidr;

    /*
     * smp_up_cpu will be accessed with the MMU off, so ensure the update
     * is visible by cleaning the cache.
     */
    clean_dcache_va_range(ptr, sizeof(unsigned long));

    unmap_domain_page(ptr);

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

    rc = prepare_secondary_mm(cpu);
    if ( rc < 0 )
        return rc;

    console_start_sync(); /* Secondary may use early_printk */

    /* Tell the remote CPU which stack to boot on. */
    init_data.stack = idle_vcpu[cpu]->arch.stack;

    /* Tell the remote CPU what its logical CPU ID is. */
    init_data.cpuid = cpu;

    /* Open the gate for this CPU */
    set_smp_up_cpu(cpu_logical_map(cpu));

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

    set_smp_up_cpu(MPIDR_INVALID);

    arch_cpu_up_finish();

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

static int cpu_smpboot_callback(struct notifier_block *nfb,
                                unsigned long action,
                                void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    unsigned int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = setup_cpu_sibling_map(cpu);
        if ( rc )
            printk(XENLOG_ERR
                   "Unable to allocate CPU sibling/core map  for CPU%u\n",
                   cpu);

        break;

    case CPU_DEAD:
        remove_cpu_sibling_map(cpu);
        break;
    default:
        break;
    }

    return notifier_from_errno(rc);
}

static struct notifier_block cpu_smpboot_nfb = {
    .notifier_call = cpu_smpboot_callback,
};

static int __init cpu_smpboot_notifier_init(void)
{
    register_cpu_notifier(&cpu_smpboot_nfb);

    return 0;
}
presmp_initcall(cpu_smpboot_notifier_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
