/*
 * x86 SMP booting functions
 *
 * This inherits a great deal from Linux's SMP boot code:
 *  (c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *  (c) 1998, 1999, 2000 Ingo Molnar <mingo@redhat.com>
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
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/serial.h>
#include <xen/numa.h>
#include <xen/cpu.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/desc.h>
#include <asm/div64.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/time.h>
#include <asm/tboot.h>
#include <mach_apic.h>
#include <mach_wakecpu.h>
#include <smpboot_hooks.h>

#define setup_trampoline()    (bootsym_phys(trampoline_realmode_entry))

unsigned long __read_mostly trampoline_phys;

/* representing HT siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_sibling_mask);
/* representing HT and core siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_core_mask);

cpumask_t cpu_online_map __read_mostly;
EXPORT_SYMBOL(cpu_online_map);

unsigned int __read_mostly nr_sockets;
cpumask_t **__read_mostly socket_cpumask;
static cpumask_t *secondary_socket_cpumask;

struct cpuinfo_x86 cpu_data[NR_CPUS];

u32 x86_cpu_to_apicid[NR_CPUS] __read_mostly =
	{ [0 ... NR_CPUS-1] = BAD_APICID };

static int cpu_error;
static enum cpu_state {
    CPU_STATE_DYING,    /* slave -> master: I am dying */
    CPU_STATE_DEAD,     /* slave -> master: I am completely dead */
    CPU_STATE_INIT,     /* master -> slave: Early bringup phase 1 */
    CPU_STATE_CALLOUT,  /* master -> slave: Early bringup phase 2 */
    CPU_STATE_CALLIN,   /* slave -> master: Completed phase 2 */
    CPU_STATE_ONLINE    /* master -> slave: Go fully online now. */
} cpu_state;
#define set_cpu_state(state) do { mb(); cpu_state = (state); } while (0)

void *stack_base[NR_CPUS];

static void smp_store_cpu_info(int id)
{
    struct cpuinfo_x86 *c = cpu_data + id;
    unsigned int socket;

    *c = boot_cpu_data;
    if ( id != 0 )
    {
        identify_cpu(c);

        socket = cpu_to_socket(id);
        if ( !socket_cpumask[socket] )
        {
            socket_cpumask[socket] = secondary_socket_cpumask;
            secondary_socket_cpumask = NULL;
        }
    }
}

/*
 * TSC's upper 32 bits can't be written in earlier CPUs (before
 * Prescott), there is no way to resync one AP against BP.
 */
bool_t disable_tsc_sync;

static atomic_t tsc_count;
static uint64_t tsc_value;
static cpumask_t tsc_sync_cpu_mask;

static void synchronize_tsc_master(unsigned int slave)
{
    unsigned int i;

    if ( disable_tsc_sync )
        return;

    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) &&
         !cpumask_test_cpu(slave, &tsc_sync_cpu_mask) )
        return;

    for ( i = 1; i <= 5; i++ )
    {
        tsc_value = rdtsc_ordered();
        wmb();
        atomic_inc(&tsc_count);
        while ( atomic_read(&tsc_count) != (i<<1) )
            cpu_relax();
    }

    atomic_set(&tsc_count, 0);
    cpumask_clear_cpu(slave, &tsc_sync_cpu_mask);
}

static void synchronize_tsc_slave(unsigned int slave)
{
    unsigned int i;

    if ( disable_tsc_sync )
        return;

    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) &&
         !cpumask_test_cpu(slave, &tsc_sync_cpu_mask) )
        return;

    for ( i = 1; i <= 5; i++ )
    {
        while ( atomic_read(&tsc_count) != ((i<<1)-1) )
            cpu_relax();
        rmb();
        /*
         * If a CPU has been physically hotplugged, we may as well write
         * to its TSC in spite of X86_FEATURE_TSC_RELIABLE. The platform does
         * not sync up a new CPU's TSC for us.
         */
        __write_tsc(tsc_value);
        atomic_inc(&tsc_count);
    }
}

static void smp_callin(void)
{
    unsigned int cpu = smp_processor_id();
    int i, rc;

    /* Wait 2s total for startup. */
    Dprintk("Waiting for CALLOUT.\n");
    for ( i = 0; cpu_state != CPU_STATE_CALLOUT; i++ )
    {
        BUG_ON(i >= 200);
        cpu_relax();
        mdelay(10);
    }

    /*
     * The boot CPU has finished the init stage and is spinning on cpu_state
     * update until we finish. We are free to set up this CPU: first the APIC.
     */
    Dprintk("CALLIN, before setup_local_APIC().\n");
    x2apic_ap_setup();
    setup_local_APIC();

    /* Save our processor parameters. */
    smp_store_cpu_info(cpu);

    if ( (rc = hvm_cpu_up()) != 0 )
    {
        printk("CPU%d: Failed to initialise HVM. Not coming online.\n", cpu);
        cpu_error = rc;
        clear_local_APIC();
        spin_debug_enable();
        cpu_exit_clear(cpu);
        (*dead_idle)();
    }

    /* Allow the master to continue. */
    set_cpu_state(CPU_STATE_CALLIN);

    synchronize_tsc_slave(cpu);

    /* And wait for our final Ack. */
    while ( cpu_state != CPU_STATE_ONLINE )
        cpu_relax();
}

static int booting_cpu;

/* CPUs for which sibling maps can be computed. */
static cpumask_t cpu_sibling_setup_map;

static void link_thread_siblings(int cpu1, int cpu2)
{
    cpumask_set_cpu(cpu1, per_cpu(cpu_sibling_mask, cpu2));
    cpumask_set_cpu(cpu2, per_cpu(cpu_sibling_mask, cpu1));
    cpumask_set_cpu(cpu1, per_cpu(cpu_core_mask, cpu2));
    cpumask_set_cpu(cpu2, per_cpu(cpu_core_mask, cpu1));
}

static void set_cpu_sibling_map(int cpu)
{
    int i;
    struct cpuinfo_x86 *c = cpu_data;

    cpumask_set_cpu(cpu, &cpu_sibling_setup_map);

    cpumask_set_cpu(cpu, socket_cpumask[cpu_to_socket(cpu)]);

    if ( c[cpu].x86_num_siblings > 1 )
    {
        for_each_cpu ( i, &cpu_sibling_setup_map )
        {
            if ( cpu_has(c, X86_FEATURE_TOPOEXT) ) {
                if ( (c[cpu].phys_proc_id == c[i].phys_proc_id) &&
                     (c[cpu].compute_unit_id == c[i].compute_unit_id) )
                    link_thread_siblings(cpu, i);
            } else if ( (c[cpu].phys_proc_id == c[i].phys_proc_id) &&
                        (c[cpu].cpu_core_id == c[i].cpu_core_id) ) {
                link_thread_siblings(cpu, i);
            }
        }
    }
    else
    {
        cpumask_set_cpu(cpu, per_cpu(cpu_sibling_mask, cpu));
    }

    if ( c[cpu].x86_max_cores == 1 )
    {
        cpumask_copy(per_cpu(cpu_core_mask, cpu),
                     per_cpu(cpu_sibling_mask, cpu));
        c[cpu].booted_cores = 1;
        return;
    }

    for_each_cpu ( i, &cpu_sibling_setup_map )
    {
        if ( c[cpu].phys_proc_id == c[i].phys_proc_id )
        {
            cpumask_set_cpu(i, per_cpu(cpu_core_mask, cpu));
            cpumask_set_cpu(cpu, per_cpu(cpu_core_mask, i));
            /*
             *  Does this new cpu bringup a new core?
             */
            if ( cpumask_weight(per_cpu(cpu_sibling_mask, cpu)) == 1 )
            {
                /*
                 * for each core in package, increment
                 * the booted_cores for this new cpu
                 */
                if ( cpumask_first(per_cpu(cpu_sibling_mask, i)) == i )
                    c[cpu].booted_cores++;
                /*
                 * increment the core count for all
                 * the other cpus in this package
                 */
                if ( i != cpu )
                    c[i].booted_cores++;
            }
            else if ( (i != cpu) && !c[cpu].booted_cores )
            {
                c[cpu].booted_cores = c[i].booted_cores;
            }
        }
    }
}

void start_secondary(void *unused)
{
    /*
     * Dont put anything before smp_callin(), SMP booting is so fragile that we
     * want to limit the things done here to the most necessary things.
     */
    unsigned int cpu = booting_cpu;

    /* Critical region without IDT or TSS.  Any fault is deadly! */

    set_processor_id(cpu);
    set_current(idle_vcpu[cpu]);
    this_cpu(curr_vcpu) = idle_vcpu[cpu];
    rdmsrl(MSR_EFER, this_cpu(efer));

    /*
     * Just as during early bootstrap, it is convenient here to disable
     * spinlock checking while we have IRQs disabled. This allows us to
     * acquire IRQ-unsafe locks when it would otherwise be disallowed.
     * 
     * It is safe because the race we are usually trying to avoid involves
     * a group of CPUs rendezvousing in an IPI handler, where one cannot
     * join because it is spinning with IRQs disabled waiting to acquire a
     * lock held by another in the rendezvous group (the lock must be an
     * IRQ-unsafe lock since the CPU took the IPI after acquiring it, and
     * hence had IRQs enabled). This is a deadlock scenario.
     * 
     * However, no CPU can be involved in rendezvous until it is online,
     * hence no such group can be waiting for this CPU until it is
     * visible in cpu_online_map. Hence such a deadlock is not possible.
     */
    spin_debug_disable();

    load_system_tables();

    /* Full exception support from here on in. */

    /* Safe to enable feature such as CR4.MCE with the IDT set up now. */
    write_cr4(mmu_cr4_features);

    percpu_traps_init();

    cpu_init();

    smp_callin();

    init_percpu_time();

    setup_secondary_APIC_clock();

    /*
     * low-memory mappings have been cleared, flush them from
     * the local TLBs too.
     */
    flush_tlb_local();

    /* This must be done before setting cpu_online_map */
    spin_debug_enable();
    set_cpu_sibling_map(cpu);
    notify_cpu_starting(cpu);
    wmb();

    /*
     * We need to hold vector_lock so there the set of online cpus
     * does not change while we are assigning vectors to cpus.  Holding
     * this lock ensures we don't half assign or remove an irq from a cpu.
     */
    lock_vector_lock();
    setup_vector_irq(cpu);
    cpumask_set_cpu(cpu, &cpu_online_map);
    unlock_vector_lock();

    /* We can take interrupts now: we're officially "up". */
    local_irq_enable();
    mtrr_ap_init();

    microcode_resume_cpu(cpu);

    wmb();
    startup_cpu_idle_loop();
}

extern void *stack_start;

static int wakeup_secondary_cpu(int phys_apicid, unsigned long start_eip)
{
    unsigned long send_status = 0, accept_status = 0;
    int maxlvt, timeout, i;

    /*
     * Be paranoid about clearing APIC errors.
     */
    if ( !APIC_INTEGRATED(apic_version[phys_apicid]) )
        return -ENODEV;

    apic_read_around(APIC_SPIV);
    apic_write(APIC_ESR, 0);
    apic_read(APIC_ESR);

    Dprintk("Asserting INIT.\n");

    /*
     * Turn INIT on target chip via IPI
     */
    apic_icr_write(APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT,
                   phys_apicid);

    if ( !x2apic_enabled )
    {
        Dprintk("Waiting for send to finish...\n");
        timeout = 0;
        do {
            Dprintk("+");
            udelay(100);
            send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
        } while ( send_status && (timeout++ < 1000) );

        mdelay(10);

        Dprintk("Deasserting INIT.\n");

        apic_icr_write(APIC_INT_LEVELTRIG | APIC_DM_INIT, phys_apicid);

        Dprintk("Waiting for send to finish...\n");
        timeout = 0;
        do {
            Dprintk("+");
            udelay(100);
            send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
        } while ( send_status && (timeout++ < 1000) );
    }
    else if ( tboot_in_measured_env() )
    {
        /*
         * With tboot AP is actually spinning in a mini-guest before 
         * receiving INIT. Upon receiving INIT ipi, AP need time to VMExit, 
         * update VMCS to tracking SIPIs and VMResume.
         *
         * While AP is in root mode handling the INIT the CPU will drop
         * any SIPIs
         */
        udelay(10);
    }

    maxlvt = get_maxlvt();

    for ( i = 0; i < 2; i++ )
    {
        Dprintk("Sending STARTUP #%d.\n", i+1);
        apic_read_around(APIC_SPIV);
        apic_write(APIC_ESR, 0);
        apic_read(APIC_ESR);
        Dprintk("After apic_write.\n");

        /*
         * STARTUP IPI
         * Boot on the stack
         */
        apic_icr_write(APIC_DM_STARTUP | (start_eip >> 12), phys_apicid);

        if ( !x2apic_enabled )
        {
            /* Give the other CPU some time to accept the IPI. */
            udelay(300);

            Dprintk("Startup point 1.\n");

            Dprintk("Waiting for send to finish...\n");
            timeout = 0;
            do {
                Dprintk("+");
                udelay(100);
                send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
            } while ( send_status && (timeout++ < 1000) );

            /* Give the other CPU some time to accept the IPI. */
            udelay(200);
        }

        /* Due to the Pentium erratum 3AP. */
        if ( maxlvt > 3 )
        {
            apic_read_around(APIC_SPIV);
            apic_write(APIC_ESR, 0);
        }
        accept_status = (apic_read(APIC_ESR) & 0xEF);
        if ( send_status || accept_status )
            break;
    }
    Dprintk("After Startup.\n");

    if ( send_status )
        printk("APIC never delivered???\n");
    if ( accept_status )
        printk("APIC delivery error (%lx).\n", accept_status);

    return (send_status | accept_status);
}

int alloc_cpu_id(void)
{
    cpumask_t tmp_map;
    int cpu;

    cpumask_complement(&tmp_map, &cpu_present_map);
    cpu = cpumask_first(&tmp_map);
    return (cpu < nr_cpu_ids) ? cpu : -ENODEV;
}

static int do_boot_cpu(int apicid, int cpu)
{
    int timeout, boot_error = 0, rc = 0;
    unsigned long start_eip;

    /*
     * Save current MTRR state in case it was changed since early boot
     * (e.g. by the ACPI SMI) to initialize new CPUs with MTRRs in sync:
     */
    mtrr_save_state();

    booting_cpu = cpu;

    /* start_eip had better be page-aligned! */
    start_eip = setup_trampoline();

    /* So we see what's up   */
    if ( opt_cpu_info )
        printk("Booting processor %d/%d eip %lx\n",
               cpu, apicid, start_eip);

    stack_start = stack_base[cpu];

    /* This grunge runs the startup process for the targeted processor. */

    set_cpu_state(CPU_STATE_INIT);

    Dprintk("Setting warm reset code and vector.\n");

    smpboot_setup_warm_reset_vector(start_eip);

    /* Starting actual IPI sequence... */
    if ( !tboot_in_measured_env() || tboot_wake_ap(apicid, start_eip) )
        boot_error = wakeup_secondary_cpu(apicid, start_eip);

    if ( !boot_error )
    {
        /* Allow AP to start initializing. */
        set_cpu_state(CPU_STATE_CALLOUT);
        Dprintk("After Callout %d.\n", cpu);

        /* Wait 5s total for a response. */
        for ( timeout = 0; timeout < 50000; timeout++ )
        {
            if ( cpu_state != CPU_STATE_CALLOUT )
                break;
            udelay(100);
        }

        if ( cpu_state == CPU_STATE_CALLIN )
        {
            /* number CPUs logically, starting from 1 (BSP is 0) */
            Dprintk("OK.\n");
            print_cpu_info(cpu);
            synchronize_tsc_master(cpu);
            Dprintk("CPU has booted.\n");
        }
        else if ( cpu_state == CPU_STATE_DEAD )
        {
            rmb();
            rc = cpu_error;
        }
        else
        {
            boot_error = 1;
            mb();
            if ( bootsym(trampoline_cpu_started) == 0xA5 )
                /* trampoline started but...? */
                printk("Stuck ??\n");
            else
                /* trampoline code not run */
                printk("Not responding.\n");
        }
    }

    if ( boot_error )
    {
        cpu_exit_clear(cpu);
        rc = -EIO;
    }

    /* mark "stuck" area as not stuck */
    bootsym(trampoline_cpu_started) = 0;
    mb();

    smpboot_restore_warm_reset_vector();

    return rc;
}

#define STUB_BUF_CPU_OFFS(cpu) (((cpu) & (STUBS_PER_PAGE - 1)) * STUB_BUF_SIZE)

unsigned long alloc_stub_page(unsigned int cpu, unsigned long *mfn)
{
    unsigned long stub_va;
    struct page_info *pg;

    BUILD_BUG_ON(STUBS_PER_PAGE & (STUBS_PER_PAGE - 1));

    if ( *mfn )
        pg = mfn_to_page(*mfn);
    else
    {
        nodeid_t node = cpu_to_node(cpu);
        unsigned int memflags = node != NUMA_NO_NODE ? MEMF_node(node) : 0;

        pg = alloc_domheap_page(NULL, memflags);
        if ( !pg )
            return 0;

        unmap_domain_page(memset(__map_domain_page(pg), 0xcc, PAGE_SIZE));
    }

    stub_va = XEN_VIRT_END - (cpu + 1) * PAGE_SIZE;
    if ( map_pages_to_xen(stub_va, page_to_mfn(pg), 1,
                          PAGE_HYPERVISOR_RX | MAP_SMALL_PAGES) )
    {
        if ( !*mfn )
            free_domheap_page(pg);
        stub_va = 0;
    }
    else if ( !*mfn )
        *mfn = page_to_mfn(pg);

    return stub_va;
}

void cpu_exit_clear(unsigned int cpu)
{
    cpu_uninit(cpu);
    set_cpu_state(CPU_STATE_DEAD);
}

static void cpu_smpboot_free(unsigned int cpu)
{
    unsigned int order, socket = cpu_to_socket(cpu);
    struct cpuinfo_x86 *c = cpu_data;

    if ( cpumask_empty(socket_cpumask[socket]) )
    {
        xfree(socket_cpumask[socket]);
        socket_cpumask[socket] = NULL;
    }

    c[cpu].phys_proc_id = XEN_INVALID_SOCKET_ID;
    c[cpu].cpu_core_id = XEN_INVALID_CORE_ID;
    c[cpu].compute_unit_id = INVALID_CUID;
    cpumask_clear_cpu(cpu, &cpu_sibling_setup_map);

    free_cpumask_var(per_cpu(cpu_sibling_mask, cpu));
    free_cpumask_var(per_cpu(cpu_core_mask, cpu));

    if ( per_cpu(stubs.addr, cpu) )
    {
        unsigned long mfn = per_cpu(stubs.mfn, cpu);
        unsigned char *stub_page = map_domain_page(_mfn(mfn));
        unsigned int i;

        memset(stub_page + STUB_BUF_CPU_OFFS(cpu), 0xcc, STUB_BUF_SIZE);
        for ( i = 0; i < STUBS_PER_PAGE; ++i )
            if ( stub_page[i * STUB_BUF_SIZE] != 0xcc )
                break;
        unmap_domain_page(stub_page);
        destroy_xen_mappings(per_cpu(stubs.addr, cpu) & PAGE_MASK,
                             (per_cpu(stubs.addr, cpu) | ~PAGE_MASK) + 1);
        if ( i == STUBS_PER_PAGE )
            free_domheap_page(mfn_to_page(mfn));
    }

    order = get_order_from_pages(NR_RESERVED_GDT_PAGES);
    free_xenheap_pages(per_cpu(gdt_table, cpu), order);

    free_xenheap_pages(per_cpu(compat_gdt_table, cpu), order);

    order = get_order_from_bytes(IDT_ENTRIES * sizeof(idt_entry_t));
    free_xenheap_pages(idt_tables[cpu], order);
    idt_tables[cpu] = NULL;

    if ( stack_base[cpu] != NULL )
    {
        memguard_unguard_stack(stack_base[cpu]);
        free_xenheap_pages(stack_base[cpu], STACK_ORDER);
        stack_base[cpu] = NULL;
    }
}

static int cpu_smpboot_alloc(unsigned int cpu)
{
    unsigned int i, order, memflags = 0;
    nodeid_t node = cpu_to_node(cpu);
    struct desc_struct *gdt;
    unsigned long stub_page;

    if ( node != NUMA_NO_NODE )
        memflags = MEMF_node(node);

    stack_base[cpu] = alloc_xenheap_pages(STACK_ORDER, memflags);
    if ( stack_base[cpu] == NULL )
        goto oom;
    memguard_guard_stack(stack_base[cpu]);

    order = get_order_from_pages(NR_RESERVED_GDT_PAGES);
    per_cpu(gdt_table, cpu) = gdt = alloc_xenheap_pages(order, memflags);
    if ( gdt == NULL )
        goto oom;
    memcpy(gdt, boot_cpu_gdt_table, NR_RESERVED_GDT_PAGES * PAGE_SIZE);
    BUILD_BUG_ON(NR_CPUS > 0x10000);
    gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;

    per_cpu(compat_gdt_table, cpu) = gdt = alloc_xenheap_pages(order, memflags);
    if ( gdt == NULL )
        goto oom;
    memcpy(gdt, boot_cpu_compat_gdt_table, NR_RESERVED_GDT_PAGES * PAGE_SIZE);
    gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;

    order = get_order_from_bytes(IDT_ENTRIES * sizeof(idt_entry_t));
    idt_tables[cpu] = alloc_xenheap_pages(order, memflags);
    if ( idt_tables[cpu] == NULL )
        goto oom;
    memcpy(idt_tables[cpu], idt_table, IDT_ENTRIES * sizeof(idt_entry_t));

    for ( stub_page = 0, i = cpu & ~(STUBS_PER_PAGE - 1);
          i < nr_cpu_ids && i <= (cpu | (STUBS_PER_PAGE - 1)); ++i )
        if ( cpu_online(i) && cpu_to_node(i) == node )
        {
            per_cpu(stubs.mfn, cpu) = per_cpu(stubs.mfn, i);
            break;
        }
    BUG_ON(i == cpu);
    stub_page = alloc_stub_page(cpu, &per_cpu(stubs.mfn, cpu));
    if ( !stub_page )
        goto oom;
    per_cpu(stubs.addr, cpu) = stub_page + STUB_BUF_CPU_OFFS(cpu);

    if ( secondary_socket_cpumask == NULL &&
         (secondary_socket_cpumask = xzalloc(cpumask_t)) == NULL )
        goto oom;

    if ( zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, cpu)) &&
         zalloc_cpumask_var(&per_cpu(cpu_core_mask, cpu)) )
        return 0;

 oom:
    cpu_smpboot_free(cpu);
    return -ENOMEM;
}

static int cpu_smpboot_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = cpu_smpboot_alloc(cpu);
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        cpu_smpboot_free(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_smpboot_nfb = {
    .notifier_call = cpu_smpboot_callback
};

void __init smp_prepare_cpus(unsigned int max_cpus)
{
    register_cpu_notifier(&cpu_smpboot_nfb);

    mtrr_aps_sync_begin();

    /* Setup boot CPU information */
    smp_store_cpu_info(0); /* Final full version of the data */
    print_cpu_info(0);

    boot_cpu_physical_apicid = get_apic_id();
    x86_cpu_to_apicid[0] = boot_cpu_physical_apicid;

    stack_base[0] = stack_start;

    set_nr_sockets();

    socket_cpumask = xzalloc_array(cpumask_t *, nr_sockets);
    if ( socket_cpumask == NULL ||
         (socket_cpumask[cpu_to_socket(0)] = xzalloc(cpumask_t)) == NULL )
        panic("No memory for socket CPU siblings map");

    if ( !zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, 0)) ||
         !zalloc_cpumask_var(&per_cpu(cpu_core_mask, 0)) )
        panic("No memory for boot CPU sibling/core maps");

    set_cpu_sibling_map(0);

    /*
     * If we couldn't find an SMP configuration at boot time,
     * get out of here now!
     */
    if ( !smp_found_config && !acpi_lapic )
    {
        printk(KERN_NOTICE "SMP motherboard not detected.\n");
    init_uniprocessor:
        physids_clear(phys_cpu_present_map);
        physid_set(0, phys_cpu_present_map);
        if (APIC_init_uniprocessor())
            printk(KERN_NOTICE "Local APIC not detected."
                   " Using dummy APIC emulation.\n");
        return;
    }

    /*
     * Should not be necessary because the MP table should list the boot
     * CPU too, but we do it for the sake of robustness anyway.
     * Makes no sense to do this check in clustered apic mode, so skip it
     */
    if ( !check_apicid_present(boot_cpu_physical_apicid) )
    {
        printk("weird, boot CPU (#%d) not listed by the BIOS.\n",
               boot_cpu_physical_apicid);
        physid_set(get_apic_id(), phys_cpu_present_map);
    }

    /* If we couldn't find a local APIC, then get out of here now! */
    if ( !APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid])
         || !cpu_has_apic )
    {
        printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        goto init_uniprocessor;
    }

    verify_local_APIC();

    connect_bsp_APIC();
    setup_local_APIC();

    smpboot_setup_io_apic();

    setup_boot_APIC_clock();
}

void __init smp_prepare_boot_cpu(void)
{
    cpumask_set_cpu(smp_processor_id(), &cpu_online_map);
    cpumask_set_cpu(smp_processor_id(), &cpu_present_map);
}

static void
remove_siblinginfo(int cpu)
{
    int sibling;

    cpumask_clear_cpu(cpu, socket_cpumask[cpu_to_socket(cpu)]);

    for_each_cpu ( sibling, per_cpu(cpu_core_mask, cpu) )
    {
        cpumask_clear_cpu(cpu, per_cpu(cpu_core_mask, sibling));
        /* Last thread sibling in this cpu core going down. */
        if ( cpumask_weight(per_cpu(cpu_sibling_mask, cpu)) == 1 )
            cpu_data[sibling].booted_cores--;
    }
   
    for_each_cpu(sibling, per_cpu(cpu_sibling_mask, cpu))
        cpumask_clear_cpu(cpu, per_cpu(cpu_sibling_mask, sibling));
    cpumask_clear(per_cpu(cpu_sibling_mask, cpu));
    cpumask_clear(per_cpu(cpu_core_mask, cpu));
}

void __cpu_disable(void)
{
    int cpu = smp_processor_id();

    set_cpu_state(CPU_STATE_DYING);

    local_irq_disable();
    clear_local_APIC();
    /* Allow any queued timer interrupts to get serviced */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    time_suspend();

    remove_siblinginfo(cpu);

    /* It's now safe to remove this processor from the online map */
    cpumask_clear_cpu(cpu, &cpu_online_map);
    fixup_irqs(&cpu_online_map, 1);
    fixup_eoi();

    if ( cpu_disable_scheduler(cpu) )
        BUG();
}

void __cpu_die(unsigned int cpu)
{
    /* We don't do anything here: idle task is faking death itself. */
    unsigned int i = 0;
    enum cpu_state seen_state;

    while ( (seen_state = cpu_state) != CPU_STATE_DEAD )
    {
        BUG_ON(seen_state != CPU_STATE_DYING);
        mdelay(100);
        cpu_relax();
        process_pending_softirqs();
        if ( (++i % 10) == 0 )
            printk(KERN_ERR "CPU %u still not dead...\n", cpu);
    }
}

int cpu_add(uint32_t apic_id, uint32_t acpi_id, uint32_t pxm)
{
    int cpu = -1;

    dprintk(XENLOG_DEBUG, "cpu_add apic_id %x acpi_id %x pxm %x\n",
            apic_id, acpi_id, pxm);

    if ( (acpi_id >= MAX_MADT_ENTRIES) ||
         (apic_id >= MAX_APICS) ||
         (pxm >= 256) )
        return -EINVAL;

    if ( !cpu_hotplug_begin() )
        return -EBUSY;

    /* Detect if the cpu has been added before */
    if ( x86_acpiid_to_apicid[acpi_id] != BAD_APICID )
    {
        cpu = (x86_acpiid_to_apicid[acpi_id] != apic_id)
            ? -EINVAL : -EEXIST;
        goto out;
    }

    if ( physid_isset(apic_id, phys_cpu_present_map) )
    {
        cpu = -EEXIST;
        goto out;
    }

    if ( (cpu = mp_register_lapic(apic_id, 1, 1)) < 0 )
        goto out;

    x86_acpiid_to_apicid[acpi_id] = apic_id;

    if ( !srat_disabled() )
    {
        nodeid_t node = setup_node(pxm);

        if ( node == NUMA_NO_NODE )
        {
            dprintk(XENLOG_WARNING,
                    "Setup node failed for pxm %x\n", pxm);
            x86_acpiid_to_apicid[acpi_id] = BAD_APICID;
            mp_unregister_lapic(apic_id, cpu);
            cpu = node;
            goto out;
        }
        if ( apic_id < MAX_LOCAL_APIC )
             apicid_to_node[apic_id] = node;
    }

    /* Physically added CPUs do not have synchronised TSC. */
    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
    {
        static bool_t once_only;
        if ( !test_and_set_bool(once_only) )
            printk(XENLOG_WARNING
                   " ** New physical CPU %u may have skewed TSC and hence "
                   "break assumed cross-CPU TSC coherency.\n"
                   " ** Consider using boot parameter \"tsc=skewed\" "
                   "which forces TSC emulation where appropriate.\n", cpu);
        cpumask_set_cpu(cpu, &tsc_sync_cpu_mask);
    }

    srat_detect_node(cpu);
    numa_add_cpu(cpu);
    dprintk(XENLOG_INFO, "Add CPU %x with index %x\n", apic_id, cpu);
 out:
    cpu_hotplug_done();
    return cpu;
}


int __cpu_up(unsigned int cpu)
{
    int apicid, ret;

    if ( (apicid = x86_cpu_to_apicid[cpu]) == BAD_APICID )
        return -ENODEV;

    if ( (ret = do_boot_cpu(apicid, cpu)) != 0 )
        return ret;

    time_latch_stamps();

    set_cpu_state(CPU_STATE_ONLINE);
    while ( !cpu_online(cpu) )
    {
        cpu_relax();
        process_pending_softirqs();
    }

    return 0;
}


void __init smp_cpus_done(void)
{
    if ( nmi_watchdog == NMI_LOCAL_APIC )
        check_nmi_watchdog();

    setup_ioapic_dest();

    mtrr_save_state();
    mtrr_aps_sync_end();
}

void __init smp_intr_init(void)
{
    int irq, vector, seridx, cpu = smp_processor_id();

    /*
     * IRQ0 must be given a fixed assignment and initialized,
     * because it's used before the IO-APIC is set up.
     */
    irq_to_desc(0)->arch.vector = IRQ0_VECTOR;

    /*
     * Also ensure serial interrupts are high priority. We do not
     * want them to be blocked by unacknowledged guest-bound interrupts.
     */
    for ( seridx = 0; seridx <= SERHND_IDX; seridx++ )
    {
        if ( (irq = serial_irq(seridx)) < 0 )
            continue;
        vector = alloc_hipriority_vector();
        per_cpu(vector_irq, cpu)[vector] = irq;
        irq_to_desc(irq)->arch.vector = vector;
        cpumask_copy(irq_to_desc(irq)->arch.cpu_mask, &cpu_online_map);
    }

    /* Direct IPI vectors. */
    set_direct_apic_vector(IRQ_MOVE_CLEANUP_VECTOR, irq_move_cleanup_interrupt);
    set_direct_apic_vector(EVENT_CHECK_VECTOR, event_check_interrupt);
    set_direct_apic_vector(INVALIDATE_TLB_VECTOR, invalidate_interrupt);
    set_direct_apic_vector(CALL_FUNCTION_VECTOR, call_function_interrupt);
}
