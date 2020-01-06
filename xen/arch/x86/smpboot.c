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

#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/serial.h>
#include <xen/numa.h>
#include <xen/cpu.h>
#include <asm/cpuidle.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/desc.h>
#include <asm/div64.h>
#include <asm/flushtlb.h>
#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/spec_ctrl.h>
#include <asm/time.h>
#include <asm/tboot.h>
#include <irq_vectors.h>
#include <mach_apic.h>

unsigned long __read_mostly trampoline_phys;

/* representing HT siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_sibling_mask);
/* representing HT and core siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, cpu_core_mask);

DEFINE_PER_CPU_READ_MOSTLY(cpumask_var_t, scratch_cpumask);
static cpumask_t scratch_cpu0mask;

cpumask_t cpu_online_map __read_mostly;
EXPORT_SYMBOL(cpu_online_map);

bool __read_mostly park_offline_cpus;

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
#define set_cpu_state(state) do { smp_mb(); cpu_state = (state); } while (0)

void *stack_base[NR_CPUS];

void initialize_cpu_data(unsigned int cpu)
{
    cpu_data[cpu] = boot_cpu_data;
}

static bool smp_store_cpu_info(unsigned int id)
{
    unsigned int socket;

    if ( system_state != SYS_STATE_resume )
        identify_cpu(&cpu_data[id]);
    else if ( !recheck_cpu_features(id) )
        return false;

    socket = cpu_to_socket(id);
    if ( !socket_cpumask[socket] )
    {
        socket_cpumask[socket] = secondary_socket_cpumask;
        secondary_socket_cpumask = NULL;
    }

    return true;
}

/*
 * TSC's upper 32 bits can't be written in earlier CPUs (before
 * Prescott), there is no way to resync one AP against BP.
 */
bool disable_tsc_sync;

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
        smp_wmb();
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
        smp_rmb();
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
    if ( !smp_store_cpu_info(cpu) )
    {
        printk("CPU%u: Failed to validate features - not coming back online\n",
               cpu);
        cpu_error = -ENXIO;
        goto halt;
    }

    if ( (rc = hvm_cpu_up()) != 0 )
    {
        printk("CPU%d: Failed to initialise HVM. Not coming online.\n", cpu);
        cpu_error = rc;
    halt:
        clear_local_APIC();
        spin_debug_enable();
        play_dead();
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

static void set_cpu_sibling_map(unsigned int cpu)
{
    unsigned int i;
    struct cpuinfo_x86 *c = cpu_data;

    cpumask_set_cpu(cpu, &cpu_sibling_setup_map);

    cpumask_set_cpu(cpu, socket_cpumask[cpu_to_socket(cpu)]);
    cpumask_set_cpu(cpu, per_cpu(cpu_core_mask, cpu));
    cpumask_set_cpu(cpu, per_cpu(cpu_sibling_mask, cpu));

    if ( c[cpu].x86_num_siblings > 1 )
    {
        for_each_cpu ( i, &cpu_sibling_setup_map )
        {
            if ( cpu == i || c[cpu].phys_proc_id != c[i].phys_proc_id )
                continue;
            if ( c[cpu].compute_unit_id != INVALID_CUID &&
                 c[i].compute_unit_id != INVALID_CUID )
            {
                if ( c[cpu].compute_unit_id == c[i].compute_unit_id )
                    link_thread_siblings(cpu, i);
            }
            else if ( c[cpu].cpu_core_id != XEN_INVALID_CORE_ID &&
                      c[i].cpu_core_id != XEN_INVALID_CORE_ID )
            {
                if ( c[cpu].cpu_core_id == c[i].cpu_core_id )
                    link_thread_siblings(cpu, i);
            }
            else
                printk(XENLOG_WARNING
                       "CPU%u: unclear relationship with CPU%u\n",
                       cpu, i);
        }
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
    init_shadow_spec_ctrl_state();

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

    get_cpu_info()->use_pv_cr3 = false;
    get_cpu_info()->xen_cr3 = 0;
    get_cpu_info()->pv_cr3 = 0;

    load_system_tables();

    /* Full exception support from here on in. */

    /* Safe to enable feature such as CR4.MCE with the IDT set up now. */
    write_cr4(mmu_cr4_features);

    percpu_traps_init();

    cpu_init();

    initialize_cpu_data(cpu);

    microcode_update_one(false);

    /*
     * If MSR_SPEC_CTRL is available, apply Xen's default setting and discard
     * any firmware settings.  Note: MSR_SPEC_CTRL may only become available
     * after loading microcode.
     */
    if ( boot_cpu_has(X86_FEATURE_IBRSB) )
        wrmsrl(MSR_SPEC_CTRL, default_xen_spec_ctrl);

    tsx_init(); /* Needs microcode.  May change HLE/RTM feature bits. */

    if ( xen_guest )
        hypervisor_ap_setup();

    smp_callin();

    set_cpu_sibling_map(cpu);

    init_percpu_time();

    setup_secondary_APIC_clock();

    /*
     * low-memory mappings have been cleared, flush them from
     * the local TLBs too.
     */
    flush_tlb_local();

    /* This must be done before setting cpu_online_map */
    spin_debug_enable();
    notify_cpu_starting(cpu);

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

    start_eip = bootsym_phys(trampoline_realmode_entry);

    /* start_eip needs be page aligned, and below the 1M boundary. */
    if ( start_eip & ~0xff000 )
        panic("AP trampoline %#lx not suitably positioned\n", start_eip);

    /* So we see what's up   */
    if ( opt_cpu_info )
        printk("Booting processor %d/%d eip %lx\n",
               cpu, apicid, start_eip);

    stack_start = stack_base[cpu];

    /* This grunge runs the startup process for the targeted processor. */

    set_cpu_state(CPU_STATE_INIT);

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
            smp_rmb();
            rc = cpu_error;
        }
        else
        {
            boot_error = 1;
            smp_mb();
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
    smp_mb();

    return rc;
}

#define STUB_BUF_CPU_OFFS(cpu) (((cpu) & (STUBS_PER_PAGE - 1)) * STUB_BUF_SIZE)

unsigned long alloc_stub_page(unsigned int cpu, unsigned long *mfn)
{
    unsigned long stub_va;
    struct page_info *pg;

    BUILD_BUG_ON(STUBS_PER_PAGE & (STUBS_PER_PAGE - 1));

    if ( *mfn )
        pg = mfn_to_page(_mfn(*mfn));
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
        *mfn = mfn_x(page_to_mfn(pg));

    return stub_va;
}

void cpu_exit_clear(unsigned int cpu)
{
    cpu_uninit(cpu);
    set_cpu_state(CPU_STATE_DEAD);
}

static int clone_mapping(const void *ptr, root_pgentry_t *rpt)
{
    unsigned long linear = (unsigned long)ptr, pfn;
    unsigned int flags;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    /*
     * Sanity check 'linear'.  We only allow cloning from the Xen virtual
     * range, and in particular, only from the directmap and .text ranges.
     */
    if ( root_table_offset(linear) > ROOT_PAGETABLE_LAST_XEN_SLOT ||
         root_table_offset(linear) < ROOT_PAGETABLE_FIRST_XEN_SLOT )
        return -EINVAL;

    if ( linear < XEN_VIRT_START ||
         (linear >= XEN_VIRT_END && linear < DIRECTMAP_VIRT_START) )
        return -EINVAL;

    pl3e = l4e_to_l3e(idle_pg_table[root_table_offset(linear)]) +
        l3_table_offset(linear);

    flags = l3e_get_flags(*pl3e);
    ASSERT(flags & _PAGE_PRESENT);
    if ( flags & _PAGE_PSE )
    {
        pfn = (l3e_get_pfn(*pl3e) & ~((1UL << (2 * PAGETABLE_ORDER)) - 1)) |
              (PFN_DOWN(linear) & ((1UL << (2 * PAGETABLE_ORDER)) - 1));
        flags &= ~_PAGE_PSE;
    }
    else
    {
        pl2e = l3e_to_l2e(*pl3e) + l2_table_offset(linear);
        flags = l2e_get_flags(*pl2e);
        ASSERT(flags & _PAGE_PRESENT);
        if ( flags & _PAGE_PSE )
        {
            pfn = (l2e_get_pfn(*pl2e) & ~((1UL << PAGETABLE_ORDER) - 1)) |
                  (PFN_DOWN(linear) & ((1UL << PAGETABLE_ORDER) - 1));
            flags &= ~_PAGE_PSE;
        }
        else
        {
            pl1e = l2e_to_l1e(*pl2e) + l1_table_offset(linear);
            flags = l1e_get_flags(*pl1e);
            if ( !(flags & _PAGE_PRESENT) )
                return 0;
            pfn = l1e_get_pfn(*pl1e);
        }
    }

    if ( !(root_get_flags(rpt[root_table_offset(linear)]) & _PAGE_PRESENT) )
    {
        pl3e = alloc_xen_pagetable();
        if ( !pl3e )
            return -ENOMEM;
        clear_page(pl3e);
        l4e_write(&rpt[root_table_offset(linear)],
                  l4e_from_paddr(__pa(pl3e), __PAGE_HYPERVISOR));
    }
    else
        pl3e = l4e_to_l3e(rpt[root_table_offset(linear)]);

    pl3e += l3_table_offset(linear);

    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
    {
        pl2e = alloc_xen_pagetable();
        if ( !pl2e )
            return -ENOMEM;
        clear_page(pl2e);
        l3e_write(pl3e, l3e_from_paddr(__pa(pl2e), __PAGE_HYPERVISOR));
    }
    else
    {
        ASSERT(!(l3e_get_flags(*pl3e) & _PAGE_PSE));
        pl2e = l3e_to_l2e(*pl3e);
    }

    pl2e += l2_table_offset(linear);

    if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
    {
        pl1e = alloc_xen_pagetable();
        if ( !pl1e )
            return -ENOMEM;
        clear_page(pl1e);
        l2e_write(pl2e, l2e_from_paddr(__pa(pl1e), __PAGE_HYPERVISOR));
    }
    else
    {
        ASSERT(!(l2e_get_flags(*pl2e) & _PAGE_PSE));
        pl1e = l2e_to_l1e(*pl2e);
    }

    pl1e += l1_table_offset(linear);
    flags &= ~_PAGE_GLOBAL;

    if ( l1e_get_flags(*pl1e) & _PAGE_PRESENT )
    {
        ASSERT(l1e_get_pfn(*pl1e) == pfn);
        ASSERT(l1e_get_flags(*pl1e) == flags);
    }
    else
        l1e_write(pl1e, l1e_from_pfn(pfn, flags));

    return 0;
}

DEFINE_PER_CPU(root_pgentry_t *, root_pgt);

static root_pgentry_t common_pgt;

extern const char _stextentry[], _etextentry[];

static int setup_cpu_root_pgt(unsigned int cpu)
{
    root_pgentry_t *rpt;
    unsigned int off;
    int rc;

    if ( !opt_xpti_hwdom && !opt_xpti_domu )
        return 0;

    rpt = alloc_xen_pagetable();
    if ( !rpt )
        return -ENOMEM;

    clear_page(rpt);
    per_cpu(root_pgt, cpu) = rpt;

    rpt[root_table_offset(RO_MPT_VIRT_START)] =
        idle_pg_table[root_table_offset(RO_MPT_VIRT_START)];
    /* SH_LINEAR_PT inserted together with guest mappings. */
    /* PERDOMAIN inserted during context switch. */

    /* One-time setup of common_pgt, which maps .text.entry and the stubs. */
    if ( unlikely(!root_get_intpte(common_pgt)) )
    {
        const char *ptr;

        for ( rc = 0, ptr = _stextentry;
              !rc && ptr < _etextentry; ptr += PAGE_SIZE )
            rc = clone_mapping(ptr, rpt);

        if ( rc )
            return rc;

        common_pgt = rpt[root_table_offset(XEN_VIRT_START)];
    }

    rpt[root_table_offset(XEN_VIRT_START)] = common_pgt;

    /* Install direct map page table entries for stack, IDT, and TSS. */
    for ( off = rc = 0; !rc && off < STACK_SIZE; off += PAGE_SIZE )
        if ( !memguard_is_stack_guard_page(off) )
            rc = clone_mapping(__va(__pa(stack_base[cpu])) + off, rpt);

    if ( !rc )
        rc = clone_mapping(idt_tables[cpu], rpt);
    if ( !rc )
    {
        struct tss_page *ptr = &per_cpu(tss_page, cpu);

        BUILD_BUG_ON(sizeof(*ptr) != PAGE_SIZE);

        rc = clone_mapping(&ptr->tss, rpt);
    }
    if ( !rc )
        rc = clone_mapping((void *)per_cpu(stubs.addr, cpu), rpt);

    return rc;
}

static void cleanup_cpu_root_pgt(unsigned int cpu)
{
    root_pgentry_t *rpt = per_cpu(root_pgt, cpu);
    unsigned int r;
    unsigned long stub_linear = per_cpu(stubs.addr, cpu);

    if ( !rpt )
        return;

    per_cpu(root_pgt, cpu) = NULL;

    for ( r = root_table_offset(DIRECTMAP_VIRT_START);
          r < root_table_offset(HYPERVISOR_VIRT_END); ++r )
    {
        l3_pgentry_t *l3t;
        unsigned int i3;

        if ( !(root_get_flags(rpt[r]) & _PAGE_PRESENT) )
            continue;

        l3t = l4e_to_l3e(rpt[r]);

        for ( i3 = 0; i3 < L3_PAGETABLE_ENTRIES; ++i3 )
        {
            l2_pgentry_t *l2t;
            unsigned int i2;

            if ( !(l3e_get_flags(l3t[i3]) & _PAGE_PRESENT) )
                continue;

            ASSERT(!(l3e_get_flags(l3t[i3]) & _PAGE_PSE));
            l2t = l3e_to_l2e(l3t[i3]);

            for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; ++i2 )
            {
                if ( !(l2e_get_flags(l2t[i2]) & _PAGE_PRESENT) )
                    continue;

                ASSERT(!(l2e_get_flags(l2t[i2]) & _PAGE_PSE));
                free_xen_pagetable(l2e_to_l1e(l2t[i2]));
            }

            free_xen_pagetable(l2t);
        }

        free_xen_pagetable(l3t);
    }

    free_xen_pagetable(rpt);

    /* Also zap the stub mapping for this CPU. */
    if ( stub_linear )
    {
        l3_pgentry_t *l3t = l4e_to_l3e(common_pgt);
        l2_pgentry_t *l2t = l3e_to_l2e(l3t[l3_table_offset(stub_linear)]);
        l1_pgentry_t *l1t = l2e_to_l1e(l2t[l2_table_offset(stub_linear)]);

        l1t[l1_table_offset(stub_linear)] = l1e_empty();
    }
}

/*
 * The 'remove' boolean controls whether a CPU is just getting offlined (and
 * parked), or outright removed / offlined without parking. Parked CPUs need
 * things like their stack, GDT, IDT, TSS, and per-CPU data still available.
 * A few other items, in particular CPU masks, are also retained, as it's
 * difficult to prove that they're entirely unreferenced from parked CPUs.
 */
static void cpu_smpboot_free(unsigned int cpu, bool remove)
{
    unsigned int socket = cpu_to_socket(cpu);
    struct cpuinfo_x86 *c = cpu_data;

    if ( cpumask_empty(socket_cpumask[socket]) )
    {
        xfree(socket_cpumask[socket]);
        socket_cpumask[socket] = NULL;
    }

    cpumask_clear_cpu(cpu, &cpu_sibling_setup_map);

    if ( remove )
    {
        c[cpu].phys_proc_id = XEN_INVALID_SOCKET_ID;
        c[cpu].cpu_core_id = XEN_INVALID_CORE_ID;
        c[cpu].compute_unit_id = INVALID_CUID;

        FREE_CPUMASK_VAR(per_cpu(cpu_sibling_mask, cpu));
        FREE_CPUMASK_VAR(per_cpu(cpu_core_mask, cpu));
        if ( per_cpu(scratch_cpumask, cpu) != &scratch_cpu0mask )
            FREE_CPUMASK_VAR(per_cpu(scratch_cpumask, cpu));
    }

    cleanup_cpu_root_pgt(cpu);

    if ( per_cpu(stubs.addr, cpu) )
    {
        mfn_t mfn = _mfn(per_cpu(stubs.mfn, cpu));
        unsigned char *stub_page = map_domain_page(mfn);
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

    FREE_XENHEAP_PAGE(per_cpu(compat_gdt, cpu));

    if ( remove )
    {
        FREE_XENHEAP_PAGE(per_cpu(gdt, cpu));
        FREE_XENHEAP_PAGE(idt_tables[cpu]);

        if ( stack_base[cpu] )
        {
            memguard_unguard_stack(stack_base[cpu]);
            FREE_XENHEAP_PAGES(stack_base[cpu], STACK_ORDER);
        }
    }
}

static int cpu_smpboot_alloc(unsigned int cpu)
{
    unsigned int i, memflags = 0;
    nodeid_t node = cpu_to_node(cpu);
    seg_desc_t *gdt;
    unsigned long stub_page;
    int rc = -ENOMEM;

    if ( node != NUMA_NO_NODE )
        memflags = MEMF_node(node);

    if ( stack_base[cpu] == NULL )
        stack_base[cpu] = alloc_xenheap_pages(STACK_ORDER, memflags);
    if ( stack_base[cpu] == NULL )
        goto out;
    memguard_guard_stack(stack_base[cpu]);

    gdt = per_cpu(gdt, cpu) ?: alloc_xenheap_pages(0, memflags);
    if ( gdt == NULL )
        goto out;
    per_cpu(gdt, cpu) = gdt;
    per_cpu(gdt_l1e, cpu) =
        l1e_from_pfn(virt_to_mfn(gdt), __PAGE_HYPERVISOR_RW);
    memcpy(gdt, boot_gdt, NR_RESERVED_GDT_PAGES * PAGE_SIZE);
    BUILD_BUG_ON(NR_CPUS > 0x10000);
    gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;

    per_cpu(compat_gdt, cpu) = gdt = alloc_xenheap_pages(0, memflags);
    if ( gdt == NULL )
        goto out;
    per_cpu(compat_gdt_l1e, cpu) =
        l1e_from_pfn(virt_to_mfn(gdt), __PAGE_HYPERVISOR_RW);
    memcpy(gdt, boot_compat_gdt, NR_RESERVED_GDT_PAGES * PAGE_SIZE);
    gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;

    if ( idt_tables[cpu] == NULL )
        idt_tables[cpu] = alloc_xenheap_pages(0, memflags);
    if ( idt_tables[cpu] == NULL )
        goto out;
    memcpy(idt_tables[cpu], idt_table, IDT_ENTRIES * sizeof(idt_entry_t));
    disable_each_ist(idt_tables[cpu]);

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
        goto out;
    per_cpu(stubs.addr, cpu) = stub_page + STUB_BUF_CPU_OFFS(cpu);

    rc = setup_cpu_root_pgt(cpu);
    if ( rc )
        goto out;
    rc = -ENOMEM;

    if ( secondary_socket_cpumask == NULL &&
         (secondary_socket_cpumask = xzalloc(cpumask_t)) == NULL )
        goto out;

    if ( !(cond_zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, cpu)) &&
           cond_zalloc_cpumask_var(&per_cpu(cpu_core_mask, cpu)) &&
           cond_alloc_cpumask_var(&per_cpu(scratch_cpumask, cpu))) )
        goto out;

    rc = 0;

 out:
    if ( rc )
        cpu_smpboot_free(cpu, true);

    return rc;
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
        cpu_smpboot_free(cpu, !park_offline_cpus);
        break;
    case CPU_REMOVE:
        cpu_smpboot_free(cpu, true);
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_smpboot_nfb = {
    .notifier_call = cpu_smpboot_callback
};

void __init smp_prepare_cpus(void)
{
    int rc;

    register_cpu_notifier(&cpu_smpboot_nfb);

    mtrr_aps_sync_begin();

    /* Setup boot CPU information */
    initialize_cpu_data(0); /* Final full version of the data */
    print_cpu_info(0);

    boot_cpu_physical_apicid = get_apic_id();
    x86_cpu_to_apicid[0] = boot_cpu_physical_apicid;

    stack_base[0] = stack_start;

    rc = setup_cpu_root_pgt(0);
    if ( rc )
        panic("Error %d setting up PV root page table\n", rc);
    if ( per_cpu(root_pgt, 0) )
    {
        get_cpu_info()->pv_cr3 = 0;

#ifdef CONFIG_PV
        /*
         * All entry points which may need to switch page tables have to start
         * with interrupts off. Re-write what pv_trap_init() has put there.
         */
        _set_gate(idt_table + LEGACY_SYSCALL_VECTOR, SYS_DESC_irq_gate, 3,
                  &int80_direct_trap);
#endif
    }

    set_nr_sockets();

    socket_cpumask = xzalloc_array(cpumask_t *, nr_sockets);
    if ( socket_cpumask == NULL ||
         (socket_cpumask[cpu_to_socket(0)] = xzalloc(cpumask_t)) == NULL )
        panic("No memory for socket CPU siblings map\n");

    if ( !zalloc_cpumask_var(&per_cpu(cpu_sibling_mask, 0)) ||
         !zalloc_cpumask_var(&per_cpu(cpu_core_mask, 0)) )
        panic("No memory for boot CPU sibling/core maps\n");

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
    if ( !cpu_has_apic )
    {
        printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        goto init_uniprocessor;
    }

    verify_local_APIC();

    connect_bsp_APIC();
    setup_local_APIC();

    if ( !skip_ioapic_setup && nr_ioapics )
        setup_IO_APIC();

    setup_boot_APIC_clock();
}

void __init smp_prepare_boot_cpu(void)
{
    unsigned int cpu = smp_processor_id();

    cpumask_set_cpu(cpu, &cpu_online_map);
    cpumask_set_cpu(cpu, &cpu_present_map);
#if NR_CPUS > 2 * BITS_PER_LONG
    per_cpu(scratch_cpumask, cpu) = &scratch_cpu0mask;
#endif

    get_cpu_info()->use_pv_cr3 = false;
    get_cpu_info()->xen_cr3 = 0;
    get_cpu_info()->pv_cr3 = 0;
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
            cpu = -ENOSPC;
            goto out;
        }
        if ( apic_id < MAX_LOCAL_APIC )
             apicid_to_node[apic_id] = node;
    }

    /* Physically added CPUs do not have synchronised TSC. */
    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
    {
        printk_once(
            XENLOG_WARNING
            "New CPU %u may have skewed TSC and break cross-CPU TSC coherency\n"
            "Consider using \"tsc=skewed\" to force emulation where appropriate\n",
            cpu);
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

    if ( (!x2apic_enabled && apicid >= APIC_ALL_CPUS) ||
         (!iommu_intremap && (apicid >> 8)) )
    {
        printk("Unsupported: APIC ID %#x in xAPIC mode w/o interrupt remapping\n",
               apicid);
        return -EINVAL;
    }

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
    {
        setup_apic_nmi_watchdog();
        check_nmi_watchdog();
    }

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
