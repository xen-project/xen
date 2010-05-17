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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/domain.h>
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
#include <mach_apic.h>
#include <mach_wakecpu.h>
#include <smpboot_hooks.h>
#include <acpi/cpufreq/processor_perf.h>

#define setup_trampoline()    (bootsym_phys(trampoline_realmode_entry))

/* Set if we find a B stepping CPU */
static int smp_b_stepping;

/* Package ID of each logical CPU */
int phys_proc_id[NR_CPUS] __read_mostly = {[0 ... NR_CPUS-1] = BAD_APICID};

/* Core ID of each logical CPU */
int cpu_core_id[NR_CPUS] __read_mostly = {[0 ... NR_CPUS-1] = BAD_APICID};

/* representing HT siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_t, cpu_sibling_map);
/* representing HT and core siblings of each logical CPU */
DEFINE_PER_CPU_READ_MOSTLY(cpumask_t, cpu_core_map);

cpumask_t cpu_online_map __read_mostly;
EXPORT_SYMBOL(cpu_online_map);

cpumask_t cpu_callin_map;
cpumask_t cpu_callout_map;
cpumask_t cpu_possible_map = CPU_MASK_ALL;
static cpumask_t smp_commenced_mask;

struct cpuinfo_x86 cpu_data[NR_CPUS];

u32 x86_cpu_to_apicid[NR_CPUS] __read_mostly = { [0 ... NR_CPUS-1] = -1U };

static void map_cpu_to_logical_apicid(void);

DEFINE_PER_CPU(int, cpu_state);

void *stack_base[NR_CPUS];

static void smp_store_cpu_info(int id)
{
    struct cpuinfo_x86 *c = cpu_data + id;

    *c = boot_cpu_data;
    if ( id != 0 )
        identify_cpu(c);

    /* Mask B, Pentium, but not Pentium MMX -- remember it, as it has bugs. */
    if ( (c->x86_vendor == X86_VENDOR_INTEL) &&
         (c->x86 == 5) &&
         ((c->x86_mask >= 1) && (c->x86_mask <= 4)) &&
         (c->x86_model <= 3) )
        smp_b_stepping = 1;

    /*
     * Certain Athlons might work (for various values of 'work') in SMP
     * but they are not certified as MP capable.
     */
    if ( (c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 6) )
    {
        /* Athlon 660/661 is valid. */ 
        if ( (c->x86_model==6) && ((c->x86_mask==0) || (c->x86_mask==1)) )
            goto valid_k7;

        /* Duron 670 is valid */
        if ( (c->x86_model==7) && (c->x86_mask==0) )
            goto valid_k7;

        /*
         * Athlon 662, Duron 671, and Athlon >model 7 have capability bit.
         * It's worth noting that the A5 stepping (662) of some Athlon XP's
         * have the MP bit set.
         * See http://www.heise.de/newsticker/data/jow-18.10.01-000 for more.
         */
        if ( ((c->x86_model==6) && (c->x86_mask>=2)) ||
             ((c->x86_model==7) && (c->x86_mask>=1)) ||
             (c->x86_model> 7) )
            if (cpu_has_mp)
                goto valid_k7;

        /* If we get here, it's not a certified SMP capable AMD system. */
        add_taint(TAINT_UNSAFE_SMP);
    }

 valid_k7:
    ;
}

static atomic_t init_deasserted;

void smp_callin(void)
{
    int cpuid, phys_id, i;

    /*
     * If waken up by an INIT in an 82489DX configuration
     * we may get here before an INIT-deassert IPI reaches
     * our local APIC.  We have to wait for the IPI or we'll
     * lock up on an APIC access.
     */
    wait_for_init_deassert(&init_deasserted);

    if ( x2apic_enabled )
        enable_x2apic();

    /*
     * (This works even if the APIC is not enabled.)
     */
    phys_id = get_apic_id();
    cpuid = smp_processor_id();
    if ( cpu_isset(cpuid, cpu_callin_map) )
    {
        printk("huh, phys CPU#%d, CPU#%d already present??\n",
               phys_id, cpuid);
        BUG();
    }
    Dprintk("CPU#%d (phys ID: %d) waiting for CALLOUT\n", cpuid, phys_id);

    /*
     * STARTUP IPIs are fragile beasts as they might sometimes
     * trigger some glue motherboard logic. Complete APIC bus
     * silence for 1 second, this overestimates the time the
     * boot CPU is spending to send the up to 2 STARTUP IPIs
     * by a factor of two. This should be enough.
     */

    /* Wait 2s total for startup. */
    for ( i = 0; (i < 200) && !cpu_isset(cpuid, cpu_callout_map); i++ )
    {
        cpu_relax();
        mdelay(10);
    }

    if ( !cpu_isset(cpuid, cpu_callout_map) )
    {
        printk("BUG: CPU%d started up but did not get a callout!\n",
               cpuid);
        BUG();
    }

    /*
     * the boot CPU has finished the init stage and is spinning
     * on callin_map until we finish. We are free to set up this
     * CPU, first the APIC. (this is probably redundant on most
     * boards)
     */

    Dprintk("CALLIN, before setup_local_APIC().\n");
    smp_callin_clear_local_apic();
    setup_local_APIC();
    map_cpu_to_logical_apicid();

    /* Save our processor parameters. */
    smp_store_cpu_info(cpuid);

    /* Allow the master to continue. */
    cpu_set(cpuid, cpu_callin_map);
}

static int booting_cpu;

/* CPUs for which sibling maps can be computed. */
static cpumask_t cpu_sibling_setup_map;

static void set_cpu_sibling_map(int cpu)
{
    int i;
    struct cpuinfo_x86 *c = cpu_data;

    cpu_set(cpu, cpu_sibling_setup_map);

    if ( c[cpu].x86_num_siblings > 1 )
    {
        for_each_cpu_mask ( i, cpu_sibling_setup_map )
        {
            if ( (phys_proc_id[cpu] == phys_proc_id[i]) &&
                 (cpu_core_id[cpu] == cpu_core_id[i]) )
            {
                cpu_set(i, per_cpu(cpu_sibling_map, cpu));
                cpu_set(cpu, per_cpu(cpu_sibling_map, i));
                cpu_set(i, per_cpu(cpu_core_map, cpu));
                cpu_set(cpu, per_cpu(cpu_core_map, i));
            }
        }
    }
    else
    {
        cpu_set(cpu, per_cpu(cpu_sibling_map, cpu));
    }

    if ( c[cpu].x86_max_cores == 1 )
    {
        per_cpu(cpu_core_map, cpu) = per_cpu(cpu_sibling_map, cpu);
        c[cpu].booted_cores = 1;
        return;
    }

    for_each_cpu_mask ( i, cpu_sibling_setup_map )
    {
        if ( phys_proc_id[cpu] == phys_proc_id[i] )
        {
            cpu_set(i, per_cpu(cpu_core_map, cpu));
            cpu_set(cpu, per_cpu(cpu_core_map, i));
            /*
             *  Does this new cpu bringup a new core?
             */
            if ( cpus_weight(per_cpu(cpu_sibling_map, cpu)) == 1 )
            {
                /*
                 * for each core in package, increment
                 * the booted_cores for this new cpu
                 */
                if ( first_cpu(per_cpu(cpu_sibling_map, i)) == i )
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

static void construct_percpu_idt(unsigned int cpu)
{
    unsigned char idt_load[10];

    *(unsigned short *)(&idt_load[0]) = (IDT_ENTRIES*sizeof(idt_entry_t))-1;
    *(unsigned long  *)(&idt_load[2]) = (unsigned long)idt_tables[cpu];
    __asm__ __volatile__ ( "lidt %0" : "=m" (idt_load) );
}

void start_secondary(void *unused)
{
    /*
     * Dont put anything before smp_callin(), SMP booting is so fragile that we
     * want to limit the things done here to the most necessary things.
     */
    unsigned int cpu = booting_cpu;

    set_processor_id(cpu);
    set_current(idle_vcpu[cpu]);
    this_cpu(curr_vcpu) = idle_vcpu[cpu];
    if ( cpu_has_efer )
        rdmsrl(MSR_EFER, this_cpu(efer));
    asm volatile ( "mov %%cr4,%0" : "=r" (this_cpu(cr4)) );

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

    percpu_traps_init();

    cpu_init();

    smp_callin();
    while (!cpu_isset(smp_processor_id(), smp_commenced_mask))
        cpu_relax();

    /*
     * At this point, boot CPU has fully initialised the IDT. It is
     * now safe to make ourselves a private copy.
     */
    construct_percpu_idt(cpu);

    setup_secondary_APIC_clock();
    enable_APIC_timer();
    /*
     * low-memory mappings have been cleared, flush them from
     * the local TLBs too.
     */
    flush_tlb_local();

    /* This must be done before setting cpu_online_map */
    spin_debug_enable();
    set_cpu_sibling_map(raw_smp_processor_id());
    wmb();

    /*
     * We need to hold vector_lock so there the set of online cpus
     * does not change while we are assigning vectors to cpus.  Holding
     * this lock ensures we don't half assign or remove an irq from a cpu.
     */
    lock_vector_lock();
    __setup_vector_irq(smp_processor_id());
    cpu_set(smp_processor_id(), cpu_online_map);
    unlock_vector_lock();

    per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;

    init_percpu_time();

    /* We can take interrupts now: we're officially "up". */
    local_irq_enable();
    mtrr_ap_init();

    microcode_resume_cpu(cpu);

    wmb();
    startup_cpu_idle_loop();
}

extern struct {
    void * esp;
    unsigned short ss;
} stack_start;

u32 cpu_2_logical_apicid[NR_CPUS] __read_mostly =
    { [0 ... NR_CPUS-1] = BAD_APICID };

static void map_cpu_to_logical_apicid(void)
{
    int cpu = smp_processor_id();
    int apicid = logical_smp_processor_id();

    cpu_2_logical_apicid[cpu] = apicid;
}

static void unmap_cpu_to_logical_apicid(int cpu)
{
    cpu_2_logical_apicid[cpu] = BAD_APICID;
}

#if APIC_DEBUG
static void __inquire_remote_apic(int apicid)
{
    int i, regs[] = { APIC_ID >> 4, APIC_LVR >> 4, APIC_SPIV >> 4 };
    char *names[] = { "ID", "VERSION", "SPIV" };
    int timeout, status;

    printk("Inquiring remote APIC #%d...\n", apicid);

    for ( i = 0; i < ARRAY_SIZE(regs); i++ )
    {
        printk("... APIC #%d %s: ", apicid, names[i]);

        /*
         * Wait for idle.
         */
        apic_wait_icr_idle();

        apic_icr_write(APIC_DM_REMRD | regs[i], apicid);

        timeout = 0;
        do {
            udelay(100);
            status = apic_read(APIC_ICR) & APIC_ICR_RR_MASK;
        } while ( status == APIC_ICR_RR_INPROG && timeout++ < 1000 );

        switch ( status )
        {
        case APIC_ICR_RR_VALID:
            status = apic_read(APIC_RRR);
            printk("%08x\n", status);
            break;
        default:
            printk("failed\n");
        }
    }
}
#endif

static int wakeup_secondary_cpu(int phys_apicid, unsigned long start_eip)
{
    unsigned long send_status = 0, accept_status = 0;
    int maxlvt, timeout, num_starts, i;

    /*
     * Be paranoid about clearing APIC errors.
     */
    if ( APIC_INTEGRATED(apic_version[phys_apicid]) )
    {
        apic_read_around(APIC_SPIV);
        apic_write(APIC_ESR, 0);
        apic_read(APIC_ESR);
    }

    Dprintk("Asserting INIT.\n");

    /*
     * Turn INIT on target chip via IPI
     */
    apic_icr_write(APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT,
                   phys_apicid);

    Dprintk("Waiting for send to finish...\n");
    timeout = 0;
    do {
        Dprintk("+");
        udelay(100);
        if ( !x2apic_enabled )
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
        if ( !x2apic_enabled )
            send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
    } while ( send_status && (timeout++ < 1000) );

    atomic_set(&init_deasserted, 1);

    /*
     * Should we send STARTUP IPIs ?
     *
     * Determine this based on the APIC version.
     * If we don't have an integrated APIC, don't send the STARTUP IPIs.
     */
    num_starts = APIC_INTEGRATED(apic_version[phys_apicid]) ? 2 : 0;

    /* Run STARTUP IPI loop. */
    Dprintk("#startup loops: %d.\n", num_starts);

    maxlvt = get_maxlvt();

    for ( i = 0; i < num_starts; i++ )
    {
        Dprintk("Sending STARTUP #%d.\n",j);
        apic_read_around(APIC_SPIV);
        apic_write(APIC_ESR, 0);
        apic_read(APIC_ESR);
        Dprintk("After apic_write.\n");

        /*
         * STARTUP IPI
         * Boot on the stack
         */
        apic_icr_write(APIC_DM_STARTUP | (start_eip >> 12), phys_apicid);

        /* Give the other CPU some time to accept the IPI. */
        udelay(300);

        Dprintk("Startup point 1.\n");

        Dprintk("Waiting for send to finish...\n");
        timeout = 0;
        do {
            Dprintk("+");
            udelay(100);
            if ( !x2apic_enabled )
            send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
        } while ( send_status && (timeout++ < 1000) );

        /* Give the other CPU some time to accept the IPI. */
        udelay(200);

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
    cpus_complement(tmp_map, cpu_present_map);
    cpu = first_cpu(tmp_map);
    return (cpu < NR_CPUS) ? cpu : -ENODEV;
}

static void *prepare_idle_stack(unsigned int cpu)
{
    if ( !stack_base[cpu] )
        stack_base[cpu] = alloc_xenheap_pages(STACK_ORDER, 0);
    return stack_base[cpu];
}

static int do_boot_cpu(int apicid, int cpu)
{
    unsigned long boot_error;
    unsigned int order;
    int timeout;
    unsigned long start_eip;
    struct vcpu *v;
    struct desc_struct *gdt;
#ifdef __x86_64__
    struct page_info *page;
#endif

    /*
     * Save current MTRR state in case it was changed since early boot
     * (e.g. by the ACPI SMI) to initialize new CPUs with MTRRs in sync:
     */
    mtrr_save_state();

    booting_cpu = cpu;

    v = alloc_idle_vcpu(cpu);
    BUG_ON(v == NULL);

    /* start_eip had better be page-aligned! */
    start_eip = setup_trampoline();

    /* So we see what's up   */
    if (opt_cpu_info)
        printk("Booting processor %d/%d eip %lx\n",
               cpu, apicid, start_eip);

    stack_start.esp = prepare_idle_stack(cpu);

    /* Debug build: detect stack overflow by setting up a guard page. */
    memguard_guard_stack(stack_start.esp);

    gdt = per_cpu(gdt_table, cpu);
    if ( gdt == boot_cpu_gdt_table )
    {
        order = get_order_from_pages(NR_RESERVED_GDT_PAGES);
#ifdef __x86_64__
        page = alloc_domheap_pages(NULL, order,
                                   MEMF_node(cpu_to_node(cpu)));
        per_cpu(compat_gdt_table, cpu) = gdt = page_to_virt(page);
        memcpy(gdt, boot_cpu_compat_gdt_table,
               NR_RESERVED_GDT_PAGES * PAGE_SIZE);
        gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;
        page = alloc_domheap_pages(NULL, order,
                                   MEMF_node(cpu_to_node(cpu)));
        per_cpu(gdt_table, cpu) = gdt = page_to_virt(page);
#else
        per_cpu(gdt_table, cpu) = gdt = alloc_xenheap_pages(order, 0);
#endif
        memcpy(gdt, boot_cpu_gdt_table,
               NR_RESERVED_GDT_PAGES * PAGE_SIZE);
        BUILD_BUG_ON(NR_CPUS > 0x10000);
        gdt[PER_CPU_GDT_ENTRY - FIRST_RESERVED_GDT_ENTRY].a = cpu;
    }

#ifdef __i386__
    if ( !per_cpu(doublefault_tss, cpu) )
    {
        per_cpu(doublefault_tss, cpu) = alloc_xenheap_page();
        memset(per_cpu(doublefault_tss, cpu), 0, PAGE_SIZE);
    }
#else
    if ( !per_cpu(compat_arg_xlat, cpu) )
        setup_compat_arg_xlat(cpu, cpu_to_node[cpu]);
#endif

    if ( !idt_tables[cpu] )
    {
        idt_tables[cpu] = xmalloc_array(idt_entry_t, IDT_ENTRIES);
        memcpy(idt_tables[cpu], idt_table,
               IDT_ENTRIES*sizeof(idt_entry_t));
    }

    /* This grunge runs the startup process for the targeted processor. */

    atomic_set(&init_deasserted, 0);

    Dprintk("Setting warm reset code and vector.\n");

    smpboot_setup_warm_reset_vector(start_eip);

    /* Starting actual IPI sequence... */
    boot_error = wakeup_secondary_cpu(apicid, start_eip);

    if ( !boot_error )
    {
        /* Allow AP to start initializing. */
        Dprintk("Before Callout %d.\n", cpu);
        cpu_set(cpu, cpu_callout_map);
        Dprintk("After Callout %d.\n", cpu);

        /* Wait 5s total for a response. */
        for ( timeout = 0; timeout < 50000; timeout++ )
        {
            if ( cpu_isset(cpu, cpu_callin_map) )
                break; /* It has booted */
            udelay(100);
        }

        if ( cpu_isset(cpu, cpu_callin_map) )
        {
            /* number CPUs logically, starting from 1 (BSP is 0) */
            Dprintk("OK.\n");
            print_cpu_info(cpu);
            Dprintk("CPU has booted.\n");
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
            inquire_remote_apic(apicid);
        }
    }

    if ( boot_error )
    {
        /* Try to put things back the way they were before ... */
        unmap_cpu_to_logical_apicid(cpu);
        cpu_clear(cpu, cpu_callout_map); /* was set here */
        cpu_uninit(cpu); /* undoes cpu_init() */

        /* Mark the CPU as non-present */
        x86_cpu_to_apicid[cpu] = BAD_APICID;
        cpu_clear(cpu, cpu_present_map);
    }

    /* mark "stuck" area as not stuck */
    bootsym(trampoline_cpu_started) = 0;
    mb();

    smpboot_restore_warm_reset_vector();

    return boot_error ? -EIO : 0;
}

void cpu_exit_clear(void)
{
    int cpu = raw_smp_processor_id();

    cpu_uninit(cpu);

    cpu_clear(cpu, cpu_callout_map);
    cpu_clear(cpu, cpu_callin_map);

    cpu_clear(cpu, smp_commenced_mask);
    unmap_cpu_to_logical_apicid(cpu);
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
    mtrr_aps_sync_begin();

    /* Setup boot CPU information */
    smp_store_cpu_info(0); /* Final full version of the data */
    print_cpu_info(0);

    boot_cpu_physical_apicid = get_apic_id();
    x86_cpu_to_apicid[0] = boot_cpu_physical_apicid;

    stack_base[0] = stack_start.esp;

    set_cpu_sibling_map(0);

    /*
     * If we couldn't find an SMP configuration at boot time,
     * get out of here now!
     */
    if ( !smp_found_config && !acpi_lapic )
    {
        printk(KERN_NOTICE "SMP motherboard not detected.\n");
    init_uniprocessor:
        phys_cpu_present_map = physid_mask_of_physid(0);
        if (APIC_init_uniprocessor())
            printk(KERN_NOTICE "Local APIC not detected."
                   " Using dummy APIC emulation.\n");
        map_cpu_to_logical_apicid();
        cpu_set(0, per_cpu(cpu_sibling_map, 0));
        cpu_set(0, per_cpu(cpu_core_map, 0));
        return;
    }

    /*
     * Should not be necessary because the MP table should list the boot
     * CPU too, but we do it for the sake of robustness anyway.
     * Makes no sense to do this check in clustered apic mode, so skip it
     */
    if ( !check_phys_apicid_present(boot_cpu_physical_apicid) )
    {
        printk("weird, boot CPU (#%d) not listed by the BIOS.\n",
               boot_cpu_physical_apicid);
        physid_set(hard_smp_processor_id(), phys_cpu_present_map);
    }

    /* If we couldn't find a local APIC, then get out of here now! */
    if ( APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid])
         && !cpu_has_apic )
    {
        printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        goto init_uniprocessor;
    }

    verify_local_APIC();

    connect_bsp_APIC();
    setup_local_APIC();
    map_cpu_to_logical_apicid();

    /*
     * construct cpu_sibling_map, so that we can tell sibling CPUs
     * efficiently.
     */
    cpu_set(0, per_cpu(cpu_sibling_map, 0));
    cpu_set(0, per_cpu(cpu_core_map, 0));

    smpboot_setup_io_apic();

    setup_boot_APIC_clock();
}

void __init smp_prepare_boot_cpu(void)
{
    cpu_set(smp_processor_id(), smp_commenced_mask);
    cpu_set(smp_processor_id(), cpu_callin_map);
    cpu_set(smp_processor_id(), cpu_online_map);
    cpu_set(smp_processor_id(), cpu_callout_map);
    cpu_set(smp_processor_id(), cpu_present_map);
    cpu_set(smp_processor_id(), cpu_possible_map);
    per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;
}

static void
remove_siblinginfo(int cpu)
{
    int sibling;
    struct cpuinfo_x86 *c = cpu_data;

    for_each_cpu_mask ( sibling, per_cpu(cpu_core_map, cpu) )
    {
        cpu_clear(cpu, per_cpu(cpu_core_map, sibling));
        /* Last thread sibling in this cpu core going down. */
        if ( cpus_weight(per_cpu(cpu_sibling_map, cpu)) == 1 )
            c[sibling].booted_cores--;
    }
   
    for_each_cpu_mask(sibling, per_cpu(cpu_sibling_map, cpu))
        cpu_clear(cpu, per_cpu(cpu_sibling_map, sibling));
    cpus_clear(per_cpu(cpu_sibling_map, cpu));
    cpus_clear(per_cpu(cpu_core_map, cpu));
    phys_proc_id[cpu] = BAD_APICID;
    cpu_core_id[cpu] = BAD_APICID;
    cpu_clear(cpu, cpu_sibling_setup_map);
}

void __cpu_disable(void)
{
    extern void fixup_irqs(void);
    int cpu = smp_processor_id();

    local_irq_disable();
    clear_local_APIC();
    /* Allow any queued timer interrupts to get serviced */
    local_irq_enable();
    mdelay(1);
    local_irq_disable();

    time_suspend();

    remove_siblinginfo(cpu);

    /* It's now safe to remove this processor from the online map */
    cpu_clear(cpu, cpupool0->cpu_valid);
    cpu_clear(cpu, cpu_online_map);
    fixup_irqs();

    cpu_disable_scheduler(cpu);
}

void __cpu_die(unsigned int cpu)
{
    /* We don't do anything here: idle task is faking death itself. */
    unsigned int i = 0;

    while ( per_cpu(cpu_state, cpu) != CPU_DEAD )
    {
        mdelay(100);
        cpu_relax();
        process_pending_softirqs();
        if ( (++i % 10) == 0 )
            printk(KERN_ERR "CPU %u still not dead...\n", cpu);
    }
}

int cpu_add(uint32_t apic_id, uint32_t acpi_id, uint32_t pxm)
{
    int node, cpu = -1;

    dprintk(XENLOG_DEBUG, "cpu_add apic_id %x acpi_id %x pxm %x\n",
            apic_id, acpi_id, pxm);

    if ( acpi_id > MAX_MADT_ENTRIES || apic_id > MAX_APICS || pxm > 256 )
        return -EINVAL;

    if ( !cpu_hotplug_begin() )
        return -EBUSY;

    /* Detect if the cpu has been added before */
    if ( x86_acpiid_to_apicid[acpi_id] != 0xff )
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

    if ( (cpu = mp_register_lapic(apic_id, 1)) < 0 )
        goto out;

    x86_acpiid_to_apicid[acpi_id] = apic_id;

    if ( !srat_disabled() )
    {
        if ( (node = setup_node(pxm)) < 0 )
        {
            dprintk(XENLOG_WARNING,
                    "Setup node failed for pxm %x\n", pxm);
            x86_acpiid_to_apicid[acpi_id] = 0xff;
            mp_unregister_lapic(apic_id, cpu);
            cpu = node;
            goto out;
        }
        apicid_to_node[apic_id] = node;
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

    BUG_ON(cpu_isset(cpu, cpu_callin_map));

    if ( (apicid = x86_cpu_to_apicid[cpu]) == BAD_APICID )
        return -ENODEV;

    if ( (ret = do_boot_cpu(apicid, cpu)) != 0 )
        return ret;

    cpu_set(cpu, smp_commenced_mask);
    while ( !cpu_isset(cpu, cpu_online_map) )
    {
        cpu_relax();
        process_pending_softirqs();
    }

    return 0;
}


void __init smp_cpus_done(unsigned int max_cpus)
{
    if ( smp_b_stepping )
        printk(KERN_WARNING "WARNING: SMP operation may be "
               "unreliable with B stepping processors.\n");

    /*
     * Don't taint if we are running SMP kernel on a single non-MP
     * approved Athlon
     */
    if ( tainted & TAINT_UNSAFE_SMP )
    {
        if ( num_online_cpus() > 1 )
            printk(KERN_INFO "WARNING: This combination of AMD "
                   "processors is not suitable for SMP.\n");
        else
            tainted &= ~TAINT_UNSAFE_SMP;
    }

    if ( nmi_watchdog == NMI_LOCAL_APIC )
        check_nmi_watchdog();

    setup_ioapic_dest();

    mtrr_save_state();
    mtrr_aps_sync_end();
}

void __init smp_intr_init(void)
{
    int irq, seridx, cpu = smp_processor_id();

    /*
     * IRQ0 must be given a fixed assignment and initialized,
     * because it's used before the IO-APIC is set up.
     */
    irq_vector[0] = FIRST_HIPRIORITY_VECTOR;

    /*
     * Also ensure serial interrupts are high priority. We do not
     * want them to be blocked by unacknowledged guest-bound interrupts.
     */
    for ( seridx = 0; seridx < 2; seridx++ )
    {
        if ( (irq = serial_irq(seridx)) < 0 )
            continue;
        irq_vector[irq] = FIRST_HIPRIORITY_VECTOR + seridx + 1;
        per_cpu(vector_irq, cpu)[FIRST_HIPRIORITY_VECTOR + seridx + 1] = irq;
        irq_cfg[irq].vector = FIRST_HIPRIORITY_VECTOR + seridx + 1;
        irq_cfg[irq].domain = (cpumask_t)CPU_MASK_ALL;
    }

    /* IPI for cleanuping vectors after irq move */
    set_intr_gate(IRQ_MOVE_CLEANUP_VECTOR, irq_move_cleanup_interrupt);

    /* IPI for event checking. */
    set_intr_gate(EVENT_CHECK_VECTOR, event_check_interrupt);

    /* IPI for invalidation */
    set_intr_gate(INVALIDATE_TLB_VECTOR, invalidate_interrupt);

    /* IPI for generic function call */
    set_intr_gate(CALL_FUNCTION_VECTOR, call_function_interrupt);
}
