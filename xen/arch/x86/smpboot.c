/*
 *	x86 SMP booting functions
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998, 1999, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	Much of the core SMP work is based on previous work by Thomas Radke, to
 *	whom a great many thanks are extended.
 *
 *	Thanks to Intel for making available several different Pentium,
 *	Pentium Pro and Pentium-II/Xeon MP machines.
 *	Original development of Linux SMP code supported by Caldera.
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 *
 *	Fixes
 *		Felix Koop	:	NR_CPUS used properly
 *		Jose Renau	:	Handle single CPU case.
 *		Alan Cox	:	By repeated request 8) - Total BogoMIP report.
 *		Greg Wright	:	Fix for kernel stacks panic.
 *		Erich Boleyn	:	MP v1.4 and additional changes.
 *	Matthias Sattler	:	Changes for 2.1 kernel map.
 *	Michel Lespinasse	:	Changes for 2.1 kernel map.
 *	Michael Chastain	:	Change trampoline.S to gnu as.
 *		Alan Cox	:	Dumb bug: 'B' step PPro's are fine
 *		Ingo Molnar	:	Added APIC timers, based on code
 *					from Jose Renau
 *		Ingo Molnar	:	various cleanups and rewrites
 *		Tigran Aivazian	:	fixed "0.00 in /proc/uptime on SMP" bug.
 *	Maciej W. Rozycki	:	Bits for genuine 82489DX APICs
 *		Martin J. Bligh	: 	Added support for multi-quad systems
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/slab.h>
#include <asm/flushtlb.h>
#include <asm/mc146818rtc.h>
#include <asm/smpboot.h>
#include <xen/smp.h>
#include <asm/msr.h>
#include <asm/system.h>
#include <asm/mpspec.h>
#include <asm/io_apic.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/lib.h>

#ifdef CONFIG_SMP

/* Setup configured maximum number of CPUs to activate */
static int max_cpus = -1;

/* Total count of live CPUs */
int smp_num_cpus = 1;

/* Number of hyperthreads per core */
int ht_per_core = 1;

/* Bitmask of currently online CPUs */
unsigned long cpu_online_map;

static volatile unsigned long cpu_callin_map;
static volatile unsigned long cpu_callout_map;

/* Per CPU bogomips and other parameters */
struct cpuinfo_x86 cpu_data[NR_CPUS];

/* Set when the idlers are all forked */
int smp_threads_ready;

/*
 * Trampoline 80x86 program as an array.
 */

extern unsigned char trampoline_data [];
extern unsigned char trampoline_end  [];
static unsigned char *trampoline_base;

/*
 * Currently trivial. Write the real->protected mode
 * bootstrap into the page concerned. The caller
 * has made sure it's suitably aligned.
 */

static unsigned long __init setup_trampoline(void)
{
    memcpy(trampoline_base, trampoline_data, trampoline_end - trampoline_data);
    return virt_to_phys(trampoline_base);
}

/*
 * We are called very early to get the low memory for the
 * SMP bootup trampoline page.
 */
void __init smp_alloc_memory(void)
{
    /*
     * Has to be in very low memory so we can execute
     * real-mode AP code.
     */
    trampoline_base = __va(0x90000);
}

/*
 * The bootstrap kernel entry code has set these up. Save them for
 * a given CPU
 */

void __init smp_store_cpu_info(int id)
{
    cpu_data[id] = boot_cpu_data;
    identify_cpu(&cpu_data[id]);
}

/*
 * Architecture specific routine called by the kernel just before init is
 * fired off. This allows the BP to have everything in order [we hope].
 * At the end of this all the APs will hit the system scheduling and off
 * we go. Each AP will load the system gdt's and jump through the kernel
 * init into idle(). At this point the scheduler will one day take over
 * and give them jobs to do. smp_callin is a standard routine
 * we use to track CPUs as they power up.
 */

static atomic_t smp_commenced = ATOMIC_INIT(0);

void __init smp_commence(void)
{
    /*
     * Lets the callins below out of their loop.
     */
    Dprintk("Setting commenced=1, go go go\n");

    wmb();
    atomic_set(&smp_commenced,1);
}

/*
 * TSC synchronization.
 *
 * We first check wether all CPUs have their TSC's synchronized,
 * then we print a warning if not, and always resync.
 */

static atomic_t tsc_start_flag = ATOMIC_INIT(0);
static atomic_t tsc_count_start = ATOMIC_INIT(0);
static atomic_t tsc_count_stop = ATOMIC_INIT(0);
static unsigned long long tsc_values[NR_CPUS];

#define NR_LOOPS 5

/*
 * accurate 64-bit/32-bit division, expanded to 32-bit divisions and 64-bit
 * multiplication. Not terribly optimized but we need it at boot time only
 * anyway.
 *
 * result == a / b
 *	== (a1 + a2*(2^32)) / b
 *	== a1/b + a2*(2^32/b)
 *	== a1/b + a2*((2^32-1)/b) + a2/b + (a2*((2^32-1) % b))/b
 *		    ^---- (this multiplication can overflow)
 */

static unsigned long long div64 (unsigned long long a, unsigned long b0)
{
    unsigned int a1, a2;
    unsigned long long res;

    a1 = ((unsigned int*)&a)[0];
    a2 = ((unsigned int*)&a)[1];

    res = a1/b0 +
        (unsigned long long)a2 * (unsigned long long)(0xffffffff/b0) +
        a2 / b0 +
        (a2 * (0xffffffff % b0)) / b0;

    return res;
}

static void __init synchronize_tsc_bp (void)
{
    int i;
    unsigned long long t0;
    unsigned long long sum, avg;
    long long delta;
    int buggy = 0;

    printk("checking TSC synchronization across CPUs: ");

    atomic_set(&tsc_start_flag, 1);
    wmb();

    /*
     * We loop a few times to get a primed instruction cache,
     * then the last pass is more or less synchronized and
     * the BP and APs set their cycle counters to zero all at
     * once. This reduces the chance of having random offsets
     * between the processors, and guarantees that the maximum
     * delay between the cycle counters is never bigger than
     * the latency of information-passing (cachelines) between
     * two CPUs.
     */
    for (i = 0; i < NR_LOOPS; i++) {
        /*
         * all APs synchronize but they loop on '== num_cpus'
         */
        while (atomic_read(&tsc_count_start) != smp_num_cpus-1) mb();
        atomic_set(&tsc_count_stop, 0);
        wmb();
        /*
         * this lets the APs save their current TSC:
         */
        atomic_inc(&tsc_count_start);

        rdtscll(tsc_values[smp_processor_id()]);
        /*
         * We clear the TSC in the last loop:
         */
        if (i == NR_LOOPS-1)
            write_tsc(0, 0);

        /*
         * Wait for all APs to leave the synchronization point:
         */
        while (atomic_read(&tsc_count_stop) != smp_num_cpus-1) mb();
        atomic_set(&tsc_count_start, 0);
        wmb();
        atomic_inc(&tsc_count_stop);
    }

    sum = 0;
    for (i = 0; i < smp_num_cpus; i++) {
        t0 = tsc_values[i];
        sum += t0;
    }
    avg = div64(sum, smp_num_cpus);

    sum = 0;
    for (i = 0; i < smp_num_cpus; i++) {
        delta = tsc_values[i] - avg;
        if (delta < 0)
            delta = -delta;
        /*
         * We report bigger than 2 microseconds clock differences.
         */
        if (delta > 2*ticks_per_usec) {
            long realdelta;
            if (!buggy) {
                buggy = 1;
                printk("\n");
            }
            realdelta = div64(delta, ticks_per_usec);
            if (tsc_values[i] < avg)
                realdelta = -realdelta;

            printk("BIOS BUG: CPU#%d improperly initialized, has %ld usecs TSC skew! FIXED.\n",
                   i, realdelta);
        }

        sum += delta;
    }
    if (!buggy)
        printk("passed.\n");
}

static void __init synchronize_tsc_ap (void)
{
    int i;

    /*
     * smp_num_cpus is not necessarily known at the time
     * this gets called, so we first wait for the BP to
     * finish SMP initialization:
     */
    while (!atomic_read(&tsc_start_flag)) mb();

    for (i = 0; i < NR_LOOPS; i++) {
        atomic_inc(&tsc_count_start);
        while (atomic_read(&tsc_count_start) != smp_num_cpus) mb();

        rdtscll(tsc_values[smp_processor_id()]);
        if (i == NR_LOOPS-1)
            write_tsc(0, 0);

        atomic_inc(&tsc_count_stop);
        while (atomic_read(&tsc_count_stop) != smp_num_cpus) mb();
    }
}
#undef NR_LOOPS

static atomic_t init_deasserted;

void __init smp_callin(void)
{
    int cpuid, phys_id, i;

    /*
     * If waken up by an INIT in an 82489DX configuration
     * we may get here before an INIT-deassert IPI reaches
     * our local APIC.  We have to wait for the IPI or we'll
     * lock up on an APIC access.
     */
    while (!atomic_read(&init_deasserted));

    /*
     * (This works even if the APIC is not enabled.)
     */
    phys_id = GET_APIC_ID(apic_read(APIC_ID));
    cpuid = smp_processor_id();
    if (test_and_set_bit(cpuid, &cpu_online_map)) {
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

    for ( i = 0; i < 200; i++ )
    {
        if ( test_bit(cpuid, &cpu_callout_map) ) break;
        mdelay(10);
    }

    if (!test_bit(cpuid, &cpu_callout_map)) {
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

    setup_local_APIC();

    __sti();

    Dprintk("Stack at about %p\n",&cpuid);

    /*
     * Save our processor parameters
     */
    smp_store_cpu_info(cpuid);

    if (nmi_watchdog == NMI_LOCAL_APIC)
        setup_apic_nmi_watchdog();

    /*
     * Allow the master to continue.
     */
    set_bit(cpuid, &cpu_callin_map);

    /*
     *      Synchronize the TSC with the BP
     */
    synchronize_tsc_ap();
}

static int cpucount;

#ifdef __i386__
static void construct_percpu_idt(unsigned int cpu)
{
    unsigned char idt_load[10];

    idt_tables[cpu] = xmalloc_array(idt_entry_t, IDT_ENTRIES);
    memcpy(idt_tables[cpu], idt_table, IDT_ENTRIES*sizeof(idt_entry_t));

    *(unsigned short *)(&idt_load[0]) = (IDT_ENTRIES*sizeof(idt_entry_t))-1;
    *(unsigned long  *)(&idt_load[2]) = (unsigned long)idt_tables[cpu];
    __asm__ __volatile__ ( "lidt %0" : "=m" (idt_load) );
}
#endif

/*
 * Activate a secondary processor.
 */
void __init start_secondary(void)
{
    unsigned int cpu = cpucount;

    extern void percpu_traps_init(void);
    extern void cpu_init(void);

    set_current(idle_task[cpu]);

    percpu_traps_init();

    cpu_init();

    smp_callin();

    while (!atomic_read(&smp_commenced))
        rep_nop();

#ifdef __i386__
    /*
     * At this point, boot CPU has fully initialised the IDT. It is
     * now safe to make ourselves a private copy.
     */
    construct_percpu_idt(cpu);
#endif

    local_flush_tlb();

    startup_cpu_idle_loop();

    BUG();
}

extern struct {
    unsigned long esp, ss;
} stack_start;

/* which physical APIC ID maps to which logical CPU number */
volatile int physical_apicid_2_cpu[MAX_APICID];
/* which logical CPU number maps to which physical APIC ID */
volatile int cpu_2_physical_apicid[NR_CPUS];

/* which logical APIC ID maps to which logical CPU number */
volatile int logical_apicid_2_cpu[MAX_APICID];
/* which logical CPU number maps to which logical APIC ID */
volatile int cpu_2_logical_apicid[NR_CPUS];

static inline void init_cpu_to_apicid(void)
/* Initialize all maps between cpu number and apicids */
{
    int apicid, cpu;

    for (apicid = 0; apicid < MAX_APICID; apicid++) {
        physical_apicid_2_cpu[apicid] = -1;
        logical_apicid_2_cpu[apicid] = -1;
    }
    for (cpu = 0; cpu < NR_CPUS; cpu++) {
        cpu_2_physical_apicid[cpu] = -1;
        cpu_2_logical_apicid[cpu] = -1;
    }
}

static inline void map_cpu_to_boot_apicid(int cpu, int apicid)
/* 
 * set up a mapping between cpu and apicid. Uses logical apicids for multiquad,
 * else physical apic ids
 */
{
    physical_apicid_2_cpu[apicid] = cpu;	
    cpu_2_physical_apicid[cpu] = apicid;
}

static inline void unmap_cpu_to_boot_apicid(int cpu, int apicid)
/* 
 * undo a mapping between cpu and apicid. Uses logical apicids for multiquad,
 * else physical apic ids
 */
{
    physical_apicid_2_cpu[apicid] = -1;	
    cpu_2_physical_apicid[cpu] = -1;
}

#if APIC_DEBUG
static inline void inquire_remote_apic(int apicid)
{
    int i, regs[] = { APIC_ID >> 4, APIC_LVR >> 4, APIC_SPIV >> 4 };
    char *names[] = { "ID", "VERSION", "SPIV" };
    int timeout, status;

    printk("Inquiring remote APIC #%d...\n", apicid);

    for (i = 0; i < sizeof(regs) / sizeof(*regs); i++) {
        printk("... APIC #%d %s: ", apicid, names[i]);

        /*
         * Wait for idle.
         */
        apic_wait_icr_idle();

        apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(apicid));
        apic_write_around(APIC_ICR, APIC_DM_REMRD | regs[i]);

        timeout = 0;
        do {
            udelay(100);
            status = apic_read(APIC_ICR) & APIC_ICR_RR_MASK;
        } while (status == APIC_ICR_RR_INPROG && timeout++ < 1000);

        switch (status) {
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


static int wakeup_secondary_via_INIT(int phys_apicid, unsigned long start_eip)
{
    unsigned long send_status = 0, accept_status = 0;
    int maxlvt, timeout, num_starts, j;

    Dprintk("Asserting INIT.\n");

    /*
     * Turn INIT on target chip
     */
    apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

    /*
     * Send IPI
     */
    apic_write_around(APIC_ICR, APIC_INT_LEVELTRIG | APIC_INT_ASSERT
                      | APIC_DM_INIT);

    Dprintk("Waiting for send to finish...\n");
    timeout = 0;
    do {
        Dprintk("+");
        udelay(100);
        send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
    } while (send_status && (timeout++ < 1000));

    mdelay(10);

    Dprintk("Deasserting INIT.\n");

    /* Target chip */
    apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

    /* Send IPI */
    apic_write_around(APIC_ICR, APIC_INT_LEVELTRIG | APIC_DM_INIT);

    Dprintk("Waiting for send to finish...\n");
    timeout = 0;
    do {
        Dprintk("+");
        udelay(100);
        send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
    } while (send_status && (timeout++ < 1000));

    atomic_set(&init_deasserted, 1);

    /*
     * Should we send STARTUP IPIs ?
     *
     * Determine this based on the APIC version.
     * If we don't have an integrated APIC, don't send the STARTUP IPIs.
     */
    if (APIC_INTEGRATED(apic_version[phys_apicid]))
        num_starts = 2;
    else
        num_starts = 0;

    /*
     * Run STARTUP IPI loop.
     */
    Dprintk("#startup loops: %d.\n", num_starts);

    maxlvt = get_maxlvt();

    for (j = 1; j <= num_starts; j++) {
        Dprintk("Sending STARTUP #%d.\n",j);

        apic_read_around(APIC_SPIV);
        apic_write(APIC_ESR, 0);
        apic_read(APIC_ESR);
        Dprintk("After apic_write.\n");

        /*
         * STARTUP IPI
         */

        /* Target chip */
        apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(phys_apicid));

        /* Boot on the stack */
        /* Kick the second */
        apic_write_around(APIC_ICR, APIC_DM_STARTUP
                          | (start_eip >> 12));

        /*
         * Give the other CPU some time to accept the IPI.
         */
        udelay(300);

        Dprintk("Startup point 1.\n");

        Dprintk("Waiting for send to finish...\n");
        timeout = 0;
        do {
            Dprintk("+");
            udelay(100);
            send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
        } while (send_status && (timeout++ < 1000));

        /*
         * Give the other CPU some time to accept the IPI.
         */
        udelay(200);
        /*
         * Due to the Pentium erratum 3AP.
         */
        if (maxlvt > 3) {
            apic_read_around(APIC_SPIV);
            apic_write(APIC_ESR, 0);
        }
        accept_status = (apic_read(APIC_ESR) & 0xEF);
        if (send_status || accept_status)
            break;
    }
    Dprintk("After Startup.\n");

    if (send_status)
        printk("APIC never delivered???\n");
    if (accept_status)
        printk("APIC delivery error (%lx).\n", accept_status);

    return (send_status | accept_status);
}

extern unsigned long cpu_initialized;

static void __init do_boot_cpu (int apicid) 
/*
 * NOTE - on most systems this is a PHYSICAL apic ID, but on multiquad
 * (ie clustered apic addressing mode), this is a LOGICAL apic ID.
 */
{
    struct domain *idle;
    struct exec_domain *ed;
    unsigned long boot_error = 0;
    int timeout, cpu;
    unsigned long start_eip;
    void *stack;

    cpu = ++cpucount;

    if ( (idle = do_createdomain(IDLE_DOMAIN_ID, cpu)) == NULL )
        panic("failed 'createdomain' for CPU %d", cpu);

    ed = idle->exec_domain[0];

    set_bit(DF_IDLETASK, &idle->d_flags);

    ed->arch.monitor_table = mk_pagetable(__pa(idle_pg_table));

    map_cpu_to_boot_apicid(cpu, apicid);

    idle_task[cpu] = ed;

    /* start_eip had better be page-aligned! */
    start_eip = setup_trampoline();

    /* So we see what's up. */
    printk("Booting processor %d/%d eip %lx\n", cpu, apicid, start_eip);

    stack = (void *)alloc_xenheap_pages(STACK_ORDER);
#if defined(__i386__)
    stack_start.esp = __pa(stack) + STACK_SIZE - STACK_RESERVED;
#elif defined(__x86_64__)
    stack_start.esp = (unsigned long)stack + STACK_SIZE - STACK_RESERVED;
#endif

    /* Debug build: detect stack overflow by setting up a guard page. */
    memguard_guard_stack(stack);

    /*
     * This grunge runs the startup process for
     * the targeted processor.
     */

    atomic_set(&init_deasserted, 0);

    Dprintk("Setting warm reset code and vector.\n");

    CMOS_WRITE(0xa, 0xf);
    local_flush_tlb();
    Dprintk("1.\n");
    *((volatile unsigned short *) TRAMPOLINE_HIGH) = start_eip >> 4;
    Dprintk("2.\n");
    *((volatile unsigned short *) TRAMPOLINE_LOW) = start_eip & 0xf;
    Dprintk("3.\n");

    /*
     * Be paranoid about clearing APIC errors.
     */
    if ( APIC_INTEGRATED(apic_version[apicid]) )
    {
        apic_read_around(APIC_SPIV);
        apic_write(APIC_ESR, 0);
        apic_read(APIC_ESR);
    }

    /*
     * Status is now clean
     */
    boot_error = 0;

    /*
     * Starting actual IPI sequence...
     */

    boot_error = wakeup_secondary_via_INIT(apicid, start_eip);

    if (!boot_error) {
        /*
         * allow APs to start initializing.
         */
        Dprintk("Before Callout %d.\n", cpu);
        set_bit(cpu, &cpu_callout_map);
        Dprintk("After Callout %d.\n", cpu);

        /*
         * Wait 5s total for a response
         */
        for (timeout = 0; timeout < 50000; timeout++) {
            if (test_bit(cpu, &cpu_callin_map))
                break;	/* It has booted */
            udelay(100);
        }

        if (test_bit(cpu, &cpu_callin_map)) {
            /* number CPUs logically, starting from 1 (BSP is 0) */
            printk("CPU%d has booted.\n", cpu);
        } else {
            boot_error= 1;
            if (*((volatile unsigned int *)phys_to_virt(start_eip))
                == 0xA5A5A5A5)
				/* trampoline started but...? */
                printk("Stuck ??\n");
            else
				/* trampoline code not run */
                printk("Not responding.\n");
#if APIC_DEBUG
            inquire_remote_apic(apicid);
#endif
        }
    }
    if (boot_error) {
        /* Try to put things back the way they were before ... */
        unmap_cpu_to_boot_apicid(cpu, apicid);
        clear_bit(cpu, &cpu_callout_map); /* was set here (do_boot_cpu()) */
        clear_bit(cpu, &cpu_initialized); /* was set by cpu_init() */
        clear_bit(cpu, &cpu_online_map);  /* was set in smp_callin() */
        cpucount--;
    }
}


/*
 * Cycle through the processors sending APIC IPIs to boot each.
 */

static int boot_cpu_logical_apicid;
/* Where the IO area was mapped on multiquad, always 0 otherwise */
void *xquad_portio = NULL;

void __init smp_boot_cpus(void)
{
    int apicid, bit;

    /* Initialize the logical to physical CPU number mapping */
    init_cpu_to_apicid();

    /*
     * Setup boot CPU information
     */
    smp_store_cpu_info(0); /* Final full version of the data */
    printk("CPU%d booted\n", 0);

    /*
     * We have the boot CPU online for sure.
     */
    set_bit(0, &cpu_online_map);
    boot_cpu_logical_apicid = logical_smp_processor_id();
    map_cpu_to_boot_apicid(0, boot_cpu_apicid);

    /*
     * If we couldnt find an SMP configuration at boot time,
     * get out of here now!
     */
    if (!smp_found_config) {
        printk("SMP motherboard not detected.\n");
        io_apic_irqs = 0;
        cpu_online_map = phys_cpu_present_map = 1;
        smp_num_cpus = 1;
        if (APIC_init_uniprocessor())
            printk("Local APIC not detected."
                   " Using dummy APIC emulation.\n");
        goto smp_done;
    }

    /*
     * Should not be necessary because the MP table should list the boot
     * CPU too, but we do it for the sake of robustness anyway.
     */
    if (!test_bit(boot_cpu_physical_apicid, &phys_cpu_present_map)) {
        printk("weird, boot CPU (#%d) not listed by the BIOS.\n",
               boot_cpu_physical_apicid);
        phys_cpu_present_map |= (1 << hard_smp_processor_id());
    }

    /*
     * If we couldn't find a local APIC, then get out of here now!
     */
    if (APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid]) &&
        !test_bit(X86_FEATURE_APIC, boot_cpu_data.x86_capability)) {
        printk("BIOS bug, local APIC #%d not detected!...\n",
               boot_cpu_physical_apicid);
        printk("... forcing use of dummy APIC emulation. (tell your hw vendor)\n");
        io_apic_irqs = 0;
        cpu_online_map = phys_cpu_present_map = 1;
        smp_num_cpus = 1;
        goto smp_done;
    }

    verify_local_APIC();

    /*
     * If SMP should be disabled, then really disable it!
     */
    if (!max_cpus) {
        smp_found_config = 0;
        printk("SMP mode deactivated, forcing use of dummy APIC emulation.\n");
        io_apic_irqs = 0;
        cpu_online_map = phys_cpu_present_map = 1;
        smp_num_cpus = 1;
        goto smp_done;
    }

    connect_bsp_APIC();
    setup_local_APIC();

    if (GET_APIC_ID(apic_read(APIC_ID)) != boot_cpu_physical_apicid)
        BUG();

    /*
     * Scan the CPU present map and fire up the other CPUs via do_boot_cpu
     *
     * In clustered apic mode, phys_cpu_present_map is a constructed thus:
     * bits 0-3 are quad0, 4-7 are quad1, etc. A perverse twist on the 
     * clustered apic ID.
     */
    Dprintk("CPU present map: %lx\n", phys_cpu_present_map);

    for (bit = 0; bit < NR_CPUS; bit++) {
        apicid = cpu_present_to_apicid(bit);
        /*
         * Don't even attempt to start the boot CPU!
         */
        if (apicid == boot_cpu_apicid)
            continue;

        /* 
         * Don't start hyperthreads if option noht requested.
         */
        if (opt_noht && (apicid & (ht_per_core - 1)))
            continue;

        if (!(phys_cpu_present_map & (1 << bit)))
            continue;
        if ((max_cpus >= 0) && (max_cpus <= cpucount+1))
            continue;

        do_boot_cpu(apicid);

        /*
         * Make sure we unmap all failed CPUs
         */
        if ((boot_apicid_to_cpu(apicid) == -1) &&
            (phys_cpu_present_map & (1 << bit)))
            printk("CPU #%d not responding - cannot use it.\n",
                   apicid);
    }

    /*
     * Cleanup possible dangling ends...
     */
    /*
     * Install writable page 0 entry to set BIOS data area.
     */
    local_flush_tlb();

    /*
     * Paranoid:  Set warm reset code and vector here back
     * to default values.
     */
    CMOS_WRITE(0, 0xf);

    *((volatile long *) phys_to_virt(0x467)) = 0;

    if (!cpucount) {
        printk("Error: only one processor found.\n");
    } else {
        printk("Total of %d processors activated.\n", cpucount+1);
    }
    smp_num_cpus = cpucount + 1;

    Dprintk("Boot done.\n");

    /*
     * Here we can be sure that there is an IO-APIC in the system. Let's
     * go and set it up:
     */
    if ( nr_ioapics ) setup_IO_APIC();

    /* Set up all local APIC timers in the system. */
    setup_APIC_clocks();

    /* Synchronize the TSC with the AP(s). */
    if ( cpucount ) synchronize_tsc_bp();

 smp_done:
    ;
}

#endif /* CONFIG_SMP */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
