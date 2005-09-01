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
 *		Alan Cox	:	By repeated request 8) - Total BogoMIPS report.
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
 *		Dave Jones	:	Report invalid combinations of Athlon CPUs.
*		Rusty Russell	:	Hacked into shape for new "hotplug" boot process. */

#include <linux/module.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/smp_lock.h>
#include <linux/irq.h>
#include <linux/bootmem.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/percpu.h>

#include <linux/delay.h>
#include <linux/mc146818rtc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/arch_hooks.h>

#include <asm/smp_alt.h>

#ifndef CONFIG_X86_IO_APIC
#define Dprintk(args...)
#endif
#include <mach_wakecpu.h>
#include <smpboot_hooks.h>

#include <asm-xen/evtchn.h>

/* Set if we find a B stepping CPU */
static int __initdata smp_b_stepping;

/* Number of siblings per CPU package */
int smp_num_siblings = 1;
int phys_proc_id[NR_CPUS]; /* Package ID of each logical CPU */
EXPORT_SYMBOL(phys_proc_id);
int cpu_core_id[NR_CPUS]; /* Core ID of each logical CPU */
EXPORT_SYMBOL(cpu_core_id);

/* bitmap of online cpus */
cpumask_t cpu_online_map;

cpumask_t cpu_callin_map;
cpumask_t cpu_callout_map;
static cpumask_t smp_commenced_mask;

/* Per CPU bogomips and other parameters */
struct cpuinfo_x86 cpu_data[NR_CPUS] __cacheline_aligned;

u8 x86_cpu_to_apicid[NR_CPUS] =
			{ [0 ... NR_CPUS-1] = 0xff };
EXPORT_SYMBOL(x86_cpu_to_apicid);

#if 0
/*
 * Trampoline 80x86 program as an array.
 */

extern unsigned char trampoline_data [];
extern unsigned char trampoline_end  [];
static unsigned char *trampoline_base;
static int trampoline_exec;
#endif

#ifdef CONFIG_HOTPLUG_CPU
/* State of each CPU. */
DEFINE_PER_CPU(int, cpu_state) = { 0 };
#endif

static DEFINE_PER_CPU(int, resched_irq);
static DEFINE_PER_CPU(int, callfunc_irq);
static char resched_name[NR_CPUS][15];
static char callfunc_name[NR_CPUS][15];

#if 0
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
#endif

static void map_cpu_to_logical_apicid(void);

/*
 * We are called very early to get the low memory for the
 * SMP bootup trampoline page.
 */
void __init smp_alloc_memory(void)
{
#if 0
	trampoline_base = (void *) alloc_bootmem_low_pages(PAGE_SIZE);
	/*
	 * Has to be in very low memory so we can execute
	 * real-mode AP code.
	 */
	if (__pa(trampoline_base) >= 0x9F000)
		BUG();
	/*
	 * Make the SMP trampoline executable:
	 */
	trampoline_exec = set_kernel_exec((unsigned long)trampoline_base, 1);
#endif
}

/*
 * The bootstrap kernel entry code has set these up. Save them for
 * a given CPU
 */

static void __init smp_store_cpu_info(int id)
{
	struct cpuinfo_x86 *c = cpu_data + id;

	*c = boot_cpu_data;
	if (id!=0)
		identify_cpu(c);
	/*
	 * Mask B, Pentium, but not Pentium MMX
	 */
	if (c->x86_vendor == X86_VENDOR_INTEL &&
	    c->x86 == 5 &&
	    c->x86_mask >= 1 && c->x86_mask <= 4 &&
	    c->x86_model <= 3)
		/*
		 * Remember we have B step Pentia with bugs
		 */
		smp_b_stepping = 1;

	/*
	 * Certain Athlons might work (for various values of 'work') in SMP
	 * but they are not certified as MP capable.
	 */
	if ((c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 6)) {

		/* Athlon 660/661 is valid. */	
		if ((c->x86_model==6) && ((c->x86_mask==0) || (c->x86_mask==1)))
			goto valid_k7;

		/* Duron 670 is valid */
		if ((c->x86_model==7) && (c->x86_mask==0))
			goto valid_k7;

		/*
		 * Athlon 662, Duron 671, and Athlon >model 7 have capability bit.
		 * It's worth noting that the A5 stepping (662) of some Athlon XP's
		 * have the MP bit set.
		 * See http://www.heise.de/newsticker/data/jow-18.10.01-000 for more.
		 */
		if (((c->x86_model==6) && (c->x86_mask>=2)) ||
		    ((c->x86_model==7) && (c->x86_mask>=1)) ||
		     (c->x86_model> 7))
			if (cpu_has_mp)
				goto valid_k7;

		/* If we get here, it's not a certified SMP capable AMD system. */
		tainted |= TAINT_UNSAFE_SMP;
	}

valid_k7:
	;
}

#if 0
/*
 * TSC synchronization.
 *
 * We first check whether all CPUs have their TSC's synchronized,
 * then we print a warning if not, and always resync.
 */

static atomic_t tsc_start_flag = ATOMIC_INIT(0);
static atomic_t tsc_count_start = ATOMIC_INIT(0);
static atomic_t tsc_count_stop = ATOMIC_INIT(0);
static unsigned long long tsc_values[NR_CPUS];

#define NR_LOOPS 5

static void __init synchronize_tsc_bp (void)
{
	int i;
	unsigned long long t0;
	unsigned long long sum, avg;
	long long delta;
	unsigned long one_usec;
	int buggy = 0;

	printk(KERN_INFO "checking TSC synchronization across %u CPUs: ", num_booting_cpus());

	/* convert from kcyc/sec to cyc/usec */
	one_usec = cpu_khz / 1000;

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
		while (atomic_read(&tsc_count_start) != num_booting_cpus()-1)
			mb();
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
		while (atomic_read(&tsc_count_stop) != num_booting_cpus()-1)
			mb();
		atomic_set(&tsc_count_start, 0);
		wmb();
		atomic_inc(&tsc_count_stop);
	}

	sum = 0;
	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_isset(i, cpu_callout_map)) {
			t0 = tsc_values[i];
			sum += t0;
		}
	}
	avg = sum;
	do_div(avg, num_booting_cpus());

	sum = 0;
	for (i = 0; i < NR_CPUS; i++) {
		if (!cpu_isset(i, cpu_callout_map))
			continue;
		delta = tsc_values[i] - avg;
		if (delta < 0)
			delta = -delta;
		/*
		 * We report bigger than 2 microseconds clock differences.
		 */
		if (delta > 2*one_usec) {
			long realdelta;
			if (!buggy) {
				buggy = 1;
				printk("\n");
			}
			realdelta = delta;
			do_div(realdelta, one_usec);
			if (tsc_values[i] < avg)
				realdelta = -realdelta;

			printk(KERN_INFO "CPU#%d had %ld usecs TSC skew, fixed it up.\n", i, realdelta);
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
	 * Not every cpu is online at the time
	 * this gets called, so we first wait for the BP to
	 * finish SMP initialization:
	 */
	while (!atomic_read(&tsc_start_flag)) mb();

	for (i = 0; i < NR_LOOPS; i++) {
		atomic_inc(&tsc_count_start);
		while (atomic_read(&tsc_count_start) != num_booting_cpus())
			mb();

		rdtscll(tsc_values[smp_processor_id()]);
		if (i == NR_LOOPS-1)
			write_tsc(0, 0);

		atomic_inc(&tsc_count_stop);
		while (atomic_read(&tsc_count_stop) != num_booting_cpus()) mb();
	}
}
#undef NR_LOOPS
#endif

extern void calibrate_delay(void);

static atomic_t init_deasserted;

static void __init smp_callin(void)
{
	int cpuid, phys_id;
	unsigned long timeout;

#if 0
	/*
	 * If waken up by an INIT in an 82489DX configuration
	 * we may get here before an INIT-deassert IPI reaches
	 * our local APIC.  We have to wait for the IPI or we'll
	 * lock up on an APIC access.
	 */
	wait_for_init_deassert(&init_deasserted);
#endif

	/*
	 * (This works even if the APIC is not enabled.)
	 */
	phys_id = smp_processor_id();
	cpuid = smp_processor_id();
	if (cpu_isset(cpuid, cpu_callin_map)) {
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

	/*
	 * Waiting 2s total for startup (udelay is not yet working)
	 */
	timeout = jiffies + 2*HZ;
	while (time_before(jiffies, timeout)) {
		/*
		 * Has the boot CPU finished it's STARTUP sequence?
		 */
		if (cpu_isset(cpuid, cpu_callout_map))
			break;
		rep_nop();
	}

	if (!time_before(jiffies, timeout)) {
		printk("BUG: CPU%d started up but did not get a callout!\n",
			cpuid);
		BUG();
	}

#if 0
	/*
	 * the boot CPU has finished the init stage and is spinning
	 * on callin_map until we finish. We are free to set up this
	 * CPU, first the APIC. (this is probably redundant on most
	 * boards)
	 */

	Dprintk("CALLIN, before setup_local_APIC().\n");
	smp_callin_clear_local_apic();
	setup_local_APIC();
#endif
	map_cpu_to_logical_apicid();

	/*
	 * Get our bogomips.
	 */
	calibrate_delay();
	Dprintk("Stack at about %p\n",&cpuid);

	/*
	 * Save our processor parameters
	 */
 	smp_store_cpu_info(cpuid);

#if 0
	disable_APIC_timer();
#endif

	/*
	 * Allow the master to continue.
	 */
	cpu_set(cpuid, cpu_callin_map);

#if 0
	/*
	 *      Synchronize the TSC with the BP
	 */
	if (cpu_has_tsc && cpu_khz)
		synchronize_tsc_ap();
#endif
}

static int cpucount;


static irqreturn_t ldebug_interrupt(
	int irq, void *dev_id, struct pt_regs *regs)
{
	return IRQ_HANDLED;
}

static DEFINE_PER_CPU(int, ldebug_irq);
static char ldebug_name[NR_CPUS][15];

void ldebug_setup(void)
{
	int cpu = smp_processor_id();

	per_cpu(ldebug_irq, cpu) = bind_virq_to_irq(VIRQ_DEBUG);
	sprintf(ldebug_name[cpu], "ldebug%d", cpu);
	BUG_ON(request_irq(per_cpu(ldebug_irq, cpu), ldebug_interrupt,
	                   SA_INTERRUPT, ldebug_name[cpu], NULL));
}


extern void local_setup_timer(void);

/*
 * Activate a secondary processor.
 */
static void __init start_secondary(void *unused)
{
	/*
	 * Dont put anything before smp_callin(), SMP
	 * booting is too fragile that we want to limit the
	 * things done here to the most necessary things.
	 */
	cpu_init();
	smp_callin();
	while (!cpu_isset(smp_processor_id(), smp_commenced_mask))
		rep_nop();
	local_setup_timer();
	ldebug_setup();
	smp_intr_init();
	local_irq_enable();
	/*
	 * low-memory mappings have been cleared, flush them from
	 * the local TLBs too.
	 */
	local_flush_tlb();
	cpu_set(smp_processor_id(), cpu_online_map);

	/* We can take interrupts now: we're officially "up". */
	local_irq_enable();

	wmb();
	cpu_idle();
}

/*
 * Everything has been set up for the secondary
 * CPUs - they just need to reload everything
 * from the task structure
 * This function must not return.
 */
void __init initialize_secondary(void)
{
	/*
	 * We don't actually need to load the full TSS,
	 * basically just the stack pointer and the eip.
	 */

	asm volatile(
		"movl %0,%%esp\n\t"
		"jmp *%1"
		:
		:"r" (current->thread.esp),"r" (current->thread.eip));
}

extern struct {
	void * esp;
	unsigned short ss;
} stack_start;

#ifdef CONFIG_NUMA

/* which logical CPUs are on which nodes */
cpumask_t node_2_cpu_mask[MAX_NUMNODES] =
				{ [0 ... MAX_NUMNODES-1] = CPU_MASK_NONE };
/* which node each logical CPU is on */
int cpu_2_node[NR_CPUS] = { [0 ... NR_CPUS-1] = 0 };
EXPORT_SYMBOL(cpu_2_node);

/* set up a mapping between cpu and node. */
static inline void map_cpu_to_node(int cpu, int node)
{
	printk("Mapping cpu %d to node %d\n", cpu, node);
	cpu_set(cpu, node_2_cpu_mask[node]);
	cpu_2_node[cpu] = node;
}

/* undo a mapping between cpu and node. */
static inline void unmap_cpu_to_node(int cpu)
{
	int node;

	printk("Unmapping cpu %d from all nodes\n", cpu);
	for (node = 0; node < MAX_NUMNODES; node ++)
		cpu_clear(cpu, node_2_cpu_mask[node]);
	cpu_2_node[cpu] = 0;
}
#else /* !CONFIG_NUMA */

#define map_cpu_to_node(cpu, node)	({})
#define unmap_cpu_to_node(cpu)	({})

#endif /* CONFIG_NUMA */

u8 cpu_2_logical_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

static void map_cpu_to_logical_apicid(void)
{
	int cpu = smp_processor_id();
	int apicid = smp_processor_id();

	cpu_2_logical_apicid[cpu] = apicid;
	map_cpu_to_node(cpu, apicid_to_node(apicid));
}

static void unmap_cpu_to_logical_apicid(int cpu)
{
	cpu_2_logical_apicid[cpu] = BAD_APICID;
	unmap_cpu_to_node(cpu);
}

#if APIC_DEBUG
static inline void __inquire_remote_apic(int apicid)
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

#if 0
#ifdef WAKE_SECONDARY_VIA_NMI
/* 
 * Poke the other CPU in the eye via NMI to wake it up. Remember that the normal
 * INIT, INIT, STARTUP sequence will reset the chip hard for us, and this
 * won't ... remember to clear down the APIC, etc later.
 */
static int __init
wakeup_secondary_cpu(int logical_apicid, unsigned long start_eip)
{
	unsigned long send_status = 0, accept_status = 0;
	int timeout, maxlvt;

	/* Target chip */
	apic_write_around(APIC_ICR2, SET_APIC_DEST_FIELD(logical_apicid));

	/* Boot on the stack */
	/* Kick the second */
	apic_write_around(APIC_ICR, APIC_DM_NMI | APIC_DEST_LOGICAL);

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
	maxlvt = get_maxlvt();
	if (maxlvt > 3) {
		apic_read_around(APIC_SPIV);
		apic_write(APIC_ESR, 0);
	}
	accept_status = (apic_read(APIC_ESR) & 0xEF);
	Dprintk("NMI sent.\n");

	if (send_status)
		printk("APIC never delivered???\n");
	if (accept_status)
		printk("APIC delivery error (%lx).\n", accept_status);

	return (send_status | accept_status);
}
#endif	/* WAKE_SECONDARY_VIA_NMI */

#ifdef WAKE_SECONDARY_VIA_INIT
static int __init
wakeup_secondary_cpu(int phys_apicid, unsigned long start_eip)
{
	unsigned long send_status = 0, accept_status = 0;
	int maxlvt, timeout, num_starts, j;

	/*
	 * Be paranoid about clearing APIC errors.
	 */
	if (APIC_INTEGRATED(apic_version[phys_apicid])) {
		apic_read_around(APIC_SPIV);
		apic_write(APIC_ESR, 0);
		apic_read(APIC_ESR);
	}

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
#endif	/* WAKE_SECONDARY_VIA_INIT */
#endif

extern cpumask_t cpu_initialized;

static int __init do_boot_cpu(int apicid)
/*
 * NOTE - on most systems this is a PHYSICAL apic ID, but on multiquad
 * (ie clustered apic addressing mode), this is a LOGICAL apic ID.
 * Returns zero if CPU booted OK, else error code from wakeup_secondary_cpu.
 */
{
	struct task_struct *idle;
	unsigned long boot_error;
	int timeout, cpu;
	unsigned long start_eip;
#if 0
	unsigned short nmi_high = 0, nmi_low = 0;
#endif
	vcpu_guest_context_t ctxt;
	extern void startup_32_smp(void);
	extern void hypervisor_callback(void);
	extern void failsafe_callback(void);
	extern void smp_trap_init(trap_info_t *);
	int i;

	cpu = ++cpucount;
	/*
	 * We can't use kernel_thread since we must avoid to
	 * reschedule the child.
	 */
	idle = fork_idle(cpu);
	if (IS_ERR(idle))
		panic("failed fork for CPU %d", cpu);
	idle->thread.eip = (unsigned long) start_secondary;
	/* start_eip had better be page-aligned! */
	start_eip = (unsigned long)startup_32_smp;

	/* So we see what's up   */
	printk("Booting processor %d/%d eip %lx\n", cpu, apicid, start_eip);
	/* Stack for startup_32 can be just as for start_secondary onwards */
	stack_start.esp = (void *) idle->thread.esp;

	irq_ctx_init(cpu);

	/*
	 * This grunge runs the startup process for
	 * the targeted processor.
	 */

	atomic_set(&init_deasserted, 0);

#if 1
	cpu_gdt_descr[cpu].address = __get_free_page(GFP_KERNEL|__GFP_ZERO);
	BUG_ON(cpu_gdt_descr[0].size > PAGE_SIZE);
	cpu_gdt_descr[cpu].size = cpu_gdt_descr[0].size;
	memcpy((void *)cpu_gdt_descr[cpu].address,
	       (void *)cpu_gdt_descr[0].address, cpu_gdt_descr[0].size);

	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.user_regs.ds = __USER_DS;
	ctxt.user_regs.es = __USER_DS;
	ctxt.user_regs.fs = 0;
	ctxt.user_regs.gs = 0;
	ctxt.user_regs.ss = __KERNEL_DS;
	ctxt.user_regs.cs = __KERNEL_CS;
	ctxt.user_regs.eip = start_eip;
	ctxt.user_regs.esp = idle->thread.esp;
#define X86_EFLAGS_IOPL_RING1 0x1000
	ctxt.user_regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_IOPL_RING1;

	/* FPU is set up to default initial state. */
	memset(&ctxt.fpu_ctxt, 0, sizeof(ctxt.fpu_ctxt));

	/* Virtual IDT is empty at start-of-day. */
	for ( i = 0; i < 256; i++ )
	{
		ctxt.trap_ctxt[i].vector = i;
		ctxt.trap_ctxt[i].cs     = FLAT_KERNEL_CS;
	}
	smp_trap_init(ctxt.trap_ctxt);

	/* No LDT. */
	ctxt.ldt_ents = 0;

	{
		unsigned long va;
		int f;

		for (va = cpu_gdt_descr[cpu].address, f = 0;
		     va < cpu_gdt_descr[cpu].address + cpu_gdt_descr[cpu].size;
		     va += PAGE_SIZE, f++) {
			ctxt.gdt_frames[f] = virt_to_mfn(va);
			make_page_readonly((void *)va);
		}
		ctxt.gdt_ents = cpu_gdt_descr[cpu].size / 8;
	}

	/* Ring 1 stack is the initial stack. */
	ctxt.kernel_ss = __KERNEL_DS;
	ctxt.kernel_sp = idle->thread.esp;

	/* Callback handlers. */
	ctxt.event_callback_cs     = __KERNEL_CS;
	ctxt.event_callback_eip    = (unsigned long)hypervisor_callback;
	ctxt.failsafe_callback_cs  = __KERNEL_CS;
	ctxt.failsafe_callback_eip = (unsigned long)failsafe_callback;

	ctxt.ctrlreg[3] = virt_to_mfn(swapper_pg_dir) << PAGE_SHIFT;

	boot_error = HYPERVISOR_boot_vcpu(cpu, &ctxt);
	if (boot_error)
		printk("boot error: %ld\n", boot_error);

	if (!boot_error) {
		/*
		 * allow APs to start initializing.
		 */
		Dprintk("Before Callout %d.\n", cpu);
		cpu_set(cpu, cpu_callout_map);
		Dprintk("After Callout %d.\n", cpu);

		/*
		 * Wait 5s total for a response
		 */
		for (timeout = 0; timeout < 50000; timeout++) {
			if (cpu_isset(cpu, cpu_callin_map))
				break;	/* It has booted */
			udelay(100);
		}

		if (cpu_isset(cpu, cpu_callin_map)) {
			/* number CPUs logically, starting from 1 (BSP is 0) */
			Dprintk("OK.\n");
			printk("CPU%d: ", cpu);
			print_cpu_info(&cpu_data[cpu]);
			Dprintk("CPU has booted.\n");
		} else {
			boot_error= 1;
		}
	}
	x86_cpu_to_apicid[cpu] = apicid;
	if (boot_error) {
		/* Try to put things back the way they were before ... */
		unmap_cpu_to_logical_apicid(cpu);
		cpu_clear(cpu, cpu_callout_map); /* was set here (do_boot_cpu()) */
		cpu_clear(cpu, cpu_initialized); /* was set by cpu_init() */
		cpucount--;
	}

#else
	Dprintk("Setting warm reset code and vector.\n");

	store_NMI_vector(&nmi_high, &nmi_low);

	smpboot_setup_warm_reset_vector(start_eip);

	/*
	 * Starting actual IPI sequence...
	 */
	boot_error = wakeup_secondary_cpu(apicid, start_eip);

	if (!boot_error) {
		/*
		 * allow APs to start initializing.
		 */
		Dprintk("Before Callout %d.\n", cpu);
		cpu_set(cpu, cpu_callout_map);
		Dprintk("After Callout %d.\n", cpu);

		/*
		 * Wait 5s total for a response
		 */
		for (timeout = 0; timeout < 50000; timeout++) {
			if (cpu_isset(cpu, cpu_callin_map))
				break;	/* It has booted */
			udelay(100);
		}

		if (cpu_isset(cpu, cpu_callin_map)) {
			/* number CPUs logically, starting from 1 (BSP is 0) */
			Dprintk("OK.\n");
			printk("CPU%d: ", cpu);
			print_cpu_info(&cpu_data[cpu]);
			Dprintk("CPU has booted.\n");
		} else {
			boot_error= 1;
			if (*((volatile unsigned char *)trampoline_base)
					== 0xA5)
				/* trampoline started but...? */
				printk("Stuck ??\n");
			else
				/* trampoline code not run */
				printk("Not responding.\n");
			inquire_remote_apic(apicid);
		}
	}
	x86_cpu_to_apicid[cpu] = apicid;
	if (boot_error) {
		/* Try to put things back the way they were before ... */
		unmap_cpu_to_logical_apicid(cpu);
		cpu_clear(cpu, cpu_callout_map); /* was set here (do_boot_cpu()) */
		cpu_clear(cpu, cpu_initialized); /* was set by cpu_init() */
		cpucount--;
	}

	/* mark "stuck" area as not stuck */
	*((volatile unsigned long *)trampoline_base) = 0;
#endif

	return boot_error;
}

static void smp_tune_scheduling (void)
{
	unsigned long cachesize;       /* kB   */
	unsigned long bandwidth = 350; /* MB/s */
	/*
	 * Rough estimation for SMP scheduling, this is the number of
	 * cycles it takes for a fully memory-limited process to flush
	 * the SMP-local cache.
	 *
	 * (For a P5 this pretty much means we will choose another idle
	 *  CPU almost always at wakeup time (this is due to the small
	 *  L1 cache), on PIIs it's around 50-100 usecs, depending on
	 *  the cache size)
	 */

	if (!cpu_khz) {
		/*
		 * this basically disables processor-affinity
		 * scheduling on SMP without a TSC.
		 */
		return;
	} else {
		cachesize = boot_cpu_data.x86_cache_size;
		if (cachesize == -1) {
			cachesize = 16; /* Pentiums, 2x8kB cache */
			bandwidth = 100;
		}
	}
}

/*
 * Cycle through the processors sending APIC IPIs to boot each.
 */

#if 0
static int boot_cpu_logical_apicid;
#endif
/* Where the IO area was mapped on multiquad, always 0 otherwise */
void *xquad_portio;

cpumask_t cpu_sibling_map[NR_CPUS] __cacheline_aligned;
cpumask_t cpu_core_map[NR_CPUS] __cacheline_aligned;
EXPORT_SYMBOL(cpu_core_map);

static void __init smp_boot_cpus(unsigned int max_cpus)
{
	int cpu, kicked;
	unsigned long bogosum = 0;
#if 0
	int apicid, bit;
#endif

	/*
	 * Setup boot CPU information
	 */
	smp_store_cpu_info(0); /* Final full version of the data */
	printk("CPU%d: ", 0);
	print_cpu_info(&cpu_data[0]);

#if 0
	boot_cpu_physical_apicid = GET_APIC_ID(apic_read(APIC_ID));
	boot_cpu_logical_apicid = logical_smp_processor_id();
	x86_cpu_to_apicid[0] = boot_cpu_physical_apicid;
#else
	// boot_cpu_physical_apicid = 0;
	// boot_cpu_logical_apicid = 0;
	x86_cpu_to_apicid[0] = 0;
#endif

	current_thread_info()->cpu = 0;
	smp_tune_scheduling();
	cpus_clear(cpu_sibling_map[0]);
	cpu_set(0, cpu_sibling_map[0]);

	cpus_clear(cpu_core_map[0]);
	cpu_set(0, cpu_core_map[0]);

#ifdef CONFIG_X86_IO_APIC
	/*
	 * If we couldn't find an SMP configuration at boot time,
	 * get out of here now!
	 */
	if (!smp_found_config && !acpi_lapic) {
		printk(KERN_NOTICE "SMP motherboard not detected.\n");
		smpboot_clear_io_apic_irqs();
#if 0
		phys_cpu_present_map = physid_mask_of_physid(0);
#endif
#ifdef CONFIG_X86_LOCAL_APIC
		if (APIC_init_uniprocessor())
			printk(KERN_NOTICE "Local APIC not detected."
					   " Using dummy APIC emulation.\n");
#endif
		map_cpu_to_logical_apicid();
		cpu_set(0, cpu_sibling_map[0]);
		cpu_set(0, cpu_core_map[0]);
		return;
	}
#endif

#if 0
	/*
	 * Should not be necessary because the MP table should list the boot
	 * CPU too, but we do it for the sake of robustness anyway.
	 * Makes no sense to do this check in clustered apic mode, so skip it
	 */
	if (!check_phys_apicid_present(boot_cpu_physical_apicid)) {
		printk("weird, boot CPU (#%d) not listed by the BIOS.\n",
				boot_cpu_physical_apicid);
		physid_set(hard_smp_processor_id(), phys_cpu_present_map);
	}

	/*
	 * If we couldn't find a local APIC, then get out of here now!
	 */
	if (APIC_INTEGRATED(apic_version[boot_cpu_physical_apicid]) && !cpu_has_apic) {
		printk(KERN_ERR "BIOS bug, local APIC #%d not detected!...\n",
			boot_cpu_physical_apicid);
		printk(KERN_ERR "... forcing use of dummy APIC emulation. (tell your hw vendor)\n");
		smpboot_clear_io_apic_irqs();
		phys_cpu_present_map = physid_mask_of_physid(0);
		cpu_set(0, cpu_sibling_map[0]);
		cpu_set(0, cpu_core_map[0]);
		cpu_set(0, cpu_sibling_map[0]);
		cpu_set(0, cpu_core_map[0]);
		return;
	}

	verify_local_APIC();
#endif

	/*
	 * If SMP should be disabled, then really disable it!
	 */
	if (!max_cpus) {
		HYPERVISOR_shared_info->n_vcpu = 1;
		printk(KERN_INFO "SMP mode deactivated, forcing use of dummy APIC emulation.\n");
		smpboot_clear_io_apic_irqs();
#if 0
		phys_cpu_present_map = physid_mask_of_physid(0);
#endif
		return;
	}

	smp_intr_init();

#if 0
	connect_bsp_APIC();
	setup_local_APIC();
#endif
	map_cpu_to_logical_apicid();
#if 0


	setup_portio_remap();

	/*
	 * Scan the CPU present map and fire up the other CPUs via do_boot_cpu
	 *
	 * In clustered apic mode, phys_cpu_present_map is a constructed thus:
	 * bits 0-3 are quad0, 4-7 are quad1, etc. A perverse twist on the 
	 * clustered apic ID.
	 */
	Dprintk("CPU present map: %lx\n", physids_coerce(phys_cpu_present_map));
#endif
	Dprintk("CPU present map: %lx\n",
		(1UL << HYPERVISOR_shared_info->n_vcpu) - 1);

	kicked = 1;
	for (cpu = 1; kicked < NR_CPUS &&
		     cpu < HYPERVISOR_shared_info->n_vcpu; cpu++) {
		if (max_cpus <= cpucount+1)
			continue;

#ifdef CONFIG_SMP_ALTERNATIVES
		if (kicked == 1)
			prepare_for_smp();
#endif
		if (do_boot_cpu(cpu))
			printk("CPU #%d not responding - cannot use it.\n",
								cpu);
		else
			++kicked;
	}

#if 0
	/*
	 * Cleanup possible dangling ends...
	 */
	smpboot_restore_warm_reset_vector();
#endif

	/*
	 * Allow the user to impress friends.
	 */
	Dprintk("Before bogomips.\n");
	for (cpu = 0; cpu < NR_CPUS; cpu++)
		if (cpu_isset(cpu, cpu_callout_map))
			bogosum += cpu_data[cpu].loops_per_jiffy;
	printk(KERN_INFO
		"Total of %d processors activated (%lu.%02lu BogoMIPS).\n",
		cpucount+1,
		bogosum/(500000/HZ),
		(bogosum/(5000/HZ))%100);
	
	Dprintk("Before bogocount - setting activated=1.\n");

	if (smp_b_stepping)
		printk(KERN_WARNING "WARNING: SMP operation may be unreliable with B stepping processors.\n");

	/*
	 * Don't taint if we are running SMP kernel on a single non-MP
	 * approved Athlon
	 */
	if (tainted & TAINT_UNSAFE_SMP) {
		if (cpucount)
			printk (KERN_INFO "WARNING: This combination of AMD processors is not suitable for SMP.\n");
		else
			tainted &= ~TAINT_UNSAFE_SMP;
	}

	Dprintk("Boot done.\n");

	/*
	 * construct cpu_sibling_map[], so that we can tell sibling CPUs
	 * efficiently.
	 */
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		cpus_clear(cpu_sibling_map[cpu]);
		cpus_clear(cpu_core_map[cpu]);
	}

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		struct cpuinfo_x86 *c = cpu_data + cpu;
		int siblings = 0;
		int i;
		if (!cpu_isset(cpu, cpu_callout_map))
			continue;

		if (smp_num_siblings > 1) {
			for (i = 0; i < NR_CPUS; i++) {
				if (!cpu_isset(i, cpu_callout_map))
					continue;
				if (cpu_core_id[cpu] == cpu_core_id[i]) {
					siblings++;
					cpu_set(i, cpu_sibling_map[cpu]);
				}
			}
		} else {
			siblings++;
			cpu_set(cpu, cpu_sibling_map[cpu]);
		}

		if (siblings != smp_num_siblings) {
			printk(KERN_WARNING "WARNING: %d siblings found for CPU%d, should be %d\n", siblings, cpu, smp_num_siblings);
			smp_num_siblings = siblings;
		}

		if (c->x86_num_cores > 1) {
			for (i = 0; i < NR_CPUS; i++) {
				if (!cpu_isset(i, cpu_callout_map))
					continue;
				if (phys_proc_id[cpu] == phys_proc_id[i]) {
					cpu_set(i, cpu_core_map[cpu]);
				}
			}
		} else {
			cpu_core_map[cpu] = cpu_sibling_map[cpu];
		}
	}

	smpboot_setup_io_apic();

#if 0
	setup_boot_APIC_clock();

	/*
	 * Synchronize the TSC with the AP
	 */
	if (cpu_has_tsc && cpucount && cpu_khz)
		synchronize_tsc_bp();
#endif
}

/* These are wrappers to interface to the new boot process.  Someone
   who understands all this stuff should rewrite it properly. --RR 15/Jul/02 */
void __init smp_prepare_cpus(unsigned int max_cpus)
{
	smp_commenced_mask = cpumask_of_cpu(0);
	cpu_callin_map = cpumask_of_cpu(0);
	mb();
	smp_boot_cpus(max_cpus);
}

void __devinit smp_prepare_boot_cpu(void)
{
	cpu_set(smp_processor_id(), cpu_online_map);
	cpu_set(smp_processor_id(), cpu_callout_map);
}

#ifdef CONFIG_HOTPLUG_CPU
#include <asm-xen/xenbus.h>
/* hotplug down/up funtion pointer and target vcpu */
struct vcpu_hotplug_handler_t {
	void (*fn) (int vcpu);
	u32 vcpu;
};
static struct vcpu_hotplug_handler_t vcpu_hotplug_handler;

static int vcpu_hotplug_cpu_process(void *unused)
{
	struct vcpu_hotplug_handler_t *handler = &vcpu_hotplug_handler;

	if (handler->fn) {
		(*(handler->fn)) (handler->vcpu);
		handler->fn = NULL;
	}
	return 0;
}

static void __vcpu_hotplug_handler(void *unused)
{
	int err;

	err = kernel_thread(vcpu_hotplug_cpu_process,
			    NULL, CLONE_FS | CLONE_FILES);
	if (err < 0)
		printk(KERN_ALERT "Error creating hotplug_cpu process!\n");
}

static void handle_vcpu_hotplug_event(struct xenbus_watch *, const char *);
static struct notifier_block xsn_cpu;

/* xenbus watch struct */
static struct xenbus_watch cpu_watch = {
	.node = "cpu",
	.callback = handle_vcpu_hotplug_event
};

/* NB: Assumes xenbus_lock is held! */
static int setup_cpu_watcher(struct notifier_block *notifier,
			      unsigned long event, void *data)
{
	int err = 0;

	BUG_ON(down_trylock(&xenbus_lock) == 0);
	err = register_xenbus_watch(&cpu_watch);

	if (err) {
		printk("Failed to register watch on /cpu\n");
	}

	return NOTIFY_DONE;
}

static void handle_vcpu_hotplug_event(struct xenbus_watch *watch, const char *node)
{
	static DECLARE_WORK(vcpu_hotplug_work, __vcpu_hotplug_handler, NULL);
	struct vcpu_hotplug_handler_t *handler = &vcpu_hotplug_handler;
	ssize_t ret;
	int err, cpu;
	char state[8];
	char dir[32];
	char *cpustr;

	/* get a pointer to start of cpu string */
	if ((cpustr = strstr(node, "cpu/")) != NULL) {

		/* find which cpu state changed, note vcpu for handler */
		sscanf(cpustr, "cpu/%d", &cpu);
		handler->vcpu = cpu;

		/* calc the dir for xenbus read */
		sprintf(dir, "cpu/%d", cpu);

		/* make sure watch that was triggered is changes to the correct key */
		if ((strcmp(node + strlen(dir), "/availability")) != 0)
			return;

		/* get the state value */
		xenbus_transaction_start("cpu");
		err = xenbus_scanf(dir, "availability", "%s", state);
		xenbus_transaction_end(0);

		if (err != 1) {
			printk(KERN_ERR
			       "XENBUS: Unable to read cpu state\n");
			return;
		}

		/* if we detect a state change, take action */
		if (strcmp(state, "online") == 0) {
			/* offline -> online */
			if (!cpu_isset(cpu, cpu_online_map)) {
				handler->fn = (void *)&cpu_up;
				ret = schedule_work(&vcpu_hotplug_work);
			} 
		} else if (strcmp(state, "offline") == 0) {
			/* online -> offline */
			if (cpu_isset(cpu, cpu_online_map)) {
				handler->fn = (void *)&cpu_down;
				ret = schedule_work(&vcpu_hotplug_work);
			} 
		} else {
			printk(KERN_ERR
			       "XENBUS: unknown state(%s) on node(%s)\n", state,
			       node);
		}
	}
	return;
}

static int __init setup_vcpu_hotplug_event(void)
{
	xsn_cpu.notifier_call = setup_cpu_watcher;

	register_xenstore_notifier(&xsn_cpu);

	return 0;
}

subsys_initcall(setup_vcpu_hotplug_event);

/* must be called with the cpucontrol mutex held */
static int __devinit cpu_enable(unsigned int cpu)
{
#ifdef CONFIG_SMP_ALTERNATIVES
	if (num_online_cpus() == 1)
		prepare_for_smp();
#endif

	/* get the target out of its holding state */
	per_cpu(cpu_state, cpu) = CPU_UP_PREPARE;
	wmb();

	/* wait for the processor to ack it. timeout? */
	while (!cpu_online(cpu))
		cpu_relax();

	fixup_irqs(cpu_online_map);

	/* counter the disable in fixup_irqs() */
	local_irq_enable();
	return 0;
}

int __cpu_disable(void)
{
	cpumask_t map = cpu_online_map;
	int cpu = smp_processor_id();

	/*
	 * Perhaps use cpufreq to drop frequency, but that could go
	 * into generic code.
 	 *
	 * We won't take down the boot processor on i386 due to some
	 * interrupts only being able to be serviced by the BSP.
	 * Especially so if we're not using an IOAPIC	-zwane
	 */
	if (cpu == 0)
		return -EBUSY;

	cpu_clear(cpu, map);
	fixup_irqs(map);

	/* It's now safe to remove this processor from the online map */
	cpu_clear(cpu, cpu_online_map);

#ifdef CONFIG_SMP_ALTERNATIVES
	if (num_online_cpus() == 1)
		unprepare_for_smp();
#endif

	return 0;
}

void __cpu_die(unsigned int cpu)
{
	/* We don't do anything here: idle task is faking death itself. */
	unsigned int i;

	for (i = 0; i < 10; i++) {
		/* They ack this in play_dead by setting CPU_DEAD */
		if (per_cpu(cpu_state, cpu) == CPU_DEAD)
			return;
		current->state = TASK_UNINTERRUPTIBLE;
		schedule_timeout(HZ/10);
	}
 	printk(KERN_ERR "CPU %u didn't die...\n", cpu);
}

#else /* ... !CONFIG_HOTPLUG_CPU */
int __cpu_disable(void)
{
	return -ENOSYS;
}

void __cpu_die(unsigned int cpu)
{
	/* We said "no" in __cpu_disable */
	BUG();
}
#endif /* CONFIG_HOTPLUG_CPU */

int __devinit __cpu_up(unsigned int cpu)
{
	/* In case one didn't come up */
	if (!cpu_isset(cpu, cpu_callin_map)) {
		printk(KERN_DEBUG "skipping cpu%d, didn't come online\n", cpu);
		local_irq_enable();
		return -EIO;
	}

#ifdef CONFIG_HOTPLUG_CPU
#ifdef CONFIG_XEN
	/* Tell hypervisor to bring vcpu up. */
	HYPERVISOR_vcpu_up(cpu);
#endif
	/* Already up, and in cpu_quiescent now? */
	if (cpu_isset(cpu, smp_commenced_mask)) {
		cpu_enable(cpu);
		return 0;
	}
#endif

	local_irq_enable();
	/* Unleash the CPU! */
	cpu_set(cpu, smp_commenced_mask);
	while (!cpu_isset(cpu, cpu_online_map))
		mb();
	return 0;
}

void __init smp_cpus_done(unsigned int max_cpus)
{
#if 1
#else
#ifdef CONFIG_X86_IO_APIC
	setup_ioapic_dest();
#endif
	zap_low_mappings();
	/*
	 * Disable executability of the SMP trampoline:
	 */
	set_kernel_exec((unsigned long)trampoline_base, trampoline_exec);
#endif
}

extern irqreturn_t smp_reschedule_interrupt(int, void *, struct pt_regs *);
extern irqreturn_t smp_call_function_interrupt(int, void *, struct pt_regs *);

void smp_intr_init(void)
{
	int cpu = smp_processor_id();

	per_cpu(resched_irq, cpu) =
		bind_ipi_to_irq(RESCHEDULE_VECTOR);
	sprintf(resched_name[cpu], "resched%d", cpu);
	BUG_ON(request_irq(per_cpu(resched_irq, cpu), smp_reschedule_interrupt,
	                   SA_INTERRUPT, resched_name[cpu], NULL));

	per_cpu(callfunc_irq, cpu) =
		bind_ipi_to_irq(CALL_FUNCTION_VECTOR);
	sprintf(callfunc_name[cpu], "callfunc%d", cpu);
	BUG_ON(request_irq(per_cpu(callfunc_irq, cpu),
	                   smp_call_function_interrupt,
	                   SA_INTERRUPT, callfunc_name[cpu], NULL));
}

static void smp_intr_exit(void)
{
	int cpu = smp_processor_id();

	free_irq(per_cpu(resched_irq, cpu), NULL);
	unbind_ipi_from_irq(RESCHEDULE_VECTOR);

	free_irq(per_cpu(callfunc_irq, cpu), NULL);
	unbind_ipi_from_irq(CALL_FUNCTION_VECTOR);
}

extern void local_setup_timer_irq(void);
extern void local_teardown_timer_irq(void);

void smp_suspend(void)
{
	local_teardown_timer_irq();
	smp_intr_exit();
}

void smp_resume(void)
{
	smp_intr_init();
	local_setup_timer_irq();
}

static atomic_t vcpus_rebooting;

static void restore_vcpu_ready(void)
{

	atomic_dec(&vcpus_rebooting);
}

void save_vcpu_context(int vcpu, vcpu_guest_context_t *ctxt)
{
	int r;
	int gdt_pages;
	r = HYPERVISOR_vcpu_pickle(vcpu, ctxt);
	if (r != 0)
		panic("pickling vcpu %d -> %d!\n", vcpu, r);

	/* Translate from machine to physical addresses where necessary,
	   so that they can be translated to our new machine address space
	   after resume.  libxc is responsible for doing this to vcpu0,
	   but we do it to the others. */
	gdt_pages = (ctxt->gdt_ents + 511) / 512;
	ctxt->ctrlreg[3] = machine_to_phys(ctxt->ctrlreg[3]);
	for (r = 0; r < gdt_pages; r++)
		ctxt->gdt_frames[r] = mfn_to_pfn(ctxt->gdt_frames[r]);
}

int restore_vcpu_context(int vcpu, vcpu_guest_context_t *ctxt)
{
	int r;
	int gdt_pages = (ctxt->gdt_ents + 511) / 512;

	/* This is kind of a hack, and implicitly relies on the fact that
	   the vcpu stops in a place where all of the call clobbered
	   registers are already dead. */
	ctxt->user_regs.esp -= 4;
	((unsigned long *)ctxt->user_regs.esp)[0] = ctxt->user_regs.eip;
	ctxt->user_regs.eip = (unsigned long)restore_vcpu_ready;

	/* De-canonicalise.  libxc handles this for vcpu 0, but we need
	   to do it for the other vcpus. */
	ctxt->ctrlreg[3] = phys_to_machine(ctxt->ctrlreg[3]);
	for (r = 0; r < gdt_pages; r++)
		ctxt->gdt_frames[r] = pfn_to_mfn(ctxt->gdt_frames[r]);

	atomic_set(&vcpus_rebooting, 1);
	r = HYPERVISOR_boot_vcpu(vcpu, ctxt);
	if (r != 0) {
		printk(KERN_EMERG "Failed to reboot vcpu %d (%d)\n", vcpu, r);
		return -1;
	}

	/* Make sure we wait for the new vcpu to come up before trying to do
	   anything with it or starting the next one. */
	while (atomic_read(&vcpus_rebooting))
		barrier();

	return 0;
}
