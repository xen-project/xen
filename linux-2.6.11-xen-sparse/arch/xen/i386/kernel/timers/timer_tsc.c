/*
 * This code largely moved from arch/i386/kernel/time.c.
 * See comments there for proper credits.
 */

#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/timex.h>
#include <linux/errno.h>
#include <linux/cpufreq.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include <asm/timer.h>
#include <asm/io.h>
/* processor.h for distable_tsc flag */
#include <asm/processor.h>

#include "io_ports.h"
#include "mach_timer.h"

#include <asm/hpet.h>

#ifdef CONFIG_HPET_TIMER
static unsigned long hpet_usec_quotient;
static unsigned long hpet_last;
static struct timer_opts timer_tsc;
#endif

static inline void cpufreq_delayed_get(void);

int tsc_disable __initdata = 0;

extern spinlock_t i8253_lock;

static int use_tsc;

static unsigned long long monotonic_base;
static u32 monotonic_offset;
static seqlock_t monotonic_lock = SEQLOCK_UNLOCKED;

/* convert from cycles(64bits) => nanoseconds (64bits)
 *  basic equation:
 *		ns = cycles / (freq / ns_per_sec)
 *		ns = cycles * (ns_per_sec / freq)
 *		ns = cycles * (10^9 / (cpu_mhz * 10^6))
 *		ns = cycles * (10^3 / cpu_mhz)
 *
 *	Then we use scaling math (suggested by george@mvista.com) to get:
 *		ns = cycles * (10^3 * SC / cpu_mhz) / SC
 *		ns = cycles * cyc2ns_scale / SC
 *
 *	And since SC is a constant power of two, we can convert the div
 *  into a shift.   
 *			-johnstul@us.ibm.com "math is hard, lets go shopping!"
 */
static unsigned long cyc2ns_scale; 
#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */

static inline void set_cyc2ns_scale(unsigned long cpu_mhz)
{
	cyc2ns_scale = (1000 << CYC2NS_SCALE_FACTOR)/cpu_mhz;
}

static inline unsigned long long cycles_2_ns(unsigned long long cyc)
{
	return (cyc * cyc2ns_scale) >> CYC2NS_SCALE_FACTOR;
}

/* Cached *multiplier* to convert TSC counts to microseconds.
 * (see the equation below).
 * Equal to 2^32 * (1 / (clocks per usec) ).
 * Initialized in time_init.
 */
static unsigned long fast_gettimeoffset_quotient;

extern u32 shadow_tsc_stamp;
extern u64 shadow_system_time;

static unsigned long get_offset_tsc(void)
{
	register unsigned long eax, edx;

	/* Read the Time Stamp Counter */

	rdtsc(eax,edx);

	/* .. relative to previous jiffy (32 bits is enough) */
	eax -= shadow_tsc_stamp;

	/*
         * Time offset = (tsc_low delta) * fast_gettimeoffset_quotient
         *             = (tsc_low delta) * (usecs_per_clock)
         *             = (tsc_low delta) * (usecs_per_jiffy / clocks_per_jiffy)
	 *
	 * Using a mull instead of a divl saves up to 31 clock cycles
	 * in the critical path.
         */

	__asm__("mull %2"
		:"=a" (eax), "=d" (edx)
		:"rm" (fast_gettimeoffset_quotient),
		 "0" (eax));

	/* our adjusted time offset in microseconds */
	return edx;
}

static unsigned long long monotonic_clock_tsc(void)
{
	unsigned long long last_offset, this_offset, base;
	unsigned seq;
	
	/* atomically read monotonic base & last_offset */
	do {
		seq = read_seqbegin(&monotonic_lock);
		last_offset = monotonic_offset;
		base = monotonic_base;
	} while (read_seqretry(&monotonic_lock, seq));

	/* Read the Time Stamp Counter */
	rdtscll(this_offset);

	/* return the value in ns */
	return base + cycles_2_ns(this_offset - last_offset);
}

/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	unsigned long long this_offset;

	/*
	 * In the NUMA case we dont use the TSC as they are not
	 * synchronized across all CPUs.
	 */
#ifndef CONFIG_NUMA
	if (!use_tsc)
#endif
		/* no locking but a rare wrong value is not a big deal */
		return jiffies_64 * (1000000000 / HZ);

	/* Read the Time Stamp Counter */
	rdtscll(this_offset);

	/* return the value in ns */
	return cycles_2_ns(this_offset);
}


static void mark_offset_tsc(void)
{

	/* update the monotonic base value */
	write_seqlock(&monotonic_lock);
	monotonic_base = shadow_system_time;
	monotonic_offset = shadow_tsc_stamp;
	write_sequnlock(&monotonic_lock);
}

static void delay_tsc(unsigned long loops)
{
	unsigned long bclock, now;
	
	rdtscl(bclock);
	do
	{
		rep_nop();
		rdtscl(now);
	} while ((now-bclock) < loops);
}

#ifdef CONFIG_HPET_TIMER
static void mark_offset_tsc_hpet(void)
{
	unsigned long long this_offset, last_offset;
 	unsigned long offset, temp, hpet_current;

	write_seqlock(&monotonic_lock);
	last_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
	/*
	 * It is important that these two operations happen almost at
	 * the same time. We do the RDTSC stuff first, since it's
	 * faster. To avoid any inconsistencies, we need interrupts
	 * disabled locally.
	 */
	/*
	 * Interrupts are just disabled locally since the timer irq
	 * has the SA_INTERRUPT flag set. -arca
	 */
	/* read Pentium cycle counter */

	hpet_current = hpet_readl(HPET_COUNTER);
	rdtsc(last_tsc_low, last_tsc_high);

	/* lost tick compensation */
	offset = hpet_readl(HPET_T0_CMP) - hpet_tick;
	if (unlikely(((offset - hpet_last) > hpet_tick) && (hpet_last != 0))) {
		int lost_ticks = (offset - hpet_last) / hpet_tick;
		jiffies_64 += lost_ticks;
	}
	hpet_last = hpet_current;

	/* update the monotonic base value */
	this_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
	monotonic_base += cycles_2_ns(this_offset - last_offset);
	write_sequnlock(&monotonic_lock);

	/* calculate delay_at_last_interrupt */
	/*
	 * Time offset = (hpet delta) * ( usecs per HPET clock )
	 *             = (hpet delta) * ( usecs per tick / HPET clocks per tick)
	 *             = (hpet delta) * ( hpet_usec_quotient ) / (2^32)
	 * Where,
	 * hpet_usec_quotient = (2^32 * usecs per tick)/HPET clocks per tick
	 */
	delay_at_last_interrupt = hpet_current - offset;
	ASM_MUL64_REG(temp, delay_at_last_interrupt,
			hpet_usec_quotient, delay_at_last_interrupt);
}
#endif


#ifdef CONFIG_CPU_FREQ
#include <linux/workqueue.h>

static unsigned int cpufreq_delayed_issched = 0;
static unsigned int cpufreq_init = 0;
static struct work_struct cpufreq_delayed_get_work;

static void handle_cpufreq_delayed_get(void *v)
{
	unsigned int cpu;
	for_each_online_cpu(cpu) {
		cpufreq_get(cpu);
	}
	cpufreq_delayed_issched = 0;
}

/* if we notice lost ticks, schedule a call to cpufreq_get() as it tries
 * to verify the CPU frequency the timing core thinks the CPU is running
 * at is still correct.
 */
static inline void cpufreq_delayed_get(void) 
{
	if (cpufreq_init && !cpufreq_delayed_issched) {
		cpufreq_delayed_issched = 1;
		printk(KERN_DEBUG "Losing some ticks... checking if CPU frequency changed.\n");
		schedule_work(&cpufreq_delayed_get_work);
	}
}

/* If the CPU frequency is scaled, TSC-based delays will need a different
 * loops_per_jiffy value to function properly.
 */

static unsigned int  ref_freq = 0;
static unsigned long loops_per_jiffy_ref = 0;

#ifndef CONFIG_SMP
static unsigned long fast_gettimeoffset_ref = 0;
static unsigned long cpu_khz_ref = 0;
#endif

static int
time_cpufreq_notifier(struct notifier_block *nb, unsigned long val,
		      void *data)
{
	struct cpufreq_freqs *freq = data;

	if (val != CPUFREQ_RESUMECHANGE)
		write_seqlock_irq(&xtime_lock);
	if (!ref_freq) {
		ref_freq = freq->old;
		loops_per_jiffy_ref = cpu_data[freq->cpu].loops_per_jiffy;
#ifndef CONFIG_SMP
		fast_gettimeoffset_ref = fast_gettimeoffset_quotient;
		cpu_khz_ref = cpu_khz;
#endif
	}

	if ((val == CPUFREQ_PRECHANGE  && freq->old < freq->new) ||
	    (val == CPUFREQ_POSTCHANGE && freq->old > freq->new) ||
	    (val == CPUFREQ_RESUMECHANGE)) {
		if (!(freq->flags & CPUFREQ_CONST_LOOPS))
			cpu_data[freq->cpu].loops_per_jiffy = cpufreq_scale(loops_per_jiffy_ref, ref_freq, freq->new);
#ifndef CONFIG_SMP
		if (cpu_khz)
			cpu_khz = cpufreq_scale(cpu_khz_ref, ref_freq, freq->new);
		if (use_tsc) {
			if (!(freq->flags & CPUFREQ_CONST_LOOPS)) {
				fast_gettimeoffset_quotient = cpufreq_scale(fast_gettimeoffset_ref, freq->new, ref_freq);
				set_cyc2ns_scale(cpu_khz/1000);
			}
		}
#endif
	}

	if (val != CPUFREQ_RESUMECHANGE)
		write_sequnlock_irq(&xtime_lock);

	return 0;
}

static struct notifier_block time_cpufreq_notifier_block = {
	.notifier_call	= time_cpufreq_notifier
};


static int __init cpufreq_tsc(void)
{
	int ret;
	INIT_WORK(&cpufreq_delayed_get_work, handle_cpufreq_delayed_get, NULL);
	ret = cpufreq_register_notifier(&time_cpufreq_notifier_block,
					CPUFREQ_TRANSITION_NOTIFIER);
	if (!ret)
		cpufreq_init = 1;
	return ret;
}
core_initcall(cpufreq_tsc);

#else /* CONFIG_CPU_FREQ */
static inline void cpufreq_delayed_get(void) { return; }
#endif 


static int init_tsc(char* override)
{
	u64 __cpu_khz;

	__cpu_khz = HYPERVISOR_shared_info->cpu_freq;
	do_div(__cpu_khz, 1000);
	cpu_khz = (u32)__cpu_khz;
	printk(KERN_INFO "Xen reported: %lu.%03lu MHz processor.\n", 
	       cpu_khz / 1000, cpu_khz % 1000);

	/* (10^6 * 2^32) / cpu_hz = (10^3 * 2^32) / cpu_khz =
	   (2^32 * 1 / (clocks/us)) */
	{	
		unsigned long eax=0, edx=1000;
		__asm__("divl %2"
		    :"=a" (fast_gettimeoffset_quotient), "=d" (edx)
		    :"r" (cpu_khz),
		    "0" (eax), "1" (edx));
	}

	set_cyc2ns_scale(cpu_khz/1000);

	use_tsc = 1;

	return 0;
}

static int __init tsc_setup(char *str)
{
	printk(KERN_WARNING "notsc: cannot disable TSC in Xen/Linux.\n");
	return 1;
}
__setup("notsc", tsc_setup);



/************************************************************/

/* tsc timer_opts struct */
struct timer_opts timer_tsc = {
	.name = "tsc",
	.mark_offset = mark_offset_tsc, 
	.get_offset = get_offset_tsc,
	.monotonic_clock = monotonic_clock_tsc,
	.delay = delay_tsc,
};

struct init_timer_opts timer_tsc_init = {
	.init = init_tsc,
	.opts = &timer_tsc,
};
