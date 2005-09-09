/*
 *  linux/arch/i386/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 *
 * This file contains the PC-specific time handling details:
 * reading the RTC at bootup, etc..
 * 1994-07-02    Alan Modra
 *	fixed set_rtc_mmss, fixed time.year for >= 2000, new mktime
 * 1995-03-26    Markus Kuhn
 *      fixed 500 ms bug at call to set_rtc_mmss, fixed DS12887
 *      precision CMOS clock update
 * 1996-05-03    Ingo Molnar
 *      fixed time warps in do_[slow|fast]_gettimeoffset()
 * 1997-09-10	Updated NTP code according to technical memorandum Jan '96
 *		"A Kernel Model for Precision Timekeeping" by Dave Mills
 * 1998-09-05    (Various)
 *	More robust do_fast_gettimeoffset() algorithm implemented
 *	(works with APM, Cyrix 6x86MX and Centaur C6),
 *	monotonic gettimeofday() with fast_get_timeoffset(),
 *	drift-proof precision TSC calibration on boot
 *	(C. Scott Ananian <cananian@alumni.princeton.edu>, Andrew D.
 *	Balsa <andrebalsa@altern.org>, Philip Gladstone <philip@raptor.com>;
 *	ported from 2.0.35 Jumbo-9 by Michael Krause <m.krause@tu-harburg.de>).
 * 1998-12-16    Andrea Arcangeli
 *	Fixed Jumbo-9 code in 2.1.131: do_gettimeofday was missing 1 jiffy
 *	because was not accounting lost_ticks.
 * 1998-12-24 Copyright (C) 1998  Andrea Arcangeli
 *	Fixed a xtime SMP race (we need the xtime_lock rw spinlock to
 *	serialize accesses to xtime/lost_ticks).
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/module.h>
#include <linux/sysdev.h>
#include <linux/bcd.h>
#include <linux/efi.h>
#include <linux/mca.h>
#include <linux/sysctl.h>
#include <linux/percpu.h>

#include <asm/io.h>
#include <asm/smp.h>
#include <asm/irq.h>
#include <asm/msr.h>
#include <asm/delay.h>
#include <asm/mpspec.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/timer.h>

#include "mach_time.h"

#include <linux/timex.h>
#include <linux/config.h>

#include <asm/hpet.h>

#include <asm/arch_hooks.h>

#include "io_ports.h"

#include <asm-xen/evtchn.h>

extern spinlock_t i8259A_lock;
int pit_latch_buggy;              /* extern */

u64 jiffies_64 = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);

#if defined(__x86_64__)
unsigned long vxtime_hz = PIT_TICK_RATE;
struct vxtime_data __vxtime __section_vxtime;   /* for vsyscalls */
volatile unsigned long __jiffies __section_jiffies = INITIAL_JIFFIES;
unsigned long __wall_jiffies __section_wall_jiffies = INITIAL_JIFFIES;
struct timespec __xtime __section_xtime;
struct timezone __sys_tz __section_sys_tz;
#endif

#if defined(__x86_64__)
unsigned int cpu_khz;	/* Detected as we calibrate the TSC */
#else
unsigned long cpu_khz;	/* Detected as we calibrate the TSC */
#endif

extern unsigned long wall_jiffies;

DEFINE_SPINLOCK(rtc_lock);

DEFINE_SPINLOCK(i8253_lock);
EXPORT_SYMBOL(i8253_lock);

extern struct init_timer_opts timer_tsc_init;
extern struct timer_opts timer_tsc;
struct timer_opts *cur_timer = &timer_tsc;

/* These are peridically updated in shared_info, and then copied here. */
struct shadow_time_info {
	u64 tsc_timestamp;     /* TSC at last update of time vals.  */
	u64 system_timestamp;  /* Time, in nanosecs, since boot.    */
	u32 tsc_to_nsec_mul;
	u32 tsc_to_usec_mul;
	int tsc_shift;
	u32 version;
};
static DEFINE_PER_CPU(struct shadow_time_info, shadow_time);
static struct timespec shadow_tv;
static u32 shadow_tv_version;

/* Keep track of last time we did processing/updating of jiffies and xtime. */
static u64 processed_system_time;   /* System time (ns) at last processing. */
static DEFINE_PER_CPU(u64, processed_system_time);

#define NS_PER_TICK (1000000000L/HZ)

static inline void __normalize_time(time_t *sec, s64 *nsec)
{
	while (*nsec >= NSEC_PER_SEC) {
		(*nsec) -= NSEC_PER_SEC;
		(*sec)++;
	}
	while (*nsec < 0) {
		(*nsec) += NSEC_PER_SEC;
		(*sec)--;
	}
}

/* Does this guest OS track Xen time, or set its wall clock independently? */
static int independent_wallclock = 0;
static int __init __independent_wallclock(char *str)
{
	independent_wallclock = 1;
	return 1;
}
__setup("independent_wallclock", __independent_wallclock);

int tsc_disable __initdata = 0;

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

struct timer_opts timer_tsc = {
	.name = "tsc",
	.delay = delay_tsc,
};

/*
 * Scale a 64-bit delta by scaling and multiplying by a 32-bit fraction,
 * yielding a 64-bit result.
 */
static inline u64 scale_delta(u64 delta, u32 mul_frac, int shift)
{
	u64 product;
#ifdef __i386__
	u32 tmp1, tmp2;
#endif

	if ( shift < 0 )
		delta >>= -shift;
	else
		delta <<= shift;

#ifdef __i386__
	__asm__ (
		"mul  %5       ; "
		"mov  %4,%%eax ; "
		"mov  %%edx,%4 ; "
		"mul  %5       ; "
		"add  %4,%%eax ; "
		"xor  %5,%5    ; "
		"adc  %5,%%edx ; "
		: "=A" (product), "=r" (tmp1), "=r" (tmp2)
		: "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (mul_frac) );
#else
	__asm__ (
		"mul %%rdx ; shrd $32,%%rdx,%%rax"
		: "=a" (product) : "0" (delta), "d" ((u64)mul_frac) );
#endif

	return product;
}

void init_cpu_khz(void)
{
	u64 __cpu_khz = 1000000ULL << 32;
	struct vcpu_time_info *info = &HYPERVISOR_shared_info->vcpu_time[0];
	do_div(__cpu_khz, info->tsc_to_system_mul);
	if ( info->tsc_shift < 0 )
		cpu_khz = __cpu_khz << -info->tsc_shift;
	else
		cpu_khz = __cpu_khz >> info->tsc_shift;
}

static u64 get_nsec_offset(struct shadow_time_info *shadow)
{
	u64 now, delta;
	rdtscll(now);
	delta = now - shadow->tsc_timestamp;
	return scale_delta(delta, shadow->tsc_to_nsec_mul, shadow->tsc_shift);
}

static unsigned long get_usec_offset(struct shadow_time_info *shadow)
{
	u64 now, delta;
	rdtscll(now);
	delta = now - shadow->tsc_timestamp;
	return scale_delta(delta, shadow->tsc_to_usec_mul, shadow->tsc_shift);
}

static void __update_wallclock(time_t sec, long nsec)
{
	long wtm_nsec, xtime_nsec;
	time_t wtm_sec, xtime_sec;
	u64 tmp, wc_nsec;

	/* Adjust wall-clock time base based on wall_jiffies ticks. */
	wc_nsec = processed_system_time;
	wc_nsec += (u64)sec * 1000000000ULL;
	wc_nsec += (u64)nsec;
	wc_nsec -= (jiffies - wall_jiffies) * (u64)(NSEC_PER_SEC / HZ);

	/* Split wallclock base into seconds and nanoseconds. */
	tmp = wc_nsec;
	xtime_nsec = do_div(tmp, 1000000000);
	xtime_sec  = (time_t)tmp;

	wtm_sec  = wall_to_monotonic.tv_sec + (xtime.tv_sec - xtime_sec);
	wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - xtime_nsec);

	set_normalized_timespec(&xtime, xtime_sec, xtime_nsec);
	set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

	time_adjust = 0;		/* stop active adjtime() */
	time_status |= STA_UNSYNC;
	time_maxerror = NTP_PHASE_LIMIT;
	time_esterror = NTP_PHASE_LIMIT;
}

static void update_wallclock(void)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	do {
		shadow_tv_version = s->wc_version;
		rmb();
		shadow_tv.tv_sec  = s->wc_sec;
		shadow_tv.tv_nsec = s->wc_nsec;
		rmb();
	}
	while ((s->wc_version & 1) | (shadow_tv_version ^ s->wc_version));

	if (!independent_wallclock)
		__update_wallclock(shadow_tv.tv_sec, shadow_tv.tv_nsec);
}

/*
 * Reads a consistent set of time-base values from Xen, into a shadow data
 * area.
 */
static void get_time_values_from_xen(void)
{
	shared_info_t           *s = HYPERVISOR_shared_info;
	struct vcpu_time_info   *src;
	struct shadow_time_info *dst;

	src = &s->vcpu_time[smp_processor_id()];
	dst = &per_cpu(shadow_time, smp_processor_id());

	do {
		dst->version = src->version;
		rmb();
		dst->tsc_timestamp     = src->tsc_timestamp;
		dst->system_timestamp  = src->system_time;
		dst->tsc_to_nsec_mul   = src->tsc_to_system_mul;
		dst->tsc_shift         = src->tsc_shift;
		rmb();
	}
	while ((src->version & 1) | (dst->version ^ src->version));

	dst->tsc_to_usec_mul = dst->tsc_to_nsec_mul / 1000;
}

static inline int time_values_up_to_date(int cpu)
{
	struct vcpu_time_info   *src;
	struct shadow_time_info *dst;

	src = &HYPERVISOR_shared_info->vcpu_time[cpu]; 
	dst = &per_cpu(shadow_time, cpu); 

	return (dst->version == src->version);
}

/*
 * This is a special lock that is owned by the CPU and holds the index
 * register we are working with.  It is required for NMI access to the
 * CMOS/RTC registers.  See include/asm-i386/mc146818rtc.h for details.
 */
volatile unsigned long cmos_lock = 0;
EXPORT_SYMBOL(cmos_lock);

/* Routines for accessing the CMOS RAM/RTC. */
unsigned char rtc_cmos_read(unsigned char addr)
{
	unsigned char val;
	lock_cmos_prefix(addr);
	outb_p(addr, RTC_PORT(0));
	val = inb_p(RTC_PORT(1));
	lock_cmos_suffix(addr);
	return val;
}
EXPORT_SYMBOL(rtc_cmos_read);

void rtc_cmos_write(unsigned char val, unsigned char addr)
{
	lock_cmos_prefix(addr);
	outb_p(addr, RTC_PORT(0));
	outb_p(val, RTC_PORT(1));
	lock_cmos_suffix(addr);
}
EXPORT_SYMBOL(rtc_cmos_write);

/*
 * This version of gettimeofday has microsecond resolution
 * and better than microsecond precision on fast x86 machines with TSC.
 */
void do_gettimeofday(struct timeval *tv)
{
	unsigned long seq;
	unsigned long usec, sec;
	unsigned long max_ntp_tick;
	s64 nsec;
	unsigned int cpu;
	struct shadow_time_info *shadow;
	u32 local_time_version;

	cpu = get_cpu();
	shadow = &per_cpu(shadow_time, cpu);

	do {
		unsigned long lost;

		local_time_version = shadow->version;
		seq = read_seqbegin(&xtime_lock);

		usec = get_usec_offset(shadow);
		lost = jiffies - wall_jiffies;

		/*
		 * If time_adjust is negative then NTP is slowing the clock
		 * so make sure not to go into next possible interval.
		 * Better to lose some accuracy than have time go backwards..
		 */
		if (unlikely(time_adjust < 0)) {
			max_ntp_tick = (USEC_PER_SEC / HZ) - tickadj;
			usec = min(usec, max_ntp_tick);

			if (lost)
				usec += lost * max_ntp_tick;
		}
		else if (unlikely(lost))
			usec += lost * (USEC_PER_SEC / HZ);

		sec = xtime.tv_sec;
		usec += (xtime.tv_nsec / NSEC_PER_USEC);

		nsec = shadow->system_timestamp - processed_system_time;
		__normalize_time(&sec, &nsec);
		usec += (long)nsec / NSEC_PER_USEC;

		if (unlikely(!time_values_up_to_date(cpu))) {
			/*
			 * We may have blocked for a long time,
			 * rendering our calculations invalid
			 * (e.g. the time delta may have
			 * overflowed). Detect that and recalculate
			 * with fresh values.
			 */
			get_time_values_from_xen();
			continue;
		}
	} while (read_seqretry(&xtime_lock, seq) ||
		 (local_time_version != shadow->version));

	put_cpu();

	while (usec >= USEC_PER_SEC) {
		usec -= USEC_PER_SEC;
		sec++;
	}

	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

EXPORT_SYMBOL(do_gettimeofday);

int do_settimeofday(struct timespec *tv)
{
	time_t sec;
	s64 nsec;
	unsigned int cpu;
	struct shadow_time_info *shadow;
	dom0_op_t op;

	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	cpu = get_cpu();
	shadow = &per_cpu(shadow_time, cpu);

	write_seqlock_irq(&xtime_lock);

	/*
	 * Ensure we don't get blocked for a long time so that our time delta
	 * overflows. If that were to happen then our shadow time values would
	 * be stale, so we can retry with fresh ones.
	 */
	for ( ; ; ) {
		nsec = (s64)tv->tv_nsec - (s64)get_nsec_offset(shadow);
		if (time_values_up_to_date(cpu))
			break;
		get_time_values_from_xen();
	}
	sec = tv->tv_sec;
	__normalize_time(&sec, &nsec);

	if ((xen_start_info->flags & SIF_INITDOMAIN) &&
	    !independent_wallclock) {
		op.cmd = DOM0_SETTIME;
		op.u.settime.secs        = sec;
		op.u.settime.nsecs       = nsec;
		op.u.settime.system_time = shadow->system_timestamp;
		HYPERVISOR_dom0_op(&op);
		update_wallclock();
	} else if (independent_wallclock) {
		nsec -= shadow->system_timestamp;
		__normalize_time(&sec, &nsec);
		__update_wallclock(sec, nsec);
	}

	write_sequnlock_irq(&xtime_lock);

	put_cpu();

	clock_was_set();
	return 0;
}

EXPORT_SYMBOL(do_settimeofday);

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
static int set_rtc_mmss(unsigned long nowtime)
{
	int retval;

	WARN_ON(irqs_disabled());

	if (!(xen_start_info->flags & SIF_INITDOMAIN))
		return 0;

	/* gets recalled with irq locally disabled */
	spin_lock_irq(&rtc_lock);
	if (efi_enabled)
		retval = efi_set_rtc_mmss(nowtime);
	else
		retval = mach_set_rtc_mmss(nowtime);
	spin_unlock_irq(&rtc_lock);

	return retval;
}
#else
static int set_rtc_mmss(unsigned long nowtime)
{
	return 0;
}
#endif

/* monotonic_clock(): returns # of nanoseconds passed since time_init()
 *		Note: This function is required to return accurate
 *		time even in the absence of multiple timer ticks.
 */
unsigned long long monotonic_clock(void)
{
	int cpu = get_cpu();
	struct shadow_time_info *shadow = &per_cpu(shadow_time, cpu);
	u64 time;
	u32 local_time_version;

	do {
		local_time_version = shadow->version;
		smp_rmb();
		time = shadow->system_timestamp + get_nsec_offset(shadow);
		if (!time_values_up_to_date(cpu))
			get_time_values_from_xen();
		smp_rmb();
	} while (local_time_version != shadow->version);

	put_cpu();

	return time;
}
EXPORT_SYMBOL(monotonic_clock);

unsigned long long sched_clock(void)
{
	return monotonic_clock();
}

#if defined(CONFIG_SMP) && defined(CONFIG_FRAME_POINTER)
unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (in_lock_functions(pc))
		return *(unsigned long *)(regs->ebp + 4);

	return pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

irqreturn_t timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	s64 delta, delta_cpu;
	int cpu = smp_processor_id();
	struct shadow_time_info *shadow = &per_cpu(shadow_time, cpu);

	write_seqlock(&xtime_lock);

	do {
		get_time_values_from_xen();

		delta = delta_cpu = 
			shadow->system_timestamp + get_nsec_offset(shadow);
		delta     -= processed_system_time;
		delta_cpu -= per_cpu(processed_system_time, cpu);
	}
	while (!time_values_up_to_date(cpu));

	if (unlikely(delta < (s64)-1000000) || unlikely(delta_cpu < 0)) {
		printk("Timer ISR/%d: Time went backwards: "
		       "delta=%lld cpu_delta=%lld shadow=%lld "
		       "off=%lld processed=%lld cpu_processed=%lld\n",
		       cpu, delta, delta_cpu, shadow->system_timestamp,
		       (s64)get_nsec_offset(shadow),
		       processed_system_time,
		       per_cpu(processed_system_time, cpu));
		for (cpu = 0; cpu < num_online_cpus(); cpu++)
			printk(" %d: %lld\n", cpu,
			       per_cpu(processed_system_time, cpu));
	}

	/* System-wide jiffy work. */
	while (delta >= NS_PER_TICK) {
		delta -= NS_PER_TICK;
		processed_system_time += NS_PER_TICK;
		do_timer(regs);
	}

	if (shadow_tv_version != HYPERVISOR_shared_info->wc_version) {
		update_wallclock();
		clock_was_set();
	}

	write_sequnlock(&xtime_lock);

	/*
         * Local CPU jiffy work. No need to hold xtime_lock, and I'm not sure
         * if there is risk of deadlock if we do (since update_process_times
         * may do scheduler rebalancing work and thus acquire runqueue locks).
         */
	while (delta_cpu >= NS_PER_TICK) {
		delta_cpu -= NS_PER_TICK;
		per_cpu(processed_system_time, cpu) += NS_PER_TICK;
		update_process_times(user_mode(regs));
		profile_tick(CPU_PROFILING, regs);
	}

	return IRQ_HANDLED;
}

/* not static: needed by APM */
unsigned long get_cmos_time(void)
{
	unsigned long retval;

	spin_lock(&rtc_lock);

	if (efi_enabled)
		retval = efi_get_time();
	else
		retval = mach_get_cmos_time();

	spin_unlock(&rtc_lock);

	return retval;
}
static void sync_cmos_clock(unsigned long dummy);

static struct timer_list sync_cmos_timer =
                                      TIMER_INITIALIZER(sync_cmos_clock, 0, 0);

static void sync_cmos_clock(unsigned long dummy)
{
	struct timeval now, next;
	int fail = 1;

	/*
	 * If we have an externally synchronized Linux clock, then update
	 * CMOS clock accordingly every ~11 minutes. Set_rtc_mmss() has to be
	 * called as close as possible to 500 ms before the new second starts.
	 * This code is run on a timer.  If the clock is set, that timer
	 * may not expire at the correct time.  Thus, we adjust...
	 */
	if ((time_status & STA_UNSYNC) != 0)
		/*
		 * Not synced, exit, do not restart a timer (if one is
		 * running, let it run out).
		 */
		return;

	do_gettimeofday(&now);
	if (now.tv_usec >= USEC_AFTER - ((unsigned) TICK_SIZE) / 2 &&
	    now.tv_usec <= USEC_BEFORE + ((unsigned) TICK_SIZE) / 2)
		fail = set_rtc_mmss(now.tv_sec);

	next.tv_usec = USEC_AFTER - now.tv_usec;
	if (next.tv_usec <= 0)
		next.tv_usec += USEC_PER_SEC;

	if (!fail)
		next.tv_sec = 659;
	else
		next.tv_sec = 0;

	if (next.tv_usec >= USEC_PER_SEC) {
		next.tv_sec++;
		next.tv_usec -= USEC_PER_SEC;
	}
	mod_timer(&sync_cmos_timer, jiffies + timeval_to_jiffies(&next));
}

void notify_arch_cmos_timer(void)
{
	mod_timer(&sync_cmos_timer, jiffies + 1);
}

static long clock_cmos_diff, sleep_start;

static int timer_suspend(struct sys_device *dev, pm_message_t state)
{
	/*
	 * Estimate time zone so that set_time can update the clock
	 */
	clock_cmos_diff = -get_cmos_time();
	clock_cmos_diff += get_seconds();
	sleep_start = get_cmos_time();
	return 0;
}

static int timer_resume(struct sys_device *dev)
{
	unsigned long flags;
	unsigned long sec;
	unsigned long sleep_length;

#ifdef CONFIG_HPET_TIMER
	if (is_hpet_enabled())
		hpet_reenable();
#endif
	sec = get_cmos_time() + clock_cmos_diff;
	sleep_length = (get_cmos_time() - sleep_start) * HZ;
	write_seqlock_irqsave(&xtime_lock, flags);
	xtime.tv_sec = sec;
	xtime.tv_nsec = 0;
	write_sequnlock_irqrestore(&xtime_lock, flags);
	jiffies += sleep_length;
	wall_jiffies += sleep_length;
	return 0;
}

static struct sysdev_class timer_sysclass = {
	.resume = timer_resume,
	.suspend = timer_suspend,
	set_kset_name("timer"),
};


/* XXX this driverfs stuff should probably go elsewhere later -john */
static struct sys_device device_timer = {
	.id	= 0,
	.cls	= &timer_sysclass,
};

static int time_init_device(void)
{
	int error = sysdev_class_register(&timer_sysclass);
	if (!error)
		error = sysdev_register(&device_timer);
	return error;
}

device_initcall(time_init_device);

#ifdef CONFIG_HPET_TIMER
extern void (*late_time_init)(void);
/* Duplicate of time_init() below, with hpet_enable part added */
static void __init hpet_time_init(void)
{
	xtime.tv_sec = get_cmos_time();
	xtime.tv_nsec = (INITIAL_JIFFIES % HZ) * (NSEC_PER_SEC / HZ);
	set_normalized_timespec(&wall_to_monotonic,
		-xtime.tv_sec, -xtime.tv_nsec);

	if ((hpet_enable() >= 0) && hpet_use_timer) {
		printk("Using HPET for base-timer\n");
	}

	cur_timer = select_timer();
	printk(KERN_INFO "Using %s for high-res timesource\n",cur_timer->name);

	time_init_hook();
}
#endif

/* Dynamically-mapped IRQ. */
DEFINE_PER_CPU(int, timer_irq);

static struct irqaction irq_timer = {
	timer_interrupt, SA_INTERRUPT, CPU_MASK_NONE, "timer0",
	NULL, NULL
};

void __init time_init(void)
{
#ifdef CONFIG_HPET_TIMER
	if (is_hpet_capable()) {
		/*
		 * HPET initialization needs to do memory-mapped io. So, let
		 * us do a late initialization after mem_init().
		 */
		late_time_init = hpet_time_init;
		return;
	}
#endif
	get_time_values_from_xen();

	processed_system_time = per_cpu(shadow_time, 0).system_timestamp;
	per_cpu(processed_system_time, 0) = processed_system_time;

	update_wallclock();

	init_cpu_khz();
	printk(KERN_INFO "Xen reported: %lu.%03lu MHz processor.\n",
	       cpu_khz / 1000, cpu_khz % 1000);

#if defined(__x86_64__)
	vxtime.mode = VXTIME_TSC;
	vxtime.quot = (1000000L << 32) / vxtime_hz;
	vxtime.tsc_quot = (1000L << 32) / cpu_khz;
	vxtime.hz = vxtime_hz;
	sync_core();
	rdtscll(vxtime.last_tsc);
#endif

	per_cpu(timer_irq, 0) = bind_virq_to_irq(VIRQ_TIMER);
	(void)setup_irq(per_cpu(timer_irq, 0), &irq_timer);
}

/* Convert jiffies to system time. */
static inline u64 jiffies_to_st(unsigned long j) 
{
	unsigned long seq;
	long delta;
	u64 st;

	do {
		seq = read_seqbegin(&xtime_lock);
		delta = j - jiffies;
		/* NB. The next check can trigger in some wrap-around cases,
		 * but that's ok: we'll just end up with a shorter timeout. */
		if (delta < 1)
			delta = 1;
		st = processed_system_time + (delta * NS_PER_TICK);
	} while (read_seqretry(&xtime_lock, seq));

	return st;
}

/*
 * stop_hz_timer / start_hz_timer - enter/exit 'tickless mode' on an idle cpu
 * These functions are based on implementations from arch/s390/kernel/time.c
 */
void stop_hz_timer(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned long j;

	/* s390 does this /before/ checking rcu_pending(). We copy them. */
	cpu_set(cpu, nohz_cpu_mask);

	/* Leave ourselves in 'tick mode' if rcu or softirq pending. */
	if (rcu_pending(cpu) || local_softirq_pending()) {
		cpu_clear(cpu, nohz_cpu_mask);
		j = jiffies + 1;
	} else {
		j = next_timer_interrupt();
	}

	BUG_ON(HYPERVISOR_set_timer_op(jiffies_to_st(j)) != 0);
}

void start_hz_timer(void)
{
	cpu_clear(smp_processor_id(), nohz_cpu_mask);
}

void time_suspend(void)
{
	/* nothing */
	teardown_irq(per_cpu(timer_irq, 0), &irq_timer);
	unbind_virq_from_irq(VIRQ_TIMER);
}

/* No locking required. We are only CPU running, and interrupts are off. */
void time_resume(void)
{
	init_cpu_khz();

	get_time_values_from_xen();

	processed_system_time = per_cpu(shadow_time, 0).system_timestamp;
	per_cpu(processed_system_time, 0) = processed_system_time;

	update_wallclock();

	per_cpu(timer_irq, 0) = bind_virq_to_irq(VIRQ_TIMER);
	(void)setup_irq(per_cpu(timer_irq, 0), &irq_timer);
}

#ifdef CONFIG_SMP
static char timer_name[NR_CPUS][15];
void local_setup_timer_irq(void)
{
	int cpu = smp_processor_id();

	if (cpu == 0)
		return;
	per_cpu(timer_irq, cpu) = bind_virq_to_irq(VIRQ_TIMER);
	sprintf(timer_name[cpu], "timer%d", cpu);
	BUG_ON(request_irq(per_cpu(timer_irq, cpu), timer_interrupt,
	                   SA_INTERRUPT, timer_name[cpu], NULL));
}

void local_setup_timer(void)
{
	int seq, cpu = smp_processor_id();

	do {
		seq = read_seqbegin(&xtime_lock);
		per_cpu(processed_system_time, cpu) = 
			per_cpu(shadow_time, cpu).system_timestamp;
	} while (read_seqretry(&xtime_lock, seq));

	local_setup_timer_irq();
}

void local_teardown_timer_irq(void)
{
	int cpu = smp_processor_id();

	if (cpu == 0)
		return;
	free_irq(per_cpu(timer_irq, cpu), NULL);
	unbind_virq_from_irq(VIRQ_TIMER);
}
#endif

/*
 * /proc/sys/xen: This really belongs in another file. It can stay here for
 * now however.
 */
static ctl_table xen_subtable[] = {
	{1, "independent_wallclock", &independent_wallclock,
	 sizeof(independent_wallclock), 0644, NULL, proc_dointvec},
	{0}
};
static ctl_table xen_table[] = {
	{123, "xen", NULL, 0, 0555, xen_subtable},
	{0}
};
static int __init xen_sysctl_init(void)
{
	(void)register_sysctl_table(xen_table, 0);
	return 0;
}
__initcall(xen_sysctl_init);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
