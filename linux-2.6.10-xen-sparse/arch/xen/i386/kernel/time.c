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
#include <linux/sysctl.h>

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

extern spinlock_t i8259A_lock;
int pit_latch_buggy;              /* extern */

u64 jiffies_64 = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);

unsigned long cpu_khz;	/* Detected as we calibrate the TSC */

extern unsigned long wall_jiffies;

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;

spinlock_t i8253_lock = SPIN_LOCK_UNLOCKED;
EXPORT_SYMBOL(i8253_lock);

extern struct init_timer_opts timer_tsc_init;
extern struct timer_opts timer_tsc;
struct timer_opts *cur_timer = &timer_tsc;

/* These are peridically updated in shared_info, and then copied here. */
u32 shadow_tsc_stamp;
u64 shadow_system_time;
static u32 shadow_time_version;
static struct timeval shadow_tv;
extern u64 processed_system_time;

/*
 * We use this to ensure that gettimeofday() is monotonically increasing. We
 * only break this guarantee if the wall clock jumps backwards "a long way".
 */
static struct timeval last_seen_tv = {0,0};

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
/* Periodically propagate synchronised time base to the RTC and to Xen. */
static long last_rtc_update, last_update_to_xen;
#endif

/* Periodically take synchronised time base from Xen, if we need it. */
static long last_update_from_xen;   /* UTC seconds when last read Xen clock. */

/* Keep track of last time we did processing/updating of jiffies and xtime. */
u64 processed_system_time;   /* System time (ns) at last processing. */

#define NS_PER_TICK (1000000000ULL/HZ)

#define HANDLE_USEC_UNDERFLOW(_tv) do {		\
	while ((_tv).tv_usec < 0) {		\
		(_tv).tv_usec += USEC_PER_SEC;	\
		(_tv).tv_sec--;			\
	}					\
} while (0)
#define HANDLE_USEC_OVERFLOW(_tv) do {		\
	while ((_tv).tv_usec >= USEC_PER_SEC) {	\
		(_tv).tv_usec -= USEC_PER_SEC;	\
		(_tv).tv_sec++;			\
	}					\
} while (0)
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
#define INDEPENDENT_WALLCLOCK() \
    (independent_wallclock || (xen_start_info.flags & SIF_INITDOMAIN))

/*
 * Reads a consistent set of time-base values from Xen, into a shadow data
 * area. Must be called with the xtime_lock held for writing.
 */
static void __get_time_values_from_xen(void)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	do {
		shadow_time_version = s->time_version2;
		rmb();
		shadow_tv.tv_sec    = s->wc_sec;
		shadow_tv.tv_usec   = s->wc_usec;
		shadow_tsc_stamp    = (u32)s->tsc_timestamp;
		shadow_system_time  = s->system_time;
		rmb();
	}
	while (shadow_time_version != s->time_version1);

	cur_timer->mark_offset();
}

#define TIME_VALUES_UP_TO_DATE \
 ({ rmb(); (shadow_time_version == HYPERVISOR_shared_info->time_version2); })

/*
 * This version of gettimeofday has microsecond resolution
 * and better than microsecond precision on fast x86 machines with TSC.
 */
void do_gettimeofday(struct timeval *tv)
{
	unsigned long seq;
	unsigned long usec, sec;
	unsigned long max_ntp_tick;
	unsigned long flags;
	s64 nsec;

	do {
		unsigned long lost;

		seq = read_seqbegin(&xtime_lock);

		usec = cur_timer->get_offset();
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

		nsec = shadow_system_time - processed_system_time;
		__normalize_time(&sec, &nsec);
		usec += (long)nsec / NSEC_PER_USEC;

		if (unlikely(!TIME_VALUES_UP_TO_DATE)) {
			/*
			 * We may have blocked for a long time,
			 * rendering our calculations invalid
			 * (e.g. the time delta may have
			 * overflowed). Detect that and recalculate
			 * with fresh values.
			 */
			write_seqlock_irqsave(&xtime_lock, flags);
			__get_time_values_from_xen();
			write_sequnlock_irqrestore(&xtime_lock, flags);
			continue;
		}
	} while (read_seqretry(&xtime_lock, seq));

	while (usec >= USEC_PER_SEC) {
		usec -= USEC_PER_SEC;
		sec++;
	}

	/* Ensure that time-of-day is monotonically increasing. */
	if ((sec < last_seen_tv.tv_sec) ||
	    ((sec == last_seen_tv.tv_sec) && (usec < last_seen_tv.tv_usec))) {
		sec = last_seen_tv.tv_sec;
		usec = last_seen_tv.tv_usec;
	} else {
		last_seen_tv.tv_sec = sec;
		last_seen_tv.tv_usec = usec;
	}

	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

EXPORT_SYMBOL(do_gettimeofday);

int do_settimeofday(struct timespec *tv)
{
	time_t wtm_sec, sec = tv->tv_sec;
	long wtm_nsec;
	s64 nsec;
	struct timespec xentime;

	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	if (!INDEPENDENT_WALLCLOCK())
		return 0; /* Silent failure? */

	write_seqlock_irq(&xtime_lock);

	/*
	 * Ensure we don't get blocked for a long time so that our time delta
	 * overflows. If that were to happen then our shadow time values would
	 * be stale, so we can retry with fresh ones.
	 */
 again:
	nsec = (s64)tv->tv_nsec -
	    ((s64)cur_timer->get_offset() * (s64)NSEC_PER_USEC);
	if (unlikely(!TIME_VALUES_UP_TO_DATE)) {
		__get_time_values_from_xen();
		goto again;
	}

	__normalize_time(&sec, &nsec);
	set_normalized_timespec(&xentime, sec, nsec);

	/*
	 * This is revolting. We need to set "xtime" correctly. However, the
	 * value in this location is the value at the most recent update of
	 * wall time.  Discover what correction gettimeofday() would have
	 * made, and then undo it!
	 */
	nsec -= (jiffies - wall_jiffies) * TICK_NSEC;

	nsec -= (shadow_system_time - processed_system_time);

	__normalize_time(&sec, &nsec);
	wtm_sec  = wall_to_monotonic.tv_sec + (xtime.tv_sec - sec);
	wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - nsec);

	set_normalized_timespec(&xtime, sec, nsec);
	set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

	time_adjust = 0;		/* stop active adjtime() */
	time_status |= STA_UNSYNC;
	time_maxerror = NTP_PHASE_LIMIT;
	time_esterror = NTP_PHASE_LIMIT;

	/* Reset all our running time counts. They make no sense now. */
	last_seen_tv.tv_sec = 0;
	last_update_from_xen = 0;

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
	if (xen_start_info.flags & SIF_INITDOMAIN) {
		dom0_op_t op;
		last_rtc_update = last_update_to_xen = 0;
		op.cmd = DOM0_SETTIME;
		op.u.settime.secs        = xentime.tv_sec;
		op.u.settime.usecs       = xentime.tv_nsec / NSEC_PER_USEC;
		op.u.settime.system_time = shadow_system_time;
		write_sequnlock_irq(&xtime_lock);
		HYPERVISOR_dom0_op(&op);
	} else
#endif
		write_sequnlock_irq(&xtime_lock);

	clock_was_set();
	return 0;
}

EXPORT_SYMBOL(do_settimeofday);

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
static int set_rtc_mmss(unsigned long nowtime)
{
	int retval;

	/* gets recalled with irq locally disabled */
	spin_lock(&rtc_lock);
	if (efi_enabled)
		retval = efi_set_rtc_mmss(nowtime);
	else
		retval = mach_set_rtc_mmss(nowtime);
	spin_unlock(&rtc_lock);

	return retval;
}
#endif

/* monotonic_clock(): returns # of nanoseconds passed since time_init()
 *		Note: This function is required to return accurate
 *		time even in the absence of multiple timer ticks.
 */
unsigned long long monotonic_clock(void)
{
	return cur_timer->monotonic_clock();
}
EXPORT_SYMBOL(monotonic_clock);

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

/*
 * timer_interrupt() needs to keep up the real-time clock,
 * as well as call the "do_timer()" routine every clocktick
 */
static inline void do_timer_interrupt(int irq, void *dev_id,
					struct pt_regs *regs)
{
	time_t wtm_sec, sec;
	s64 delta, nsec;
	long sec_diff, wtm_nsec;

	do {
		__get_time_values_from_xen();

		delta = (s64)(shadow_system_time +
			      ((s64)cur_timer->get_offset() * 
			       (s64)NSEC_PER_USEC) -
			      processed_system_time);
	}
	while (!TIME_VALUES_UP_TO_DATE);

	if (unlikely(delta < 0)) {
		printk("Timer ISR: Time went backwards: %lld %lld %lld %lld\n",
		       delta, shadow_system_time,
		       ((s64)cur_timer->get_offset() * (s64)NSEC_PER_USEC), 
		       processed_system_time);
		return;
	}

	/* Process elapsed jiffies since last call. */
	while (delta >= NS_PER_TICK) {
		delta -= NS_PER_TICK;
		processed_system_time += NS_PER_TICK;
		do_timer(regs);
#ifndef CONFIG_SMP
		update_process_times(user_mode(regs));
#endif
		if (regs)
		    profile_tick(CPU_PROFILING, regs);
	}

	/*
	 * Take synchronised time from Xen once a minute if we're not
	 * synchronised ourselves, and we haven't chosen to keep an independent
	 * time base.
	 */
	if (!INDEPENDENT_WALLCLOCK() &&
	    ((time_status & STA_UNSYNC) != 0) &&
	    (xtime.tv_sec > (last_update_from_xen + 60))) {
		/* Adjust shadow for jiffies that haven't updated xtime yet. */
		shadow_tv.tv_usec -= 
			(jiffies - wall_jiffies) * (USEC_PER_SEC / HZ);
		HANDLE_USEC_UNDERFLOW(shadow_tv);

		/*
		 * Reset our running time counts if they are invalidated by
		 * a warp backwards of more than 500ms.
		 */
		sec_diff = xtime.tv_sec - shadow_tv.tv_sec;
		if (unlikely(abs(sec_diff) > 1) ||
		    unlikely(((sec_diff * USEC_PER_SEC) +
			      (xtime.tv_nsec / NSEC_PER_USEC) -
			      shadow_tv.tv_usec) > 500000)) {
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
			last_rtc_update = last_update_to_xen = 0;
#endif
			last_seen_tv.tv_sec = 0;
		}

		/* Update our unsynchronised xtime appropriately. */
		sec = shadow_tv.tv_sec;
		nsec = shadow_tv.tv_usec * NSEC_PER_USEC;

		__normalize_time(&sec, &nsec);
		wtm_sec  = wall_to_monotonic.tv_sec + (xtime.tv_sec - sec);
		wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - nsec);

		set_normalized_timespec(&xtime, sec, nsec);
		set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

		last_update_from_xen = sec;
	}

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
	if (!(xen_start_info.flags & SIF_INITDOMAIN))
		return;

	/* Send synchronised time to Xen approximately every minute. */
	if (((time_status & STA_UNSYNC) == 0) &&
	    (xtime.tv_sec > (last_update_to_xen + 60))) {
		dom0_op_t op;
		struct timeval tv;

		tv.tv_sec   = xtime.tv_sec;
		tv.tv_usec  = xtime.tv_nsec / NSEC_PER_USEC;
		tv.tv_usec += (jiffies - wall_jiffies) * (USEC_PER_SEC/HZ);
		HANDLE_USEC_OVERFLOW(tv);

		op.cmd = DOM0_SETTIME;
		op.u.settime.secs        = tv.tv_sec;
		op.u.settime.usecs       = tv.tv_usec;
		op.u.settime.system_time = shadow_system_time;
		HYPERVISOR_dom0_op(&op);

		last_update_to_xen = xtime.tv_sec;
	}

	/*
	 * If we have an externally synchronized Linux clock, then update
	 * CMOS clock accordingly every ~11 minutes. Set_rtc_mmss() has to be
	 * called as close as possible to 500 ms before the new second starts.
	 */
	if ((time_status & STA_UNSYNC) == 0 &&
	    xtime.tv_sec > last_rtc_update + 660 &&
	    (xtime.tv_nsec / 1000)
			>= USEC_AFTER - ((unsigned) TICK_SIZE) / 2 &&
	    (xtime.tv_nsec / 1000)
			<= USEC_BEFORE + ((unsigned) TICK_SIZE) / 2) {
		/* horrible...FIXME */
		if (efi_enabled) {
	 		if (efi_set_rtc_mmss(xtime.tv_sec) == 0)
				last_rtc_update = xtime.tv_sec;
			else
				last_rtc_update = xtime.tv_sec - 600;
		} else if (set_rtc_mmss(xtime.tv_sec) == 0)
			last_rtc_update = xtime.tv_sec;
		else
			last_rtc_update = xtime.tv_sec - 600; /* do it again in 60 s */
	}
#endif
}

/*
 * This is the same as the above, except we _also_ save the current
 * Time Stamp Counter value at the time of the timer interrupt, so that
 * we later on can estimate the time of day more exactly.
 */
irqreturn_t timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	/*
	 * Here we are in the timer irq handler. We just have irqs locally
	 * disabled but we don't know if the timer_bh is running on the other
	 * CPU. We need to avoid to SMP race with it. NOTE: we don' t need
	 * the irq version of write_lock because as just said we have irq
	 * locally disabled. -arca
	 */
	write_seqlock(&xtime_lock);
	do_timer_interrupt(irq, NULL, regs);
	write_sequnlock(&xtime_lock);
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

static long clock_cmos_diff, sleep_start;

static int timer_suspend(struct sys_device *dev, u32 state)
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
	sleep_length = get_cmos_time() - sleep_start;
	write_seqlock_irqsave(&xtime_lock, flags);
	xtime.tv_sec = sec;
	xtime.tv_nsec = 0;
	write_sequnlock_irqrestore(&xtime_lock, flags);
	jiffies += sleep_length * HZ;
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
void __init hpet_time_init(void)
{
	xtime.tv_sec = get_cmos_time();
	xtime.tv_nsec = (INITIAL_JIFFIES % HZ) * (NSEC_PER_SEC / HZ);
	set_normalized_timespec(&wall_to_monotonic,
		-xtime.tv_sec, -xtime.tv_nsec);

	if (hpet_enable() >= 0) {
		printk("Using HPET for base-timer\n");
	}

	cur_timer = select_timer();
	printk(KERN_INFO "Using %s for high-res timesource\n",cur_timer->name);

	time_init_hook();
}
#endif

/* Dynamically-mapped IRQ. */
static int TIMER_IRQ;

static struct irqaction irq_timer = {
	timer_interrupt, SA_INTERRUPT, CPU_MASK_NONE, "timer",
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
	__get_time_values_from_xen();
	xtime.tv_sec = shadow_tv.tv_sec;
	xtime.tv_nsec = shadow_tv.tv_usec * NSEC_PER_USEC;
	set_normalized_timespec(&wall_to_monotonic,
		-xtime.tv_sec, -xtime.tv_nsec);
	processed_system_time = shadow_system_time;

	if (timer_tsc_init.init(NULL) != 0)
		BUG();
	printk(KERN_INFO "Using %s for high-res timesource\n",cur_timer->name);

	TIMER_IRQ = bind_virq_to_irq(VIRQ_TIMER);

	(void)setup_irq(TIMER_IRQ, &irq_timer);
}

/* Convert jiffies to system time. Call with xtime_lock held for reading. */
static inline u64 __jiffies_to_st(unsigned long j) 
{
	return processed_system_time + ((j - jiffies) * NS_PER_TICK);
}

/*
 * This function works out when the the next timer function has to be
 * executed (by looking at the timer list) and sets the Xen one-shot
 * domain timer to the appropriate value. This is typically called in
 * cpu_idle() before the domain blocks.
 * 
 * The function returns a non-0 value on error conditions.
 * 
 * It must be called with interrupts disabled.
 */
int set_timeout_timer(void)
{
	u64 alarm = 0;
	int ret = 0;

	/*
	 * This is safe against long blocking (since calculations are
	 * not based on TSC deltas). It is also safe against warped
	 * system time since suspend-resume is cooperative and we
	 * would first get locked out. It is safe against normal
	 * updates of jiffies since interrupts are off.
	 */
	alarm = __jiffies_to_st(next_timer_interrupt());

	/* Failure is pretty bad, but we'd best soldier on. */
	if ( HYPERVISOR_set_timer_op(alarm) != 0 )
		ret = -1;

	return ret;
}

void time_suspend(void)
{
	/* nothing */
}

/* No locking required. We are only CPU running, and interrupts are off. */
void time_resume(void)
{
	if (timer_tsc_init.init(NULL) != 0)
		BUG();

	/* Get timebases for new environment. */ 
	__get_time_values_from_xen();

	/* Reset our own concept of passage of system time. */
	processed_system_time = shadow_system_time;

	/* Accept a warp in UTC (wall-clock) time. */
	last_seen_tv.tv_sec = 0;

	/* Make sure we resync UTC time with Xen on next timer interrupt. */
	last_update_from_xen = 0;
}

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
