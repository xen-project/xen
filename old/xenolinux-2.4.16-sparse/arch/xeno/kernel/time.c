/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: arch.xeno/time.c
 *      Author: Rolf Neugebauer
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: XenoLinux
 * Description: Interface with Hypervisor to get correct notion of time
 *              Currently supports Systemtime and WallClock time.
 *
 * (This has hardly any resemblence with the Linux code but left the
 *  copyright notice anyway. Ignore the comments in the copyright notice.)
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

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

#include <asm/smp.h>
#include <asm/irq.h>
#include <asm/msr.h>
#include <asm/delay.h>
#include <asm/mpspec.h>
#include <asm/uaccess.h>
#include <asm/processor.h>

#include <asm/div64.h>
#include <asm/hypervisor.h>

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/irq.h>

#undef XENO_TIME_DEBUG	/* adds sanity checks and periodic printouts */

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;
extern rwlock_t xtime_lock;

unsigned long cpu_khz;	/* get this from Xen, used elsewhere */
static spinlock_t hyp_stime_lock = SPIN_LOCK_UNLOCKED;
static spinlock_t hyp_wctime_lock = SPIN_LOCK_UNLOCKED;

static u32 st_scale_f;
static u32 st_scale_i;
static u32 shadow_st_pcc;
static s64 shadow_st;

/*
 * System time.
 * Although the rest of the Linux kernel doesn't know about this, we
 * we use it to extrapolate passage of wallclock time.
 * We need to read the values from the shared info page "atomically" 
 * and use the cycle counter value as the "version" number. Clashes
 * should be very rare.
 */
static inline long long get_s_time(void)
{
	unsigned long flags;
    u32           delta_tsc, low, pcc;
	u64           delta;
	s64           now;

	spin_lock_irqsave(&hyp_stime_lock, flags);

	while ((pcc = HYPERVISOR_shared_info->st_timestamp) != shadow_st_pcc)
	{
		barrier();
		shadow_st_pcc = pcc;
		shadow_st     = HYPERVISOR_shared_info->system_time;
		barrier();
	}

    now = shadow_st;
    /* only use bottom 32bits of TSC. This should be sufficient */
	rdtscl(low);
    delta_tsc = low - pcc;
	delta = ((u64)delta_tsc * st_scale_f);
	delta >>= 32;
	delta += ((u64)delta_tsc * st_scale_i);

	spin_unlock_irqrestore(&hyp_time_lock, flags);

    return now + delta; 

}
#define NOW()				((long long)get_s_time())

/*
 * Wallclock time.
 * Based on what the hypervisor tells us, extrapolated using system time.
 * Again need to read a number of values from the shared page "atomically".
 * this time using a version number.
 */
static u32        shadow_wc_version=0;
static long       shadow_tv_sec;
static long       shadow_tv_usec;
static long long  shadow_wc_timestamp;
void do_gettimeofday(struct timeval *tv)
{
	unsigned long flags;
    long          usec, sec;
	u32	          version;
	u64           now;

	spin_lock_irqsave(&hyp_wctime_lock, flags);

	while ((version = HYPERVISOR_shared_info->wc_version)!= shadow_wc_version)
	{
		barrier();
		shadow_wc_version   = version;
		shadow_tv_sec       = HYPERVISOR_shared_info->tv_sec;
		shadow_tv_usec      = HYPERVISOR_shared_info->tv_usec;
		shadow_wc_timestamp = HYPERVISOR_shared_info->wc_timestamp;
		barrier();
	}

	now   = NOW();
	usec  = ((unsigned long)(now-shadow_wc_timestamp))/1000;
	sec   = shadow_tv_sec;
	usec += shadow_tv_usec;

    while ( usec >= 1000000 ) 
    {
        usec -= 1000000;
        sec++;
    }

    tv->tv_sec = sec;
    tv->tv_usec = usec;

	spin_unlock_irqrestore(&hyp_time_lock, flags);

#ifdef XENO_TIME_DEBUG
	{
		static long long old_now=0;
		static long long wct=0, old_wct=0;

		/* This debug code checks if time increase over two subsequent calls */
		wct=(((long long)sec) * 1000000) + usec;
		/* wall clock time going backwards */
		if ((wct < old_wct) ) {	
			printk("Urgh1: wc diff=%6ld, usec = %ld (0x%lX)\n",
				   (long)(wct-old_wct), usec, usec);		
			printk("       st diff=%lld cur st=0x%016llX old st=0x%016llX\n",
				   now-old_now, now, old_now);
		}

		/* system time going backwards */
		if (now<=old_now) {
			printk("Urgh2: st diff=%lld cur st=0x%016llX old st=0x%016llX\n",
				   now-old_now, now, old_now);
		}
		old_wct  = wct;
		old_now  = now;
	}
#endif

}

void do_settimeofday(struct timeval *tv)
{
/* XXX RN: should do something special here for dom0 */
#if 0
    write_lock_irq(&xtime_lock);
    /*
     * This is revolting. We need to set "xtime" correctly. However, the
     * value in this location is the value at the most recent update of
     * wall time.  Discover what correction gettimeofday() would have
     * made, and then undo it!
     */
    tv->tv_usec -= do_gettimeoffset();
    tv->tv_usec -= (jiffies - wall_jiffies) * (1000000 / HZ);

    while ( tv->tv_usec < 0 )
    {
        tv->tv_usec += 1000000;
        tv->tv_sec--;
    }

    xtime = *tv;
    time_adjust = 0;		/* stop active adjtime() */
    time_status |= STA_UNSYNC;
    time_maxerror = NTP_PHASE_LIMIT;
    time_esterror = NTP_PHASE_LIMIT;
    write_unlock_irq(&xtime_lock);
#endif
}


/*
 * Timer ISR. 
 * Unlike normal Linux these don't come in at a fixed rate of HZ. 
 * In here we wrok out how often it should have been called and then call
 * the architecture independent part (do_timer()) the appropriate number of
 * times. A bit of a nasty hack, to keep the "other" notion of wallclock time
 * happy.
 */
static long long us_per_tick=1000000/HZ;
static long long last_irq;
static inline void do_timer_interrupt(int irq, void *dev_id,
									  struct pt_regs *regs)
{
	struct timeval tv;
	long long time, delta;
	
#ifdef XENO_TIME_DEBUG
	static u32 foo_count = 0;
	foo_count++;		
	if (foo_count>= 1000) {
		s64 n = NOW();
		struct timeval tv;
		do_gettimeofday(&tv);
		printk("0x%08X%08X %ld:%ld\n",
			   (u32)(n>>32), (u32)n, tv.tv_sec, tv.tv_usec);
		foo_count = 0;
	}
#endif
    /*
     * The next bit really sucks:
     * Linux not only uses do_gettimeofday() to keep a notion of
     * wallclock time, but also maintains the xtime struct and jiffies.
     * (Even worse some userland code accesses this via the sys_time()
     * system call)
     * Unfortunately, xtime is maintain in the architecture independent
     * part of the timer ISR (./kernel/timer.c sic!). So, although we have
     * perfectly valid notion of wallclock time from the hypervisor we here
     * fake missed timer interrupts so that the arch independent part of
     * the Timer ISR updates jiffies for us *and* once the bh gets run
     * updates xtime accordingly. Yuck!
     */

	/* work out the number of jiffies past and update them */
	do_gettimeofday(&tv);
	time = (((long long)tv.tv_sec) * 1000000) + tv.tv_usec;
	delta = time - last_irq;
	if (delta <= 0) {
		printk ("Timer ISR: Time went backwards: %lld\n", delta);
		return;
	}
	while (delta >= us_per_tick) {
		do_timer(regs);
		delta    -= us_per_tick;
		last_irq += us_per_tick;
	}

#if 0
    if (!user_mode(regs))
        x86_do_profile(regs->eip);
#endif
}

static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    write_lock(&xtime_lock);
    do_timer_interrupt(irq, NULL, regs);
    write_unlock(&xtime_lock);
}

static struct irqaction irq_timer = {
    timer_interrupt, 
    SA_INTERRUPT, 
    0, 
    "timer", 
    NULL, 
    NULL
};

void __init time_init(void)
{
    unsigned long long alarm;
	u64	cpu_freq = HYPERVISOR_shared_info->cpu_freq;
	u64 scale;

	do_get_fast_time = do_gettimeofday;

	cpu_khz = (u32)cpu_freq/1000;
	printk("Xen reported: %lu.%03lu MHz processor.\n", 
		   cpu_khz / 1000, cpu_khz % 1000);

	/*
     * calculate systemtime scaling factor
	 * XXX RN: have to cast cpu_freq to u32 limits it to 4.29 GHz. 
	 *     Get a better do_div!
	 */
	scale = 1000000000LL << 32;
	do_div(scale,(u32)cpu_freq);
	st_scale_f = scale & 0xffffffff;
	st_scale_i = scale >> 32;
	printk("System Time scale: %X %X\n",st_scale_i, st_scale_f);

	do_gettimeofday(&xtime);
	last_irq = (((long long)xtime.tv_sec) * 1000000) + xtime.tv_usec;

    setup_irq(TIMER_IRQ, &irq_timer);

    /*
     * Start ticker. Note that timing runs of wall clock, not virtual
     * 'domain' time. This means that clock sshould run at the correct
     * rate. For things like scheduling, it's not clear whether it
     * matters which sort of time we use.
	 * XXX RN: unimplemented.
     */

    rdtscll(alarm);
#if 0
    alarm += (1000/HZ)*HYPERVISOR_shared_info->ticks_per_ms;
    HYPERVISOR_shared_info->wall_timeout   = alarm;
    HYPERVISOR_shared_info->domain_timeout = ~0ULL;
#endif
    clear_bit(_EVENT_TIMER, &HYPERVISOR_shared_info->events);
}
