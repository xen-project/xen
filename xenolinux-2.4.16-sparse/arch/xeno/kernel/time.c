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

#include <asm/io.h>
#include <asm/smp.h>
#include <asm/irq.h>
#include <asm/msr.h>
#include <asm/delay.h>
#include <asm/mpspec.h>
#include <asm/uaccess.h>
#include <asm/processor.h>

#include <linux/mc146818rtc.h>
#include <linux/timex.h>
#include <linux/config.h>

#include <asm/hypervisor.h>

#include <linux/irq.h>


unsigned long cpu_khz;	/* Detected as we calibrate the TSC */

/* Cached *multiplier* to convert TSC counts to microseconds.
 * (see the equation below).
 * Equal to 2^32 * (1 / (clocks per usec) ).
 * Initialized in time_init.
 */
unsigned long fast_gettimeoffset_quotient;

extern rwlock_t xtime_lock;
extern unsigned long wall_jiffies;

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;

static inline unsigned long ticks_to_secs(unsigned long long ticks)
{
    unsigned long lo, hi;
    unsigned long little_ticks;

    little_ticks = ticks /* XXX URK! XXX / 1000000ULL */;

    __asm__ __volatile__ (
        "mull %2"
        : "=a" (lo), "=d" (hi)
        : "rm" (fast_gettimeoffset_quotient), "0" (little_ticks) );

    return(hi);
}

/* NB. Only 32 bits of ticks are considered here. */
static inline unsigned long ticks_to_us(unsigned long ticks)
{
    unsigned long lo, hi;

    __asm__ __volatile__ (
        "mull %2"
        : "=a" (lo), "=d" (hi)
        : "rm" (fast_gettimeoffset_quotient), "0" (ticks) );

    return(hi);
}

static inline unsigned long do_gettimeoffset(void)
{
#if 0
    register unsigned long eax, edx;

    /* Read the Time Stamp Counter */

    rdtsc(eax,edx);

    /* .. relative to previous jiffy (32 bits is enough) */
    eax -= last_tsc_low;	/* tsc_low delta */

    /*
     * Time offset = (tsc_low delta) * fast_gettimeoffset_quotient
     *             = (tsc_low delta) * (usecs_per_clock)
     *             = (tsc_low delta) * (usecs_per_jiffy / clocks_per_jiffy)
     *
     * Using a mull instead of a divl saves up to 31 clock cycles
     * in the critical path.
     */
    
    edx = ticks_to_us(eax);

    /* our adjusted time offset in microseconds */
    return delay_at_last_interrupt + edx;
#else
    /*
     * We should keep a 'last_tsc_low' thing which incorporates 
     * delay_at_last_interrupt, adjusted in timer_interrupt after
     * do_timer_interrupt. It would look at change in xtime, and
     * make appropriate adjustment to a last_tsc variable.
     * 
     * We'd be affected by rounding error in ticks_per_usec, and by
     * processor clock drift (which should be no more than in an
     * external interrupt source anyhow). 
     * 
     * Perhaps a bit rough and ready, but never mind!
     */
    return 0;
#endif
}

/*
 * This version of gettimeofday has microsecond resolution
 * and better than microsecond precision on fast x86 machines with TSC.
 */
void do_gettimeofday(struct timeval *tv)
{
    unsigned long flags;
    unsigned long usec, sec, lost;

    read_lock_irqsave(&xtime_lock, flags);
    usec = do_gettimeoffset();
    lost = jiffies - wall_jiffies;
    if ( lost != 0 ) usec += lost * (1000000 / HZ);
    sec = xtime.tv_sec;
    usec += xtime.tv_usec;
    read_unlock_irqrestore(&xtime_lock, flags);

    while ( usec >= 1000000 ) 
    {
        usec -= 1000000;
        sec++;
    }

    tv->tv_sec = sec;
    tv->tv_usec = usec;
}

void do_settimeofday(struct timeval *tv)
{
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
}


/*
 * timer_interrupt() needs to keep up the real-time clock,
 * as well as call the "do_timer()" routine every clocktick
 */
static inline void do_timer_interrupt(
    int irq, void *dev_id, struct pt_regs *regs)
{
    do_timer(regs);
#if 0
    if (!user_mode(regs))
        x86_do_profile(regs->eip);
#endif
}


/*
 * This is the same as the above, except we _also_ save the current
 * Time Stamp Counter value at the time of the timer interrupt, so that
 * we later on can estimate the time of day more exactly.
 */
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


unsigned long get_cmos_time(void)
{
    unsigned long secs = HYPERVISOR_shared_info->rtc_time;
    unsigned long diff;

    rdtscl(diff);
    diff -= (unsigned long)HYPERVISOR_shared_info->rtc_timestamp;

    secs += ticks_to_us(diff);

    return(secs + ticks_to_secs(diff));
}


/* Return 2^32 * (1 / (TSC clocks per usec)) for do_fast_gettimeoffset(). */
static unsigned long __init calibrate_tsc(void)
{
    unsigned long quo, rem;

    /* quotient == (1000 * 2^32) / ticks_per ms */
    __asm__ __volatile__ (
        "divl %2"
        : "=a" (quo), "=d" (rem)
        : "r" (HYPERVISOR_shared_info->ticks_per_ms), "0" (0), "1" (1000) );

    return(quo);
}

void __init time_init(void)
{
    unsigned long long alarm;
	
    fast_gettimeoffset_quotient = calibrate_tsc();
    do_get_fast_time = do_gettimeofday;

    /* report CPU clock rate in Hz.
     * The formula is (10^6 * 2^32) / (2^32 * 1 / (clocks/us)) =
     * clock/second. Our precision is about 100 ppm.
     */
    {	
        unsigned long eax=0, edx=1000;
        __asm__ __volatile__
            ("divl %2"
             :"=a" (cpu_khz), "=d" (edx)
             :"r" (fast_gettimeoffset_quotient),
             "0" (eax), "1" (edx));
        printk("Detected %lu.%03lu MHz processor.\n", 
               cpu_khz / 1000, cpu_khz % 1000);
    }

    setup_irq(TIMER_IRQ, &irq_timer);

    /*
     * Start ticker. Note that timing runs of wall clock, not virtual
     * 'domain' time. This means that clock sshould run at the correct
     * rate. For things like scheduling, it's not clear whether it
     * matters which sort of time we use.
     */
    rdtscll(alarm);
    alarm += (1000/HZ)*HYPERVISOR_shared_info->ticks_per_ms;
    HYPERVISOR_shared_info->wall_timeout   = alarm;
    HYPERVISOR_shared_info->domain_timeout = ~0ULL;
    clear_bit(_EVENT_TIMER, &HYPERVISOR_shared_info->events);

    xtime.tv_sec = get_cmos_time();
    xtime.tv_usec = 0;
}
