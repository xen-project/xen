/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz and Don Ahn.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)clock.c	7.2 (Berkeley) 5/12/91
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: src/sys/i386/isa/clock.c,v 1.207 2003/11/13 10:02:12 phk Exp $");

/* #define DELAYDEBUG */
/*
 * Routines to handle clock hardware.
 */

/*
 * inittodr, settodr and support routines written
 * by Christoph Robitschko <chmr@edvz.tu-graz.ac.at>
 *
 * reintroduced and updated by Chris Stenton <chris@gnome.co.uk> 8/10/94
 */

#include "opt_clock.h"
#include "opt_isa.h"
#include "opt_mca.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/timetc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/sysctl.h>
#include <sys/cons.h>
#include <sys/power.h>

#include <machine/clock.h>
#include <machine/cputypes.h>
#include <machine/frame.h>
#include <machine/intr_machdep.h>
#include <machine/md_var.h>
#include <machine/psl.h>
#if defined(SMP)
#include <machine/smp.h>
#endif
#include <machine/specialreg.h>

#include <i386/isa/icu.h>
#include <i386/isa/isa.h>
#include <isa/rtc.h>
#include <i386/isa/timerreg.h>

/* XEN specific defines */
#include <machine/xen_intr.h>

/*
 * 32-bit time_t's can't reach leap years before 1904 or after 2036, so we
 * can use a simple formula for leap years.
 */
#define	LEAPYEAR(y) (((u_int)(y) % 4 == 0) ? 1 : 0)
#define DAYSPERYEAR   (31+28+31+30+31+30+31+31+30+31+30+31)

int	adjkerntz;		/* local offset from GMT in seconds */
int	clkintr_pending;
int	disable_rtc_set = 1;	/* disable resettodr() if != 0 */
int	pscnt = 1;
int	psdiv = 1;
int	statclock_disable;
#ifndef TIMER_FREQ
#define TIMER_FREQ   1193182
#endif
u_int	timer_freq = TIMER_FREQ;
struct mtx clock_lock;


static	const u_char daysinmonth[] = {31,28,31,30,31,30,31,31,30,31,30,31};

/* Values for timerX_state: */
#define	RELEASED	0
#define	RELEASE_PENDING	1
#define	ACQUIRED	2
#define	ACQUIRE_PENDING	3

/* Cached *multiplier* to convert TSC counts to microseconds.
 * (see the equation below).
 * Equal to 2^32 * (1 / (clocks per usec) ).
 * Initialized in time_init.
 */
static unsigned long fast_gettimeoffset_quotient;

/* These are peridically updated in shared_info, and then copied here. */
static uint32_t shadow_tsc_stamp;
static uint64_t shadow_system_time;
static uint32_t shadow_time_version;
static struct timeval shadow_tv;

static uint64_t processed_system_time;/* System time (ns) at last processing. */

#define NS_PER_TICK (1000000000ULL/hz)

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
		shadow_tsc_stamp    = (uint32_t)s->tsc_timestamp;
		shadow_system_time  = s->system_time;
		rmb();
	}
	while (shadow_time_version != s->time_version1);
}

#define TIME_VALUES_UP_TO_DATE \
	(shadow_time_version == HYPERVISOR_shared_info->time_version2)

static	void	(*timer_func)(struct clockframe *frame) = hardclock;

static	unsigned xen_get_offset(void);
static	unsigned xen_get_timecount(struct timecounter *tc);

static struct timecounter xen_timecounter = {
	xen_get_timecount,	/* get_timecount */
	0,			/* no poll_pps */
	~0u,			/* counter_mask */
	0,			/* frequency */
	"ixen",			/* name */
	0			/* quality */
};


static void 
clkintr(struct clockframe *frame)
{
    int64_t delta;
    long ticks = 0;


    do {
    	__get_time_values_from_xen();
    	delta = (int64_t)(shadow_system_time + 
			  xen_get_offset() * 1000 - 
			  processed_system_time);
    } while (!TIME_VALUES_UP_TO_DATE);

    if (unlikely(delta < 0)) {
        printk("Timer ISR: Time went backwards: %lld\n", delta);
        return;
    }

    /* Process elapsed ticks since last call. */
    while ( delta >= NS_PER_TICK )
    {
        ticks++;
        delta -= NS_PER_TICK;
        processed_system_time += NS_PER_TICK;
    }

    if (ticks > 0) {
	if (frame)
		timer_func(frame);
#ifdef SMP
	if (timer_func == hardclock && frame)
		forward_hardclock();
#endif
    }
}

#include "opt_ddb.h"
static uint32_t
getit(void)
{
	__get_time_values_from_xen();
	return shadow_tsc_stamp;
}

/*
 * Wait "n" microseconds.
 * Relies on timer 1 counting down from (timer_freq / hz)
 * Note: timer had better have been programmed before this is first used!
 */
void
DELAY(int n)
{
	int delta, ticks_left;
	uint32_t tick, prev_tick;
#ifdef DELAYDEBUG
	int getit_calls = 1;
	int n1;
	static int state = 0;

	if (state == 0) {
		state = 1;
		for (n1 = 1; n1 <= 10000000; n1 *= 10)
			DELAY(n1);
		state = 2;
	}
	if (state == 1)
		printf("DELAY(%d)...", n);
#endif
	/*
	 * Read the counter first, so that the rest of the setup overhead is
	 * counted.  Guess the initial overhead is 20 usec (on most systems it
	 * takes about 1.5 usec for each of the i/o's in getit().  The loop
	 * takes about 6 usec on a 486/33 and 13 usec on a 386/20.  The
	 * multiplications and divisions to scale the count take a while).
	 *
	 * However, if ddb is active then use a fake counter since reading
	 * the i8254 counter involves acquiring a lock.  ddb must not go
	 * locking for many reasons, but it calls here for at least atkbd
	 * input.
	 */
	prev_tick = getit();

	n -= 0;			/* XXX actually guess no initial overhead */
	/*
	 * Calculate (n * (timer_freq / 1e6)) without using floating point
	 * and without any avoidable overflows.
	 */
	if (n <= 0)
		ticks_left = 0;
	else if (n < 256)
		/*
		 * Use fixed point to avoid a slow division by 1000000.
		 * 39099 = 1193182 * 2^15 / 10^6 rounded to nearest.
		 * 2^15 is the first power of 2 that gives exact results
		 * for n between 0 and 256.
		 */
		ticks_left = ((u_int)n * 39099 + (1 << 15) - 1) >> 15;
	else
		/*
		 * Don't bother using fixed point, although gcc-2.7.2
		 * generates particularly poor code for the long long
		 * division, since even the slow way will complete long
		 * before the delay is up (unless we're interrupted).
		 */
		ticks_left = ((u_int)n * (long long)timer_freq + 999999)
			     / 1000000;

	while (ticks_left > 0) {
		tick = getit();
#ifdef DELAYDEBUG
		++getit_calls;
#endif
		delta = tick - prev_tick;
		prev_tick = tick;
		if (delta < 0) {
			/*
			 * Guard against timer0_max_count being wrong.
			 * This shouldn't happen in normal operation,
			 * but it may happen if set_timer_freq() is
			 * traced.
			 */
			/* delta += timer0_max_count; ??? */
			if (delta < 0)
				delta = 0;
		}
		ticks_left -= delta;
	}
#ifdef DELAYDEBUG
	if (state == 1)
		printf(" %d calls to getit() at %d usec each\n",
		       getit_calls, (n + 5) / getit_calls);
#endif
}


int
sysbeep(int pitch, int period)
{
	return (0);
}

/*
 * Restore all the timers non-atomically (XXX: should be atomically).
 *
 * This function is called from pmtimer_resume() to restore all the timers.
 * This should not be necessary, but there are broken laptops that do not
 * restore all the timers on resume.
 */
void
timer_restore(void)
{
    /* Get timebases for new environment. */ 
    __get_time_values_from_xen();

    /* Reset our own concept of passage of system time. */
    processed_system_time = shadow_system_time;
}

void
startrtclock()
{
	unsigned long long alarm;
	uint64_t __cpu_khz;
	uint32_t cpu_khz;

	__cpu_khz = HYPERVISOR_shared_info->cpu_freq;
	__cpu_khz /= 1000;
	cpu_khz = (uint32_t)__cpu_khz;
	printk("Xen reported: %lu.%03lu MHz processor.\n", 
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
	timer_freq = tsc_freq = xen_timecounter.tc_frequency = cpu_khz * 1000;
        tc_init(&xen_timecounter);


	rdtscll(alarm);
}

/*
 * Initialize the time of day register, based on the time base which is, e.g.
 * from a filesystem.
 */
void
inittodr(time_t base)
{
	int		s, y;
	struct timespec ts;

	s = splclock();
	if (base) {
		ts.tv_sec = base;
		ts.tv_nsec = 0;
		tc_setclock(&ts);
	}

	y = time_second - shadow_tv.tv_sec;
	if (y <= -2 || y >= 2) {
		/* badly off, adjust it */
		ts.tv_sec = shadow_tv.tv_sec;
		ts.tv_nsec = shadow_tv.tv_usec * 1000;
		tc_setclock(&ts);
	}
	splx(s);
}

/*
 * Write system time back to RTC.  Not supported for guest domains.
 */
void
resettodr()
{
}


/*
 * Start clocks running.
 */
void
cpu_initclocks()
{
	int diag;
	int time_irq = bind_virq_to_irq(VIRQ_TIMER);

        if ((diag = intr_add_handler("clk", time_irq,
				     (driver_intr_t *)clkintr, NULL,
				     INTR_TYPE_CLK | INTR_FAST, NULL))) {
		panic("failed to register clock interrupt: %d\n", diag);
	}

	/* should fast clock be enabled ? */

	/* initialize xen values */
	__get_time_values_from_xen();
	processed_system_time = shadow_system_time;
}

void
cpu_startprofclock(void)
{

    	printf("cpu_startprofclock: profiling clock is not supported\n");
}

void
cpu_stopprofclock(void)
{

    	printf("cpu_stopprofclock: profiling clock is not supported\n");
}

static uint32_t
xen_get_timecount(struct timecounter *tc)
{
    	__get_time_values_from_xen();
	return shadow_tsc_stamp;
}

/*
 * Track behavior of cur_timer->get_offset() functionality in timer_tsc.c
 */
#undef rdtsc
#define rdtsc(low,high) \
     __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))

static uint32_t
xen_get_offset(void)
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

void
idle_block(void)
{
	if (HYPERVISOR_set_timer_op(processed_system_time + NS_PER_TICK) == 0)
		HYPERVISOR_block();
}
