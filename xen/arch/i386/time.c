/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 ****************************************************************************
 *
 *        File: i386/time.c
 *      Author: Rolf Neugebar & Keir Fraser
 * 
 * Environment: Xen Hypervisor
 * Description: modified version of Linux' time.c
 *              implements system and wall clock time.
 *              based on freebsd's implementation.
 */

/*
 *  linux/arch/i386/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 */

#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/interrupt.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>

#include <asm/io.h>
#include <xeno/smp.h>
#include <xeno/irq.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/mc146818rtc.h>

#ifdef TIME_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

extern rwlock_t xtime_lock;
extern unsigned long wall_jiffies;

/* GLOBAL */
unsigned long cpu_khz;  /* Detected as we calibrate the TSC */
unsigned long ticks_per_usec; /* TSC ticks per microsecond. */
spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;
int timer_ack = 0;
int do_timer_lists_from_pit = 0;

/* PRIVATE */
static unsigned int    rdtsc_bitshift;  /* Which 32 bits of TSC do we use?   */
static u64             cpu_freq;        /* CPU frequency (Hz)                */
static u32             st_scale_f;      /* Cycles -> ns, fractional part     */
static u32             st_scale_i;      /* Cycles -> ns, integer part        */
static u32             tsc_irq;         /* CPU0's TSC at last 'time update'  */
static s_time_t        stime_irq;       /* System time at last 'time update' */

static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    u64 full_tsc;

    write_lock(&xtime_lock);

#ifdef CONFIG_X86_IO_APIC
    if ( timer_ack ) 
    {
        extern spinlock_t i8259A_lock;
        spin_lock(&i8259A_lock);
        outb(0x0c, 0x20);
        /* Ack the IRQ; AEOI will end it automatically. */
        inb(0x20);
        spin_unlock(&i8259A_lock);
    }
#endif
    
    /*
     * Updates TSC timestamp (used to interpolate passage of time between
     * interrupts).
     */
    rdtscll(full_tsc);
    tsc_irq = (u32)(full_tsc >> rdtsc_bitshift);

    /* Updates xtime (wallclock time). */
    do_timer(regs);

    /* Updates system time (nanoseconds since boot). */
    stime_irq += MILLISECS(1000/HZ);

    write_unlock(&xtime_lock);

    /* Rough hack to allow accurate timers to sort-of-work with no APIC. */
    if ( do_timer_lists_from_pit )
        do_ac_timer();
}

static struct irqaction irq0  = { timer_interrupt, SA_INTERRUPT, 0,
                                  "timer", NULL, NULL};

/* ------ Calibrate the TSC ------- 
 * Return processor ticks per second / CALIBRATE_FRAC.
 */

#define CLOCK_TICK_RATE 1193180 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20      /* calibrate over 50ms */
#define CALIBRATE_LATCH ((CLOCK_TICK_RATE+(CALIBRATE_FRAC/2))/CALIBRATE_FRAC)

static unsigned long __init calibrate_tsc(void)
{
    unsigned long startlow, starthigh, endlow, endhigh, count;

    /* Set the Gate high, disable speaker */
    outb((inb(0x61) & ~0x02) | 0x01, 0x61);

    /*
     * Now let's take care of CTC channel 2
     *
     * Set the Gate high, program CTC channel 2 for mode 0, (interrupt on
     * terminal count mode), binary count, load 5 * LATCH count, (LSB and MSB)
     * to begin countdown.
     */
    outb(0xb0, 0x43);           /* binary, mode 0, LSB/MSB, Ch 2 */
    outb(CALIBRATE_LATCH & 0xff, 0x42); /* LSB of count */
    outb(CALIBRATE_LATCH >> 8, 0x42);   /* MSB of count */

    rdtsc(startlow, starthigh);
    for ( count = 0; (inb(0x61) & 0x20) == 0; count++ )
        continue;
    rdtsc(endlow, endhigh);

    /* Error if the CTC doesn't behave itself. */
    if ( count == 0 )
        return 0;

    /* [endhigh:endlow] = [endhigh:endlow] - [starthigh:startlow] */
    __asm__( "subl %2,%0 ; sbbl %3,%1"
             : "=a" (endlow), "=d" (endhigh)
             : "g" (startlow), "g" (starthigh), "0" (endlow), "1" (endhigh) );

    /* If quotient doesn't fit in 32 bits then we return error (zero). */
    return endhigh ? 0 : endlow;
}


/***************************************************************************
 * CMOS Timer functions
 ***************************************************************************/

/* Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * WARNING: this function will overflow on 2106-02-07 06:28:16 on
 * machines were long is 32-bit! (However, as time_t is signed, we
 * will already get problems at other places on 2038-01-19 03:14:08)
 */
static inline unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec)
{
    /* 1..12 -> 11,12,1..10: put Feb last since it has a leap day. */
    if ( 0 >= (int) (mon -= 2) )
    {
        mon += 12;
        year -= 1;
    }

    return ((((unsigned long)(year/4 - year/100 + year/400 + 367*mon/12 + day)+
              year*365 - 719499
        )*24 + hour /* now have hours */
        )*60 + min  /* now have minutes */
        )*60 + sec; /* finally seconds */
}

static unsigned long __get_cmos_time(void)
{
    unsigned int year, mon, day, hour, min, sec;

    sec  = CMOS_READ(RTC_SECONDS);
    min  = CMOS_READ(RTC_MINUTES);
    hour = CMOS_READ(RTC_HOURS);
    day  = CMOS_READ(RTC_DAY_OF_MONTH);
    mon  = CMOS_READ(RTC_MONTH);
    year = CMOS_READ(RTC_YEAR);
    
    if ( !(CMOS_READ(RTC_CONTROL) & RTC_DM_BINARY) || RTC_ALWAYS_BCD )
    {
        BCD_TO_BIN(sec);
        BCD_TO_BIN(min);
        BCD_TO_BIN(hour);
        BCD_TO_BIN(day);
        BCD_TO_BIN(mon);
        BCD_TO_BIN(year);
    }

    if ( (year += 1900) < 1970 )
        year += 100;

    return mktime(year, mon, day, hour, min, sec);
}

static unsigned long get_cmos_time(void)
{
    unsigned long res, flags;
    int i;

    spin_lock_irqsave(&rtc_lock, flags);

    /* read RTC exactly on falling edge of update flag */
    for ( i = 0 ; i < 1000000 ; i++ ) /* may take up to 1 second... */
        if ( (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) )
            break;
    for ( i = 0 ; i < 1000000 ; i++ ) /* must try at least 2.228 ms */
        if ( !(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) )
            break;

    res = __get_cmos_time();

    spin_unlock_irqrestore(&rtc_lock, flags);
    return res;
}

/***************************************************************************
 * System Time
 ***************************************************************************/

static inline u64 get_time_delta(void)
{
    s32      delta_tsc;
    u32      low;
    u64      delta, tsc;

    rdtscll(tsc);
    low = (u32)(tsc >> rdtsc_bitshift);
    delta_tsc = (s32)(low - tsc_irq);
    if ( unlikely(delta_tsc < 0) ) delta_tsc = 0;
    delta = ((u64)delta_tsc * st_scale_f);
    delta >>= 32;
    delta += ((u64)delta_tsc * st_scale_i);

    return delta;
}

s_time_t get_s_time(void)
{
    s_time_t now;
    unsigned long flags;

    read_lock_irqsave(&xtime_lock, flags);

    now = stime_irq + get_time_delta();

    /* Ensure that the returned system time is monotonically increasing. */
    {
        static s_time_t prev_now = 0;
        if ( unlikely(now < prev_now) )
            now = prev_now;
        prev_now = now;
    }

    read_unlock_irqrestore(&xtime_lock, flags);

    return now; 
}


void update_dom_time(shared_info_t *si)
{
    unsigned long flags;

    read_lock_irqsave(&xtime_lock, flags);

    si->time_version1++;
    wmb();

    /* NB. These two values don't actually ever change. */
    si->cpu_freq       = cpu_freq;
    si->rdtsc_bitshift = rdtsc_bitshift;

    si->system_time    = stime_irq;
    si->tsc_timestamp  = tsc_irq;
    si->wc_sec         = xtime.tv_sec;
    si->wc_usec        = xtime.tv_usec;
    si->wc_usec       += (jiffies - wall_jiffies) * (1000000 / HZ);
    while ( si->wc_usec >= 1000000 )
    {
        si->wc_usec -= 1000000;
        si->wc_sec++;
    }

    wmb();
    si->time_version2++;

    read_unlock_irqrestore(&xtime_lock, flags);
}


/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long usecs, u64 system_time_base)
{
    s64 delta;
    long _usecs = (long)usecs;

    write_lock_irq(&xtime_lock);

    delta = (s64)(stime_irq - system_time_base);

	_usecs += (long)(delta/1000);
	_usecs -= (jiffies - wall_jiffies) * (1000000 / HZ);

	while ( _usecs < 0 ) 
    {
		_usecs += 1000000;
		secs--;
	}

    xtime.tv_sec  = secs;
    xtime.tv_usec = _usecs;

    write_unlock_irq(&xtime_lock);

    update_dom_time(current->shared_info);
}


/* Late init function (after all CPUs are booted). */
int __init init_xeno_time()
{
    u64      scale;
    u64      full_tsc;
    unsigned int cpu_ghz;

    cpu_ghz = (unsigned int)(cpu_freq / 1000000000ULL);
    for ( rdtsc_bitshift = 0; cpu_ghz != 0; rdtsc_bitshift++, cpu_ghz >>= 1 )
        continue;

    scale  = 1000000000LL << (32 + rdtsc_bitshift);
    scale /= cpu_freq;
    st_scale_f = scale & 0xffffffff;
    st_scale_i = scale >> 32;

    /* System time ticks from zero. */
    rdtscll(full_tsc);
    stime_irq = (s_time_t)0;
    tsc_irq   = (u32)(full_tsc >> rdtsc_bitshift);

    /* Wallclock time starts as the initial RTC time. */
    xtime.tv_sec  = get_cmos_time();

    printk("Time init:\n");
    printk(".... System Time: %lldns\n", 
           NOW());
    printk(".... cpu_freq:    %08X:%08X\n", 
           (u32)(cpu_freq>>32), (u32)cpu_freq);
    printk(".... scale:       %08X:%08X\n", 
           (u32)(scale>>32), (u32)scale);
    printk(".... Wall Clock:  %lds %ldus\n", 
           xtime.tv_sec, xtime.tv_usec);

    return 0;
}


/* Early init function. */
void __init time_init(void)
{
    unsigned long ticks_per_frac = calibrate_tsc();

    if ( !ticks_per_frac )
        panic("Error calibrating TSC\n");

    ticks_per_usec = ticks_per_frac / (1000000/CALIBRATE_FRAC);
    cpu_khz = ticks_per_frac / (1000/CALIBRATE_FRAC);

    cpu_freq = (u64)ticks_per_frac * (u64)CALIBRATE_FRAC;

    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, &irq0);
}
