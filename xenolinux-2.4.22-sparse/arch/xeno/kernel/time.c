/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 - Keir Fraser - University of Cambridge
 ****************************************************************************
 *
 *        File: arch/xeno/kernel/time.c
 *      Author: Rolf Neugebauer and Keir Fraser
 * 
 * Description: Interface with Xen to get correct notion of time
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
#include <asm/hypervisor-ifs/dom0_ops.h>

#include <linux/mc146818rtc.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/irq.h>

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;
extern rwlock_t xtime_lock;
extern unsigned long wall_jiffies;

unsigned long cpu_khz;	/* get this from Xen, used elsewhere */

static unsigned int rdtsc_bitshift;
static u32 st_scale_f; /* convert ticks -> usecs */
static u32 st_scale_i; /* convert ticks -> usecs */

/* These are peridically updated in shared_info, and then copied here. */
static u32 shadow_tsc_stamp;
static s64 shadow_system_time;
static u32 shadow_time_version;
static struct timeval shadow_tv;

#ifdef CONFIG_XENO_PRIV
/* Periodically propagate synchronised time to the RTC and to Xen. */
static long last_rtc_update, last_xen_update;
#endif

static u64 processed_system_time;

#define HANDLE_USEC_UNDERFLOW(_tv)         \
    do {                                   \
        while ( (_tv).tv_usec < 0 )        \
        {                                  \
            (_tv).tv_usec += 1000000;      \
            (_tv).tv_sec--;                \
        }                                  \
    } while ( 0 )
#define HANDLE_USEC_OVERFLOW(_tv)          \
    do {                                   \
        while ( (_tv).tv_usec >= 1000000 ) \
        {                                  \
            (_tv).tv_usec -= 1000000;      \
            (_tv).tv_sec++;                \
        }                                  \
    } while ( 0 )


#ifdef CONFIG_XENO_PRIV
/*
 * In order to set the CMOS clock precisely, set_rtc_mmss has to be
 * called 500 ms after the second nowtime has started, because when
 * nowtime is written into the registers of the CMOS clock, it will
 * jump to the next second precisely 500 ms later. Check the Motorola
 * MC146818A or Dallas DS12887 data sheet for details.
 *
 * BUG: This routine does not handle hour overflow properly; it just
 *      sets the minutes. Usually you'll only notice that after reboot!
 */
static int set_rtc_mmss(unsigned long nowtime)
{
    int retval = 0;
    int real_seconds, real_minutes, cmos_minutes;
    unsigned char save_control, save_freq_select;

    /* gets recalled with irq locally disabled */
    spin_lock(&rtc_lock);
    save_control = CMOS_READ(RTC_CONTROL);
    CMOS_WRITE((save_control|RTC_SET), RTC_CONTROL);

    save_freq_select = CMOS_READ(RTC_FREQ_SELECT);
    CMOS_WRITE((save_freq_select|RTC_DIV_RESET2), RTC_FREQ_SELECT);

    cmos_minutes = CMOS_READ(RTC_MINUTES);
    if ( !(save_control & RTC_DM_BINARY) || RTC_ALWAYS_BCD )
        BCD_TO_BIN(cmos_minutes);

    /*
     * since we're only adjusting minutes and seconds, don't interfere with
     * hour overflow. This avoids messing with unknown time zones but requires
     * your RTC not to be off by more than 15 minutes
     */
    real_seconds = nowtime % 60;
    real_minutes = nowtime / 60;
    if ( ((abs(real_minutes - cmos_minutes) + 15)/30) & 1 )
        real_minutes += 30;		/* correct for half hour time zone */
    real_minutes %= 60;

    if ( abs(real_minutes - cmos_minutes) < 30 )
    {
        if ( !(save_control & RTC_DM_BINARY) || RTC_ALWAYS_BCD )
        {
            BIN_TO_BCD(real_seconds);
            BIN_TO_BCD(real_minutes);
        }
        CMOS_WRITE(real_seconds,RTC_SECONDS);
        CMOS_WRITE(real_minutes,RTC_MINUTES);
    }
    else 
    {
        printk(KERN_WARNING
               "set_rtc_mmss: can't update from %d to %d\n",
               cmos_minutes, real_minutes);
        retval = -1;
    }

    /* The following flags have to be released exactly in this order,
     * otherwise the DS12887 (popular MC146818A clone with integrated
     * battery and quartz) will not reset the oscillator and will not
     * update precisely 500 ms later. You won't find this mentioned in
     * the Dallas Semiconductor data sheets, but who believes data
     * sheets anyway ...                           -- Markus Kuhn
     */
    CMOS_WRITE(save_control, RTC_CONTROL);
    CMOS_WRITE(save_freq_select, RTC_FREQ_SELECT);
    spin_unlock(&rtc_lock);

    return retval;
}
#endif


/* Must be called with the xtime_lock held for writing. */
static void get_time_values_from_xen(void)
{
    do {
        shadow_time_version = HYPERVISOR_shared_info->time_version2;
        rmb();
        shadow_tv.tv_sec    = HYPERVISOR_shared_info->wc_sec;
        shadow_tv.tv_usec   = HYPERVISOR_shared_info->wc_usec;
        shadow_tsc_stamp    = HYPERVISOR_shared_info->tsc_timestamp;
        shadow_system_time  = HYPERVISOR_shared_info->system_time;
        rmb();
    }
    while ( shadow_time_version != HYPERVISOR_shared_info->time_version1 );
}

#define TIME_VALUES_UP_TO_DATE \
    (shadow_time_version == HYPERVISOR_shared_info->time_version2)


static inline unsigned long get_time_delta_usecs(void)
{
    s32      delta_tsc;
    u32      low;
    u64      delta, tsc;

    rdtscll(tsc);
    low = (u32)(tsc >> rdtsc_bitshift);
    delta_tsc = (s32)(low - shadow_tsc_stamp);
    if ( unlikely(delta_tsc < 0) ) delta_tsc = 0;
    delta = ((u64)delta_tsc * st_scale_f);
    delta >>= 32;
    delta += ((u64)delta_tsc * st_scale_i);

    return (unsigned long)delta;
}


void do_gettimeofday(struct timeval *tv)
{
	unsigned long flags, lost;
    struct timeval _tv;

 again:
    read_lock_irqsave(&xtime_lock, flags);
    _tv.tv_usec = get_time_delta_usecs();
    if ( (lost = (jiffies - wall_jiffies)) != 0 )
        _tv.tv_usec += lost * (1000000 / HZ);
    _tv.tv_sec   = xtime.tv_sec;
    _tv.tv_usec += xtime.tv_usec;
    if ( unlikely(!TIME_VALUES_UP_TO_DATE) )
    {
        /*
         * We may have blocked for a long time, rendering our calculations
         * invalid (e.g. the time delta may have overflowed). Detect that
         * and recalculate with fresh values.
         */
        read_unlock_irqrestore(&xtime_lock, flags);
        write_lock_irqsave(&xtime_lock, flags);
        get_time_values_from_xen();
        write_unlock_irqrestore(&xtime_lock, flags);
        goto again;
    }
    read_unlock_irqrestore(&xtime_lock, flags);

    HANDLE_USEC_OVERFLOW(_tv);

    *tv = _tv;
}

void do_settimeofday(struct timeval *tv)
{
#ifdef CONFIG_XENO_PRIV
    struct timeval newtv;
    dom0_op_t op;
    
    if ( start_info.dom_id != 0 )
        return;
    
    write_lock_irq(&xtime_lock);
    
    /*
     * Ensure we don't get blocked for a long time so that our time delta
     * overflows. If that were to happen then our shadow time values would
     * be stale, so we can retry with fresh ones.
     */
 again:
    tv->tv_usec -= get_time_delta_usecs();
    if ( unlikely(!TIME_VALUES_UP_TO_DATE) )
    {
        get_time_values_from_xen();
        goto again;
    }
    
    HANDLE_USEC_UNDERFLOW(*tv);
    
    newtv = *tv;
    
    tv->tv_usec -= (jiffies - wall_jiffies) * (1000000 / HZ);
    HANDLE_USEC_UNDERFLOW(*tv);

    xtime = *tv;
    time_adjust = 0;		/* stop active adjtime() */
    time_status |= STA_UNSYNC;
    time_maxerror = NTP_PHASE_LIMIT;
    time_esterror = NTP_PHASE_LIMIT;

    last_rtc_update = last_xen_update = 0;

    op.cmd = DOM0_SETTIME;
    op.u.settime.secs        = newtv.tv_sec;
    op.u.settime.usecs       = newtv.tv_usec;
    op.u.settime.system_time = shadow_system_time;

    write_unlock_irq(&xtime_lock);

    HYPERVISOR_dom0_op(&op);
#endif
}

asmlinkage long sys_stime(int *tptr)
{
	int value;
    struct timeval tv;

	if ( !capable(CAP_SYS_TIME) )
		return -EPERM;

	if ( get_user(value, tptr) )
		return -EFAULT;

    tv.tv_sec  = value;
    tv.tv_usec = 0;

    do_settimeofday(&tv);

	return 0;
}

#define NS_PER_TICK (1000000000ULL/HZ)
static inline void do_timer_interrupt(int irq, void *dev_id,
                                      struct pt_regs *regs)
{
    s64 delta;

    get_time_values_from_xen();

    if ( (delta = (s64)(shadow_system_time - processed_system_time)) < 0 )
    {
        printk("Timer ISR: Time went backwards: %lld\n", delta);
        return;
    }

    while ( delta >= NS_PER_TICK )
    {
        do_timer(regs);
        delta -= NS_PER_TICK;
        processed_system_time += NS_PER_TICK;
    }
    
    if ( (time_status & STA_UNSYNC) != 0 )
    {
        /* Adjust shadow timeval for jiffies that haven't updated xtime yet. */
        shadow_tv.tv_usec -= (jiffies - wall_jiffies) * (1000000/HZ);
        HANDLE_USEC_UNDERFLOW(shadow_tv);

        /* Update our unsynchronised xtime appropriately. */
        xtime = shadow_tv;
    }

#ifdef CONFIG_XENO_PRIV
	if ( (start_info.dom_id == 0) && ((time_status & STA_UNSYNC) == 0) )
    {
        /* Send synchronised time to Xen approximately every minute. */
        if ( xtime.tv_sec > (last_xen_update + 60) )
        {
            dom0_op_t op;
            struct timeval tv = xtime;

            tv.tv_usec += (jiffies - wall_jiffies) * (1000000/HZ);
            HANDLE_USEC_OVERFLOW(tv);

            op.cmd = DOM0_SETTIME;
            op.u.settime.secs        = tv.tv_sec;
            op.u.settime.usecs       = tv.tv_usec;
            op.u.settime.system_time = shadow_system_time;
            HYPERVISOR_dom0_op(&op);

            last_xen_update = xtime.tv_sec;
        }

        /*
         * If we have an externally synchronized Linux clock, then update CMOS
         * clock accordingly every ~11 minutes. Set_rtc_mmss() has to be called
         * as close as possible to 500 ms before the new second starts.
         */
        if ( (xtime.tv_sec > (last_rtc_update + 660)) &&
             (xtime.tv_usec >= (500000 - ((unsigned) tick) / 2)) &&
             (xtime.tv_usec <= (500000 + ((unsigned) tick) / 2)) )
        {
            if ( set_rtc_mmss(xtime.tv_sec) == 0 )
                last_rtc_update = xtime.tv_sec;
            else
                last_rtc_update = xtime.tv_sec - 600;
        }
    }
#endif
}

static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    write_lock(&xtime_lock);
    while ( !TIME_VALUES_UP_TO_DATE )
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
    u64 __cpu_khz, cpu_freq, scale, scale2;

    __cpu_khz = HYPERVISOR_shared_info->cpu_freq;
    do_div(__cpu_khz, 1000);
    cpu_khz = (u32)__cpu_khz;
    printk("Xen reported: %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    xtime.tv_sec = HYPERVISOR_shared_info->wc_sec;
    xtime.tv_usec = HYPERVISOR_shared_info->wc_usec;
    processed_system_time = shadow_system_time;

    rdtsc_bitshift      = HYPERVISOR_shared_info->rdtsc_bitshift;
    cpu_freq            = HYPERVISOR_shared_info->cpu_freq;

    scale = 1000000LL << (32 + rdtsc_bitshift);
    do_div(scale, (u32)cpu_freq);

    if ( (cpu_freq >> 32) != 0 )
    {
        scale2 = 1000000LL << rdtsc_bitshift;
        do_div(scale2, (u32)(cpu_freq>>32));
        scale += scale2;
    }

    st_scale_f = scale & 0xffffffff;
    st_scale_i = scale >> 32;

    setup_irq(TIMER_IRQ, &irq_timer);

    rdtscll(alarm);

    clear_bit(_EVENT_TIMER, &HYPERVISOR_shared_info->events);
}
