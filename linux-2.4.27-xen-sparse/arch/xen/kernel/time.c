/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 - Keir Fraser - University of Cambridge
 ****************************************************************************
 *
 *        File: arch/xen/kernel/time.c
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
 * fixed set_rtc_mmss, fixed time.year for >= 2000, new mktime
 * 1995-03-26    Markus Kuhn
 *      fixed 500 ms bug at call to set_rtc_mmss, fixed DS12887
 *      precision CMOS clock update
 * 1996-05-03    Ingo Molnar
 *      fixed time warps in do_[slow|fast]_gettimeoffset()
 * 1997-09-10 Updated NTP code according to technical memorandum Jan '96
 *  "A Kernel Model for Precision Timekeeping" by Dave Mills
 * 1998-09-05    (Various)
 * More robust do_fast_gettimeoffset() algorithm implemented
 * (works with APM, Cyrix 6x86MX and Centaur C6),
 * monotonic gettimeofday() with fast_get_timeoffset(),
 * drift-proof precision TSC calibration on boot
 * (C. Scott Ananian <cananian@alumni.princeton.edu>, Andrew D.
 * Balsa <andrebalsa@altern.org>, Philip Gladstone <philip@raptor.com>;
 * ported from 2.0.35 Jumbo-9 by Michael Krause <m.krause@tu-harburg.de>).
 * 1998-12-16    Andrea Arcangeli
 * Fixed Jumbo-9 code in 2.1.131: do_gettimeofday was missing 1 jiffy
 * because was not accounting lost_ticks.
 * 1998-12-24 Copyright (C) 1998  Andrea Arcangeli
 * Fixed a xtime SMP race (we need the xtime_lock rw spinlock to
 * serialize accesses to xtime/lost_ticks).
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
#include <linux/sysctl.h>
#include <linux/sysrq.h>

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;
extern rwlock_t xtime_lock;
extern unsigned long wall_jiffies;

unsigned long cpu_khz; /* get this from Xen, used elsewhere */

static unsigned int rdtsc_bitshift;
static u32 st_scale_f; /* convert ticks -> usecs */
static u32 st_scale_i; /* convert ticks -> usecs */

/* These are peridically updated in shared_info, and then copied here. */
static u32 shadow_tsc_stamp;
static u64 shadow_system_time;
static u32 shadow_time_version;
static struct timeval shadow_tv;

/*
 * We use this to ensure that gettimeofday() is monotonically increasing. We
 * only break this guarantee if the wall clock jumps backwards "a long way".
 */
static struct timeval last_seen_tv = {0,0};

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
/* Periodically propagate synchronised time base to the RTC and to Xen. */
static long last_update_to_rtc, last_update_to_xen;
#endif

/* Periodically take synchronised time base from Xen, if we need it. */
static long last_update_from_xen;   /* UTC seconds when last read Xen clock. */

/* Keep track of last time we did processing/updating of jiffies and xtime. */
static u64 processed_system_time;   /* System time (ns) at last processing. */

#define NS_PER_TICK (1000000000ULL/HZ)

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

/* Dynamically-mapped IRQs. */
static int time_irq, debug_irq;

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

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
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
        real_minutes += 30;  /* correct for half hour time zone */
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


/*
 * Reads a consistent set of time-base values from Xen, into a shadow data
 * area. Must be called with the xtime_lock held for writing.
 */
static void __get_time_values_from_xen(void)
{
    do {
        shadow_time_version = HYPERVISOR_shared_info->time_version2;
        rmb();
        shadow_tv.tv_sec    = HYPERVISOR_shared_info->wc_sec;
        shadow_tv.tv_usec   = HYPERVISOR_shared_info->wc_usec;
        shadow_tsc_stamp    = 
            (u32)(HYPERVISOR_shared_info->tsc_timestamp >> rdtsc_bitshift);
        shadow_system_time  = HYPERVISOR_shared_info->system_time;
        rmb();
    }
    while ( shadow_time_version != HYPERVISOR_shared_info->time_version1 );
}

#define TIME_VALUES_UP_TO_DATE \
 ({ rmb(); (shadow_time_version == HYPERVISOR_shared_info->time_version2); })


/*
 * Returns the system time elapsed, in ns, since the current shadow_timestamp
 * was calculated. Must be called with the xtime_lock held for reading.
 */
static inline unsigned long __get_time_delta_usecs(void)
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


/*
 * Returns the current time-of-day in UTC timeval format.
 */
void do_gettimeofday(struct timeval *tv)
{
    unsigned long flags, lost;
    struct timeval _tv;

 again:
    read_lock_irqsave(&xtime_lock, flags);

    _tv.tv_usec = __get_time_delta_usecs();
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
        __get_time_values_from_xen();
        write_unlock_irqrestore(&xtime_lock, flags);
        goto again;
    }

    HANDLE_USEC_OVERFLOW(_tv);

    /* Ensure that time-of-day is monotonically increasing. */
    if ( (_tv.tv_sec < last_seen_tv.tv_sec) ||
         ((_tv.tv_sec == last_seen_tv.tv_sec) &&
          (_tv.tv_usec < last_seen_tv.tv_usec)) )
        _tv = last_seen_tv;
    last_seen_tv = _tv;

    read_unlock_irqrestore(&xtime_lock, flags);

    *tv = _tv;
}


/*
 * Sets the current time-of-day based on passed-in UTC timeval parameter.
 */
void do_settimeofday(struct timeval *tv)
{
    struct timeval newtv;
    suseconds_t usec;
    
    if ( !INDEPENDENT_WALLCLOCK() )
        return;
    
    write_lock_irq(&xtime_lock);
    
    /*
     * Ensure we don't get blocked for a long time so that our time delta
     * overflows. If that were to happen then our shadow time values would
     * be stale, so we can retry with fresh ones.
     */
 again:
    usec = tv->tv_usec - __get_time_delta_usecs();
    if ( unlikely(!TIME_VALUES_UP_TO_DATE) )
    {
        __get_time_values_from_xen();
        goto again;
    }
    tv->tv_usec = usec;
    
    HANDLE_USEC_UNDERFLOW(*tv);
    
    newtv = *tv;
    
    tv->tv_usec -= (jiffies - wall_jiffies) * (1000000 / HZ);
    HANDLE_USEC_UNDERFLOW(*tv);

    xtime = *tv;
    time_adjust = 0;  /* stop active adjtime() */
    time_status |= STA_UNSYNC;
    time_maxerror = NTP_PHASE_LIMIT;
    time_esterror = NTP_PHASE_LIMIT;

    /* Reset all our running time counts. They make no sense now. */
    last_seen_tv.tv_sec = 0;
    last_update_from_xen = 0;

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
    if ( xen_start_info.flags & SIF_INITDOMAIN )
    {
        dom0_op_t op;
        last_update_to_rtc = last_update_to_xen = 0;
        op.cmd = DOM0_SETTIME;
        op.u.settime.secs        = newtv.tv_sec;
        op.u.settime.usecs       = newtv.tv_usec;
        op.u.settime.system_time = shadow_system_time;
        write_unlock_irq(&xtime_lock);
        HYPERVISOR_dom0_op(&op);
    }
    else
#endif
    {
        write_unlock_irq(&xtime_lock);
    }
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


/* Convert jiffies to system time. Call with xtime_lock held for reading. */
static inline u64 __jiffies_to_st(unsigned long j) 
{
    return processed_system_time + ((j - jiffies) * NS_PER_TICK);
}


static inline void do_timer_interrupt(int irq, void *dev_id,
                                      struct pt_regs *regs)
{
    s64 delta;
    unsigned long ticks = 0;
    long sec_diff;

    do {
        __get_time_values_from_xen();
        
        delta = (s64)(shadow_system_time + 
                      (__get_time_delta_usecs() * 1000) -
                      processed_system_time);
    }
    while ( !TIME_VALUES_UP_TO_DATE );

    if ( unlikely(delta < 0) )
    {
        printk("Timer ISR: Time went backwards: %lld\n", delta);
        return;
    }

    /* Process elapsed jiffies since last call. */
    while ( delta >= NS_PER_TICK )
    {
        ticks++;
        delta -= NS_PER_TICK;
        processed_system_time += NS_PER_TICK;
    }

    if ( ticks != 0 )
    {
        do_timer_ticks(ticks);

        if ( user_mode(regs) )
            update_process_times_us(ticks, 0);
        else
            update_process_times_us(0, ticks);
    }

    /*
     * Take synchronised time from Xen once a minute if we're not
     * synchronised ourselves, and we haven't chosen to keep an independent
     * time base.
     */
    if ( !INDEPENDENT_WALLCLOCK() &&
         ((time_status & STA_UNSYNC) != 0) &&
         (xtime.tv_sec > (last_update_from_xen + 60)) )
    {
        /* Adjust shadow timeval for jiffies that haven't updated xtime yet. */
        shadow_tv.tv_usec -= (jiffies - wall_jiffies) * (1000000/HZ);
        HANDLE_USEC_UNDERFLOW(shadow_tv);

        /*
         * Reset our running time counts if they are invalidated by a warp
         * backwards of more than 500ms.
         */
        sec_diff = xtime.tv_sec - shadow_tv.tv_sec;
        if ( unlikely(abs(sec_diff) > 1) ||
             unlikely(((sec_diff * 1000000) + 
                       xtime.tv_usec - shadow_tv.tv_usec) > 500000) )
        {
#ifdef CONFIG_XEN_PRIVILEGED_GUEST
            last_update_to_rtc = last_update_to_xen = 0;
#endif
            last_seen_tv.tv_sec = 0;
        }

        /* Update our unsynchronised xtime appropriately. */
        xtime = shadow_tv;

        last_update_from_xen = xtime.tv_sec;
    }

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
    if ( (xen_start_info.flags & SIF_INITDOMAIN) &&
         ((time_status & STA_UNSYNC) == 0) )
    {
        /* Send synchronised time to Xen approximately every minute. */
        if ( xtime.tv_sec > (last_update_to_xen + 60) )
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

            last_update_to_xen = xtime.tv_sec;
        }

        /*
         * If we have an externally synchronized Linux clock, then update CMOS
         * clock accordingly every ~11 minutes. Set_rtc_mmss() has to be called
         * as close as possible to 500 ms before the new second starts.
         */
        if ( (xtime.tv_sec > (last_update_to_rtc + 660)) &&
             (xtime.tv_usec >= (500000 - ((unsigned) tick) / 2)) &&
             (xtime.tv_usec <= (500000 + ((unsigned) tick) / 2)) )
        {
            if ( set_rtc_mmss(xtime.tv_sec) == 0 )
                last_update_to_rtc = xtime.tv_sec;
            else
                last_update_to_rtc = xtime.tv_sec - 600;
        }
    }
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
extern spinlock_t timerlist_lock;
int set_timeout_timer(void)
{
    struct timer_list *timer;
    u64 alarm = 0;
    int ret = 0;

    spin_lock(&timerlist_lock);

    /*
     * This is safe against long blocking (since calculations are not based on 
     * TSC deltas). It is also safe against warped system time since
     * suspend-resume is cooperative and we would first get locked out. It is 
     * safe against normal updates of jiffies since interrupts are off.
     */
    if ( (timer = next_timer_event()) != NULL )
        alarm = __jiffies_to_st(timer->expires);

    /* Tasks on the timer task queue expect to be executed on the next tick. */
    if ( TQ_ACTIVE(tq_timer) )
        alarm = __jiffies_to_st(jiffies + 1);

    /* Failure is pretty bad, but we'd best soldier on. */
    if ( HYPERVISOR_set_timer_op(alarm) != 0 )
        ret = -1;
    
    spin_unlock(&timerlist_lock);

    return ret;
}


/* Time debugging. */
static void dbg_time_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    unsigned long flags, j;
    u64 s_now, j_st;
    struct timeval s_tv, tv;

    struct timer_list *timer;
    u64 t_st;

    read_lock_irqsave(&xtime_lock, flags);
    s_tv.tv_sec  = shadow_tv.tv_sec;
    s_tv.tv_usec = shadow_tv.tv_usec;
    s_now        = shadow_system_time;
    read_unlock_irqrestore(&xtime_lock, flags);

    do_gettimeofday(&tv);

    j = jiffies;
    j_st = __jiffies_to_st(j);

    timer = next_timer_event();
    t_st = __jiffies_to_st(timer->expires);

    printk(KERN_ALERT "time: shadow_st=0x%X:%08X\n",
           (u32)(s_now>>32), (u32)s_now);
    printk(KERN_ALERT "time: wct=%lds %ldus shadow_wct=%lds %ldus\n",
           tv.tv_sec, tv.tv_usec, s_tv.tv_sec, s_tv.tv_usec);
    printk(KERN_ALERT "time: jiffies=%lu(0x%X:%08X) timeout=%lu(0x%X:%08X)\n",
           jiffies,(u32)(j_st>>32), (u32)j_st,
           timer->expires,(u32)(t_st>>32), (u32)t_st);
    printk(KERN_ALERT "time: processed_system_time=0x%X:%08X\n",
           (u32)(processed_system_time>>32), (u32)processed_system_time);

#ifdef CONFIG_MAGIC_SYSRQ
    handle_sysrq('t',NULL,NULL,NULL);
#endif
}

static struct irqaction dbg_time = {
    dbg_time_int, 
    SA_SHIRQ, 
    0, 
    "timer_dbg", 
    &dbg_time_int,
    NULL
};

void __init time_init(void)
{
    unsigned long long alarm;
    u64 __cpu_khz, __cpu_ghz, cpu_freq, scale, scale2;
    unsigned int cpu_ghz;

    __cpu_khz = __cpu_ghz = cpu_freq = HYPERVISOR_shared_info->cpu_freq;
    do_div(__cpu_khz, 1000UL);
    cpu_khz = (u32)__cpu_khz;
    do_div(__cpu_ghz, 1000000000UL);
    cpu_ghz = (unsigned int)__cpu_ghz;

    printk("Xen reported: %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    xtime.tv_sec = HYPERVISOR_shared_info->wc_sec;
    xtime.tv_usec = HYPERVISOR_shared_info->wc_usec;
    processed_system_time = shadow_system_time;

    for ( rdtsc_bitshift = 0; cpu_ghz != 0; rdtsc_bitshift++, cpu_ghz >>= 1 )
        continue;

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

    __get_time_values_from_xen();
    processed_system_time = shadow_system_time;

    time_irq  = bind_virq_to_irq(VIRQ_TIMER);
    debug_irq = bind_virq_to_irq(VIRQ_DEBUG);

    (void)setup_irq(time_irq, &irq_timer);
    (void)setup_irq(debug_irq, &dbg_time);

    rdtscll(alarm);
}

void time_suspend(void)
{
}

void time_resume(void)
{
    unsigned long flags;
    write_lock_irqsave(&xtime_lock, flags);
    /* Get timebases for new environment. */ 
    __get_time_values_from_xen();
    /* Reset our own concept of passage of system time. */
    processed_system_time = shadow_system_time;
    /* Accept a warp in UTC (wall-clock) time. */
    last_seen_tv.tv_sec = 0;
    /* Make sure we resync UTC time with Xen on next timer interrupt. */
    last_update_from_xen = 0;
    write_unlock_irqrestore(&xtime_lock, flags);
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
