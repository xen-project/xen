/******************************************************************************
 * arch/x86/time.c
 * 
 * Per-CPU time calibration and management.
 * 
 * Copyright (c) 2002-2005, K A Fraser
 * 
 * Portions from Linux are:
 * Copyright (c) 1991, 1992, 1995  Linus Torvalds
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/smp.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/mc146818rtc.h>
#include <asm/div64.h>
#include <io_ports.h>

#define EPOCH MILLISECS(1000)

unsigned long cpu_khz;  /* CPU clock frequency in kHz. */
spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;
int timer_ack = 0;
unsigned long volatile jiffies;
static unsigned long wc_sec, wc_usec; /* UTC time at last 'time update'. */

struct time_scale {
    int shift;
    u32 mul_frac;
};

struct cpu_time {
    u64 local_tsc_stamp;
    s_time_t stime_local_stamp;
    s_time_t stime_master_stamp;
    struct time_scale tsc_scale;
    struct ac_timer calibration_timer;
} __cacheline_aligned;

static struct cpu_time cpu_time[NR_CPUS];

/* Protected by platform_timer_lock. */
static s_time_t stime_platform_stamp;
static u64 platform_timer_stamp;
static struct time_scale platform_timer_scale;
static spinlock_t platform_timer_lock = SPIN_LOCK_UNLOCKED;

static inline u32 down_shift(u64 time, int shift)
{
    if ( shift < 0 )
        return (u32)(time >> -shift);
    return (u32)((u32)time << shift);
}

/*
 * 32-bit division of integer dividend and integer divisor yielding
 * 32-bit fractional quotient.
 */
static inline u32 div_frac(u32 dividend, u32 divisor)
{
    u32 quotient, remainder;
    ASSERT(dividend < divisor);
    __asm__ ( 
        "div %4"
        : "=a" (quotient), "=d" (remainder)
        : "0" (0), "1" (dividend), "r" (divisor) );
    return quotient;
}

/*
 * 32-bit multiplication of multiplicand and fractional multiplier
 * yielding 32-bit product (radix point at same position as in multiplicand).
 */
static inline u32 mul_frac(u32 multiplicand, u32 multiplier)
{
    u32 product_int, product_frac;
    __asm__ (
        "mul %3"
        : "=a" (product_frac), "=d" (product_int)
        : "0" (multiplicand), "r" (multiplier) );
    return product_int;
}

void timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    if ( timer_ack ) 
    {
        extern spinlock_t i8259A_lock;
        spin_lock(&i8259A_lock);
        outb(0x0c, 0x20);
        /* Ack the IRQ; AEOI will end it automatically. */
        inb(0x20);
        spin_unlock(&i8259A_lock);
    }
    
    /* Update jiffies counter. */
    (*(unsigned long *)&jiffies)++;

    /* Rough hack to allow accurate timers to sort-of-work with no APIC. */
    if ( !cpu_has_apic )
        raise_softirq(AC_TIMER_SOFTIRQ);
}

static struct irqaction irq0 = { timer_interrupt, "timer", NULL};

/* ------ Calibrate the TSC ------- 
 * Return processor ticks per second / CALIBRATE_FRAC.
 */

#define CLOCK_TICK_RATE 1193180 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20      /* calibrate over 50ms */
#define CALIBRATE_LATCH ((CLOCK_TICK_RATE+(CALIBRATE_FRAC/2))/CALIBRATE_FRAC)

static u64 calibrate_boot_tsc(void)
{
    u64 start, end;
    unsigned long count;

    /* Set the Gate high, disable speaker */
    outb((inb(0x61) & ~0x02) | 0x01, 0x61);

    /*
     * Now let's take care of CTC channel 2
     *
     * Set the Gate high, program CTC channel 2 for mode 0, (interrupt on
     * terminal count mode), binary count, load 5 * LATCH count, (LSB and MSB)
     * to begin countdown.
     */
    outb(0xb0, PIT_MODE);           /* binary, mode 0, LSB/MSB, Ch 2 */
    outb(CALIBRATE_LATCH & 0xff, PIT_CH2); /* LSB of count */
    outb(CALIBRATE_LATCH >> 8, PIT_CH2);   /* MSB of count */

    rdtscll(start);
    for ( count = 0; (inb(0x61) & 0x20) == 0; count++ )
        continue;
    rdtscll(end);

    /* Error if the CTC doesn't behave itself. */
    if ( count == 0 )
        return 0;

    return ((end - start) * (u64)CALIBRATE_FRAC);
}

static void set_time_scale(struct time_scale *ts, u64 ticks_per_sec)
{
    u64 tps64 = ticks_per_sec;
    u32 tps32;
    int shift = 0;

    while ( tps64 > (MILLISECS(1000)*2) )
    {
        tps64 >>= 1;
        shift--;
    }

    tps32 = (u32)tps64;
    while ( tps32 < (u32)MILLISECS(1000) )
    {
        tps32 <<= 1;
        shift++;
    }

    ts->mul_frac = div_frac(MILLISECS(1000), tps32);
    ts->shift    = shift;
}

static atomic_t tsc_calibrate_gang = ATOMIC_INIT(0);
static unsigned int tsc_calibrate_status = 0;

void calibrate_tsc_bp(void)
{
    while ( atomic_read(&tsc_calibrate_gang) != (num_booting_cpus() - 1) )
        mb();

    outb(CALIBRATE_LATCH & 0xff, PIT_CH2);
    outb(CALIBRATE_LATCH >> 8, PIT_CH2);

    tsc_calibrate_status = 1;
	wmb();

    while ( (inb(0x61) & 0x20) == 0 )
        continue;

    tsc_calibrate_status = 2;
	wmb();

    while ( atomic_read(&tsc_calibrate_gang) != 0 )
        mb();
}

void calibrate_tsc_ap(void)
{
    u64 t1, t2, ticks_per_sec;

    atomic_inc(&tsc_calibrate_gang);

    while ( tsc_calibrate_status < 1 )
        mb();

    rdtscll(t1);

    while ( tsc_calibrate_status < 2 )
        mb();

    rdtscll(t2);

    ticks_per_sec = (t2 - t1) * (u64)CALIBRATE_FRAC;
    set_time_scale(&cpu_time[smp_processor_id()].tsc_scale, ticks_per_sec);

    atomic_dec(&tsc_calibrate_gang);
}

/* Protected by platform_timer_lock. */
static u64 platform_pit_counter;
static u16 pit_stamp;
static struct ac_timer pit_overflow_timer;

static u16 pit_read_counter(void)
{
    u16 count;
    ASSERT(spin_is_locked(&platform_timer_lock));
    outb(0x80, PIT_MODE);
    count  = inb(PIT_CH2);
    count |= inb(PIT_CH2) << 8;
    return count;
}

static void pit_overflow(void *unused)
{
    u16 counter;

    spin_lock(&platform_timer_lock);
    counter = pit_read_counter();
    platform_pit_counter += (u16)(pit_stamp - counter);
    pit_stamp = counter;
    spin_unlock(&platform_timer_lock);

    set_ac_timer(&pit_overflow_timer, NOW() + MILLISECS(20));
}

static void init_platform_timer(void)
{
    init_ac_timer(&pit_overflow_timer, pit_overflow, NULL, 0);
    pit_overflow(NULL);
    platform_timer_stamp = platform_pit_counter;
    set_time_scale(&platform_timer_scale, CLOCK_TICK_RATE);
}

static s_time_t __read_platform_stime(u64 platform_time)
{
    u64 diff64 = platform_time - platform_timer_stamp;
    u32 diff   = down_shift(diff64, platform_timer_scale.shift);
    ASSERT(spin_is_locked(&platform_timer_lock));
    return (stime_platform_stamp + 
            (u64)mul_frac(diff, platform_timer_scale.mul_frac));
}

static s_time_t read_platform_stime(void)
{
    u64 counter;
    s_time_t stime;

    spin_lock(&platform_timer_lock);
    counter = platform_pit_counter + (u16)(pit_stamp - pit_read_counter());
    stime   = __read_platform_stime(counter);
    spin_unlock(&platform_timer_lock);

    return stime;
}

static void platform_time_calibration(void)
{
    u64 counter;
    s_time_t stamp;

    spin_lock(&platform_timer_lock);
    counter = platform_pit_counter + (u16)(pit_stamp - pit_read_counter());
    stamp   = __read_platform_stime(counter);
    stime_platform_stamp = stamp;
    platform_timer_stamp = counter;
    spin_unlock(&platform_timer_lock);
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

s_time_t get_s_time(void)
{
    struct cpu_time *t = &cpu_time[smp_processor_id()];
    u64 tsc;
    u32 delta;
    s_time_t now;

    rdtscll(tsc);
    delta = down_shift(tsc - t->local_tsc_stamp, t->tsc_scale.shift);
    now = t->stime_local_stamp + (u64)mul_frac(delta, t->tsc_scale.mul_frac);

    return now;
}

static inline void __update_dom_time(struct vcpu *v)
{
    struct cpu_time       *t = &cpu_time[smp_processor_id()];
    struct vcpu_time_info *u = &v->domain->shared_info->vcpu_time[v->vcpu_id];

    u->time_version1++;
    wmb();

    u->tsc_timestamp     = t->local_tsc_stamp;
    u->system_time       = t->stime_local_stamp;
    u->tsc_to_system_mul = t->tsc_scale.mul_frac;
    u->tsc_shift         = (s8)t->tsc_scale.shift;

    wmb();
    u->time_version2++;

    /* Should only do this during do_settime(). */
    v->domain->shared_info->wc_sec  = wc_sec;
    v->domain->shared_info->wc_usec = wc_usec;
}

void update_dom_time(struct vcpu *v)
{
    if ( v->domain->shared_info->vcpu_time[v->vcpu_id].tsc_timestamp != 
         cpu_time[smp_processor_id()].local_tsc_stamp )
        __update_dom_time(v);
}

/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long usecs, u64 system_time_base)
{
    u64 x, base_usecs;
    u32 y;

    base_usecs = system_time_base;
    do_div(base_usecs, 1000);

    x = (secs * 1000000ULL) + (u64)usecs + base_usecs;
    y = do_div(x, 1000000);

    wc_sec  = (unsigned long)x;
    wc_usec = (unsigned long)y;

    __update_dom_time(current);
}

static void local_time_calibration(void *unused)
{
    unsigned int cpu = smp_processor_id();

    /*
     * System timestamps, extrapolated from local and master oscillators,
     * taken during this calibration and the previous calibration.
     */
    s_time_t prev_local_stime, curr_local_stime;
    s_time_t prev_master_stime, curr_master_stime;

    /* TSC timestamps taken during this calibration and prev calibration. */
    u64 prev_tsc, curr_tsc;

    /*
     * System time and TSC ticks elapsed during the previous calibration
     * 'epoch'. These values are down-shifted to fit in 32 bits.
     */
    u64 stime_elapsed64, tsc_elapsed64;
    u32 stime_elapsed32, tsc_elapsed32;

    /* The accumulated error in the local estimate. */
    u64 local_stime_err;

    /* Error correction to slow down a fast local clock. */
    u32 error_factor = 0;

    /* Calculated TSC shift to ensure 32-bit scale multiplier. */
    int tsc_shift = 0;

    /* The overall calibration scale multiplier. */
    u32 calibration_mul_frac;

    prev_tsc          = cpu_time[cpu].local_tsc_stamp;
    prev_local_stime  = cpu_time[cpu].stime_local_stamp;
    prev_master_stime = cpu_time[cpu].stime_master_stamp;

    /* Disable IRQs to get 'instantaneous' current timestamps. */
    local_irq_disable();
    rdtscll(curr_tsc);
    curr_local_stime  = get_s_time();
    curr_master_stime = read_platform_stime();
    local_irq_enable();

#if 0
    printk("PRE%d: tsc=%lld stime=%lld master=%lld\n",
           cpu, prev_tsc, prev_local_stime, prev_master_stime);
    printk("CUR%d: tsc=%lld stime=%lld master=%lld %lld\n",
           cpu, curr_tsc, curr_local_stime, curr_master_stime,
           platform_pit_counter);
#endif

    /* Local time warps forward if it lags behind master time. */
    if ( curr_local_stime < curr_master_stime )
        curr_local_stime = curr_master_stime;

    stime_elapsed64 = curr_master_stime - prev_master_stime;
    tsc_elapsed64   = curr_tsc - prev_tsc;

    /*
     * Calculate error-correction factor. This only slows down a fast local
     * clock (slow clocks are warped forwards). The scale factor is clamped
     * to >= 0.5.
     */
    if ( curr_local_stime != curr_master_stime )
    {
        local_stime_err = curr_local_stime - curr_master_stime;
        if ( local_stime_err > EPOCH )
            local_stime_err = EPOCH;
        error_factor = div_frac(EPOCH, EPOCH + (u32)local_stime_err);
    }

    /*
     * We require 0 < stime_elapsed < 2^31.
     * This allows us to binary shift a 32-bit tsc_elapsed such that:
     * stime_elapsed < tsc_elapsed <= 2*stime_elapsed
     */
    while ( ((u32)stime_elapsed64 != stime_elapsed64) ||
            ((s32)stime_elapsed64 < 0) )
    {
        stime_elapsed64 >>= 1;
        tsc_elapsed64   >>= 1;
    }

    /* stime_master_diff now fits in a 32-bit word. */
    stime_elapsed32 = (u32)stime_elapsed64;

    /* tsc_elapsed <= 2*stime_elapsed */
    while ( tsc_elapsed64 > (stime_elapsed32 * 2) )
    {
        tsc_elapsed64 >>= 1;
        tsc_shift--;
    }

    /* Local difference must now fit in 32 bits. */
    ASSERT((u32)tsc_elapsed64 == tsc_elapsed64);
    tsc_elapsed32 = (u32)tsc_elapsed64;

    /* tsc_elapsed > stime_elapsed */
    ASSERT(tsc_elapsed32 != 0);
    while ( tsc_elapsed32 <= stime_elapsed32 )
    {
        tsc_elapsed32 <<= 1;
        tsc_shift++;
    }

    calibration_mul_frac = div_frac(stime_elapsed32, tsc_elapsed32);
    if ( error_factor != 0 )
        calibration_mul_frac = mul_frac(calibration_mul_frac, error_factor);

#if 0
    printk("---%d: %08x %d\n", cpu, calibration_mul_frac, tsc_shift);
#endif

    /* Record new timestamp information. */
    cpu_time[cpu].tsc_scale.mul_frac = calibration_mul_frac;
    cpu_time[cpu].tsc_scale.shift    = tsc_shift;
    cpu_time[cpu].local_tsc_stamp    = curr_tsc;
    cpu_time[cpu].stime_local_stamp  = curr_local_stime;
    cpu_time[cpu].stime_master_stamp = curr_master_stime;

    set_ac_timer(&cpu_time[cpu].calibration_timer, NOW() + EPOCH);

    if ( cpu == 0 )
        platform_time_calibration();
}

void init_percpu_time(void)
{
    unsigned int cpu = smp_processor_id();
    unsigned long flags;
    s_time_t now;

    local_irq_save(flags);
    rdtscll(cpu_time[cpu].local_tsc_stamp);
    now = (cpu == 0) ? 0 : read_platform_stime();
    local_irq_restore(flags);

    cpu_time[cpu].stime_master_stamp = now;
    cpu_time[cpu].stime_local_stamp  = now;

    init_ac_timer(&cpu_time[cpu].calibration_timer,
                  local_time_calibration, NULL, cpu);
    set_ac_timer(&cpu_time[cpu].calibration_timer, NOW() + EPOCH);
}

/* Late init function (after all CPUs are booted). */
int __init init_xen_time(void)
{
    wc_sec = get_cmos_time();

    local_irq_disable();

    init_percpu_time();

    stime_platform_stamp = 0;
    init_platform_timer();

    local_irq_enable();

    return 0;
}


/* Early init function. */
void __init early_time_init(void)
{
    u64 tmp = calibrate_boot_tsc();

    set_time_scale(&cpu_time[0].tsc_scale, tmp);

    do_div(tmp, 1000);
    cpu_khz = (unsigned long)tmp;
    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, &irq0);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
