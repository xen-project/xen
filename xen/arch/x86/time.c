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

#include <xen/errno.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/smp.h>
#include <xen/irq.h>
#include <xen/pci_ids.h>
#include <xen/softirq.h>
#include <xen/efi.h>
#include <xen/cpuidle.h>
#include <xen/symbols.h>
#include <xen/keyhandler.h>
#include <xen/guest_access.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <asm/iocap.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/guest.h>
#include <asm/mc146818rtc.h>
#include <asm/mwait.h>
#include <asm/div64.h>
#include <asm/acpi.h>
#include <asm/hpet.h>
#include <io_ports.h>
#include <asm/setup.h> /* for early_time_init */
#include <public/arch-x86/cpuid.h>

/* opt_clocksource: Force clocksource to one of: pit, hpet, acpi. */
static char __initdata opt_clocksource[10];
string_param("clocksource", opt_clocksource);

unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */
DEFINE_SPINLOCK(rtc_lock);
unsigned long pit0_ticks;

struct cpu_time_stamp {
    u64 local_tsc;
    s_time_t local_stime;
    /* Next field unconditionally valid only when !CONSTANT_TSC. */
    s_time_t master_stime;
};

struct cpu_time {
    struct cpu_time_stamp stamp;
    struct time_scale tsc_scale;
};

struct platform_timesource {
    const char *id;
    const char *name;
    u64 frequency;
    /* Post-init this hook may only be invoked via the read_counter() wrapper! */
    u64 (*read_counter)(void);
    s64 (*init)(struct platform_timesource *);
    void (*resume)(struct platform_timesource *);
    int counter_bits;
};

static DEFINE_PER_CPU(struct cpu_time, cpu_time);

/* Calibrate all CPUs to platform timer every EPOCH. */
#define EPOCH MILLISECS(1000)
static struct timer calibration_timer;

/*
 * We simulate a 32-bit platform timer from the 16-bit PIT ch2 counter.
 * Otherwise overflow happens too quickly (~50ms) for us to guarantee that
 * softirq handling will happen in time.
 * 
 * The pit_lock protects the 16- and 32-bit stamp fields as well as the 
 */
static DEFINE_SPINLOCK(pit_lock);
static u16 pit_stamp16;
static u32 pit_stamp32;
static bool __read_mostly using_pit;

/* Boot timestamp, filled in head.S */
u64 __initdata boot_tsc_stamp;

/* Per-socket TSC_ADJUST values, for secondary cores/threads to sync to. */
static uint64_t *__read_mostly tsc_adjust;

/*
 * 32-bit division of integer dividend and integer divisor yielding
 * 32-bit fractional quotient.
 */
static inline u32 div_frac(u32 dividend, u32 divisor)
{
    u32 quotient, remainder;
    ASSERT(dividend < divisor);
    asm ( 
        "divl %4"
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
    asm (
        "mul %3"
        : "=a" (product_frac), "=d" (product_int)
        : "0" (multiplicand), "r" (multiplier) );
    return product_int;
}

/*
 * Scale a 64-bit delta by scaling and multiplying by a 32-bit fraction,
 * yielding a 64-bit result.
 */
u64 scale_delta(u64 delta, const struct time_scale *scale)
{
    u64 product;

    if ( scale->shift < 0 )
        delta >>= -scale->shift;
    else
        delta <<= scale->shift;

    asm (
        "mulq %2 ; shrd $32,%1,%0"
        : "=a" (product), "=d" (delta)
        : "rm" (delta), "0" ((u64)scale->mul_frac) );

    return product;
}

#define _TS_MUL_FRAC_IDENTITY 0x80000000UL

/* Compute the reciprocal of the given time_scale. */
static inline struct time_scale scale_reciprocal(struct time_scale scale)
{
    struct time_scale reciprocal;
    u32 dividend;

    ASSERT(scale.mul_frac != 0);
    dividend = _TS_MUL_FRAC_IDENTITY;
    reciprocal.shift = 1 - scale.shift;
    while ( unlikely(dividend >= scale.mul_frac) )
    {
        dividend >>= 1;
        reciprocal.shift++;
    }

    asm (
        "divl %4"
        : "=a" (reciprocal.mul_frac), "=d" (dividend)
        : "0" (0), "1" (dividend), "r" (scale.mul_frac) );

    return reciprocal;
}

/*
 * cpu_mask that denotes the CPUs that needs timer interrupt coming in as
 * IPIs in place of local APIC timers
 */
static cpumask_t pit_broadcast_mask;

static void smp_send_timer_broadcast_ipi(void)
{
    int cpu = smp_processor_id();
    cpumask_t mask;

    cpumask_and(&mask, &cpu_online_map, &pit_broadcast_mask);

    if ( cpumask_test_cpu(cpu, &mask) )
    {
        __cpumask_clear_cpu(cpu, &mask);
        raise_softirq(TIMER_SOFTIRQ);
    }

    if ( !cpumask_empty(&mask) )
    {
        cpumask_raise_softirq(&mask, TIMER_SOFTIRQ);
    }
}

static void cf_check timer_interrupt(int irq, void *dev_id)
{
    ASSERT(local_irq_is_enabled());

    if ( hpet_legacy_irq_tick() )
        return;

    /* Only for start-of-day interruopt tests in io_apic.c. */
    pit0_ticks++;

    /* Rough hack to allow accurate timers to sort-of-work with no APIC. */
    if ( !cpu_has_apic )
        raise_softirq(TIMER_SOFTIRQ);

    if ( xen_cpuidle )
        smp_send_timer_broadcast_ipi();

    /* Emulate a 32-bit PIT counter. */
    if ( using_pit )
    {
        u16 count;

        spin_lock_irq(&pit_lock);

        outb(PIT_LTCH_CH(2), PIT_MODE);
        count  = inb(PIT_CH2);
        count |= inb(PIT_CH2) << 8;

        pit_stamp32 += (u16)(pit_stamp16 - count);
        pit_stamp16 = count;

        spin_unlock_irq(&pit_lock);
    }
}

static struct irqaction __read_mostly irq0 = {
    timer_interrupt, "timer", NULL
};

#define CLOCK_TICK_RATE 1193182 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20      /* calibrate over 50ms */
#define CALIBRATE_VALUE(freq) (((freq) + CALIBRATE_FRAC / 2) / CALIBRATE_FRAC)

static void preinit_pit(void)
{
    /* Set PIT channel 0 to HZ Hz. */
#define LATCH (((CLOCK_TICK_RATE)+(HZ/2))/HZ)
    outb_p(PIT_TCW_CH(0) | PIT_RW_LSB_MSB | PIT_MODE_RATE_GEN | PIT_BINARY,
           PIT_MODE);
    outb_p(LATCH & 0xff, PIT_CH0); /* LSB */
    outb(LATCH >> 8, PIT_CH0);     /* MSB */
#undef LATCH
}

void set_time_scale(struct time_scale *ts, u64 ticks_per_sec)
{
    u64 tps64 = ticks_per_sec;
    u32 tps32;
    int shift = 0;

    ASSERT(tps64 != 0);

    while ( tps64 > (MILLISECS(1000)*2) )
    {
        tps64 >>= 1;
        shift--;
    }

    tps32 = (u32)tps64;
    while ( tps32 <= (u32)MILLISECS(1000) )
    {
        tps32 <<= 1;
        shift++;
    }

    ts->mul_frac = div_frac(MILLISECS(1000), tps32);
    ts->shift    = shift;
}

static char *freq_string(u64 freq)
{
    static char s[20];
    unsigned int x, y;

    if ( do_div(freq, 1000) > 500 )
        ++freq;
    y = (unsigned int)do_div(freq, 1000);
    x = (unsigned int)freq;
    snprintf(s, sizeof(s), "%u.%03uMHz", x, y);
    return s;
}

static uint32_t __init read_pt_and_tsc(uint64_t *tsc,
                                       const struct platform_timesource *pts)
{
    uint64_t tsc_prev = *tsc = rdtsc_ordered(), tsc_min = ~0;
    uint32_t best = ~0;
    unsigned int i;

    for ( i = 0; ; ++i )
    {
        uint32_t pt = pts->read_counter();
        uint64_t tsc_cur = rdtsc_ordered();
        uint64_t tsc_delta = tsc_cur - tsc_prev;

        if ( tsc_delta < tsc_min )
        {
            tsc_min = tsc_delta;
            *tsc = tsc_cur;
            best = pt;
        }
        else if ( i > 2 )
            break;

        tsc_prev = tsc_cur;
    }

    return best;
}

static uint64_t __init calibrate_tsc(const struct platform_timesource *pts)
{
    uint64_t start, end, elapsed;
    unsigned int count = read_pt_and_tsc(&start, pts);
    unsigned int target = CALIBRATE_VALUE(pts->frequency), actual;
    unsigned int mask = (uint32_t)~0 >> (32 - pts->counter_bits);

    while ( ((pts->read_counter() - count) & mask) < target )
        continue;

    actual = (read_pt_and_tsc(&end, pts) - count) & mask;
    elapsed = end - start;

    if ( likely(actual > target) )
    {
        /*
         * A (perhaps significant) delay before the last timer read (e.g. due
         * to a SMI or NMI) can lead to (perhaps severe) inaccuracy if not
         * accounting for the time elapsed beyond the originally calculated
         * duration of the calibration interval.
         */
        elapsed = muldiv64(elapsed, target, actual);
    }

    return elapsed * CALIBRATE_FRAC;
}

/************************************************************
 * PLATFORM TIMER 1: PROGRAMMABLE INTERVAL TIMER (LEGACY PIT)
 */

static u64 cf_check read_pit_count(void)
{
    u16 count16;
    u32 count32;
    unsigned long flags;

    spin_lock_irqsave(&pit_lock, flags);

    outb(PIT_LTCH_CH(2), PIT_MODE);
    count16  = inb(PIT_CH2);
    count16 |= inb(PIT_CH2) << 8;

    count32 = pit_stamp32 + (u16)(pit_stamp16 - count16);

    spin_unlock_irqrestore(&pit_lock, flags);

    return count32;
}

static s64 __init cf_check init_pit(struct platform_timesource *pts)
{
    u8 portb = inb(0x61);
    u64 start, end;
    unsigned long count;

    /* Set the Gate high, disable speaker. */
    outb((portb & ~0x02) | 0x01, 0x61);

    /*
     * Now let's take care of CTC channel 2: mode 0, (interrupt on
     * terminal count mode), binary count, load CALIBRATE_LATCH count,
     * (LSB and MSB) to begin countdown.
     */
#define CALIBRATE_LATCH CALIBRATE_VALUE(CLOCK_TICK_RATE)
    BUILD_BUG_ON(CALIBRATE_LATCH >> 16);
    outb(PIT_TCW_CH(2) | PIT_RW_LSB_MSB | PIT_MODE_EOC | PIT_BINARY,
         PIT_MODE);
    outb(CALIBRATE_LATCH & 0xff, PIT_CH2); /* LSB of count */
    outb(CALIBRATE_LATCH >> 8, PIT_CH2);   /* MSB of count */
#undef CALIBRATE_LATCH

    start = rdtsc_ordered();
    for ( count = 0; !(inb(0x61) & 0x20); ++count )
        continue;
    end = rdtsc_ordered();

    /* Set the Gate low, disable speaker. */
    outb(portb & ~0x03, 0x61);

    /* Error if the CTC doesn't behave itself. */
    if ( count == 0 )
        return 0;

    using_pit = true;

    return (end - start) * CALIBRATE_FRAC;
}

static void cf_check resume_pit(struct platform_timesource *pts)
{
    /* Set CTC channel 2 to mode 0 again; initial value does not matter. */
    outb(PIT_TCW_CH(2) | PIT_RW_LSB_MSB | PIT_MODE_EOC | PIT_BINARY,
         PIT_MODE);
    outb(0, PIT_CH2);     /* LSB of count */
    outb(0, PIT_CH2);     /* MSB of count */
}

static struct platform_timesource __initdata_cf_clobber plt_pit =
{
    .id = "pit",
    .name = "PIT",
    .frequency = CLOCK_TICK_RATE,
    .read_counter = read_pit_count,
    .counter_bits = 32,
    .init = init_pit,
    .resume = resume_pit,
};

unsigned int __initdata pit_alias_mask;

static void __init probe_pit_alias(void)
{
    unsigned int mask = 0x1c;
    uint8_t val = 0;

    if ( !opt_probe_port_aliases )
        return;

    /*
     * Use channel 2 in mode 0 for probing.  In this mode even a non-initial
     * count is loaded independent of counting being / becoming enabled.  Thus
     * we have a 16-bit value fully under our control, to write and then check
     * whether we can also read it back unaltered.
     */

    /* Turn off speaker output and disable channel 2 counting. */
    outb(inb(0x61) & 0x0c, 0x61);

    outb(PIT_TCW_CH(2) | PIT_RW_LSB_MSB | PIT_MODE_EOC | PIT_BINARY,
         PIT_MODE);

    do {
        uint8_t val2;
        unsigned int offs;

        outb(val, PIT_CH2);
        outb(val ^ 0xff, PIT_CH2);

        /* Wait for the Null Count bit to clear. */
        do {
            /* Latch status. */
            outb(PIT_RDB | PIT_RDB_NO_COUNT | PIT_RDB_CH2, PIT_MODE);

            /* Try to make sure we're actually having a PIT here. */
            val2 = inb(PIT_CH2);
            if ( (val2 & ~(PIT_STATUS_OUT_PIN | PIT_STATUS_NULL_COUNT)) !=
                 (PIT_RW_LSB_MSB | PIT_MODE_EOC | PIT_BINARY) )
                return;
        } while ( val2 & PIT_STATUS_NULL_COUNT );

        /*
         * Try to further make sure we're actually having a PIT here.
         *
         * NB: Deliberately |, not ||, as we always want both reads.
         */
        val2 = inb(PIT_CH2);
        if ( (val2 ^ val) | (inb(PIT_CH2) ^ val ^ 0xff) )
            return;

        for ( offs = ISOLATE_LSB(mask); offs <= mask; offs <<= 1 )
        {
            if ( !(mask & offs) )
                continue;
            val2 = inb(PIT_CH2 + offs);
            if ( (val2 ^ val) | (inb(PIT_CH2 + offs) ^ val ^ 0xff) )
                mask &= ~offs;
        }
    } while ( mask && (val += 0x0b) );  /* Arbitrary uneven number. */

    if ( mask )
    {
        dprintk(XENLOG_INFO, "PIT aliasing mask: %02x\n", mask);
        pit_alias_mask = mask;
    }
}

/************************************************************
 * PLATFORM TIMER 2: HIGH PRECISION EVENT TIMER (HPET)
 */

static u64 cf_check read_hpet_count(void)
{
    return hpet_read32(HPET_COUNTER);
}

static int64_t __init cf_check init_hpet(struct platform_timesource *pts)
{
    uint64_t hpet_rate;
    /*
     * Allow HPET to be setup, but report a frequency of 0 so it's not selected
     * as a timer source. This is required so it can be used in legacy
     * replacement mode in check_timer.
     */
    bool disable_hpet = false;

    if ( hpet_address && strcmp(opt_clocksource, pts->id) &&
         cpuidle_using_deep_cstate() )
    {
        if ( pci_conf_read16(PCI_SBDF(0, 0, 0x1f, 0),
                             PCI_VENDOR_ID) == PCI_VENDOR_ID_INTEL )
            switch ( pci_conf_read16(PCI_SBDF(0, 0, 0x1f, 0), PCI_DEVICE_ID) )
            {
            /* HPET on Bay Trail platforms will halt in deep C states. */
            case 0x0f1c:
            /* HPET on Cherry Trail platforms will halt in deep C states. */
            case 0x229c:
                disable_hpet = true;
                break;
            }

        /*
         * Some Coffee Lake and later platforms have a skewed HPET timer once
         * they entered PC10.
         *
         * Check whether the system supports PC10. If so force disable HPET as
         * that stops counting in PC10. This check is overbroad as it does not
         * take any of the following into account:
         *
         *	- ACPI tables
         *	- Enablement of mwait-idle
         *	- Command line arguments which limit mwait-idle C-state support
         *
         * That's perfectly fine. HPET is a piece of hardware designed by
         * committee and the only reasons why it is still in use on modern
         * systems is the fact that it is impossible to reliably query TSC and
         * CPU frequency via CPUID or firmware.
         *
         * If HPET is functional it is useful for calibrating TSC, but this can
         * be done via PMTIMER as well which seems to be the last remaining
         * timer on X86/INTEL platforms that has not been completely wreckaged
         * by feature creep.
         *
         * In theory HPET support should be removed altogether, but there are
         * older systems out there which depend on it because TSC and APIC timer
         * are dysfunctional in deeper C-states.
         */
        if ( mwait_pc10_supported() )
        {
            uint64_t pcfg;

            rdmsrl(MSR_PKG_CST_CONFIG_CONTROL, pcfg);
            if ( (pcfg & 0xf) < 8 )
                /* nothing */;
            else if ( !strcmp(opt_clocksource, pts->id) )
                printk("HPET use requested via command line, but dysfunctional in PC10\n");
            else
                disable_hpet = true;
        }

        if ( disable_hpet )
            printk("Disabling HPET for being unreliable\n");
    }

    if ( (hpet_rate = hpet_setup()) == 0 || disable_hpet )
        return 0;

    pts->frequency = hpet_rate;

    return calibrate_tsc(pts);
}

static void cf_check resume_hpet(struct platform_timesource *pts)
{
    hpet_resume(NULL);
}

static struct platform_timesource __initdata_cf_clobber plt_hpet =
{
    .id = "hpet",
    .name = "HPET",
    .read_counter = read_hpet_count,
    .counter_bits = 32,
    .init = init_hpet,
    .resume = resume_hpet
};

/************************************************************
 * PLATFORM TIMER 3: ACPI PM TIMER
 */

u32 __read_mostly pmtmr_ioport;
unsigned int __initdata pmtmr_width;

/* ACPI PM timer ticks at 3.579545 MHz. */
#define ACPI_PM_FREQUENCY 3579545

static u64 cf_check read_pmtimer_count(void)
{
    return inl(pmtmr_ioport);
}

static s64 __init cf_check init_pmtimer(struct platform_timesource *pts)
{
    if ( !pmtmr_ioport || (pmtmr_width != 24 && pmtmr_width != 32) )
        return 0;

    pts->counter_bits = pmtmr_width;

    return calibrate_tsc(pts);
}

static struct platform_timesource __initdata_cf_clobber plt_pmtimer =
{
    .id = "acpi",
    .name = "ACPI PM Timer",
    .frequency = ACPI_PM_FREQUENCY,
    .read_counter = read_pmtimer_count,
    .init = init_pmtimer
};

static struct time_scale __read_mostly pmt_scale;

static __init int cf_check init_pmtmr_scale(void)
{
    set_time_scale(&pmt_scale, ACPI_PM_FREQUENCY);
    return 0;
}
__initcall(init_pmtmr_scale);

uint64_t cf_check acpi_pm_tick_to_ns(uint64_t ticks)
{
    return scale_delta(ticks, &pmt_scale);
}

/************************************************************
 * PLATFORM TIMER 4: TSC
 */
static unsigned int __initdata tsc_flags;

/* TSC is reliable across sockets */
#define TSC_RELIABLE_SOCKET (1 << 0)

/*
 * Called in verify_tsc_reliability() under reliable TSC conditions
 * thus reusing all the checks already performed there.
 */
static s64 __init cf_check init_tsc(struct platform_timesource *pts)
{
    u64 ret = pts->frequency;

    if ( nr_cpu_ids != num_present_cpus() )
    {
        printk(XENLOG_WARNING "TSC: CPU Hotplug intended\n");
        ret = 0;
    }

    if ( nr_sockets > 1 && !(tsc_flags & TSC_RELIABLE_SOCKET) )
    {
        printk(XENLOG_WARNING "TSC: Not invariant across sockets\n");
        ret = 0;
    }

    if ( !ret )
        printk(XENLOG_DEBUG "TSC: Not setting it as clocksource\n");

    return ret;
}

/*
 * plt_tsc's read_counter hook is not (and should not be) invoked via the
 * struct field. To avoid carrying an unused, indirectly reachable function,
 * poison the field with an easily identifiable non-canonical pointer.
 */
#define READ_TSC_POISON ((uint64_t(*)(void))0x75C75C75C75C75C0ul)

static struct platform_timesource __initdata_cf_clobber plt_tsc =
{
    .id = "tsc",
    .name = "TSC",
    .read_counter = READ_TSC_POISON,
    /*
     * Calculations for platform timer overflow assume u64 boundary.
     * Hence we set to less than 64, such that the TSC wraparound is
     * correctly checked and handled.
     */
    .counter_bits = 63,
    .init = init_tsc,
};

#ifdef CONFIG_XEN_GUEST
/************************************************************
 * PLATFORM TIMER 5: XEN PV CLOCK SOURCE
 *
 * Xen clock source is a variant of TSC source.
 */
static uint64_t xen_timer_last;

static uint64_t xen_timer_cpu_frequency(void)
{
    struct vcpu_time_info *info = &this_cpu(vcpu_info)->time;
    uint64_t freq;

    freq = (1000000000ULL << 32) / info->tsc_to_system_mul;
    if ( info->tsc_shift < 0 )
        freq <<= -info->tsc_shift;
    else
        freq >>= info->tsc_shift;

    return freq;
}

static int64_t __init cf_check init_xen_timer(struct platform_timesource *pts)
{
    if ( !xen_guest )
        return 0;

    return xen_timer_cpu_frequency();
}

static always_inline uint64_t read_cycle(const struct vcpu_time_info *info,
                                         uint64_t tsc)
{
    uint64_t delta = tsc - info->tsc_timestamp;
    struct time_scale ts = {
        .shift    = info->tsc_shift,
        .mul_frac = info->tsc_to_system_mul,
    };
    uint64_t offset = scale_delta(delta, &ts);

    return info->system_time + offset;
}

static uint64_t cf_check read_xen_timer(void)
{
    struct vcpu_time_info *info = &this_cpu(vcpu_info)->time;
    uint32_t version;
    uint64_t ret;
    uint64_t last;

    do {
        version = info->version & ~1;
        /* Make sure version is read before the data */
        smp_rmb();

        ret = read_cycle(info, rdtsc_ordered());
        /* Ignore fancy flags for now */

        /* Make sure version is reread after the data */
        smp_rmb();
    } while ( unlikely(version != info->version) );

    /* Maintain a monotonic global value */
    do {
        last = read_atomic(&xen_timer_last);
        if ( ret < last )
            return last;
    } while ( unlikely(cmpxchg(&xen_timer_last, last, ret) != last) );

    return ret;
}

static void cf_check resume_xen_timer(struct platform_timesource *pts)
{
    write_atomic(&xen_timer_last, 0);
}

static struct platform_timesource __initdata_cf_clobber plt_xen_timer =
{
    .id = "xen",
    .name = "XEN PV CLOCK",
    .frequency = 1000000000ULL,
    .read_counter = read_xen_timer,
    .init = init_xen_timer,
    .resume = resume_xen_timer,
    .counter_bits = 63,
};
#endif

static unsigned long read_xen_wallclock(void)
{
#ifdef CONFIG_XEN_GUEST
    const struct shared_info *sh_info = XEN_shared_info;
    uint32_t wc_version;
    uint64_t wc_sec;

    ASSERT(xen_guest);

    do {
        wc_version = sh_info->wc_version & ~1;
        smp_rmb();

        wc_sec  = sh_info->wc_sec;
        smp_rmb();
    } while ( wc_version != sh_info->wc_version );

    return wc_sec + read_xen_timer() / 1000000000;
#else
    ASSERT_UNREACHABLE();
    return 0;
#endif
}

#ifdef CONFIG_HYPERV_GUEST
/************************************************************
 * HYPER-V REFERENCE TSC
 */
#include <asm/guest/hyperv-tlfs.h>

static struct ms_hyperv_tsc_page *hyperv_tsc;
static struct page_info *hyperv_tsc_page;

static int64_t __init cf_check init_hyperv_timer(
    struct platform_timesource *pts)
{
    paddr_t maddr;
    uint64_t tsc_msr, freq;

    if ( !(ms_hyperv.features & HV_MSR_REFERENCE_TSC_AVAILABLE) ||
         !(ms_hyperv.features & HV_X64_ACCESS_FREQUENCY_MSRS) )
        return 0;

    hyperv_tsc_page = alloc_domheap_page(NULL, 0);
    if ( !hyperv_tsc_page )
        return 0;

    hyperv_tsc = __map_domain_page_global(hyperv_tsc_page);
    if ( !hyperv_tsc )
    {
        free_domheap_page(hyperv_tsc_page);
        hyperv_tsc_page = NULL;
        return 0;
    }

    maddr = page_to_maddr(hyperv_tsc_page);

    /*
     * Per Hyper-V TLFS:
     *   1. Read existing MSR value
     *   2. Preserve bits [11:1]
     *   3. Set bits [63:12] to be guest physical address of tsc page
     *   4. Set enabled bit (0)
     *   5. Write back new MSR value
     */
    rdmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr);
    tsc_msr &= 0xffe;
    tsc_msr |= maddr | 1 /* enabled */;
    wrmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr);

    /* Get TSC frequency from Hyper-V */
    rdmsrl(HV_X64_MSR_TSC_FREQUENCY, freq);
    pts->frequency = freq;

    return freq;
}

static uint64_t cf_check read_hyperv_timer(void)
{
    uint64_t scale, ret, tsc;
    int64_t offset;
    uint32_t seq;
    const struct ms_hyperv_tsc_page *tsc_page = hyperv_tsc;

    do {
        seq = tsc_page->tsc_sequence;

        /* Seq 0 is special. It means the TSC enlightenment is not
         * available at the moment. The reference time can only be
         * obtained from the Reference Counter MSR.
         */
        if ( seq == 0 )
        {
            rdmsrl(HV_X64_MSR_TIME_REF_COUNT, ret);
            return ret;
        }

        /* rdtsc_ordered already contains a load fence */
        tsc = rdtsc_ordered();
        scale = tsc_page->tsc_scale;
        offset = tsc_page->tsc_offset;

        smp_rmb();

    } while ( tsc_page->tsc_sequence != seq );

    return hv_scale_tsc(tsc, scale, offset);
}

static struct platform_timesource __initdata_cf_clobber plt_hyperv_timer =
{
    .id = "hyperv",
    .name = "HYPER-V REFERENCE TSC",
    .read_counter = read_hyperv_timer,
    .init = init_hyperv_timer,
    /* See TSC time source for why counter_bits is set to 63 */
    .counter_bits = 63,
};
#endif

/************************************************************
 * GENERIC PLATFORM TIMER INFRASTRUCTURE
 */

/* details of chosen timesource */
static struct platform_timesource __read_mostly plt_src;
/* hardware-width mask */
static u64 __read_mostly plt_mask;
 /* ns between calls to plt_overflow() */
static u64 __read_mostly plt_overflow_period;
/* scale: platform counter -> nanosecs */
static struct time_scale __read_mostly plt_scale;

/* Protected by platform_timer_lock. */
static DEFINE_SPINLOCK(platform_timer_lock);
static s_time_t stime_platform_stamp; /* System time at below platform time */
static u64 platform_timer_stamp;      /* Platform time at above system time */
static u64 plt_stamp64;          /* 64-bit platform counter stamp           */
static u64 plt_stamp;            /* hardware-width platform counter stamp   */
static struct timer plt_overflow_timer;

static s_time_t __read_platform_stime(u64 platform_time)
{
    u64 diff = platform_time - platform_timer_stamp;
    ASSERT(spin_is_locked(&platform_timer_lock));
    return (stime_platform_stamp + scale_delta(diff, &plt_scale));
}

static uint64_t read_counter(void)
{
    /*
     * plt_tsc is put in use only after alternatives patching has occurred,
     * hence we can't invoke read_tsc() that way. Special case it here, open-
     * coding the function call at the same time.
     */
    return plt_src.read_counter != READ_TSC_POISON
           ? alternative_call(plt_src.read_counter)
           : rdtsc_ordered();
}

static void cf_check plt_overflow(void *unused)
{
    int i;
    u64 count;
    s_time_t now, plt_now, plt_wrap;

    spin_lock_irq(&platform_timer_lock);

    count = read_counter();
    plt_stamp64 += (count - plt_stamp) & plt_mask;
    plt_stamp = count;

    now = NOW();
    plt_wrap = __read_platform_stime(plt_stamp64);
    for ( i = 0; i < 10; i++ )
    {
        plt_now = plt_wrap;
        plt_wrap = __read_platform_stime(plt_stamp64 + plt_mask + 1);
        if ( ABS(plt_wrap - now) > ABS(plt_now - now) )
            break;
        plt_stamp64 += plt_mask + 1;
    }
    if ( i != 0 )
        printk_once("Platform timer appears to have unexpectedly wrapped "
                    "%u%s times.\n", i, (i == 10) ? " or more" : "");

    spin_unlock_irq(&platform_timer_lock);

    set_timer(&plt_overflow_timer, NOW() + plt_overflow_period);
}

static s_time_t read_platform_stime(u64 *stamp)
{
    u64 plt_counter, count;
    s_time_t stime;

    ASSERT(!local_irq_is_enabled());

    spin_lock(&platform_timer_lock);
    plt_counter = read_counter();
    count = plt_stamp64 + ((plt_counter - plt_stamp) & plt_mask);
    stime = __read_platform_stime(count);
    spin_unlock(&platform_timer_lock);

    if ( unlikely(stamp) )
        *stamp = plt_counter;

    return stime;
}

static void platform_time_calibration(void)
{
    u64 count;
    s_time_t stamp;
    unsigned long flags;

    spin_lock_irqsave(&platform_timer_lock, flags);
    count = plt_stamp64 + ((read_counter() - plt_stamp) & plt_mask);
    stamp = __read_platform_stime(count);
    stime_platform_stamp = stamp;
    platform_timer_stamp = count;
    spin_unlock_irqrestore(&platform_timer_lock, flags);
}

static void resume_platform_timer(void)
{
    /* Timer source can be reset when backing from S3 to S0 */
    if ( plt_src.resume )
        alternative_vcall(plt_src.resume, &plt_src);

    plt_stamp64 = platform_timer_stamp;
    plt_stamp = read_counter();
}

static void __init reset_platform_timer(void)
{
    kill_timer(&plt_overflow_timer);

    /* Reset counters and stamps */
    spin_lock_irq(&platform_timer_lock);
    plt_stamp = 0;
    plt_stamp64 = 0;
    platform_timer_stamp = 0;
    stime_platform_stamp = 0;
    spin_unlock_irq(&platform_timer_lock);
}

static s64 __init try_platform_timer(struct platform_timesource *pts)
{
    s64 rc = pts->init(pts);

    if ( rc <= 0 )
        return rc;

    /* We have a platform timesource already so reset it */
    if ( plt_src.counter_bits != 0 )
        reset_platform_timer();

    plt_mask = (u64)~0ull >> (64 - pts->counter_bits);

    set_time_scale(&plt_scale, pts->frequency);

    plt_overflow_period = scale_delta(
        1ull << (pts->counter_bits - 1), &plt_scale);
    plt_src = *pts;

    return rc;
}

static u64 __init init_platform_timer(void)
{
    static struct platform_timesource * __initdata plt_timers[] = {
#ifdef CONFIG_XEN_GUEST
        &plt_xen_timer,
#endif
#ifdef CONFIG_HYPERV_GUEST
        &plt_hyperv_timer,
#endif
        &plt_hpet, &plt_pmtimer, &plt_pit
    };

    struct platform_timesource *pts = NULL;
    unsigned int i;
    s64 rc = -1;

    /* clocksource=tsc is initialized via __initcalls (when CPUs are up). */
    if ( (opt_clocksource[0] != '\0') && strcmp(opt_clocksource, "tsc") )
    {
        for ( i = 0; i < ARRAY_SIZE(plt_timers); i++ )
        {
            pts = plt_timers[i];
            if ( !strcmp(opt_clocksource, pts->id) )
            {
                rc = try_platform_timer(pts);
                break;
            }
        }

        if ( rc <= 0 )
            printk("WARNING: %s clocksource '%s'.\n",
                   (rc == 0) ? "Could not initialise" : "Unrecognised",
                   opt_clocksource);
    }

    if ( rc <= 0 )
    {
        for ( i = 0; i < ARRAY_SIZE(plt_timers); i++ )
        {
            pts = plt_timers[i];
            if ( (rc = try_platform_timer(pts)) > 0 )
                break;
        }
    }

    if ( rc <= 0 )
        panic("Unable to find usable platform timer\n");

    printk("Platform timer is %s %s\n",
           freq_string(pts->frequency), pts->name);

    return rc;
}

static uint64_t __init read_pt_and_tmcct(uint32_t *tmcct)
{
    uint32_t tmcct_prev = *tmcct = apic_tmcct_read(), tmcct_min = ~0;
    uint64_t best = ~0;
    unsigned int i;

    for ( i = 0; ; ++i )
    {
        uint64_t pt = plt_src.read_counter();
        uint32_t tmcct_cur = apic_tmcct_read();
        uint32_t tmcct_delta = tmcct_prev - tmcct_cur;

        if ( tmcct_delta < tmcct_min )
        {
            tmcct_min = tmcct_delta;
            *tmcct = tmcct_cur;
            best = pt;
        }
        else if ( i > 2 )
            break;

        tmcct_prev = tmcct_cur;
    }

    return best;
}

uint64_t __init calibrate_apic_timer(void)
{
    uint32_t start, end;
    uint64_t count = read_pt_and_tmcct(&start), elapsed;
    uint64_t target = CALIBRATE_VALUE(plt_src.frequency), actual;
    uint64_t mask = (uint64_t)~0 >> (64 - plt_src.counter_bits);

    /*
     * PIT cannot be used here as it requires the timer interrupt to maintain
     * its 32-bit software counter, yet here we run with IRQs disabled.
     */
    if ( using_pit )
        return 0;

    while ( ((plt_src.read_counter() - count) & mask) < target )
        continue;

    actual = (read_pt_and_tmcct(&end) - count) & mask;
    elapsed = start - end;

    if ( likely(actual > target) )
    {
        /*
         * See the comment in calibrate_tsc(). But first scale down values
         * to actually fit muldiv64()'s input range.
         */
        while ( unlikely(actual > (uint32_t)actual) )
        {
            actual >>= 1;
            target >>= 1;
        }
        elapsed = muldiv64(elapsed, target, actual);
    }

    return elapsed * CALIBRATE_FRAC;
}

u64 stime2tsc(s_time_t stime)
{
    struct cpu_time *t;
    struct time_scale sys_to_tsc;
    s_time_t stime_delta;

    t = &this_cpu(cpu_time);
    sys_to_tsc = scale_reciprocal(t->tsc_scale);

    stime_delta = stime - t->stamp.local_stime;
    if ( stime_delta < 0 )
        stime_delta = 0;

    return t->stamp.local_tsc + scale_delta(stime_delta, &sys_to_tsc);
}

void cstate_restore_tsc(void)
{
    struct cpu_time *t = &this_cpu(cpu_time);

    if ( boot_cpu_has(X86_FEATURE_NONSTOP_TSC) )
        return;

    t->stamp.master_stime = read_platform_stime(NULL);
    t->stamp.local_tsc = stime2tsc(t->stamp.master_stime);
    t->stamp.local_stime = t->stamp.master_stime;

    write_tsc(t->stamp.local_tsc);
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
unsigned long
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

struct rtc_time {
    unsigned int year, mon, day, hour, min, sec;
};

static bool __get_cmos_time(struct rtc_time *rtc)
{
    s_time_t start, t1, t2;
    unsigned long flags;

    spin_lock_irqsave(&rtc_lock, flags);

    /* read RTC exactly on falling edge of update flag */
    start = NOW();
    do { /* may take up to 1 second... */
        t1 = NOW() - start;
    } while ( !(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) &&
              t1 <= SECONDS(1) );

    start = NOW();
    do { /* must try at least 2.228 ms */
        t2 = NOW() - start;
    } while ( (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) &&
              t2 < MILLISECS(3) );

    rtc->sec  = CMOS_READ(RTC_SECONDS);
    rtc->min  = CMOS_READ(RTC_MINUTES);
    rtc->hour = CMOS_READ(RTC_HOURS);
    rtc->day  = CMOS_READ(RTC_DAY_OF_MONTH);
    rtc->mon  = CMOS_READ(RTC_MONTH);
    rtc->year = CMOS_READ(RTC_YEAR);
    
    if ( RTC_ALWAYS_BCD || !(CMOS_READ(RTC_CONTROL) & RTC_DM_BINARY) )
    {
        BCD_TO_BIN(rtc->sec);
        BCD_TO_BIN(rtc->min);
        BCD_TO_BIN(rtc->hour);
        BCD_TO_BIN(rtc->day);
        BCD_TO_BIN(rtc->mon);
        BCD_TO_BIN(rtc->year);
    }

    spin_unlock_irqrestore(&rtc_lock, flags);

    if ( (rtc->year += 1900) < 1970 )
        rtc->year += 100;

    return t1 <= SECONDS(1) && t2 < MILLISECS(3);
}

static bool __read_mostly opt_cmos_rtc_probe;
boolean_param("cmos-rtc-probe", opt_cmos_rtc_probe);

static bool cmos_rtc_probe(struct rtc_time *rtc_p)
{
    unsigned int seconds = 60;

    for ( ; ; )
    {
        bool success = __get_cmos_time(rtc_p);
        struct rtc_time rtc = *rtc_p;

        if ( likely(!opt_cmos_rtc_probe) )
            return true;

        if ( !success ||
             rtc.sec >= 60 || rtc.min >= 60 || rtc.hour >= 24 ||
             !rtc.day || rtc.day > 31 ||
             !rtc.mon || rtc.mon > 12 )
            return false;

        if ( seconds < 60 )
        {
            if ( rtc.sec != seconds )
            {
                acpi_gbl_FADT.boot_flags &= ~ACPI_FADT_NO_CMOS_RTC;
                return true;
            }
            return false;
        }

        process_pending_softirqs();

        seconds = rtc.sec;
    }

    ASSERT_UNREACHABLE();
    return false;
}

static unsigned long get_cmos_time(void)
{
    unsigned long res;
    struct rtc_time rtc;

    if ( efi_enabled(EFI_RS) )
    {
        res = efi_get_time();
        if ( res )
            return res;
    }

    if ( likely(!(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_CMOS_RTC)) )
        opt_cmos_rtc_probe = false;
    else if ( system_state < SYS_STATE_smp_boot && !opt_cmos_rtc_probe )
        panic("System with no CMOS RTC advertised must be booted from EFI"
              " (or with command line option \"cmos-rtc-probe\")\n");

    if ( !cmos_rtc_probe(&rtc) )
        panic("No CMOS RTC found - system must be booted from EFI\n");

    return mktime(rtc.year, rtc.mon, rtc.day, rtc.hour, rtc.min, rtc.sec);
}

static unsigned int __ro_after_init cmos_alias_mask;

static int __init cf_check probe_cmos_alias(void)
{
    unsigned int offs;

    if ( (acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_CMOS_RTC) ||
         !opt_probe_port_aliases )
        return 0;

    for ( offs = 2; offs < 8; offs <<= 1 )
    {
        unsigned int i;
        bool read = true;

        for ( i = RTC_REG_D + 1; i < 0x80; ++i )
        {
            uint8_t normal, alt;
            unsigned long flags;

            if ( i == acpi_gbl_FADT.century )
                continue;

            spin_lock_irqsave(&rtc_lock, flags);

            normal = CMOS_READ(i);
            if ( inb(RTC_PORT(offs)) != i )
                read = false;

            alt = inb(RTC_PORT(offs + 1));

            spin_unlock_irqrestore(&rtc_lock, flags);

            if ( normal != alt )
                break;

            process_pending_softirqs();
        }
        if ( i == 0x80 )
        {
            cmos_alias_mask |= offs;
            dprintk(XENLOG_INFO, "CMOS aliased at %02x, index %s\n",
                    RTC_PORT(offs), read ? "r/w" : "w/o");
        }
    }

    return 0;
}
__initcall(probe_cmos_alias);

bool is_cmos_port(unsigned int port, unsigned int bytes, const struct domain *d)
{
    unsigned int offs;

    if ( !is_hardware_domain(d) )
        return port <= RTC_PORT(1) && port + bytes > RTC_PORT(0);

    /*
     * While not really CMOS-related, port 0x70 always needs intercepting
     * to deal with the NMI disable bit.
     */
    if ( port <= RTC_PORT(0) && port + bytes > RTC_PORT(0) )
        return true;

    if ( acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_CMOS_RTC )
        return false;

    if ( port <= RTC_PORT(1) && port + bytes > RTC_PORT(0) )
        return true;

    for ( offs = 2; offs <= cmos_alias_mask; offs <<= 1 )
    {
        if ( !(offs & cmos_alias_mask) )
            continue;
        if ( port <= RTC_PORT(offs | 1) && port + bytes > RTC_PORT(offs) )
            return true;
    }

    return false;
}

/* Helpers for guest accesses to the physical RTC. */
unsigned int rtc_guest_read(unsigned int port)
{
    const struct domain *currd = current->domain;
    unsigned long flags;
    unsigned int data = ~0;

    switch ( port & ~cmos_alias_mask )
    {
    case RTC_PORT(0):
        /*
         * All PV domains (and PVH dom0) are allowed to read the latched value
         * of the first RTC port, as there's no access to the physical IO
         * ports.  Note that we return the index value regardless of whether
         * underlying hardware would permit doing so.
         */
        data = currd->arch.cmos_idx & (0xff >> (port == RTC_PORT(0)));

        /*
         * When there's (supposedly) no RTC/CMOS, we don't intercept the other
         * ports. While reading the index register isn't normally possible,
         * play safe and return back whatever can be read (just in case a value
         * written through an alias would be attempted to be read back here).
         */
        if ( port == RTC_PORT(0) &&
             (acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_CMOS_RTC) &&
             ioports_access_permitted(currd, port, port) )
            data = inb(port) & 0x7f;
        break;

    case RTC_PORT(1):
        if ( !ioports_access_permitted(currd, port - 1, port) )
            break;
        spin_lock_irqsave(&rtc_lock, flags);
        outb(currd->arch.cmos_idx & (0xff >> (port == RTC_PORT(1))),
             port - 1);
        data = inb(port);
        spin_unlock_irqrestore(&rtc_lock, flags);
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    return data;
}

void rtc_guest_write(unsigned int port, unsigned int data)
{
    struct domain *currd = current->domain;
    unsigned long flags;

    switch ( port & ~cmos_alias_mask )
    {
        typeof(pv_rtc_handler) hook;
        unsigned int idx;

    case RTC_PORT(0):
        /*
         * All PV domains (and PVH dom0) are allowed to write to the latched
         * value of the first RTC port, as there's no access to the physical IO
         * ports.
         */
        currd->arch.cmos_idx = data & (0xff >> (port == RTC_PORT(0)));

        /*
         * When there's (supposedly) no RTC/CMOS, we don't intercept the other
         * ports. Therefore the port write, with the NMI disable bit zapped,
         * needs carrying out right away.
         */
        if ( port == RTC_PORT(0) &&
             (acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_CMOS_RTC) &&
             ioports_access_permitted(currd, port, port) )
            outb(data & 0x7f, port);
        break;

    case RTC_PORT(1):
        if ( !ioports_access_permitted(currd, port - 1, port) )
            break;

        idx = currd->arch.cmos_idx & (0xff >> (port == RTC_PORT(1)));

        hook = ACCESS_ONCE(pv_rtc_handler);
        if ( hook )
            hook(idx, data);

        spin_lock_irqsave(&rtc_lock, flags);
        outb(idx, port - 1);
        outb(data, port);
        spin_unlock_irqrestore(&rtc_lock, flags);
        break;

    default:
        ASSERT_UNREACHABLE();
    }
}

static unsigned long get_wallclock_time(void)
{
    if ( xen_guest )
        return read_xen_wallclock();

    return get_cmos_time();
}

/***************************************************************************
 * System Time
 ***************************************************************************/

s_time_t get_s_time_fixed(u64 at_tsc)
{
    const struct cpu_time *t = &this_cpu(cpu_time);
    u64 tsc, delta;

    if ( at_tsc )
        tsc = at_tsc;
    else
        tsc = rdtsc_ordered();
    delta = tsc - t->stamp.local_tsc;
    return t->stamp.local_stime + scale_delta(delta, &t->tsc_scale);
}

s_time_t get_s_time(void)
{
    return get_s_time_fixed(0);
}

uint64_t tsc_ticks2ns(uint64_t ticks)
{
    struct cpu_time *t = &this_cpu(cpu_time);

    return scale_delta(ticks, &t->tsc_scale);
}

static void collect_time_info(const struct vcpu *v,
                              struct vcpu_time_info *u)
{
    const struct cpu_time *t = &this_cpu(cpu_time);
    const struct domain *d = v->domain;
    s_time_t tsc_stamp;

    memset(u, 0, sizeof(*u));

    if ( d->arch.vtsc )
    {
        s_time_t stime = t->stamp.local_stime;

        if ( is_hvm_domain(d) )
        {
            const struct pl_time *pl = d->arch.hvm.pl_time;

            stime += pl->stime_offset + v->arch.hvm.stime_offset;
            if ( stime >= 0 )
                tsc_stamp = gtime_to_gtsc(d, stime);
            else
                tsc_stamp = -gtime_to_gtsc(d, -stime);
        }
        else
            tsc_stamp = gtime_to_gtsc(d, stime);

        u->tsc_to_system_mul = d->arch.vtsc_to_ns.mul_frac;
        u->tsc_shift         = d->arch.vtsc_to_ns.shift;
    }
    else
    {
        if ( is_hvm_domain(d) && hvm_tsc_scaling_supported )
        {
            tsc_stamp            = hvm_scale_tsc(d, t->stamp.local_tsc);
            u->tsc_to_system_mul = d->arch.vtsc_to_ns.mul_frac;
            u->tsc_shift         = d->arch.vtsc_to_ns.shift;
        }
        else
        {
            tsc_stamp            = t->stamp.local_tsc;
            u->tsc_to_system_mul = t->tsc_scale.mul_frac;
            u->tsc_shift         = t->tsc_scale.shift;
        }
    }

    u->tsc_timestamp = tsc_stamp;
    u->system_time   = t->stamp.local_stime;

    /*
     * It's expected that domains cope with this bit changing on every
     * pvclock read to check whether they can resort solely on this tuple
     * or if it further requires monotonicity checks with other vcpus.
     */
    if ( clocksource_is_tsc() )
        u->flags |= XEN_PVCLOCK_TSC_STABLE_BIT;

    if ( is_hvm_domain(d) )
        u->tsc_timestamp += v->arch.hvm.cache_tsc_offset;
}

static void __update_vcpu_system_time(struct vcpu *v, int force)
{
    struct vcpu_time_info *u, _u;
    const struct domain *d = v->domain;

    if ( !v->vcpu_info_area.map )
        return;

    u = &vcpu_info(v, time);

    collect_time_info(v, &_u);

    /* Don't bother unless timestamp record has changed or we are forced. */
    _u.version = u->version; /* make versions match for memcmp test */
    if ( !force && !memcmp(u, &_u, sizeof(_u)) )
        return;

    /* 1. Update guest kernel version. */
    _u.version = u->version = version_update_begin(u->version);
    smp_wmb();
    /* 2. Update all other guest kernel fields. */
    *u = _u;
    smp_wmb();
    /* 3. Update guest kernel version. */
    u->version = version_update_end(u->version);

    if ( !update_secondary_system_time(v, &_u) && is_pv_domain(d) &&
         !is_pv_32bit_domain(d) && !(v->arch.flags & TF_kernel_mode) )
        v->arch.pv.pending_system_time = _u;
}

static void write_time_guest_area(struct vcpu_time_info *map,
                                  const struct vcpu_time_info *src)
{
    /* 1. Update userspace version. */
    write_atomic(&map->version, src->version);
    smp_wmb();

    /* 2. Update all other userspace fields. */
    *map = *src;

    /* 3. Update userspace version again. */
    smp_wmb();
    write_atomic(&map->version, version_update_end(src->version));
}

bool update_secondary_system_time(struct vcpu *v,
                                  struct vcpu_time_info *u)
{
    XEN_GUEST_HANDLE(vcpu_time_info_t) user_u = v->arch.time_info_guest;
    struct vcpu_time_info *map = v->arch.time_guest_area.map;
    struct guest_memory_policy policy = { .nested_guest_mode = false };

    if ( map )
    {
        write_time_guest_area(map, u);
        return true;
    }

    if ( guest_handle_is_null(user_u) )
        return true;

    update_guest_memory_policy(v, &policy);

    /* 1. Update userspace version. */
    if ( __copy_field_to_guest(user_u, u, version) == sizeof(u->version) )
    {
        update_guest_memory_policy(v, &policy);
        return false;
    }
    smp_wmb();
    /* 2. Update all other userspace fields. */
    __copy_to_guest(user_u, u, 1);
    smp_wmb();
    /* 3. Update userspace version. */
    u->version = version_update_end(u->version);
    __copy_field_to_guest(user_u, u, version);

    update_guest_memory_policy(v, &policy);

    return true;
}

void update_vcpu_system_time(struct vcpu *v)
{
    __update_vcpu_system_time(v, 0);
}

void force_update_vcpu_system_time(struct vcpu *v)
{
    __update_vcpu_system_time(v, 1);
}

void force_update_secondary_system_time(struct vcpu *v,
                                        struct vcpu_time_info *map)
{
    struct vcpu_time_info u;

    collect_time_info(v, &u);
    u.version = -1; /* Compensate for version_update_end(). */
    write_time_guest_area(map, &u);
}

static void update_domain_rtc(void)
{
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        if ( is_hvm_domain(d) )
            rtc_update_clock(d);

    rcu_read_unlock(&domlist_read_lock);
}

void domain_set_time_offset(struct domain *d, int64_t time_offset_seconds)
{
    d->time_offset.seconds = time_offset_seconds;
    d->time_offset.set = true;
    if ( is_hvm_domain(d) )
        rtc_update_clock(d);
    update_domain_wallclock_time(d);
}

int cpu_frequency_change(u64 freq)
{
    struct cpu_time *t = &this_cpu(cpu_time);
    u64 curr_tsc;

    /* Sanity check: CPU frequency allegedly dropping below 1MHz? */
    if ( freq < 1000000u )
    {
        printk(XENLOG_WARNING "Rejecting CPU frequency change "
               "to %"PRIu64" Hz\n", freq);
        return -EINVAL;
    }

    local_irq_disable();
    /* Platform time /first/, as we may be delayed by platform_timer_lock. */
    t->stamp.master_stime = read_platform_stime(NULL);
    curr_tsc = rdtsc_ordered();
    /* TSC-extrapolated time may be bogus after frequency change. */
    /*t->stamp.local_stime = get_s_time_fixed(curr_tsc);*/
    t->stamp.local_stime = t->stamp.master_stime;
    t->stamp.local_tsc = curr_tsc;
    set_time_scale(&t->tsc_scale, freq);
    local_irq_enable();

    update_vcpu_system_time(current);

    /* A full epoch should pass before we check for deviation. */
    if ( smp_processor_id() == 0 )
    {
        set_timer(&calibration_timer, NOW() + EPOCH);
        platform_time_calibration();
    }

    return 0;
}

/* Per-CPU communication between rendezvous IRQ and softirq handler. */
static DEFINE_PER_CPU(struct cpu_time_stamp, cpu_calibration);

/* Softirq handler for per-CPU time calibration. */
static void cf_check local_time_calibration(void)
{
    struct cpu_time *t = &this_cpu(cpu_time);
    const struct cpu_time_stamp *c = &this_cpu(cpu_calibration);

    /*
     * System (extrapolated from local and master oscillators) and TSC
     * timestamps, taken during this calibration and the previous one.
     */
    struct cpu_time_stamp prev, curr;

    /*
     * System time and TSC ticks elapsed during the previous calibration
     * 'epoch'. These values are down-shifted to fit in 32 bits.
     */
    u64 stime_elapsed64, tsc_elapsed64;
    u32 stime_elapsed32, tsc_elapsed32;

    /* Error correction to slow down a fast local clock. */
    u32 error_factor = 0;

    /* Calculated TSC shift to ensure 32-bit scale multiplier. */
    int tsc_shift = 0;

    /* The overall calibration scale multiplier. */
    u32 calibration_mul_frac;

    if ( boot_cpu_has(X86_FEATURE_CONSTANT_TSC) )
    {
        /* Atomically read cpu_calibration struct and write cpu_time struct. */
        local_irq_disable();
        t->stamp = *c;
        local_irq_enable();
        update_vcpu_system_time(current);
        goto out;
    }

    prev = t->stamp;

    /* Disabling IRQs ensures we atomically read cpu_calibration struct. */
    local_irq_disable();
    curr = *c;
    local_irq_enable();

#if 0
    printk("PRE%d: tsc=%"PRIu64" stime=%"PRIu64" master=%"PRIu64"\n",
           smp_processor_id(), prev.local_tsc, prev.local_stime, prev.master_stime);
    printk("CUR%d: tsc=%"PRIu64" stime=%"PRIu64" master=%"PRIu64
           " -> %"PRId64"\n",
           smp_processor_id(), curr.local_tsc, curr.local_stime, curr.master_stime,
           curr.master_stime - curr.local_stime);
#endif

    /* Local time warps forward if it lags behind master time. */
    if ( curr.local_stime < curr.master_stime )
        curr.local_stime = curr.master_stime;

    stime_elapsed64 = curr.master_stime - prev.master_stime;
    tsc_elapsed64   = curr.local_tsc - prev.local_tsc;

    /*
     * Weirdness can happen if we lose sync with the platform timer.
     * We could be smarter here: resync platform timer with local timer?
     */
    if ( ((s64)stime_elapsed64 < (EPOCH / 2)) )
        goto out;

    /*
     * Calculate error-correction factor. This only slows down a fast local
     * clock (slow clocks are warped forwards). The scale factor is clamped
     * to >= 0.5.
     */
    if ( curr.local_stime != curr.master_stime )
    {
        u64 local_stime_err = curr.local_stime - curr.master_stime;

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
    printk("---%d: %08x %08x %d\n", smp_processor_id(),
           error_factor, calibration_mul_frac, tsc_shift);
#endif

    /* Record new timestamp information, atomically w.r.t. interrupts. */
    local_irq_disable();
    t->tsc_scale.mul_frac = calibration_mul_frac;
    t->tsc_scale.shift    = tsc_shift;
    t->stamp              = curr;
    local_irq_enable();

    update_vcpu_system_time(current);

 out:
    if ( smp_processor_id() == 0 )
    {
        set_timer(&calibration_timer, NOW() + EPOCH);
        platform_time_calibration();
    }
}

/*
 * TSC Reliability check
 */

/*
 * The Linux original version of this function is
 * Copyright (c) 2006, Red Hat, Inc., Ingo Molnar
 */
static void check_tsc_warp(unsigned long tsc_khz, unsigned long *max_warp)
{
    static DEFINE_SPINLOCK(sync_lock);
    static cycles_t last_tsc;

    cycles_t start, now, prev, end;
    int i;

    start = rdtsc_ordered();

    /* The measurement runs for 20 msecs: */
    end = start + tsc_khz * 20ULL;
    now = start;

    for ( i = 0; ; i++ )
    {
        /*
         * We take the global lock, measure TSC, save the
         * previous TSC that was measured (possibly on
         * another CPU) and update the previous TSC timestamp.
         */
        spin_lock(&sync_lock);
        prev = last_tsc;
        now = rdtsc_ordered();
        last_tsc = now;
        spin_unlock(&sync_lock);

        /*
         * Be nice every now and then (and also check whether measurement is 
         * done [we also insert a 10 million loops safety exit, so we dont 
         * lock up in case the TSC readout is totally broken]):
         */
        if ( unlikely(!(i & 7)) )
        {
            if ( (now > end) || (i > 10000000) )
                break;
            cpu_relax();
            /*touch_nmi_watchdog();*/
        }

        /*
         * Outside the critical section we can now see whether we saw a 
         * time-warp of the TSC going backwards:
         */
        if ( unlikely(prev > now) )
        {
            spin_lock(&sync_lock);
            if ( *max_warp < prev - now )
                *max_warp = prev - now;
            spin_unlock(&sync_lock);
        }
    }
}

static unsigned long tsc_max_warp, tsc_check_count;
static cpumask_t tsc_check_cpumask;

static void cf_check tsc_check_slave(void *unused)
{
    unsigned int cpu = smp_processor_id();
    local_irq_disable();
    while ( !cpumask_test_cpu(cpu, &tsc_check_cpumask) )
        cpu_relax();
    check_tsc_warp(cpu_khz, &tsc_max_warp);
    cpumask_clear_cpu(cpu, &tsc_check_cpumask);
    local_irq_enable();
}

static void tsc_check_reliability(void)
{
    unsigned int cpu = smp_processor_id();
    static DEFINE_SPINLOCK(lock);

    spin_lock(&lock);

    tsc_check_count++;
    smp_call_function(tsc_check_slave, NULL, 0);
    cpumask_andnot(&tsc_check_cpumask, &cpu_online_map, cpumask_of(cpu));
    local_irq_disable();
    check_tsc_warp(cpu_khz, &tsc_max_warp);
    local_irq_enable();
    while ( !cpumask_empty(&tsc_check_cpumask) )
        cpu_relax();

    spin_unlock(&lock);
}

/*
 * Rendezvous for all CPUs in IRQ context.
 * Master CPU snapshots the platform timer.
 * All CPUS snapshot their local TSC and extrapolation of system time.
 */
struct calibration_rendezvous {
    cpumask_t cpu_calibration_map;
    atomic_t semaphore;
    s_time_t master_stime;
    uint64_t master_tsc_stamp, max_tsc_stamp;
};

static void
time_calibration_rendezvous_tail(const struct calibration_rendezvous *r,
                                 uint64_t old_tsc, uint64_t new_tsc)
{
    struct cpu_time_stamp *c = &this_cpu(cpu_calibration);

    c->local_tsc    = new_tsc;
    c->local_stime  = get_s_time_fixed(old_tsc ?: new_tsc);
    c->master_stime = r->master_stime;

    raise_softirq(TIME_CALIBRATE_SOFTIRQ);
}

/*
 * Keep TSCs in sync when they run at the same rate, but may stop in
 * deep-sleep C states.
 */
static void cf_check time_calibration_tsc_rendezvous(void *_r)
{
    int i;
    struct calibration_rendezvous *r = _r;
    unsigned int total_cpus = cpumask_weight(&r->cpu_calibration_map);
    uint64_t tsc = 0, master_tsc = 0;

    /* Loop to get rid of cache effects on TSC skew. */
    for ( i = 4; i >= 0; i-- )
    {
        if ( smp_processor_id() == 0 )
        {
            while ( atomic_read(&r->semaphore) != (total_cpus - 1) )
                cpu_relax();

            if ( tsc == 0 )
                r->master_tsc_stamp = tsc = rdtsc_ordered();
            else if ( r->master_tsc_stamp < r->max_tsc_stamp )
                /*
                 * We want to avoid moving the TSC backwards for any CPU.
                 * Use the largest value observed anywhere on the first
                 * iteration.
                 */
                r->master_tsc_stamp = r->max_tsc_stamp;
            else if ( !boot_cpu_has(X86_FEATURE_CONSTANT_TSC) && i == 0 )
                r->master_stime = read_platform_stime(NULL);

            atomic_inc(&r->semaphore);

            if ( i == 0 )
            {
                write_tsc(master_tsc);
                /*
                 * Try to give our hyperthread(s), if any, a chance to do
                 * the same as instantly as possible.
                 */
                cpu_relax();
            }

            while ( atomic_read(&r->semaphore) != (2*total_cpus - 1) )
                cpu_relax();
            atomic_set(&r->semaphore, 0);
        }
        else
        {
            atomic_inc(&r->semaphore);
            while ( atomic_read(&r->semaphore) < total_cpus )
                cpu_relax();

            if ( tsc == 0 )
            {
                uint64_t cur = ACCESS_ONCE(r->max_tsc_stamp);

                tsc = rdtsc_ordered();
                while ( tsc > cur )
                    cur = cmpxchg(&r->max_tsc_stamp, cur, tsc);
            }

            if ( i == 0 )
            {
                write_tsc(master_tsc);
                /*
                 * Try to give our hyperthread(s), if any, a chance to do
                 * the same as instantly as possible.
                 */
                cpu_relax();
            }

            atomic_inc(&r->semaphore);
            while ( atomic_read(&r->semaphore) > total_cpus )
                cpu_relax();
        }

        /* Just in case a read above ended up reading zero. */
        tsc += !tsc;

        /*
         * To reduce latency of the TSC write on the last iteration,
         * fetch the value to be written into a local variable. To avoid
         * introducing yet another conditional branch (which the CPU may
         * have difficulty predicting well) do this on all iterations.
         */
        master_tsc = r->master_tsc_stamp;
    }

    time_calibration_rendezvous_tail(r, tsc, master_tsc);
}

/* Ordinary rendezvous function which does not modify TSC values. */
static void cf_check time_calibration_std_rendezvous(void *_r)
{
    struct calibration_rendezvous *r = _r;
    unsigned int total_cpus = cpumask_weight(&r->cpu_calibration_map);

    if ( smp_processor_id() == 0 )
    {
        while ( atomic_read(&r->semaphore) != (total_cpus - 1) )
            cpu_relax();
        if ( !boot_cpu_has(X86_FEATURE_CONSTANT_TSC) )
        {
            r->master_stime = read_platform_stime(NULL);
            smp_wmb(); /* write r->master_stime /then/ signal */
        }
        atomic_inc(&r->semaphore);
    }
    else
    {
        atomic_inc(&r->semaphore);
        while ( atomic_read(&r->semaphore) != total_cpus )
            cpu_relax();
        smp_rmb(); /* receive signal /then/ read r->master_stime */
    }

    time_calibration_rendezvous_tail(r, 0, rdtsc_ordered());
}

/*
 * Rendezvous function used when clocksource is TSC and
 * no CPU hotplug will be performed.
 */
static void cf_check time_calibration_nop_rendezvous(void *rv)
{
    const struct calibration_rendezvous *r = rv;
    struct cpu_time_stamp *c = &this_cpu(cpu_calibration);

    c->local_tsc    = r->master_tsc_stamp;
    c->local_stime  = r->master_stime;
    c->master_stime = r->master_stime;

    raise_softirq(TIME_CALIBRATE_SOFTIRQ);
}

static void (*time_calibration_rendezvous_fn)(void *) =
    time_calibration_std_rendezvous;

static void cf_check time_calibration(void *unused)
{
    struct calibration_rendezvous r = {
        .semaphore = ATOMIC_INIT(0)
    };

    if ( clocksource_is_tsc() )
    {
        local_irq_disable();
        r.master_stime = read_platform_stime(&r.master_tsc_stamp);
        local_irq_enable();
    }

    cpumask_copy(&r.cpu_calibration_map, &cpu_online_map);

    /* @wait=1 because we must wait for all cpus before freeing @r. */
    on_selected_cpus(&r.cpu_calibration_map,
                     time_calibration_rendezvous_fn,
                     &r, 1);
}

static struct cpu_time_stamp ap_bringup_ref;

void time_latch_stamps(void)
{
    unsigned long flags;

    local_irq_save(flags);
    ap_bringup_ref.master_stime = read_platform_stime(NULL);
    ap_bringup_ref.local_tsc = rdtsc_ordered();
    local_irq_restore(flags);

    ap_bringup_ref.local_stime = get_s_time_fixed(ap_bringup_ref.local_tsc);
}

void init_percpu_time(void)
{
    struct cpu_time *t = &this_cpu(cpu_time);
    unsigned long flags;
    u64 tsc;
    s_time_t now;

    /* Initial estimate for TSC rate. */
    t->tsc_scale = per_cpu(cpu_time, 0).tsc_scale;

    if ( tsc_adjust )
    {
        unsigned int socket = cpu_to_socket(smp_processor_id());
        int64_t adj;

        /* For now we don't want to come here for the BSP. */
        ASSERT(system_state >= SYS_STATE_smp_boot);

        rdmsrl(MSR_IA32_TSC_ADJUST, adj);

        /*
         * Check whether this CPU is the first in a package to come up. In
         * this case do not check the boot value against another package
         * because the new package might have been physically hotplugged,
         * where TSC_ADJUST is expected to be different.
         */
        if ( cpumask_weight(socket_cpumask[socket]) == 1 )
        {
            /*
             * On the boot CPU we just force the ADJUST value to 0 if it's non-
             * zero (in early_time_init()). We don't do that on non-boot CPUs
             * because physical hotplug should have set the ADJUST register to a
             * value > 0, so the TSC is in sync with the already running CPUs.
             *
             * But we always force non-negative ADJUST values for now.
             */
            if ( adj < 0 )
            {
                printk(XENLOG_WARNING
                       "TSC ADJUST set to -%lx on CPU%u - clearing\n",
                       -adj, smp_processor_id());
                wrmsrl(MSR_IA32_TSC_ADJUST, 0);
                adj = 0;
            }
            tsc_adjust[socket] = adj;
        }
        else if ( adj != tsc_adjust[socket] )
        {
            printk_once(XENLOG_WARNING
                        "Differing TSC ADJUST values within socket(s) - fixing all\n");
            wrmsrl(MSR_IA32_TSC_ADJUST, tsc_adjust[socket]);
        }
    }

    local_irq_save(flags);
    now = read_platform_stime(NULL);
    tsc = rdtsc_ordered();
    local_irq_restore(flags);

    t->stamp.master_stime = now;
    /*
     * To avoid a discontinuity (TSC and platform clock can't be expected
     * to be in perfect sync), initialization here needs to match up with
     * local_time_calibration()'s decision whether to use its fast path.
     */
    if ( boot_cpu_has(X86_FEATURE_CONSTANT_TSC) )
    {
        if ( system_state < SYS_STATE_smp_boot )
            now = get_s_time_fixed(tsc);
        else
            now += ap_bringup_ref.local_stime - ap_bringup_ref.master_stime;
    }
    t->stamp.local_tsc   = tsc;
    t->stamp.local_stime = now;
}

/*
 * On certain older Intel CPUs writing the TSC MSR clears the upper 32 bits. 
 * Obviously we must not use write_tsc() on such CPUs.
 *
 * Additionally, AMD specifies that being able to write the TSC MSR is not an 
 * architectural feature (but, other than their manual says, also cannot be 
 * determined from CPUID bits).
 */
static void __init tsc_check_writability(void)
{
    const char *what = NULL;
    uint64_t tsc;

    /*
     * If all CPUs are reported as synchronised and in sync, we never write
     * the TSCs (except unavoidably, when a CPU is physically hot-plugged).
     * Hence testing for writability is pointless and even harmful.
     */
    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
        return;

    tsc = rdtsc();
    if ( wrmsr_safe(MSR_IA32_TSC, 0) == 0 )
    {
        uint64_t tmp, tmp2 = rdtsc();

        write_tsc(tsc | (1ULL << 32));
        tmp = rdtsc();
        if ( ABS((s64)tmp - (s64)tmp2) < (1LL << 31) )
            what = "only partially";
    }
    else
    {
        what = "not";
    }

    /* Nothing to do if the TSC is fully writable. */
    if ( !what )
    {
        /*
         * Paranoia - write back original TSC value. However, APs get synced
         * with BSP as they are brought up, so this doesn't much matter.
         */
        write_tsc(tsc);
        return;
    }

    printk(XENLOG_WARNING "TSC %s writable\n", what);

    /* time_calibration_tsc_rendezvous() must not be used */
    setup_clear_cpu_cap(X86_FEATURE_CONSTANT_TSC);

    /* cstate_restore_tsc() must not be used (or do nothing) */
    if ( !boot_cpu_has(X86_FEATURE_NONSTOP_TSC) )
        cpuidle_disable_deep_cstate();

    /* synchronize_tsc_slave() must do nothing */
    disable_tsc_sync = true;
}

static void __init cf_check reset_percpu_time(void *unused)
{
    struct cpu_time *t = &this_cpu(cpu_time);

    t->stamp.local_tsc = boot_tsc_stamp;
    t->stamp.local_stime = 0;
    t->stamp.local_stime = get_s_time_fixed(boot_tsc_stamp);
    t->stamp.master_stime = t->stamp.local_stime;
}

static void __init try_platform_timer_tail(void)
{
    init_timer(&plt_overflow_timer, plt_overflow, NULL, 0);
    plt_overflow(NULL);

    platform_timer_stamp = plt_stamp64;
    stime_platform_stamp = NOW();
}

/* Late init function, after all cpus have booted */
static int __init cf_check verify_tsc_reliability(void)
{
    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
    {
        /*
         * Sadly, despite processor vendors' best design guidance efforts, on
         * some systems, cpus may come out of reset improperly synchronized.
         * So we must verify there is no warp and we can't do that until all
         * CPUs are booted.
         */
        tsc_check_reliability();
        if ( tsc_max_warp )
        {
            printk("TSC warp detected, disabling TSC_RELIABLE\n");
            setup_clear_cpu_cap(X86_FEATURE_TSC_RELIABLE);
        }
        else if ( !strcmp(opt_clocksource, "tsc") &&
                  (try_platform_timer(&plt_tsc) > 0) )
        {
            /*
             * Platform timer has changed and CPU time will only be updated
             * after we set again the calibration timer, which means we need to
             * seed again each local CPU time. At this stage TSC is known to be
             * reliable i.e. monotonically increasing across all CPUs so this
             * lets us remove the skew between platform timer and TSC, since
             * these are now effectively the same.
             */
            on_selected_cpus(&cpu_online_map, reset_percpu_time, NULL, 1);

            /*
             * We won't do CPU Hotplug and TSC clocksource is being used which
             * means we have a reliable TSC, plus we don't sync with any other
             * clocksource so no need for rendezvous.
             */
            time_calibration_rendezvous_fn = time_calibration_nop_rendezvous;

            /* Finish platform timer switch. */
            try_platform_timer_tail();

            printk("Switched to Platform timer %s TSC\n",
                   freq_string(plt_src.frequency));

            time_calibration(NULL);

            return 0;
        }
    }

    /*
     * Re-run the TSC writability check if it didn't run to completion, as
     * X86_FEATURE_TSC_RELIABLE may have been cleared by now. This is needed
     * for determining which rendezvous function to use (below).
     */
    if ( !disable_tsc_sync )
        tsc_check_writability();

    /*
     * While with constant-rate TSCs the scale factor can be shared, when TSCs
     * are not marked as 'reliable', re-sync during rendezvous.
     */
    if ( boot_cpu_has(X86_FEATURE_CONSTANT_TSC) &&
         !boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
        time_calibration_rendezvous_fn = time_calibration_tsc_rendezvous;

    time_calibration(NULL);

    return 0;
}
__initcall(verify_tsc_reliability);

/* Late init function (after interrupts are enabled). */
int __init init_xen_time(void)
{
    tsc_check_writability();

    open_softirq(TIME_CALIBRATE_SOFTIRQ, local_time_calibration);

    /* NB. get_wallclock_time() can take over one second to execute. */
    do_settime(get_wallclock_time(), 0, NOW());

    /* Finish platform timer initialization. */
    try_platform_timer_tail();

    init_percpu_time();

    init_timer(&calibration_timer, time_calibration, NULL, 0);

    /*
     * Setup space to track per-socket TSC_ADJUST values. Don't fiddle with
     * values if the TSC is not reported as invariant. Ignore allocation
     * failure here - most systems won't need any adjustment anyway.
     */
    if ( boot_cpu_has(X86_FEATURE_TSC_ADJUST) &&
         boot_cpu_has(X86_FEATURE_ITSC) )
        tsc_adjust = xzalloc_array(uint64_t, nr_sockets);

    return 0;
}


/* Early init function. */
void __init early_time_init(void)
{
    struct cpu_time *t = &this_cpu(cpu_time);
    u64 tmp;

    if ( boot_cpu_has(X86_FEATURE_TSC_ADJUST) &&
         boot_cpu_has(X86_FEATURE_ITSC) )
    {
        rdmsrl(MSR_IA32_TSC_ADJUST, tmp);
        if ( tmp )
        {
            printk(XENLOG_WARNING
                   "TSC ADJUST set to %lx on boot CPU - clearing\n", tmp);
            wrmsrl(MSR_IA32_TSC_ADJUST, 0);
            boot_tsc_stamp -= tmp;
        }
    }

    preinit_pit();
    probe_pit_alias();

    tmp = init_platform_timer();
    plt_tsc.frequency = tmp;

    set_time_scale(&t->tsc_scale, tmp);
    t->stamp.local_tsc = boot_tsc_stamp;

    cpu_khz = tmp / 1000;
    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, 0, &irq0);
}

/* keep pit enabled for pit_broadcast working while cpuidle enabled */
static int _disable_pit_irq(bool init)
{
    int ret = 1;

    if ( using_pit || !cpu_has_apic )
        return -1;

    /*
     * If we do not rely on PIT CH0 then we can use HPET for one-shot timer 
     * emulation when entering deep C states.
     * XXX dom0 may rely on RTC interrupt delivery, so only enable
     * hpet_broadcast if FSB mode available or if force_hpet_broadcast.
     */
    if ( cpuidle_using_deep_cstate() && !boot_cpu_has(X86_FEATURE_ARAT) )
    {
        init ? hpet_broadcast_init() : hpet_broadcast_resume();
        if ( !hpet_broadcast_is_available() )
        {
            if ( xen_cpuidle > 0 )
            {
                printk("hpet_broadcast_%s() failed, turning to PIT broadcast\n",
                       init ? "init" : "resume");
                return -1;
            }
            ret = 0;
        }
    }

    /* Disable PIT CH0 timer interrupt. */
    outb_p(PIT_TCW_CH(0) | PIT_RW_LSB_MSB | PIT_MODE_EOC | PIT_BINARY,
           PIT_MODE);
    outb_p(0, PIT_CH0);
    outb_p(0, PIT_CH0);

    return ret;
}

static int __init cf_check disable_pit_irq(void)
{
    if ( !_disable_pit_irq(true) )
    {
        xen_cpuidle = 0;
        printk("CPUIDLE: disabled due to no HPET. "
               "Force enable with 'cpuidle'.\n");
    }

    return 0;
}
__initcall(disable_pit_irq);

void cf_check pit_broadcast_enter(void)
{
    cpumask_set_cpu(smp_processor_id(), &pit_broadcast_mask);
}

void cf_check pit_broadcast_exit(void)
{
    int cpu = smp_processor_id();

    if ( cpumask_test_and_clear_cpu(cpu, &pit_broadcast_mask) )
        reprogram_timer(this_cpu(timer_deadline));
}

int pit_broadcast_is_available(void)
{
    return cpuidle_using_deep_cstate();
}

void send_timer_event(struct vcpu *v)
{
    send_guest_vcpu_virq(v, VIRQ_TIMER);
}

/* "cmos_utc_offset" is the difference between UTC time and CMOS time. */
static long cmos_utc_offset; /* in seconds */

int time_suspend(void)
{
    unsigned int cpu = smp_processor_id();

    if ( cpu == 0 )
    {
        cmos_utc_offset = -get_wallclock_time();
        cmos_utc_offset += get_sec();
        kill_timer(&calibration_timer);

        /* Sync platform timer stamps. */
        platform_time_calibration();
    }

    /* Better to cancel calibration timer for accuracy. */
    clear_bit(TIME_CALIBRATE_SOFTIRQ, &softirq_pending(cpu));

    return 0;
}

int time_resume(void)
{
    preinit_pit();

    resume_platform_timer();

    if ( !_disable_pit_irq(false) )
        BUG();

    init_percpu_time();

    set_timer(&calibration_timer, NOW() + EPOCH);

    do_settime(get_wallclock_time() + cmos_utc_offset, 0, NOW());

    update_vcpu_system_time(current);

    update_domain_rtc();

    return 0;
}

int hwdom_pit_access(struct ioreq *ioreq)
{
    /* Is Xen using Channel 2? Then disallow direct dom0 access. */
    if ( using_pit )
        return 0;

    switch ( ioreq->addr )
    {
    case PIT_CH2:
        if ( ioreq->dir == IOREQ_READ )
            ioreq->data = inb(PIT_CH2);
        else
            outb(ioreq->data, PIT_CH2);
        return 1;

    case PIT_MODE:
        if ( ioreq->dir == IOREQ_READ )
            return 0; /* urk! */
        switch ( ioreq->data & PIT_TCW_CH(3) )
        {
        case PIT_RDB: /* Read Back */
            if ( ioreq->data & PIT_RDB_CH2 )
                outb(ioreq->data & ~(PIT_RDB_CH1 | PIT_RDB_CH0 | PIT_RDB_RSVD),
                     PIT_MODE);
            if ( !(ioreq->data & (PIT_RDB_CH0 | PIT_RDB_CH1)) )
                return 1; /* no - we're done */
            /* Filter Channel 2 and reserved bit 0. */
            ioreq->data &= ~(PIT_RDB_CH2 | PIT_RDB_RSVD);
            return 0; /* emulate ch0/1 readback */
        case PIT_TCW_CH(2):
            outb(ioreq->data, PIT_MODE);
            return 1;
        }
        break;

    case 0x61:
        if ( ioreq->dir == IOREQ_READ )
            ioreq->data = inb(0x61);
        else
            outb((inb(0x61) & ~3) | (ioreq->data & 3), 0x61);
        return 1;
    }

    return 0;
}

/*
 * PV SoftTSC Emulation.
 */

/*
 * tsc=unstable: Override all tests; assume TSC is unreliable.
 * tsc=skewed: Assume TSCs are individually reliable, but skewed across CPUs.
 * tsc=stable:socket: Assume TSCs are reliable across sockets.
 */
static int __init cf_check tsc_parse(const char *s)
{
    if ( !strcmp(s, "unstable") )
    {
        setup_clear_cpu_cap(X86_FEATURE_CONSTANT_TSC);
        setup_clear_cpu_cap(X86_FEATURE_NONSTOP_TSC);
        setup_clear_cpu_cap(X86_FEATURE_TSC_RELIABLE);
    }
    else if ( !strcmp(s, "skewed") )
        setup_clear_cpu_cap(X86_FEATURE_TSC_RELIABLE);
    else if ( !strcmp(s, "stable:socket") )
        tsc_flags |= TSC_RELIABLE_SOCKET;
    else
        return -EINVAL;

    return 0;
}
custom_param("tsc", tsc_parse);

uint64_t gtime_to_gtsc(const struct domain *d, uint64_t time)
{
    if ( !is_hvm_domain(d) )
    {
        if ( time < d->arch.vtsc_offset )
            return -scale_delta(d->arch.vtsc_offset - time,
                                &d->arch.ns_to_vtsc);
        time -= d->arch.vtsc_offset;
    }
    return scale_delta(time, &d->arch.ns_to_vtsc);
}

uint64_t gtsc_to_gtime(const struct domain *d, uint64_t tsc)
{
    u64 time = scale_delta(tsc, &d->arch.vtsc_to_ns);

    if ( !is_hvm_domain(d) )
        time += d->arch.vtsc_offset;
    return time;
}

uint64_t pv_soft_rdtsc(const struct vcpu *v, const struct cpu_user_regs *regs)
{
    s_time_t old, new, now = get_s_time();
    struct domain *d = v->domain;

    do {
        old = d->arch.vtsc_last;
        new = now > d->arch.vtsc_last ? now : old + 1;
    } while ( cmpxchg(&d->arch.vtsc_last, old, new) != old );

    return gtime_to_gtsc(d, new);
}

bool clocksource_is_tsc(void)
{
    return plt_src.read_counter == READ_TSC_POISON;
}

int host_tsc_is_safe(void)
{
    return boot_cpu_has(X86_FEATURE_TSC_RELIABLE);
}

/*
 * called to collect tsc-related data only for save file or live
 * migrate; called after last rdtsc is done on this incarnation
 */
void tsc_get_info(struct domain *d, uint32_t *tsc_mode,
                  uint64_t *elapsed_nsec, uint32_t *gtsc_khz,
                  uint32_t *incarnation)
{
    bool enable_tsc_scaling = is_hvm_domain(d) &&
                              hvm_tsc_scaling_supported && !d->arch.vtsc;

    *incarnation = d->arch.incarnation;
    *tsc_mode = d->arch.tsc_mode;

    switch ( *tsc_mode )
    {
        uint64_t tsc;

    case XEN_CPUID_TSC_MODE_NEVER_EMULATE:
        *elapsed_nsec = *gtsc_khz = 0;
        break;
    case XEN_CPUID_TSC_MODE_DEFAULT:
        if ( d->arch.vtsc )
        {
    case XEN_CPUID_TSC_MODE_ALWAYS_EMULATE:
            *elapsed_nsec = get_s_time() - d->arch.vtsc_offset;
            *gtsc_khz = d->arch.tsc_khz;
            break;
        }
        tsc = rdtsc();
        *elapsed_nsec = scale_delta(tsc, &d->arch.vtsc_to_ns);
        *gtsc_khz = enable_tsc_scaling ? d->arch.tsc_khz : cpu_khz;
        break;
    }

    if ( (int64_t)*elapsed_nsec < 0 )
        *elapsed_nsec = 0;
}

/*
 * This may be called as many as three times for a domain, once when the
 * hypervisor creates the domain, once when the toolstack creates the
 * domain and, if restoring/migrating, once when saved/migrated values
 * are restored.  Care must be taken that, if multiple calls occur,
 * only the last "sticks" and all are completed before the guest executes
 * an rdtsc instruction
 */
int tsc_set_info(struct domain *d,
                 uint32_t tsc_mode, uint64_t elapsed_nsec,
                 uint32_t gtsc_khz, uint32_t incarnation)
{
    ASSERT(!is_system_domain(d));

    if ( is_pv_domain(d) && is_hardware_domain(d) )
    {
        d->arch.vtsc = 0;
        return 0;
    }

    switch ( tsc_mode )
    {
    case XEN_CPUID_TSC_MODE_DEFAULT:
    case XEN_CPUID_TSC_MODE_ALWAYS_EMULATE:
        d->arch.vtsc_offset = get_s_time() - elapsed_nsec;
        d->arch.tsc_khz = gtsc_khz ?: cpu_khz;
        set_time_scale(&d->arch.vtsc_to_ns, d->arch.tsc_khz * 1000UL);

        /*
         * In default mode use native TSC if the host has safe TSC and
         * host and guest frequencies are the same (either "naturally" or
         * - for HVM/PVH - via TSC scaling).
         * When a guest is created, gtsc_khz is passed in as zero, making
         * d->arch.tsc_khz == cpu_khz. Thus no need to check incarnation.
         */
        if ( tsc_mode == XEN_CPUID_TSC_MODE_DEFAULT && host_tsc_is_safe() &&
             (d->arch.tsc_khz == cpu_khz ||
              (is_hvm_domain(d) &&
               hvm_get_tsc_scaling_ratio(d->arch.tsc_khz))) )
        {
    case XEN_CPUID_TSC_MODE_NEVER_EMULATE:
            d->arch.vtsc = 0;
            break;
        }
        d->arch.vtsc = 1;
        d->arch.ns_to_vtsc = scale_reciprocal(d->arch.vtsc_to_ns);
        break;

    default:
        return -EINVAL;
    }

    d->arch.tsc_mode = tsc_mode;

    d->arch.incarnation = incarnation + 1;
    if ( is_hvm_domain(d) )
    {
        if ( hvm_tsc_scaling_supported && !d->arch.vtsc )
            d->arch.hvm.tsc_scaling_ratio =
                hvm_get_tsc_scaling_ratio(d->arch.tsc_khz);

        hvm_set_rdtsc_exiting(d, d->arch.vtsc);
        if ( d->vcpu && d->vcpu[0] && incarnation == 0 )
        {
            /*
             * set_tsc_offset() is called from hvm_vcpu_initialise() before
             * tsc_set_info(). New vtsc mode may require recomputing TSC
             * offset.
             * We only need to do this for BSP during initial boot. APs will
             * call set_tsc_offset() later from hvm_vcpu_reset_state() and they
             * will sync their TSC to BSP's sync_tsc.
             */
            d->arch.hvm.sync_tsc = rdtsc();
            hvm_set_tsc_offset(d->vcpu[0],
                               d->vcpu[0]->arch.hvm.cache_tsc_offset,
                               d->arch.hvm.sync_tsc);
        }
    }

    return 0;
}

/* vtsc may incur measurable performance degradation, diagnose with this */
static void cf_check dump_softtsc(unsigned char key)
{
    struct domain *d;
    int domcnt = 0;

    tsc_check_reliability();
    if ( boot_cpu_has(X86_FEATURE_TSC_RELIABLE) )
        printk("TSC marked as reliable, "
               "warp = %lu (count=%lu)\n", tsc_max_warp, tsc_check_count);
    else if ( boot_cpu_has(X86_FEATURE_CONSTANT_TSC ) )
    {
        printk("TSC has constant rate, ");
        if ( max_cstate <= ACPI_STATE_C2 && tsc_max_warp == 0 )
            printk("no deep Cstates, passed warp test, deemed reliable, ");
        else
            printk("deep Cstates possible, so not reliable, ");
        printk("warp=%lu (count=%lu)\n", tsc_max_warp, tsc_check_count);
    } else
        printk("TSC not marked as either constant or reliable, "
               "warp=%lu (count=%lu)\n", tsc_max_warp, tsc_check_count);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( is_hardware_domain(d) &&
             d->arch.tsc_mode == XEN_CPUID_TSC_MODE_DEFAULT )
            continue;
        printk("dom%u%s: mode=%d",d->domain_id,
                is_hvm_domain(d) ? "(hvm)" : "", d->arch.tsc_mode);
        if ( d->arch.vtsc_offset )
            printk(",ofs=%#"PRIx64, d->arch.vtsc_offset);
        if ( d->arch.tsc_khz )
            printk(",khz=%"PRIu32, d->arch.tsc_khz);
        if ( d->arch.incarnation )
            printk(",inc=%"PRIu32, d->arch.incarnation);
        printk("\n");
        domcnt++;
    }

    rcu_read_unlock(&domlist_read_lock);

    if ( !domcnt )
            printk("No domains have emulated TSC\n");
}

static int __init cf_check setup_dump_softtsc(void)
{
    register_keyhandler('s', dump_softtsc, "dump softtsc stats", 1);
    return 0;
}
__initcall(setup_dump_softtsc);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
