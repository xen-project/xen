#include <mini-os/os.h>
#include <mini-os/hypervisor.h>
#include <mini-os/events.h>
#include <mini-os/traps.h>
#include <mini-os/types.h>
#include <mini-os/time.h>
#include <mini-os/lib.h>

//#define VTIMER_DEBUG
#ifdef VTIMER_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=vtimer.c, line=%d) " _f , __LINE__, ## _a)
#else
#define DEBUG(_f, _a...)    ((void)0)
#endif

/************************************************************************
 * Time functions
 *************************************************************************/

static uint64_t cntvct_at_init;
static uint32_t counter_freq;

/* Compute with 96 bit intermediate result: (a*b)/c */
uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    union {
        uint64_t ll;
        struct {
            uint32_t low, high;
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
}

static inline s_time_t ticks_to_ns(uint64_t ticks)
{
    return muldiv64(ticks, SECONDS(1), counter_freq);
}

static inline uint64_t ns_to_ticks(s_time_t ns)
{
    return muldiv64(ns, counter_freq, SECONDS(1));
}

/* Wall-clock time is not currently available on ARM, so this is always zero for now:
 * http://wiki.xenproject.org/wiki/Xen_ARM_TODO#Expose_Wallclock_time_to_guests
 */
static struct timespec shadow_ts;

static inline uint64_t read_virtual_count(void)
{
    uint32_t c_lo, c_hi;
    __asm__ __volatile__("mrrc p15, 1, %0, %1, c14":"=r"(c_lo), "=r"(c_hi));
    return (((uint64_t) c_hi) << 32) + c_lo;
}

/* monotonic_clock(): returns # of nanoseconds passed since time_init()
 *        Note: This function is required to return accurate
 *        time even in the absence of multiple timer ticks.
 */
uint64_t monotonic_clock(void)
{
    return ticks_to_ns(read_virtual_count() - cntvct_at_init);
}

int gettimeofday(struct timeval *tv, void *tz)
{
    uint64_t nsec = monotonic_clock();
    nsec += shadow_ts.tv_nsec;

    tv->tv_sec = shadow_ts.tv_sec;
    tv->tv_sec += NSEC_TO_SEC(nsec);
    tv->tv_usec = NSEC_TO_USEC(nsec % 1000000000UL);

    return 0;
}

/* Set the timer and mask. */
void write_timer_ctl(uint32_t value) {
    __asm__ __volatile__(
            "mcr p15, 0, %0, c14, c3, 1\n"
            "isb"::"r"(value));
}

void set_vtimer_compare(uint64_t value) {
    DEBUG("New CompareValue : %llx\n", value);

    __asm__ __volatile__("mcrr p15, 3, %0, %H0, c14"
            ::"r"(value));

    /* Enable timer and unmask the output signal */
    write_timer_ctl(1);
}

void unset_vtimer_compare(void) {
    /* Disable timer and mask the output signal */
    write_timer_ctl(2);
}

void block_domain(s_time_t until)
{
    uint64_t until_count = ns_to_ticks(until) + cntvct_at_init;
    ASSERT(irqs_disabled());
    if (read_virtual_count() < until_count)
    {
        set_vtimer_compare(until_count);
        __asm__ __volatile__("wfi");
        unset_vtimer_compare();

        /* Give the IRQ handler a chance to handle whatever woke us up. */
        local_irq_enable();
        local_irq_disable();
    }
}

void init_time(void)
{
    printk("Initialising timer interface\n");

    __asm__ __volatile__("mrc p15, 0, %0, c14, c0, 0":"=r"(counter_freq));
    cntvct_at_init = read_virtual_count();
    printk("Virtual Count register is %llx, freq = %d Hz\n", cntvct_at_init, counter_freq);
}

void fini_time(void)
{
}
