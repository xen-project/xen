#ifndef __ARM_TIME_H__
#define __ARM_TIME_H__

#include <asm/sysregs.h>
#include <asm/system.h>
#include <asm/cpuerrata.h>

#define DT_MATCH_TIMER                      \
    DT_MATCH_COMPATIBLE("arm,armv7-timer"), \
    DT_MATCH_COMPATIBLE("arm,armv8-timer")

typedef uint64_t cycles_t;

/*
 * Ensure that reads of the counter are treated the same as memory reads
 * for the purposes of ordering by subsequent memory barriers.
 */
#if defined(CONFIG_ARM_64)
#define read_cntpct_enforce_ordering(val) do { \
    uint64_t tmp, _val = (val);                \
                                               \
    asm volatile(                              \
    "eor %0, %1, %1\n"                         \
    "add %0, sp, %0\n"                         \
    "ldr xzr, [%0]"                            \
    : "=r" (tmp) : "r" (_val));                \
} while (0)
#else
#define read_cntpct_enforce_ordering(val) do {} while (0)
#endif

static inline cycles_t read_cntpct_stable(void)
{
    /*
     * ARM_WORKAROUND_858921: Cortex-A73 (all versions) counter read
     * can return a wrong value when the counter crosses a 32bit boundary.
     */
    if ( !check_workaround_858921() )
        return READ_SYSREG64(CNTPCT_EL0);
    else
    {
        /*
         * A recommended workaround for erratum 858921 is to:
         *  1- Read twice CNTPCT.
         *  2- Compare bit[32] of the two read values.
         *      - If bit[32] is different, keep the old value.
         *      - If bit[32] is the same, keep the new value.
         */
        cycles_t old, new;
        old = READ_SYSREG64(CNTPCT_EL0);
        new = READ_SYSREG64(CNTPCT_EL0);
        return (((old ^ new) >> 32) & 1) ? old : new;
    }
}

static inline cycles_t get_cycles(void)
{
    cycles_t cnt;

    isb();
    cnt = read_cntpct_stable();

    /*
     * If there is not any barrier here. When get_cycles being used in
     * some seqlock critical context in the future, the seqlock can be
     * speculated potentially.
     *
     * To prevent seqlock from being speculated silently, we add a barrier
     * here defensively. Normally, we just need an ISB here is enough, but
     * considering the minimum performance cost. We prefer to use enforce
     * order here.
     */
    read_cntpct_enforce_ordering(cnt);

    return cnt;
}

/* List of timer's IRQ */
enum timer_ppi
{
    TIMER_PHYS_SECURE_PPI = 0,
    TIMER_PHYS_NONSECURE_PPI = 1,
    TIMER_VIRT_PPI = 2,
    TIMER_HYP_PPI = 3,
    MAX_TIMER_PPI = 4,
};

/*
 * Value of "clock-frequency" in the DT timer node if present.
 * 0 means the property doesn't exist.
 */
extern uint32_t timer_dt_clock_frequency;

/* Get one of the timer IRQ number */
unsigned int timer_get_irq(enum timer_ppi ppi);

/* Set up the timer interrupt on this CPU */
extern void init_timer_interrupt(void);

/* Counter value at boot time */
extern uint64_t boot_count;

extern s_time_t ticks_to_ns(uint64_t ticks);
extern uint64_t ns_to_ticks(s_time_t ns);

void preinit_xen_time(void);

#endif /* __ARM_TIME_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
