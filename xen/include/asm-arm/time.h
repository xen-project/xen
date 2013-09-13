#ifndef __ARM_TIME_H__
#define __ARM_TIME_H__

#define DT_MATCH_TIMER                      \
    DT_MATCH_COMPATIBLE("arm,armv7-timer"), \
    DT_MATCH_COMPATIBLE("arm,armv8-timer")

typedef unsigned long cycles_t;

static inline cycles_t get_cycles (void)
{
        return 0;
}

struct tm;
struct tm wallclock_time(void);

/* List of timer's IRQ */
enum timer_ppi
{
    TIMER_PHYS_SECURE_PPI = 0,
    TIMER_PHYS_NONSECURE_PPI = 1,
    TIMER_VIRT_PPI = 2,
    TIMER_HYP_PPI = 3,
    MAX_TIMER_PPI = 4,
};

/* Get one of the timer IRQ description */
const struct dt_irq* timer_dt_irq(enum timer_ppi ppi);

/* Route timer's IRQ on this CPU */
extern void __cpuinit route_timer_interrupt(void);

/* Set up the timer interrupt on this CPU */
extern void __cpuinit init_timer_interrupt(void);

/* Counter value at boot time */
extern uint64_t boot_count;

#endif /* __ARM_TIME_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
