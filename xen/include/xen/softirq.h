#if !defined(__XEN_SOFTIRQ_H__) && !defined(__ASSEMBLY__)
#define __XEN_SOFTIRQ_H__

/* Low-latency softirqs come first in the following list. */
enum {
    TIMER_SOFTIRQ = 0,
    SCHEDULE_SOFTIRQ,
    NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ,
    PAGE_SCRUB_SOFTIRQ,
    RCU_SOFTIRQ,
    STOPMACHINE_SOFTIRQ,
    TASKLET_SOFTIRQ,
    NR_COMMON_SOFTIRQS
};

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <asm/bitops.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <asm/softirq.h>

#define NR_SOFTIRQS (NR_COMMON_SOFTIRQS + NR_ARCH_SOFTIRQS)

typedef void (*softirq_handler)(void);

asmlinkage void do_softirq(void);
void open_softirq(int nr, softirq_handler handler);
void softirq_init(void);

static inline void cpumask_raise_softirq(cpumask_t mask, unsigned int nr)
{
    int cpu;

    for_each_cpu_mask(cpu, mask)
    {
        if ( test_and_set_bit(nr, &softirq_pending(cpu)) )
            cpu_clear(cpu, mask);
    }

    smp_send_event_check_mask(mask);
}

static inline void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    if ( !test_and_set_bit(nr, &softirq_pending(cpu)) )
        smp_send_event_check_cpu(cpu);
}

static inline void raise_softirq(unsigned int nr)
{
    set_bit(nr, &softirq_pending(smp_processor_id()));
}

/*
 * TASKLETS -- dynamically-allocatable tasks run in softirq context
 * on at most one CPU at a time.
 */
struct tasklet
{
    struct tasklet *next;
    bool_t is_scheduled;
    bool_t is_running;
    void (*func)(unsigned long);
    unsigned long data;
};

#define DECLARE_TASKLET(name, func, data) \
    struct tasklet name = { NULL, 0, 0, func, data }

void tasklet_schedule(struct tasklet *t);
void tasklet_kill(struct tasklet *t);
void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data);

#endif /* __XEN_SOFTIRQ_H__ */
