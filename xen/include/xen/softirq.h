#ifndef __XEN_SOFTIRQ_H__
#define __XEN_SOFTIRQ_H__

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <asm/bitops.h>
#include <asm/hardirq.h>

enum
{
    AC_TIMER_SOFTIRQ=0,
    NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ,
    SCHEDULE_SOFTIRQ, /* NB. This must come last or do_softirq() will break! */
    NR_SOFTIRQS
};

typedef void (*softirq_handler)(void);

asmlinkage void do_softirq(void);
extern void open_softirq(int nr, softirq_handler handler);

static inline void cpu_raise_softirq(unsigned int cpu, unsigned int nr)
{
    if ( !test_and_set_bit(nr, &softirq_pending(cpu)) )
        smp_send_event_check_cpu(cpu);
}

static inline void raise_softirq(unsigned int nr)
{
    set_bit(nr, &softirq_pending(smp_processor_id()));
}

#endif /* __XEN_SOFTIRQ_H__ */
