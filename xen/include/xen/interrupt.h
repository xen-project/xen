#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/cache.h>

#include <asm/bitops.h>
#include <asm/atomic.h>
#include <asm/ptrace.h>

struct irqaction
{
    void (*handler)(int, void *, struct pt_regs *);
    const char *name;
    void *dev_id;
};

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
#define __cpu_raise_softirq(cpu, nr) set_bit(nr, &softirq_pending(cpu))
extern void FASTCALL(cpu_raise_softirq(unsigned int cpu, unsigned int nr));
extern void FASTCALL(raise_softirq(unsigned int nr));

#endif
