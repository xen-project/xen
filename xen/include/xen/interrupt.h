#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/cache.h>

#include <asm/bitops.h>
#include <asm/atomic.h>
#include <asm/ptrace.h>

struct irqaction {
    void (*handler)(int, void *, struct pt_regs *);
    unsigned long flags;
    unsigned long mask;
    const char *name;
    void *dev_id;
    struct irqaction *next;
};

#include <asm/hardirq.h>
#include <asm/softirq.h>

enum
{
    HI_SOFTIRQ=0,
    AC_TIMER_SOFTIRQ,
    TASKLET_SOFTIRQ,
    NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ
};

/* softirq mask and active fields moved to irq_cpustat_t in
 * asm/hardirq.h to get better cache usage.  KAO
 */

struct softirq_action
{
    void (*action)(struct softirq_action *);
    void *data;
};

asmlinkage void do_softirq(void);
extern void open_softirq(int nr, void (*action)(struct softirq_action*), void *data);
extern void softirq_init(void);
#define __cpu_raise_softirq(cpu, nr) set_bit(nr, &softirq_pending(cpu))
extern void FASTCALL(cpu_raise_softirq(unsigned int cpu, unsigned int nr));
extern void FASTCALL(raise_softirq(unsigned int nr));

/* Tasklets --- multithreaded analogue of BHs.

   Main feature differing them of generic softirqs: tasklet
   is running only on one CPU simultaneously.

   Main feature differing them of BHs: different tasklets
   may be run simultaneously on different CPUs.

   Properties:
   * If tasklet_schedule() is called, then tasklet is guaranteed
     to be executed on some cpu at least once after this.
   * If the tasklet is already scheduled, but its excecution is still not
     started, it will be executed only once.
   * If this tasklet is already running on another CPU (or schedule is called
     from tasklet itself), it is rescheduled for later.
   * Tasklet is strictly serialized wrt itself, but not
     wrt another tasklets. If client needs some intertask synchronization,
     he makes it with spinlocks.
 */

struct tasklet_struct
{
    struct tasklet_struct *next;
    unsigned long state;
    atomic_t count;
    void (*func)(unsigned long);
    unsigned long data;
};

#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }


enum
{
    TASKLET_STATE_SCHED,	/* Tasklet is scheduled for execution */
    TASKLET_STATE_RUN	/* Tasklet is running (SMP only) */
};

struct tasklet_head
{
    struct tasklet_struct *list;
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));

extern struct tasklet_head tasklet_vec[NR_CPUS];
extern struct tasklet_head tasklet_hi_vec[NR_CPUS];

#ifdef CONFIG_SMP
static inline int tasklet_trylock(struct tasklet_struct *t)
{
    return !test_and_set_bit(TASKLET_STATE_RUN, &(t)->state);
}

static inline void tasklet_unlock(struct tasklet_struct *t)
{
    smp_mb__before_clear_bit(); 
    clear_bit(TASKLET_STATE_RUN, &(t)->state);
}

static inline void tasklet_unlock_wait(struct tasklet_struct *t)
{
    while (test_bit(TASKLET_STATE_RUN, &(t)->state)) { barrier(); }
}
#else
#define tasklet_trylock(t) 1
#define tasklet_unlock_wait(t) do { } while (0)
#define tasklet_unlock(t) do { } while (0)
#endif

extern void FASTCALL(__tasklet_schedule(struct tasklet_struct *t));

static inline void tasklet_schedule(struct tasklet_struct *t)
{
    if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
        __tasklet_schedule(t);
}

extern void FASTCALL(__tasklet_hi_schedule(struct tasklet_struct *t));

static inline void tasklet_hi_schedule(struct tasklet_struct *t)
{
    if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
        __tasklet_hi_schedule(t);
}


static inline void tasklet_disable_nosync(struct tasklet_struct *t)
{
    atomic_inc(&t->count);
    smp_mb__after_atomic_inc();
}

static inline void tasklet_disable(struct tasklet_struct *t)
{
    tasklet_disable_nosync(t);
    tasklet_unlock_wait(t);
    smp_mb();
}

static inline void tasklet_enable(struct tasklet_struct *t)
{
    smp_mb__before_atomic_dec();
    if (atomic_dec_and_test(&t->count) &&
        test_bit(TASKLET_STATE_SCHED, &t->state))
        __tasklet_schedule(t);
}

static inline void tasklet_hi_enable(struct tasklet_struct *t)
{
    smp_mb__before_atomic_dec();
    if (atomic_dec_and_test(&t->count) &&
        test_bit(TASKLET_STATE_SCHED, &t->state))
        __tasklet_hi_schedule(t);
}

extern void tasklet_kill(struct tasklet_struct *t);
extern void tasklet_init(struct tasklet_struct *t,
			 void (*func)(unsigned long), unsigned long data);

#endif
