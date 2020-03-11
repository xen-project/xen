/*
 * Read-Copy Update mechanism for mutual exclusion
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) IBM Corporation, 2001
 *
 * Authors: Dipankar Sarma <dipankar@in.ibm.com>
 *          Manfred Spraul <manfred@colorfullife.com>
 * 
 * Modifications for Xen: Jose Renato Santos
 * Copyright (C) Hewlett-Packard, 2006
 *
 * Based on the original work by Paul McKenney <paulmck@us.ibm.com>
 * and inputs from Rusty Russell, Andrea Arcangeli and Andi Kleen.
 * Papers:
 * http://www.rdrop.com/users/paulmck/paper/rclockpdcsproof.pdf
 * http://lse.sourceforge.net/locking/rclock_OLS.2001.05.01c.sc.pdf (OLS2001)
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 * http://lse.sourceforge.net/locking/rcupdate.html
 */
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/spinlock.h>
#include <xen/smp.h>
#include <xen/rcupdate.h>
#include <xen/sched.h>
#include <asm/atomic.h>
#include <xen/bitops.h>
#include <xen/percpu.h>
#include <xen/softirq.h>
#include <xen/cpu.h>
#include <xen/stop_machine.h>

/* Global control variables for rcupdate callback mechanism. */
static struct rcu_ctrlblk {
    long cur;           /* Current batch number.                      */
    long completed;     /* Number of the last completed batch         */
    int  next_pending;  /* Is the next batch already waiting?         */

    spinlock_t  lock __cacheline_aligned;
    cpumask_t   cpumask; /* CPUs that need to switch in order ... */
    cpumask_t   idle_cpumask; /* ... unless they are already idle */
    /* for current batch to proceed.        */
} __cacheline_aligned rcu_ctrlblk = {
    .cur = -300,
    .completed = -300,
    .lock = SPIN_LOCK_UNLOCKED,
};

/*
 * Per-CPU data for Read-Copy Update.
 * nxtlist - new callbacks are added here
 * curlist - current batch for which quiescent cycle started if any
 */
struct rcu_data {
    /* 1) quiescent state handling : */
    long quiescbatch;    /* Batch # for grace period */
    int  qs_pending;     /* core waits for quiesc state */

    /* 2) batch handling */
    long            batch;            /* Batch # for current RCU batch */
    struct rcu_head *nxtlist;
    struct rcu_head **nxttail;
    long            qlen;             /* # of queued callbacks */
    struct rcu_head *curlist;
    struct rcu_head **curtail;
    struct rcu_head *donelist;
    struct rcu_head **donetail;
    long            blimit;           /* Upper limit on a processed batch */
    int cpu;
    struct rcu_head barrier;
    long            last_rs_qlen;     /* qlen during the last resched */

    /* 3) idle CPUs handling */
    struct timer idle_timer;
    bool idle_timer_active;

    bool            process_callbacks;
};

/*
 * If a CPU with RCU callbacks queued goes idle, when the grace period is
 * not finished yet, how can we make sure that the callbacks will eventually
 * be executed? In Linux (2.6.21, the first "tickless idle" Linux kernel),
 * the periodic timer tick would not be stopped for such CPU. Here in Xen,
 * we (may) don't even have a periodic timer tick, so we need to use a
 * special purpose timer.
 *
 * Such timer:
 * 1) is armed only when a CPU with an RCU callback(s) queued goes idle
 *    before the end of the current grace period (_not_ for any CPUs that
 *    go idle!);
 * 2) when it fires, it is only re-armed if the grace period is still
 *    running;
 * 3) it is stopped immediately, if the CPU wakes up from idle and
 *    resumes 'normal' execution.
 *
 * About how far in the future the timer should be programmed each time,
 * it's hard to tell (guess!!). Since this mimics Linux's periodic timer
 * tick, take values used there as an indication. In Linux 2.6.21, tick
 * period can be 10ms, 4ms, 3.33ms or 1ms.
 *
 * By default, we use 10ms, to enable at least some power saving on the
 * CPU that is going idle. The user can change this, via a boot time
 * parameter, but only up to 100ms.
 */
#define IDLE_TIMER_PERIOD_MAX     MILLISECS(100)
#define IDLE_TIMER_PERIOD_DEFAULT MILLISECS(10)
#define IDLE_TIMER_PERIOD_MIN     MICROSECS(100)

static s_time_t __read_mostly idle_timer_period;

/*
 * Increment and decrement values for the idle timer handler. The algorithm
 * works as follows:
 * - if the timer actually fires, and it finds out that the grace period isn't
 *   over yet, we add IDLE_TIMER_PERIOD_INCR to the timer's period;
 * - if the timer actually fires and it finds the grace period over, we
 *   subtract IDLE_TIMER_PERIOD_DECR from the timer's period.
 */
#define IDLE_TIMER_PERIOD_INCR    MILLISECS(10)
#define IDLE_TIMER_PERIOD_DECR    MICROSECS(100)

static DEFINE_PER_CPU(struct rcu_data, rcu_data);

static int blimit = 10;
static int qhimark = 10000;
static int qlowmark = 100;
static int rsinterval = 1000;

struct rcu_barrier_data {
    struct rcu_head head;
    atomic_t *cpu_count;
};

static void rcu_barrier_callback(struct rcu_head *head)
{
    struct rcu_barrier_data *data = container_of(
        head, struct rcu_barrier_data, head);
    atomic_inc(data->cpu_count);
}

static int rcu_barrier_action(void *_cpu_count)
{
    struct rcu_barrier_data data = { .cpu_count = _cpu_count };

    ASSERT(!local_irq_is_enabled());
    local_irq_enable();

    /*
     * When callback is executed, all previously-queued RCU work on this CPU
     * is completed. When all CPUs have executed their callback, data.cpu_count
     * will have been incremented to include every online CPU.
     */
    call_rcu(&data.head, rcu_barrier_callback);

    while ( atomic_read(data.cpu_count) != num_online_cpus() )
    {
        process_pending_softirqs();
        cpu_relax();
    }

    local_irq_disable();

    return 0;
}

/*
 * As rcu_barrier() is using stop_machine_run() it is allowed to be used in
 * idle context only (see comment for stop_machine_run()).
 */
int rcu_barrier(void)
{
    atomic_t cpu_count = ATOMIC_INIT(0);
    return stop_machine_run(rcu_barrier_action, &cpu_count, NR_CPUS);
}

/* Is batch a before batch b ? */
static inline int rcu_batch_before(long a, long b)
{
    return (a - b) < 0;
}

static void force_quiescent_state(struct rcu_data *rdp,
                                  struct rcu_ctrlblk *rcp)
{
    cpumask_t cpumask;
    raise_softirq(RCU_SOFTIRQ);
    if (unlikely(rdp->qlen - rdp->last_rs_qlen > rsinterval)) {
        rdp->last_rs_qlen = rdp->qlen;
        /*
         * Don't send IPI to itself. With irqs disabled,
         * rdp->cpu is the current cpu.
         */
        cpumask_andnot(&cpumask, &rcp->cpumask, cpumask_of(rdp->cpu));
        cpumask_raise_softirq(&cpumask, RCU_SOFTIRQ);
    }
}

/**
 * call_rcu - Queue an RCU callback for invocation after a grace period.
 * @head: structure to be used for queueing the RCU updates.
 * @func: actual update function to be invoked after the grace period
 *
 * The update function will be invoked some time after a full grace
 * period elapses, in other words after all currently executing RCU
 * read-side critical sections have completed.  RCU read-side critical
 * sections are delimited by rcu_read_lock() and rcu_read_unlock(),
 * and may be nested.
 */
void call_rcu(struct rcu_head *head,
              void (*func)(struct rcu_head *rcu))
{
    unsigned long flags;
    struct rcu_data *rdp;

    head->func = func;
    head->next = NULL;
    local_irq_save(flags);
    rdp = &this_cpu(rcu_data);
    *rdp->nxttail = head;
    rdp->nxttail = &head->next;
    if (unlikely(++rdp->qlen > qhimark)) {
        rdp->blimit = INT_MAX;
        force_quiescent_state(rdp, &rcu_ctrlblk);
    }
    local_irq_restore(flags);
}

/*
 * Invoke the completed RCU callbacks. They are expected to be in
 * a per-cpu list.
 */
static void rcu_do_batch(struct rcu_data *rdp)
{
    struct rcu_head *next, *list;
    int count = 0;

    list = rdp->donelist;
    while (list) {
        next = rdp->donelist = list->next;
        list->func(list);
        list = next;
        rdp->qlen--;
        if (++count >= rdp->blimit)
            break;
    }
    if (rdp->blimit == INT_MAX && rdp->qlen <= qlowmark)
        rdp->blimit = blimit;
    if (!rdp->donelist)
        rdp->donetail = &rdp->donelist;
    else
    {
        rdp->process_callbacks = true;
        raise_softirq(RCU_SOFTIRQ);
    }
}

/*
 * Grace period handling:
 * The grace period handling consists out of two steps:
 * - A new grace period is started.
 *   This is done by rcu_start_batch. The start is not broadcasted to
 *   all cpus, they must pick this up by comparing rcp->cur with
 *   rdp->quiescbatch. All cpus are recorded  in the
 *   rcu_ctrlblk.cpumask bitmap.
 * - All cpus must go through a quiescent state.
 *   Since the start of the grace period is not broadcasted, at least two
 *   calls to rcu_check_quiescent_state are required:
 *   The first call just notices that a new grace period is running. The
 *   following calls check if there was a quiescent state since the beginning
 *   of the grace period. If so, it updates rcu_ctrlblk.cpumask. If
 *   the bitmap is empty, then the grace period is completed.
 *   rcu_check_quiescent_state calls rcu_start_batch(0) to start the next grace
 *   period (if necessary).
 */
/*
 * Register a new batch of callbacks, and start it up if there is currently no
 * active batch and the batch to be registered has not already occurred.
 * Caller must hold rcu_ctrlblk.lock.
 */
static void rcu_start_batch(struct rcu_ctrlblk *rcp)
{
    if (rcp->next_pending &&
        rcp->completed == rcp->cur) {
        rcp->next_pending = 0;
        /*
         * next_pending == 0 must be visible in
         * __rcu_process_callbacks() before it can see new value of cur.
         */
        smp_wmb();
        rcp->cur++;

       /*
        * Make sure the increment of rcp->cur is visible so, even if a
        * CPU that is about to go idle, is captured inside rcp->cpumask,
        * rcu_pending() will return false, which then means cpu_quiet()
        * will be invoked, before the CPU would actually enter idle.
        *
        * This barrier is paired with the one in rcu_idle_enter().
        */
        smp_mb();
        cpumask_andnot(&rcp->cpumask, &cpu_online_map, &rcp->idle_cpumask);
    }
}

/*
 * cpu went through a quiescent state since the beginning of the grace period.
 * Clear it from the cpu mask and complete the grace period if it was the last
 * cpu. Start another grace period if someone has further entries pending
 */
static void cpu_quiet(int cpu, struct rcu_ctrlblk *rcp)
{
    cpumask_clear_cpu(cpu, &rcp->cpumask);
    if (cpumask_empty(&rcp->cpumask)) {
        /* batch completed ! */
        rcp->completed = rcp->cur;
        rcu_start_batch(rcp);
    }
}

/*
 * Check if the cpu has gone through a quiescent state (say context
 * switch). If so and if it already hasn't done so in this RCU
 * quiescent cycle, then indicate that it has done so.
 */
static void rcu_check_quiescent_state(struct rcu_ctrlblk *rcp,
                                      struct rcu_data *rdp)
{
    if (rdp->quiescbatch != rcp->cur) {
        /* start new grace period: */
        rdp->qs_pending = 1;
        rdp->quiescbatch = rcp->cur;
        return;
    }

    /* Grace period already completed for this cpu?
     * qs_pending is checked instead of the actual bitmap to avoid
     * cacheline trashing.
     */
    if (!rdp->qs_pending)
        return;

    rdp->qs_pending = 0;

    spin_lock(&rcp->lock);
    /*
     * rdp->quiescbatch/rcp->cur and the cpu bitmap can come out of sync
     * during cpu startup. Ignore the quiescent state.
     */
    if (likely(rdp->quiescbatch == rcp->cur))
        cpu_quiet(rdp->cpu, rcp);

    spin_unlock(&rcp->lock);
}


/*
 * This does the RCU processing work from softirq context. 
 */
static void __rcu_process_callbacks(struct rcu_ctrlblk *rcp,
                                    struct rcu_data *rdp)
{
    if (rdp->curlist && !rcu_batch_before(rcp->completed, rdp->batch)) {
        *rdp->donetail = rdp->curlist;
        rdp->donetail = rdp->curtail;
        rdp->curlist = NULL;
        rdp->curtail = &rdp->curlist;
    }

    local_irq_disable();
    if (rdp->nxtlist && !rdp->curlist) {
        rdp->curlist = rdp->nxtlist;
        rdp->curtail = rdp->nxttail;
        rdp->nxtlist = NULL;
        rdp->nxttail = &rdp->nxtlist;
        local_irq_enable();

        /*
         * start the next batch of callbacks
         */

        /* determine batch number */
        rdp->batch = rcp->cur + 1;
        /* see the comment and corresponding wmb() in
         * the rcu_start_batch()
         */
        smp_rmb();

        if (!rcp->next_pending) {
            /* and start it/schedule start if it's a new batch */
            spin_lock(&rcp->lock);
            rcp->next_pending = 1;
            rcu_start_batch(rcp);
            spin_unlock(&rcp->lock);
        }
    } else {
        local_irq_enable();
    }
    rcu_check_quiescent_state(rcp, rdp);
    if (rdp->donelist)
        rcu_do_batch(rdp);
}

static void rcu_process_callbacks(void)
{
    struct rcu_data *rdp = &this_cpu(rcu_data);

    if ( rdp->process_callbacks )
    {
        rdp->process_callbacks = false;
        __rcu_process_callbacks(&rcu_ctrlblk, rdp);
    }
}

static int __rcu_pending(struct rcu_ctrlblk *rcp, struct rcu_data *rdp)
{
    /* This cpu has pending rcu entries and the grace period
     * for them has completed.
     */
    if (rdp->curlist && !rcu_batch_before(rcp->completed, rdp->batch))
        return 1;

    /* This cpu has no pending entries, but there are new entries */
    if (!rdp->curlist && rdp->nxtlist)
        return 1;

    /* This cpu has finished callbacks to invoke */
    if (rdp->donelist)
        return 1;

    /* The rcu core waits for a quiescent state from the cpu */
    if (rdp->quiescbatch != rcp->cur || rdp->qs_pending)
        return 1;

    /* nothing to do */
    return 0;
}

int rcu_pending(int cpu)
{
    return __rcu_pending(&rcu_ctrlblk, &per_cpu(rcu_data, cpu));
}

/*
 * Check to see if any future RCU-related work will need to be done
 * by the current CPU, even if none need be done immediately, returning
 * 1 if so.  This function is part of the RCU implementation; it is -not-
 * an exported member of the RCU API.
 */
int rcu_needs_cpu(int cpu)
{
    struct rcu_data *rdp = &per_cpu(rcu_data, cpu);

    return (rdp->curlist && !rdp->idle_timer_active) || rcu_pending(cpu);
}

/*
 * Timer for making sure the CPU where a callback is queued does
 * periodically poke rcu_pedning(), so that it will invoke the callback
 * not too late after the end of the grace period.
 */
static void rcu_idle_timer_start(void)
{
    struct rcu_data *rdp = &this_cpu(rcu_data);

    /*
     * Note that we don't check rcu_pending() here. In fact, we don't want
     * the timer armed on CPUs that are in the process of quiescing while
     * going idle, unless they really are the ones with a queued callback.
     */
    if (likely(!rdp->curlist))
        return;

    set_timer(&rdp->idle_timer, NOW() + idle_timer_period);
    rdp->idle_timer_active = true;
}

static void rcu_idle_timer_stop(void)
{
    struct rcu_data *rdp = &this_cpu(rcu_data);

    if (likely(!rdp->idle_timer_active))
        return;

    rdp->idle_timer_active = false;

    /*
     * In general, as the CPU is becoming active again, we don't need the
     * idle timer, and so we want to stop it.
     *
     * However, in case we are here because idle_timer has (just) fired and
     * has woken up the CPU, we skip stop_timer() now. In fact, when a CPU
     * wakes up from idle, this code always runs before do_softirq() has the
     * chance to check and deal with TIMER_SOFTIRQ. And if we stop the timer
     * now, the TIMER_SOFTIRQ handler will see it as inactive, and will not
     * call rcu_idle_timer_handler().
     *
     * Therefore, if we see that the timer is expired already, we leave it
     * alone. The TIMER_SOFTIRQ handler will then run the timer routine, and
     * deactivate it.
     */
    if ( !timer_is_expired(&rdp->idle_timer) )
        stop_timer(&rdp->idle_timer);
}

static void rcu_idle_timer_handler(void* data)
{
    perfc_incr(rcu_idle_timer);

    if ( !cpumask_empty(&rcu_ctrlblk.cpumask) )
        idle_timer_period = min(idle_timer_period + IDLE_TIMER_PERIOD_INCR,
                                IDLE_TIMER_PERIOD_MAX);
    else
        idle_timer_period = max(idle_timer_period - IDLE_TIMER_PERIOD_DECR,
                                IDLE_TIMER_PERIOD_MIN);
}

void rcu_check_callbacks(int cpu)
{
    struct rcu_data *rdp = &this_cpu(rcu_data);

    rdp->process_callbacks = true;
    raise_softirq(RCU_SOFTIRQ);
}

static void rcu_move_batch(struct rcu_data *this_rdp, struct rcu_head *list,
                           struct rcu_head **tail)
{
    local_irq_disable();
    *this_rdp->nxttail = list;
    if (list)
        this_rdp->nxttail = tail;
    local_irq_enable();
}

static void rcu_offline_cpu(struct rcu_data *this_rdp,
                            struct rcu_ctrlblk *rcp, struct rcu_data *rdp)
{
    kill_timer(&rdp->idle_timer);

    /* If the cpu going offline owns the grace period we can block
     * indefinitely waiting for it, so flush it here.
     */
    spin_lock(&rcp->lock);
    if (rcp->cur != rcp->completed)
        cpu_quiet(rdp->cpu, rcp);
    spin_unlock(&rcp->lock);

    rcu_move_batch(this_rdp, rdp->donelist, rdp->donetail);
    rcu_move_batch(this_rdp, rdp->curlist, rdp->curtail);
    rcu_move_batch(this_rdp, rdp->nxtlist, rdp->nxttail);

    local_irq_disable();
    this_rdp->qlen += rdp->qlen;
    local_irq_enable();
}

static void rcu_init_percpu_data(int cpu, struct rcu_ctrlblk *rcp,
                                 struct rcu_data *rdp)
{
    memset(rdp, 0, sizeof(*rdp));
    rdp->curtail = &rdp->curlist;
    rdp->nxttail = &rdp->nxtlist;
    rdp->donetail = &rdp->donelist;
    rdp->quiescbatch = rcp->completed;
    rdp->qs_pending = 0;
    rdp->cpu = cpu;
    rdp->blimit = blimit;
    init_timer(&rdp->idle_timer, rcu_idle_timer_handler, rdp, cpu);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    struct rcu_data *rdp = &per_cpu(rcu_data, cpu);

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rcu_init_percpu_data(cpu, &rcu_ctrlblk, rdp);
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        rcu_offline_cpu(&this_cpu(rcu_data), &rcu_ctrlblk, rdp);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

void __init rcu_init(void)
{
    void *cpu = (void *)(long)smp_processor_id();
    static unsigned int __initdata idle_timer_period_ms =
                                    IDLE_TIMER_PERIOD_DEFAULT / MILLISECS(1);
    integer_param("rcu-idle-timer-period-ms", idle_timer_period_ms);

    /* We don't allow 0, or anything higher than IDLE_TIMER_PERIOD_MAX */
    if ( idle_timer_period_ms == 0 ||
         idle_timer_period_ms > IDLE_TIMER_PERIOD_MAX / MILLISECS(1) )
    {
        idle_timer_period_ms = IDLE_TIMER_PERIOD_DEFAULT / MILLISECS(1);
        printk("WARNING: rcu-idle-timer-period-ms outside of "
               "(0,%"PRI_stime"]. Resetting it to %u.\n",
               IDLE_TIMER_PERIOD_MAX / MILLISECS(1), idle_timer_period_ms);
    }
    idle_timer_period = MILLISECS(idle_timer_period_ms);

    cpumask_clear(&rcu_ctrlblk.idle_cpumask);
    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);
    register_cpu_notifier(&cpu_nfb);
    open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
}

/*
 * The CPU is becoming idle, so no more read side critical
 * sections, and one more step toward grace period.
 */
void rcu_idle_enter(unsigned int cpu)
{
    ASSERT(!cpumask_test_cpu(cpu, &rcu_ctrlblk.idle_cpumask));
    cpumask_set_cpu(cpu, &rcu_ctrlblk.idle_cpumask);
    /*
     * If some other CPU is starting a new grace period, we'll notice that
     * by seeing a new value in rcp->cur (different than our quiescbatch).
     * That will force us all the way until cpu_quiet(), clearing our bit
     * in rcp->cpumask, even in case we managed to get in there.
     *
     * Se the comment before cpumask_andnot() in  rcu_start_batch().
     */
    smp_mb();

    rcu_idle_timer_start();
}

void rcu_idle_exit(unsigned int cpu)
{
    rcu_idle_timer_stop();
    ASSERT(cpumask_test_cpu(cpu, &rcu_ctrlblk.idle_cpumask));
    cpumask_clear_cpu(cpu, &rcu_ctrlblk.idle_cpumask);
}
