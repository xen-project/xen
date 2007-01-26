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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
#include <xen/spinlock.h>
#include <xen/smp.h>
#include <xen/rcupdate.h>
#include <xen/sched.h>
#include <asm/atomic.h>
#include <xen/bitops.h>
#include <xen/percpu.h>
#include <xen/softirq.h>

/* Definition for rcupdate control block. */
struct rcu_ctrlblk rcu_ctrlblk = {
    .cur = -300,
    .completed = -300,
    .lock = SPIN_LOCK_UNLOCKED,
    .cpumask = CPU_MASK_NONE,
};

DEFINE_PER_CPU(struct rcu_data, rcu_data) = { 0L };

static int blimit = 10;
static int qhimark = 10000;
static int qlowmark = 100;
static int rsinterval = 1000;

static void force_quiescent_state(struct rcu_data *rdp,
                                  struct rcu_ctrlblk *rcp)
{
    cpumask_t cpumask;
    raise_softirq(SCHEDULE_SOFTIRQ);
    if (unlikely(rdp->qlen - rdp->last_rs_qlen > rsinterval)) {
        rdp->last_rs_qlen = rdp->qlen;
        /*
         * Don't send IPI to itself. With irqs disabled,
         * rdp->cpu is the current cpu.
         */
        cpumask = rcp->cpumask;
        cpu_clear(rdp->cpu, cpumask);
        cpumask_raise_softirq(cpumask, SCHEDULE_SOFTIRQ);
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
void fastcall call_rcu(struct rcu_head *head,
                       void (*func)(struct rcu_head *rcu))
{
    unsigned long flags;
    struct rcu_data *rdp;

    head->func = func;
    head->next = NULL;
    local_irq_save(flags);
    rdp = &__get_cpu_var(rcu_data);
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
        raise_softirq(RCU_SOFTIRQ);
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

        rcp->cpumask = cpu_online_map;
    }
}

/*
 * cpu went through a quiescent state since the beginning of the grace period.
 * Clear it from the cpu mask and complete the grace period if it was the last
 * cpu. Start another grace period if someone has further entries pending
 */
static void cpu_quiet(int cpu, struct rcu_ctrlblk *rcp)
{
    cpu_clear(cpu, rcp->cpumask);
    if (cpus_empty(rcp->cpumask)) {
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
    __rcu_process_callbacks(&rcu_ctrlblk, &__get_cpu_var(rcu_data));
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

    return (!!rdp->curlist || rcu_pending(cpu));
}

void rcu_check_callbacks(int cpu)
{
    raise_softirq(RCU_SOFTIRQ);
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
}

void __devinit rcu_online_cpu(int cpu)
{
    struct rcu_data *rdp = &per_cpu(rcu_data, cpu);

    rcu_init_percpu_data(cpu, &rcu_ctrlblk, rdp);
}

void rcu_init(void)
{
    rcu_online_cpu(smp_processor_id());
    open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
}
