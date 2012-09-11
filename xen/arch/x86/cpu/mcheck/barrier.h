#ifndef _MCHECK_BARRIER_H
#define _MCHECK_BARRIER_H

#include <asm/atomic.h>

/* MCE handling */
struct mce_softirq_barrier {
    atomic_t val;
    atomic_t ingen;
    atomic_t outgen;
};

/*
 * Initialize a barrier. Just set it to 0.
 */
void mce_barrier_init(struct mce_softirq_barrier *);

/*
 * This function will need to be used when offlining a CPU in the
 * recovery actions.
 *
 * Decrement a barrier only. Needed for cases where the CPU
 * in question can't do it itself (e.g. it is being offlined).
 */
void mce_barrier_dec(struct mce_softirq_barrier *);

/*
 * Increment the generation number and the value. The generation number
 * is incremented when entering a barrier. This way, it can be checked
 * on exit if a CPU is trying to re-enter the barrier. This can happen
 * if the first CPU to make it out immediately exits or re-enters, while
 * another CPU that is still in the loop becomes otherwise occupied
 * (e.g. it needs to service an interrupt, etc), missing the value
 * it's waiting for.
 *
 * These barrier functions should always be paired, so that the
 * counter value will reach 0 again after all CPUs have exited.
 */
void mce_barrier_enter(struct mce_softirq_barrier *);
void mce_barrier_exit(struct mce_softirq_barrier *);

void mce_barrier(struct mce_softirq_barrier *);

#endif /* _MCHECK_BARRIER_H */
