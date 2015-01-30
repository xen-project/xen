#ifndef __ARCH_ASM_SPINLOCK_H
#define __ARCH_ASM_SPINLOCK_H

#include "os.h"

#define ARCH_SPIN_LOCK_UNLOCKED { 1 }

/*
 * Simple spin lock operations.  There are two variants, one clears IRQ's
 * on the local processor, one does not.
 *
 * We make no fairness assumptions. They have a cost.
 */

#define arch_spin_is_locked(x)    (*(volatile signed char *)(&(x)->slock) <= 0)
#define arch_spin_unlock_wait(x) do { barrier(); } while(spin_is_locked(x))

static inline void _raw_spin_unlock(spinlock_t *lock)
{
    xchg(&lock->slock, 1);
}

static inline int _raw_spin_trylock(spinlock_t *lock)
{
    return xchg(&lock->slock, 0) != 0 ? 1 : 0;
}

static inline void _raw_spin_lock(spinlock_t *lock)
{
    volatile int was_locked;
    do {
        was_locked = xchg(&lock->slock, 0) == 0 ? 1 : 0;
    } while(was_locked);
}

#endif
