/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_SPINLOCK_H
#define _ASM_SPINLOCK_H

#include <xen/types.h>
#include <xen/smp.h>
#include <asm/atomic.h>

static inline void
sync_after_acquire(void)
{
    __asm__ __volatile__ ("isync" : : : "memory");
}

static inline void
sync_before_release(void)
{
    __asm__ __volatile__ ("sync" : : : "memory");
}

/*
 * CAS : Compare and Store 32bits.. works for everyone
 *
 * NOTE:  The ptr parameters to these routines are cast to character pointers
 *        in order to prevent any strict-aliasing optimizations the compiler
 *        might otherwise attempt.
 */
static inline u32
cas_u32(volatile u32 *ptr, u32 oval, u32 nval)
{
    u32 tmp;

    sync_before_release();
    __asm__ ("\n"
            "# cas_u32                                          \n"
            "1: lwarx   %1,0,%4 # tmp = (*ptr)  [linked]        \n"
            "   cmplw   %1,%2   # if (tmp != oval)              \n"
            "   bne-    2f      #     goto failure              \n"
            "   stwcx.  %3,0,%4 # (*ptr) = nval [conditional]   \n"
            "   bne-    1b      # if (store failed) retry       \n"
            "   li      %1,1    # tmp = SUCCESS                 \n"
            "   b       $+8     # goto end                      \n"
            "2: li      %1,0    # tmp = FAILURE                 \n"
            "# end cas_u32                                      \n"
            : "=m" (*(volatile char *)ptr), "=&r" (tmp)
            : "r" (oval), "r" (nval), "r" (ptr), "m" (*(volatile char*)ptr)
            : "cc"
            );
    sync_after_acquire();

    return tmp;
}

typedef struct {
    volatile u32 lock;
    s16 recurse_cpu;
    u16 recurse_cnt;
} spinlock_t;

#define __UNLOCKED (0U)
#define __LOCKED (~__UNLOCKED)
#define SPIN_LOCK_UNLOCKED /*(spinlock_t)*/ { __UNLOCKED, -1, 0 }
static inline void spin_lock_init(spinlock_t *lock)
{
    *lock = (spinlock_t) SPIN_LOCK_UNLOCKED;
}

static inline int spin_is_locked(spinlock_t *lock)
{
    return lock->lock != __UNLOCKED;
}

static inline void _raw_spin_lock(spinlock_t *lock)
{
    while (!cas_u32(&lock->lock, __UNLOCKED, __LOCKED)) {
        continue;
    }
    sync_after_acquire();
}

static inline void _raw_spin_unlock(spinlock_t *lock)
{
    sync_before_release();
    *lock = (spinlock_t) SPIN_LOCK_UNLOCKED;
}

static inline int _raw_spin_trylock(spinlock_t *lock)
{
    int ret = 0;

    if (cas_u32(&lock->lock, __UNLOCKED, __LOCKED)) {
        ret = 1;
    }
    sync_after_acquire();
    return ret;
}

typedef struct {
    volatile unsigned int lock;
} rwlock_t;

#define RW_LOCK_UNLOCKED /*(rwlock_t)*/ { __UNLOCKED }
static inline void rwlock_init(rwlock_t *lock)
{
    *lock = (rwlock_t) RW_LOCK_UNLOCKED;
}

static inline void _raw_read_lock(rwlock_t *lock)
{
    u32 val;

    /* Lock is acquired if we can increment lower 31 bits, while
     * uppermost bit is 0. */
    do {
        val = lock->lock & ((1UL << 31) - 1);
    } while (!cas_u32(&lock->lock, val, val + 1));
    sync_after_acquire();
}

static inline void _raw_write_lock(rwlock_t *lock)
{
    /* Lock is acquired if we can set 32nd bit, while all other
     * bits are 0 */
    while (!cas_u32(&lock->lock, 0, 1 << 31)) {
        continue;
    }
    sync_after_acquire();
}

static inline void _raw_write_unlock(rwlock_t *lock)
{
    sync_before_release();
    *lock = (rwlock_t) RW_LOCK_UNLOCKED;
}

static inline void _raw_read_unlock(rwlock_t *lock)
{
    u32 val;

    /* We want to decrement the low-order 31-bits atomically */
    sync_before_release();
    do {
        val = lock->lock;
    } while (!cas_u32(&lock->lock, val, val - 1));

    /* necessary? */
    sync_after_acquire();
}

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */

#if 0
static inline void _raw_spin_unlock_recursive(spinlock_t *lock)
{
    int cpu = smp_processor_id();
    if (likely(lock->recurse_cpu != cpu)) {
        spin_lock(lock);
        lock->recurse_cpu = cpu;
    }
    lock->recurse_cnt++;
}

static inline void _raw_spin_unlock_recursive(spinlock_t *lock)
{
    if (likely(--lock->recurse_cnt == 0)) {
        lock->recurse_cpu = -1;
        spin_unlock(lock);
    }
}
#else

#define _raw_spin_lock_recursive(_lock)            \
    do {                                           \
        int cpu = smp_processor_id();              \
        if ( likely((_lock)->recurse_cpu != cpu) ) \
        {                                          \
            spin_lock(_lock);                      \
            (_lock)->recurse_cpu = cpu;            \
        }                                          \
        (_lock)->recurse_cnt++;                    \
    } while ( 0 )

#define _raw_spin_unlock_recursive(_lock)          \
    do {                                           \
        if ( likely(--(_lock)->recurse_cnt == 0) ) \
        {                                          \
            (_lock)->recurse_cpu = -1;             \
            spin_unlock(_lock);                    \
        }                                          \
    } while ( 0 )
#endif

#endif
