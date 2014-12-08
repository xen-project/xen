#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <xen/config.h>
#include <xen/lib.h>
#include <asm/atomic.h>

typedef struct {
    volatile s16 lock;
} raw_spinlock_t;

#define _RAW_SPIN_LOCK_UNLOCKED /*(raw_spinlock_t)*/ { 1 }

#define _raw_spin_is_locked(x) ((x)->lock <= 0)

static always_inline void _raw_spin_unlock(raw_spinlock_t *lock)
{
    ASSERT(_raw_spin_is_locked(lock));
    asm volatile (
        "movw $1,%0" 
        : "=m" (lock->lock) : : "memory" );
}

static always_inline int _raw_spin_trylock(raw_spinlock_t *lock)
{
    s16 oldval;
    asm volatile (
        "xchgw %w0,%1"
        :"=r" (oldval), "=m" (lock->lock)
        :"0" ((s16)0) : "memory" );
    return (oldval > 0);
}

#endif /* __ASM_SPINLOCK_H */
