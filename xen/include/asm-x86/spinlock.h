#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <xen/config.h>
#include <xen/lib.h>
#include <asm/atomic.h>
#include <asm/rwlock.h>

typedef struct {
    volatile s16 lock;
} raw_spinlock_t;

#define _RAW_SPIN_LOCK_UNLOCKED /*(raw_spinlock_t)*/ { 1 }

#define _raw_spin_is_locked(x)                  \
    (*(volatile char *)(&(x)->lock) <= 0)

static inline void _raw_spin_lock(raw_spinlock_t *lock)
{
    asm volatile (
        "1:  lock; decb %0         \n"
        "    js 2f                 \n"
        ".section .text.lock,\"ax\"\n"
        "2:  rep; nop              \n"
        "    cmpb $0,%0            \n"
        "    jle 2b                \n"
        "    jmp 1b                \n"
        ".previous"
        : "=m" (lock->lock) : : "memory" );
}

static inline void _raw_spin_unlock(raw_spinlock_t *lock)
{
    ASSERT(_raw_spin_is_locked(lock));
    asm volatile (
        "movb $1,%0" 
        : "=m" (lock->lock) : : "memory" );
}

static inline int _raw_spin_trylock(raw_spinlock_t *lock)
{
    char oldval;
    asm volatile (
        "xchgb %b0,%1"
        :"=q" (oldval), "=m" (lock->lock)
        :"0" (0) : "memory" );
    return (oldval > 0);
}

typedef struct {
    volatile unsigned int lock;
} raw_rwlock_t;

#define _RAW_RW_LOCK_UNLOCKED /*(raw_rwlock_t)*/ { RW_LOCK_BIAS }

/*
 * On x86, we implement read-write locks as a 32-bit counter
 * with the high bit (sign) being the "contended" bit.
 */
static inline void _raw_read_lock(raw_rwlock_t *rw)
{
    __build_read_lock(rw, "__read_lock_failed");
}

static inline void _raw_write_lock(raw_rwlock_t *rw)
{
    __build_write_lock(rw, "__write_lock_failed");
}

#define _raw_read_unlock(rw)                    \
    asm volatile (                              \
        "lock ; incl %0" :                      \
        "=m" ((rw)->lock) : : "memory" )
#define _raw_write_unlock(rw)                           \
    asm volatile (                                      \
        "lock ; addl $" RW_LOCK_BIAS_STR ",%0" :        \
        "=m" ((rw)->lock) : : "memory" )

#endif /* __ASM_SPINLOCK_H */
