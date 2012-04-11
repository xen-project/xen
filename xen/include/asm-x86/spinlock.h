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

typedef struct {
    volatile int lock;
} raw_rwlock_t;

#define RW_WRITE_BIAS 0x7fffffff
#define _RAW_RW_LOCK_UNLOCKED /*(raw_rwlock_t)*/ { 0 }

static always_inline int _raw_read_trylock(raw_rwlock_t *rw)
{
    int acquired;

    asm volatile (
        "    lock; decl %0         \n"
        "    jns 2f                \n"
#ifdef __clang__ /* clang's builtin assember can't do .subsection */
        "1:  .pushsection .fixup,\"ax\"\n"
#else
        "1:  .subsection 1         \n"
#endif
        "2:  lock; incl %0         \n"
        "    decl %1               \n"
        "    jmp 1b                \n"
#ifdef __clang__
        "    .popsection           \n"
#else
        "    .subsection 0         \n"
#endif
        : "=m" (rw->lock), "=r" (acquired) : "1" (1) : "memory" );

    return acquired;
}

static always_inline int _raw_write_trylock(raw_rwlock_t *rw)
{
    return (cmpxchg(&rw->lock, 0, RW_WRITE_BIAS) == 0);
}

static always_inline void _raw_read_unlock(raw_rwlock_t *rw)
{
    asm volatile (
        "lock ; incl %0"
        : "=m" ((rw)->lock) : : "memory" );
}

static always_inline void _raw_write_unlock(raw_rwlock_t *rw)
{
    asm volatile (
        "lock ; subl %1,%0"
        : "=m" ((rw)->lock) : "i" (RW_WRITE_BIAS) : "memory" );
}

#define _raw_rw_is_locked(x) ((x)->lock != 0)
#define _raw_rw_is_write_locked(x) ((x)->lock > 0)

#endif /* __ASM_SPINLOCK_H */
