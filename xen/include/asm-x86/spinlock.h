#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <xen/config.h>
#include <xen/lib.h>
#include <asm/atomic.h>
#include <asm/rwlock.h>

typedef struct {
    volatile s16 lock;
    s8 recurse_cpu;
    u8 recurse_cnt;
} spinlock_t;

#define SPIN_LOCK_UNLOCKED (spinlock_t) { 1, -1, 0 }

#define spin_lock_init(x)	do { *(x) = SPIN_LOCK_UNLOCKED; } while(0)
#define spin_is_locked(x)	(*(volatile char *)(&(x)->lock) <= 0)

static inline void _raw_spin_lock(spinlock_t *lock)
{
    __asm__ __volatile__ (
        "1:  lock; decb %0         \n"
        "    js 2f                 \n"
        ".section .text.lock,\"ax\"\n"
        "2:  cmpb $0,%0            \n"
        "    rep; nop              \n"
        "    jle 2b                \n"
        "    jmp 1b                \n"
        ".previous"
        : "=m" (lock->lock) : : "memory" );
}

static inline void _raw_spin_unlock(spinlock_t *lock)
{
#if !defined(CONFIG_X86_OOSTORE)
    ASSERT(spin_is_locked(lock));
    __asm__ __volatile__ (
	"movb $1,%0" 
        : "=m" (lock->lock) : : "memory" );
#else
    char oldval = 1;
    ASSERT(spin_is_locked(lock));
    __asm__ __volatile__ (
	"xchgb %b0, %1"
        : "=q" (oldval), "=m" (lock->lock) : "0" (oldval) : "memory" );
#endif
}

static inline int _raw_spin_trylock(spinlock_t *lock)
{
    char oldval;
    __asm__ __volatile__(
        "xchgb %b0,%1"
        :"=q" (oldval), "=m" (lock->lock)
        :"0" (0) : "memory");
    return oldval > 0;
}

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */
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


typedef struct {
    volatile unsigned int lock;
} rwlock_t;

#define RW_LOCK_UNLOCKED (rwlock_t) { RW_LOCK_BIAS }

#define rwlock_init(x)	do { *(x) = RW_LOCK_UNLOCKED; } while(0)

/*
 * On x86, we implement read-write locks as a 32-bit counter
 * with the high bit (sign) being the "contended" bit.
 */
static inline void _raw_read_lock(rwlock_t *rw)
{
    __build_read_lock(rw, "__read_lock_failed");
}

static inline void _raw_write_lock(rwlock_t *rw)
{
    __build_write_lock(rw, "__write_lock_failed");
}

#define _raw_read_unlock(rw)                       \
    __asm__ __volatile__ (                         \
        "lock ; incl %0" :                         \
        "=m" ((rw)->lock) : : "memory" )
#define _raw_write_unlock(rw)                      \
    __asm__ __volatile__ (                         \
        "lock ; addl $" RW_LOCK_BIAS_STR ",%0" :   \
        "=m" ((rw)->lock) : : "memory" )

#endif /* __ASM_SPINLOCK_H */
