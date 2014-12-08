#ifndef __ASM_ARM32_SPINLOCK_H
#define __ASM_ARM32_SPINLOCK_H

static inline void dsb_sev(void)
{
    __asm__ __volatile__ (
        "dsb\n"
        "sev\n"
        );
}

typedef struct {
    volatile unsigned int lock;
} raw_spinlock_t;

#define _RAW_SPIN_LOCK_UNLOCKED { 0 }

#define _raw_spin_is_locked(x)          ((x)->lock != 0)

static always_inline void _raw_spin_unlock(raw_spinlock_t *lock)
{
    ASSERT(_raw_spin_is_locked(lock));

    smp_mb();

    __asm__ __volatile__(
"   str     %1, [%0]\n"
    :
    : "r" (&lock->lock), "r" (0)
    : "cc");

    dsb_sev();
}

static always_inline int _raw_spin_trylock(raw_spinlock_t *lock)
{
    unsigned long contended, res;

    do {
        __asm__ __volatile__(
    "   ldrex   %0, [%2]\n"
    "   teq     %0, #0\n"
    "   strexeq %1, %3, [%2]\n"
    "   movne   %1, #0\n"
        : "=&r" (contended), "=r" (res)
        : "r" (&lock->lock), "r" (1)
        : "cc");
    } while (res);

    if (!contended) {
        smp_mb();
        return 1;
    } else {
        return 0;
    }
}

#endif /* __ASM_SPINLOCK_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
