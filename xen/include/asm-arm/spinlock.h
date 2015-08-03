#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#define arch_lock_acquire_barrier() smp_mb()
#define arch_lock_release_barrier() smp_mb()

#define arch_lock_relax() wfe()
#define arch_lock_signal() do { \
    dsb(ishst);                 \
    sev();                      \
} while(0)

#endif /* __ASM_SPINLOCK_H */
