#ifndef __ASM_RISCV_SPINLOCK_H
#define __ASM_RISCV_SPINLOCK_H

#define arch_lock_acquire_barrier() smp_mb()
#define arch_lock_release_barrier() smp_mb()

#define arch_lock_relax() cpu_relax()
#define arch_lock_signal() ((void)0)
#define arch_lock_signal_wmb()      \
({                                  \
    smp_wmb();                      \
    arch_lock_signal();             \
})

#endif /* __ASM_RISCV_SPINLOCK_H */
