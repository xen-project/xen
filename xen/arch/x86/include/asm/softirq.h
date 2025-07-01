#ifndef __ASM_SOFTIRQ_H__
#define __ASM_SOFTIRQ_H__

#include <asm/system.h>

#define NMI_SOFTIRQ            (NR_COMMON_SOFTIRQS + 0)
#define TIME_CALIBRATE_SOFTIRQ (NR_COMMON_SOFTIRQS + 1)
#define VCPU_KICK_SOFTIRQ      (NR_COMMON_SOFTIRQS + 2)

#define MACHINE_CHECK_SOFTIRQ  (NR_COMMON_SOFTIRQS + 3)
#define HVM_DPCI_SOFTIRQ       (NR_COMMON_SOFTIRQS + 4)
#define NR_ARCH_SOFTIRQS       5

/*
 * Ensure softirq @nr is pending on @cpu.  Return true if an IPI can be
 * skipped, false if the IPI cannot be skipped.
 *
 * We use a CMPXCHG covering both __softirq_pending and in_mwait, in order to
 * set softirq @nr while also observing in_mwait in a race-free way.
 */
static always_inline bool arch_set_softirq(unsigned int nr, unsigned int cpu)
{
    uint64_t *ptr = &irq_stat[cpu].softirq_mwait_raw;
    uint64_t prev, old, new;
    unsigned int softirq = 1U << nr;

    old = ACCESS_ONCE(*ptr);

    for ( ;; )
    {
        if ( old & softirq )
            /* Softirq already pending, nothing to do. */
            return true;

        new = old | softirq;

        prev = cmpxchg(ptr, old, new);
        if ( prev == old )
            break;

        old = prev;
    }

    /*
     * We have caused the softirq to become pending.  If in_mwait was set, the
     * target CPU will notice the modification and act on it.
     *
     * We can't access the in_mwait field nicely, so use some BUILD_BUG_ON()'s
     * to cross-check the (1UL << 32) opencoding.
     */
    BUILD_BUG_ON(sizeof(irq_stat[0].softirq_mwait_raw) != 8);
    BUILD_BUG_ON((offsetof(irq_cpustat_t, in_mwait) -
                  offsetof(irq_cpustat_t, softirq_mwait_raw)) != 4);

    return new & (1UL << 32) /* in_mwait */;

}
#define arch_set_softirq arch_set_softirq

#endif /* __ASM_SOFTIRQ_H__ */
