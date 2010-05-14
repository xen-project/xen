#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/cpu.h>

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x) [x+1][0] = 1UL << (x)
#define MASK_DECLARE_2(x) MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x) MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x) MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

    MASK_DECLARE_8(0),  MASK_DECLARE_8(8),
    MASK_DECLARE_8(16), MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
    MASK_DECLARE_8(32), MASK_DECLARE_8(40),
    MASK_DECLARE_8(48), MASK_DECLARE_8(56),
#endif
};

DEFINE_SPINLOCK(cpu_add_remove_lock);

static RAW_NOTIFIER_HEAD(cpu_chain);

int register_cpu_notifier(struct notifier_block *nb)
{
    int ret;
    spin_lock(&cpu_add_remove_lock);
    ret = raw_notifier_chain_register(&cpu_chain, nb);
    spin_unlock(&cpu_add_remove_lock);
    return ret;
}

void unregister_cpu_notifier(struct notifier_block *nb)
{
    spin_lock(&cpu_add_remove_lock);
    raw_notifier_chain_unregister(&cpu_chain, nb);
    spin_unlock(&cpu_add_remove_lock);
}

int cpu_notifier_call_chain(unsigned long val, void *v)
{
    BUG_ON(!spin_is_locked(&cpu_add_remove_lock));
    return raw_notifier_call_chain(&cpu_chain, val, v);
}

int __cpu_notifier_call_chain(
    unsigned long val, void *v, int nr_to_call, int *nr_calls)
{
    BUG_ON(!spin_is_locked(&cpu_add_remove_lock));
    return __raw_notifier_call_chain(&cpu_chain, val, v, nr_to_call, nr_calls);
}
