#include <xen/cpumask.h>
#include <xen/cpu.h>
#include <xen/event.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/stop_machine.h>

unsigned int __read_mostly nr_cpu_ids = NR_CPUS;
#ifndef nr_cpumask_bits
unsigned int __read_mostly nr_cpumask_bits
    = BITS_TO_LONGS(NR_CPUS) * BITS_PER_LONG;
#endif

const cpumask_t cpumask_all = {
    .bits[0 ... (BITS_TO_LONGS(NR_CPUS) - 1)] = ~0UL
};

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

static DEFINE_RWLOCK(cpu_add_remove_lock);

bool get_cpu_maps(void)
{
    return read_trylock(&cpu_add_remove_lock);
}

void put_cpu_maps(void)
{
    read_unlock(&cpu_add_remove_lock);
}

void cpu_hotplug_begin(void)
{
    write_lock(&cpu_add_remove_lock);
}

void cpu_hotplug_done(void)
{
    write_unlock(&cpu_add_remove_lock);
}

static NOTIFIER_HEAD(cpu_chain);

void __init register_cpu_notifier(struct notifier_block *nb)
{
    write_lock(&cpu_add_remove_lock);
    notifier_chain_register(&cpu_chain, nb);
    write_unlock(&cpu_add_remove_lock);
}

static int cpu_notifier_call_chain(unsigned int cpu, unsigned long action,
                                   struct notifier_block **nb, bool nofail)
{
    void *hcpu = (void *)(long)cpu;
    int notifier_rc = notifier_call_chain(&cpu_chain, action, hcpu, nb);
    int ret = (notifier_rc == NOTIFY_DONE) ? 0 : notifier_to_errno(notifier_rc);

    BUG_ON(ret && nofail);

    return ret;
}

static void _take_cpu_down(void *unused)
{
    cpu_notifier_call_chain(smp_processor_id(), CPU_DYING, NULL, true);
    __cpu_disable();
}

static int take_cpu_down(void *arg)
{
    _take_cpu_down(arg);
    return 0;
}

int cpu_down(unsigned int cpu)
{
    int err;
    struct notifier_block *nb = NULL;

    cpu_hotplug_begin();

    err = -EINVAL;
    if ( (cpu >= nr_cpu_ids) || (cpu == 0) )
        goto out;

    err = -EEXIST;
    if ( !cpu_online(cpu) )
        goto out;

    err = cpu_notifier_call_chain(cpu, CPU_DOWN_PREPARE, &nb, false);
    if ( err )
        goto fail;

    if ( system_state < SYS_STATE_active || system_state == SYS_STATE_resume )
        on_selected_cpus(cpumask_of(cpu), _take_cpu_down, NULL, true);
    else if ( (err = stop_machine_run(take_cpu_down, NULL, cpu)) < 0 )
        goto fail;

    __cpu_die(cpu);
    err = cpu_online(cpu);
    BUG_ON(err);

    cpu_notifier_call_chain(cpu, CPU_DEAD, NULL, true);

    send_global_virq(VIRQ_PCPU_STATE);
    cpu_hotplug_done();
    return 0;

 fail:
    cpu_notifier_call_chain(cpu, CPU_DOWN_FAILED, &nb, true);
 out:
    cpu_hotplug_done();
    return err;
}

int cpu_up(unsigned int cpu)
{
    int err;
    struct notifier_block *nb = NULL;

    cpu_hotplug_begin();

    err = -EINVAL;
    if ( (cpu >= nr_cpu_ids) || !cpu_present(cpu) )
        goto out;

    err = -EEXIST;
    if ( cpu_online(cpu) )
        goto out;

    err = cpu_notifier_call_chain(cpu, CPU_UP_PREPARE, &nb, false);
    if ( err )
        goto fail;

    err = __cpu_up(cpu);
    if ( err < 0 )
        goto fail;

    cpu_notifier_call_chain(cpu, CPU_ONLINE, NULL, true);

    send_global_virq(VIRQ_PCPU_STATE);

    cpu_hotplug_done();
    return 0;

 fail:
    cpu_notifier_call_chain(cpu, CPU_UP_CANCELED, &nb, true);
 out:
    cpu_hotplug_done();
    return err;
}

void notify_cpu_starting(unsigned int cpu)
{
    cpu_notifier_call_chain(cpu, CPU_STARTING, NULL, true);
}

static cpumask_t frozen_cpus;

int disable_nonboot_cpus(void)
{
    int cpu, error = 0;

    BUG_ON(smp_processor_id() != 0);

    cpumask_clear(&frozen_cpus);

    printk("Disabling non-boot CPUs ...\n");

    for_each_online_cpu ( cpu )
    {
        if ( cpu == 0 )
            continue;

        if ( (error = cpu_down(cpu)) )
        {
            printk("Error taking CPU%d down: %d\n", cpu, error);
            BUG_ON(error == -EBUSY);
            break;
        }

        __cpumask_set_cpu(cpu, &frozen_cpus);
    }

    BUG_ON(!error && (num_online_cpus() != 1));
    return error;
}

void enable_nonboot_cpus(void)
{
    int cpu, error;

    printk("Enabling non-boot CPUs  ...\n");

    for_each_present_cpu ( cpu )
    {
        if ( park_offline_cpus ? cpu == smp_processor_id()
                               : !cpumask_test_cpu(cpu, &frozen_cpus) )
            continue;
        if ( (error = cpu_up(cpu)) )
        {
            printk("Error bringing CPU%d up: %d\n", cpu, error);
            BUG_ON(error == -EBUSY);
        }
        else if ( !__cpumask_test_and_clear_cpu(cpu, &frozen_cpus) &&
                  (error = cpu_down(cpu)) )
            printk("Error re-offlining CPU%d: %d\n", cpu, error);
    }

    for_each_cpu ( cpu, &frozen_cpus )
        cpu_notifier_call_chain(cpu, CPU_RESUME_FAILED, NULL, true);

    cpumask_clear(&frozen_cpus);
}
