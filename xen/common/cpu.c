#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/cpu.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/stop_machine.h>

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

static DEFINE_SPINLOCK(cpu_add_remove_lock);

bool_t get_cpu_maps(void)
{
    return spin_trylock_recursive(&cpu_add_remove_lock);
}

void put_cpu_maps(void)
{
    spin_unlock_recursive(&cpu_add_remove_lock);
}

bool_t cpu_hotplug_begin(void)
{
    return get_cpu_maps();
}

void cpu_hotplug_done(void)
{
    put_cpu_maps();
}

static RAW_NOTIFIER_HEAD(cpu_chain);

int register_cpu_notifier(struct notifier_block *nb)
{
    int ret;
    if ( !spin_trylock(&cpu_add_remove_lock) )
        BUG(); /* Should never fail as we are called only during boot. */
    ret = raw_notifier_chain_register(&cpu_chain, nb);
    spin_unlock(&cpu_add_remove_lock);
    return ret;
}

static int take_cpu_down(void *unused)
{
    void *hcpu = (void *)(long)smp_processor_id();
    if ( raw_notifier_call_chain(&cpu_chain, CPU_DYING, hcpu) != NOTIFY_DONE )
        BUG();
    return __cpu_disable();
}

int cpu_down(unsigned int cpu)
{
    int err, notifier_rc, nr_calls;
    void *hcpu = (void *)(long)cpu;

    if ( !cpu_hotplug_begin() )
        return -EBUSY;

    if ( (cpu == 0) || !cpu_online(cpu) )
    {
        cpu_hotplug_done();
        return -EINVAL;
    }

    printk("Prepare to bring CPU%d down...\n", cpu);

    notifier_rc = __raw_notifier_call_chain(
        &cpu_chain, CPU_DOWN_PREPARE, hcpu, -1, &nr_calls);
    if ( notifier_rc != NOTIFY_DONE )
    {
        err = notifier_to_errno(notifier_rc);
        nr_calls--;
        notifier_rc = __raw_notifier_call_chain(
            &cpu_chain, CPU_DOWN_FAILED, hcpu, nr_calls, NULL);
        BUG_ON(notifier_rc != NOTIFY_DONE);
        goto out;
    }

    if ( (err = stop_machine_run(take_cpu_down, NULL, cpu)) < 0 )
    {
        notifier_rc = raw_notifier_call_chain(
            &cpu_chain, CPU_DOWN_FAILED, hcpu);
        BUG_ON(notifier_rc != NOTIFY_DONE);
        goto out;
    }

    __cpu_die(cpu);
    BUG_ON(cpu_online(cpu));

    notifier_rc = raw_notifier_call_chain(&cpu_chain, CPU_DEAD, hcpu);
    BUG_ON(notifier_rc != NOTIFY_DONE);

 out:
    if ( !err )
    {
        printk("CPU %u is now offline\n", cpu);
        send_guest_global_virq(dom0, VIRQ_PCPU_STATE);
    }
    else
    {
        printk("Failed to take down CPU %u (error %d)\n", cpu, err);
    }
    cpu_hotplug_done();
    return err;
}

int cpu_up(unsigned int cpu)
{
    int notifier_rc, nr_calls, err = 0;
    void *hcpu = (void *)(long)cpu;

    if ( !cpu_hotplug_begin() )
        return -EBUSY;

    if ( cpu_online(cpu) || !cpu_present(cpu) )
    {
        cpu_hotplug_done();
        return -EINVAL;
    }

    notifier_rc = __raw_notifier_call_chain(
        &cpu_chain, CPU_UP_PREPARE, hcpu, -1, &nr_calls);
    if ( notifier_rc != NOTIFY_DONE )
    {
        err = notifier_to_errno(notifier_rc);
        nr_calls--;
        goto fail;
    }

    err = __cpu_up(cpu);
    if ( err < 0 )
        goto fail;

    notifier_rc = raw_notifier_call_chain(&cpu_chain, CPU_ONLINE, hcpu);
    BUG_ON(notifier_rc != NOTIFY_DONE);

    send_guest_global_virq(dom0, VIRQ_PCPU_STATE);

    cpu_hotplug_done();
    return 0;

 fail:
    notifier_rc = __raw_notifier_call_chain(
        &cpu_chain, CPU_UP_CANCELED, hcpu, nr_calls, NULL);
    BUG_ON(notifier_rc != NOTIFY_DONE);
    cpu_hotplug_done();
    return err;
}

static cpumask_t frozen_cpus;

int disable_nonboot_cpus(void)
{
    int cpu, error = 0;

    BUG_ON(raw_smp_processor_id() != 0);

    cpus_clear(frozen_cpus);

    printk("Disabling non-boot CPUs ...\n");

    for_each_online_cpu ( cpu )
    {
        if ( cpu == 0 )
            continue;

        if ( (error = cpu_down(cpu)) )
        {
            BUG_ON(error == -EBUSY);
            printk("Error taking CPU%d down: %d\n", cpu, error);
            break;
        }

        cpu_set(cpu, frozen_cpus);
        printk("CPU%d is down\n", cpu);
    }

    BUG_ON(!error && (num_online_cpus() != 1));
    return error;
}

void enable_nonboot_cpus(void)
{
    int cpu, error;

    printk("Enabling non-boot CPUs  ...\n");

    for_each_cpu_mask ( cpu, frozen_cpus )
    {
        if ( (error = cpu_up(cpu)) )
        {
            BUG_ON(error == -EBUSY);
            printk("Error taking CPU%d up: %d\n", cpu, error);
            continue;
        }
        printk("CPU%d is up\n", cpu);
    }

    cpus_clear(frozen_cpus);
}
