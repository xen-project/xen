/******************************************************************************
 * common/stop_machine.c
 *
 * Facilities to put whole machine in a safe 'stop' state
 *
 * Copyright 2005 Rusty Russell rusty@rustcorp.com.au IBM Corporation
 * Copyright 2008 Kevin Tian <kevin.tian@intel.com>, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/tasklet.h>
#include <xen/stop_machine.h>
#include <xen/errno.h>
#include <xen/smp.h>
#include <xen/cpu.h>
#include <asm/current.h>
#include <asm/processor.h>

enum stopmachine_state {
    STOPMACHINE_START,
    STOPMACHINE_PREPARE,
    STOPMACHINE_DISABLE_IRQ,
    STOPMACHINE_INVOKE,
    STOPMACHINE_EXIT
};

struct stopmachine_data {
    unsigned int nr_cpus;

    enum stopmachine_state state;
    atomic_t done;

    unsigned int fn_cpu;
    int fn_result;
    int (*fn)(void *);
    void *fn_data;
};

static DEFINE_PER_CPU(struct tasklet, stopmachine_tasklet);
static struct stopmachine_data stopmachine_data;
static DEFINE_SPINLOCK(stopmachine_lock);

static void stopmachine_set_state(enum stopmachine_state state)
{
    atomic_set(&stopmachine_data.done, 0);
    smp_wmb();
    stopmachine_data.state = state;
}

static void stopmachine_wait_state(void)
{
    while ( atomic_read(&stopmachine_data.done) != stopmachine_data.nr_cpus )
        cpu_relax();
}

int stop_machine_run(int (*fn)(void *), void *data, unsigned int cpu)
{
    unsigned int i, nr_cpus;
    unsigned int this = smp_processor_id();
    int ret;

    BUG_ON(!local_irq_is_enabled());

    /* cpu_online_map must not change. */
    if ( !get_cpu_maps() )
        return -EBUSY;

    nr_cpus = num_online_cpus();
    if ( cpu_online(this) )
        nr_cpus--;

    /* Must not spin here as the holder will expect us to be descheduled. */
    if ( !spin_trylock(&stopmachine_lock) )
    {
        put_cpu_maps();
        return -EBUSY;
    }

    stopmachine_data.fn = fn;
    stopmachine_data.fn_data = data;
    stopmachine_data.nr_cpus = nr_cpus;
    stopmachine_data.fn_cpu = cpu;
    stopmachine_data.fn_result = 0;
    atomic_set(&stopmachine_data.done, 0);
    stopmachine_data.state = STOPMACHINE_START;

    smp_wmb();

    for_each_online_cpu ( i )
        if ( i != this )
            tasklet_schedule_on_cpu(&per_cpu(stopmachine_tasklet, i), i);

    stopmachine_set_state(STOPMACHINE_PREPARE);
    stopmachine_wait_state();

    local_irq_disable();
    stopmachine_set_state(STOPMACHINE_DISABLE_IRQ);
    stopmachine_wait_state();
    spin_debug_disable();

    stopmachine_set_state(STOPMACHINE_INVOKE);
    if ( (cpu == this) || (cpu == NR_CPUS) )
    {
        ret = (*fn)(data);
        if ( ret )
            write_atomic(&stopmachine_data.fn_result, ret);
    }
    stopmachine_wait_state();
    ret = stopmachine_data.fn_result;

    spin_debug_enable();
    stopmachine_set_state(STOPMACHINE_EXIT);
    stopmachine_wait_state();
    local_irq_enable();

    spin_unlock(&stopmachine_lock);

    put_cpu_maps();

    return ret;
}

static void stopmachine_action(void *data)
{
    unsigned int cpu = (unsigned long)data;
    enum stopmachine_state state = STOPMACHINE_START;

    BUG_ON(cpu != smp_processor_id());

    smp_mb();

    while ( state != STOPMACHINE_EXIT )
    {
        while ( stopmachine_data.state == state )
            cpu_relax();

        state = stopmachine_data.state;
        switch ( state )
        {
        case STOPMACHINE_DISABLE_IRQ:
            local_irq_disable();
            break;
        case STOPMACHINE_INVOKE:
            if ( (stopmachine_data.fn_cpu == smp_processor_id()) ||
                 (stopmachine_data.fn_cpu == NR_CPUS) )
            {
                int ret = stopmachine_data.fn(stopmachine_data.fn_data);

                if ( ret )
                    write_atomic(&stopmachine_data.fn_result, ret);
            }
            break;
        default:
            break;
        }

        smp_mb();
        atomic_inc(&stopmachine_data.done);
    }

    local_irq_enable();
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    if ( action == CPU_UP_PREPARE )
        tasklet_init(&per_cpu(stopmachine_tasklet, cpu),
                     stopmachine_action, hcpu);

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

static int __init cpu_stopmachine_init(void)
{
    unsigned int cpu;
    for_each_online_cpu ( cpu )
    {
        void *hcpu = (void *)(long)cpu;
        cpu_callback(&cpu_nfb, CPU_UP_PREPARE, hcpu);
    }
    register_cpu_notifier(&cpu_nfb);
    return 0;
}
__initcall(cpu_stopmachine_init);
