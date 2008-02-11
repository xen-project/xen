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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/spinlock.h>
#include <asm/smp.h>
#include <asm/current.h>
#include <xen/softirq.h>
#include <asm/processor.h>
#include <xen/errno.h>

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

static struct stopmachine_data stopmachine_data;
static DEFINE_SPINLOCK(stopmachine_lock);

static void stopmachine_set_state(enum stopmachine_state state)
{
    atomic_set(&stopmachine_data.done, 0);
    smp_wmb();
    stopmachine_data.state = state;
    while ( atomic_read(&stopmachine_data.done) != stopmachine_data.nr_cpus )
        cpu_relax();
}

int __stop_machine_run(int (*fn)(void *), void *data, unsigned int cpu)
{
    cpumask_t allbutself;
    unsigned int i, nr_cpus;
    int ret;

    BUG_ON(!local_irq_is_enabled());

    allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    nr_cpus = cpus_weight(allbutself);

    if ( nr_cpus == 0 )
    {
        BUG_ON(cpu != smp_processor_id());
        return (*fn)(data);
    }

    /* Note: We shouldn't spin on lock when it's held by others since others
     * is expecting this cpus to enter softirq context. Or else deadlock
     * is caused.
     */
    if ( !spin_trylock(&stopmachine_lock) )
        return -EBUSY;

    stopmachine_data.fn = fn;
    stopmachine_data.fn_data = data;
    stopmachine_data.nr_cpus = nr_cpus;
    stopmachine_data.fn_cpu = cpu;
    atomic_set(&stopmachine_data.done, 0);
    stopmachine_data.state = STOPMACHINE_START;

    smp_wmb();

    for_each_cpu_mask ( i, allbutself )
        cpu_raise_softirq(i, STOPMACHINE_SOFTIRQ);

    stopmachine_set_state(STOPMACHINE_PREPARE);

    local_irq_disable();
    stopmachine_set_state(STOPMACHINE_DISABLE_IRQ);

    if ( cpu == smp_processor_id() )
        stopmachine_data.fn_result = (*fn)(data);
    stopmachine_set_state(STOPMACHINE_INVOKE);
    ret = stopmachine_data.fn_result;

    stopmachine_set_state(STOPMACHINE_EXIT);
    local_irq_enable();

    spin_unlock(&stopmachine_lock);

    return ret;
}

int stop_machine_run(int (*fn)(void *), void *data, unsigned int cpu)
{
    int ret;

    lock_cpu_hotplug();
    ret = __stop_machine_run(fn, data, cpu);
    unlock_cpu_hotplug();

    return ret;
}

static void stopmachine_softirq(void)
{
    enum stopmachine_state state = STOPMACHINE_START;

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
            if ( stopmachine_data.fn_cpu == smp_processor_id() )
                stopmachine_data.fn_result =
                    stopmachine_data.fn(stopmachine_data.fn_data);
            break;
        default:
            break;
        }

        smp_mb();
        atomic_inc(&stopmachine_data.done);
    }

    local_irq_enable();
}

static int __init cpu_stopmachine_init(void)
{
    open_softirq(STOPMACHINE_SOFTIRQ, stopmachine_softirq);
    return 0;
}
__initcall(cpu_stopmachine_init);
