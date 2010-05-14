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
    while ( atomic_read(&stopmachine_data.done) != stopmachine_data.nr_cpus )
        cpu_relax();
}

int stop_machine_run(int (*fn)(void *), void *data, unsigned int cpu)
{
    cpumask_t allbutself;
    unsigned int i, nr_cpus;
    int ret;

    BUG_ON(!local_irq_is_enabled());

    /* cpu_online_map must not change. */
    if ( !get_cpu_maps() )
        return -EBUSY;

    allbutself = cpu_online_map;
    cpu_clear(smp_processor_id(), allbutself);
    nr_cpus = cpus_weight(allbutself);

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
    atomic_set(&stopmachine_data.done, 0);
    stopmachine_data.state = STOPMACHINE_START;

    smp_wmb();

    for_each_cpu_mask ( i, allbutself )
        tasklet_schedule_on_cpu(&per_cpu(stopmachine_tasklet, i), i);

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

    put_cpu_maps();

    return ret;
}

static void stopmachine_action(unsigned long cpu)
{
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
    unsigned int cpu;
    for_each_possible_cpu ( cpu )
        tasklet_init(&per_cpu(stopmachine_tasklet, cpu),
                     stopmachine_action, cpu);
    return 0;
}
__initcall(cpu_stopmachine_init);
