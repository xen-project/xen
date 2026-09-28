/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/atomic.h>
#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/xmalloc.h>
#include <asm/gic.h>
#include <asm/processor.h>
#include <asm/setup.h>

static bool __initdata opt_gic_test;
boolean_param("gic-test", opt_gic_test);

static DEFINE_PER_CPU(unsigned int, sgi_test_count);

void gic_sgi_test_interrupt(void)
{
    ACCESS_ONCE(this_cpu(sgi_test_count))++;
}

static unsigned int __init sgi_count(unsigned int cpu)
{
    return ACCESS_ONCE(per_cpu(sgi_test_count, cpu));
}

static void __init snapshot_sgi(unsigned int *before)
{
    unsigned int cpu;

    for_each_online_cpu ( cpu )
        before[cpu] = sgi_count(cpu);
}

/*
 * Wait for every CPU in @mask to take one more GIC_SGI_TEST than the count
 * recorded in @before.
 */
static void __init expect_sgi(const cpumask_t *mask,
                              const unsigned int *before, const char *what)
{
    s_time_t deadline = NOW() + MILLISECS(100);
    unsigned int cpu;

    for_each_cpu ( cpu, mask )
    {
        while ( sgi_count(cpu) == before[cpu] )
        {
            if ( NOW() > deadline )
                panic("GIC selftest: %s: CPU%u did not receive GIC_SGI_TEST\n",
                      what, cpu);
            cpu_relax();
        }
    }

    printk("GIC selftest: CPU%u: %s: OK\n", smp_processor_id(), what);
}

/*
 * "All but self" is only meaningful once every CPU can take an SGI, so it is
 * run by whichever CPU observes that it is the last one to get here.
 */
static int __init gic_sgi_selftest(void)
{
    static atomic_t __initdata seen = ATOMIC_INIT(0);
    unsigned int cpu = smp_processor_id();
    unsigned int *before;

    if ( !opt_gic_test )
        return 0;

    before = xzalloc_array(unsigned int, nr_cpu_ids);
    if ( !before )
        panic("GIC selftest: CPU%u: cannot allocate %u counters\n",
              cpu, nr_cpu_ids);

    snapshot_sgi(before);
    send_SGI_self(GIC_SGI_TEST);
    expect_sgi(cpumask_of(cpu), before, "SGI to self");

    if ( cpu != 0 )
    {
        snapshot_sgi(before);
        send_SGI_one(0, GIC_SGI_TEST);
        expect_sgi(cpumask_of(0), before, "SGI to CPU0");
    }

    if ( atomic_add_return(1, &seen) == num_online_cpus() )
    {
        cpumask_t target;

        cpumask_andnot(&target, &cpu_online_map, cpumask_of(cpu));

        if ( !cpumask_empty(&target) )
        {
            snapshot_sgi(before);
            send_SGI_allbutself(GIC_SGI_TEST);
            expect_sgi(&target, before, "SGI to all but self");
        }
    }

    xfree(before);

    return 0;
}
__initcallboottest(gic_sgi_selftest);
