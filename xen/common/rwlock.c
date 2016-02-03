#include <xen/rwlock.h>
#include <xen/irq.h>

static DEFINE_PER_CPU(cpumask_t, percpu_rwlock_readers);

void _percpu_write_lock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    unsigned int cpu;
    cpumask_t *rwlock_readers = &this_cpu(percpu_rwlock_readers);

    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /*
     * First take the write lock to protect against other writers or slow
     * path readers.
     */
    write_lock(&percpu_rwlock->rwlock);

    /* Now set the global variable so that readers start using read_lock. */
    percpu_rwlock->writer_activating = 1;
    smp_mb();

    /* Using a per cpu cpumask is only safe if there is no nesting. */
    ASSERT(!in_irq());
    cpumask_copy(rwlock_readers, &cpu_online_map);

    /* Check if there are any percpu readers in progress on this rwlock. */
    for ( ; ; )
    {
        for_each_cpu(cpu, rwlock_readers)
        {
            /*
             * Remove any percpu readers not contending on this rwlock
             * from our check mask.
             */
            if ( per_cpu_ptr(per_cpudata, cpu) != percpu_rwlock )
                __cpumask_clear_cpu(cpu, rwlock_readers);
        }
        /* Check if we've cleared all percpu readers from check mask. */
        if ( cpumask_empty(rwlock_readers) )
            break;
        /* Give the coherency fabric a break. */
        cpu_relax();
    };
}
