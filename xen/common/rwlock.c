#include <xen/rwlock.h>
#include <xen/irq.h>

/*
 * rspin_until_writer_unlock - spin until writer is gone.
 * @lock  : Pointer to queue rwlock structure.
 * @cnts: Current queue rwlock writer status byte.
 *
 * In interrupt context or at the head of the queue, the reader will just
 * increment the reader count & wait until the writer releases the lock.
 */
static inline void rspin_until_writer_unlock(rwlock_t *lock, u32 cnts)
{
    while ( (cnts & _QW_WMASK) == _QW_LOCKED )
    {
        cpu_relax();
        smp_rmb();
        cnts = atomic_read(&lock->cnts);
    }
}

/*
 * queue_read_lock_slowpath - acquire read lock of a queue rwlock.
 * @lock: Pointer to queue rwlock structure.
 */
void queue_read_lock_slowpath(rwlock_t *lock)
{
    u32 cnts;

    /*
     * Readers come here when they cannot get the lock without waiting.
     */
    atomic_sub(_QR_BIAS, &lock->cnts);

    /*
     * Put the reader into the wait queue.
     */
    spin_lock(&lock->lock);

    /*
     * At the head of the wait queue now, wait until the writer state
     * goes to 0 and then try to increment the reader count and get
     * the lock. It is possible that an incoming writer may steal the
     * lock in the interim, so it is necessary to check the writer byte
     * to make sure that the write lock isn't taken.
     */
    while ( atomic_read(&lock->cnts) & _QW_WMASK )
        cpu_relax();

    cnts = atomic_add_return(_QR_BIAS, &lock->cnts) - _QR_BIAS;
    rspin_until_writer_unlock(lock, cnts);

    /*
     * Signal the next one in queue to become queue head.
     */
    spin_unlock(&lock->lock);
}

/*
 * queue_write_lock_slowpath - acquire write lock of a queue rwlock
 * @lock : Pointer to queue rwlock structure.
 */
void queue_write_lock_slowpath(rwlock_t *lock)
{
    u32 cnts;

    /* Put the writer into the wait queue. */
    spin_lock(&lock->lock);

    /* Try to acquire the lock directly if no reader is present. */
    if ( !atomic_read(&lock->cnts) &&
         (atomic_cmpxchg(&lock->cnts, 0, _QW_LOCKED) == 0) )
        goto unlock;

    /*
     * Set the waiting flag to notify readers that a writer is pending,
     * or wait for a previous writer to go away.
     */
    for ( ; ; )
    {
        cnts = atomic_read(&lock->cnts);
        if ( !(cnts & _QW_WMASK) &&
             (atomic_cmpxchg(&lock->cnts, cnts,
                             cnts | _QW_WAITING) == cnts) )
            break;

        cpu_relax();
    }

    /* When no more readers, set the locked flag. */
    for ( ; ; )
    {
        cnts = atomic_read(&lock->cnts);
        if ( (cnts == _QW_WAITING) &&
             (atomic_cmpxchg(&lock->cnts, _QW_WAITING,
                             _QW_LOCKED) == _QW_WAITING) )
            break;

        cpu_relax();
    }
 unlock:
    spin_unlock(&lock->lock);
}


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
