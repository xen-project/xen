#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#include <xen/spinlock.h>

#define read_lock(l)                  _read_lock(l)
#define read_lock_irq(l)              _read_lock_irq(l)
#define read_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _read_lock_irqsave(l));                          \
    })

#define read_unlock(l)                _read_unlock(l)
#define read_unlock_irq(l)            _read_unlock_irq(l)
#define read_unlock_irqrestore(l, f)  _read_unlock_irqrestore(l, f)
#define read_trylock(l)               _read_trylock(l)

#define write_lock(l)                 _write_lock(l)
#define write_lock_irq(l)             _write_lock_irq(l)
#define write_lock_irqsave(l, f)                                \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _write_lock_irqsave(l));                         \
    })
#define write_trylock(l)              _write_trylock(l)

#define write_unlock(l)               _write_unlock(l)
#define write_unlock_irq(l)           _write_unlock_irq(l)
#define write_unlock_irqrestore(l, f) _write_unlock_irqrestore(l, f)

#define rw_is_locked(l)               _rw_is_locked(l)
#define rw_is_write_locked(l)         _rw_is_write_locked(l)


typedef struct percpu_rwlock percpu_rwlock_t;

struct percpu_rwlock {
    rwlock_t            rwlock;
    bool_t              writer_activating;
#ifndef NDEBUG
    percpu_rwlock_t     **percpu_owner;
#endif
};

#ifndef NDEBUG
#define PERCPU_RW_LOCK_UNLOCKED(owner) { RW_LOCK_UNLOCKED, 0, owner }
static inline void _percpu_rwlock_owner_check(percpu_rwlock_t **per_cpudata,
                                         percpu_rwlock_t *percpu_rwlock)
{
    ASSERT(per_cpudata == percpu_rwlock->percpu_owner);
}
#else
#define PERCPU_RW_LOCK_UNLOCKED(owner) { RW_LOCK_UNLOCKED, 0 }
#define _percpu_rwlock_owner_check(data, lock) ((void)0)
#endif

#define DEFINE_PERCPU_RWLOCK_RESOURCE(l, owner) \
    percpu_rwlock_t l = PERCPU_RW_LOCK_UNLOCKED(&get_per_cpu_var(owner))
#define percpu_rwlock_resource_init(l, owner) \
    (*(l) = (percpu_rwlock_t)PERCPU_RW_LOCK_UNLOCKED(&get_per_cpu_var(owner)))

static inline void _percpu_read_lock(percpu_rwlock_t **per_cpudata,
                                         percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /* We cannot support recursion on the same lock. */
    ASSERT(this_cpu_ptr(per_cpudata) != percpu_rwlock);
    /*
     * Detect using a second percpu_rwlock_t simulatenously and fallback
     * to standard read_lock.
     */
    if ( unlikely(this_cpu_ptr(per_cpudata) != NULL ) )
    {
        read_lock(&percpu_rwlock->rwlock);
        return;
    }

    /* Indicate this cpu is reading. */
    this_cpu_ptr(per_cpudata) = percpu_rwlock;
    smp_mb();
    /* Check if a writer is waiting. */
    if ( unlikely(percpu_rwlock->writer_activating) )
    {
        /* Let the waiting writer know we aren't holding the lock. */
        this_cpu_ptr(per_cpudata) = NULL;
        /* Wait using the read lock to keep the lock fair. */
        read_lock(&percpu_rwlock->rwlock);
        /* Set the per CPU data again and continue. */
        this_cpu_ptr(per_cpudata) = percpu_rwlock;
        /* Drop the read lock because we don't need it anymore. */
        read_unlock(&percpu_rwlock->rwlock);
    }
}

static inline void _percpu_read_unlock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /* Verify the read lock was taken for this lock */
    ASSERT(this_cpu_ptr(per_cpudata) != NULL);
    /*
     * Detect using a second percpu_rwlock_t simulatenously and fallback
     * to standard read_unlock.
     */
    if ( unlikely(this_cpu_ptr(per_cpudata) != percpu_rwlock ) )
    {
        read_unlock(&percpu_rwlock->rwlock);
        return;
    }
    this_cpu_ptr(per_cpudata) = NULL;
    smp_wmb();
}

/* Don't inline percpu write lock as it's a complex function. */
void _percpu_write_lock(percpu_rwlock_t **per_cpudata,
                        percpu_rwlock_t *percpu_rwlock);

static inline void _percpu_write_unlock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    ASSERT(percpu_rwlock->writer_activating);
    percpu_rwlock->writer_activating = 0;
    write_unlock(&percpu_rwlock->rwlock);
}

#define percpu_rw_is_write_locked(l)         _rw_is_write_locked(&((l)->rwlock))

#define percpu_read_lock(percpu, lock) \
    _percpu_read_lock(&get_per_cpu_var(percpu), lock)
#define percpu_read_unlock(percpu, lock) \
    _percpu_read_unlock(&get_per_cpu_var(percpu), lock)
#define percpu_write_lock(percpu, lock) \
    _percpu_write_lock(&get_per_cpu_var(percpu), lock)
#define percpu_write_unlock(percpu, lock) \
    _percpu_write_unlock(&get_per_cpu_var(percpu), lock)

#define DEFINE_PERCPU_RWLOCK_GLOBAL(name) DEFINE_PER_CPU(percpu_rwlock_t *, \
                                                         name)
#define DECLARE_PERCPU_RWLOCK_GLOBAL(name) DECLARE_PER_CPU(percpu_rwlock_t *, \
                                                           name)

#endif /* __RWLOCK_H__ */
