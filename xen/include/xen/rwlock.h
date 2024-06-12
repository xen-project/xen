#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#include <xen/percpu.h>
#include <xen/preempt.h>
#include <xen/smp.h>
#include <xen/spinlock.h>

#include <asm/atomic.h>
#include <asm/system.h>

typedef struct {
    atomic_t cnts;
    spinlock_t lock;
} rwlock_t;

#define    RW_LOCK_UNLOCKED {           \
    .cnts = ATOMIC_INIT(0),             \
    .lock = SPIN_LOCK_UNLOCKED          \
}

#define DEFINE_RWLOCK(l) rwlock_t l = RW_LOCK_UNLOCKED
#define rwlock_init(l) (*(l) = (rwlock_t)RW_LOCK_UNLOCKED)

/* Writer states & reader shift and bias. */
#define    _QW_SHIFT    14                      /* Writer flags shift */
#define    _QW_CPUMASK  ((1U << _QW_SHIFT) - 1) /* Writer CPU mask */
#define    _QW_WAITING  (1U << _QW_SHIFT)       /* A writer is waiting */
#define    _QW_LOCKED   (3U << _QW_SHIFT)       /* A writer holds the lock */
#define    _QW_WMASK    (3U << _QW_SHIFT)       /* Writer mask */
#define    _QR_SHIFT    (_QW_SHIFT + 2)         /* Reader count shift */
#define    _QR_BIAS     (1U << _QR_SHIFT)

void queue_read_lock_slowpath(rwlock_t *lock);
void queue_write_lock_slowpath(rwlock_t *lock);

static inline bool _is_write_locked_by_me(unsigned int cnts)
{
    BUILD_BUG_ON((_QW_CPUMASK + 1) < NR_CPUS);
    BUILD_BUG_ON(NR_CPUS * _QR_BIAS > INT_MAX);
    return (cnts & _QW_WMASK) == _QW_LOCKED &&
           (cnts & _QW_CPUMASK) == smp_processor_id();
}

static inline bool _can_read_lock(unsigned int cnts)
{
    /*
     * If write locked by the caller, no other readers are possible.
     * Not allowing the lock holder to read_lock() another
     * INT_MAX >> _QR_SHIFT times ought to be fine.
     */
    return cnts <= INT_MAX &&
           (!(cnts & _QW_WMASK) || _is_write_locked_by_me(cnts));
}

/*
 * _read_trylock - try to acquire read lock of a queue rwlock.
 * @lock : Pointer to queue rwlock structure.
 * Return: 1 if lock acquired, 0 if failed.
 */
static inline int _read_trylock(rwlock_t *lock)
{
    u32 cnts;

    preempt_disable();
    check_lock(&lock->lock.debug, true);
    cnts = atomic_read(&lock->cnts);
    if ( likely(_can_read_lock(cnts)) )
    {
        cnts = (u32)atomic_add_return(_QR_BIAS, &lock->cnts);
        /*
         * atomic_add_return() is a full barrier so no need for an
         * arch_lock_acquire_barrier().
         */
        if ( likely(_can_read_lock(cnts)) )
        {
            lock_enter(&lock->lock.debug);
            return 1;
        }
        atomic_sub(_QR_BIAS, &lock->cnts);
    }
    preempt_enable();
    return 0;
}

/*
 * _read_lock - acquire read lock of a queue rwlock.
 * @lock: Pointer to queue rwlock structure.
 */
static inline void _read_lock(rwlock_t *lock)
{
    u32 cnts;

    preempt_disable();
    cnts = atomic_add_return(_QR_BIAS, &lock->cnts);
    /*
     * atomic_add_return() is a full barrier so no need for an
     * arch_lock_acquire_barrier().
     */
    if ( likely(_can_read_lock(cnts)) )
    {
        /* The slow path calls check_lock() via spin_lock(). */
        check_lock(&lock->lock.debug, false);
        lock_enter(&lock->lock.debug);
        return;
    }

    /* The slowpath will decrement the reader count, if necessary. */
    queue_read_lock_slowpath(lock);
    /*
     * queue_read_lock_slowpath() is using spinlock and therefore is a
     * full barrier. So no need for an arch_lock_acquire_barrier().
     */
}

static inline void _read_lock_irq(rwlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _read_lock(lock);
}

static inline unsigned long _read_lock_irqsave(rwlock_t *lock)
{
    unsigned long flags;
    local_irq_save(flags);
    _read_lock(lock);
    return flags;
}

/*
 * _read_unlock - release read lock of a queue rwlock.
 * @lock : Pointer to queue rwlock structure.
 */
static inline void _read_unlock(rwlock_t *lock)
{
    lock_exit(&lock->lock.debug);

    arch_lock_release_barrier();
    /*
     * Atomically decrement the reader count
     */
    atomic_sub(_QR_BIAS, &lock->cnts);
    preempt_enable();
}

static inline void _read_unlock_irq(rwlock_t *lock)
{
    _read_unlock(lock);
    local_irq_enable();
}

static inline void _read_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    _read_unlock(lock);
    local_irq_restore(flags);
}

static inline int _rw_is_locked(const rwlock_t *lock)
{
    return atomic_read(&lock->cnts);
}

static inline unsigned int _write_lock_val(void)
{
    return _QW_LOCKED | smp_processor_id();
}

/*
 * queue_write_lock - acquire write lock of a queue rwlock.
 * @lock : Pointer to queue rwlock structure.
 */
static inline void _write_lock(rwlock_t *lock)
{
    preempt_disable();
    /*
     * Optimize for the unfair lock case where the fair flag is 0.
     *
     * atomic_cmpxchg() is a full barrier so no need for an
     * arch_lock_acquire_barrier().
     */
    if ( atomic_cmpxchg(&lock->cnts, 0, _write_lock_val()) == 0 )
    {
        /* The slow path calls check_lock() via spin_lock(). */
        check_lock(&lock->lock.debug, false);
        lock_enter(&lock->lock.debug);
        return;
    }

    queue_write_lock_slowpath(lock);
    /*
     * queue_write_lock_slowpath() is using spinlock and therefore is a
     * full barrier. So no need for an arch_lock_acquire_barrier().
     */
}

static inline void _write_lock_irq(rwlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _write_lock(lock);
}

static inline unsigned long _write_lock_irqsave(rwlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);
    _write_lock(lock);
    return flags;
}

/*
 * queue_write_trylock - try to acquire write lock of a queue rwlock.
 * @lock : Pointer to queue rwlock structure.
 * Return: 1 if lock acquired, 0 if failed.
 */
static inline int _write_trylock(rwlock_t *lock)
{
    u32 cnts;

    preempt_disable();
    check_lock(&lock->lock.debug, true);
    cnts = atomic_read(&lock->cnts);
    if ( unlikely(cnts) ||
         unlikely(atomic_cmpxchg(&lock->cnts, 0, _write_lock_val()) != 0) )
    {
        preempt_enable();
        return 0;
    }

    lock_enter(&lock->lock.debug);

    /*
     * atomic_cmpxchg() is a full barrier so no need for an
     * arch_lock_acquire_barrier().
     */
    return 1;
}

static inline void _write_unlock(rwlock_t *lock)
{
    ASSERT(_is_write_locked_by_me(atomic_read(&lock->cnts)));

    lock_exit(&lock->lock.debug);

    arch_lock_release_barrier();
    atomic_and(~(_QW_CPUMASK | _QW_WMASK), &lock->cnts);
    preempt_enable();
}

static inline void _write_unlock_irq(rwlock_t *lock)
{
    _write_unlock(lock);
    local_irq_enable();
}

static inline void _write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    _write_unlock(lock);
    local_irq_restore(flags);
}

static inline int _rw_is_write_locked(const rwlock_t *lock)
{
    return (atomic_read(&lock->cnts) & _QW_WMASK) == _QW_LOCKED;
}

static always_inline void read_lock(rwlock_t *l)
{
    _read_lock(l);
    block_lock_speculation();
}

static always_inline void read_lock_irq(rwlock_t *l)
{
    _read_lock_irq(l);
    block_lock_speculation();
}

#define read_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _read_lock_irqsave(l));                          \
        block_lock_speculation();                               \
    })

#define read_unlock(l)                _read_unlock(l)
#define read_unlock_irq(l)            _read_unlock_irq(l)
#define read_unlock_irqrestore(l, f)  _read_unlock_irqrestore(l, f)
#define read_trylock(l)               lock_evaluate_nospec(_read_trylock(l))

static always_inline void write_lock(rwlock_t *l)
{
    _write_lock(l);
    block_lock_speculation();
}

static always_inline void write_lock_irq(rwlock_t *l)
{
    _write_lock_irq(l);
    block_lock_speculation();
}

#define write_lock_irqsave(l, f)                                \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _write_lock_irqsave(l));                         \
        block_lock_speculation();                               \
    })
#define write_trylock(l)              lock_evaluate_nospec(_write_trylock(l))

#define write_unlock(l)               _write_unlock(l)
#define write_unlock_irq(l)           _write_unlock_irq(l)
#define write_unlock_irqrestore(l, f) _write_unlock_irqrestore(l, f)

#define rw_is_locked(l)               _rw_is_locked(l)
#define rw_is_write_locked(l)         _rw_is_write_locked(l)
#define rw_is_write_locked_by_me(l) \
    lock_evaluate_nospec(_is_write_locked_by_me(atomic_read(&(l)->cnts)))


typedef struct percpu_rwlock percpu_rwlock_t;

struct percpu_rwlock {
    rwlock_t            rwlock;
    bool                writer_activating;
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

static always_inline void _percpu_read_lock(percpu_rwlock_t **per_cpudata,
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
    preempt_disable();
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
    else
    {
        /* Other branch already has a speculation barrier in read_lock(). */
        block_lock_speculation();
        /* All other paths have implicit check_lock() calls via read_lock(). */
        check_lock(&percpu_rwlock->rwlock.lock.debug, false);
    }

    lock_enter(&percpu_rwlock->rwlock.lock.debug);
}

static inline void _percpu_read_unlock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /* Verify the read lock was taken for this lock */
    ASSERT(this_cpu_ptr(per_cpudata) != NULL);

    lock_exit(&percpu_rwlock->rwlock.lock.debug);

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
    preempt_enable();
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

    lock_exit(&percpu_rwlock->rwlock.lock.debug);

    write_unlock(&percpu_rwlock->rwlock);
}

#define percpu_rw_is_write_locked(l)         _rw_is_write_locked(&((l)->rwlock))

#define percpu_read_lock(percpu, lock) \
    _percpu_read_lock(&get_per_cpu_var(percpu), lock)
#define percpu_read_unlock(percpu, lock) \
    _percpu_read_unlock(&get_per_cpu_var(percpu), lock)

#define percpu_write_lock(percpu, lock)                 \
({                                                      \
    _percpu_write_lock(&get_per_cpu_var(percpu), lock); \
    block_lock_speculation();                           \
})
#define percpu_write_unlock(percpu, lock) \
    _percpu_write_unlock(&get_per_cpu_var(percpu), lock)

#define DEFINE_PERCPU_RWLOCK_GLOBAL(name) DEFINE_PER_CPU(percpu_rwlock_t *, \
                                                         name)
#define DECLARE_PERCPU_RWLOCK_GLOBAL(name) DECLARE_PER_CPU(percpu_rwlock_t *, \
                                                           name)

#endif /* __RWLOCK_H__ */
