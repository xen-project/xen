#include <xen/config.h>
#include <xen/smp.h>
#include <xen/spinlock.h>

void _spin_lock(spinlock_t *lock)
{
    _raw_spin_lock(&lock->raw);
}

void _spin_lock_irq(spinlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _raw_spin_lock(&lock->raw);
}

unsigned long _spin_lock_irqsave(spinlock_t *lock)
{
    unsigned long flags;
    local_irq_save(flags);
    _raw_spin_lock(&lock->raw);
    return flags;
}

void _spin_unlock(spinlock_t *lock)
{
    _raw_spin_unlock(&lock->raw);
}

void _spin_unlock_irq(spinlock_t *lock)
{
    _raw_spin_unlock(&lock->raw);
    local_irq_enable();
}

void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
    _raw_spin_unlock(&lock->raw);
    local_irq_restore(flags);
}

int _spin_is_locked(spinlock_t *lock)
{
    return _raw_spin_is_locked(&lock->raw);
}

int _spin_trylock(spinlock_t *lock)
{
    return _raw_spin_trylock(&lock->raw);
}

void _spin_barrier(spinlock_t *lock)
{
    do { mb(); } while ( _raw_spin_is_locked(&lock->raw) );
    mb();
}

void _spin_barrier_irq(spinlock_t *lock)
{
    unsigned long flags;
    local_irq_save(flags);
    _spin_barrier(lock);
    local_irq_restore(flags);
}

void _spin_lock_recursive(spinlock_t *lock)
{
    int cpu = smp_processor_id();

    /* Don't allow overflow of recurse_cpu field. */
    BUILD_BUG_ON(NR_CPUS > 0xfffu);

    if ( likely(lock->recurse_cpu != cpu) )
    {
        spin_lock(lock);
        lock->recurse_cpu = cpu;
    }

    /* We support only fairly shallow recursion, else the counter overflows. */
    ASSERT(lock->recurse_cnt < 0xfu);
    lock->recurse_cnt++;
}

void _spin_unlock_recursive(spinlock_t *lock)
{
    if ( likely(--lock->recurse_cnt == 0) )
    {
        lock->recurse_cpu = 0xfffu;
        spin_unlock(lock);
    }
}

void _read_lock(rwlock_t *lock)
{
    _raw_read_lock(&lock->raw);
}

void _read_lock_irq(rwlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _raw_read_lock(&lock->raw);
}

unsigned long _read_lock_irqsave(rwlock_t *lock)
{
    unsigned long flags;
    local_irq_save(flags);
    _raw_read_lock(&lock->raw);
    return flags;
}

void _read_unlock(rwlock_t *lock)
{
    _raw_read_unlock(&lock->raw);
}

void _read_unlock_irq(rwlock_t *lock)
{
    _raw_read_unlock(&lock->raw);
    local_irq_enable();
}

void _read_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    _raw_read_unlock(&lock->raw);
    local_irq_restore(flags);
}

void _write_lock(rwlock_t *lock)
{
    _raw_write_lock(&lock->raw);
}

void _write_lock_irq(rwlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _raw_write_lock(&lock->raw);
}

unsigned long _write_lock_irqsave(rwlock_t *lock)
{
    unsigned long flags;
    local_irq_save(flags);
    _raw_write_lock(&lock->raw);
    return flags;
}

void _write_unlock(rwlock_t *lock)
{
    _raw_write_unlock(&lock->raw);
}

void _write_unlock_irq(rwlock_t *lock)
{
    _raw_write_unlock(&lock->raw);
    local_irq_enable();
}

void _write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    _raw_write_unlock(&lock->raw);
    local_irq_restore(flags);
}
