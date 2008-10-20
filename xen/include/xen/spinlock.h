#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <xen/config.h>
#include <asm/system.h>
#include <asm/spinlock.h>

typedef struct {
    raw_spinlock_t raw;
    u16 recurse_cpu:12;
    u16 recurse_cnt:4;
} spinlock_t;

#define SPIN_LOCK_UNLOCKED { _RAW_SPIN_LOCK_UNLOCKED, 0xfffu, 0 }
#define DEFINE_SPINLOCK(l) spinlock_t l = SPIN_LOCK_UNLOCKED
#define spin_lock_init(l) (*(l) = (spinlock_t)SPIN_LOCK_UNLOCKED)

typedef struct {
    raw_rwlock_t raw;
} rwlock_t;

#define RW_LOCK_UNLOCKED { _RAW_RW_LOCK_UNLOCKED }
#define DEFINE_RWLOCK(l) rwlock_t l = RW_LOCK_UNLOCKED
#define rwlock_init(l) (*(l) = (rwlock_t)RW_LOCK_UNLOCKED)

void _spin_lock(spinlock_t *lock);
void _spin_lock_irq(spinlock_t *lock);
unsigned long _spin_lock_irqsave(spinlock_t *lock);

void _spin_unlock(spinlock_t *lock);
void _spin_unlock_irq(spinlock_t *lock);
void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);

int _spin_is_locked(spinlock_t *lock);
int _spin_trylock(spinlock_t *lock);
void _spin_barrier(spinlock_t *lock);

void _spin_lock_recursive(spinlock_t *lock);
void _spin_unlock_recursive(spinlock_t *lock);

void _read_lock(rwlock_t *lock);
void _read_lock_irq(rwlock_t *lock);
unsigned long _read_lock_irqsave(rwlock_t *lock);

void _read_unlock(rwlock_t *lock);
void _read_unlock_irq(rwlock_t *lock);
void _read_unlock_irqrestore(rwlock_t *lock, unsigned long flags);

void _write_lock(rwlock_t *lock);
void _write_lock_irq(rwlock_t *lock);
unsigned long _write_lock_irqsave(rwlock_t *lock);

void _write_unlock(rwlock_t *lock);
void _write_unlock_irq(rwlock_t *lock);
void _write_unlock_irqrestore(rwlock_t *lock, unsigned long flags);

#define spin_lock(l)                  _spin_lock(l)
#define spin_lock_irq(l)              _spin_lock_irq(l)
#define spin_lock_irqsave(l, f)       ((f) = _spin_lock_irqsave(l))

#define spin_unlock(l)                _spin_unlock(l)
#define spin_unlock_irq(l)            _spin_unlock_irq(l)
#define spin_unlock_irqrestore(l, f)  _spin_unlock_irqrestore(l, f)

#define spin_is_locked(l)             _raw_spin_is_locked(&(l)->raw)
#define spin_trylock(l)               _spin_trylock(l)

/* Ensure a lock is quiescent between two critical operations. */
#define spin_barrier(l)               _spin_barrier(l)

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */
#define spin_lock_recursive(l)        _spin_lock_recursive(l)
#define spin_unlock_recursive(l)      _spin_unlock_recursive(l)

#define read_lock(l)                  _read_lock(l)
#define read_lock_irq(l)              _read_lock_irq(l)
#define read_lock_irqsave(l, f)       ((f) = _read_lock_irqsave(l))

#define read_unlock(l)                _read_unlock(l)
#define read_unlock_irq(l)            _read_unlock_irq(l)
#define read_unlock_irqrestore(l, f)  _read_unlock_irqrestore(l, f)

#define write_lock(l)                 _write_lock(l)
#define write_lock_irq(l)             _write_lock_irq(l)
#define write_lock_irqsave(l, f)      ((f) = _write_lock_irqsave(l))

#define write_unlock(l)               _write_unlock(l)
#define write_unlock_irq(l)           _write_unlock_irq(l)
#define write_unlock_irqrestore(l, f) _write_unlock_irqrestore(l, f)

#endif /* __SPINLOCK_H__ */
