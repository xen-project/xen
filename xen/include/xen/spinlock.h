#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <xen/config.h>
#include <asm/system.h>

#define spin_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); spin_lock(lock); } while ( 0 )
#define spin_lock_irq(lock) \
    do { local_irq_disable(); spin_lock(lock); } while ( 0 )

#define read_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); read_lock(lock); } while ( 0 )
#define read_lock_irq(lock) \
    do { local_irq_disable(); read_lock(lock); } while ( 0 )

#define write_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); write_lock(lock); } while ( 0 )
#define write_lock_irq(lock) \
    do { local_irq_disable(); write_lock(lock); } while ( 0 )

#define spin_unlock_irqrestore(lock, flags) \
    do { spin_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define spin_unlock_irq(lock) \
    do { spin_unlock(lock); local_irq_enable(); } while ( 0 )

#define read_unlock_irqrestore(lock, flags) \
    do { read_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define read_unlock_irq(lock) \
    do { read_unlock(lock); local_irq_enable(); } while ( 0 )

#define write_unlock_irqrestore(lock, flags) \
    do { write_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define write_unlock_irq(lock) \
    do { write_unlock(lock); local_irq_enable(); } while ( 0 )

#ifdef CONFIG_SMP

#include <asm/spinlock.h>

#else

#if (__GNUC__ > 2)
typedef struct { } spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { }
#else
typedef struct { int gcc_is_buggy; } spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { 0 }
#endif

#define spin_lock_init(lock)             do { } while(0)
#define spin_is_locked(lock)             (0)
#define _raw_spin_lock(lock)             (void)(lock)
#define _raw_spin_trylock(lock)          ({1; })
#define _raw_spin_unlock(lock)           do { } while(0)
#define _raw_spin_lock_recursive(lock)   do { } while(0)
#define _raw_spin_unlock_recursive(lock) do { } while(0)

#if (__GNUC__ > 2)
typedef struct { } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { }
#else
typedef struct { int gcc_is_buggy; } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { 0 }
#endif

#define rwlock_init(lock)            do { } while(0)
#define _raw_read_lock(lock)         (void)(lock) /* Not "unused variable". */
#define _raw_read_unlock(lock)       do { } while(0)
#define _raw_write_lock(lock)        (void)(lock) /* Not "unused variable". */
#define _raw_write_unlock(lock)      do { } while(0)

#endif

#ifndef NDEBUG

extern void criticalregion_enter(void);
extern void criticalregion_exit(void);
extern void ASSERT_no_criticalregion(void);
extern void disable_criticalregion_checking(void);

#define spin_lock(_lock) \
    do { criticalregion_enter(); _raw_spin_lock(_lock); } while (0)
#define spin_unlock(_lock) \
    do { _raw_spin_unlock(_lock); criticalregion_exit(); } while (0)
#define spin_lock_recursive(_lock) \
    do { criticalregion_enter(); _raw_spin_lock_recursive(_lock); } while (0)
#define spin_unlock_recursive(_lock) \
    do { _raw_spin_unlock_recursive(_lock); criticalregion_exit(); } while (0)
#define read_lock(_lock) \
    do { criticalregion_enter(); _raw_read_lock(_lock); } while (0)
#define read_unlock(_lock) \
    do { _raw_read_unlock(_lock); criticalregion_exit(); } while (0)
#define write_lock(_lock) \
    do { criticalregion_enter(); _raw_write_lock(_lock); } while (0)
#define write_unlock(_lock) \
    do { _raw_write_unlock(_lock); criticalregion_exit(); } while (0)

static inline int spin_trylock(spinlock_t *lock)
{
    criticalregion_enter();
    if ( !_raw_spin_trylock(lock) )
    {
        criticalregion_exit();
        return 0;
    }
    return 1;
}

#else

#define ASSERT_no_criticalregion()        ((void)0)
#define disable_criticalregion_checking() ((void)0)

#define spin_lock(_lock)             _raw_spin_lock(_lock)
#define spin_trylock(_lock)          _raw_spin_trylock(_lock)
#define spin_unlock(_lock)           _raw_spin_unlock(_lock)
#define spin_lock_recursive(_lock)   _raw_spin_lock_recursive(_lock)
#define spin_unlock_recursive(_lock) _raw_spin_unlock_recursive(_lock)
#define read_lock(_lock)             _raw_read_lock(_lock)
#define read_unlock(_lock)           _raw_read_unlock(_lock)
#define write_lock(_lock)            _raw_write_lock(_lock)
#define write_unlock(_lock)          _raw_write_unlock(_lock)

#endif

#endif /* __SPINLOCK_H__ */
