#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <asm/system.h>
#include <asm/spinlock.h>
#include <asm/types.h>

#define SPINLOCK_CPU_BITS  12

#ifdef CONFIG_DEBUG_LOCKS
union lock_debug {
    uint16_t val;
#define LOCK_DEBUG_INITVAL 0xffff
    struct {
        uint16_t cpu:SPINLOCK_CPU_BITS;
#define LOCK_DEBUG_PAD_BITS (14 - SPINLOCK_CPU_BITS)
        uint16_t :LOCK_DEBUG_PAD_BITS;
        bool irq_safe:1;
        bool unseen:1;
    };
};
#define _LOCK_DEBUG { LOCK_DEBUG_INITVAL }
void spin_debug_enable(void);
void spin_debug_disable(void);
#else
union lock_debug { };
#define _LOCK_DEBUG { }
#define spin_debug_enable() ((void)0)
#define spin_debug_disable() ((void)0)
#endif

#ifdef CONFIG_LOCK_PROFILE

#include <public/sysctl.h>

/*
    lock profiling on:

    Global locks which should be subject to profiling must be declared via
    DEFINE_SPINLOCK.

    For locks in structures further measures are necessary:
    - the structure definition must include a profile_head with exactly this
      name:

      struct lock_profile_qhead   profile_head;

    - the single locks which are subject to profiling have to be initialized
      via

      spin_lock_init_prof(ptr, lock);

      with ptr being the main structure pointer and lock the spinlock field

    - each structure has to be added to profiling with

      lock_profile_register_struct(type, ptr, idx, print);

      with:
        type:  something like LOCKPROF_TYPE_PERDOM
        ptr:   pointer to the structure
        idx:   index of that structure, e.g. domid
        print: descriptive string like "domain"

    - removing of a structure is done via

      lock_profile_deregister_struct(type, ptr);
*/

struct spinlock;

struct lock_profile {
    struct lock_profile *next;       /* forward link */
    char                *name;       /* lock name */
    struct spinlock     *lock;       /* the lock itself */
    u64                 lock_cnt;    /* # of complete locking ops */
    u64                 block_cnt;   /* # of complete wait for lock */
    s64                 time_hold;   /* cumulated lock time */
    s64                 time_block;  /* cumulated wait time */
    s64                 time_locked; /* system time of last locking */
};

struct lock_profile_qhead {
    struct lock_profile_qhead *head_q; /* next head of this type */
    struct lock_profile       *elem_q; /* first element in q */
    int32_t                   idx;     /* index for printout */
};

#define _LOCK_PROFILE(name) { 0, #name, &name, 0, 0, 0, 0, 0 }
#define _LOCK_PROFILE_PTR(name)                                               \
    static struct lock_profile * const __lock_profile_##name                  \
    __used_section(".lockprofile.data") =                                     \
    &__lock_profile_data_##name
#define _SPIN_LOCK_UNLOCKED(x) { { 0 }, SPINLOCK_NO_CPU, 0, _LOCK_DEBUG, x }
#define SPIN_LOCK_UNLOCKED _SPIN_LOCK_UNLOCKED(NULL)
#define DEFINE_SPINLOCK(l)                                                    \
    spinlock_t l = _SPIN_LOCK_UNLOCKED(NULL);                                 \
    static struct lock_profile __lock_profile_data_##l = _LOCK_PROFILE(l);    \
    _LOCK_PROFILE_PTR(l)

#define spin_lock_init_prof(s, l)                                             \
    do {                                                                      \
        struct lock_profile *prof;                                            \
        prof = xzalloc(struct lock_profile);                                  \
        if (!prof) break;                                                     \
        prof->name = #l;                                                      \
        prof->lock = &(s)->l;                                                 \
        (s)->l = (spinlock_t)_SPIN_LOCK_UNLOCKED(prof);                       \
        prof->next = (s)->profile_head.elem_q;                                \
        (s)->profile_head.elem_q = prof;                                      \
    } while(0)

void _lock_profile_register_struct(
    int32_t, struct lock_profile_qhead *, int32_t, char *);
void _lock_profile_deregister_struct(int32_t, struct lock_profile_qhead *);

#define lock_profile_register_struct(type, ptr, idx, print)                   \
    _lock_profile_register_struct(type, &((ptr)->profile_head), idx, print)
#define lock_profile_deregister_struct(type, ptr)                             \
    _lock_profile_deregister_struct(type, &((ptr)->profile_head))

extern int spinlock_profile_control(struct xen_sysctl_lockprof_op *pc);
extern void spinlock_profile_printall(unsigned char key);
extern void spinlock_profile_reset(unsigned char key);

#else

struct lock_profile_qhead { };

#define SPIN_LOCK_UNLOCKED { { 0 }, SPINLOCK_NO_CPU, 0, _LOCK_DEBUG }
#define DEFINE_SPINLOCK(l) spinlock_t l = SPIN_LOCK_UNLOCKED

#define spin_lock_init_prof(s, l) spin_lock_init(&((s)->l))
#define lock_profile_register_struct(type, ptr, idx, print)
#define lock_profile_deregister_struct(type, ptr)

#endif

typedef union {
    u32 head_tail;
    struct {
        u16 head;
        u16 tail;
    };
} spinlock_tickets_t;

#define SPINLOCK_TICKET_INC { .head_tail = 0x10000, }

typedef struct spinlock {
    spinlock_tickets_t tickets;
    u16 recurse_cpu:SPINLOCK_CPU_BITS;
#define SPINLOCK_NO_CPU        ((1u << SPINLOCK_CPU_BITS) - 1)
#define SPINLOCK_RECURSE_BITS  (16 - SPINLOCK_CPU_BITS)
    u16 recurse_cnt:SPINLOCK_RECURSE_BITS;
#define SPINLOCK_MAX_RECURSE   ((1u << SPINLOCK_RECURSE_BITS) - 1)
    union lock_debug debug;
#ifdef CONFIG_LOCK_PROFILE
    struct lock_profile *profile;
#endif
} spinlock_t;


#define spin_lock_init(l) (*(l) = (spinlock_t)SPIN_LOCK_UNLOCKED)

void _spin_lock(spinlock_t *lock);
void _spin_lock_cb(spinlock_t *lock, void (*cond)(void *), void *data);
void _spin_lock_irq(spinlock_t *lock);
unsigned long _spin_lock_irqsave(spinlock_t *lock);

void _spin_unlock(spinlock_t *lock);
void _spin_unlock_irq(spinlock_t *lock);
void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);

int _spin_is_locked(spinlock_t *lock);
int _spin_trylock(spinlock_t *lock);
void _spin_barrier(spinlock_t *lock);

int _spin_trylock_recursive(spinlock_t *lock);
void _spin_lock_recursive(spinlock_t *lock);
void _spin_unlock_recursive(spinlock_t *lock);

#define spin_lock(l)                  _spin_lock(l)
#define spin_lock_cb(l, c, d)         _spin_lock_cb(l, c, d)
#define spin_lock_irq(l)              _spin_lock_irq(l)
#define spin_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _spin_lock_irqsave(l));                          \
    })

#define spin_unlock(l)                _spin_unlock(l)
#define spin_unlock_irq(l)            _spin_unlock_irq(l)
#define spin_unlock_irqrestore(l, f)  _spin_unlock_irqrestore(l, f)

#define spin_is_locked(l)             _spin_is_locked(l)
#define spin_trylock(l)               _spin_trylock(l)

#define spin_trylock_irqsave(lock, flags)       \
({                                              \
    local_irq_save(flags);                      \
    spin_trylock(lock) ?                        \
    1 : ({ local_irq_restore(flags); 0; });     \
})

#define spin_lock_kick(l)             arch_lock_signal_wmb()

/* Ensure a lock is quiescent between two critical operations. */
#define spin_barrier(l)               _spin_barrier(l)

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */
#define spin_trylock_recursive(l)     _spin_trylock_recursive(l)
#define spin_lock_recursive(l)        _spin_lock_recursive(l)
#define spin_unlock_recursive(l)      _spin_unlock_recursive(l)

#endif /* __SPINLOCK_H__ */
