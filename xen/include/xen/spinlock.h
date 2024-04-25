#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <xen/nospec.h>
#include <xen/time.h>
#include <xen/types.h>

#include <asm/system.h>
#include <asm/spinlock.h>

#define SPINLOCK_CPU_BITS  16

#ifdef CONFIG_DEBUG_LOCKS
union lock_debug {
    uint32_t val;
#define LOCK_DEBUG_INITVAL 0xffffffffU
    struct {
        unsigned int cpu:SPINLOCK_CPU_BITS;
#define LOCK_DEBUG_PAD_BITS (30 - SPINLOCK_CPU_BITS)
        unsigned int :LOCK_DEBUG_PAD_BITS;
        bool irq_safe:1;
        bool unseen:1;
    };
};
#define LOCK_DEBUG_ { .val = LOCK_DEBUG_INITVAL }
void check_lock(union lock_debug *debug, bool try);
void lock_enter(const union lock_debug *debug);
void lock_exit(const union lock_debug *debug);
void spin_debug_enable(void);
void spin_debug_disable(void);
#else
union lock_debug { };
#define LOCK_DEBUG_ { }
#define check_lock(l, t) ((void)0)
#define lock_enter(l) ((void)0)
#define lock_exit(l) ((void)0)
#define spin_debug_enable() ((void)0)
#define spin_debug_disable() ((void)0)
#endif

#ifdef CONFIG_DEBUG_LOCK_PROFILE

#include <public/sysctl.h>

/*
    lock profiling on:

    Global locks which should be subject to profiling must be declared via
    DEFINE_[R]SPINLOCK.

    For locks in structures further measures are necessary:
    - the structure definition must include a profile_head with exactly this
      name:

      struct lock_profile_qhead   profile_head;

    - the single locks which are subject to profiling have to be initialized
      via

      [r]spin_lock_init_prof(ptr, lock);

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
    const char          *name;       /* lock name */
    union {
        struct spinlock *lock;       /* the lock itself */
        struct rspinlock *rlock;     /* the recursive lock itself */
    } ptr;
    uint64_t            lock_cnt;    /* # of complete locking ops */
    uint64_t            block_cnt:63; /* # of complete wait for lock */
    bool                is_rlock:1;  /* use rlock pointer */
    s_time_t            time_hold;   /* cumulated lock time */
    s_time_t            time_block;  /* cumulated wait time */
    s_time_t            time_locked; /* system time of last locking */
};

struct lock_profile_qhead {
    struct lock_profile_qhead *head_q; /* next head of this type */
    struct lock_profile       *elem_q; /* first element in q */
    int32_t                   idx;     /* index for printout */
};

#define LOCK_PROFILE_(lockname) { .name = #lockname, .ptr.lock = &(lockname), }
#define RLOCK_PROFILE_(lockname) { .name = #lockname,                         \
                                   .ptr.rlock = &(lockname),                  \
                                   .is_rlock = true, }
#define LOCK_PROFILE_PTR_(name)                                               \
    static struct lock_profile * const lock_profile__##name                   \
    __used_section(".lockprofile.data") =                                     \
    &lock_profile_data__##name
#define SPIN_LOCK_UNLOCKED_(x) {                                              \
    .debug = LOCK_DEBUG_,                                                     \
    .profile = x,                                                             \
}
#define RSPIN_LOCK_UNLOCKED_(x) {                                             \
    .recurse_cpu = SPINLOCK_NO_CPU,                                           \
    .debug = LOCK_DEBUG_,                                                     \
    .profile = x,                                                             \
}
#define SPIN_LOCK_UNLOCKED SPIN_LOCK_UNLOCKED_(NULL)
#define DEFINE_SPINLOCK(l)                                                    \
    spinlock_t l = SPIN_LOCK_UNLOCKED_(NULL);                                 \
    static struct lock_profile lock_profile_data__##l = LOCK_PROFILE_(l);     \
    LOCK_PROFILE_PTR_(l)
#define RSPIN_LOCK_UNLOCKED RSPIN_LOCK_UNLOCKED_(NULL)
#define DEFINE_RSPINLOCK(l)                                                   \
    rspinlock_t l = RSPIN_LOCK_UNLOCKED_(NULL);                               \
    static struct lock_profile lock_profile_data__##l = RLOCK_PROFILE_(l);    \
    LOCK_PROFILE_PTR_(l)

#define spin_lock_init_prof__(s, l, lockptr, locktype, isr)                   \
    do {                                                                      \
        struct lock_profile *prof;                                            \
        prof = xzalloc(struct lock_profile);                                  \
        (s)->l = (locktype)SPIN_LOCK_UNLOCKED_(prof);                         \
        if ( !prof )                                                          \
        {                                                                     \
            printk(XENLOG_WARNING                                             \
                   "lock profiling unavailable for %p(%d)'s %s\n",            \
                   s, (s)->profile_head.idx, #l);                             \
            break;                                                            \
        }                                                                     \
        prof->name = #l;                                                      \
        prof->ptr.lockptr = &(s)->l;                                          \
        prof->is_rlock = (isr);                                               \
        prof->next = (s)->profile_head.elem_q;                                \
        (s)->profile_head.elem_q = prof;                                      \
    } while( 0 )

#define spin_lock_init_prof(s, l)                                             \
    spin_lock_init_prof__(s, l, lock, spinlock_t, false)
#define rspin_lock_init_prof(s, l) do {                                       \
        spin_lock_init_prof__(s, l, rlock, rspinlock_t, true);                \
        (s)->l.recurse_cpu = SPINLOCK_NO_CPU;                                 \
        (s)->l.recurse_cnt = 0;                                               \
    } while (0)

void _lock_profile_register_struct(
    int32_t type, struct lock_profile_qhead *qhead, int32_t idx);
void _lock_profile_deregister_struct(int32_t type,
    struct lock_profile_qhead *qhead);

#define lock_profile_register_struct(type, ptr, idx)                          \
    _lock_profile_register_struct(type, &((ptr)->profile_head), idx)
#define lock_profile_deregister_struct(type, ptr)                             \
    _lock_profile_deregister_struct(type, &((ptr)->profile_head))

extern int spinlock_profile_control(struct xen_sysctl_lockprof_op *pc);
extern void cf_check spinlock_profile_printall(unsigned char key);
extern void cf_check spinlock_profile_reset(unsigned char key);

#else

struct lock_profile_qhead { };
struct lock_profile { };

#define SPIN_LOCK_UNLOCKED {                                                  \
    .debug = LOCK_DEBUG_,                                                     \
}
#define RSPIN_LOCK_UNLOCKED {                                                 \
    .recurse_cpu = SPINLOCK_NO_CPU,                                           \
    .debug = LOCK_DEBUG_,                                                     \
}
#define DEFINE_SPINLOCK(l) spinlock_t l = SPIN_LOCK_UNLOCKED
#define DEFINE_RSPINLOCK(l) rspinlock_t l = RSPIN_LOCK_UNLOCKED

#define spin_lock_init_prof(s, l) spin_lock_init(&((s)->l))
#define rspin_lock_init_prof(s, l) rspin_lock_init(&((s)->l))
#define lock_profile_register_struct(type, ptr, idx)
#define lock_profile_deregister_struct(type, ptr)
#define spinlock_profile_printall(key)

#endif

typedef union {
    uint32_t head_tail;
    struct {
        uint16_t head;
        uint16_t tail;
    };
} spinlock_tickets_t;

#define SPINLOCK_TICKET_INC { .head_tail = 0x10000, }

typedef struct spinlock {
    spinlock_tickets_t tickets;
    union lock_debug debug;
#ifdef CONFIG_DEBUG_LOCK_PROFILE
    struct lock_profile *profile;
#endif
} spinlock_t;

typedef struct rspinlock {
    spinlock_tickets_t tickets;
    uint16_t recurse_cpu;
#define SPINLOCK_NO_CPU        ((1u << SPINLOCK_CPU_BITS) - 1)
#define SPINLOCK_RECURSE_BITS  8
    uint8_t recurse_cnt;
#define SPINLOCK_MAX_RECURSE   15
    union lock_debug debug;
#ifdef CONFIG_DEBUG_LOCK_PROFILE
    struct lock_profile *profile;
#endif
} rspinlock_t;

#define spin_lock_init(l) (*(l) = (spinlock_t)SPIN_LOCK_UNLOCKED)
#define rspin_lock_init(l) (*(l) = (rspinlock_t)RSPIN_LOCK_UNLOCKED)

void _spin_lock(spinlock_t *lock);
void _spin_lock_cb(spinlock_t *lock, void (*cb)(void *data), void *data);
void _spin_lock_irq(spinlock_t *lock);
unsigned long _spin_lock_irqsave(spinlock_t *lock);

void _spin_unlock(spinlock_t *lock);
void _spin_unlock_irq(spinlock_t *lock);
void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);

bool _spin_is_locked(const spinlock_t *lock);
bool _spin_trylock(spinlock_t *lock);
void _spin_barrier(spinlock_t *lock);

static always_inline void spin_lock(spinlock_t *l)
{
    _spin_lock(l);
    block_lock_speculation();
}

static always_inline void spin_lock_cb(spinlock_t *l, void (*c)(void *data),
                                       void *d)
{
    _spin_lock_cb(l, c, d);
    block_lock_speculation();
}

static always_inline void spin_lock_irq(spinlock_t *l)
{
    _spin_lock_irq(l);
    block_lock_speculation();
}

#define spin_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _spin_lock_irqsave(l));                          \
        block_lock_speculation();                               \
    })

/* Conditionally take a spinlock in a speculation safe way. */
static always_inline void spin_lock_if(bool condition, spinlock_t *l)
{
    if ( condition )
        _spin_lock(l);
    block_lock_speculation();
}

#define spin_unlock(l)                _spin_unlock(l)
#define spin_unlock_irq(l)            _spin_unlock_irq(l)
#define spin_unlock_irqrestore(l, f)  _spin_unlock_irqrestore(l, f)

#define spin_is_locked(l)             _spin_is_locked(l)
#define spin_trylock(l)               lock_evaluate_nospec(_spin_trylock(l))

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
 * rspin_[un]lock(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * nrspin_[un]lock().
 * The nrspin_[un]lock() forms act the same way as normal spin_[un]lock()
 * calls, but operate on rspinlock_t locks. nrspin_lock() and rspin_lock()
 * calls are blocking to each other for a specific lock even on the same cpu.
 */
bool _rspin_trylock(rspinlock_t *lock);
void _rspin_lock(rspinlock_t *lock);
#define rspin_lock_irqsave(l, f)                                \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        (f) = _rspin_lock_irqsave(l);                           \
        block_lock_speculation();                               \
    })
unsigned long _rspin_lock_irqsave(rspinlock_t *lock);
void _rspin_unlock(rspinlock_t *lock);
void _rspin_unlock_irqrestore(rspinlock_t *lock, unsigned long flags);
bool _rspin_is_locked(const rspinlock_t *lock);
void _rspin_barrier(rspinlock_t *lock);

static always_inline void rspin_lock(rspinlock_t *lock)
{
    _rspin_lock(lock);
    block_lock_speculation();
}

#define rspin_trylock(l)              lock_evaluate_nospec(_rspin_trylock(l))
#define rspin_unlock(l)               _rspin_unlock(l)
#define rspin_unlock_irqrestore(l, f) _rspin_unlock_irqrestore(l, f)
#define rspin_barrier(l)              _rspin_barrier(l)
#define rspin_is_locked(l)            _rspin_is_locked(l)

bool _nrspin_trylock(rspinlock_t *lock);
void _nrspin_lock(rspinlock_t *lock);
#define nrspin_lock_irqsave(l, f)                               \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        (f) = _nrspin_lock_irqsave(l);                         \
        block_lock_speculation();                               \
    })
unsigned long _nrspin_lock_irqsave(rspinlock_t *lock);
void _nrspin_unlock(rspinlock_t *lock);
void _nrspin_lock_irq(rspinlock_t *lock);
void _nrspin_unlock_irq(rspinlock_t *lock);
void _nrspin_unlock_irqrestore(rspinlock_t *lock, unsigned long flags);

static always_inline void nrspin_lock(rspinlock_t *lock)
{
    _nrspin_lock(lock);
    block_lock_speculation();
}

static always_inline void nrspin_lock_irq(rspinlock_t *l)
{
    _nrspin_lock_irq(l);
    block_lock_speculation();
}

#define nrspin_trylock(l)              lock_evaluate_nospec(_nrspin_trylock(l))
#define nrspin_unlock(l)               _nrspin_unlock(l)
#define nrspin_unlock_irqrestore(l, f) _nrspin_unlock_irqrestore(l, f)
#define nrspin_unlock_irq(l)           _nrspin_unlock_irq(l)

#endif /* __SPINLOCK_H__ */
