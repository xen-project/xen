#include <xen/lib.h>
#include <xen/irq.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>
#include <xen/preempt.h>
#include <public/sysctl.h>
#include <asm/processor.h>
#include <asm/atomic.h>

#ifdef CONFIG_DEBUG_LOCKS

static atomic_t spin_debug __read_mostly = ATOMIC_INIT(0);

static void check_lock(union lock_debug *debug)
{
    bool irq_safe = !local_irq_is_enabled();

    BUILD_BUG_ON(LOCK_DEBUG_PAD_BITS <= 0);

    if ( unlikely(atomic_read(&spin_debug) <= 0) )
        return;

    /* A few places take liberties with this. */
    /* BUG_ON(in_irq() && !irq_safe); */

    /*
     * We partition locks into IRQ-safe (always held with IRQs disabled) and
     * IRQ-unsafe (always held with IRQs enabled) types. The convention for
     * every lock must be consistently observed else we can deadlock in
     * IRQ-context rendezvous functions (a rendezvous which gets every CPU
     * into IRQ context before any CPU is released from the rendezvous).
     * 
     * If we can mix IRQ-disabled and IRQ-enabled callers, the following can
     * happen:
     *  * Lock is held by CPU A, with IRQs enabled
     *  * CPU B is spinning on same lock, with IRQs disabled
     *  * Rendezvous starts -- CPU A takes interrupt and enters rendezbous spin
     *  * DEADLOCK -- CPU B will never enter rendezvous, CPU A will never exit
     *                the rendezvous, and will hence never release the lock.
     * 
     * To guard against this subtle bug we latch the IRQ safety of every
     * spinlock in the system, on first use.
     */
    if ( unlikely(debug->irq_safe != irq_safe) )
    {
        union lock_debug seen, new = { 0 };

        new.irq_safe = irq_safe;
        seen.val = cmpxchg(&debug->val, LOCK_DEBUG_INITVAL, new.val);

        if ( !seen.unseen && seen.irq_safe == !irq_safe )
        {
            printk("CHECKLOCK FAILURE: prev irqsafe: %d, curr irqsafe %d\n",
                   seen.irq_safe, irq_safe);
            BUG();
        }
    }
}

static void check_barrier(union lock_debug *debug)
{
    if ( unlikely(atomic_read(&spin_debug) <= 0) )
        return;

    /*
     * For a barrier, we have a relaxed IRQ-safety-consistency check.
     * 
     * It is always safe to spin at the barrier with IRQs enabled -- that does
     * not prevent us from entering an IRQ-context rendezvous, and nor are
     * we preventing anyone else from doing so (since we do not actually
     * acquire the lock during a barrier operation).
     * 
     * However, if we spin on an IRQ-unsafe lock with IRQs disabled then that
     * is clearly wrong, for the same reason outlined in check_lock() above.
     */
    BUG_ON(!local_irq_is_enabled() && !debug->irq_safe);
}

static void got_lock(union lock_debug *debug)
{
    debug->cpu = smp_processor_id();
}

static void rel_lock(union lock_debug *debug)
{
    if ( atomic_read(&spin_debug) > 0 )
        BUG_ON(debug->cpu != smp_processor_id());
    debug->cpu = SPINLOCK_NO_CPU;
}

void spin_debug_enable(void)
{
    atomic_inc(&spin_debug);
}

void spin_debug_disable(void)
{
    atomic_dec(&spin_debug);
}

#else /* CONFIG_DEBUG_LOCKS */

#define check_lock(l) ((void)0)
#define check_barrier(l) ((void)0)
#define got_lock(l) ((void)0)
#define rel_lock(l) ((void)0)

#endif

#ifdef CONFIG_DEBUG_LOCK_PROFILE

#define LOCK_PROFILE_REL                                                     \
    if (lock->profile)                                                       \
    {                                                                        \
        lock->profile->time_hold += NOW() - lock->profile->time_locked;      \
        lock->profile->lock_cnt++;                                           \
    }
#define LOCK_PROFILE_VAR    s_time_t block = 0
#define LOCK_PROFILE_BLOCK  block = block ? : NOW();
#define LOCK_PROFILE_GOT                                                     \
    if (lock->profile)                                                       \
    {                                                                        \
        lock->profile->time_locked = NOW();                                  \
        if (block)                                                           \
        {                                                                    \
            lock->profile->time_block += lock->profile->time_locked - block; \
            lock->profile->block_cnt++;                                      \
        }                                                                    \
    }

#else

#define LOCK_PROFILE_REL
#define LOCK_PROFILE_VAR
#define LOCK_PROFILE_BLOCK
#define LOCK_PROFILE_GOT

#endif

static always_inline spinlock_tickets_t observe_lock(spinlock_tickets_t *t)
{
    spinlock_tickets_t v;

    smp_rmb();
    v.head_tail = read_atomic(&t->head_tail);
    return v;
}

static always_inline u16 observe_head(spinlock_tickets_t *t)
{
    smp_rmb();
    return read_atomic(&t->head);
}

void inline _spin_lock_cb(spinlock_t *lock, void (*cb)(void *), void *data)
{
    spinlock_tickets_t tickets = SPINLOCK_TICKET_INC;
    LOCK_PROFILE_VAR;

    check_lock(&lock->debug);
    preempt_disable();
    tickets.head_tail = arch_fetch_and_add(&lock->tickets.head_tail,
                                           tickets.head_tail);
    while ( tickets.tail != observe_head(&lock->tickets) )
    {
        LOCK_PROFILE_BLOCK;
        if ( unlikely(cb) )
            cb(data);
        arch_lock_relax();
    }
    got_lock(&lock->debug);
    LOCK_PROFILE_GOT;
    arch_lock_acquire_barrier();
}

void _spin_lock(spinlock_t *lock)
{
     _spin_lock_cb(lock, NULL, NULL);
}

void _spin_lock_irq(spinlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _spin_lock(lock);
}

unsigned long _spin_lock_irqsave(spinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);
    _spin_lock(lock);
    return flags;
}

void _spin_unlock(spinlock_t *lock)
{
    arch_lock_release_barrier();
    LOCK_PROFILE_REL;
    rel_lock(&lock->debug);
    add_sized(&lock->tickets.head, 1);
    arch_lock_signal();
    preempt_enable();
}

void _spin_unlock_irq(spinlock_t *lock)
{
    _spin_unlock(lock);
    local_irq_enable();
}

void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
    _spin_unlock(lock);
    local_irq_restore(flags);
}

int _spin_is_locked(spinlock_t *lock)
{
    check_lock(&lock->debug);

    /*
     * Recursive locks may be locked by another CPU, yet we return
     * "false" here, making this function suitable only for use in
     * ASSERT()s and alike.
     */
    return lock->recurse_cpu == SPINLOCK_NO_CPU
           ? lock->tickets.head != lock->tickets.tail
           : lock->recurse_cpu == smp_processor_id();
}

int _spin_trylock(spinlock_t *lock)
{
    spinlock_tickets_t old, new;

    check_lock(&lock->debug);
    old = observe_lock(&lock->tickets);
    if ( old.head != old.tail )
        return 0;
    new = old;
    new.tail++;
    preempt_disable();
    if ( cmpxchg(&lock->tickets.head_tail,
                 old.head_tail, new.head_tail) != old.head_tail )
    {
        preempt_enable();
        return 0;
    }
    got_lock(&lock->debug);
#ifdef CONFIG_DEBUG_LOCK_PROFILE
    if (lock->profile)
        lock->profile->time_locked = NOW();
#endif
    /*
     * cmpxchg() is a full barrier so no need for an
     * arch_lock_acquire_barrier().
     */
    return 1;
}

void _spin_barrier(spinlock_t *lock)
{
    spinlock_tickets_t sample;
#ifdef CONFIG_DEBUG_LOCK_PROFILE
    s_time_t block = NOW();
#endif

    check_barrier(&lock->debug);
    smp_mb();
    sample = observe_lock(&lock->tickets);
    if ( sample.head != sample.tail )
    {
        while ( observe_head(&lock->tickets) == sample.head )
            arch_lock_relax();
#ifdef CONFIG_DEBUG_LOCK_PROFILE
        if ( lock->profile )
        {
            lock->profile->time_block += NOW() - block;
            lock->profile->block_cnt++;
        }
#endif
    }
    smp_mb();
}

int _spin_trylock_recursive(spinlock_t *lock)
{
    unsigned int cpu = smp_processor_id();

    /* Don't allow overflow of recurse_cpu field. */
    BUILD_BUG_ON(NR_CPUS > SPINLOCK_NO_CPU);
    BUILD_BUG_ON(SPINLOCK_RECURSE_BITS < 3);

    check_lock(&lock->debug);

    if ( likely(lock->recurse_cpu != cpu) )
    {
        if ( !spin_trylock(lock) )
            return 0;
        lock->recurse_cpu = cpu;
    }

    /* We support only fairly shallow recursion, else the counter overflows. */
    ASSERT(lock->recurse_cnt < SPINLOCK_MAX_RECURSE);
    lock->recurse_cnt++;

    return 1;
}

void _spin_lock_recursive(spinlock_t *lock)
{
    unsigned int cpu = smp_processor_id();

    if ( likely(lock->recurse_cpu != cpu) )
    {
        _spin_lock(lock);
        lock->recurse_cpu = cpu;
    }

    /* We support only fairly shallow recursion, else the counter overflows. */
    ASSERT(lock->recurse_cnt < SPINLOCK_MAX_RECURSE);
    lock->recurse_cnt++;
}

void _spin_unlock_recursive(spinlock_t *lock)
{
    if ( likely(--lock->recurse_cnt == 0) )
    {
        lock->recurse_cpu = SPINLOCK_NO_CPU;
        spin_unlock(lock);
    }
}

#ifdef CONFIG_DEBUG_LOCK_PROFILE

struct lock_profile_anc {
    struct lock_profile_qhead *head_q;   /* first head of this type */
    char                      *name;     /* descriptive string for print */
};

typedef void lock_profile_subfunc(
    struct lock_profile *, int32_t, int32_t, void *);

extern struct lock_profile *__lock_profile_start;
extern struct lock_profile *__lock_profile_end;

static s_time_t lock_profile_start;
static struct lock_profile_anc lock_profile_ancs[LOCKPROF_TYPE_N];
static struct lock_profile_qhead lock_profile_glb_q;
static spinlock_t lock_profile_lock = SPIN_LOCK_UNLOCKED;

static void spinlock_profile_iterate(lock_profile_subfunc *sub, void *par)
{
    int i;
    struct lock_profile_qhead *hq;
    struct lock_profile *eq;

    spin_lock(&lock_profile_lock);
    for ( i = 0; i < LOCKPROF_TYPE_N; i++ )
        for ( hq = lock_profile_ancs[i].head_q; hq; hq = hq->head_q )
            for ( eq = hq->elem_q; eq; eq = eq->next )
                sub(eq, i, hq->idx, par);
    spin_unlock(&lock_profile_lock);
}

static void spinlock_profile_print_elem(struct lock_profile *data,
    int32_t type, int32_t idx, void *par)
{
    struct spinlock *lock = data->lock;

    printk("%s ", lock_profile_ancs[type].name);
    if ( type != LOCKPROF_TYPE_GLOBAL )
        printk("%d ", idx);
    printk("%s: addr=%p, lockval=%08x, ", data->name, lock,
           lock->tickets.head_tail);
    if ( lock->debug.cpu == SPINLOCK_NO_CPU )
        printk("not locked\n");
    else
        printk("cpu=%d\n", lock->debug.cpu);
    printk("  lock:%" PRId64 "(%" PRI_stime "), block:%" PRId64 "(%" PRI_stime ")\n",
           data->lock_cnt, data->time_hold, data->block_cnt, data->time_block);
}

void spinlock_profile_printall(unsigned char key)
{
    s_time_t now = NOW();
    s_time_t diff;

    diff = now - lock_profile_start;
    printk("Xen lock profile info SHOW  (now = %"PRI_stime" total = "
           "%"PRI_stime")\n", now, diff);
    spinlock_profile_iterate(spinlock_profile_print_elem, NULL);
}

static void spinlock_profile_reset_elem(struct lock_profile *data,
    int32_t type, int32_t idx, void *par)
{
    data->lock_cnt = 0;
    data->block_cnt = 0;
    data->time_hold = 0;
    data->time_block = 0;
}

void spinlock_profile_reset(unsigned char key)
{
    s_time_t now = NOW();

    if ( key != '\0' )
        printk("Xen lock profile info RESET (now = %"PRI_stime")\n", now);
    lock_profile_start = now;
    spinlock_profile_iterate(spinlock_profile_reset_elem, NULL);
}

typedef struct {
    struct xen_sysctl_lockprof_op *pc;
    int                      rc;
} spinlock_profile_ucopy_t;

static void spinlock_profile_ucopy_elem(struct lock_profile *data,
    int32_t type, int32_t idx, void *par)
{
    spinlock_profile_ucopy_t *p = par;
    struct xen_sysctl_lockprof_data elem;

    if ( p->rc )
        return;

    if ( p->pc->nr_elem < p->pc->max_elem )
    {
        safe_strcpy(elem.name, data->name);
        elem.type = type;
        elem.idx = idx;
        elem.lock_cnt = data->lock_cnt;
        elem.block_cnt = data->block_cnt;
        elem.lock_time = data->time_hold;
        elem.block_time = data->time_block;
        if ( copy_to_guest_offset(p->pc->data, p->pc->nr_elem, &elem, 1) )
            p->rc = -EFAULT;
    }

    if ( !p->rc )
        p->pc->nr_elem++;
}

/* Dom0 control of lock profiling */
int spinlock_profile_control(struct xen_sysctl_lockprof_op *pc)
{
    int rc = 0;
    spinlock_profile_ucopy_t par;

    switch ( pc->cmd )
    {
    case XEN_SYSCTL_LOCKPROF_reset:
        spinlock_profile_reset('\0');
        break;
    case XEN_SYSCTL_LOCKPROF_query:
        pc->nr_elem = 0;
        par.rc = 0;
        par.pc = pc;
        spinlock_profile_iterate(spinlock_profile_ucopy_elem, &par);
        pc->time = NOW() - lock_profile_start;
        rc = par.rc;
        break;
    default:
        rc = -EINVAL;
        break;
    }

    return rc;
}

void _lock_profile_register_struct(
    int32_t type, struct lock_profile_qhead *qhead, int32_t idx, char *name)
{
    qhead->idx = idx;
    spin_lock(&lock_profile_lock);
    qhead->head_q = lock_profile_ancs[type].head_q;
    lock_profile_ancs[type].head_q = qhead;
    lock_profile_ancs[type].name = name;
    spin_unlock(&lock_profile_lock);
}

void _lock_profile_deregister_struct(
    int32_t type, struct lock_profile_qhead *qhead)
{
    struct lock_profile_qhead **q;

    spin_lock(&lock_profile_lock);
    for ( q = &lock_profile_ancs[type].head_q; *q; q = &(*q)->head_q )
    {
        if ( *q == qhead )
        {
            *q = qhead->head_q;
            break;
        }
    }
    spin_unlock(&lock_profile_lock);
}

static int __init lock_prof_init(void)
{
    struct lock_profile **q;

    for ( q = &__lock_profile_start; q < &__lock_profile_end; q++ )
    {
        (*q)->next = lock_profile_glb_q.elem_q;
        lock_profile_glb_q.elem_q = *q;
        (*q)->lock->profile = *q;
    }

    _lock_profile_register_struct(
        LOCKPROF_TYPE_GLOBAL, &lock_profile_glb_q,
        0, "Global lock");

    return 0;
}
__initcall(lock_prof_init);

#endif /* CONFIG_DEBUG_LOCK_PROFILE */
