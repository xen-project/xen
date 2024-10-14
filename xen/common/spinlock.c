#include <xen/cpu.h>
#include <xen/lib.h>
#include <xen/irq.h>
#include <xen/notifier.h>
#include <xen/param.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/sections.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>
#include <xen/preempt.h>
#include <public/sysctl.h>
#include <asm/processor.h>
#include <asm/atomic.h>

#ifdef CONFIG_DEBUG_LOCKS

/* Max. number of entries in locks_taken array. */
static unsigned int __ro_after_init lock_depth_size = 64;
integer_param("lock-depth-size", lock_depth_size);

/*
 * Array of addresses of taken locks.
 * nr_locks_taken is the index after the last entry. As locks tend to be
 * nested cleanly, when freeing a lock it will probably be the one before
 * nr_locks_taken, and new entries can be entered at that index. It is fine
 * for a lock to be released out of order, though.
 */
static DEFINE_PER_CPU(const union lock_debug **, locks_taken);
static DEFINE_PER_CPU(unsigned int, nr_locks_taken);
static bool __read_mostly max_depth_reached;

static atomic_t spin_debug __read_mostly = ATOMIC_INIT(0);

static int cf_check cpu_lockdebug_callback(struct notifier_block *nfb,
                                           unsigned long action,
                                           void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        if ( !per_cpu(locks_taken, cpu) )
            per_cpu(locks_taken, cpu) = xzalloc_array(const union lock_debug *,
                                                      lock_depth_size);
        if ( !per_cpu(locks_taken, cpu) )
            printk(XENLOG_WARNING
                   "cpu %u: failed to allocate lock recursion check area\n",
                   cpu);
        break;

    case CPU_UP_CANCELED:
    case CPU_DEAD:
        XFREE(per_cpu(locks_taken, cpu));
        break;

    default:
        break;
    }

    return 0;
}

static struct notifier_block cpu_lockdebug_nfb = {
    .notifier_call = cpu_lockdebug_callback,
};

static int __init cf_check lockdebug_init(void)
{
    if ( lock_depth_size )
    {
        register_cpu_notifier(&cpu_lockdebug_nfb);
        cpu_lockdebug_callback(&cpu_lockdebug_nfb, CPU_UP_PREPARE,
                               (void *)(unsigned long)smp_processor_id());
    }

    return 0;
}
presmp_initcall(lockdebug_init);

void check_lock(union lock_debug *debug, bool try)
{
    bool irq_safe = !local_irq_is_enabled();
    unsigned int cpu = smp_processor_id();
    const union lock_debug *const *taken = per_cpu(locks_taken, cpu);
    unsigned int nr_taken = per_cpu(nr_locks_taken, cpu);
    unsigned int i;

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
     *
     * A spin_trylock() with interrupts off is always fine, as this can't
     * block and above deadlock scenario doesn't apply.
     */
    if ( try && irq_safe )
        return;

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

    if ( try )
        return;

    for ( i = 0; i < nr_taken; i++ )
        if ( taken[i] == debug )
        {
            printk("CHECKLOCK FAILURE: lock at %p taken recursively\n", debug);
            BUG();
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

void lock_enter(const union lock_debug *debug)
{
    unsigned int cpu = smp_processor_id();
    const union lock_debug **taken = per_cpu(locks_taken, cpu);
    unsigned int *nr_taken = &per_cpu(nr_locks_taken, cpu);
    unsigned long flags;

    if ( !taken )
        return;

    local_irq_save(flags);

    if ( *nr_taken < lock_depth_size )
        taken[(*nr_taken)++] = debug;
    else if ( !max_depth_reached )
    {
        max_depth_reached = true;
        printk("CHECKLOCK max lock depth %u reached!\n", lock_depth_size);
        WARN();
    }

    local_irq_restore(flags);
}

void lock_exit(const union lock_debug *debug)
{
    unsigned int cpu = smp_processor_id();
    const union lock_debug **taken = per_cpu(locks_taken, cpu);
    unsigned int *nr_taken = &per_cpu(nr_locks_taken, cpu);
    unsigned int i;
    unsigned long flags;

    if ( !taken )
        return;

    local_irq_save(flags);

    for ( i = *nr_taken; i > 0; i-- )
    {
        if ( taken[i - 1] == debug )
        {
            memmove(taken + i - 1, taken + i,
                    (*nr_taken - i) * sizeof(*taken));
            (*nr_taken)--;
            taken[*nr_taken] = NULL;

            local_irq_restore(flags);

            return;
        }
    }

    if ( !max_depth_reached )
    {
        printk("CHECKLOCK released lock at %p not recorded!\n", debug);
        WARN();
    }

    local_irq_restore(flags);
}

static void got_lock(union lock_debug *debug)
{
    debug->cpu = smp_processor_id();

    lock_enter(debug);
}

static void rel_lock(union lock_debug *debug)
{
    if ( atomic_read(&spin_debug) > 0 )
        BUG_ON(debug->cpu != smp_processor_id());

    lock_exit(debug);

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

#define check_barrier(l) ((void)0)
#define got_lock(l) ((void)0)
#define rel_lock(l) ((void)0)

#endif

#ifdef CONFIG_DEBUG_LOCK_PROFILE

#define LOCK_PROFILE_PAR lock->profile
#define LOCK_PROFILE_REL                                                     \
    if ( profile )                                                           \
    {                                                                        \
        profile->time_hold += NOW() - profile->time_locked;                  \
        profile->lock_cnt++;                                                 \
    }
#define LOCK_PROFILE_VAR(var, val)    s_time_t var = (val)
#define LOCK_PROFILE_BLOCK(var)       (var) = (var) ? : NOW()
#define LOCK_PROFILE_BLKACC(tst, val)                                        \
    if ( tst )                                                               \
    {                                                                        \
        profile->time_block += profile->time_locked - (val);                 \
        profile->block_cnt++;                                                \
    }
#define LOCK_PROFILE_GOT(val)                                                \
    if ( profile )                                                           \
    {                                                                        \
        profile->time_locked = NOW();                                        \
        LOCK_PROFILE_BLKACC(val, val);                                       \
    }

#else

#define LOCK_PROFILE_PAR NULL
#define LOCK_PROFILE_REL
#define LOCK_PROFILE_VAR(var, val)
#define LOCK_PROFILE_BLOCK(var)
#define LOCK_PROFILE_BLKACC(tst, val)
#define LOCK_PROFILE_GOT(val)

#endif

static always_inline spinlock_tickets_t observe_lock(spinlock_tickets_t *t)
{
    spinlock_tickets_t v;

    smp_rmb();
    v.head_tail = read_atomic(&t->head_tail);
    return v;
}

static always_inline uint16_t observe_head(const spinlock_tickets_t *t)
{
    smp_rmb();
    return read_atomic(&t->head);
}

static void always_inline spin_lock_common(spinlock_tickets_t *t,
                                           union lock_debug *debug,
                                           struct lock_profile *profile,
                                           void (*cb)(void *data), void *data)
{
    spinlock_tickets_t tickets = SPINLOCK_TICKET_INC;
    LOCK_PROFILE_VAR(block, 0);

    check_lock(debug, false);
    preempt_disable();
    tickets.head_tail = arch_fetch_and_add(&t->head_tail, tickets.head_tail);
    while ( tickets.tail != observe_head(t) )
    {
        LOCK_PROFILE_BLOCK(block);
        if ( cb )
            cb(data);
        arch_lock_relax();
    }
    arch_lock_acquire_barrier();
    got_lock(debug);
    LOCK_PROFILE_GOT(block);
}

void _spin_lock(spinlock_t *lock)
{
    spin_lock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR, NULL,
                     NULL);
}

void _spin_lock_cb(spinlock_t *lock, void (*cb)(void *data), void *data)
{
    spin_lock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR, cb, data);
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

static void always_inline spin_unlock_common(spinlock_tickets_t *t,
                                             union lock_debug *debug,
                                             struct lock_profile *profile)
{
    LOCK_PROFILE_REL;
    rel_lock(debug);
    arch_lock_release_barrier();
    add_sized(&t->head, 1);
    arch_lock_signal();
    preempt_enable();
}

void _spin_unlock(spinlock_t *lock)
{
    spin_unlock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
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

static bool always_inline spin_is_locked_common(const spinlock_tickets_t *t)
{
    return t->head != t->tail;
}

bool _spin_is_locked(const spinlock_t *lock)
{
    /*
     * This function is suitable only for use in ASSERT()s and alike, as it
     * doesn't tell _who_ is holding the lock.
     */
    return spin_is_locked_common(&lock->tickets);
}

static bool always_inline spin_trylock_common(spinlock_tickets_t *t,
                                              union lock_debug *debug,
                                              struct lock_profile *profile)
{
    spinlock_tickets_t old, new;

    preempt_disable();
    check_lock(debug, true);
    old = observe_lock(t);
    if ( old.head != old.tail )
    {
        preempt_enable();
        return false;
    }
    new = old;
    new.tail++;
    if ( cmpxchg(&t->head_tail, old.head_tail, new.head_tail) != old.head_tail )
    {
        preempt_enable();
        return false;
    }
    /*
     * cmpxchg() is a full barrier so no need for an
     * arch_lock_acquire_barrier().
     */
    got_lock(debug);
    LOCK_PROFILE_GOT(0);

    return true;
}

bool _spin_trylock(spinlock_t *lock)
{
    return spin_trylock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
}

static void always_inline spin_barrier_common(spinlock_tickets_t *t,
                                              union lock_debug *debug,
                                              struct lock_profile *profile)
{
    spinlock_tickets_t sample;
    LOCK_PROFILE_VAR(block, NOW());

    check_barrier(debug);
    smp_mb();
    sample = observe_lock(t);
    if ( sample.head != sample.tail )
    {
        while ( observe_head(t) == sample.head )
            arch_lock_relax();
        LOCK_PROFILE_BLKACC(profile, block);
    }
    smp_mb();
}

void _spin_barrier(spinlock_t *lock)
{
    spin_barrier_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
}

bool _rspin_is_locked(const rspinlock_t *lock)
{
    /*
     * Recursive locks may be locked by another CPU, yet we return
     * "false" here, making this function suitable only for use in
     * ASSERT()s and alike.
     */
    return lock->recurse_cpu == SPINLOCK_NO_CPU
           ? spin_is_locked_common(&lock->tickets)
           : lock->recurse_cpu == smp_processor_id();
}

void _rspin_barrier(rspinlock_t *lock)
{
    spin_barrier_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
}

bool _rspin_trylock(rspinlock_t *lock)
{
    unsigned int cpu = smp_processor_id();

    /* Don't allow overflow of recurse_cpu field. */
    BUILD_BUG_ON(NR_CPUS > SPINLOCK_NO_CPU);
    BUILD_BUG_ON(SPINLOCK_CPU_BITS > sizeof(lock->recurse_cpu) * 8);
    BUILD_BUG_ON(SPINLOCK_RECURSE_BITS < 3);
    BUILD_BUG_ON(SPINLOCK_MAX_RECURSE > ((1u << SPINLOCK_RECURSE_BITS) - 1));

    check_lock(&lock->debug, true);

    if ( likely(lock->recurse_cpu != cpu) )
    {
        if ( !spin_trylock_common(&lock->tickets, &lock->debug,
                                  LOCK_PROFILE_PAR) )
            return false;
        lock->recurse_cpu = cpu;
    }

    /* We support only fairly shallow recursion, else the counter overflows. */
    ASSERT(lock->recurse_cnt < SPINLOCK_MAX_RECURSE);
    lock->recurse_cnt++;

    return true;
}

void _rspin_lock(rspinlock_t *lock)
{
    unsigned int cpu = smp_processor_id();

    if ( likely(lock->recurse_cpu != cpu) )
    {
        spin_lock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR, NULL,
                         NULL);
        lock->recurse_cpu = cpu;
    }

    /* We support only fairly shallow recursion, else the counter overflows. */
    ASSERT(lock->recurse_cnt < SPINLOCK_MAX_RECURSE);
    lock->recurse_cnt++;
}

unsigned long _rspin_lock_irqsave(rspinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);
    _rspin_lock(lock);

    return flags;
}

void _rspin_unlock(rspinlock_t *lock)
{
    if ( likely(--lock->recurse_cnt == 0) )
    {
        lock->recurse_cpu = SPINLOCK_NO_CPU;
        spin_unlock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
    }
}

void _rspin_unlock_irqrestore(rspinlock_t *lock, unsigned long flags)
{
    _rspin_unlock(lock);
    local_irq_restore(flags);
}

bool _nrspin_trylock(rspinlock_t *lock)
{
    check_lock(&lock->debug, true);

    if ( unlikely(lock->recurse_cpu != SPINLOCK_NO_CPU) )
        return false;

    return spin_trylock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
}

void _nrspin_lock(rspinlock_t *lock)
{
    spin_lock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR, NULL,
                     NULL);
}

void _nrspin_unlock(rspinlock_t *lock)
{
    spin_unlock_common(&lock->tickets, &lock->debug, LOCK_PROFILE_PAR);
}

void _nrspin_lock_irq(rspinlock_t *lock)
{
    ASSERT(local_irq_is_enabled());
    local_irq_disable();
    _nrspin_lock(lock);
}

void _nrspin_unlock_irq(rspinlock_t *lock)
{
    _nrspin_unlock(lock);
    local_irq_enable();
}

unsigned long _nrspin_lock_irqsave(rspinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);
    _nrspin_lock(lock);

    return flags;
}

void _nrspin_unlock_irqrestore(rspinlock_t *lock, unsigned long flags)
{
    _nrspin_unlock(lock);
    local_irq_restore(flags);
}

#ifdef CONFIG_DEBUG_LOCK_PROFILE

struct lock_profile_anc {
    struct lock_profile_qhead *head_q;   /* first head of this type */
    const char                *name;     /* descriptive string for print */
};

typedef void lock_profile_subfunc(struct lock_profile *data, int32_t type,
    int32_t idx, void *par);

static s_time_t lock_profile_start;
static struct lock_profile_anc lock_profile_ancs[] = {
    [LOCKPROF_TYPE_GLOBAL] = { .name = "Global" },
    [LOCKPROF_TYPE_PERDOM] = { .name = "Domain" },
};
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

static void cf_check spinlock_profile_print_elem(struct lock_profile *data,
    int32_t type, int32_t idx, void *par)
{
    unsigned int cpu;
    unsigned int lockval;

    if ( data->is_rlock )
    {
        cpu = data->ptr.rlock->debug.cpu;
        lockval = data->ptr.rlock->tickets.head_tail;
    }
    else
    {
        cpu = data->ptr.lock->debug.cpu;
        lockval = data->ptr.lock->tickets.head_tail;
    }

    printk("%s ", lock_profile_ancs[type].name);
    if ( type != LOCKPROF_TYPE_GLOBAL )
        printk("%d ", idx);
    printk("%s: addr=%p, lockval=%08x, ", data->name, data->ptr.lock, lockval);
    if ( cpu == SPINLOCK_NO_CPU )
        printk("not locked\n");
    else
        printk("cpu=%u\n", cpu);
    printk("  lock:%" PRIu64 "(%" PRI_stime "), block:%" PRIu64 "(%" PRI_stime ")\n",
           data->lock_cnt, data->time_hold, (uint64_t)data->block_cnt,
           data->time_block);
}

void cf_check spinlock_profile_printall(unsigned char key)
{
    s_time_t now = NOW();
    s_time_t diff;

    diff = now - lock_profile_start;
    printk("Xen lock profile info SHOW  (now = %"PRI_stime" total = "
           "%"PRI_stime")\n", now, diff);
    spinlock_profile_iterate(spinlock_profile_print_elem, NULL);
}

static void cf_check spinlock_profile_reset_elem(struct lock_profile *data,
    int32_t type, int32_t idx, void *par)
{
    data->lock_cnt = 0;
    data->block_cnt = 0;
    data->time_hold = 0;
    data->time_block = 0;
}

void cf_check spinlock_profile_reset(unsigned char key)
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

static void cf_check spinlock_profile_ucopy_elem(struct lock_profile *data,
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
    int32_t type, struct lock_profile_qhead *qhead, int32_t idx)
{
    qhead->idx = idx;
    spin_lock(&lock_profile_lock);
    qhead->head_q = lock_profile_ancs[type].head_q;
    lock_profile_ancs[type].head_q = qhead;
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

extern struct lock_profile *__lock_profile_start[];
extern struct lock_profile *__lock_profile_end[];

static int __init cf_check lock_prof_init(void)
{
    struct lock_profile **q;

    BUILD_BUG_ON(ARRAY_SIZE(lock_profile_ancs) != LOCKPROF_TYPE_N);

    for ( q = __lock_profile_start; q < __lock_profile_end; q++ )
    {
        (*q)->next = lock_profile_glb_q.elem_q;
        lock_profile_glb_q.elem_q = *q;

        if ( (*q)->is_rlock )
            (*q)->ptr.rlock->profile = *q;
        else
            (*q)->ptr.lock->profile = *q;
    }

    _lock_profile_register_struct(LOCKPROF_TYPE_GLOBAL,
                                  &lock_profile_glb_q, 0);

    return 0;
}
__initcall(lock_prof_init);

#endif /* CONFIG_DEBUG_LOCK_PROFILE */
