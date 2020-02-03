/******************************************************************************
 * timer.c
 * 
 * Copyright (c) 2002-2003 Rolf Neugebauer
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/smp.h>
#include <xen/perfc.h>
#include <xen/time.h>
#include <xen/softirq.h>
#include <xen/timer.h>
#include <xen/keyhandler.h>
#include <xen/percpu.h>
#include <xen/cpu.h>
#include <xen/rcupdate.h>
#include <xen/symbols.h>
#include <asm/system.h>
#include <asm/desc.h>
#include <asm/atomic.h>

/* We program the time hardware this far behind the closest deadline. */
static unsigned int timer_slop __read_mostly = 50000; /* 50 us */
integer_param("timer_slop", timer_slop);

struct timers {
    spinlock_t     lock;
    struct timer **heap;
    struct timer  *list;
    struct timer  *running;
    struct list_head inactive;
} __cacheline_aligned;

static DEFINE_PER_CPU(struct timers, timers);

/* Protects lock-free access to per-timer cpu field against cpu offlining. */
static DEFINE_RCU_READ_LOCK(timer_cpu_read_lock);

DEFINE_PER_CPU(s_time_t, timer_deadline);

/****************************************************************************
 * HEAP OPERATIONS.
 *
 * Slot 0 of the heap is never a valid timer pointer, and instead holds the
 * heap metadata.
 */

struct heap_metadata {
    uint16_t size, limit;
};

static struct heap_metadata *heap_metadata(struct timer **heap)
{
    /* Check that our type-punning doesn't overflow into heap[1] */
    BUILD_BUG_ON(sizeof(struct heap_metadata) > sizeof(struct timer *));

    return (struct heap_metadata *)&heap[0];
}

/* Sink down element @pos of @heap. */
static void down_heap(struct timer **heap, unsigned int pos)
{
    unsigned int sz = heap_metadata(heap)->size, nxt;
    struct timer *t = heap[pos];

    while ( (nxt = (pos << 1)) <= sz )
    {
        if ( ((nxt+1) <= sz) && (heap[nxt+1]->expires < heap[nxt]->expires) )
            nxt++;
        if ( heap[nxt]->expires > t->expires )
            break;
        heap[pos] = heap[nxt];
        heap[pos]->heap_offset = pos;
        pos = nxt;
    }

    heap[pos] = t;
    t->heap_offset = pos;
}

/* Float element @pos up @heap. */
static void up_heap(struct timer **heap, unsigned int pos)
{
    struct timer *t = heap[pos];

    while ( (pos > 1) && (t->expires < heap[pos>>1]->expires) )
    {
        heap[pos] = heap[pos>>1];
        heap[pos]->heap_offset = pos;
        pos >>= 1;
    }

    heap[pos] = t;
    t->heap_offset = pos;
}


/* Delete @t from @heap. Return TRUE if new top of heap. */
static int remove_from_heap(struct timer **heap, struct timer *t)
{
    unsigned int sz = heap_metadata(heap)->size;
    unsigned int pos = t->heap_offset;

    if ( unlikely(pos == sz) )
    {
        heap_metadata(heap)->size = sz - 1;
        goto out;
    }

    heap[pos] = heap[sz];
    heap[pos]->heap_offset = pos;

    heap_metadata(heap)->size = --sz;

    if ( (pos > 1) && (heap[pos]->expires < heap[pos>>1]->expires) )
        up_heap(heap, pos);
    else
        down_heap(heap, pos);

 out:
    return (pos == 1);
}


/* Add new entry @t to @heap. Return TRUE if new top of heap. */
static int add_to_heap(struct timer **heap, struct timer *t)
{
    unsigned int sz = heap_metadata(heap)->size;

    /* Fail if the heap is full. */
    if ( unlikely(sz == heap_metadata(heap)->limit) )
        return 0;

    heap_metadata(heap)->size = ++sz;
    heap[sz] = t;
    t->heap_offset = sz;
    up_heap(heap, sz);

    return (t->heap_offset == 1);
}


/****************************************************************************
 * LINKED LIST OPERATIONS.
 */

static int remove_from_list(struct timer **pprev, struct timer *t)
{
    struct timer *curr, **_pprev = pprev;

    while ( (curr = *_pprev) != t )
        _pprev = &curr->list_next;

    *_pprev = t->list_next;

    return (_pprev == pprev);
}

static int add_to_list(struct timer **pprev, struct timer *t)
{
    struct timer *curr, **_pprev = pprev;

    while ( ((curr = *_pprev) != NULL) && (curr->expires <= t->expires) )
        _pprev = &curr->list_next;

    t->list_next = curr;
    *_pprev = t;

    return (_pprev == pprev);
}


/****************************************************************************
 * TIMER OPERATIONS.
 */

static int remove_entry(struct timer *t)
{
    struct timers *timers = &per_cpu(timers, t->cpu);
    int rc;

    switch ( t->status )
    {
    case TIMER_STATUS_in_heap:
        rc = remove_from_heap(timers->heap, t);
        break;
    case TIMER_STATUS_in_list:
        rc = remove_from_list(&timers->list, t);
        break;
    default:
        rc = 0;
        BUG();
    }

    t->status = TIMER_STATUS_invalid;
    return rc;
}

static int add_entry(struct timer *t)
{
    struct timers *timers = &per_cpu(timers, t->cpu);
    int rc;

    ASSERT(t->status == TIMER_STATUS_invalid);

    /* Try to add to heap. t->heap_offset indicates whether we succeed. */
    t->heap_offset = 0;
    t->status = TIMER_STATUS_in_heap;
    rc = add_to_heap(timers->heap, t);
    if ( t->heap_offset != 0 )
        return rc;

    /* Fall back to adding to the slower linked list. */
    t->status = TIMER_STATUS_in_list;
    return add_to_list(&timers->list, t);
}

static inline void activate_timer(struct timer *timer)
{
    ASSERT(timer->status == TIMER_STATUS_inactive);
    timer->status = TIMER_STATUS_invalid;
    list_del(&timer->inactive);

    if ( add_entry(timer) )
        cpu_raise_softirq(timer->cpu, TIMER_SOFTIRQ);
}

static inline void deactivate_timer(struct timer *timer)
{
    if ( remove_entry(timer) )
        cpu_raise_softirq(timer->cpu, TIMER_SOFTIRQ);

    timer->status = TIMER_STATUS_inactive;
    list_add(&timer->inactive, &per_cpu(timers, timer->cpu).inactive);
}

static inline bool_t timer_lock(struct timer *timer)
{
    unsigned int cpu;

    rcu_read_lock(&timer_cpu_read_lock);

    for ( ; ; )
    {
        cpu = read_atomic(&timer->cpu);
        if ( unlikely(cpu == TIMER_CPU_status_killed) )
        {
            rcu_read_unlock(&timer_cpu_read_lock);
            return 0;
        }
        spin_lock(&per_cpu(timers, cpu).lock);
        if ( likely(timer->cpu == cpu) )
            break;
        spin_unlock(&per_cpu(timers, cpu).lock);
    }

    rcu_read_unlock(&timer_cpu_read_lock);
    return 1;
}

#define timer_lock_irqsave(t, flags) ({         \
    bool_t __x;                                 \
    local_irq_save(flags);                      \
    if ( !(__x = timer_lock(t)) )               \
        local_irq_restore(flags);               \
    __x;                                        \
})

static inline void timer_unlock(struct timer *timer)
{
    spin_unlock(&per_cpu(timers, timer->cpu).lock);
}

#define timer_unlock_irqrestore(t, flags) ({    \
    timer_unlock(t);                            \
    local_irq_restore(flags);                   \
})


static bool active_timer(const struct timer *timer)
{
    ASSERT(timer->status >= TIMER_STATUS_inactive);
    return timer_is_active(timer);
}


void init_timer(
    struct timer *timer,
    void        (*function)(void *),
    void         *data,
    unsigned int  cpu)
{
    unsigned long flags;
    memset(timer, 0, sizeof(*timer));
    timer->function = function;
    timer->data = data;
    write_atomic(&timer->cpu, cpu);
    timer->status = TIMER_STATUS_inactive;
    if ( !timer_lock_irqsave(timer, flags) )
        BUG();
    list_add(&timer->inactive, &per_cpu(timers, cpu).inactive);
    timer_unlock_irqrestore(timer, flags);
}


void set_timer(struct timer *timer, s_time_t expires)
{
    unsigned long flags;

    if ( !timer_lock_irqsave(timer, flags) )
        return;

    if ( active_timer(timer) )
        deactivate_timer(timer);

    timer->expires = expires;

    activate_timer(timer);

    timer_unlock_irqrestore(timer, flags);
}


void stop_timer(struct timer *timer)
{
    unsigned long flags;

    if ( !timer_lock_irqsave(timer, flags) )
        return;

    if ( active_timer(timer) )
        deactivate_timer(timer);

    timer_unlock_irqrestore(timer, flags);
}

bool timer_expires_before(struct timer *timer, s_time_t t)
{
    unsigned long flags;
    bool ret;

    if ( !timer_lock_irqsave(timer, flags) )
        return false;

    ret = active_timer(timer) && timer->expires <= t;

    timer_unlock_irqrestore(timer, flags);

    return ret;
}

void migrate_timer(struct timer *timer, unsigned int new_cpu)
{
    unsigned int old_cpu;
    bool_t active;
    unsigned long flags;

    rcu_read_lock(&timer_cpu_read_lock);

    for ( ; ; )
    {
        old_cpu = read_atomic(&timer->cpu);
        if ( (old_cpu == new_cpu) || (old_cpu == TIMER_CPU_status_killed) )
        {
            rcu_read_unlock(&timer_cpu_read_lock);
            return;
        }

        if ( old_cpu < new_cpu )
        {
            spin_lock_irqsave(&per_cpu(timers, old_cpu).lock, flags);
            spin_lock(&per_cpu(timers, new_cpu).lock);
        }
        else
        {
            spin_lock_irqsave(&per_cpu(timers, new_cpu).lock, flags);
            spin_lock(&per_cpu(timers, old_cpu).lock);
        }

        if ( likely(timer->cpu == old_cpu) )
             break;

        spin_unlock(&per_cpu(timers, old_cpu).lock);
        spin_unlock_irqrestore(&per_cpu(timers, new_cpu).lock, flags);
    }

    rcu_read_unlock(&timer_cpu_read_lock);

    active = active_timer(timer);
    if ( active )
        deactivate_timer(timer);

    list_del(&timer->inactive);
    write_atomic(&timer->cpu, new_cpu);
    list_add(&timer->inactive, &per_cpu(timers, new_cpu).inactive);

    if ( active )
        activate_timer(timer);

    spin_unlock(&per_cpu(timers, old_cpu).lock);
    spin_unlock_irqrestore(&per_cpu(timers, new_cpu).lock, flags);
}


void kill_timer(struct timer *timer)
{
    unsigned int old_cpu, cpu;
    unsigned long flags;

    BUG_ON(this_cpu(timers).running == timer);

    if ( !timer_lock_irqsave(timer, flags) )
        return;

    if ( active_timer(timer) )
        deactivate_timer(timer);

    list_del(&timer->inactive);
    timer->status = TIMER_STATUS_killed;
    old_cpu = timer->cpu;
    write_atomic(&timer->cpu, TIMER_CPU_status_killed);

    spin_unlock_irqrestore(&per_cpu(timers, old_cpu).lock, flags);

    for_each_online_cpu ( cpu )
        while ( per_cpu(timers, cpu).running == timer )
            cpu_relax();
}


static void execute_timer(struct timers *ts, struct timer *t)
{
    void (*fn)(void *) = t->function;
    void *data = t->data;

    t->status = TIMER_STATUS_inactive;
    list_add(&t->inactive, &ts->inactive);

    ts->running = t;
    spin_unlock_irq(&ts->lock);
    (*fn)(data);
    spin_lock_irq(&ts->lock);
    ts->running = NULL;
}


static void timer_softirq_action(void)
{
    struct timer  *t, **heap, *next;
    struct timers *ts;
    s_time_t       now, deadline;

    ts = &this_cpu(timers);
    heap = ts->heap;

    /* If we overflowed the heap, try to allocate a larger heap. */
    if ( unlikely(ts->list != NULL) )
    {
        /* old_limit == (2^n)-1; new_limit == (2^(n+4))-1 */
        unsigned int old_limit = heap_metadata(heap)->limit;
        unsigned int new_limit = ((old_limit + 1) << 4) - 1;
        struct timer **newheap = NULL;

        /* Don't grow the heap beyond what is representable in its metadata. */
        if ( new_limit == (typeof(heap_metadata(heap)->limit))new_limit &&
             new_limit + 1 )
            newheap = xmalloc_array(struct timer *, new_limit + 1);
        else
            printk_once(XENLOG_WARNING "CPU%u: timer heap limit reached\n",
                        smp_processor_id());
        if ( newheap != NULL )
        {
            spin_lock_irq(&ts->lock);
            memcpy(newheap, heap, (old_limit + 1) * sizeof(*heap));
            heap_metadata(newheap)->limit = new_limit;
            ts->heap = newheap;
            spin_unlock_irq(&ts->lock);
            if ( old_limit != 0 )
                xfree(heap);
            heap = newheap;
        }
    }

    spin_lock_irq(&ts->lock);

    now = NOW();

    /* Execute ready heap timers. */
    while ( (heap_metadata(heap)->size != 0) &&
            ((t = heap[1])->expires < now) )
    {
        remove_from_heap(heap, t);
        execute_timer(ts, t);
    }

    /* Execute ready list timers. */
    while ( ((t = ts->list) != NULL) && (t->expires < now) )
    {
        ts->list = t->list_next;
        execute_timer(ts, t);
    }

    /* Try to move timers from linked list to more efficient heap. */
    next = ts->list;
    ts->list = NULL;
    while ( unlikely((t = next) != NULL) )
    {
        next = t->list_next;
        t->status = TIMER_STATUS_invalid;
        add_entry(t);
    }

    /* Find earliest deadline from head of linked list and top of heap. */
    deadline = STIME_MAX;
    if ( heap_metadata(heap)->size != 0 )
        deadline = heap[1]->expires;
    if ( (ts->list != NULL) && (ts->list->expires < deadline) )
        deadline = ts->list->expires;
    now = NOW();
    this_cpu(timer_deadline) =
        (deadline == STIME_MAX) ? 0 : MAX(deadline, now + timer_slop);

    if ( !reprogram_timer(this_cpu(timer_deadline)) )
        raise_softirq(TIMER_SOFTIRQ);

    spin_unlock_irq(&ts->lock);
}

s_time_t align_timer(s_time_t firsttick, uint64_t period)
{
    if ( !period )
        return firsttick;

    return firsttick + (period - 1) - ((firsttick - 1) % period);
}

static void dump_timer(struct timer *t, s_time_t now)
{
    printk("  ex=%12"PRId64"us timer=%p cb=%ps(%p)\n",
           (t->expires - now) / 1000, t, t->function, t->data);
}

static void dump_timerq(unsigned char key)
{
    struct timer  *t;
    struct timers *ts;
    unsigned long  flags;
    s_time_t       now = NOW();
    unsigned int   i, j;

    printk("Dumping timer queues:\n");

    for_each_online_cpu( i )
    {
        ts = &per_cpu(timers, i);

        printk("CPU%02d:\n", i);
        spin_lock_irqsave(&ts->lock, flags);
        for ( j = 1; j <= heap_metadata(ts->heap)->size; j++ )
            dump_timer(ts->heap[j], now);
        for ( t = ts->list; t != NULL; t = t->list_next )
            dump_timer(t, now);
        spin_unlock_irqrestore(&ts->lock, flags);
    }
}

static void migrate_timers_from_cpu(unsigned int old_cpu)
{
    unsigned int new_cpu = cpumask_any(&cpu_online_map);
    struct timers *old_ts, *new_ts;
    struct timer *t;
    bool_t notify = 0;

    ASSERT(!cpu_online(old_cpu) && cpu_online(new_cpu));

    old_ts = &per_cpu(timers, old_cpu);
    new_ts = &per_cpu(timers, new_cpu);

    if ( old_cpu < new_cpu )
    {
        spin_lock_irq(&old_ts->lock);
        spin_lock(&new_ts->lock);
    }
    else
    {
        spin_lock_irq(&new_ts->lock);
        spin_lock(&old_ts->lock);
    }

    while ( (t = heap_metadata(old_ts->heap)->size
             ? old_ts->heap[1] : old_ts->list) != NULL )
    {
        remove_entry(t);
        write_atomic(&t->cpu, new_cpu);
        notify |= add_entry(t);
    }

    while ( !list_empty(&old_ts->inactive) )
    {
        t = list_entry(old_ts->inactive.next, struct timer, inactive);
        list_del(&t->inactive);
        write_atomic(&t->cpu, new_cpu);
        list_add(&t->inactive, &new_ts->inactive);
    }

    spin_unlock(&old_ts->lock);
    spin_unlock_irq(&new_ts->lock);

    if ( notify )
        cpu_raise_softirq(new_cpu, TIMER_SOFTIRQ);
}

/*
 * All CPUs initially share an empty dummy heap. Only those CPUs that
 * are brought online will be dynamically allocated their own heap.
 * The size/limit metadata are both 0 by being in .bss
 */
static struct timer *dummy_heap[1];

static void free_percpu_timers(unsigned int cpu)
{
    struct timers *ts = &per_cpu(timers, cpu);

    ASSERT(heap_metadata(ts->heap)->size == 0);
    if ( heap_metadata(ts->heap)->limit )
    {
        xfree(ts->heap);
        ts->heap = dummy_heap;
    }
    else
        ASSERT(ts->heap == dummy_heap);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    struct timers *ts = &per_cpu(timers, cpu);

    switch ( action )
    {
    case CPU_UP_PREPARE:
        /* Only initialise ts once. */
        if ( !ts->heap )
        {
            INIT_LIST_HEAD(&ts->inactive);
            spin_lock_init(&ts->lock);
            ts->heap = dummy_heap;
        }
        break;

    case CPU_UP_CANCELED:
    case CPU_DEAD:
    case CPU_RESUME_FAILED:
        migrate_timers_from_cpu(cpu);

        if ( !park_offline_cpus && system_state != SYS_STATE_suspend )
            free_percpu_timers(cpu);
        break;

    case CPU_REMOVE:
        if ( park_offline_cpus )
            free_percpu_timers(cpu);
        break;

    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    .priority = 99
};

void __init timer_init(void)
{
    void *cpu = (void *)(long)smp_processor_id();

    open_softirq(TIMER_SOFTIRQ, timer_softirq_action);

    cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);
    register_cpu_notifier(&cpu_nfb);

    register_keyhandler('a', dump_timerq, "dump timer queues", 1);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
