/******************************************************************************
 * timer.c
 * 
 * Copyright (c) 2002-2003 Rolf Neugebauer
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/perfc.h>
#include <xen/time.h>
#include <xen/softirq.h>
#include <xen/timer.h>
#include <xen/keyhandler.h>
#include <xen/percpu.h>
#include <asm/system.h>
#include <asm/desc.h>

/*
 * We pull handlers off the timer list this far in future,
 * rather than reprogramming the time hardware.
 */
static unsigned int timer_slop __read_mostly = 50000; /* 50 us */
integer_param("timer_slop", timer_slop);

struct timers {
    spinlock_t     lock;
    bool_t         overflow;
    struct timer **heap;
    struct timer  *list;
    struct timer  *running;
} __cacheline_aligned;

static DEFINE_PER_CPU(struct timers, timers);

DEFINE_PER_CPU(s_time_t, timer_deadline_start);
DEFINE_PER_CPU(s_time_t, timer_deadline_end);

/****************************************************************************
 * HEAP OPERATIONS.
 */

#define GET_HEAP_SIZE(_h)     ((int)(((u16 *)(_h))[0]))
#define SET_HEAP_SIZE(_h,_v)  (((u16 *)(_h))[0] = (u16)(_v))

#define GET_HEAP_LIMIT(_h)    ((int)(((u16 *)(_h))[1]))
#define SET_HEAP_LIMIT(_h,_v) (((u16 *)(_h))[1] = (u16)(_v))

/* Sink down element @pos of @heap. */
static void down_heap(struct timer **heap, int pos)
{
    int sz = GET_HEAP_SIZE(heap), nxt;
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
static void up_heap(struct timer **heap, int pos)
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
    int sz = GET_HEAP_SIZE(heap);
    int pos = t->heap_offset;

    if ( unlikely(pos == sz) )
    {
        SET_HEAP_SIZE(heap, sz-1);
        goto out;
    }

    heap[pos] = heap[sz];
    heap[pos]->heap_offset = pos;

    SET_HEAP_SIZE(heap, --sz);

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
    int sz = GET_HEAP_SIZE(heap);

    /* Fail if the heap is full. */
    if ( unlikely(sz == GET_HEAP_LIMIT(heap)) )
        return 0;

    SET_HEAP_SIZE(heap, ++sz);
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

static int remove_entry(struct timers *timers, struct timer *t)
{
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

    t->status = TIMER_STATUS_inactive;
    return rc;
}

static int add_entry(struct timers *timers, struct timer *t)
{
    int rc;

    ASSERT(t->status == TIMER_STATUS_inactive);

    /* Try to add to heap. t->heap_offset indicates whether we succeed. */
    t->heap_offset = 0;
    t->status = TIMER_STATUS_in_heap;
    rc = add_to_heap(timers->heap, t);
    if ( t->heap_offset != 0 )
        return rc;

    /* Fall back to adding to the slower linked list. */
    timers->overflow = 1;
    t->status = TIMER_STATUS_in_list;
    return add_to_list(&timers->list, t);
}

static inline void __add_timer(struct timer *timer)
{
    int cpu = timer->cpu;
    if ( add_entry(&per_cpu(timers, cpu), timer) )
        cpu_raise_softirq(cpu, TIMER_SOFTIRQ);
}

static inline void __stop_timer(struct timer *timer)
{
    int cpu = timer->cpu;
    if ( remove_entry(&per_cpu(timers, cpu), timer) )
        cpu_raise_softirq(cpu, TIMER_SOFTIRQ);
}

static inline void timer_lock(struct timer *timer)
{
    unsigned int cpu;

    for ( ; ; )
    {
        cpu = timer->cpu;
        spin_lock(&per_cpu(timers, cpu).lock);
        if ( likely(timer->cpu == cpu) )
            break;
        spin_unlock(&per_cpu(timers, cpu).lock);
    }
}

#define timer_lock_irq(t) \
    do { local_irq_disable(); timer_lock(t); } while ( 0 )
#define timer_lock_irqsave(t, flags) \
    do { local_irq_save(flags); timer_lock(t); } while ( 0 )

static inline void timer_unlock(struct timer *timer)
{
    spin_unlock(&per_cpu(timers, timer->cpu).lock);
}

#define timer_unlock_irq(t) \
    do { timer_unlock(t); local_irq_enable(); } while ( 0 )
#define timer_unlock_irqrestore(t, flags) \
    do { timer_unlock(t); local_irq_restore(flags); } while ( 0 )


void set_timer(struct timer *timer, s_time_t expires)
{
    unsigned long flags;

    timer_lock_irqsave(timer, flags);

    if ( active_timer(timer) )
        __stop_timer(timer);

    timer->expires = expires;
    timer->expires_end = expires + timer_slop;

    if ( likely(timer->status != TIMER_STATUS_killed) )
        __add_timer(timer);

    timer_unlock_irqrestore(timer, flags);
}


void stop_timer(struct timer *timer)
{
    unsigned long flags;

    timer_lock_irqsave(timer, flags);

    if ( active_timer(timer) )
        __stop_timer(timer);

    timer_unlock_irqrestore(timer, flags);
}


void migrate_timer(struct timer *timer, unsigned int new_cpu)
{
    int           old_cpu;
    unsigned long flags;

    for ( ; ; )
    {
        if ( (old_cpu = timer->cpu) == new_cpu )
            return;

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

    if ( active_timer(timer) )
    {
        __stop_timer(timer);
        timer->cpu = new_cpu;
        __add_timer(timer);
    }
    else
    {
        timer->cpu = new_cpu;
    }

    spin_unlock(&per_cpu(timers, old_cpu).lock);
    spin_unlock_irqrestore(&per_cpu(timers, new_cpu).lock, flags);
}


void kill_timer(struct timer *timer)
{
    int           cpu;
    unsigned long flags;

    BUG_ON(this_cpu(timers).running == timer);

    timer_lock_irqsave(timer, flags);

    if ( active_timer(timer) )
        __stop_timer(timer);
    timer->status = TIMER_STATUS_killed;

    timer_unlock_irqrestore(timer, flags);

    for_each_online_cpu ( cpu )
        while ( per_cpu(timers, cpu).running == timer )
            cpu_relax();
}


static void execute_timer(struct timers *ts, struct timer *t)
{
    void (*fn)(void *) = t->function;
    void *data = t->data;

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
    s_time_t       now;

    ts = &this_cpu(timers);
    heap = ts->heap;

    /* If we overflowed the heap, try to allocate a larger heap. */
    if ( unlikely(ts->overflow) )
    {
        /* old_limit == (2^n)-1; new_limit == (2^(n+4))-1 */
        int old_limit = GET_HEAP_LIMIT(heap);
        int new_limit = ((old_limit + 1) << 4) - 1;
        struct timer **newheap = xmalloc_array(struct timer *, new_limit + 1);
        if ( newheap != NULL )
        {
            spin_lock_irq(&ts->lock);
            memcpy(newheap, heap, (old_limit + 1) * sizeof(*heap));
            SET_HEAP_LIMIT(newheap, new_limit);
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
    while ( (GET_HEAP_SIZE(heap) != 0) &&
            ((t = heap[1])->expires < now) )
    {
        remove_from_heap(heap, t);
        t->status = TIMER_STATUS_inactive;
        execute_timer(ts, t);
    }

    /* Execute ready list timers. */
    while ( ((t = ts->list) != NULL) && (t->expires < now) )
    {
        ts->list = t->list_next;
        t->status = TIMER_STATUS_inactive;
        execute_timer(ts, t);
    }

    /* Try to move timers from linked list to more efficient heap. */
    next = ts->list;
    ts->list = NULL;
    while ( unlikely((t = next) != NULL) )
    {
        next = t->list_next;
        t->status = TIMER_STATUS_inactive;
        add_entry(ts, t);
    }

    ts->overflow = (ts->list != NULL);
    if ( unlikely(ts->overflow) )
    {
        /* Find earliest deadline at head of list or top of heap. */
        this_cpu(timer_deadline_start) = ts->list->expires;
        if ( (GET_HEAP_SIZE(heap) != 0) &&
             ((t = heap[1])->expires < this_cpu(timer_deadline_start)) )
            this_cpu(timer_deadline_start) = t->expires;
        this_cpu(timer_deadline_end) = this_cpu(timer_deadline_start);
    }
    else
    {
        /*
         * Find the earliest deadline that encompasses largest number of timers
         * on the heap. To do this we take timers from the heap while their
         * valid deadline ranges continue to intersect.
         */
        s_time_t start = 0, end = STIME_MAX;
        struct timer **list_tail = &ts->list;

        while ( (GET_HEAP_SIZE(heap) != 0) &&
                ((t = heap[1])->expires <= end) )
        {
            remove_entry(ts, t);

            t->status = TIMER_STATUS_in_list;
            t->list_next = NULL;
            *list_tail = t;
            list_tail = &t->list_next;

            start = t->expires;
            if ( end > t->expires_end )
                end = t->expires_end;
        }

        this_cpu(timer_deadline_start) = start;
        this_cpu(timer_deadline_end) = end;
    }

    if ( !reprogram_timer(this_cpu(timer_deadline_start)) )
        raise_softirq(TIMER_SOFTIRQ);

    spin_unlock_irq(&ts->lock);
}

s_time_t align_timer(s_time_t firsttick, uint64_t period)
{
    if ( !period )
        return firsttick;

    return firsttick + (period - 1) - ((firsttick - 1) % period);
}

static void dump_timerq(unsigned char key)
{
    struct timer  *t;
    struct timers *ts;
    unsigned long  flags;
    s_time_t       now = NOW();
    int            i, j;

    printk("Dumping timer queues: NOW=0x%08X%08X\n",
           (u32)(now>>32), (u32)now);

    for_each_online_cpu( i )
    {
        ts = &per_cpu(timers, i);

        printk("CPU[%02d] ", i);
        spin_lock_irqsave(&ts->lock, flags);
        for ( j = 1; j <= GET_HEAP_SIZE(ts->heap); j++ )
        {
            t = ts->heap[j];
            printk ("  %d : %p ex=0x%08X%08X %p %p\n",
                    j, t, (u32)(t->expires>>32), (u32)t->expires,
                    t->data, t->function);
        }
        for ( t = ts->list, j = 0; t != NULL; t = t->list_next, j++ )
            printk (" L%d : %p ex=0x%08X%08X %p %p\n",
                    j, t, (u32)(t->expires>>32), (u32)t->expires,
                    t->data, t->function);
        spin_unlock_irqrestore(&ts->lock, flags);
        printk("\n");
    }
}

static struct keyhandler dump_timerq_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_timerq,
    .desc = "dump timer queues"
};

void __init timer_init(void)
{
    static struct timer *dummy_heap;
    int i;

    open_softirq(TIMER_SOFTIRQ, timer_softirq_action);

    /*
     * All CPUs initially share an empty dummy heap. Only those CPUs that
     * are brought online will be dynamically allocated their own heap.
     */
    SET_HEAP_SIZE(&dummy_heap, 0);
    SET_HEAP_LIMIT(&dummy_heap, 0);

    for_each_possible_cpu ( i )
    {
        spin_lock_init(&per_cpu(timers, i).lock);
        per_cpu(timers, i).heap = &dummy_heap;
    }

    register_keyhandler('a', &dump_timerq_keyhandler);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
