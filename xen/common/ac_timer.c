/****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 ****************************************************************************
 *
 *        File: ac_timer.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *              Keir Fraser (kaf24@cl.cam.ac.uk)
 *              
 * Environment: Xen Hypervisor
 * Description: Accurate timer for the Hypervisor
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
#include <xen/ac_timer.h>
#include <xen/keyhandler.h>
#include <asm/system.h>
#include <asm/desc.h>

/*
 * We pull handlers off the timer list this far in future,
 * rather than reprogramming the time hardware.
 */
#define TIMER_SLOP (50*1000) /* ns */

#define DEFAULT_HEAP_LIMIT 127

/* A timer list per CPU */
typedef struct ac_timers_st
{
    spinlock_t        lock;
    struct ac_timer **heap;
} __cacheline_aligned ac_timers_t;
static ac_timers_t ac_timers[NR_CPUS];


/****************************************************************************
 * HEAP OPERATIONS.
 */

#define GET_HEAP_SIZE(_h)     ((int)(((u16 *)(_h))[0]))
#define SET_HEAP_SIZE(_h,_v)  (((u16 *)(_h))[0] = (u16)(_v))

#define GET_HEAP_LIMIT(_h)    ((int)(((u16 *)(_h))[1]))
#define SET_HEAP_LIMIT(_h,_v) (((u16 *)(_h))[1] = (u16)(_v))

/* Sink down element @pos of @heap. */
static void down_heap(struct ac_timer **heap, int pos)
{
    int sz = GET_HEAP_SIZE(heap), nxt;
    struct ac_timer *t = heap[pos];

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
static void up_heap(struct ac_timer **heap, int pos)
{
    struct ac_timer *t = heap[pos];

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
static int remove_entry(struct ac_timer **heap, struct ac_timer *t)
{
    int sz = GET_HEAP_SIZE(heap);
    int pos = t->heap_offset;

    t->heap_offset = 0;

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
static int add_entry(struct ac_timer **heap, struct ac_timer *t)
{
    int sz = GET_HEAP_SIZE(heap);

    /* Copy the heap if it is full. */
    if ( unlikely(sz == GET_HEAP_LIMIT(heap)) )
    {
        int i, limit = (GET_HEAP_LIMIT(heap)+1) << 1;
        struct ac_timer **new_heap = xmalloc_array(struct ac_timer *, limit);
        if ( new_heap == NULL ) BUG();
        memcpy(new_heap, heap, (limit>>1)*sizeof(struct ac_timer *));
        for ( i = 0; i < smp_num_cpus; i++ )
            if ( ac_timers[i].heap == heap )
                ac_timers[i].heap = new_heap;
        xfree(heap);
        heap = new_heap;
        SET_HEAP_LIMIT(heap, limit-1);
    }

    SET_HEAP_SIZE(heap, ++sz);
    heap[sz] = t;
    t->heap_offset = sz;
    up_heap(heap, sz);
    return (t->heap_offset == 1);
}


/****************************************************************************
 * TIMER OPERATIONS.
 */

static inline void __add_ac_timer(struct ac_timer *timer)
{
    int cpu = timer->cpu;
    if ( add_entry(ac_timers[cpu].heap, timer) )
        cpu_raise_softirq(cpu, AC_TIMER_SOFTIRQ);
}

void add_ac_timer(struct ac_timer *timer) 
{
    int           cpu = timer->cpu;
    unsigned long flags;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    ASSERT(timer != NULL);
    ASSERT(!active_ac_timer(timer));
    __add_ac_timer(timer);
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
}


static inline void __rem_ac_timer(struct ac_timer *timer)
{
    int cpu = timer->cpu;
    if ( remove_entry(ac_timers[cpu].heap, timer) )
        cpu_raise_softirq(cpu, AC_TIMER_SOFTIRQ);
}

void rem_ac_timer(struct ac_timer *timer)
{
    int           cpu = timer->cpu;
    unsigned long flags;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    ASSERT(timer != NULL);
    if ( active_ac_timer(timer) )
        __rem_ac_timer(timer);
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
}


void mod_ac_timer(struct ac_timer *timer, s_time_t new_time)
{
    int           cpu = timer->cpu;
    unsigned long flags;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    ASSERT(timer != NULL);
    if ( active_ac_timer(timer) )
        __rem_ac_timer(timer);
    timer->expires = new_time;
    __add_ac_timer(timer);
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
}


static void ac_timer_softirq_action(void)
{
    int              cpu = smp_processor_id();
    struct ac_timer *t, **heap;
    s_time_t         now;
    void             (*fn)(unsigned long);

    spin_lock_irq(&ac_timers[cpu].lock);
    
    do {
        heap = ac_timers[cpu].heap;
        now  = NOW();
        
        while ( (GET_HEAP_SIZE(heap) != 0) &&
                ((t = heap[1])->expires < (now + TIMER_SLOP)) )
        {
            remove_entry(heap, t);

            if ( (fn = t->function) != NULL )
            {
                unsigned long data = t->data;
                spin_unlock_irq(&ac_timers[cpu].lock);
                (*fn)(data);
                spin_lock_irq(&ac_timers[cpu].lock);
            }

            /* Heap may have grown while the lock was released. */
            heap = ac_timers[cpu].heap;
        }
    }
    while ( !reprogram_ac_timer(GET_HEAP_SIZE(heap) ? heap[1]->expires : 0) );

    spin_unlock_irq(&ac_timers[cpu].lock);
}


static void dump_timerq(unsigned char key)
{
    struct ac_timer *t;
    unsigned long    flags; 
    s_time_t         now = NOW();
    int              i, j;

    printk("Dumping ac_timer queues: NOW=0x%08X%08X\n",
           (u32)(now>>32), (u32)now); 

    for ( i = 0; i < smp_num_cpus; i++ )
    {
        printk("CPU[%02d] ", i);
        spin_lock_irqsave(&ac_timers[i].lock, flags);
        for ( j = 1; j <= GET_HEAP_SIZE(ac_timers[i].heap); j++ )
        {
            t = ac_timers[i].heap[j];
            printk ("  %d : %p ex=0x%08X%08X %lu\n",
                    j, t, (u32)(t->expires>>32), (u32)t->expires, t->data);
        }
        spin_unlock_irqrestore(&ac_timers[i].lock, flags);
        printk("\n");
    }
}


void __init ac_timer_init(void)
{
    int i;

    open_softirq(AC_TIMER_SOFTIRQ, ac_timer_softirq_action);

    for ( i = 0; i < smp_num_cpus; i++ )
    {
        ac_timers[i].heap = xmalloc_array(struct ac_timer *, DEFAULT_HEAP_LIMIT+1);
        if ( ac_timers[i].heap == NULL ) BUG();
        SET_HEAP_SIZE(ac_timers[i].heap, 0);
        SET_HEAP_LIMIT(ac_timers[i].heap, DEFAULT_HEAP_LIMIT);
        spin_lock_init(&ac_timers[i].lock);
    }

    register_keyhandler('a', dump_timerq, "dump ac_timer queues");
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
