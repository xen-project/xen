/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: ac_timer.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: Accurate timer for the Hypervisor
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/types.h>
#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/smp.h>
#include <xeno/perfc.h>
#include <xeno/time.h>
#include <xeno/interrupt.h>
#include <xeno/ac_timer.h>
#include <xeno/keyhandler.h>
#include <asm/system.h>
#include <asm/desc.h>

#ifdef AC_TIMER_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/*****************************************************************************
 * We pull handlers off the timer list this far in future,
 * rather than reprogramming the time hardware.
 *****************************************************************************/
#define TIMER_SLOP (50*1000) /* ns */

/* A timer list per CPU */
typedef struct ac_timers_st
{
    spinlock_t lock;
    struct list_head timers;
    s_time_t    max_diff;
} __cacheline_aligned ac_timers_t;
static ac_timers_t ac_timers[NR_CPUS];


/*****************************************************************************
 * add a timer.
 * return value: CPU mask of remote processors to send an event to
 *****************************************************************************/
static inline unsigned long __add_ac_timer(struct ac_timer *timer)
{
    int cpu = timer->cpu;

    /*
     * Add timer to the list. If it gets added to the front we schedule
     * a softirq. This will reprogram the timer, or handle the timer event
     * imemdiately, depending on whether alarm is sufficiently ahead in the
     * future.
     */
    if (list_empty(&ac_timers[cpu].timers)) {
        list_add(&timer->timer_list, &ac_timers[cpu].timers);
        goto send_softirq;
    } else {
        struct list_head *pos;
        struct ac_timer  *t;

        list_for_each(pos, &ac_timers[cpu].timers) {
            t = list_entry(pos, struct ac_timer, timer_list);
            if (t->expires > timer->expires)
                break;
        }
        list_add(&(timer->timer_list), pos->prev);

        if (timer->timer_list.prev == &ac_timers[cpu].timers)
            goto send_softirq;
    }

    return 0;

 send_softirq:
    __cpu_raise_softirq(cpu, AC_TIMER_SOFTIRQ);
    return (cpu != smp_processor_id()) ? 1<<cpu : 0;
}

void add_ac_timer(struct ac_timer *timer) 
{
    int           cpu = timer->cpu;
    unsigned long flags, cpu_mask;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    ASSERT(timer != NULL);
    ASSERT(!active_ac_timer(timer));
    cpu_mask = __add_ac_timer(timer);
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);

    if ( cpu_mask ) smp_send_event_check_mask(cpu_mask);
}


/*****************************************************************************
 * detach a timer (no locking)
 * return values:
 *  0: success
 * -1: bogus timer
 *****************************************************************************/
static inline void detach_ac_timer(struct ac_timer *timer)
{  
    TRC(printk("ACT  [%02d] detach(): \n", cpu));
    list_del(&timer->timer_list);
    timer->timer_list.next = NULL;
}


/*****************************************************************************
 * remove a timer
 * return values: CPU mask of remote processors to send an event to
 *****************************************************************************/
static inline unsigned long __rem_ac_timer(struct ac_timer *timer)
{
    int cpu = timer->cpu;

    TRC(printk("ACT  [%02d] remove(): timo=%lld \n", cpu, timer->expires));
    ASSERT(timer->timer_list.next);

    detach_ac_timer(timer);
    
    if (timer->timer_list.prev == &ac_timers[cpu].timers) {
        /* just removed the head */
        if (list_empty(&ac_timers[cpu].timers)) {
            goto send_softirq;
        } else {
            timer = list_entry(ac_timers[cpu].timers.next,
                               struct ac_timer, timer_list);
            if ( timer->expires > (NOW() + TIMER_SLOP) )
                goto send_softirq;
        }
    }

    return 0;

 send_softirq:
    __cpu_raise_softirq(cpu, AC_TIMER_SOFTIRQ);
    return (cpu != smp_processor_id()) ? 1<<cpu : 0;
}

void rem_ac_timer(struct ac_timer *timer)
{
    int           cpu = timer->cpu;
    unsigned long flags, cpu_mask = 0;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    ASSERT(timer != NULL);
    if ( active_ac_timer(timer) )
        cpu_mask = __rem_ac_timer(timer);
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);

    if ( cpu_mask ) smp_send_event_check_mask(cpu_mask);
}


/*****************************************************************************
 * modify a timer, i.e., set a new timeout value
 * return value:
 *  0: sucess
 *  1: timeout error
 * -1: bogus timer
 *****************************************************************************/
void mod_ac_timer(struct ac_timer *timer, s_time_t new_time)
{
    int           cpu = timer->cpu;
    unsigned long flags, cpu_mask = 0;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);

    ASSERT(timer != NULL);

    if ( active_ac_timer(timer) )
        cpu_mask = __rem_ac_timer(timer);
    timer->expires = new_time;
    cpu_mask |= __add_ac_timer(timer);

    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);

    if ( cpu_mask ) smp_send_event_check_mask(cpu_mask);
}


/*****************************************************************************
 * do_ac_timer
 * deal with timeouts and run the handlers
 *****************************************************************************/
void do_ac_timer(void)
{
    int              cpu = smp_processor_id();
    unsigned long    flags;
    struct ac_timer  *t;
    s_time_t diff, now = NOW();
    long max;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);

 do_timer_again:
    TRC(printk("ACT  [%02d] do(): now=%lld\n", cpu, NOW()));
        
    /* Sanity: is the timer list empty? */
    if ( list_empty(&ac_timers[cpu].timers) ) goto out;

    /* Handle all timeouts in the near future. */
    while ( !list_empty(&ac_timers[cpu].timers) )
    {
        t = list_entry(ac_timers[cpu].timers.next,struct ac_timer, timer_list);
        if ( t->expires > (NOW() + TIMER_SLOP) ) break;

        ASSERT(t->cpu == cpu);

        /* do some stats */
        diff = (now - t->expires);
        if (diff > 0x7fffffff) diff =  0x7fffffff; /* THIS IS BAD! */
        max = perfc_valuea(ac_timer_max, cpu);
        if (diff > max) perfc_seta(ac_timer_max, cpu, diff);

        detach_ac_timer(t);
        spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
        if ( t->function != NULL ) t->function(t->data);
        spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    }
        
    /* If list not empty then reprogram timer to new head of list */
    if ( !list_empty(&ac_timers[cpu].timers) )
    {
        t = list_entry(ac_timers[cpu].timers.next,struct ac_timer, timer_list);
        TRC(printk("ACT  [%02d] do(): reprog timo=%lld\n",cpu,t->expires));
        if ( !reprogram_ac_timer(t->expires) )
        {
            TRC(printk("ACT  [%02d] do(): again\n", cpu));
            goto do_timer_again;
        }
    } else {
        reprogram_ac_timer((s_time_t) 0);
    }

 out:
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
    TRC(printk("ACT  [%02d] do(): end\n", cpu));
}


static void ac_timer_softirq_action(struct softirq_action *a)
{
    int           cpu = smp_processor_id();
    unsigned long flags;
    struct ac_timer *t;
    struct list_head *tlist;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    
    tlist = &ac_timers[cpu].timers;
    if ( list_empty(tlist) ) 
    {
        reprogram_ac_timer((s_time_t)0);
        spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
        return;
    }

    t = list_entry(tlist, struct ac_timer, timer_list);

    if ( (t->expires < (NOW() + TIMER_SLOP)) ||
         !reprogram_ac_timer(t->expires) ) 
    {
        /*
         * Timer handler needs protecting from local APIC interrupts, but takes
         * the spinlock itself, so we release that before calling in.
         */
        spin_unlock(&ac_timers[cpu].lock);
        do_ac_timer();
        local_irq_restore(flags);
    }
}

/*****************************************************************************
 * debug dump_queue
 * arguments: queue head, name of queue
 *****************************************************************************/
static void dump_tqueue(struct list_head *queue, char *name)
{
    struct list_head *list;
    int loop = 0;
    struct ac_timer  *t;

    printk ("QUEUE %s %lx   n: %lx, p: %lx\n", name,  (unsigned long)queue,
            (unsigned long) queue->next, (unsigned long) queue->prev);
    list_for_each (list, queue) {
        t = list_entry(list, struct ac_timer, timer_list);
        printk ("  %s %d : %lx ex=0x%08X%08X %lu  n: %lx, p: %lx\n",
                name, loop++, 
                (unsigned long)list,
                (u32)(t->expires>>32), (u32)t->expires, t->data,
                (unsigned long)list->next, (unsigned long)list->prev);
    }
    return; 
}

void dump_timerq(u_char key, void *dev_id, struct pt_regs *regs)
{
    u_long   flags; 
    s_time_t now = NOW();
    int i;

    printk("Dumping ac_timer queues: NOW=0x%08X%08X\n",
           (u32)(now>>32), (u32)now); 
    for (i = 0; i < smp_num_cpus; i++) {
        printk("CPU[%02d] ", i);
        spin_lock_irqsave(&ac_timers[i].lock, flags);
        dump_tqueue(&ac_timers[i].timers, "ac_time"); 
        spin_unlock_irqrestore(&ac_timers[i].lock, flags);
        printk("\n");
    }
    return; 
}


void __init ac_timer_init(void)
{
    int i;

    printk ("ACT: Initialising Accurate timers\n");

    open_softirq(AC_TIMER_SOFTIRQ, ac_timer_softirq_action, NULL);

    for (i = 0; i < NR_CPUS; i++)
    {
        INIT_LIST_HEAD(&ac_timers[i].timers);
        spin_lock_init(&ac_timers[i].lock);
    }
}


/*****************************************************************************
 * GRAVEYARD
 *****************************************************************************/

#if 0

#ifdef AC_TIMER_STATS
#define BUCKETS     1000
#define MAX_STATS
typedef struct act_stats_st
{
    u32 count;
    u32 times[2*(BUCKETS)];
} __cacheline_aligned act_stats_t;
static act_stats_t act_stats[NR_CPUS];

#endif

#ifdef AC_TIMER_STATS
    {
        XXX this is at the wrong place
        s32 diff;
        u32 i;
        diff = ((s32)(NOW() - t->expires)) / 1000; /* delta in us */
        if (diff < -BUCKETS)
            diff = -BUCKETS;
        else if (diff > BUCKETS)
            diff = BUCKETS;
        act_stats[cpu].times[diff+BUCKETS]++;
        act_stats[cpu].count++;

        if (act_stats[cpu].count >= 5000) {
            printk("ACT Stats\n");
            for (i=0; i < 2*BUCKETS; i++) {
                if (act_stats[cpu].times[i] != 0)
                    printk("ACT [%02d]: %3dus: %5d\n",
                           cpu,i-BUCKETS, act_stats[cpu].times[i]);
                act_stats[cpu].times[i]=0;
            }
            act_stats[cpu].count = 0;
            printk("\n");
        }
    }
#endif

#endif /* 0 */
