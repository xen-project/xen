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
#include <xeno/config.h>
#include <xeno/smp.h>
#include <xeno/init.h>

#include <xeno/time.h>
#include <xeno/ac_timer.h>
#include <xeno/keyhandler.h>

#include <asm/system.h>
#include <asm/desc.h>


#undef AC_TIMER_TRACE
#undef AC_TIMER_STATS

#ifdef AC_TIMER_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

/*
 * We pull handlers off the timer list this far in future,
 * rather than reprogramming the time hardware.
 */
#define TIMER_SLOP (50*1000) /* ns */

/* A timer list per CPU */
typedef struct ac_timers_st
{
    spinlock_t lock;
    struct list_head timers;
    struct ac_timer *prev, *curr;
} __cacheline_aligned ac_timers_t;
static ac_timers_t ac_timers[NR_CPUS];

#ifdef AC_TIMER_STATS
#define BUCKETS		1000
#define MAX_STATS
typedef struct act_stats_st
{
    u32 count;
    u32 times[2*(BUCKETS)];
} __cacheline_aligned act_stats_t;
static act_stats_t act_stats[NR_CPUS];

#endif

/* local prototypes */
static int  detach_ac_timer(struct ac_timer *timer);
/*static void ac_timer_debug(unsigned long);*/

/*
 * add a timer.
 * return value:
 *  0: success
 *  1: failure, timer in the past or timeout value to small
 * -1: failure, timer uninitialised
 * fail
 */
int add_ac_timer(struct ac_timer *timer)
{
    int 			 cpu = smp_processor_id();
    unsigned long 	 flags;
    s_time_t		 now;

    /* make sure timeout value is in the future */
    now = NOW();
    TRC(printk("ACT  [%02d] add(): now=%lld timo=%lld\n",
               cpu, now, timer->expires));
    if (timer->expires <= now) {	
        printk("ACT[%02d] add_ac_timer: now=0x%08X%08X > expire=0x%08X%08X\n",
               cpu, (u32)(now>>32), (u32)now,
               (u32)(timer->expires>>32), (u32)timer->expires);
        return 1;
    }
    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    /*
     * Add timer to the list. If it gets added to the front we have to
     * reprogramm the timer
     */
    if (list_empty(&ac_timers[cpu].timers)) {
        /* Reprogramm and add to head of list */
        if (!reprogram_ac_timer(timer->expires)) {
            /* failed */
            printk("ACT  [%02d] add(): add at head failed\n", cpu);
            spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
            return 1;
        }
        list_add(&timer->timer_list, &ac_timers[cpu].timers);
        TRC(printk("ACT  [%02d] add(0x%08X%08X): added at head\n", cpu,
                   (u32)(timer->expires>>32), (u32)timer->expires));
    } else {
        struct list_head *pos;
        struct ac_timer	 *t;
        for (pos = ac_timers[cpu].timers.next;
             pos != &ac_timers[cpu].timers;
             pos = pos->next) {
            t = list_entry(pos, struct ac_timer, timer_list);
            if (t->expires > timer->expires)
                break;
        }

        if (pos->prev == &ac_timers[cpu].timers) {
            /* added to head, reprogramm timer */
            if (!reprogram_ac_timer(timer->expires)) {
                /* failed */
                TRC(printk("ACT  [%02d] add(): add at head failed\n", cpu));
                spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
                return 1;
            }
            list_add (&(timer->timer_list), pos->prev);
            TRC(printk("ACT  [%02d] add(0x%08X%08X): added at head\n", cpu,
                       (u32)(timer->expires>>32), (u32)timer->expires));
        } else {
            list_add (&(timer->timer_list), pos->prev);
            TRC(printk("ACT  [%02d] add(0x%08X%08X): add < exp=0x%08X%08X\n",
                       cpu,
                       (u32)(timer->expires>>32), (u32)timer->expires,
                       (u32)(t->expires>>32), (u32)t->expires));
        }
    }
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
    return 0;
}

/*
 * remove a timer
 * return values:
 *  0: success
 * -1: bogus timer
 */
static int detach_ac_timer(struct ac_timer *timer)
{  
    TRC(int 			 cpu = smp_processor_id());
    TRC(printk("ACT  [%02d] detach(): \n", cpu));
    list_del(&timer->timer_list);
    timer->timer_list.next = NULL;
    return 0;
}

/*
 * remove a timer
 * return values:
 *  0: success
 * -1: bogus timer
 */
int rem_ac_timer(struct ac_timer *timer)
{
    int 		  cpu = smp_processor_id();
    int           res;
    unsigned long flags;

    TRC(printk("ACT  [%02d] remove(): timo=%lld \n", cpu, timer->expires));

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    res = detach_ac_timer(timer);	
    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);

    return res;
}

/*
 * modify a timer, i.e., set a new timeout value
 * return value:
 *  0: sucess
 * -1: error
 */
int mod_ac_timer(struct ac_timer *timer, s_time_t new_time)
{
    if (rem_ac_timer(timer) != 0)
        return -1;
    timer->expires = new_time;
    if (add_ac_timer(timer) != 0)
        return -1;
    return 0;
}

/*
 * do_ac_timer
 * deal with timeouts and run the handlers
 */
void do_ac_timer(void)
{
    int 			 cpu = smp_processor_id();
    unsigned long 	 flags;
    struct ac_timer	 *t;

    spin_lock_irqsave(&ac_timers[cpu].lock, flags);

 do_timer_again:

    TRC(printk("ACT  [%02d] do(): now=%lld\n", cpu, NOW()));
		
	/* Sanity: is the timer list empty? */
    if ( list_empty(&ac_timers[cpu].timers) )
        printk("ACT[%02d] do_ac_timer(): timer irq without timer\n", cpu);

#ifdef AC_TIMER_STATS
    {
        s32	diff;
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

    /* Handle all timeouts in the near future. */
    while ( !list_empty(&ac_timers[cpu].timers) )
    {
        t = list_entry(ac_timers[cpu].timers.next, 
                       struct ac_timer, timer_list);
        if ( t->expires > (NOW() + TIMER_SLOP) ) break;
        detach_ac_timer(t);
        spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
        if ( t->function != NULL ) t->function(t->data);
        spin_lock_irqsave(&ac_timers[cpu].lock, flags);
    }
		
    /* If list not empty then reprogram timer to new head of list */
    if ( !list_empty(&ac_timers[cpu].timers) )
    {
        t = list_entry(ac_timers[cpu].timers.next, 
                       struct ac_timer, timer_list);
        if ( t->expires > 0 )
        {
            TRC(printk("ACT  [%02d] do(): reprog timo=%lld\n",cpu,t->expires));
            if ( !reprogram_ac_timer(t->expires) )
            {
                TRC(printk("ACT  [%02d] do(): again\n", cpu));
                goto do_timer_again;
            }
        }
    }

    spin_unlock_irqrestore(&ac_timers[cpu].lock, flags);
    TRC(printk("ACT  [%02d] do(): end\n", cpu));
}

/*
 * debug dump_queue
 * arguments: queue head, name of queue
 */
static void dump_tqueue(struct list_head *queue, char *name)
{
    struct list_head *list;
    int loop = 0;
    struct ac_timer	 *t;

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


static void dump_timerq(u_char key, void *dev_id, struct pt_regs *regs)
{
    u_long   flags; 
    s_time_t now = NOW();

    printk("Dumping ac_timer queues for cpu 0: NOW=0x%08X%08X\n",
           (u32)(now>>32), (u32)now); 
	
    spin_lock_irqsave(&ac_timers[0].lock, flags);
    dump_tqueue(&ac_timers[0].timers, "ac_time"); 
    spin_unlock_irqrestore(&ac_timers[0].lock, flags);
    printk("\n");
    return; 
}


void __init ac_timer_init(void)
{
    int i;

    printk ("ACT: Initialising Accurate timers\n");

    for (i = 0; i < NR_CPUS; i++)
    {
        INIT_LIST_HEAD(&ac_timers[i].timers);
        spin_lock_init(&ac_timers[i].lock);
    }

    add_key_handler('a', dump_timerq, "dump ac_timer queues");
}
