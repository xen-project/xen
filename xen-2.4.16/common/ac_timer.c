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

#include <asm/system.h>
#include <asm/desc.h>


#undef AC_TIMER_TRACE
#undef AC_TIMER_STATS

#ifdef AC_TIMER_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

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
	struct list_head *tmp, *prev;
	struct ac_timer	 *t;
	s_time_t		 now;

	/* sanity checks */

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

	local_irq_save(flags);

	/* check if timer would be inserted at start of list */
	if ((list_empty(&ac_timers[cpu].timers)) ||
		(timer->expires <
		(list_entry(&ac_timers[cpu].timers,
					struct ac_timer, timer_list))->expires)) {

		TRC(printk("ACT  [%02d] add(): add at head\n", cpu));
		/* Reprogramm and add to head of list */
		if (!reprogram_ac_timer(timer->expires)) {
			/* failed */
			TRC(printk("ACT  [%02d] add(): add at head failed\n", cpu));
			local_irq_restore(flags);
			return 1;
		}
		list_add(&timer->timer_list, &ac_timers[cpu].timers);
		
	} else {
		/* find correct entry and add timer */
		prev = &ac_timers[cpu].timers;
		list_for_each(tmp, &ac_timers[cpu].timers) {
			t = list_entry(tmp, struct ac_timer, timer_list);
			if (t->expires < timer->expires) {
				list_add(&timer->timer_list, prev);
				TRC(printk("ACT  [%02d] add(): added between %lld and %lld\n",
					   cpu,
					   list_entry(prev,struct ac_timer,timer_list)->expires,
					   list_entry(tmp,struct ac_timer,timer_list)->expires));
				break;
			}
			prev = tmp;
		}
	}
	local_irq_restore(flags);
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
	int res;
	unsigned long flags;
	TRC(int cpu = smp_processor_id());

	TRC(printk("ACT  [%02d] remove(): timo=%lld \n", cpu, timer->expires));
	/* sanity checks */

	local_irq_save(flags);
	res = detach_ac_timer(timer);	
	local_irq_restore(flags);
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
	s_time_t		 now;
	struct ac_timer	 *t;
	struct list_head *tmp;

	local_irq_save(flags);

 do_timer_again:

	now = NOW();
	TRC(printk("ACT  [%02d] do(): now=%lld\n", cpu, now));
		
	/* Sanity checks */
    /* empty time list  */
	if (list_empty(&ac_timers[cpu].timers)) {
		printk("ACT[%02d] do_ac_timer(): timer irq without timer\n", cpu);
		local_irq_restore(flags);
		return;
	}


	/* execute the head of timer queue */
	t = list_entry(ac_timers[cpu].timers.next, struct ac_timer, timer_list);
	detach_ac_timer(t);


#ifdef AC_TIMER_STATS
	{
		s32	diff;
		u32 i;
		diff = ((s32)(now - t->expires)) / 1000; /* delta in us */
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



	if (t->expires > now) {
		//printk("ACT  [%02d] do(): irq too early (%lld ns)\n",
		//	   cpu, now - t->expires );
	}
	if (t->function != NULL)
		t->function(t->data);


	/* check if there are other timer functions on the list */
	now = NOW();
	if (!list_empty(&ac_timers[cpu].timers)) {
		list_for_each(tmp, &ac_timers[cpu].timers) {
			t = list_entry(tmp, struct ac_timer, timer_list);
			TRC(printk("ACT  [%02d] do(): now=%lld timo=%lld\n",
					   cpu, now, t->expires));
			if (t->expires <= now) {
				detach_ac_timer(t);
				if (t->function != NULL)
					t->function(t->data);
				now = NOW();
			} else {
				TRC(printk("ACT  [%02d] do(): break1\n", cpu));
				break;
			}
		}
	}
		
	/* If list not empty reprogramm timer to new head of list */
	if (!list_empty(&ac_timers[cpu].timers)) {
		t = list_entry(ac_timers[cpu].timers.next,struct ac_timer,timer_list);
		if (t->expires > 0) {
			TRC(printk("ACT  [%02d] do(): reprog timo=%lld\n",cpu,t->expires));
			if (!reprogram_ac_timer(t->expires)) {
				TRC(printk("ACT  [%02d] do(): again\n", cpu));
				goto do_timer_again;
			}
		}
	}
	local_irq_restore(flags);
}

/*
 * init
 */
void __init ac_timer_init(void)
{
    int i;

	printk ("ACT: Initialising Accurate timers\n");

    for (i = 0; i < NR_CPUS; i++)
    {
		INIT_LIST_HEAD(&ac_timers[i].timers);
		spin_lock_init(&ac_timers[i].lock);
    }
	/* ac_timer_debug(0); */
}
