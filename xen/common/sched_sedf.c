/****************************************************************************
 * Simple EDF scheduler for xen
 *
 * by Stephan Diestelhorst (C)  2004 Cambridge University
 * based on code by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/sched.h>
#include <xen/sched-if.h>
#include <public/sched_ctl.h>
#include <xen/ac_timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/slab.h>

/*#include <xen/adv_sched_hist.h>*/

/*verbosity settings*/
#define SEDFLEVEL 0
#define PRINT(_f, _a...)  \
if ((_f)<=SEDFLEVEL) printk(_a );

#ifdef DEBUG
	#define SEDF_STATS
#endif

/*various ways of unblocking domains*/
#define UNBLOCK_ISOCHRONOUS_EDF 1
#define UNBLOCK_EDF 2
#define UNBLOCK_ATROPOS 3
#define UNBLOCK_SHORT_RESUME 4
#define UNBLOCK_BURST 5
#define UNBLOCK_EXTRA_SUPPORT 6
#define UNBLOCK UNBLOCK_EXTRA_SUPPORT

/*various ways of treating extra-time*/
#define EXTRA_OFF 1
#define EXTRA_ROUNDR 2
#define EXTRA_SLICE_WEIGHT 3
#define EXTRA_BLOCK_WEIGHT 4

#define EXTRA EXTRA_BLOCK_WEIGHT

#define EXTRA_NONE (0)
#define EXTRA_AWARE (1)
#define EXTRA_RUN_PEN (2)
#define EXTRA_RUN_UTIL (4)
#define EXTRA_WANT_PEN_Q (8)
#define EXTRA_PEN_Q (0)
#define EXTRA_UTIL_Q (1)

#define extra_runs(inf) ((inf->extra) & 6)
#define extra_get_cur_q(inf) (((inf->extra & 6) >> 1)-1)

#define EXTRA_QUANTUM (MICROSECS(500)) 
#define WEIGHT_PERIOD (MILLISECS(100))
#define WEIGHT_SAFETY (MILLISECS(5))


struct sedf_dom_info
{
	struct domain		*owner;
	struct list_head	list;
	struct list_head	extralist[2];
	
	/*Parameters for EDF*/
	s_time_t		period;		/*=(relative deadline)*/
	s_time_t		slice;		/*=worst case execution time*/
	
	/*Advaced Parameters*/
	/*Latency Scaling*/
	s_time_t		period_orig;	
	s_time_t		slice_orig;
	s_time_t		latency;
	
	/*extra-time status of domain*/
	short			extra;
	/*weights for "Scheduling for beginners/ lazy/ etc." ;)*/
	short			weight;
	
	/*Bookkeeping*/
	s_time_t		absdead;
	s_time_t		sched_start;
	s_time_t		cputime;
	s_time_t		absblock;
	
	/*time the domain unblocked, used to determine unblocking intervals*/
	s_time_t		absunblock;
	
	/*scores for {util, block penalty}-weighted extratime distribution*/
	int			score[2];	
	s_time_t		short_block_lost_tot;
	
	/*Statistics*/
	s_time_t		extra_time_tot;

#ifdef SEDF_STATS
	s_time_t		block_time_tot;
	s_time_t		penalty_time_tot;
	int			block_tot;
	int			short_block_tot;
	int			long_block_tot;
	int			short_cont;
	int			pen_extra_blocks;
	int			pen_extra_slices;
#endif
};

struct sedf_cpu_info {
	struct list_head runnableq;
	struct list_head waitq;
	struct list_head extraq[2];
};

#define DOM_INFO(d)		((struct sedf_dom_info *)((d)->sched_priv))
#define CPU_INFO(cpu)	((struct sedf_cpu_info *)schedule_data[cpu].sched_priv)
#define LIST(d)			(&DOM_INFO(d)->list)
#define EXTRALIST(d,i)		(&(DOM_INFO(d)->extralist[i]))
#define RUNQ(cpu)   		(&CPU_INFO(cpu)->runnableq)
#define WAITQ(cpu)   		(&CPU_INFO(cpu)->waitq)
#define EXTRAQ(cpu,i)  		(&(CPU_INFO(cpu)->extraq[i]))
#define IDLETASK(cpu)		((struct domain *)schedule_data[cpu].idle)

#define PERIOD_BEGIN(inf)	((inf)->absdead - (inf)->period)

#define MIN(x,y) (((x)<(y))?(x):(y))
#define DIV_UP(x,y) (((x) + (y) - 1) / y)

static xmem_cache_t *dom_info_cache;

static void sedf_dump_cpu_state(int i);

static inline int extraq_on(struct domain *d, int i) {
	return ((EXTRALIST(d,i)->next != NULL) &&
		(EXTRALIST(d,i)->next != EXTRALIST(d,i)));
}

static inline void extraq_add_head(struct domain *d, int i)
{
    list_add(EXTRALIST(d,i), EXTRAQ(d->processor,i));
}

static inline void extraq_add_tail(struct domain *d, int i)
{
    list_add_tail(EXTRALIST(d,i), EXTRAQ(d->processor,i));
}

static inline void extraq_del(struct domain *d, int i)
{
	struct list_head *list = EXTRALIST(d,i);
	/*if (!extraq_on(d,i)) {
		PRINT(0,"extraq_del: domain %i is NOT on L%i extraq "\
			"HALTING\n",d->id,i);
		sedf_dump_cpu_state(0);(*((int*)0))++;
	}*/
	PRINT(3, "Removing domain %i from L%i extraq\n", d->id,i);	
	list_del(list);
	list->next = NULL;
}

/* adds a domain to the queue of processes which are aware of extra time. List
   is sorted by score, where a lower score means higher priority for an extra
   slice. It also updates the score, by simply subtracting a fixed value from
   each entry, in order to avoid overflow. The algorithm works by simply
   charging each domain that recieved extratime with an inverse of its weight.
 */ 
static inline void extraq_add_sort_update(struct domain *d, int i, int sub) {
	struct list_head     *cur;
	struct sedf_dom_info *curinf;
	
	/*if (extraq_on(d,i)) {
		PRINT(0,"extraq_add_sort_update: domain %i is already on "\
		        "L%i extraq! HALTING\n",d->id,i);
		sedf_dump_cpu_state(0);(*((int*)0))++;
	}*/
	PRINT(3, "Adding domain %i (score= %i, short_pen= %lli) to L%i "\
	         "extraq\n", d->id, DOM_INFO(d)->score[i],
	         DOM_INFO(d)->short_block_lost_tot, i);	
	/*iterate through all elements to find our "hole" and on our way
	  update all the other scores*/
	list_for_each(cur,EXTRAQ(d->processor,i)){
		curinf = list_entry(cur,struct sedf_dom_info,extralist[i]);
		curinf->score[i] -= sub;
		if (DOM_INFO(d)->score[i] < curinf->score[i])
	 		break;
		else
			PRINT(4,"\tbehind domain %i (score= %i)\n",
			      curinf->owner->id, curinf->score[i]);
	}
	/*cur now contains the element, before which we'll enqueue*/
	PRINT(3, "\tlist_add to %x\n", cur->prev);
	list_add(EXTRALIST(d,i),cur->prev);
	
	/*continue updating the extraq*/
	if ((cur != EXTRAQ(d->processor,i)) && sub)
		for (cur = cur->next; cur != EXTRAQ(d->processor,i);
		     cur = cur-> next) {
			curinf = list_entry(cur,struct sedf_dom_info,
				extralist[i]);
			curinf->score[i] -= sub;
			PRINT(4, "\tupdating domain %i (score= %llu)\n",
			      curinf->owner->id, curinf->score[i]);
		}
}
static inline void extraq_check(struct domain *d) {
	if (extraq_on(d, EXTRA_UTIL_Q)) {
		PRINT(2,"Dom %i is on extraQ\n",d->id);
		if (!(DOM_INFO(d)->extra & EXTRA_AWARE) &&
		    !extra_runs(DOM_INFO(d))) {
			extraq_del(d, EXTRA_UTIL_Q);
			PRINT(2,"Removed dom %i from L1 extraQ\n",d->id);
		}
	} else {
		PRINT(2,"Dom %i is NOT on L1 extraQ\n",d->id);
		if ((DOM_INFO(d)->extra & EXTRA_AWARE) && domain_runnable(d))
		{
			#if (EXTRA == EXTRA_ROUNDR)
			/*Favour domains which got short unblocked*/
			extraq_add_tail(d, EXTRA_UTIL_Q);
			#elif (EXTRA == EXTRA_SLICE_WEIGHT || \
			       EXTRA == EXTRA_BLOCK_WEIGHT)
			extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
			#elif
			;
			#endif
			PRINT(2,"Added dom %i to L1 extraQ\n",d->id);
		}
	}
}
static inline void __del_from_queue(struct domain *d)
{
    struct list_head *list = LIST(d);
    PRINT(3,"Removing domain %i (bop= %llu) from runq/waitq\n", d->id,
          PERIOD_BEGIN(DOM_INFO(d)));
    list_del(list);
    list->next = NULL;
}

/* adds a domain to the queue of processes which wait for the beginning of the
   next period; this list is therefore sortet by this time, which is simply
   absol. deadline - period
 */ 
static inline void __add_to_waitqueue_sort(struct domain *d) {
	struct list_head     *cur;
	struct sedf_dom_info *curinf;
	
	PRINT(3,"Adding domain %i (bop= %llu) to waitq\n", d->id,
	      PERIOD_BEGIN(DOM_INFO(d)));
	      
	/*iterate through all elements to find our "hole"*/
	list_for_each(cur,WAITQ(d->processor)){
		curinf = list_entry(cur,struct sedf_dom_info,list);
		if (PERIOD_BEGIN(DOM_INFO(d)) < PERIOD_BEGIN(curinf))
	 		break;
		else
			PRINT(4,"\tbehind domain %i (bop= %llu)\n",
			      curinf->owner->id, PERIOD_BEGIN(curinf));
	}
	/*cur now contains the element, before which we'll enqueue*/
	PRINT(3,"\tlist_add to %x\n",cur->prev);
	list_add(LIST(d),cur->prev);

}

/* adds a domain to the queue of processes which have started their current
   period and are runnable (i.e. not blocked, dieing,...). The first element
   on this list is running on the processor, if the list is empty the idle
   task will run. As we are implementing EDF, this list is sorted by deadlines.
 */ 
static inline void __add_to_runqueue_sort(struct domain *d) {
	struct list_head     *cur;
	struct sedf_dom_info *curinf;

	PRINT(3,"Adding domain %i (deadl= %llu) to runq\n", d->id,
	      DOM_INFO(d)->absdead);	
	      
	/*iterate through all elements to find our "hole"*/
	list_for_each(cur, RUNQ(d->processor)) {
		curinf = list_entry(cur, struct sedf_dom_info, list);
		if (DOM_INFO(d)->absdead < curinf->absdead)
	 		break;
		else
			PRINT(4,"\tbehind domain %i (deadl= %llu)\n",
			      curinf->owner->id, curinf->absdead);
	}
	
	/*cur now contains the element, before which we'll enqueue*/
	PRINT(3,"\tlist_add to %x\n",cur->prev);
	list_add(LIST(d),cur->prev);

}
static inline int __task_on_queue(struct domain *d) {
	return (((LIST(d))->next != NULL) && (LIST(d)->next != LIST(d)));
}

/* Initialises the queues and creates the domain info cache */
static int sedf_init_scheduler() {
	int i;
	PRINT(2,"sedf_init_scheduler was called\n");
	
	for ( i = 0; i < NR_CPUS; i++ ) {
		schedule_data[i].sched_priv = 
			xmalloc(sizeof(struct sedf_cpu_info));
		if ( schedule_data[i].sched_priv == NULL )
			return -1;
		INIT_LIST_HEAD(WAITQ(i));
		INIT_LIST_HEAD(RUNQ(i));
		INIT_LIST_HEAD(EXTRAQ(i,EXTRA_PEN_Q));
		INIT_LIST_HEAD(EXTRAQ(i,EXTRA_UTIL_Q));
	}
	dom_info_cache = xmem_cache_create("SEDF dom info",
		sizeof(struct sedf_dom_info), 0, 0, 0, NULL);
	if ( dom_info_cache == NULL )
	{
		printk("Could not allocate SLAB cache.\n");
		return -1;
	}
	
	return 0;   
}

/* Allocates memory for per domain private scheduling data*/
static int sedf_alloc_task(struct domain *d) {
	PRINT(2,"sedf_alloc_task was called, domain-id %i\n",d->id);
	if ( (d->sched_priv = xmem_cache_alloc(dom_info_cache)) == NULL )
		return -1;
	memset(d->sched_priv, 0, sizeof(struct sedf_dom_info));
	return 0;
}

/* Setup the sedf_dom_info */
static void sedf_add_task(struct domain *d)
{
	struct sedf_dom_info *inf=DOM_INFO(d);
	inf->owner = d;
	
	PRINT(2,"sedf_add_task was called, domain-id %i\n",d->id);
	if (d->id==0) {
		/*set dom0 to something useful to boot the machine*/
		inf->period    = MILLISECS(20);
		inf->slice     = MILLISECS(15);
		inf->latency   = 0;
		inf->absdead   = 0;
		inf->extra     = EXTRA_NONE;/*EXTRA_AWARE; */
	}
	else {
		/*other domains run in best effort mode*/
		inf->period    = MILLISECS(20);
		inf->slice     = 0;
		inf->absdead   = 0;
		inf->latency   = 0;
		inf->extra     = EXTRA_AWARE;
	}
	inf->period_orig = inf->period; inf->slice_orig = inf->slice;
	INIT_LIST_HEAD(&(inf->list));
	INIT_LIST_HEAD(&(inf->extralist[EXTRA_PEN_Q]));
	INIT_LIST_HEAD(&(inf->extralist[EXTRA_UTIL_Q]));
}

/* Frees memory used by domain info */
static void sedf_free_task(struct domain *d)
{
	PRINT(2,"sedf_free_task was called, domain-id %i\n",d->id);
	ASSERT(d->sched_priv != NULL);
	xmem_cache_free(dom_info_cache, d->sched_priv);
}

/* Initialises idle task */
static int sedf_init_idle_task(struct domain *d) {
	PRINT(2,"sedf_init_idle_task was called, domain-id %i\n",d->id);
	if ( sedf_alloc_task(d) < 0 )
		return -1;
	
	sedf_add_task(d);
	DOM_INFO(d)->absdead = 0;
	set_bit(DF_RUNNING, &d->flags);
	/*the idle task doesn't have to turn up on any list...*/
	return 0;
}

/* handles the rescheduling, bookkeeping of domains running in their realtime-time :)*/
static inline void desched_edf_dom (s_time_t now, struct domain* d) {
	struct sedf_dom_info* inf = DOM_INFO(d);
	/*current domain is running in real time mode*/
	
	/*update the domains cputime*/
	inf->cputime += now - inf->sched_start;

	/*scheduling decisions, which don't remove the running domain
	  from the runq*/
	if ((inf->cputime < inf->slice) && domain_runnable(d))
		return;
		
	__del_from_queue(d);
	/*if (__task_on_queue(current)) {
		PRINT(0,"domain %i was removed but still on run/waitq => "\
		        "HALT\n",current->id);
		sedf_dump_cpu_state(0);(*((int*)0))++;
	}*/
	
	/*manage bookkeeping (i.e. calculate next deadline,
	  memorize overun-time of slice) of finished domains*/
	if (inf->cputime >= inf->slice) {
		inf->cputime -= inf->slice;
		
		if (inf->period < inf->period_orig) {
			/*this domain runs in latency scaling or burst mode*/
			#if (UNBLOCK == UNBLOCK_BURST)
			if (now - inf->absunblock >= 2 * inf->period)
			#endif
			{
				inf->period *= 2; inf->slice *= 2;
				if ((inf->period > inf->period_orig) ||
				    (inf->slice > inf->slice_orig)) {
					/*reset slice & period*/
					inf->period = inf->period_orig;
					inf->slice = inf->slice_orig;
				}
			}
		}
		/*set next deadline*/
		inf->absdead += inf->period;
	}
	/*if (inf->absdead<now)
		printk("Domain %i exceeded it't deadline!!!! "\
		       "(now: %llu ddl: %llu)\n", current->id, now,
		       inf->absdead);*/
		       
	/*add a runnable domain to the waitqueue*/
	if (domain_runnable(d))
		__add_to_waitqueue_sort(d);
	else {
		/*we have a blocked realtime task*/
		inf->absblock = now;
		#if (EXTRA > EXTRA_OFF)
		#if (EXTRA == EXTRA_BLOCK_WEIGHT)
		if (extraq_on(d,EXTRA_PEN_Q)) extraq_del(d,EXTRA_PEN_Q);
		#endif
		if (extraq_on(d,EXTRA_UTIL_Q)) extraq_del(d,EXTRA_UTIL_Q);
		#endif
	}
}

/* Update all elements on the queues */
static inline void update_queues(
s_time_t now, struct list_head* runq, struct list_head* waitq) {
	struct list_head     *cur,*tmp;
	struct sedf_dom_info *curinf;
	
	PRINT(3,"Updating waitq..\n");
	/*check for the first elements of the waitqueue, whether their
	  next period has already started*/
	list_for_each_safe(cur, tmp, waitq) {
		curinf = list_entry(cur, struct sedf_dom_info, list);
		PRINT(4,"\tLooking @ dom %i\n", curinf->owner->id);
		if (PERIOD_BEGIN(curinf) <= now) {
			__del_from_queue(curinf->owner);
			__add_to_runqueue_sort(curinf->owner);
		}
		else
			break;
	}
	
	PRINT(3,"Updating runq..\n");
	/*process the runq, find domains that are on
	  the runqueue which shouldn't be there*/
	list_for_each_safe(cur, tmp, runq) {
		curinf = list_entry(cur,struct sedf_dom_info,list);
		PRINT(4,"\tLooking @ dom %i\n", curinf->owner->id);
		if (unlikely(curinf->slice == 0)) {
			/*ignore domains with empty slice*/
			PRINT(4,"\tUpdating zero-slice domain %i\n",
			      curinf->owner->id);
			__del_from_queue(curinf->owner);
			
			/*move them to their next period*/
			curinf->absdead += curinf->period;
			/*and put them back into the queue*/
			__add_to_waitqueue_sort(curinf->owner);
		}
		else {
			if (unlikely((curinf->absdead < now) ||
			   (curinf->cputime > curinf->slice))) {
				/*we missed the deadline or the slice was
				  already finished... might hapen because
				  of dom_adj.*/
				PRINT(4,"\tDomain %i exceeded it's deadline/"\
				       "slice (%llu / %llu) now: %llu "\
				       "cputime: %llu\n", curinf->owner->id,
				       curinf->absdead, curinf->slice, now,
				       curinf->cputime);
				__del_from_queue(curinf->owner);
				/*common case: we miss one period!*/
				curinf->absdead += curinf->period;
				
				/*if we are still behind: modulo arithmetic,
				  force deadline to be in future and
				  aligned to period borders!*/
				if (unlikely(curinf->absdead < now))
					curinf->absdead += 
					  DIV_UP(now - curinf->absdead,
					     curinf->period) * curinf->period;
					     
				/*give a fresh slice*/
				curinf->cputime = 0;
				if (PERIOD_BEGIN(curinf) < now)
					__add_to_waitqueue_sort(curinf->owner);
				else
					__add_to_runqueue_sort(curinf->owner);
			}
			else
				break;
		}
	}
	PRINT(3,"done updating the queues\n");
}

#if (EXTRA > EXTRA_OFF)
/* removes a domain from the head of the according extraQ and
   requeues it at a specified position:
     round-robin extratime: end of extraQ
     weighted ext.: insert in sorted list by score
   if the domain is blocked / has regained its short-block-loss
   time it is not put on any queue */
static inline void desched_extra_dom(s_time_t now, struct domain* d) {
	struct sedf_dom_info	*inf = DOM_INFO(d);
	int 			i    = extra_get_cur_q(inf);
	
	#if (EXTRA == EXTRA_SLICE_WEIGHT || EXTRA == EXTRA_BLOCK_WEIGHT)
	unsigned long         oldscore;
	#endif
	
	/*unset all running flags*/
	inf->extra  &= ~(EXTRA_RUN_PEN | EXTRA_RUN_UTIL);
	/*fresh slice for the next run*/
	inf->cputime = 0;
	/*accumulate total extratime*/
	inf->extra_time_tot += now - inf->sched_start;
	/*remove extradomain from head of the queue*/
	extraq_del(d, i);

	#if (EXTRA == EXTRA_ROUNDR)
	if (domain_runnable(d))
		/*add to the tail if it is runnable => round-robin*/
		extraq_add_tail(d, EXTRA_UTIL_Q);
	#elif (EXTRA == EXTRA_SLICE_WEIGHT || EXTRA == EXTRA_BLOCK_WEIGHT)
	/*update the score*/
	oldscore      = inf->score[i];
	#if (EXTRA == EXTRA_BLOCK_WEIGHT)
	if (i == EXTRA_PEN_Q) {
		/*domain was running in L0 extraq*/
		/*reduce block lost, probably more sophistication here!*/
		/*inf->short_block_lost_tot -= EXTRA_QUANTUM;*/
		inf->short_block_lost_tot -= now - inf->sched_start;
		PRINT(3,"Domain %i: Short_block_lost: %lli\n", 
		      inf->owner->id, inf->short_block_lost_tot);
		if (inf->short_block_lost_tot <= 0) {
			PRINT(4,"Domain %i compensated short block loss!\n");
			/*we have (over-)compensated our block penalty*/
			inf->short_block_lost_tot = 0;
			/*we don't want a place on the penalty queue anymore!*/
			inf->extra &= ~EXTRA_WANT_PEN_Q;
			/*do not add us on this block extraq again!*/
			return;
		}
		/*we have to go again for another try in the block-extraq,
		  the score is not used incremantally here, as this is
		  already done by recalculating the block_lost*/
		inf->score[EXTRA_PEN_Q] = (inf->period << 10) /
		                          inf->short_block_lost_tot;
		oldscore = 0;
	} else
	#endif
	{
		/*domain was running in L1 extraq => score is inverse of
		  utilization and is used somewhat incremental!*/
		if (inf->slice)
			/*NB: use fixed point arithmetic with 10 bits*/
			inf->score[EXTRA_UTIL_Q] = (inf->period << 10) /
			                            inf->slice;
		else
			/*set best effort domains to the maximum value*/
			inf->score[EXTRA_UTIL_Q] = 2^10;
	}
	if (domain_runnable(d))
		/*add according to score: weighted round robin*/
		extraq_add_sort_update(d, i, oldscore);
	else {
		inf->absblock = now;
		/*if (!__task_on_queue(d)) 
			printf("Oops... We attempt to remove d %i from the "\
			       "waitq, but it is not on :(\n",d->id);*/
		/*remove this blocked domain from the waitq!*/
		__del_from_queue(d);				
		/*make sure that we remove a blocked domain from the other
		  extraq aswell (this caused hours of debugging!)*/
		#if (EXTRA == EXTRA_BLOCK_WEIGHT)
		if (i == EXTRA_PEN_Q) {
			if (extraq_on(d,EXTRA_UTIL_Q))
				extraq_del(d,EXTRA_UTIL_Q);
		}
		else {
			if (extraq_on(d,EXTRA_PEN_Q))
				extraq_del(d,EXTRA_PEN_Q);
		}
		#endif
	}
	#endif
	/*if (!domain_runnable(d)) {
		if (extraq_on(d,EXTRA_UTIL_Q)) {
			PRINT(0,"domain %i is blocked but still on L1 "\
			        "xq=> HALT\n",d->id);
			sedf_dump_cpu_state(0);(*((int*)0))++;
		}
		if (__task_on_queue(d)) {
			PRINT(0,"domain %i is blocked but still on run/waitq"\
			        "=> HALT\n",d->id);
			sedf_dump_cpu_state(0);(*((int*)0))++;
		}
	}*/
}
#endif


static inline task_slice_t sedf_do_extra_schedule
(s_time_t now, s_time_t end_xt, struct list_head *extraq[], int cpu) {
	task_slice_t 		ret;
	struct sedf_dom_info	*runinf;
	
	if (end_xt - now < EXTRA_QUANTUM)
		goto return_idle;
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
	if (!list_empty(extraq[EXTRA_PEN_Q])) {
		/*we still have elements on the level 0 extraq 
		  => let those run first!*/
		runinf   = list_entry(extraq[EXTRA_PEN_Q]->next, 
		              struct sedf_dom_info, extralist[EXTRA_PEN_Q]);
		runinf->extra |= EXTRA_RUN_PEN;
		ret.task = runinf->owner;
		ret.time = EXTRA_QUANTUM;
#ifdef SEDF_STATS
		runinf->pen_extra_slices++;
#endif
	} else
#endif
	if (!list_empty(extraq[EXTRA_UTIL_Q])) {
		/*use elements from the normal extraqueue*/
		runinf   = list_entry(extraq[EXTRA_UTIL_Q]->next,
		              struct sedf_dom_info,extralist[EXTRA_UTIL_Q]);
		runinf->extra |= EXTRA_RUN_UTIL;
		ret.task = runinf->owner;
		ret.time = EXTRA_QUANTUM;
	}
	else
		goto return_idle;

	return ret;
	
return_idle:
	ret.task = IDLETASK(cpu);
	ret.time = end_xt - now;
	return ret;
}
/* Main scheduling function
   Reasons for calling this function are:
   -timeslice for the current period used up
   -domain on waitqueue has started it's period
   -and various others ;) in general: determine which domain to run next*/
static task_slice_t sedf_do_schedule(s_time_t now)
{
	int                   cpu      = current->processor;
	struct list_head     *runq     = RUNQ(cpu);
	struct list_head     *waitq    = WAITQ(cpu);
	#if (EXTRA > EXTRA_OFF)
	struct sedf_dom_info *inf      = DOM_INFO(current);
	struct list_head     *extraq[] = {EXTRAQ(cpu,EXTRA_PEN_Q),
	                                  EXTRAQ(cpu, EXTRA_UTIL_Q)};
	#endif
	task_slice_t          ret;
	/*int i = 0;*/
	/*idle tasks don't need any of the following stuf*/
	if (is_idle_task(current))
		goto check_waitq;
	
	#if (EXTRA > EXTRA_OFF)
	if (unlikely(extra_runs(inf))) {
		/*i=1;*/
		/*special treatment of domains running in extra time*/
		desched_extra_dom(now, current);
	}
	else 
	#endif
	{
		/*i=2;*/
		desched_edf_dom(now, current);
	}
	/*if (!domain_runnable(current)) {
		if (extraq_on(current,EXTRA_UTIL_Q)) {
			PRINT(0,"domain %i is blocked but still on L1 xq"\
			        " branch %i=> HALT\n", current->id, i);
			sedf_dump_cpu_state(0);(*((int*)0))++;
		}
		if (__task_on_queue(current)) {
			PRINT(0,"domain %i is blocked but still on run/waitq"\
			        " branch %i=> HALT\n",current->id,i);
			sedf_dump_cpu_state(0);(*((int*)0))++;
		}
	}*/
check_waitq:
	update_queues(now, runq, waitq);
	
	/*now simply pick the first domain from the runqueue*/
	struct sedf_dom_info *runinf, *waitinf;
	
	if (!list_empty(runq)) {
		runinf   = list_entry(runq->next,struct sedf_dom_info,list);
		ret.task = runinf->owner;
		if (!list_empty(waitq)) {
			waitinf  = list_entry(waitq->next,
			               struct sedf_dom_info,list);
			/*rerun scheduler, when scheduled domain reaches it's
			  end of slice or the first domain from the waitqueue
			  gets ready*/
			ret.time = MIN(now + runinf->slice - runinf->cputime,
			               PERIOD_BEGIN(waitinf)) - now;
		}
		else {
			ret.time = runinf->slice - runinf->cputime;
		}
		goto sched_done;
	}
	
	if (!list_empty(waitq)) {
		waitinf  = list_entry(waitq->next,struct sedf_dom_info,list);
		/*we could not find any suitable domain 
		  => look for domains that are aware of extratime*/
		#if (EXTRA > EXTRA_OFF)
		ret = sedf_do_extra_schedule(now, PERIOD_BEGIN(waitinf),
		                             extraq, cpu);
		#else
		ret.task = IDLETASK(cpu);
		ret.time = PERIOD_BEGIN(waitinf) - now;
		#endif
	}
	else {
		/*this could probably never happen, but one never knows...*/
		/*it can... imagine a second CPU, which is pure scifi ATM,
		  but one never knows ;)*/
		ret.task = IDLETASK(cpu);
		ret.time = SECONDS(1);
	}

sched_done:	
	/*TODO: Do something USEFUL when this happens and find out, why it
	still can happen!!!*/
	if (ret.time<0) {
		printk("Ouch! We are seriously BEHIND schedule! %lli\n",
		       ret.time);
		ret.time = EXTRA_QUANTUM;
	}
	DOM_INFO(ret.task)->sched_start=now;
	return ret;
}

static void sedf_sleep(struct domain *d) {
	PRINT(2,"sedf_sleep was called, domain-id %i\n",d->id);
	if ( test_bit(DF_RUNNING, &d->flags) ) {
#ifdef ADV_SCHED_HISTO
		adv_sched_hist_start(d->processor);
#endif
		cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
	}
	else  {
		if ( __task_on_queue(d) )
			__del_from_queue(d);
		#if (EXTRA > EXTRA_OFF)
		if (extraq_on(d, EXTRA_UTIL_Q)) 
			extraq_del(d, EXTRA_UTIL_Q);
		#endif
		#if (EXTRA == EXTRA_BLOCK_WEIGHT)
		if (extraq_on(d, EXTRA_PEN_Q))
			extraq_del(d, EXTRA_PEN_Q);
		#endif
	}
}

/* This function wakes up a domain, i.e. moves them into the waitqueue
 * things to mention are: admission control is taking place nowhere at
 * the moment, so we can't be sure, whether it is safe to wake the domain
 * up at all. Anyway, even if it is safe (total cpu usage <=100%) there are
 * some considerations on when to allow the domain to wake up and have it's
 * first deadline...
 * I detected 3 cases, which could describe the possible behaviour of the
 * scheduler,
 * and I'll try to make them more clear:
 *
 * 1. Very conservative
 *     -when a blocked domain unblocks, it is allowed to start execution at
 *      the beginning of the next complete period
 *      (D..deadline, R..running, B..blocking/sleeping, U..unblocking/waking up
 *
 *      DRRB_____D__U_____DRRRRR___D________ ... 
 *
 *     -this causes the domain to miss a period (and a deadlline)
 *     -doesn't disturb the schedule at all
 *     -deadlines keep occuring isochronous
 *
 * 2. Conservative Part 1: Short Unblocking
 *     -when a domain unblocks in the same period as it was blocked it
 *      unblocks and may consume the rest of it's original time-slice minus
 *      the time it was blocked
 *      (assume period=9, slice=5)
 *
 *      DRB_UR___DRRRRR___D...
 *
 *     -this also doesn't disturb scheduling, but might lead to the fact, that
 *      the domain can't finish it's workload in the period
 *     -in addition to that the domain can be treated prioritised when
 *      extratime is available
 *     -addition: experiments hve shown that this may have a HUGE impact on
 *      performance of other domains, becaus it can lead to excessive context
 *      switches
 
 *    Part2: Long Unblocking
 *    Part 2a
 *     -it is obvious that such accounting of block time, applied when
 *      unblocking is happening in later periods, works fine aswell
 *     -the domain is treated as if it would have been running since the start
 *      of its new period
 *
 *      DRB______D___UR___D... 
 *
 *    Part 2b
 *     -if one needs the full slice in the next period, it is necessary to
 *      treat the unblocking time as the start of the new period, i.e. move
 *      the deadline further back (later)
 *     -this doesn't disturb scheduling as well, because for EDF periods can
 *      be treated as minimal inter-release times and scheduling stays
 *      correct, when deadlines are kept relative to the time the process
 *      unblocks
 *
 *      DRB______D___URRRR___D...<prev [Thread] next>
 *                       (D) <- old deadline was here
 *     -problem: deadlines don't occur isochronous anymore
 *    Part 2c (Improved Atropos design)
 *     -when a domain unblocks it is given a very short period (=latency hint)
 *      and slice length scaled accordingly
 *     -both rise again to the original value (e.g. get doubled every period)
 *
 * 3. Unconservative (i.e. incorrect)
 *     -to boost the performance of I/O dependent domains it would be possible
 *      to put the domain into the runnable queue immediately, and let it run
 *      for the remainder of the slice of the current period
 *      (or even worse: allocate a new full slice for the domain) 
 *     -either behaviour can lead to missed deadlines in other domains as
 *      opposed to approaches 1,2a,2b
 */
static inline void unblock_short_vcons
(struct sedf_dom_info* inf, s_time_t now) {
	inf->absdead += inf->period;
	inf->cputime = 0;
}

static inline void unblock_short_cons(struct sedf_dom_info* inf, s_time_t now)
{
	/*treat blocked time as consumed by the domain*/
	inf->cputime += now - inf->absblock;	
	if (inf->cputime + EXTRA_QUANTUM > inf->slice) {
		/*we don't have a reasonable amount of time in 
		  our slice left :( => start in next period!*/
		unblock_short_vcons(inf, now);
	}
#ifdef SEDF_STATS
	else
		inf->short_cont++;
#endif
}
static inline void unblock_short_extra_support (struct sedf_dom_info* inf,
   s_time_t now) {
	/*this unblocking scheme tries to support the domain, by assigning it
	   a priority in extratime distribution according to the loss of time
	   in this slice due to blocking*/
	s_time_t pen;
	
	/*no more realtime execution in this period!*/
	inf->absdead += inf->period;
	if (likely(inf->absblock)) {
		//treat blocked time as consumed by the domain*/
		/*inf->cputime += now - inf->absblock;*/	
		pen = (inf->slice - inf->cputime);
		if (pen < 0) pen = 0;
		/*accumulate all penalties over the periods*/
		/*inf->short_block_lost_tot += pen;*/
		/*set penalty to the current value*/
		inf->short_block_lost_tot = pen;
		/*not sure which one is better.. but seems to work well...*/
		
		if (inf->short_block_lost_tot) {
			inf->score[0] = (inf->period << 10) /
			                 inf->short_block_lost_tot;
#ifdef SEDF_STATS
			inf->pen_extra_blocks++;
#endif
			if (extraq_on(inf->owner, EXTRA_PEN_Q))
				/*remove domain for possible resorting!*/
				extraq_del(inf->owner, EXTRA_PEN_Q);
			else
				/*remember that we want to be on the penalty q
				  so that we can continue when we (un-)block
				  in penalty-extratime*/
				inf->extra |= EXTRA_WANT_PEN_Q;
			
			/*(re-)add domain to the penalty extraq*/
			extraq_add_sort_update(inf->owner,
					 EXTRA_PEN_Q, 0);
		}
	}
	/*give it a fresh slice in the next period!*/
	inf->cputime = 0;
}
static inline void unblock_long_vcons(struct sedf_dom_info* inf, s_time_t now)
{
	/* align to next future period */
	inf->absdead += ((now - inf->absdead) / inf->period + 1)
	                 * inf->period;
	inf->cputime = 0;
}

static inline void unblock_long_cons_a (struct sedf_dom_info* inf,
   s_time_t now) {
	/*treat the time the domain was blocked in the
	  CURRENT period as consumed by the domain*/
	inf->cputime = (now - inf->absdead) % inf->period;	
	if (inf->cputime + EXTRA_QUANTUM > inf->slice) {
		/*we don't have a reasonable amount of time in our slice
		  left :( => start in next period!*/
		unblock_long_vcons(inf, now);
	}
}
static inline void unblock_long_cons_b(struct sedf_dom_info* inf,s_time_t now) {
	/*Conservative 2b*/
	/*Treat the unblocking time as a start of a new period */
	inf->absdead = now + inf->period;
	inf->cputime = 0;
}
static inline void unblock_long_cons_c(struct sedf_dom_info* inf,s_time_t now) {
	if (likely(inf->latency)) {
		/*scale the slice and period accordingly to the latency hint*/
		/*reduce period temporarily to the latency hint*/
		inf->period = inf->latency;
		/*this results in max. 4s slice/period length*/
		ASSERT((inf->period < ULONG_MAX)
		    && (inf->slice_orig < ULONG_MAX));
		/*scale slice accordingly, so that utilisation stays the same*/
		inf->slice = (inf->period * inf->slice_orig)
		            / inf->period_orig;
		inf->absdead = now + inf->period;
		inf->cputime = 0;
	}	
	else {
		/*we don't have a latency hint.. use some other technique*/
		unblock_long_cons_b(inf, now);
	}
}
/*a new idea of dealing with short blocks: burst period scaling*/
static inline void unblock_short_burst(struct sedf_dom_info* inf, s_time_t now)
{
	/*treat blocked time as consumed by the domain*/
	inf->cputime += now - inf->absblock;
	
	if (inf->cputime + EXTRA_QUANTUM <= inf->slice) {
		/*if we can still use some time in the current slice
		  then use it!*/
#ifdef SEDF_STATS
		/*we let the domain run in the current period*/
		inf->short_cont++;
#endif
	}
	else {
		/*we don't have a reasonable amount of time in
		  our slice left => switch to burst mode*/
		if (likely(inf->absunblock)) {
			/*set the period-length to the current blocking
			  interval, possible enhancements: average over last
			  blocking intervals, user-specified minimum,...*/
			inf->period = now - inf->absunblock;
			/*check for overflow on multiplication*/
			ASSERT((inf->period < ULONG_MAX) 
			    && (inf->slice_orig < ULONG_MAX));
			/*scale slice accordingly, so that utilisation
			  stays the same*/
			inf->slice = (inf->period * inf->slice_orig)
			            / inf->period_orig;
			/*set new (shorter) deadline*/
			inf->absdead += inf->period;
		}
		else {
			/*in case we haven't unblocked before
			  start in next period!*/
			inf->cputime=0;
			inf->absdead += inf->period;
		}
	}
	inf->absunblock = now;
}
static inline void unblock_long_burst(struct sedf_dom_info* inf,s_time_t now) {
	if (unlikely(inf->latency && (inf->period > inf->latency))) {
		/*scale the slice and period accordingly to the latency hint*/
		inf->period = inf->latency;
		/*check for overflows on multiplication*/
		ASSERT((inf->period < ULONG_MAX)
		    && (inf->slice_orig < ULONG_MAX));
		/*scale slice accordingly, so that utilisation stays the same*/
		inf->slice = (inf->period * inf->slice_orig)
		            / inf->period_orig;
		inf->absdead = now + inf->period;
		inf->cputime = 0;
	}
	else {
		/*we don't have a latency hint.. or we are currently in 
		 "burst mode": use some other technique
		  NB: this should be in fact the normal way of operation,
		  when we are in sync with the device!*/
		unblock_long_cons_b(inf, now);
	}
	inf->absunblock = now;
}

#define DOMAIN_EDF 		1
#define DOMAIN_EXTRA_PEN 	2
#define DOMAIN_EXTRA_UTIL 	3
#define DOMAIN_IDLE 		4
static inline int get_run_type(struct domain* d) {
	struct sedf_dom_info* inf = DOM_INFO(d);
	if (is_idle_task(d))
		return DOMAIN_IDLE;
	if (inf->extra & EXTRA_RUN_PEN)
		return DOMAIN_EXTRA_PEN;
	if (inf->extra & EXTRA_RUN_UTIL)
		return DOMAIN_EXTRA_UTIL;
	return DOMAIN_EDF;
}
/*Compares two domains in the relation of whether the one is allowed to
  interrupt the others execution.
  It returns true (!=0) if a switch to the other domain is good.
  Current Priority scheme is as follows:
  	EDF > L0 (penalty based) extra-time > 
  	L1 (utilization) extra-time > idle-domain
  In the same class priorities are assigned as following:
  	EDF: early deadline > late deadline
  	L0 extra-time: lower score > higher score*/
static inline int should_switch(struct domain* cur, struct domain* other,
    s_time_t now) {
	struct sedf_dom_info *cur_inf, *other_inf;
	cur_inf   = DOM_INFO(cur);
	other_inf = DOM_INFO(other);
	
	/*check whether we need to make an earlier sched-decision*/
	if ((PERIOD_BEGIN(other_inf) < 
	     schedule_data[other->processor].s_timer.expires))
		return 1;
	/*no timing-based switches need to be taken into account here*/
	switch (get_run_type(cur)) {
		case DOMAIN_EDF:
			/* do not interrupt a running EDF domain */ 
			return 0;
		case DOMAIN_EXTRA_PEN:
			/*check whether we also want 
			  the L0 ex-q with lower score*/
			if ((other_inf->extra & EXTRA_WANT_PEN_Q)
			&&  (other_inf->score[EXTRA_PEN_Q] < 
			     cur_inf->score[EXTRA_PEN_Q]))
				return 1;
			else	return 0;
		case DOMAIN_EXTRA_UTIL:
			/*check whether we want the L0 extraq, don't
			  switch if both domains want L1 extraq */
			if (other_inf->extra & EXTRA_WANT_PEN_Q)
				return 1;
			else	return 0;
		case DOMAIN_IDLE:
			return 1;
	}
}
void sedf_wake(struct domain *d) {
	s_time_t              now = NOW();
	struct sedf_dom_info* inf = DOM_INFO(d);
	
	PRINT(3,"sedf_wake was called, domain-id %i\n",d->id);
	
	if (unlikely(is_idle_task(d)))
		return;
	
	if ( unlikely(__task_on_queue(d)) ) {
		PRINT(3,"\tdomain %i is already in some queue\n",d->id);
		return;
	}
	if ( unlikely(extraq_on(d,EXTRA_UTIL_Q) || extraq_on(d,EXTRA_PEN_Q)) ) {
		PRINT(3,"\tdomain %i is already in the extraQ\n",d->id);
	}
	if (unlikely(inf->absdead == 0))
		/*initial setup of the deadline*/
		inf->absdead = now + inf->slice;
		
	PRINT(3,"waking up domain %i (deadl= %llu period= %llu "\
	        "now= %llu)\n",d->id,inf->absdead,inf->period,now);
#ifdef SEDF_STATS	
	inf->block_tot++;
#endif
	if (unlikely(now< PERIOD_BEGIN(inf))) {
		PRINT(4,"extratime unblock\n");
		/*this might happen, imagine unblocking in extra-time!*/
		#if (EXTRA == EXTRA_BLOCK_WEIGHT)
		if (inf->extra & EXTRA_WANT_PEN_Q) {
			/*we have a domain that wants compensation
			  for block penalty and did just block in
			  its compensation time. Give it another
			  chance!*/
			extraq_add_sort_update(d, EXTRA_PEN_Q, 0);
		}
		#endif
		if (inf->extra & EXTRA_AWARE) 
		#if (EXTRA == EXTRA_ROUNDR)
			extraq_add_tail(d,EXTRA_UTIL_Q);
			#elif (EXTRA == EXTRA_SLICE_WEIGHT \
			    || EXTRA == EXTRA_BLOCK_WEIGHT)
			/*put in on the weighted extraq, 
			  without updating any scores*/
			extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
		#else
			;
		#endif
		/*else*/
		/*This is very very unlikely, ie. might even be an error?!*/
	}		
	else {		
		if (now < inf->absdead) {
			PRINT(4,"short unblocking\n");
			/*short blocking*/
#ifdef SEDF_STATS
			inf->short_block_tot++;
#endif
			#if (UNBLOCK <= UNBLOCK_ATROPOS)
			unblock_short_vcons(inf, now);
			#elif (UNBLOCK == UNBLOCK_SHORT_RESUME)
			unblock_short_cons(inf, now);
			#elif (UNBLOCK == UNBLOCK_BURST)
			unblock_short_burst(inf, now);
			#elif (UNBLOCK == UNBLOCK_EXTRA_SUPPORT)
			unblock_short_extra_support(inf, now);
			#endif

			if (inf->extra & EXTRA_AWARE)
				#if (EXTRA == EXTRA_OFF)
				;
				#elif (EXTRA == EXTRA_ROUNDR)
				/*Favour domains which got short unblocked*/
				extraq_add_head(d, EXTRA_UTIL_Q);
				#elif (EXTRA == EXTRA_SLICE_WEIGHT \
				    || EXTRA == EXTRA_BLOCK_WEIGHT)
				extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
				#endif
		}
		else {
			PRINT(4,"long unblocking\n");
			/*long unblocking*/
#ifdef SEDF_STATS
			inf->long_block_tot++;
#endif
			#if (UNBLOCK == UNBLOCK_ISOCHRONOUS_EDF)
			unblock_long_vcons(inf, now);
			#elif (UNBLOCK == UNBLOCK_EDF \
			    || UNBLOCK == UNBLOCK_EXTRA_SUPPORT)
			unblock_long_cons_b(inf, now);
			#elif (UNBLOCK == UNBLOCK_ATROPOS)
			unblock_long_cons_c(inf, now);
			#elif (UNBLOCK == UNBLOCK_SHORT_RESUME)
			unblock_long_cons_b(inf, now);
			/*unblock_short_cons_c(inf, now);*/
			#elif (UNBLOCK == UNBLOCK_BURST)
			unblock_long_burst(inf, now);
			#endif
			
			if (inf->extra & EXTRA_AWARE) {
				#if (EXTRA == EXTRA_OFF)
				;
				#elif (EXTRA == EXTRA_ROUNDR)
				extraq_add_head(d, EXTRA_UTIL_Q);
				#elif (EXTRA == EXTRA_SLICE_WEIGHT \
				    || EXTRA == EXTRA_BLOCK_WEIGHT)
				extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
				#endif
			}
			
		}
	}
	PRINT(3,"woke up domain %i (deadl= %llu period= %llu "\
	        "now= %llu)\n",d->id,inf->absdead,inf->period,now);
	__add_to_waitqueue_sort(d);
	PRINT(3,"added to waitq\n");	
	
#ifdef SEDF_STATS
	/*do some statistics here...*/
	if (inf->absblock != 0) {
		inf->block_time_tot += now - inf->absblock;
		inf->penalty_time_tot +=
		   PERIOD_BEGIN(inf) + inf->cputime - inf->absblock;
	}
#endif
	/*sanity check: make sure each extra-aware domain IS on the util-q!*/
	/*if (inf->extra & EXTRA_AWARE) {
		if (!extraq_on(d, EXTRA_UTIL_Q))
			printf("sedf_wake: domain %i is extra-aware, "\
			       "but NOT on L1 extraq!\n",d->id);
	}*/
	
	/*check whether the awakened task needs to invoke the do_schedule
	  routine. Try to avoid unnecessary runs but:
	  Save approximation: Always switch to scheduler!*/
	if (should_switch(schedule_data[d->processor].curr, d, now)){
#ifdef ADV_SCHED_HISTO
		adv_sched_hist_start(d->processor);
#endif
		cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
	}
}

/*Print a lot of use-{full, less} information about a domains in the system*/
static void sedf_dump_domain(struct domain *d) {
	printk("%u has=%c ", d->id,
		test_bit(DF_RUNNING, &d->flags) ? 'T':'F');
	printk("p=%llu sl=%llu ddl=%llu w=%hu c=%llu sc=%i xtr(%s)=%llu",
	  DOM_INFO(d)->period, DOM_INFO(d)->slice, DOM_INFO(d)->absdead,
	  DOM_INFO(d)->weight, d->cpu_time, DOM_INFO(d)->score[EXTRA_UTIL_Q],
	 (DOM_INFO(d)->extra & EXTRA_AWARE) ? "yes" : "no",
	  DOM_INFO(d)->extra_time_tot);
	if (d->cpu_time !=0)
		printf(" (%lu%)", (DOM_INFO(d)->extra_time_tot * 100)
		                 / d->cpu_time);
#ifdef SEDF_STATS
	if (DOM_INFO(d)->block_time_tot!=0)
		printf(" pen=%lu%", (DOM_INFO(d)->penalty_time_tot * 100) /
		                     DOM_INFO(d)->block_time_tot);
	if (DOM_INFO(d)->block_tot!=0)
		printf("\n   blks=%lu sh=%lu (%lu%) (shc=%lu (%lu%) shex=%i "\
		       "shexsl=%i) l=%lu (%lu%) avg: b=%llu p=%llu",
		    DOM_INFO(d)->block_tot, DOM_INFO(d)->short_block_tot,
		   (DOM_INFO(d)->short_block_tot * 100) 
		  / DOM_INFO(d)->block_tot, DOM_INFO(d)->short_cont,
		   (DOM_INFO(d)->short_cont * 100) / DOM_INFO(d)->block_tot,
		    DOM_INFO(d)->pen_extra_blocks,
		    DOM_INFO(d)->pen_extra_slices,
		    DOM_INFO(d)->long_block_tot,
		   (DOM_INFO(d)->long_block_tot * 100) / DOM_INFO(d)->block_tot,
		   (DOM_INFO(d)->block_time_tot) / DOM_INFO(d)->block_tot,
		   (DOM_INFO(d)->penalty_time_tot) / DOM_INFO(d)->block_tot);
#endif
	printf("\n");
}

/*dumps all domains on hte specified cpu*/
static void sedf_dump_cpu_state(int i)
{
	struct list_head *list, *queue, *tmp;
	int loop = 0;
	struct sedf_dom_info *d_inf;
	struct domain* d;
	
	printk("now=%llu\n",NOW());
	queue = RUNQ(i);
	printk("RUNQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
		(unsigned long) queue->next, (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue ) {
		printk("%3d: ",loop++);
		d_inf = list_entry(list, struct sedf_dom_info, list);
		sedf_dump_domain(d_inf->owner);
	}
	
	queue = WAITQ(i); loop = 0;
	printk("\nWAITQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
		(unsigned long) queue->next, (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue ) {
		printk("%3d: ",loop++);
		d_inf = list_entry(list, struct sedf_dom_info, list);
		sedf_dump_domain(d_inf->owner);
	}
	
	queue = EXTRAQ(i,EXTRA_PEN_Q); loop = 0;
	printk("\nEXTRAQ (penalty) rq %lx   n: %lx, p: %lx\n",
	       (unsigned long)queue, (unsigned long) queue->next,
	       (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue ) {
		d_inf = list_entry(list, struct sedf_dom_info,
		                   extralist[EXTRA_PEN_Q]);
		printk("%3d: ",loop++);
		sedf_dump_domain(d_inf->owner);
	}
	
	queue = EXTRAQ(i,EXTRA_UTIL_Q); loop = 0;
	printk("\nEXTRAQ (utilization) rq %lx   n: %lx, p: %lx\n",
	       (unsigned long)queue, (unsigned long) queue->next,
	       (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue )	{
		d_inf = list_entry(list, struct sedf_dom_info,
		                   extralist[EXTRA_UTIL_Q]);
		printk("%3d: ",loop++);
		sedf_dump_domain(d_inf->owner);
	}
	
	loop = 0;
	printk("\nnot on Q\n");
	for_each_domain(d) {
		if (!__task_on_queue(d) && (d->processor == i)) {
			printk("%3d: ",loop++);
			sedf_dump_domain(d);
		}
	}
}
/*Adjusts periods and slices of the domains accordingly to their weights*/
static inline int sedf_adjust_weights(struct domain *p, 
struct sched_adjdom_cmd *cmd) {
	int sumw[NR_CPUS];
	s_time_t sumt[NR_CPUS];
	int cpu;
	
	for (cpu=0; cpu < NR_CPUS; cpu++) {
		sumw[cpu] = 0;
		sumt[cpu] = 0;
	}
	/*sum up all weights*/
	for_each_domain(p) {
		if (DOM_INFO(p)->weight)
			sumw[p->processor] += DOM_INFO(p)->weight;
		else {
			/*don't modify domains who don't have a weight, but sum
			  up the time they need, projected to a WEIGHT_PERIOD,
			  so that this time is not given to the weight-driven
			  domains*/
			/*check for overflows*/
			ASSERT((WEIGHT_PERIOD < ULONG_MAX) 
			    && (DOM_INFO(p)->slice_orig < ULONG_MAX));
			sumt[p->processor] += (WEIGHT_PERIOD *
			    DOM_INFO(p)->slice_orig) / DOM_INFO(p)->period_orig;
		}
	}
	/*adjust all slices (and periods) to the new weight*/
	for_each_domain(p) {
		if (DOM_INFO(p)->weight) {
			DOM_INFO(p)->period_orig = 
			     DOM_INFO(p)->period = WEIGHT_PERIOD;
			DOM_INFO(p)->slice_orig  =
			      DOM_INFO(p)->slice = (DOM_INFO(p)->weight *
			      (WEIGHT_PERIOD -WEIGHT_SAFETY -
			       sumt[p->processor])) / sumw[p->processor];
		}
	}
	return 0;
}

/* set or fetch domain scheduling parameters */
static int sedf_adjdom(struct domain *p, struct sched_adjdom_cmd *cmd) {
	PRINT(2,"sedf_adjdom was called, domain-id %i new period %llu "\
	        "new slice %llu\nlatency %llu extra:%s\n",
		p->id, cmd->u.sedf.period, cmd->u.sedf.slice,
		cmd->u.sedf.latency, (cmd->u.sedf.extratime)?"yes":"no");
	if ( cmd->direction == SCHED_INFO_PUT )
	{
		/*check for sane parameters*/
		if (!cmd->u.sedf.period && !cmd->u.sedf.weight)
			return -EINVAL;
		/*weight driven domains*/
		if (cmd->u.sedf.weight) {
			DOM_INFO(p)->weight = cmd->u.sedf.weight;
		}
		else {
			/*time driven domains*/
			DOM_INFO(p)->weight = 0;
			/* sanity checking! */
			if(cmd->u.sedf.slice > cmd->u.sedf.period )
				return -EINVAL;
			DOM_INFO(p)->period_orig = 
			   DOM_INFO(p)->period   = cmd->u.sedf.period;
			DOM_INFO(p)->slice_orig  = 
			   DOM_INFO(p)->slice    = cmd->u.sedf.slice;
		}
		if (sedf_adjust_weights(p,cmd))
			return -EINVAL;
		DOM_INFO(p)->extra       = (DOM_INFO(p)-> extra & ~EXTRA_AWARE)
		    | (cmd->u.sedf.extratime & EXTRA_AWARE);
		DOM_INFO(p)->latency     = cmd->u.sedf.latency;
		extraq_check(p);
	}
	else if ( cmd->direction == SCHED_INFO_GET )
	{
		cmd->u.sedf.period    = DOM_INFO(p)->period;
		cmd->u.sedf.slice     = DOM_INFO(p)->slice;
		cmd->u.sedf.extratime = DOM_INFO(p)->extra & EXTRA_AWARE;
		cmd->u.sedf.latency   = DOM_INFO(p)->latency;
		cmd->u.sedf.weight    = DOM_INFO(p)->weight;
	}
	PRINT(2,"sedf_adjdom_finished\n");
	return 0;
}

struct scheduler sched_sedf_def = {
    .name     = "Simple EDF Scheduler",
    .opt_name = "sedf",
    .sched_id = SCHED_SEDF,
    
    .init_idle_task = sedf_init_idle_task,
    .alloc_task     = sedf_alloc_task,
    .add_task       = sedf_add_task,
    .free_task      = sedf_free_task,
    .init_scheduler = sedf_init_scheduler,
    .do_schedule    = sedf_do_schedule,
    .dump_cpu_state = sedf_dump_cpu_state,
    .sleep          = sedf_sleep,
    .wake           = sedf_wake,
    .adjdom         = sedf_adjdom,
};
