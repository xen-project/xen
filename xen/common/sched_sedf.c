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

#define SEDFLEVEL 2
#define PRINT(_f, _a...)  \
if ((_f)<=SEDFLEVEL) printk(_a );

/*
	TODO:
	TESTING!
	implement stylish features!
	tracing instead of PRINTs
*/


#define TRC_SEDF 0xBEEF0000
#define EXTRA_NONE (0)
#define EXTRA_AWARE (1)
#define EXTRA_RUNNING (2)
#define EXTRA_QUANTUM (MICROSECS(1000)) 
#define WEIGHT_PERIOD (MILLISECS(100))
#define WEIGHT_SAFETY (MILLISECS(5))

struct sedf_dom_info
{
	struct domain		*owner;
	struct list_head	list;
	struct list_head	extralist;
	
	//Parameters for EDF
	s_time_t		period;		//=(relative deadline)
	s_time_t		slice;		//=worst case execution time
	
	//Advaced Parameters
	//Latency Scaling
	s_time_t		period_orig;	
	s_time_t		slice_orig;
	s_time_t		latency;
	//extra-time status of domain
	short			extra;
	//weights for "Scheduling for Beginners/ Lazy/ etc."
	short			weight;
	
	//Bookkeeping
	s_time_t		absdead;
	s_time_t		sched_start;
	s_time_t		cputime;
	s_time_t		absblock;
	
	//Statistics
	s_time_t		block_time_tot;
	s_time_t		penalty_time_tot;
	s_time_t		extra_time_tot;
	int			block_tot;
	int			short_block_tot;
	int			long_block_tot;
	int			short_cont;
};

struct sedf_cpu_info {
	struct list_head runnableq;
	struct list_head waitq;
	struct list_head extraq;
};

#define DOM_INFO(d)		((struct sedf_dom_info *)((d)->sched_priv))
#define CPU_INFO(cpu)		((struct sedf_cpu_info *)schedule_data[cpu].sched_priv)
#define LIST(d)			(&DOM_INFO(d)->list)
#define EXTRALIST(d)		(&DOM_INFO(d)->extralist)
#define RUNQ(cpu)   		(&CPU_INFO(cpu)->runnableq)
#define WAITQ(cpu)   		(&CPU_INFO(cpu)->waitq)
#define EXTRAQ(cpu)   		(&CPU_INFO(cpu)->extraq)
#define IDLETASK(cpu)		((struct domain *)schedule_data[cpu].idle)

#define PERIOD_BEGIN(inf)	((inf)->absdead - (inf)->period)

static xmem_cache_t *dom_info_cache;

static inline void extraq_add_head(struct domain *d)
{
    list_add(EXTRALIST(d), EXTRAQ(d->processor));
}

static inline void extraq_add_tail(struct domain *d)
{
    list_add_tail(EXTRALIST(d), EXTRAQ(d->processor));
}

static inline void extraq_del(struct domain *d)
{
    struct list_head *list = EXTRALIST(d);
    list_del(list);
    list->next = NULL;
}

static inline int extraq_on(struct domain *d) {
	return (((EXTRALIST(d))->next != NULL) && (EXTRALIST(d)->next != EXTRALIST(d)));
}

static inline void extraq_check(struct domain *d) {
	if (extraq_on(d)) {
		PRINT(2,"Dom %i is on extraQ\n",d->id);
		if (DOM_INFO(d)->extra == EXTRA_NONE) {
			extraq_del(d);
			PRINT(2,"Removed dom %i from extraQ\n",d->id);
		}
	} else {
		PRINT(2,"Dom %i is NOT on extraQ\n",d->id);
		if (DOM_INFO(d)->extra != EXTRA_NONE) {
			PRINT(2,"Added dom %i to extraQ\n",d->id);
			extraq_add_tail(d);
		}
	}
}

static inline void __del_from_queue(struct domain *d)
{
    struct list_head *list = LIST(d);
    list_del(list);
    list->next = NULL;
}

/* adds a domain to the queue of processes which wait for the beginning of the next period
 * this list is therefore sortet by this time, which is simply absol. deadline - period
 */ 
static inline void __add_to_waitqueue_sort(struct domain *d) {
	struct list_head     *cur;
	struct sedf_dom_info *curinf;
	
	PRINT(3,"Adding domain %i (bop= %llu) to waitq\n",d->id,PERIOD_BEGIN(DOM_INFO(d)));	
	//iterate through all elements to find our "hole"
	list_for_each(cur,WAITQ(d->processor)){
		curinf = list_entry(cur,struct sedf_dom_info,list);
		if (PERIOD_BEGIN(DOM_INFO(d)) < PERIOD_BEGIN(curinf))
	 		break;
		else
			PRINT(4,"\tbehind domain %i (bop= %llu)\n",curinf->owner->id,PERIOD_BEGIN(curinf));
	}
	//cur now contains the element, before which we'll enqueue
	PRINT(3,"\tlist_add to %x\n",cur->prev);
	list_add(LIST(d),cur->prev);

}

/* adds a domain to the queue of processes which have started their current period and are
 * runnable (i.e. not blocked, dieing,...). The first element on this list is running on the processor,
 * if the list is empty the idle task will run. As we are implementing EDF, this list is sorted by 
 * deadlines.
 */ 
static inline void __add_to_runqueue_sort(struct domain *d) {
	struct list_head     *cur;
	struct sedf_dom_info *curinf;

	PRINT(3,"Adding domain %i (deadl= %llu) to runq\n",d->id,DOM_INFO(d)->absdead);	
	//iterate through all elements to find our "hole"
	list_for_each(cur,RUNQ(d->processor)){
		curinf = list_entry(cur,struct sedf_dom_info,list);
		if (DOM_INFO(d)->absdead < curinf->absdead)
	 		break;
		else
			PRINT(4,"\tbehind domain %i (deadl= %llu)\n",curinf->owner->id,curinf->absdead);
	}
	//cur now contains the element, before which we'll enqueue
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
		schedule_data[i].sched_priv = xmalloc(sizeof(struct sedf_cpu_info));
		if ( schedule_data[i].sched_priv == NULL )
			return -1;
		INIT_LIST_HEAD(WAITQ(i));//used for Latency Scaling
		INIT_LIST_HEAD(RUNQ(i));
		INIT_LIST_HEAD(EXTRAQ(i));
	}
				//we could not find any suitable domain => look for domains that are aware of extratime
	dom_info_cache = xmem_cache_create(
		"SEDF dom info", sizeof(struct sedf_dom_info), 0, 0, 0, NULL);
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
	//s_time_t now=NOW();
	struct sedf_dom_info *inf=DOM_INFO(d);
	inf->owner = d;
	
	PRINT(2,"sedf_add_task was called, domain-id %i\n",d->id);
	if (d->id==0) {
		//set dom0 to something useful to boot the machine
		inf->period    = MILLISECS(20);
		inf->slice     = MILLISECS(15);
		inf->latency   = 0;
		inf->absdead   = 0;
		inf->extra     = EXTRA_NONE;//EXTRA_AWARE; 
	}
	else {
		//other domains don't get any execution time at all in the beginning!
		inf->period    = MILLISECS(20);
		inf->slice     = 0;
		inf->absdead   = 0;
		inf->latency   = 0;
		inf->extra     = EXTRA_NONE;//EXTRA_AWARE
	}
	inf->period_orig = inf->period; inf->slice_orig = inf->slice;
	INIT_LIST_HEAD(&(inf->list));
	INIT_LIST_HEAD(&(inf->extralist));
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
	DOM_INFO(d)->absdead=0;
	set_bit(DF_RUNNING, &d->flags);
	//the idle task doesn't have to turn up on any list...
	return 0;
}

#define MIN(x,y) (((x)<(y))?(x):(y))
/* Main scheduling function
 * Reasons for calling this function are:
 * -timeslice for the current period used up
 * -domain on waitqueue has started it's period
 * -and various others ;) in general: determin which domain to run next*/
static task_slice_t sedf_do_schedule(s_time_t now)
{
	struct sedf_dom_info *inf   = DOM_INFO(current);
	int                   cpu   = current->processor;
	struct list_head     *runq  = RUNQ(cpu);
	struct list_head     *waitq = WAITQ(cpu);
	struct list_head     *extraq = EXTRAQ(cpu);
	struct list_head     *cur,*tmp;
	struct sedf_dom_info *curinf;
	task_slice_t          ret;

	
	//idle tasks don't need any of the following stuf
	if (is_idle_task(inf->owner))
		goto check_waitq;				//idle task doesn't get scheduled on the runq
	
	if (unlikely(inf->extra == EXTRA_RUNNING)) {
		//special treatment of domains running in extra time
		inf->extra = EXTRA_AWARE;
		inf->cputime=0;
		inf->extra_time_tot += now - inf->sched_start;
		
		extraq_del(current);				//remove extradomain from head of the queue
		if (domain_runnable(inf->owner))
			extraq_add_tail(current);		//and add to the tail if it is runnable => round-robin
		else
			__del_from_queue(inf->owner);		//if domain blocked in extratime remove it from waitq(/runq) as well
	}
	else {
		//current domain is running in real time mode
		//update the domains cputime
		inf->cputime += now - inf->sched_start;
		//scheduling decisions, which don't move the running domain to any queues
		if ((inf->cputime < inf->slice) && domain_runnable(inf->owner))
			goto check_waitq;			//there is nothing to do with the running task
		
		//remove tasks that can't run
		__del_from_queue(inf->owner);
		
		//manage bookkeeping (i.e. calculate next deadline, memorize overun time of slice) of finished domains
		if (inf->cputime >= inf->slice) {
			inf->cputime -= inf->slice;
			
			if (inf->period < inf->period_orig) {
				//this domain runs in latency scaling mode
				inf->period *= 2;
				inf->slice *= 2;
				if ((inf->period > inf->period_orig) || (inf->slice > inf->slice_orig)) {
					//now switch back to standard timing
					inf->period = inf->period_orig;
					inf->slice = inf->slice_orig;
				}
			}
			inf->absdead += inf->period;		//set next deadline
		}
		//if (inf->absdead<now);
			//printk("Domain %i exceeded it't deadline!!!! (now: %llu ddl: %llu)\n",current->id,now,inf->absdead);
		//add a runnable domain to the waitqueue		
		if (domain_runnable(inf->owner))
			__add_to_waitqueue_sort(inf->owner);
		else {
			//we have a blocked realtime task
			inf->absblock=now;
			if (inf->extra == EXTRA_AWARE)
				extraq_del(inf->owner);		//remove a blocked domain from the extraq aswell
		}
	}
check_waitq:
	//check for the first elements of the waitqueue, whether their next period has already started
	list_for_each_safe(cur,tmp,waitq) {
		curinf = list_entry(cur,struct sedf_dom_info,list);
		if (PERIOD_BEGIN(curinf) <= now) {
			__del_from_queue(curinf->owner);
			__add_to_runqueue_sort(curinf->owner);
		}
		else
			break;
	}
	
	//process the runq
	list_for_each_safe(cur,tmp,runq) {
		curinf = list_entry(cur,struct sedf_dom_info,list);
		if (unlikely(curinf->slice == 0)) {
			//special treatment of elements with empty slice
			__del_from_queue(curinf->owner);
			curinf->absdead += curinf->period;
			__add_to_waitqueue_sort(curinf->owner);
		}
		else {
			if (unlikely((curinf->absdead < now) || (curinf->cputime > curinf->slice))) {
				//we missed the deadline or the slice was already finished... might hapen because of dom_adj.
				//printk("Ouch! Domain %i missed deadline %llu\n",curinf->owner->id,curinf->absdead);
				__del_from_queue(curinf->owner);
				curinf->absdead += ((now - curinf->absdead + (curinf->period-1)) / curinf->period) * curinf->period;		
					//force start of period to be in future and aligned to period borders!
				curinf->cputime = 0;
				__add_to_runqueue_sort(curinf->owner);
			}
			else
				break;
		}
	}
	
	//now simply pick the first domain from the runqueue
	struct sedf_dom_info *runinf, *waitinf;
	
	if (!list_empty(runq)) {
		runinf   = list_entry(runq->next,struct sedf_dom_info,list);
		ret.task = runinf->owner;
		if (!list_empty(waitq)) {
			//rerun scheduler, when scheduled domain reaches it's end of slice or the first domain from the waitqueue gets ready
			waitinf  = list_entry(waitq->next,struct sedf_dom_info,list);
			ret.time = MIN(now + runinf->slice - runinf->cputime,PERIOD_BEGIN(waitinf)) - now;
		}
		else {
			ret.time = runinf->slice - runinf->cputime;
		}
	}
	else {
		if (!list_empty(waitq)) {
			waitinf  = list_entry(waitq->next,struct sedf_dom_info,list);
			//we could not find any suitable domain => look for domains that are aware of extratime
			if (!list_empty(extraq) && (PERIOD_BEGIN(waitinf) - now >= EXTRA_QUANTUM)) {
				runinf   = list_entry(extraq->next,struct sedf_dom_info,extralist);
				runinf->extra = EXTRA_RUNNING;
				ret.task = runinf->owner;
				ret.time = EXTRA_QUANTUM;
			}
			else {
				//we have an empty run- and extraqueue or too less time => idle task!
				ret.task = IDLETASK(cpu);
				ret.time = PERIOD_BEGIN(waitinf) - now;
			}
		}
		else {
			//this could probably never happen, but one never knows...
			//it can... imagine a second CPU, which is pure scifi ATM, but one never knows ;)
			ret.task = IDLETASK(cpu);
			ret.time = SECONDS(1);
		}
	}
	if (ret.time<0)
		printk("Ouch! We are seriously BEHIND schedule! %lli\n",ret.time);
	DOM_INFO(ret.task)->sched_start=now;
	return ret;
}

static void sedf_sleep(struct domain *d) {
	PRINT(2,"sedf_sleep was called, domain-id %i\n",d->id);
	if ( test_bit(DF_RUNNING, &d->flags) )
		cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
	else  {
		if ( __task_on_queue(d) )
			__del_from_queue(d);
		if (extraq_on(d))
			extraq_del(d);
	}
}

/* This function wakes ifup a domain, i.e. moves them into the waitqueue
 * things to mention are: admission control is taking place nowhere at
 * the moment, so we can't be sure, whether it is safe to wake the domain
 * up at all. Anyway, even if it is safe (total cpu usage <=100%) there are
 * some considerations on when to allow the domain to wake up and have it's
 * first deadline...
 * I detected 3 cases, which could describe the possible behaviour of the scheduler,
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
 *     -when a domain unblocks in the same period as it was blocked it unblocks and
 *      may consume the rest of it's original time-slice minus the time it was blocked
 *      (assume period=9, slice=5)
 *
 *      DRB_UR___DRRRRR___D...
 *
 *     -this also doesn't disturb scheduling, but might lead to the fact, that the domain
 *      can't finish it's workload in the period
 *     -in addition to that the domain can be treated prioritised when extratime is available
 *
 *    Part2: Long Unblocking
 *    Part 2a
 *     -it is obvious that such behaviour, applied when then unblocking is happening in
 *      later periods, works fine aswell
 *     -the domain is treated as if it would have been running since the start of its new period
 *
 *      DRB______D___UR___D... 
 *
 *    Part 2b
 *     -if one needs the full slice in the next period, it is necessary to treat the unblocking
 *      time as the start of the new period, i.e. move the deadline further back (later)
 *     -this doesn't disturb scheduling as well, because for EDF periods can be treated as minimal
 *      inter-release times and scheduling stays correct, when deadlines are kept relative to the time
 *      the process unblocks
 *
 *      DRB______D___URRRR___D...
 *                       (D) 
 *     -problem: deadlines don't occur isochronous anymore
 *    Part 2c (Improved Atropos design)
 *     -when a domain unblocks it is given a very short period (=latency hint) and slice length scaled
 *      accordingly
 *     -both rise again to the original value (e.g. get doubled every period)
 *
 * 3. Unconservative (i.e. incorrect)
 *     -to boost the performance of I/O dependent domains it would be possible to put the domain into
 *      the runnable queue immediately, and let it run for the remainder of the slice of the current period
 *      (or even worse: allocate a new full slice for the domain) 
 *     -either behaviour can lead to missed deadlines in other domains as opposed to approaches 1,2a,2b
 */
static inline void unblock_short_vcons(struct sedf_dom_info* inf, s_time_t now) { inf->absdead += inf->period;}
static inline void unblock_long_vcons(struct sedf_dom_info* inf, s_time_t now) {
	inf->absdead += ((now - inf->absdead) / inf->period + 1) * inf->period;		//very conservative
	inf->cputime = 0;
}

static inline void unblock_short_cons(struct sedf_dom_info* inf, s_time_t now) {
	inf->cputime += now - inf->absblock;						//treat blocked time as consumed by the domain
	if (inf->cputime + EXTRA_QUANTUM > inf->slice) {
		//we don't have a reasonable amount of time in our slice left :(
		inf->cputime=0;
		inf->absdead += inf->period;						//start in next period!
	}
	else
		inf->short_cont++;
}
static inline void unblock_long_cons_a(struct sedf_dom_info* inf, s_time_t now) {
	inf->cputime = (now - inf->absdead) % inf->period;				//treat the time the domain was blocked in the CURRENT
											//period as consumed by the domain
	if (inf->cputime + EXTRA_QUANTUM > inf->slice) {
		//we don't have a reasonable amount of time in our slice left :(
		inf->cputime=0;
		inf->absdead += inf->period;						//start in next period!
	}
}
static inline void unblock_long_cons_b(struct sedf_dom_info* inf,s_time_t now) {
	inf->absdead = now + inf->period;						//Conservative 2b
	inf->cputime = 0;
}
static inline void unblock_long_cons_c(struct sedf_dom_info* inf,s_time_t now) {
	if (likely(inf->latency)) {
		//sclae the slice and period accordingly to the latency hint
		inf->period = inf->latency;						//reduce period temporarily to the latency hint
		ASSERT((inf->latency < ULONG_MAX) && (inf->slice_orig < ULONG_MAX));	//this results in max. 4s slice/period length
		inf->slice = (inf->latency * inf->slice_orig) / inf->period_orig;	//scale slice accordingly, so that utilisation stays the same
	}	
	else {
		//we don't have a latency hint.. use some other technique
		inf->absdead = now + inf->period;					//Conservative 2b...
		inf->cputime = 0;
	}
}

/*static inline void unblock_short_vcons
static inline void unblock_short_vcons*/
void sedf_wake(struct domain *d) {
	//for the first try just implement the "very conservative" way of waking domains up
	s_time_t              now = NOW();
	struct sedf_dom_info* inf = DOM_INFO(d);
	
	PRINT(3,"sedf_wake was called, domain-id %i\n",d->id);
	
	if (unlikely(is_idle_task(d)))
		return;
	
	if ( unlikely(__task_on_queue(d)) ) {
		PRINT(3,"\tdomain %i is already in some queue\n",d->id);
		return;
	}
	if ( unlikely(extraq_on(d)) ) {
		PRINT(3,"\tdomain %i is already in the extraQ\n",d->id);
	}
	if (unlikely(inf->absdead == 0))
		inf->absdead = now + inf->slice;			//initial setup of the deadline
		
	//very conservative way of unblocking
	//make sure that the start of the period for this
	//domain is happening in the future
	PRINT(3,"waking up domain %i (deadl= %llu period= %llu now= %llu)\n",d->id,inf->absdead,inf->period,now);
	
	inf->block_tot++;
	if (unlikely(now< PERIOD_BEGIN(inf))) {
		//this might happen, imagine unblocking in extra-time!
		if (likely(inf->extra == EXTRA_AWARE)) 
			extraq_add_tail(d);				//SD: Could extraq_add_head be better?
		//else
		//This is very very unlikely, ie. might even be an error?!
	}		
	else {		
		if (now < inf->absdead) {
			//short blocking
			inf->short_block_tot++;
			//unblock_short_vcons(inf, now);
			unblock_short_cons(inf, now);
			if (inf->extra == EXTRA_AWARE) 
				extraq_add_head(d);
		}
		else {
			//long blocking
			inf->long_block_tot++;
			//PRINT(3,"old=%llu ",inf->absdead);
			//unblock_long_vcons(inf, now);
			unblock_long_cons_c(inf,now);
			if (inf->extra == EXTRA_AWARE) 
				extraq_add_tail(d);
		}
	}
	PRINT(3,"waking up domain %i (deadl= %llu period= %llu now= %llu)\n",d->id,inf->absdead,inf->period,now);
	__add_to_waitqueue_sort(d);
	PRINT(3,"added to waitq\n");	
	
	//do some statistics here...
	if (inf->absblock!=0) {
		inf->block_time_tot += now - inf->absblock;
		inf->penalty_time_tot += PERIOD_BEGIN(inf) + inf->cputime - inf->absblock;
		/*if (DOM_INFO(d)->block_time_tot)
			PRINT(3,"penalty: %lu\n",(DOM_INFO(d)->penalty_time_tot*100)/DOM_INFO(d)->block_time_tot);*/
	}
	/*if ( is_idle_task(schedule_data[d->processor].curr)) {
		cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
		return;
	}*/
	
	//check whether the awakened task needs to get scheduled before the next sched. decision
	//and check, whether we are idling and this domain is extratime aware
	if ((PERIOD_BEGIN(inf) < schedule_data[d->processor].s_timer.expires) ||
	    (is_idle_task(schedule_data[d->processor].curr) && (now + EXTRA_QUANTUM < schedule_data[d->processor].s_timer.expires) &&
	     (inf->extra == EXTRA_AWARE)))
		cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
}


/* This could probably be a bit more specific!*/
static void sedf_dump_domain(struct domain *d) {
	printk("%u has=%c ", d->id,
		test_bit(DF_RUNNING, &d->flags) ? 'T':'F');
	printk("p=%llu sl=%llu ddl=%llu w=%u c=%llu xtr(%s)=%llu",
	 	DOM_INFO(d)->period, DOM_INFO(d)->slice, DOM_INFO(d)->absdead, DOM_INFO(d)->weight, d->cpu_time,
		DOM_INFO(d)->extra ? "yes" : "no", DOM_INFO(d)->extra_time_tot);
	if (d->cpu_time !=0)
		printf(" (%lu%)", (DOM_INFO(d)->extra_time_tot * 100) / d->cpu_time);
	if (DOM_INFO(d)->block_time_tot!=0)
		printf(" pen=%lu%", (DOM_INFO(d)->penalty_time_tot * 100) / DOM_INFO(d)->block_time_tot);
	if (DOM_INFO(d)->block_tot!=0)
		printf("\n   blks=%lu sh=%lu (%lu%) (shc=%lu (%lu%)) l=%lu (%lu%) avg: b=%llu p=%llu", DOM_INFO(d)->block_tot,
		       DOM_INFO(d)->short_block_tot, (DOM_INFO(d)->short_block_tot * 100) / DOM_INFO(d)->block_tot,
		       DOM_INFO(d)->short_cont, (DOM_INFO(d)->short_cont * 100) / DOM_INFO(d)->block_tot,
		       DOM_INFO(d)->long_block_tot, (DOM_INFO(d)->long_block_tot * 100) / DOM_INFO(d)->block_tot,
		       (DOM_INFO(d)->block_time_tot) / DOM_INFO(d)->block_tot,
		       (DOM_INFO(d)->penalty_time_tot) / DOM_INFO(d)->block_tot);
	printf("\n");
}

static void sedf_dump_cpu_state(int i)
{
	struct list_head *list, *queue, *tmp;
	int loop = 0;
/*	int found = 0;
	int id1st = 0;*/
	struct sedf_dom_info *d_inf;
	struct domain* d;
	
	printk("now=%llu\n",NOW());
	queue = RUNQ(i);
	printk("RUNQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
		(unsigned long) queue->next, (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue )
	{
		printk("%3d: ",loop++);
		d_inf = list_entry(list, struct sedf_dom_info, list);
		sedf_dump_domain(d_inf->owner);
	}
	
	queue = WAITQ(i); loop = 0;
	printk("\nWAITQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
		(unsigned long) queue->next, (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue )
	{
		printk("%3d: ",loop++);
		d_inf = list_entry(list, struct sedf_dom_info, list);
		sedf_dump_domain(d_inf->owner);
	}
	
	queue = EXTRAQ(i); loop = 0;
	printk("\nEXTRAQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
		(unsigned long) queue->next, (unsigned long) queue->prev);
	list_for_each_safe ( list, tmp, queue )
	{
		d_inf = list_entry(list, struct sedf_dom_info, extralist);
		
/*		if (found) {
			if (id1st == d_inf->owner->id)
				break; 
		} 
		else { id1st=d_inf->owner->id; found=1;}*/
		printk("%3d: ",loop++);
		sedf_dump_domain(d_inf->owner);
	}
	
	loop = 0;
	printk("\nnot on Q\n");
	for_each_domain(d) {
		if (!extraq_on(d) && !__task_on_queue(d)) {
			printk("%3d: ",loop++);
			sedf_dump_domain(d);
		}
	}
}
//Adjusts periods and slices of the domains accordingly to their weights
static inline int sedf_adjust_weights(struct domain *p, struct sched_adjdom_cmd *cmd) {
	int sumw      = 0;
	s_time_t sumt = 0;
	
	//sum up all weights
	for_each_domain(p) {
		if (DOM_INFO(p)->weight)
			sumw += DOM_INFO(p)->weight;
		else {
			//don't modify domains who don't have a weight, but sum up
			//the time they need, projected to a WEIGHT_PERIOD, so that
			//this time is not given to the weight-driven domains
			ASSERT((WEIGHT_PERIOD < ULONG_MAX) && (DOM_INFO(p)->slice_orig < ULONG_MAX));	//this results in max. 4s slice/period length
			sumt += (WEIGHT_PERIOD * DOM_INFO(p)->slice_orig) / DOM_INFO(p)->period_orig;
		}
	}
	//adjust all slices (and periods) to the new weight
	for_each_domain(p) {
		if (DOM_INFO(p)->weight) {
			DOM_INFO(p)->period_orig = 
			     DOM_INFO(p)->period = WEIGHT_PERIOD;
			DOM_INFO(p)->slice_orig  =
			      DOM_INFO(p)->slice = (DOM_INFO(p)->weight * (WEIGHT_PERIOD - WEIGHT_SAFETY - sumt)) / sumw;
		}
	}
	return 0;
}

/* set or fetch domain scheduling parameters */
static int sedf_adjdom(struct domain *p, struct sched_adjdom_cmd *cmd) {
	PRINT(2,"sedf_adjdom was called, domain-id %i new period %llu new slice %llu\n"
	        "latency %llu extra: %s\n",p->id,cmd->u.sedf.period,cmd->u.sedf.slice,cmd->u.sedf.latency,(cmd->u.sedf.extratime)?"yes":"no");
	if ( cmd->direction == SCHED_INFO_PUT )
	{
		if (!cmd->u.sedf.period && !cmd->u.sedf.weight)			//check for sane parameters
			return -EINVAL;
		if (cmd->u.sedf.weight) {
			DOM_INFO(p)->weight = cmd->u.sedf.weight;		//weight driven domains
		}
		else {
			//time driven domains
			DOM_INFO(p)->weight = 0;
			if(cmd->u.sedf.slice > cmd->u.sedf.period )		/* sanity checking! */
				return -EINVAL;
			DOM_INFO(p)->period_orig = 
			   DOM_INFO(p)->period   = cmd->u.sedf.period;
			DOM_INFO(p)->slice_orig  = 
			   DOM_INFO(p)->slice    = cmd->u.sedf.slice;
		}
		if (sedf_adjust_weights(p,cmd))
			return -EINVAL;
		DOM_INFO(p)->extra       = cmd->u.sedf.extratime;
		DOM_INFO(p)->latency     = cmd->u.sedf.latency;
		extraq_check(p);
	}
	else if ( cmd->direction == SCHED_INFO_GET )
	{
		cmd->u.sedf.period    = DOM_INFO(p)->period;
		cmd->u.sedf.slice     = DOM_INFO(p)->slice;
		cmd->u.sedf.extratime = DOM_INFO(p)->extra;
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
