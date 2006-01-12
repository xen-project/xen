/******************************************************************************
 * Simple EDF scheduler for xen
 *
 * by Stephan Diestelhorst (C)  2004 Cambridge University
 * based on code by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <public/sched_ctl.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>

/*verbosity settings*/
#define SEDFLEVEL 0
#define PRINT(_f, _a...)  \
    if ((_f)<=SEDFLEVEL) printk(_a );

#ifndef NDEBUG
#define SEDF_STATS
#define CHECK(_p) if ( !(_p) ) \
 { printk("Check '%s' failed, line %d, file %s\n", #_p , __LINE__,\
 __FILE__);}
#else
#define CHECK(_p) ((void)0)
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
#define SEDF_ASLEEP (16)

#define EXTRA_QUANTUM (MICROSECS(500)) 
#define WEIGHT_PERIOD (MILLISECS(100))
#define WEIGHT_SAFETY (MILLISECS(5))

#define IMPLY(a, b) (!(a) || (b))
#define EQ(a, b) ((!!(a)) == (!!(b)))


struct sedf_dom_info {
    struct domain  *domain;
};
struct sedf_vcpu_info
{
    struct vcpu *vcpu;
    struct list_head list;
    struct list_head extralist[2];
 
    /*Parameters for EDF*/
    s_time_t  period;  /*=(relative deadline)*/
    s_time_t  slice;  /*=worst case execution time*/
 
    /*Advaced Parameters*/
    /*Latency Scaling*/
    s_time_t  period_orig; 
    s_time_t  slice_orig;
    s_time_t  latency;
 
    /*status of domain*/
    int   status;
    /*weights for "Scheduling for beginners/ lazy/ etc." ;)*/
    short   weight;
    short                   extraweight;
    /*Bookkeeping*/
    s_time_t  deadl_abs;
    s_time_t  sched_start_abs;
    s_time_t  cputime;
    /* times the domain un-/blocked */
    s_time_t  block_abs;
    s_time_t  unblock_abs;
 
    /*scores for {util, block penalty}-weighted extratime distribution*/
    int   score[2]; 
    s_time_t  short_block_lost_tot;
 
    /*Statistics*/
    s_time_t  extra_time_tot;

#ifdef SEDF_STATS
    s_time_t  block_time_tot;
    s_time_t  penalty_time_tot;
    int   block_tot;
    int   short_block_tot;
    int   long_block_tot;
    int   short_cont;
    int   pen_extra_blocks;
    int   pen_extra_slices;
#endif
};

struct sedf_cpu_info {
    struct list_head runnableq;
    struct list_head waitq;
    struct list_head extraq[2];
    s_time_t         current_slice_expires;
};

#define EDOM_INFO(d)  ((struct sedf_vcpu_info *)((d)->sched_priv))
#define CPU_INFO(cpu) ((struct sedf_cpu_info *)schedule_data[cpu].sched_priv)
#define LIST(d)   (&EDOM_INFO(d)->list)
#define EXTRALIST(d,i)  (&(EDOM_INFO(d)->extralist[i]))
#define RUNQ(cpu)     (&CPU_INFO(cpu)->runnableq)
#define WAITQ(cpu)     (&CPU_INFO(cpu)->waitq)
#define EXTRAQ(cpu,i)    (&(CPU_INFO(cpu)->extraq[i]))
#define IDLETASK(cpu)  ((struct vcpu *)schedule_data[cpu].idle)

#define PERIOD_BEGIN(inf) ((inf)->deadl_abs - (inf)->period)

#define MIN(x,y) (((x)<(y))?(x):(y))
#define DIV_UP(x,y) (((x) + (y) - 1) / y)

#define extra_runs(inf) ((inf->status) & 6)
#define extra_get_cur_q(inf) (((inf->status & 6) >> 1)-1)
#define sedf_runnable(edom) (!(EDOM_INFO(edom)->status & SEDF_ASLEEP))


static void sedf_dump_cpu_state(int i);

static inline int extraq_on(struct vcpu *d, int i) {
    return ((EXTRALIST(d,i)->next != NULL) &&
            (EXTRALIST(d,i)->next != EXTRALIST(d,i)));
}

static inline void extraq_add_head(struct vcpu *d, int i)
{
    list_add(EXTRALIST(d,i), EXTRAQ(d->processor,i));
    ASSERT(extraq_on(d, i));
}

static inline void extraq_add_tail(struct vcpu *d, int i)
{
    list_add_tail(EXTRALIST(d,i), EXTRAQ(d->processor,i));
    ASSERT(extraq_on(d, i));
}

static inline void extraq_del(struct vcpu *d, int i)
{
    struct list_head *list = EXTRALIST(d,i);
    ASSERT(extraq_on(d,i));
    PRINT(3, "Removing domain %i.%i from L%i extraq\n", d->domain->domain_id,
          d->vcpu_id, i); 
    list_del(list);
    list->next = NULL;
    ASSERT(!extraq_on(d, i));
}

/* adds a domain to the queue of processes which are aware of extra time. List
   is sorted by score, where a lower score means higher priority for an extra
   slice. It also updates the score, by simply subtracting a fixed value from
   each entry, in order to avoid overflow. The algorithm works by simply
   charging each domain that recieved extratime with an inverse of its weight.
 */ 
static inline void extraq_add_sort_update(struct vcpu *d, int i, int sub) {
    struct list_head      *cur;
    struct sedf_vcpu_info *curinf;
 
    ASSERT(!extraq_on(d,i));
    PRINT(3, "Adding domain %i.%i (score= %i, short_pen= %"PRIi64")"
          " to L%i extraq\n",
          d->domain->domain_id, d->vcpu_id, EDOM_INFO(d)->score[i],
          EDOM_INFO(d)->short_block_lost_tot, i); 
    /*iterate through all elements to find our "hole" and on our way
      update all the other scores*/
    list_for_each(cur,EXTRAQ(d->processor,i)){
        curinf = list_entry(cur,struct sedf_vcpu_info,extralist[i]);
        curinf->score[i] -= sub;
        if (EDOM_INFO(d)->score[i] < curinf->score[i])
            break;
        else
            PRINT(4,"\tbehind domain %i.%i (score= %i)\n",
                  curinf->vcpu->domain->domain_id,
                  curinf->vcpu->vcpu_id, curinf->score[i]);
    }
    /*cur now contains the element, before which we'll enqueue*/
    PRINT(3, "\tlist_add to %p\n", cur->prev);
    list_add(EXTRALIST(d,i),cur->prev);
 
    /*continue updating the extraq*/
    if ((cur != EXTRAQ(d->processor,i)) && sub)
        for (cur = cur->next; cur != EXTRAQ(d->processor,i);
             cur = cur-> next) {
            curinf = list_entry(cur,struct sedf_vcpu_info,
                                extralist[i]);
            curinf->score[i] -= sub;
            PRINT(4, "\tupdating domain %i.%i (score= %u)\n",
                  curinf->vcpu->domain->domain_id, 
                  curinf->vcpu->vcpu_id, curinf->score[i]);
        }
    ASSERT(extraq_on(d,i));
}
static inline void extraq_check(struct vcpu *d) {
    if (extraq_on(d, EXTRA_UTIL_Q)) {
        PRINT(2,"Dom %i.%i is on L1 extraQ\n",d->domain->domain_id, d->vcpu_id);
        if (!(EDOM_INFO(d)->status & EXTRA_AWARE) &&
            !extra_runs(EDOM_INFO(d))) {
            extraq_del(d, EXTRA_UTIL_Q);
            PRINT(2,"Removed dom %i.%i from L1 extraQ\n",
                  d->domain->domain_id, d->vcpu_id);
        }
    } else {
        PRINT(2,"Dom %i.%i is NOT on L1 extraQ\n",d->domain->domain_id,
              d->vcpu_id);
        if ((EDOM_INFO(d)->status & EXTRA_AWARE) && sedf_runnable(d))
        {
#if (EXTRA == EXTRA_ROUNDR)
            extraq_add_tail(d, EXTRA_UTIL_Q);
#elif (EXTRA == EXTRA_SLICE_WEIGHT || \
          EXTRA == EXTRA_BLOCK_WEIGHT)
            extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
#elif
            ;
#endif
            PRINT(2,"Added dom %i.%i to L1 extraQ\n",d->domain->domain_id,
                  d->vcpu_id);
        }
    }
}

static inline void extraq_check_add_unblocked(struct vcpu *d, 
                                              int priority) {
    struct sedf_vcpu_info *inf = EDOM_INFO(d);
    if (inf->status & EXTRA_AWARE) 
#if (EXTRA == EXTRA_ROUNDR)
        if (priority)
            extraq_add_head(d,EXTRA_UTIL_Q);
        else
            extraq_add_tail(d,EXTRA_UTIL_Q);
#elif (EXTRA == EXTRA_SLICE_WEIGHT \
     || EXTRA == EXTRA_BLOCK_WEIGHT)
    /*put in on the weighted extraq, 
    without updating any scores*/
    extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
#else
    ;
#endif
}

static inline int __task_on_queue(struct vcpu *d) {
    return (((LIST(d))->next != NULL) && (LIST(d)->next != LIST(d)));
}
static inline void __del_from_queue(struct vcpu *d)
{
    struct list_head *list = LIST(d);
    ASSERT(__task_on_queue(d));
    PRINT(3,"Removing domain %i.%i (bop= %"PRIu64") from runq/waitq\n",
          d->domain->domain_id, d->vcpu_id, PERIOD_BEGIN(EDOM_INFO(d)));
    list_del(list);
    list->next = NULL;
    ASSERT(!__task_on_queue(d));
}

typedef int(*list_comparer)(struct list_head* el1, struct list_head* el2);

static inline void list_insert_sort(struct list_head *list,
                                    struct list_head *element, list_comparer comp) {
    struct list_head     *cur;
    /*iterate through all elements to find our "hole"*/
    list_for_each(cur,list){
        if (comp(element, cur) < 0)
            break;
    }
    /*cur now contains the element, before which we'll enqueue*/
    PRINT(3,"\tlist_add to %p\n",cur->prev);
    list_add(element, cur->prev);
}  
#define DOMAIN_COMPARER(name, field, comp1, comp2)          \
int name##_comp(struct list_head* el1, struct list_head* el2) \
{                                                           \
 struct sedf_vcpu_info *d1, *d2;                     \
 d1 = list_entry(el1,struct sedf_vcpu_info, field);  \
 d2 = list_entry(el2,struct sedf_vcpu_info, field);  \
 if ((comp1) == (comp2))                             \
  return 0;                                   \
 if ((comp1) < (comp2))                              \
  return -1;                                  \
 else                                                \
  return 1;                                   \
}
/* adds a domain to the queue of processes which wait for the beginning of the
   next period; this list is therefore sortet by this time, which is simply
   absol. deadline - period
 */ 
DOMAIN_COMPARER(waitq, list, PERIOD_BEGIN(d1), PERIOD_BEGIN(d2))
    static inline void __add_to_waitqueue_sort(struct vcpu *d) {
    ASSERT(!__task_on_queue(d));
    PRINT(3,"Adding domain %i.%i (bop= %"PRIu64") to waitq\n",
          d->domain->domain_id, d->vcpu_id, PERIOD_BEGIN(EDOM_INFO(d)));
    list_insert_sort(WAITQ(d->processor), LIST(d), waitq_comp);
    ASSERT(__task_on_queue(d));
}

/* adds a domain to the queue of processes which have started their current
   period and are runnable (i.e. not blocked, dieing,...). The first element
   on this list is running on the processor, if the list is empty the idle
   task will run. As we are implementing EDF, this list is sorted by deadlines.
 */ 
DOMAIN_COMPARER(runq, list, d1->deadl_abs, d2->deadl_abs)
    static inline void __add_to_runqueue_sort(struct vcpu *d) {
    PRINT(3,"Adding domain %i.%i (deadl= %"PRIu64") to runq\n",
          d->domain->domain_id, d->vcpu_id, EDOM_INFO(d)->deadl_abs);
    list_insert_sort(RUNQ(d->processor), LIST(d), runq_comp);
}


/* Allocates memory for per domain private scheduling data*/
static int sedf_alloc_task(struct vcpu *d)
{
    PRINT(2, "sedf_alloc_task was called, domain-id %i.%i\n",
          d->domain->domain_id, d->vcpu_id);

    if ( d->domain->sched_priv == NULL )
    {
        d->domain->sched_priv = xmalloc(struct sedf_dom_info);
        if ( d->domain->sched_priv == NULL )
            return -1;
        memset(d->domain->sched_priv, 0, sizeof(struct sedf_dom_info));
    }

    if ( (d->sched_priv = xmalloc(struct sedf_vcpu_info)) == NULL )
        return -1;

    memset(d->sched_priv, 0, sizeof(struct sedf_vcpu_info));

    return 0;
}


/* Setup the sedf_dom_info */
static void sedf_add_task(struct vcpu *d)
{
    struct sedf_vcpu_info *inf = EDOM_INFO(d);
    inf->vcpu = d;
 
    PRINT(2,"sedf_add_task was called, domain-id %i.%i\n",d->domain->domain_id,
          d->vcpu_id);

    /* Allocate per-CPU context if this is the first domain to be added. */
    if ( unlikely(schedule_data[d->processor].sched_priv == NULL) )
    {
        schedule_data[d->processor].sched_priv = 
            xmalloc(struct sedf_cpu_info);
        BUG_ON(schedule_data[d->processor].sched_priv == NULL);
        memset(CPU_INFO(d->processor), 0, sizeof(*CPU_INFO(d->processor)));
        INIT_LIST_HEAD(WAITQ(d->processor));
        INIT_LIST_HEAD(RUNQ(d->processor));
        INIT_LIST_HEAD(EXTRAQ(d->processor,EXTRA_PEN_Q));
        INIT_LIST_HEAD(EXTRAQ(d->processor,EXTRA_UTIL_Q));
    }
       
    if ( d->domain->domain_id == 0 )
    {
        /*set dom0 to something useful to boot the machine*/
        inf->period    = MILLISECS(20);
        inf->slice     = MILLISECS(15);
        inf->latency   = 0;
        inf->deadl_abs = 0;
        inf->status     = EXTRA_AWARE | SEDF_ASLEEP;
    }
    else
    {
        /*other domains run in best effort mode*/
        inf->period    = WEIGHT_PERIOD;
        inf->slice     = 0;
        inf->deadl_abs = 0;
        inf->latency   = 0;
        inf->status     = EXTRA_AWARE | SEDF_ASLEEP;
        inf->extraweight = 1;
    }

    inf->period_orig = inf->period; inf->slice_orig = inf->slice;
    INIT_LIST_HEAD(&(inf->list));
    INIT_LIST_HEAD(&(inf->extralist[EXTRA_PEN_Q]));
    INIT_LIST_HEAD(&(inf->extralist[EXTRA_UTIL_Q]));
 
    if ( !is_idle_vcpu(d) )
    {
        extraq_check(d);
    }
    else
    {
        EDOM_INFO(d)->deadl_abs = 0;
        EDOM_INFO(d)->status &= ~SEDF_ASLEEP;
    }
}

/* Frees memory used by domain info */
static void sedf_free_task(struct domain *d)
{
    int i;

    PRINT(2,"sedf_free_task was called, domain-id %i\n",d->domain_id);

    ASSERT(d->sched_priv != NULL);
    xfree(d->sched_priv);
 
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
    {
        if ( d->vcpu[i] )
        {
            ASSERT(d->vcpu[i]->sched_priv != NULL);
            xfree(d->vcpu[i]->sched_priv);
        }
    }
}

/*
 * Handles the rescheduling & bookkeeping of domains running in their
 * guaranteed timeslice.
 */
static void desched_edf_dom(s_time_t now, struct vcpu* d)
{
    struct sedf_vcpu_info* inf = EDOM_INFO(d);
    /*current domain is running in real time mode*/
 
    ASSERT(__task_on_queue(d));
    /*update the domains cputime*/
    inf->cputime += now - inf->sched_start_abs;

    /*scheduling decisions, which don't remove the running domain
      from the runq*/
    if ( (inf->cputime < inf->slice) && sedf_runnable(d) )
        return;
  
    __del_from_queue(d);
  
    /*manage bookkeeping (i.e. calculate next deadline,
      memorize overun-time of slice) of finished domains*/
    if ( inf->cputime >= inf->slice )
    {
        inf->cputime -= inf->slice;
  
        if ( inf->period < inf->period_orig )
        {
            /*this domain runs in latency scaling or burst mode*/
#if (UNBLOCK == UNBLOCK_BURST)
            /*if we are runnig in burst scaling wait for two periods
              before scaling periods up again*/ 
            if ( (now - inf->unblock_abs) >= (2 * inf->period) )
#endif
            {
                inf->period *= 2; inf->slice *= 2;
                if ( (inf->period > inf->period_orig) ||
                     (inf->slice > inf->slice_orig) )
                {
                    /*reset slice & period*/
                    inf->period = inf->period_orig;
                    inf->slice = inf->slice_orig;
                }
            }
        }
        /*set next deadline*/
        inf->deadl_abs += inf->period;
    }
 
    /*add a runnable domain to the waitqueue*/
    if ( sedf_runnable(d) )
    {
        __add_to_waitqueue_sort(d);
    }
    else
    {
        /*we have a blocked realtime task -> remove it from exqs too*/
#if (EXTRA > EXTRA_OFF)
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
        if ( extraq_on(d, EXTRA_PEN_Q) )
            extraq_del(d, EXTRA_PEN_Q);
#endif
        if ( extraq_on(d, EXTRA_UTIL_Q) )
            extraq_del(d, EXTRA_UTIL_Q);
#endif
    }

    ASSERT(EQ(sedf_runnable(d), __task_on_queue(d)));
    ASSERT(IMPLY(extraq_on(d, EXTRA_UTIL_Q) || extraq_on(d, EXTRA_PEN_Q), 
                 sedf_runnable(d)));
}


/* Update all elements on the queues */
static void update_queues(
    s_time_t now, struct list_head *runq, struct list_head *waitq)
{
    struct list_head     *cur, *tmp;
    struct sedf_vcpu_info *curinf;
 
    PRINT(3,"Updating waitq..\n");

    /*check for the first elements of the waitqueue, whether their
      next period has already started*/
    list_for_each_safe(cur, tmp, waitq) {
        curinf = list_entry(cur, struct sedf_vcpu_info, list);
        PRINT(4,"\tLooking @ dom %i.%i\n",
              curinf->vcpu->domain->domain_id, curinf->vcpu->vcpu_id);
        if ( PERIOD_BEGIN(curinf) <= now )
        {
            __del_from_queue(curinf->vcpu);
            __add_to_runqueue_sort(curinf->vcpu);
        }
        else
            break;
    }
 
    PRINT(3,"Updating runq..\n");

    /*process the runq, find domains that are on
      the runqueue which shouldn't be there*/
    list_for_each_safe(cur, tmp, runq) {
        curinf = list_entry(cur,struct sedf_vcpu_info,list);
        PRINT(4,"\tLooking @ dom %i.%i\n",
              curinf->vcpu->domain->domain_id, curinf->vcpu->vcpu_id);

        if ( unlikely(curinf->slice == 0) )
        {
            /*ignore domains with empty slice*/
            PRINT(4,"\tUpdating zero-slice domain %i.%i\n",
                  curinf->vcpu->domain->domain_id,
                  curinf->vcpu->vcpu_id);
            __del_from_queue(curinf->vcpu);

            /*move them to their next period*/
            curinf->deadl_abs += curinf->period;
            /*ensure that the start of the next period is in the future*/
            if ( unlikely(PERIOD_BEGIN(curinf) < now) )
            {
                curinf->deadl_abs += 
                    (DIV_UP(now - PERIOD_BEGIN(curinf),
                           curinf->period)) * curinf->period;
            }
            /*and put them back into the queue*/
            __add_to_waitqueue_sort(curinf->vcpu);
            continue;
        }

        if ( unlikely((curinf->deadl_abs < now) ||
                      (curinf->cputime > curinf->slice)) )
        {
            /*we missed the deadline or the slice was
              already finished... might hapen because
              of dom_adj.*/
            PRINT(4,"\tDomain %i.%i exceeded it's deadline/"
                  "slice (%"PRIu64" / %"PRIu64") now: %"PRIu64
                  " cputime: %"PRIu64"\n",
                  curinf->vcpu->domain->domain_id,
                  curinf->vcpu->vcpu_id,
                  curinf->deadl_abs, curinf->slice, now,
                  curinf->cputime);
            __del_from_queue(curinf->vcpu);
            /*common case: we miss one period!*/
            curinf->deadl_abs += curinf->period;
   
            /*if we are still behind: modulo arithmetic,
              force deadline to be in future and
              aligned to period borders!*/
            if (unlikely(curinf->deadl_abs < now))
                curinf->deadl_abs += 
                    DIV_UP(now - curinf->deadl_abs,
                           curinf->period) * curinf->period;
            ASSERT(curinf->deadl_abs > now);
            /*give a fresh slice*/
            curinf->cputime = 0;
            if (PERIOD_BEGIN(curinf) > now)
                __add_to_waitqueue_sort(curinf->vcpu);
            else
                __add_to_runqueue_sort(curinf->vcpu);
        }
        else
            break;
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
static void desched_extra_dom(s_time_t now, struct vcpu* d)
{
    struct sedf_vcpu_info *inf = EDOM_INFO(d);
    int i = extra_get_cur_q(inf);
 
#if (EXTRA == EXTRA_SLICE_WEIGHT || EXTRA == EXTRA_BLOCK_WEIGHT)
    unsigned long         oldscore;
#endif
    ASSERT(extraq_on(d, i));
    /*unset all running flags*/
    inf->status  &= ~(EXTRA_RUN_PEN | EXTRA_RUN_UTIL);
    /*fresh slice for the next run*/
    inf->cputime = 0;
    /*accumulate total extratime*/
    inf->extra_time_tot += now - inf->sched_start_abs;
    /*remove extradomain from head of the queue*/
    extraq_del(d, i);

#if (EXTRA == EXTRA_ROUNDR)
    if ( sedf_runnable(d) && (inf->status & EXTRA_AWARE) )
        /*add to the tail if it is runnable => round-robin*/
        extraq_add_tail(d, EXTRA_UTIL_Q);
#elif (EXTRA == EXTRA_SLICE_WEIGHT || EXTRA == EXTRA_BLOCK_WEIGHT)
    /*update the score*/
    oldscore = inf->score[i];
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
    if ( i == EXTRA_PEN_Q )
    {
        /*domain was running in L0 extraq*/
        /*reduce block lost, probably more sophistication here!*/
        /*inf->short_block_lost_tot -= EXTRA_QUANTUM;*/
        inf->short_block_lost_tot -= now - inf->sched_start_abs;
        PRINT(3,"Domain %i.%i: Short_block_loss: %"PRIi64"\n", 
              inf->vcpu->domain->domain_id, inf->vcpu->vcpu_id,
              inf->short_block_lost_tot);
        if (inf->short_block_lost_tot <= 0) {
            PRINT(4,"Domain %i.%i compensated short block loss!\n",
                  inf->vcpu->domain->domain_id, inf->vcpu->vcpu_id);
            /*we have (over-)compensated our block penalty*/
            inf->short_block_lost_tot = 0;
            /*we don't want a place on the penalty queue anymore!*/
            inf->status &= ~EXTRA_WANT_PEN_Q;
            goto check_extra_queues;
        }
        /*we have to go again for another try in the block-extraq,
          the score is not used incremantally here, as this is
          already done by recalculating the block_lost*/
        inf->score[EXTRA_PEN_Q] = (inf->period << 10) /
            inf->short_block_lost_tot;
        oldscore = 0;
    }
    else
#endif
    {
        /*domain was running in L1 extraq => score is inverse of
          utilization and is used somewhat incremental!*/
        if ( !inf->extraweight )
            /*NB: use fixed point arithmetic with 10 bits*/
            inf->score[EXTRA_UTIL_Q] = (inf->period << 10) /
                inf->slice;
        else
            /*conversion between realtime utilisation and extrawieght:
              full (ie 100%) utilization is equivalent to 128 extraweight*/
            inf->score[EXTRA_UTIL_Q] = (1<<17) / inf->extraweight;
    }

 check_extra_queues:
    /* Adding a runnable domain to the right queue and removing blocked ones*/
    if ( sedf_runnable(d) )
    {
        /*add according to score: weighted round robin*/
        if (((inf->status & EXTRA_AWARE) && (i == EXTRA_UTIL_Q)) ||
            ((inf->status & EXTRA_WANT_PEN_Q) && (i == EXTRA_PEN_Q)))
            extraq_add_sort_update(d, i, oldscore);
    }
    else
    {
        /*remove this blocked domain from the waitq!*/
        __del_from_queue(d);
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
        /*make sure that we remove a blocked domain from the other
          extraq too*/
        if ( i == EXTRA_PEN_Q )
        {
            if ( extraq_on(d, EXTRA_UTIL_Q) )
                extraq_del(d, EXTRA_UTIL_Q);
        }
        else
        {
            if ( extraq_on(d, EXTRA_PEN_Q) )
                extraq_del(d, EXTRA_PEN_Q);
        }
#endif
    }
#endif
    ASSERT(EQ(sedf_runnable(d), __task_on_queue(d)));
    ASSERT(IMPLY(extraq_on(d, EXTRA_UTIL_Q) || extraq_on(d, EXTRA_PEN_Q), 
                 sedf_runnable(d)));
}
#endif


static struct task_slice sedf_do_extra_schedule(
    s_time_t now, s_time_t end_xt, struct list_head *extraq[], int cpu)
{
    struct task_slice   ret;
    struct sedf_vcpu_info *runinf;
    ASSERT(end_xt > now);

    /* Enough time left to use for extratime? */
    if ( end_xt - now < EXTRA_QUANTUM )
        goto return_idle;

#if (EXTRA == EXTRA_BLOCK_WEIGHT)
    if ( !list_empty(extraq[EXTRA_PEN_Q]) )
    {
        /*we still have elements on the level 0 extraq 
          => let those run first!*/
        runinf   = list_entry(extraq[EXTRA_PEN_Q]->next, 
                              struct sedf_vcpu_info, extralist[EXTRA_PEN_Q]);
        runinf->status |= EXTRA_RUN_PEN;
        ret.task = runinf->vcpu;
        ret.time = EXTRA_QUANTUM;
#ifdef SEDF_STATS
        runinf->pen_extra_slices++;
#endif
    }
    else
#endif
    {
        if ( !list_empty(extraq[EXTRA_UTIL_Q]) )
        {
            /*use elements from the normal extraqueue*/
            runinf   = list_entry(extraq[EXTRA_UTIL_Q]->next,
                                  struct sedf_vcpu_info,
                                  extralist[EXTRA_UTIL_Q]);
            runinf->status |= EXTRA_RUN_UTIL;
            ret.task = runinf->vcpu;
            ret.time = EXTRA_QUANTUM;
        }
        else
            goto return_idle;
    }

    ASSERT(ret.time > 0);
    ASSERT(sedf_runnable(ret.task));
    return ret;
 
 return_idle:
    ret.task = IDLETASK(cpu);
    ret.time = end_xt - now;
    ASSERT(ret.time > 0);
    ASSERT(sedf_runnable(ret.task));
    return ret;
}


/* Main scheduling function
   Reasons for calling this function are:
   -timeslice for the current period used up
   -domain on waitqueue has started it's period
   -and various others ;) in general: determine which domain to run next*/
static struct task_slice sedf_do_schedule(s_time_t now)
{
    int                   cpu      = smp_processor_id();
    struct list_head     *runq     = RUNQ(cpu);
    struct list_head     *waitq    = WAITQ(cpu);
#if (EXTRA > EXTRA_OFF)
    struct sedf_vcpu_info *inf     = EDOM_INFO(current);
    struct list_head      *extraq[] = {
        EXTRAQ(cpu, EXTRA_PEN_Q), EXTRAQ(cpu, EXTRA_UTIL_Q)};
#endif
    struct sedf_vcpu_info *runinf, *waitinf;
    struct task_slice      ret;

    /*idle tasks don't need any of the following stuf*/
    if ( is_idle_vcpu(current) )
        goto check_waitq;
 
    /* create local state of the status of the domain, in order to avoid
       inconsistent state during scheduling decisions, because data for
       vcpu_runnable is not protected by the scheduling lock!*/
    if ( !vcpu_runnable(current) )
        inf->status |= SEDF_ASLEEP;
 
    if ( inf->status & SEDF_ASLEEP )
        inf->block_abs = now;

#if (EXTRA > EXTRA_OFF)
    if ( unlikely(extra_runs(inf)) )
    {
        /*special treatment of domains running in extra time*/
        desched_extra_dom(now, current);
    }
    else 
#endif
    {
        desched_edf_dom(now, current);
    }
 check_waitq:
    update_queues(now, runq, waitq);
 
    /*now simply pick the first domain from the runqueue, which has the
      earliest deadline, because the list is sorted*/
 
    if ( !list_empty(runq) )
    {
        runinf   = list_entry(runq->next,struct sedf_vcpu_info,list);
        ret.task = runinf->vcpu;
        if ( !list_empty(waitq) )
        {
            waitinf  = list_entry(waitq->next,
                                  struct sedf_vcpu_info,list);
            /*rerun scheduler, when scheduled domain reaches it's
              end of slice or the first domain from the waitqueue
              gets ready*/
            ret.time = MIN(now + runinf->slice - runinf->cputime,
                           PERIOD_BEGIN(waitinf)) - now;
        }
        else
        {
            ret.time = runinf->slice - runinf->cputime;
        }
        CHECK(ret.time > 0);
        goto sched_done;
    }
 
    if ( !list_empty(waitq) )
    {
        waitinf  = list_entry(waitq->next,struct sedf_vcpu_info, list);
        /*we could not find any suitable domain 
          => look for domains that are aware of extratime*/
#if (EXTRA > EXTRA_OFF)
        ret = sedf_do_extra_schedule(now, PERIOD_BEGIN(waitinf),
                                     extraq, cpu);
#else
        ret.task = IDLETASK(cpu);
        ret.time = PERIOD_BEGIN(waitinf) - now;
#endif
        CHECK(ret.time > 0);
    }
    else
    {
        /*this could probably never happen, but one never knows...*/
        /*it can... imagine a second CPU, which is pure scifi ATM,
          but one never knows ;)*/
        ret.task = IDLETASK(cpu);
        ret.time = SECONDS(1);
    }

 sched_done: 
    /*TODO: Do something USEFUL when this happens and find out, why it
      still can happen!!!*/
    if ( ret.time < 0)
    {
        printk("Ouch! We are seriously BEHIND schedule! %"PRIi64"\n",
               ret.time);
        ret.time = EXTRA_QUANTUM;
    }

    EDOM_INFO(ret.task)->sched_start_abs = now;
    CHECK(ret.time > 0);
    ASSERT(sedf_runnable(ret.task));
    CPU_INFO(cpu)->current_slice_expires = now + ret.time;
    return ret;
}


static void sedf_sleep(struct vcpu *d)
{
    PRINT(2,"sedf_sleep was called, domain-id %i.%i\n",
          d->domain->domain_id, d->vcpu_id);
 
    if ( is_idle_vcpu(d) )
        return;

    EDOM_INFO(d)->status |= SEDF_ASLEEP;
 
    if ( schedule_data[d->processor].curr == d )
    {
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    }
    else
    {
        if ( __task_on_queue(d) )
            __del_from_queue(d);
#if (EXTRA > EXTRA_OFF)
        if ( extraq_on(d, EXTRA_UTIL_Q) ) 
            extraq_del(d, EXTRA_UTIL_Q);
#endif
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
        if ( extraq_on(d, EXTRA_PEN_Q) )
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
 *     -addition: experiments have shown that this may have a HUGE impact on
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
#if (UNBLOCK <= UNBLOCK_SHORT_RESUME)
static void unblock_short_vcons(struct sedf_vcpu_info* inf, s_time_t now)
{
    inf->deadl_abs += inf->period;
    inf->cputime = 0;
}
#endif

#if (UNBLOCK == UNBLOCK_SHORT_RESUME)
static void unblock_short_cons(struct sedf_vcpu_info* inf, s_time_t now)
{
    /*treat blocked time as consumed by the domain*/
    inf->cputime += now - inf->block_abs; 
    if ( (inf->cputime + EXTRA_QUANTUM) > inf->slice )
    {
        /*we don't have a reasonable amount of time in 
          our slice left :( => start in next period!*/
        unblock_short_vcons(inf, now);
    }
#ifdef SEDF_STATS
    else
        inf->short_cont++;
#endif
}
#endif

static void unblock_short_extra_support(
    struct sedf_vcpu_info* inf, s_time_t now)
{
    /*this unblocking scheme tries to support the domain, by assigning it
    a priority in extratime distribution according to the loss of time
    in this slice due to blocking*/
    s_time_t pen;
 
    /*no more realtime execution in this period!*/
    inf->deadl_abs += inf->period;
    if ( likely(inf->block_abs) )
    {
        //treat blocked time as consumed by the domain*/
        /*inf->cputime += now - inf->block_abs;*/
        /*penalty is time the domain would have
          had if it continued to run */
        pen = (inf->slice - inf->cputime);
        if ( pen < 0 )
            pen = 0;
        /*accumulate all penalties over the periods*/
        /*inf->short_block_lost_tot += pen;*/
        /*set penalty to the current value*/
        inf->short_block_lost_tot = pen;
        /*not sure which one is better.. but seems to work well...*/
  
        if ( inf->short_block_lost_tot )
        {
            inf->score[0] = (inf->period << 10) /
                inf->short_block_lost_tot;
#ifdef SEDF_STATS
            inf->pen_extra_blocks++;
#endif
            if ( extraq_on(inf->vcpu, EXTRA_PEN_Q) )
                /*remove domain for possible resorting!*/
                extraq_del(inf->vcpu, EXTRA_PEN_Q);
            else
                /*remember that we want to be on the penalty q
                  so that we can continue when we (un-)block
                  in penalty-extratime*/
                inf->status |= EXTRA_WANT_PEN_Q;
   
            /*(re-)add domain to the penalty extraq*/
            extraq_add_sort_update(inf->vcpu, EXTRA_PEN_Q, 0);
        }
    }

    /*give it a fresh slice in the next period!*/
    inf->cputime = 0;
}


#if (UNBLOCK == UNBLOCK_ISOCHRONOUS_EDF)
static void unblock_long_vcons(struct sedf_vcpu_info* inf, s_time_t now)
{
    /* align to next future period */
    inf->deadl_abs += (DIV_UP(now - inf->deadl_abs, inf->period) +1)
        * inf->period;
    inf->cputime = 0;
}
#endif


#if 0
static void unblock_long_cons_a (struct sedf_vcpu_info* inf, s_time_t now)
{
    /*treat the time the domain was blocked in the
     CURRENT period as consumed by the domain*/
    inf->cputime = (now - inf->deadl_abs) % inf->period; 
    if ( (inf->cputime + EXTRA_QUANTUM) > inf->slice )
    {
        /*we don't have a reasonable amount of time in our slice
          left :( => start in next period!*/
        unblock_long_vcons(inf, now);
    }
}
#endif


static void unblock_long_cons_b(struct sedf_vcpu_info* inf,s_time_t now)
{
    /*Conservative 2b*/
    /*Treat the unblocking time as a start of a new period */
    inf->deadl_abs = now + inf->period;
    inf->cputime = 0;
}


#if (UNBLOCK == UNBLOCK_ATROPOS)
static void unblock_long_cons_c(struct sedf_vcpu_info* inf,s_time_t now)
{
    if ( likely(inf->latency) )
    {
        /*scale the slice and period accordingly to the latency hint*/
        /*reduce period temporarily to the latency hint*/
        inf->period = inf->latency;
        /*this results in max. 4s slice/period length*/
        ASSERT((inf->period < ULONG_MAX)
               && (inf->slice_orig < ULONG_MAX));
        /*scale slice accordingly, so that utilisation stays the same*/
        inf->slice = (inf->period * inf->slice_orig)
            / inf->period_orig;
        inf->deadl_abs = now + inf->period;
        inf->cputime = 0;
    } 
    else
    {
        /*we don't have a latency hint.. use some other technique*/
        unblock_long_cons_b(inf, now);
    }
}
#endif


#if (UNBLOCK == UNBLOCK_BURST)
/*a new idea of dealing with short blocks: burst period scaling*/
static void unblock_short_burst(struct sedf_vcpu_info* inf, s_time_t now)
{
    /*treat blocked time as consumed by the domain*/
    inf->cputime += now - inf->block_abs;
 
    if ( (inf->cputime + EXTRA_QUANTUM) <= inf->slice )
    {
        /*if we can still use some time in the current slice
          then use it!*/
#ifdef SEDF_STATS
        /*we let the domain run in the current period*/
        inf->short_cont++;
#endif
    }
    else
    {
        /*we don't have a reasonable amount of time in
          our slice left => switch to burst mode*/
        if ( likely(inf->unblock_abs) )
        {
            /*set the period-length to the current blocking
              interval, possible enhancements: average over last
              blocking intervals, user-specified minimum,...*/
            inf->period = now - inf->unblock_abs;
            /*check for overflow on multiplication*/
            ASSERT((inf->period < ULONG_MAX) 
                   && (inf->slice_orig < ULONG_MAX));
            /*scale slice accordingly, so that utilisation
              stays the same*/
            inf->slice = (inf->period * inf->slice_orig)
                / inf->period_orig;
            /*set new (shorter) deadline*/
            inf->deadl_abs += inf->period;
        }
        else
        {
            /*in case we haven't unblocked before
              start in next period!*/
            inf->cputime=0;
            inf->deadl_abs += inf->period;
        }
    }

    inf->unblock_abs = now;
}


static void unblock_long_burst(struct sedf_vcpu_info* inf, s_time_t now)
{
    if ( unlikely(inf->latency && (inf->period > inf->latency)) )
    {
        /*scale the slice and period accordingly to the latency hint*/
        inf->period = inf->latency;
        /*check for overflows on multiplication*/
        ASSERT((inf->period < ULONG_MAX)
               && (inf->slice_orig < ULONG_MAX));
        /*scale slice accordingly, so that utilisation stays the same*/
        inf->slice = (inf->period * inf->slice_orig)
            / inf->period_orig;
        inf->deadl_abs = now + inf->period;
        inf->cputime = 0;
    }
    else
    {
        /*we don't have a latency hint.. or we are currently in 
          "burst mode": use some other technique
          NB: this should be in fact the normal way of operation,
          when we are in sync with the device!*/
        unblock_long_cons_b(inf, now);
    }

    inf->unblock_abs = now;
}
#endif /* UNBLOCK == UNBLOCK_BURST */


#define DOMAIN_EDF   1
#define DOMAIN_EXTRA_PEN  2
#define DOMAIN_EXTRA_UTIL  3
#define DOMAIN_IDLE   4
static inline int get_run_type(struct vcpu* d)
{
    struct sedf_vcpu_info* inf = EDOM_INFO(d);
    if (is_idle_vcpu(d))
        return DOMAIN_IDLE;
    if (inf->status & EXTRA_RUN_PEN)
        return DOMAIN_EXTRA_PEN;
    if (inf->status & EXTRA_RUN_UTIL)
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
static inline int should_switch(struct vcpu *cur,
                                struct vcpu *other,
                                s_time_t now)
{
    struct sedf_vcpu_info *cur_inf, *other_inf;
    cur_inf   = EDOM_INFO(cur);
    other_inf = EDOM_INFO(other);
 
 /*check whether we need to make an earlier sched-decision*/
    if (PERIOD_BEGIN(other_inf) < 
        CPU_INFO(other->processor)->current_slice_expires)
        return 1;
    /*no timing-based switches need to be taken into account here*/
    switch (get_run_type(cur)) {
    case DOMAIN_EDF:
        /* do not interrupt a running EDF domain */ 
        return 0;
    case DOMAIN_EXTRA_PEN:
        /*check whether we also want 
          the L0 ex-q with lower score*/
        if ((other_inf->status & EXTRA_WANT_PEN_Q)
            &&  (other_inf->score[EXTRA_PEN_Q] < 
                 cur_inf->score[EXTRA_PEN_Q]))
            return 1;
        else return 0;
    case DOMAIN_EXTRA_UTIL:
        /*check whether we want the L0 extraq, don't
          switch if both domains want L1 extraq */
        if (other_inf->status & EXTRA_WANT_PEN_Q)
            return 1;
        else return 0;
    case DOMAIN_IDLE:
        return 1;
    }
    return 1;
}

void sedf_wake(struct vcpu *d)
{
    s_time_t              now = NOW();
    struct sedf_vcpu_info* inf = EDOM_INFO(d);

    PRINT(3, "sedf_wake was called, domain-id %i.%i\n",d->domain->domain_id,
          d->vcpu_id);

    if ( unlikely(is_idle_vcpu(d)) )
        return;
   
    if ( unlikely(__task_on_queue(d)) )
    {
        PRINT(3,"\tdomain %i.%i is already in some queue\n",
              d->domain->domain_id, d->vcpu_id);
        return;
    }

    ASSERT(!sedf_runnable(d));
    inf->status &= ~SEDF_ASLEEP;
    ASSERT(!extraq_on(d, EXTRA_UTIL_Q));
    ASSERT(!extraq_on(d, EXTRA_PEN_Q));
 
    if ( unlikely(inf->deadl_abs == 0) )
    {
        /*initial setup of the deadline*/
        inf->deadl_abs = now + inf->slice;
    }
  
    PRINT(3, "waking up domain %i.%i (deadl= %"PRIu64" period= %"PRIu64
          "now= %"PRIu64")\n",
          d->domain->domain_id, d->vcpu_id, inf->deadl_abs, inf->period, now);

#ifdef SEDF_STATS 
    inf->block_tot++;
#endif

    if ( unlikely(now < PERIOD_BEGIN(inf)) )
    {
        PRINT(4,"extratime unblock\n");
        /* unblocking in extra-time! */
#if (EXTRA == EXTRA_BLOCK_WEIGHT)
        if ( inf->status & EXTRA_WANT_PEN_Q )
        {
            /*we have a domain that wants compensation
              for block penalty and did just block in
              its compensation time. Give it another
              chance!*/
            extraq_add_sort_update(d, EXTRA_PEN_Q, 0);
        }
#endif
        extraq_check_add_unblocked(d, 0);
    }  
    else
    {  
        if ( now < inf->deadl_abs )
        {
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

            extraq_check_add_unblocked(d, 1);
        }
        else
        {
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
#elif (UNBLOCK == UNBLOCK_BURST)
            unblock_long_burst(inf, now);
#endif

            extraq_check_add_unblocked(d, 1);
        }
    }

    PRINT(3, "woke up domain %i.%i (deadl= %"PRIu64" period= %"PRIu64
          "now= %"PRIu64")\n",
          d->domain->domain_id, d->vcpu_id, inf->deadl_abs,
          inf->period, now);

    if ( PERIOD_BEGIN(inf) > now )
    {
        __add_to_waitqueue_sort(d);
        PRINT(3,"added to waitq\n");
    }
    else
    {
        __add_to_runqueue_sort(d);
        PRINT(3,"added to runq\n");
    }
 
#ifdef SEDF_STATS
    /*do some statistics here...*/
    if ( inf->block_abs != 0 )
    {
        inf->block_time_tot += now - inf->block_abs;
        inf->penalty_time_tot +=
            PERIOD_BEGIN(inf) + inf->cputime - inf->block_abs;
    }
#endif

    /*sanity check: make sure each extra-aware domain IS on the util-q!*/
    ASSERT(IMPLY(inf->status & EXTRA_AWARE, extraq_on(d, EXTRA_UTIL_Q)));
    ASSERT(__task_on_queue(d));
    /*check whether the awakened task needs to invoke the do_schedule
      routine. Try to avoid unnecessary runs but:
      Save approximation: Always switch to scheduler!*/
    ASSERT(d->processor >= 0);
    ASSERT(d->processor < NR_CPUS);
    ASSERT(schedule_data[d->processor].curr);

    if ( should_switch(schedule_data[d->processor].curr, d, now) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
}


static int sedf_set_affinity(struct vcpu *v, cpumask_t *affinity)
{
    if ( v == current )
        return cpu_isset(v->processor, *affinity) ? 0 : -EBUSY;

    vcpu_pause(v);
    v->cpu_affinity = *affinity;
    v->processor = first_cpu(v->cpu_affinity);
    vcpu_unpause(v);

    return 0;
}


/* Print a lot of useful information about a domains in the system */
static void sedf_dump_domain(struct vcpu *d)
{
    printk("%i.%i has=%c ", d->domain->domain_id, d->vcpu_id,
           test_bit(_VCPUF_running, &d->vcpu_flags) ? 'T':'F');
    printk("p=%"PRIu64" sl=%"PRIu64" ddl=%"PRIu64" w=%hu c=%"PRIu64
           " sc=%i xtr(%s)=%"PRIu64" ew=%hu",
           EDOM_INFO(d)->period, EDOM_INFO(d)->slice, EDOM_INFO(d)->deadl_abs,
           EDOM_INFO(d)->weight, d->cpu_time,
           EDOM_INFO(d)->score[EXTRA_UTIL_Q],
           (EDOM_INFO(d)->status & EXTRA_AWARE) ? "yes" : "no",
           EDOM_INFO(d)->extra_time_tot, EDOM_INFO(d)->extraweight);
    
    if ( d->cpu_time != 0 )
        printf(" (%"PRIu64"%%)", (EDOM_INFO(d)->extra_time_tot * 100)
               / d->cpu_time);

#ifdef SEDF_STATS
    if ( EDOM_INFO(d)->block_time_tot != 0 )
        printf(" pen=%"PRIu64"%%", (EDOM_INFO(d)->penalty_time_tot * 100) /
               EDOM_INFO(d)->block_time_tot);
    if ( EDOM_INFO(d)->block_tot != 0 )
        printf("\n   blks=%u sh=%u (%u%%) (shc=%u (%u%%) shex=%i "\
               "shexsl=%i) l=%u (%u%%) avg: b=%"PRIu64" p=%"PRIu64"",
               EDOM_INFO(d)->block_tot, EDOM_INFO(d)->short_block_tot,
               (EDOM_INFO(d)->short_block_tot * 100) 
               / EDOM_INFO(d)->block_tot, EDOM_INFO(d)->short_cont,
               (EDOM_INFO(d)->short_cont * 100) / EDOM_INFO(d)->block_tot,
               EDOM_INFO(d)->pen_extra_blocks,
               EDOM_INFO(d)->pen_extra_slices,
               EDOM_INFO(d)->long_block_tot,
               (EDOM_INFO(d)->long_block_tot * 100) / EDOM_INFO(d)->block_tot,
               (EDOM_INFO(d)->block_time_tot) / EDOM_INFO(d)->block_tot,
               (EDOM_INFO(d)->penalty_time_tot) / EDOM_INFO(d)->block_tot);
#endif
    printf("\n");
}


/* dumps all domains on hte specified cpu */
static void sedf_dump_cpu_state(int i)
{
    struct list_head      *list, *queue, *tmp;
    struct sedf_vcpu_info *d_inf;
    struct domain         *d;
    struct vcpu    *ed;
    int loop = 0;
 
    printk("now=%"PRIu64"\n",NOW());
    queue = RUNQ(i);
    printk("RUNQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
           (unsigned long) queue->next, (unsigned long) queue->prev);
    list_for_each_safe ( list, tmp, queue )
    {
        printk("%3d: ",loop++);
        d_inf = list_entry(list, struct sedf_vcpu_info, list);
        sedf_dump_domain(d_inf->vcpu);
    }
 
    queue = WAITQ(i); loop = 0;
    printk("\nWAITQ rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
           (unsigned long) queue->next, (unsigned long) queue->prev);
    list_for_each_safe ( list, tmp, queue )
    {
        printk("%3d: ",loop++);
        d_inf = list_entry(list, struct sedf_vcpu_info, list);
        sedf_dump_domain(d_inf->vcpu);
    }
 
    queue = EXTRAQ(i,EXTRA_PEN_Q); loop = 0;
    printk("\nEXTRAQ (penalty) rq %lx   n: %lx, p: %lx\n",
           (unsigned long)queue, (unsigned long) queue->next,
           (unsigned long) queue->prev);
    list_for_each_safe ( list, tmp, queue )
    {
        d_inf = list_entry(list, struct sedf_vcpu_info,
                           extralist[EXTRA_PEN_Q]);
        printk("%3d: ",loop++);
        sedf_dump_domain(d_inf->vcpu);
    }
 
    queue = EXTRAQ(i,EXTRA_UTIL_Q); loop = 0;
    printk("\nEXTRAQ (utilization) rq %lx   n: %lx, p: %lx\n",
           (unsigned long)queue, (unsigned long) queue->next,
           (unsigned long) queue->prev);
    list_for_each_safe ( list, tmp, queue )
    {
        d_inf = list_entry(list, struct sedf_vcpu_info,
                           extralist[EXTRA_UTIL_Q]);
        printk("%3d: ",loop++);
        sedf_dump_domain(d_inf->vcpu);
    }
 
    loop = 0;
    printk("\nnot on Q\n");

    for_each_domain ( d )
    {
        for_each_vcpu(d, ed)
        {
            if ( !__task_on_queue(ed) && (ed->processor == i) )
            {
                printk("%3d: ",loop++);
                sedf_dump_domain(ed);
            }
        }
    }
}


/* Adjusts periods and slices of the domains accordingly to their weights. */
static int sedf_adjust_weights(struct sched_adjdom_cmd *cmd)
{
    struct vcpu *p;
    struct domain      *d;
    int                 sumw[NR_CPUS];
    s_time_t            sumt[NR_CPUS];
    int                 cpu;
 
    for ( cpu = 0; cpu < NR_CPUS; cpu++ )
    {
        sumw[cpu] = 0;
        sumt[cpu] = 0;
    }

    /* sum up all weights */
    for_each_domain( d )
    {
        for_each_vcpu( d, p )
        {
            if ( EDOM_INFO(p)->weight )
            {
                sumw[p->processor] += EDOM_INFO(p)->weight;
            }
            else
            {
                /*don't modify domains who don't have a weight, but sum
                  up the time they need, projected to a WEIGHT_PERIOD,
                  so that this time is not given to the weight-driven
                  domains*/
                /*check for overflows*/
                ASSERT((WEIGHT_PERIOD < ULONG_MAX) 
                       && (EDOM_INFO(p)->slice_orig < ULONG_MAX));
                sumt[p->processor] += 
                    (WEIGHT_PERIOD * EDOM_INFO(p)->slice_orig) / 
                    EDOM_INFO(p)->period_orig;
            }
        }
    }

    /* adjust all slices (and periods) to the new weight */
    for_each_domain( d )
    {
        for_each_vcpu ( d, p )
        {
            if ( EDOM_INFO(p)->weight )
            {
                EDOM_INFO(p)->period_orig = 
                    EDOM_INFO(p)->period  = WEIGHT_PERIOD;
                EDOM_INFO(p)->slice_orig  =
                    EDOM_INFO(p)->slice   = 
                    (EDOM_INFO(p)->weight *
                     (WEIGHT_PERIOD - WEIGHT_SAFETY - sumt[p->processor])) / 
                    sumw[p->processor];
            }
        }
    }

    return 0;
}


/* set or fetch domain scheduling parameters */
static int sedf_adjdom(struct domain *p, struct sched_adjdom_cmd *cmd)
{
    struct vcpu *v;

    PRINT(2,"sedf_adjdom was called, domain-id %i new period %"PRIu64" "\
          "new slice %"PRIu64"\nlatency %"PRIu64" extra:%s\n",
          p->domain_id, cmd->u.sedf.period, cmd->u.sedf.slice,
          cmd->u.sedf.latency, (cmd->u.sedf.extratime)?"yes":"no");

    if ( cmd->direction == SCHED_INFO_PUT )
    {
        /*check for sane parameters*/
        if (!cmd->u.sedf.period && !cmd->u.sedf.weight)
            return -EINVAL;
        if (cmd->u.sedf.weight) {
            if ((cmd->u.sedf.extratime & EXTRA_AWARE) &&
                (! cmd->u.sedf.period)) {
                /*weight driven domains with xtime ONLY!*/
                for_each_vcpu(p, v) {
                    EDOM_INFO(v)->extraweight = cmd->u.sedf.weight;
                    EDOM_INFO(v)->weight = 0;
                    EDOM_INFO(v)->slice = 0;
                    EDOM_INFO(v)->period = WEIGHT_PERIOD;
                }
            } else {
                /*weight driven domains with real-time execution*/
                for_each_vcpu(p, v)
                    EDOM_INFO(v)->weight = cmd->u.sedf.weight;
            }
        }
        else {
            /*time driven domains*/
            for_each_vcpu(p, v) {
                /* sanity checking! */
                if(cmd->u.sedf.slice > cmd->u.sedf.period )
                    return -EINVAL;
                EDOM_INFO(v)->weight = 0;
                EDOM_INFO(v)->extraweight = 0;
                EDOM_INFO(v)->period_orig = 
                    EDOM_INFO(v)->period   = cmd->u.sedf.period;
                EDOM_INFO(v)->slice_orig  = 
                    EDOM_INFO(v)->slice    = cmd->u.sedf.slice;
            }
        }
        if (sedf_adjust_weights(cmd))
            return -EINVAL;
   
        for_each_vcpu(p, v) {
            EDOM_INFO(v)->status  = 
                (EDOM_INFO(v)->status &
                 ~EXTRA_AWARE) | (cmd->u.sedf.extratime & EXTRA_AWARE);
            EDOM_INFO(v)->latency = cmd->u.sedf.latency;
            extraq_check(v);
        }
    }
    else if ( cmd->direction == SCHED_INFO_GET )
    {
        cmd->u.sedf.period    = EDOM_INFO(p->vcpu[0])->period;
        cmd->u.sedf.slice     = EDOM_INFO(p->vcpu[0])->slice;
        cmd->u.sedf.extratime = EDOM_INFO(p->vcpu[0])->status
            & EXTRA_AWARE;
        cmd->u.sedf.latency   = EDOM_INFO(p->vcpu[0])->latency;
        cmd->u.sedf.weight    = EDOM_INFO(p->vcpu[0])->weight;
    }
    PRINT(2,"sedf_adjdom_finished\n");
    return 0;
}

struct scheduler sched_sedf_def = {
    .name     = "Simple EDF Scheduler",
    .opt_name = "sedf",
    .sched_id = SCHED_SEDF,
    
    .alloc_task     = sedf_alloc_task,
    .add_task       = sedf_add_task,
    .free_task      = sedf_free_task,
    .do_schedule    = sedf_do_schedule,
    .dump_cpu_state = sedf_dump_cpu_state,
    .sleep          = sedf_sleep,
    .wake           = sedf_wake,
    .adjdom         = sedf_adjdom,
    .set_affinity   = sedf_set_affinity
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
