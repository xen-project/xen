/******************************************************************************
 * Simple EDF scheduler for xen
 *
 * by Stephan Diestelhorst (C)  2004 Cambridge University
 * based on code by Mark Williamson (C) 2004 Intel Research Cambridge
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>

#ifndef NDEBUG
#define SEDF_STATS
#define CHECK(_p)                                           \
    do {                                                    \
        if ( !(_p) )                                        \
            printk("Check '%s' failed, line %d, file %s\n", \
                   #_p , __LINE__, __FILE__);               \
    } while ( 0 )
#else
#define CHECK(_p) ((void)0)
#endif

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

#define PERIOD_MAX MILLISECS(10000) /* 10s  */
#define PERIOD_MIN (MICROSECS(10))  /* 10us */
#define SLICE_MIN (MICROSECS(5))    /*  5us */

#define IMPLY(a, b) (!(a) || (b))
#define EQ(a, b) ((!!(a)) == (!!(b)))


struct sedf_dom_info {
    struct domain  *domain;
};

struct sedf_priv_info {
    /* lock for the whole pluggable scheduler, nests inside cpupool_lock */
    spinlock_t lock;
};

struct sedf_vcpu_info {
    struct vcpu *vcpu;
    struct list_head list;
    struct list_head extralist[2];
 
    /* Parameters for EDF */
    s_time_t  period;  /* = relative deadline */
    s_time_t  slice;   /* = worst case execution time */
 
    /* Advaced Parameters */

    /* Latency Scaling */
    s_time_t  period_orig;
    s_time_t  slice_orig;
    s_time_t  latency;
 
    /* Status of domain */
    int       status;
    /* Weights for "Scheduling for beginners/ lazy/ etc." ;) */
    short     weight;
    short     extraweight;
    /* Bookkeeping */
    s_time_t  deadl_abs;
    s_time_t  sched_start_abs;
    s_time_t  cputime;
    /* Times the domain un-/blocked */
    s_time_t  block_abs;
    s_time_t  unblock_abs;
 
    /* Scores for {util, block penalty}-weighted extratime distribution */
    int   score[2];
    s_time_t  short_block_lost_tot;
 
    /* Statistics */
    s_time_t  extra_time_tot;

#ifdef SEDF_STATS
    s_time_t  block_time_tot;
    s_time_t  penalty_time_tot;
    int   block_tot;
    int   short_block_tot;
    int   long_block_tot;
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

#define SEDF_PRIV(_ops) \
    ((struct sedf_priv_info *)((_ops)->sched_data))
#define EDOM_INFO(d)   ((struct sedf_vcpu_info *)((d)->sched_priv))
#define CPU_INFO(cpu)  \
    ((struct sedf_cpu_info *)per_cpu(schedule_data, cpu).sched_priv)
#define LIST(d)        (&EDOM_INFO(d)->list)
#define EXTRALIST(d,i) (&(EDOM_INFO(d)->extralist[i]))
#define RUNQ(cpu)      (&CPU_INFO(cpu)->runnableq)
#define WAITQ(cpu)     (&CPU_INFO(cpu)->waitq)
#define EXTRAQ(cpu,i)  (&(CPU_INFO(cpu)->extraq[i]))
#define IDLETASK(cpu)  (idle_vcpu[cpu])

#define PERIOD_BEGIN(inf) ((inf)->deadl_abs - (inf)->period)

#define DIV_UP(x,y) (((x) + (y) - 1) / y)

#define extra_runs(inf)      ((inf->status) & 6)
#define extra_get_cur_q(inf) (((inf->status & 6) >> 1)-1)
#define sedf_runnable(edom)  (!(EDOM_INFO(edom)->status & SEDF_ASLEEP))


static void sedf_dump_cpu_state(const struct scheduler *ops, int i);

static inline int extraq_on(struct vcpu *d, int i)
{
    return ((EXTRALIST(d,i)->next != NULL) &&
            (EXTRALIST(d,i)->next != EXTRALIST(d,i)));
}

static inline void extraq_del(struct vcpu *d, int i)
{
    struct list_head *list = EXTRALIST(d,i);
    ASSERT(extraq_on(d,i));
    list_del(list);
    list->next = NULL;
    ASSERT(!extraq_on(d, i));
}

/*
 * Adds a domain to the queue of processes which are aware of extra time. List
 * is sorted by score, where a lower score means higher priority for an extra
 * slice. It also updates the score, by simply subtracting a fixed value from
 * each entry, in order to avoid overflow. The algorithm works by simply
 * charging each domain that recieved extratime with an inverse of its weight.
 */ 
static inline void extraq_add_sort_update(struct vcpu *d, int i, int sub)
{
    struct list_head      *cur;
    struct sedf_vcpu_info *curinf;
 
    ASSERT(!extraq_on(d,i));

    /*
     * Iterate through all elements to find our "hole" and on our way
     * update all the other scores.
     */
    list_for_each ( cur, EXTRAQ(d->processor, i) )
    {
        curinf = list_entry(cur,struct sedf_vcpu_info,extralist[i]);
        curinf->score[i] -= sub;
        if ( EDOM_INFO(d)->score[i] < curinf->score[i] )
            break;
    }

    /* cur now contains the element, before which we'll enqueue */
    list_add(EXTRALIST(d,i),cur->prev);
 
    /* Continue updating the extraq */
    if ( (cur != EXTRAQ(d->processor,i)) && sub )
    {
        for ( cur = cur->next; cur != EXTRAQ(d->processor,i); cur = cur->next )
        {
            curinf = list_entry(cur,struct sedf_vcpu_info, extralist[i]);
            curinf->score[i] -= sub;
        }
    }

    ASSERT(extraq_on(d,i));
}
static inline void extraq_check(struct vcpu *d)
{
    if ( extraq_on(d, EXTRA_UTIL_Q) )
    {
        if ( !(EDOM_INFO(d)->status & EXTRA_AWARE) &&
             !extra_runs(EDOM_INFO(d)) )
            extraq_del(d, EXTRA_UTIL_Q);
    }
    else
    {
        if ( (EDOM_INFO(d)->status & EXTRA_AWARE) && sedf_runnable(d) )
            extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
    }
}

static inline void extraq_check_add_unblocked(struct vcpu *d, int priority)
{
    struct sedf_vcpu_info *inf = EDOM_INFO(d);

    if ( inf->status & EXTRA_AWARE )
        /* Put on the weighted extraq without updating any scores */
        extraq_add_sort_update(d, EXTRA_UTIL_Q, 0);
}

static inline int __task_on_queue(struct vcpu *d)
{
    return (((LIST(d))->next != NULL) && (LIST(d)->next != LIST(d)));
}

static inline void __del_from_queue(struct vcpu *d)
{
    struct list_head *list = LIST(d);
    ASSERT(__task_on_queue(d));
    list_del(list);
    list->next = NULL;
    ASSERT(!__task_on_queue(d));
}

typedef int(*list_comparer)(struct list_head* el1, struct list_head* el2);

static inline void list_insert_sort(
    struct list_head *list, struct list_head *element, list_comparer comp)
{
    struct list_head     *cur;

    /* Iterate through all elements to find our "hole" */
    list_for_each( cur, list )
        if ( comp(element, cur) < 0 )
            break;

    /* cur now contains the element, before which we'll enqueue */
    list_add(element, cur->prev);
}

#define DOMAIN_COMPARER(name, field, comp1, comp2)                      \
static int name##_comp(struct list_head* el1, struct list_head* el2)    \
{                                                                       \
    struct sedf_vcpu_info *d1, *d2;                                     \
    d1 = list_entry(el1,struct sedf_vcpu_info, field);                  \
    d2 = list_entry(el2,struct sedf_vcpu_info, field);                  \
    if ( (comp1) == (comp2) )                                           \
        return 0;                                                       \
    if ( (comp1) < (comp2) )                                            \
        return -1;                                                      \
    else                                                                \
        return 1;                                                       \
}

/*
 * Adds a domain to the queue of processes which wait for the beginning of the
 * next period; this list is therefore sortet by this time, which is simply
 * absol. deadline - period.
 */ 
DOMAIN_COMPARER(waitq, list, PERIOD_BEGIN(d1), PERIOD_BEGIN(d2));
static inline void __add_to_waitqueue_sort(struct vcpu *v)
{
    ASSERT(!__task_on_queue(v));
    list_insert_sort(WAITQ(v->processor), LIST(v), waitq_comp);
    ASSERT(__task_on_queue(v));
}

/*
 * Adds a domain to the queue of processes which have started their current
 * period and are runnable (i.e. not blocked, dieing,...). The first element
 * on this list is running on the processor, if the list is empty the idle
 * task will run. As we are implementing EDF, this list is sorted by deadlines.
 */ 
DOMAIN_COMPARER(runq, list, d1->deadl_abs, d2->deadl_abs);
static inline void __add_to_runqueue_sort(struct vcpu *v)
{
    list_insert_sort(RUNQ(v->processor), LIST(v), runq_comp);
}


static void sedf_insert_vcpu(const struct scheduler *ops, struct vcpu *v)
{
    if ( !is_idle_vcpu(v) )
    {
        extraq_check(v);
    }
    else
    {
        EDOM_INFO(v)->deadl_abs = 0;
        EDOM_INFO(v)->status &= ~SEDF_ASLEEP;
    }
}

static void *sedf_alloc_vdata(const struct scheduler *ops, struct vcpu *v, void *dd)
{
    struct sedf_vcpu_info *inf;

    inf = xzalloc(struct sedf_vcpu_info);
    if ( inf == NULL )
        return NULL;

    inf->vcpu = v;

    /* Every VCPU gets an equal share of extratime by default */
    inf->deadl_abs   = 0;
    inf->latency     = 0;
    inf->status      = EXTRA_AWARE | SEDF_ASLEEP;
    inf->extraweight = 1;
    /* Upon creation all domain are best-effort */
    inf->period      = WEIGHT_PERIOD;
    inf->slice       = 0;

    inf->period_orig = inf->period; inf->slice_orig = inf->slice;
    INIT_LIST_HEAD(&(inf->list));
    INIT_LIST_HEAD(&(inf->extralist[EXTRA_PEN_Q]));
    INIT_LIST_HEAD(&(inf->extralist[EXTRA_UTIL_Q]));

    SCHED_STAT_CRANK(vcpu_init);

    return inf;
}

static void *
sedf_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct sedf_cpu_info *spc;

    spc = xzalloc(struct sedf_cpu_info);
    BUG_ON(spc == NULL);
    INIT_LIST_HEAD(&spc->waitq);
    INIT_LIST_HEAD(&spc->runnableq);
    INIT_LIST_HEAD(&spc->extraq[EXTRA_PEN_Q]);
    INIT_LIST_HEAD(&spc->extraq[EXTRA_UTIL_Q]);

    return (void *)spc;
}

static void
sedf_free_pdata(const struct scheduler *ops, void *spc, int cpu)
{
    if ( spc == NULL )
        return;

    xfree(spc);
}

static void sedf_free_vdata(const struct scheduler *ops, void *priv)
{
    xfree(priv);
}

static void *
sedf_alloc_domdata(const struct scheduler *ops, struct domain *d)
{
    return xzalloc(struct sedf_dom_info);
}

static int sedf_init_domain(const struct scheduler *ops, struct domain *d)
{
    d->sched_priv = sedf_alloc_domdata(ops, d);
    if ( d->sched_priv == NULL )
        return -ENOMEM;

    return 0;
}

static void sedf_free_domdata(const struct scheduler *ops, void *data)
{
    xfree(data);
}

static void sedf_destroy_domain(const struct scheduler *ops, struct domain *d)
{
    sedf_free_domdata(ops, d->sched_priv);
}

static int sedf_pick_cpu(const struct scheduler *ops, struct vcpu *v)
{
    cpumask_t online_affinity;
    cpumask_t *online;

    online = cpupool_scheduler_cpumask(v->domain->cpupool);
    cpumask_and(&online_affinity, v->cpu_hard_affinity, online);
    return cpumask_cycle(v->vcpu_id % cpumask_weight(&online_affinity) - 1,
                         &online_affinity);
}

/*
 * Handles the rescheduling & bookkeeping of domains running in their
 * guaranteed timeslice.
 */
static void desched_edf_dom(s_time_t now, struct vcpu* d)
{
    struct sedf_vcpu_info* inf = EDOM_INFO(d);

    /* Current domain is running in real time mode */
    ASSERT(__task_on_queue(d));

    /* Update the domain's cputime */
    inf->cputime += now - inf->sched_start_abs;

    /* Scheduling decisions which don't remove the running domain from
     * the runq */
    if ( (inf->cputime < inf->slice) && sedf_runnable(d) )
        return;
  
    __del_from_queue(d);

    /*
     * Manage bookkeeping (i.e. calculate next deadline, memorise
     * overrun-time of slice) of finished domains.
     */
    if ( inf->cputime >= inf->slice )
    {
        inf->cputime -= inf->slice;
  
        if ( inf->period < inf->period_orig )
        {
            /* This domain runs in latency scaling or burst mode */
            inf->period *= 2;
            inf->slice  *= 2;
            if ( (inf->period > inf->period_orig) ||
                 (inf->slice > inf->slice_orig) )
            {
                /* Reset slice and period */
                inf->period = inf->period_orig;
                inf->slice = inf->slice_orig;
            }
        }

        /* Set next deadline */
        inf->deadl_abs += inf->period;
    }
 
    /* Add a runnable domain to the waitqueue */
    if ( sedf_runnable(d) )
    {
        __add_to_waitqueue_sort(d);
    }
    else
    {
        /* We have a blocked realtime task -> remove it from exqs too */
        if ( extraq_on(d, EXTRA_PEN_Q) )
            extraq_del(d, EXTRA_PEN_Q);
        if ( extraq_on(d, EXTRA_UTIL_Q) )
            extraq_del(d, EXTRA_UTIL_Q);
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
 
    /*
     * Check for the first elements of the waitqueue, whether their
     * next period has already started.
     */
    list_for_each_safe ( cur, tmp, waitq )
    {
        curinf = list_entry(cur, struct sedf_vcpu_info, list);
        if ( PERIOD_BEGIN(curinf) > now )
            break;
        __del_from_queue(curinf->vcpu);
        __add_to_runqueue_sort(curinf->vcpu);
    }
 
    /* Process the runq, find domains that are on the runq that shouldn't */
    list_for_each_safe ( cur, tmp, runq )
    {
        curinf = list_entry(cur,struct sedf_vcpu_info,list);

        if ( unlikely(curinf->slice == 0) )
        {
            /* Ignore domains with empty slice */
            __del_from_queue(curinf->vcpu);

            /* Move them to their next period */
            curinf->deadl_abs += curinf->period;

            /* Ensure that the start of the next period is in the future */
            if ( unlikely(PERIOD_BEGIN(curinf) < now) )
                curinf->deadl_abs += 
                    (DIV_UP(now - PERIOD_BEGIN(curinf),
                            curinf->period)) * curinf->period;

            /* Put them back into the queue */
            __add_to_waitqueue_sort(curinf->vcpu);
        }
        else if ( unlikely((curinf->deadl_abs < now) ||
                           (curinf->cputime > curinf->slice)) )
        {
            /*
             * We missed the deadline or the slice was already finished.
             * Might hapen because of dom_adj.
             */
            printk("\tDomain %i.%i exceeded it's deadline/"
                   "slice (%"PRIu64" / %"PRIu64") now: %"PRIu64
                   " cputime: %"PRIu64"\n",
                   curinf->vcpu->domain->domain_id,
                   curinf->vcpu->vcpu_id,
                   curinf->deadl_abs, curinf->slice, now,
                   curinf->cputime);
            __del_from_queue(curinf->vcpu);

            /* Common case: we miss one period */
            curinf->deadl_abs += curinf->period;

            /*
             * If we are still behind: modulo arithmetic, force deadline
             * to be in future and aligned to period borders.
             */
            if ( unlikely(curinf->deadl_abs < now) )
                curinf->deadl_abs += 
                    DIV_UP(now - curinf->deadl_abs,
                           curinf->period) * curinf->period;
            ASSERT(curinf->deadl_abs >= now);

            /* Give a fresh slice */
            curinf->cputime = 0;
            if ( PERIOD_BEGIN(curinf) > now )
                __add_to_waitqueue_sort(curinf->vcpu);
            else
                __add_to_runqueue_sort(curinf->vcpu);
        }
        else
            break;
    }
}


/*
 * removes a domain from the head of the according extraQ and
 * requeues it at a specified position:
 *   round-robin extratime: end of extraQ
 *   weighted ext.: insert in sorted list by score
 * if the domain is blocked / has regained its short-block-loss
 * time it is not put on any queue.
 */
static void desched_extra_dom(s_time_t now, struct vcpu *d)
{
    struct sedf_vcpu_info *inf = EDOM_INFO(d);
    int i = extra_get_cur_q(inf);
    unsigned long oldscore;

    ASSERT(extraq_on(d, i));

    /* Unset all running flags */
    inf->status  &= ~(EXTRA_RUN_PEN | EXTRA_RUN_UTIL);
    /* Fresh slice for the next run */
    inf->cputime = 0;
    /* Accumulate total extratime */
    inf->extra_time_tot += now - inf->sched_start_abs;
    /* Remove extradomain from head of the queue. */
    extraq_del(d, i);

    /* Update the score */
    oldscore = inf->score[i];
    if ( i == EXTRA_PEN_Q )
    {
        /* Domain was running in L0 extraq */
        /* reduce block lost, probably more sophistication here!*/
        /*inf->short_block_lost_tot -= EXTRA_QUANTUM;*/
        inf->short_block_lost_tot -= now - inf->sched_start_abs;
#if 0
        /* KAF: If we don't exit short-blocking state at this point
         * domain0 can steal all CPU for up to 10 seconds before
         * scheduling settles down (when competing against another
         * CPU-bound domain). Doing this seems to make things behave
         * nicely. Noone gets starved by default.
         */
        if ( inf->short_block_lost_tot <= 0 )
#endif
        {
            /* We have (over-)compensated our block penalty */
            inf->short_block_lost_tot = 0;
            /* We don't want a place on the penalty queue anymore! */
            inf->status &= ~EXTRA_WANT_PEN_Q;
            goto check_extra_queues;
        }

        /*
         * We have to go again for another try in the block-extraq,
         * the score is not used incremantally here, as this is
         * already done by recalculating the block_lost
         */
        inf->score[EXTRA_PEN_Q] = (inf->period << 10) /
            inf->short_block_lost_tot;
        oldscore = 0;
    }
    else
    {
        /*
         * Domain was running in L1 extraq => score is inverse of
         * utilization and is used somewhat incremental!
         */
        if ( !inf->extraweight )
        {
            /* NB: use fixed point arithmetic with 10 bits */
            inf->score[EXTRA_UTIL_Q] = (inf->period << 10) /
                inf->slice;
        }
        else
        {
            /*
             * Conversion between realtime utilisation and extrawieght:
             * full (ie 100%) utilization is equivalent to 128 extraweight
             */
            inf->score[EXTRA_UTIL_Q] = (1<<17) / inf->extraweight;
        }
    }

 check_extra_queues:
    /* Adding a runnable domain to the right queue and removing blocked ones */
    if ( sedf_runnable(d) )
    {
        /* Add according to score: weighted round robin */
        if (((inf->status & EXTRA_AWARE) && (i == EXTRA_UTIL_Q)) ||
            ((inf->status & EXTRA_WANT_PEN_Q) && (i == EXTRA_PEN_Q)))
            extraq_add_sort_update(d, i, oldscore);
    }
    else
    {
        /* Remove this blocked domain from the waitq! */
        __del_from_queue(d);
        /* Make sure that we remove a blocked domain from the other
         * extraq too. */
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
    }

    ASSERT(EQ(sedf_runnable(d), __task_on_queue(d)));
    ASSERT(IMPLY(extraq_on(d, EXTRA_UTIL_Q) || extraq_on(d, EXTRA_PEN_Q), 
                 sedf_runnable(d)));
}


static struct task_slice sedf_do_extra_schedule(
    s_time_t now, s_time_t end_xt, struct list_head *extraq[], int cpu)
{
    struct task_slice   ret = { 0 };
    struct sedf_vcpu_info *runinf;
    ASSERT(end_xt > now);

    /* Enough time left to use for extratime? */
    if ( end_xt - now < EXTRA_QUANTUM )
        goto return_idle;

    if ( !list_empty(extraq[EXTRA_PEN_Q]) )
    {
        /*
         * We still have elements on the level 0 extraq
         * => let those run first!
         */
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
    {
        if ( !list_empty(extraq[EXTRA_UTIL_Q]) )
        {
            /* Use elements from the normal extraqueue */
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


static int sedf_init(struct scheduler *ops)
{
    struct sedf_priv_info *prv;

    prv = xzalloc(struct sedf_priv_info);
    if ( prv == NULL )
        return -ENOMEM;

    ops->sched_data = prv;
    spin_lock_init(&prv->lock);

    return 0;
}


static void sedf_deinit(const struct scheduler *ops)
{
    struct sedf_priv_info *prv;

    prv = SEDF_PRIV(ops);
    if ( prv != NULL )
        xfree(prv);
}


/*
 * Main scheduling function
 * Reasons for calling this function are:
 * -timeslice for the current period used up
 * -domain on waitqueue has started it's period
 * -and various others ;) in general: determine which domain to run next
 */
static struct task_slice sedf_do_schedule(
    const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    int                   cpu      = smp_processor_id();
    struct list_head     *runq     = RUNQ(cpu);
    struct list_head     *waitq    = WAITQ(cpu);
    struct sedf_vcpu_info *inf     = EDOM_INFO(current);
    struct list_head      *extraq[] = {
        EXTRAQ(cpu, EXTRA_PEN_Q), EXTRAQ(cpu, EXTRA_UTIL_Q)};
    struct sedf_vcpu_info *runinf, *waitinf;
    struct task_slice      ret;

    SCHED_STAT_CRANK(schedule);

    /* Idle tasks don't need any of the following stuf */
    if ( is_idle_vcpu(current) )
        goto check_waitq;

    /*
     * Create local state of the status of the domain, in order to avoid
     * inconsistent state during scheduling decisions, because data for
     * vcpu_runnable is not protected by the scheduling lock!
     */
    if ( !vcpu_runnable(current) )
        inf->status |= SEDF_ASLEEP;
 
    if ( inf->status & SEDF_ASLEEP )
        inf->block_abs = now;

    if ( unlikely(extra_runs(inf)) )
    {
        /* Special treatment of domains running in extra time */
        desched_extra_dom(now, current);
    }
    else 
    {
        desched_edf_dom(now, current);
    }
 check_waitq:
    update_queues(now, runq, waitq);

    /*
     * Now simply pick the first domain from the runqueue, which has the
     * earliest deadline, because the list is sorted
     *
     * Tasklet work (which runs in idle VCPU context) overrides all else.
     */
    if ( tasklet_work_scheduled ||
         (list_empty(runq) && list_empty(waitq)) ||
         unlikely(!cpumask_test_cpu(cpu,
                   cpupool_scheduler_cpumask(per_cpu(cpupool, cpu)))) )
    {
        ret.task = IDLETASK(cpu);
        ret.time = SECONDS(1);
    }
    else if ( !list_empty(runq) )
    {
        runinf   = list_entry(runq->next,struct sedf_vcpu_info,list);
        ret.task = runinf->vcpu;
        if ( !list_empty(waitq) )
        {
            waitinf  = list_entry(waitq->next,
                                  struct sedf_vcpu_info,list);
            /*
             * Rerun scheduler, when scheduled domain reaches it's
             * end of slice or the first domain from the waitqueue
             * gets ready.
             */
            ret.time = MIN(now + runinf->slice - runinf->cputime,
                           PERIOD_BEGIN(waitinf)) - now;
        }
        else
        {
            ret.time = runinf->slice - runinf->cputime;
        }
    }
    else
    {
        waitinf  = list_entry(waitq->next,struct sedf_vcpu_info, list);
        /*
         * We could not find any suitable domain 
         * => look for domains that are aware of extratime
         */
        ret = sedf_do_extra_schedule(now, PERIOD_BEGIN(waitinf),
                                     extraq, cpu);
    }

    /*
     * TODO: Do something USEFUL when this happens and find out, why it
     * still can happen!!!
     */
    if ( ret.time < 0)
    {
        printk("Ouch! We are seriously BEHIND schedule! %"PRIi64"\n",
               ret.time);
        ret.time = EXTRA_QUANTUM;
    }

    ret.migrated = 0;

    EDOM_INFO(ret.task)->sched_start_abs = now;
    CHECK(ret.time > 0);
    ASSERT(sedf_runnable(ret.task));
    CPU_INFO(cpu)->current_slice_expires = now + ret.time;
    return ret;
}


static void sedf_sleep(const struct scheduler *ops, struct vcpu *d)
{
    if ( is_idle_vcpu(d) )
        return;

    EDOM_INFO(d)->status |= SEDF_ASLEEP;
 
    if ( per_cpu(schedule_data, d->processor).curr == d )
    {
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    }
    else
    {
        if ( __task_on_queue(d) )
            __del_from_queue(d);
        if ( extraq_on(d, EXTRA_UTIL_Q) ) 
            extraq_del(d, EXTRA_UTIL_Q);
        if ( extraq_on(d, EXTRA_PEN_Q) )
            extraq_del(d, EXTRA_PEN_Q);
    }
}


/*
 * This function wakes up a domain, i.e. moves them into the waitqueue
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
 *
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
static void unblock_short_extra_support(
    struct sedf_vcpu_info* inf, s_time_t now)
{
    /*
     * This unblocking scheme tries to support the domain, by assigning it
     * a priority in extratime distribution according to the loss of time
     * in this slice due to blocking
     */
    s_time_t pen;
 
    /* No more realtime execution in this period! */
    inf->deadl_abs += inf->period;
    if ( likely(inf->block_abs) )
    {
        /* Treat blocked time as consumed by the domain */
        /*inf->cputime += now - inf->block_abs;*/
        /*
         * Penalty is time the domain would have
         * had if it continued to run.
         */
        pen = (inf->slice - inf->cputime);
        if ( pen < 0 )
            pen = 0;
        /* Accumulate all penalties over the periods */
        /*inf->short_block_lost_tot += pen;*/
        /* Set penalty to the current value */
        inf->short_block_lost_tot = pen;
        /* Not sure which one is better.. but seems to work well... */
  
        if ( inf->short_block_lost_tot )
        {
            inf->score[0] = (inf->period << 10) /
                inf->short_block_lost_tot;
#ifdef SEDF_STATS
            inf->pen_extra_blocks++;
#endif
            if ( extraq_on(inf->vcpu, EXTRA_PEN_Q) )
                /* Remove domain for possible resorting! */
                extraq_del(inf->vcpu, EXTRA_PEN_Q);
            else
                /*
                 * Remember that we want to be on the penalty q
                 * so that we can continue when we (un-)block
                 * in penalty-extratime
                 */
                inf->status |= EXTRA_WANT_PEN_Q;
   
            /* (re-)add domain to the penalty extraq */
            extraq_add_sort_update(inf->vcpu, EXTRA_PEN_Q, 0);
        }
    }

    /* Give it a fresh slice in the next period! */
    inf->cputime = 0;
}


static void unblock_long_cons_b(struct sedf_vcpu_info* inf,s_time_t now)
{
    /* Conservative 2b */

    /* Treat the unblocking time as a start of a new period */
    inf->deadl_abs = now + inf->period;
    inf->cputime = 0;
}


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


/*
 * Compares two domains in the relation of whether the one is allowed to
 * interrupt the others execution.
 * It returns true (!=0) if a switch to the other domain is good.
 * Current Priority scheme is as follows:
 *  EDF > L0 (penalty based) extra-time > 
 *  L1 (utilization) extra-time > idle-domain
 * In the same class priorities are assigned as following:
 *  EDF: early deadline > late deadline
 *  L0 extra-time: lower score > higher score
 */
static inline int should_switch(struct vcpu *cur,
                                struct vcpu *other,
                                s_time_t now)
{
    struct sedf_vcpu_info *cur_inf, *other_inf;
    cur_inf   = EDOM_INFO(cur);
    other_inf = EDOM_INFO(other);
 
    /* Check whether we need to make an earlier scheduling decision */
    if ( PERIOD_BEGIN(other_inf) < 
         CPU_INFO(other->processor)->current_slice_expires )
        return 1;

    /* No timing-based switches need to be taken into account here */
    switch ( get_run_type(cur) )
    {
    case DOMAIN_EDF:
        /* Do not interrupt a running EDF domain */
        return 0;
    case DOMAIN_EXTRA_PEN:
        /* Check whether we also want the L0 ex-q with lower score */
        return ((other_inf->status & EXTRA_WANT_PEN_Q) &&
                (other_inf->score[EXTRA_PEN_Q] < 
                 cur_inf->score[EXTRA_PEN_Q]));
    case DOMAIN_EXTRA_UTIL:
        /* Check whether we want the L0 extraq. Don't
         * switch if both domains want L1 extraq. */
        return !!(other_inf->status & EXTRA_WANT_PEN_Q);
    case DOMAIN_IDLE:
        return 1;
    }

    return 1;
}

static void sedf_wake(const struct scheduler *ops, struct vcpu *d)
{
    s_time_t              now = NOW();
    struct sedf_vcpu_info* inf = EDOM_INFO(d);

    if ( unlikely(is_idle_vcpu(d)) )
        return;
   
    if ( unlikely(__task_on_queue(d)) )
        return;

    ASSERT(!sedf_runnable(d));
    inf->status &= ~SEDF_ASLEEP;
    ASSERT(!extraq_on(d, EXTRA_UTIL_Q));
    ASSERT(!extraq_on(d, EXTRA_PEN_Q));
 
    if ( unlikely(inf->deadl_abs == 0) )
    {
        /* Initial setup of the deadline */
        inf->deadl_abs = now + inf->slice;
    }
  
#ifdef SEDF_STATS 
    inf->block_tot++;
#endif

    if ( unlikely(now < PERIOD_BEGIN(inf)) )
    {
        /* Unblocking in extra-time! */
        if ( inf->status & EXTRA_WANT_PEN_Q )
        {
            /*
             * We have a domain that wants compensation
             * for block penalty and did just block in
             * its compensation time. Give it another
             * chance!
             */
            extraq_add_sort_update(d, EXTRA_PEN_Q, 0);
        }
        extraq_check_add_unblocked(d, 0);
    }  
    else
    {  
        if ( now < inf->deadl_abs )
        {
            /* Short blocking */
#ifdef SEDF_STATS
            inf->short_block_tot++;
#endif
            unblock_short_extra_support(inf, now);

            extraq_check_add_unblocked(d, 1);
        }
        else
        {
            /* Long unblocking */
#ifdef SEDF_STATS
            inf->long_block_tot++;
#endif
            unblock_long_cons_b(inf, now);

            extraq_check_add_unblocked(d, 1);
        }
    }

    if ( PERIOD_BEGIN(inf) > now )
        __add_to_waitqueue_sort(d);
    else
        __add_to_runqueue_sort(d);
 
#ifdef SEDF_STATS
    /* Do some statistics here... */
    if ( inf->block_abs != 0 )
    {
        inf->block_time_tot += now - inf->block_abs;
        inf->penalty_time_tot +=
            PERIOD_BEGIN(inf) + inf->cputime - inf->block_abs;
    }
#endif

    /* Sanity check: make sure each extra-aware domain IS on the util-q! */
    ASSERT(IMPLY(inf->status & EXTRA_AWARE, extraq_on(d, EXTRA_UTIL_Q)));
    ASSERT(__task_on_queue(d));
    /*
     * Check whether the awakened task needs to invoke the do_schedule
     * routine. Try to avoid unnecessary runs but:
     * Save approximation: Always switch to scheduler!
     */
    ASSERT(d->processor >= 0);
    ASSERT(d->processor < nr_cpu_ids);
    ASSERT(per_cpu(schedule_data, d->processor).curr);

    if ( should_switch(per_cpu(schedule_data, d->processor).curr, d, now) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
}


/* Print a lot of useful information about a domains in the system */
static void sedf_dump_domain(struct vcpu *d)
{
    printk("%i.%i has=%c ", d->domain->domain_id, d->vcpu_id,
           d->is_running ? 'T':'F');
    printk("p=%"PRIu64" sl=%"PRIu64" ddl=%"PRIu64" w=%hu"
           " sc=%i xtr(%s)=%"PRIu64" ew=%hu",
           EDOM_INFO(d)->period, EDOM_INFO(d)->slice, EDOM_INFO(d)->deadl_abs,
           EDOM_INFO(d)->weight,
           EDOM_INFO(d)->score[EXTRA_UTIL_Q],
           (EDOM_INFO(d)->status & EXTRA_AWARE) ? "yes" : "no",
           EDOM_INFO(d)->extra_time_tot, EDOM_INFO(d)->extraweight);
    
#ifdef SEDF_STATS
    if ( EDOM_INFO(d)->block_time_tot != 0 )
        printk(" pen=%"PRIu64"%%", (EDOM_INFO(d)->penalty_time_tot * 100) /
               EDOM_INFO(d)->block_time_tot);
    if ( EDOM_INFO(d)->block_tot != 0 )
        printk("\n   blks=%u sh=%u (%u%%) (shex=%i "\
               "shexsl=%i) l=%u (%u%%) avg: b=%"PRIu64" p=%"PRIu64"",
               EDOM_INFO(d)->block_tot, EDOM_INFO(d)->short_block_tot,
               (EDOM_INFO(d)->short_block_tot * 100) / EDOM_INFO(d)->block_tot,
               EDOM_INFO(d)->pen_extra_blocks,
               EDOM_INFO(d)->pen_extra_slices,
               EDOM_INFO(d)->long_block_tot,
               (EDOM_INFO(d)->long_block_tot * 100) / EDOM_INFO(d)->block_tot,
               (EDOM_INFO(d)->block_time_tot) / EDOM_INFO(d)->block_tot,
               (EDOM_INFO(d)->penalty_time_tot) / EDOM_INFO(d)->block_tot);
#endif
    printk("\n");
}


/* Dumps all domains on the specified cpu */
static void sedf_dump_cpu_state(const struct scheduler *ops, int i)
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

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
    {
        if ( (d->cpupool ? d->cpupool->sched : &sched_sedf_def) != ops )
            continue;
        for_each_vcpu(d, ed)
        {
            if ( !__task_on_queue(ed) && (ed->processor == i) )
            {
                printk("%3d: ",loop++);
                sedf_dump_domain(ed);
            }
        }
    }
    rcu_read_unlock(&domlist_read_lock);
}


/* Adjusts periods and slices of the domains accordingly to their weights */
static int sedf_adjust_weights(struct cpupool *c, int nr_cpus, int *sumw, s_time_t *sumt)
{
    struct vcpu *p;
    struct domain      *d;
    unsigned int        cpu;

    /*
     * Sum across all weights. Notice that no runq locking is needed
     * here: the caller holds sedf_priv_info.lock and we're not changing
     * anything that is accessed during scheduling.
     */
    rcu_read_lock(&domlist_read_lock);
    for_each_domain_in_cpupool( d, c )
    {
        for_each_vcpu( d, p )
        {
            if ( (cpu = p->processor) >= nr_cpus )
                continue;

            if ( EDOM_INFO(p)->weight )
            {
                sumw[cpu] += EDOM_INFO(p)->weight;
            }
            else
            {
                /*
                 * Don't modify domains who don't have a weight, but sum
                 * up the time they need, projected to a WEIGHT_PERIOD,
                 * so that this time is not given to the weight-driven
                 *  domains
                 */

                /* Check for overflows */
                ASSERT((WEIGHT_PERIOD < ULONG_MAX) 
                       && (EDOM_INFO(p)->slice_orig < ULONG_MAX));
                sumt[cpu] += 
                    (WEIGHT_PERIOD * EDOM_INFO(p)->slice_orig) / 
                    EDOM_INFO(p)->period_orig;
            }
        }
    }
    rcu_read_unlock(&domlist_read_lock);

    /*
     * Adjust all slices (and periods) to the new weight. Unlike above, we
     * need to take thr runq lock for the various VCPUs: we're modyfing
     * slice and period which are referenced during scheduling.
     */
    rcu_read_lock(&domlist_read_lock);
    for_each_domain_in_cpupool( d, c )
    {
        for_each_vcpu ( d, p )
        {
            if ( (cpu = p->processor) >= nr_cpus )
                continue;
            if ( EDOM_INFO(p)->weight )
            {
                /* Interrupts already off */
                spinlock_t *lock = vcpu_schedule_lock(p);

                EDOM_INFO(p)->period_orig = 
                    EDOM_INFO(p)->period  = WEIGHT_PERIOD;
                EDOM_INFO(p)->slice_orig  =
                    EDOM_INFO(p)->slice   = 
                    (EDOM_INFO(p)->weight *
                     (WEIGHT_PERIOD - WEIGHT_SAFETY - sumt[cpu])) / sumw[cpu];

                vcpu_schedule_unlock(lock, p);
            }
        }
    }
    rcu_read_unlock(&domlist_read_lock);

    return 0;
}


/* Set or fetch domain scheduling parameters */
static int sedf_adjust(const struct scheduler *ops, struct domain *p, struct xen_domctl_scheduler_op *op)
{
    struct sedf_priv_info *prv = SEDF_PRIV(ops);
    unsigned long flags;
    unsigned int nr_cpus = cpumask_last(&cpu_online_map) + 1;
    int *sumw = xzalloc_array(int, nr_cpus);
    s_time_t *sumt = xzalloc_array(s_time_t, nr_cpus);
    struct vcpu *v;
    int rc = 0;

    /*
     * Serialize against the pluggable scheduler lock to protect from
     * concurrent updates. We need to take the runq lock for the VCPUs
     * as well, since we are touching extraweight, weight, slice and
     * period. As in sched_credit2.c, runq locks nest inside the
     * pluggable scheduler lock.
     */
    spin_lock_irqsave(&prv->lock, flags);

    if ( op->cmd == XEN_DOMCTL_SCHEDOP_putinfo )
    {
        /*
         * These are used in sedf_adjust_weights() but have to be allocated in
         * this function, as we need to avoid nesting xmem_pool_alloc's lock
         * within our prv->lock.
         */
        if ( !sumw || !sumt )
        {
            /* Check for errors here, the _getinfo branch doesn't care */
            rc = -ENOMEM;
            goto out;
        }

        /* Check for sane parameters */
        if ( !op->u.sedf.period && !op->u.sedf.weight )
        {
            rc = -EINVAL;
            goto out;
        }

        if ( op->u.sedf.weight )
        {
            if ( (op->u.sedf.extratime & EXTRA_AWARE) &&
                 (!op->u.sedf.period) )
            {
                /* Weight-driven domains with extratime only */
                for_each_vcpu ( p, v )
                {
                    /* (Here and everywhere in the following) IRQs are already off,
                     * hence vcpu_spin_lock() is the one. */
                    spinlock_t *lock = vcpu_schedule_lock(v);

                    EDOM_INFO(v)->extraweight = op->u.sedf.weight;
                    EDOM_INFO(v)->weight = 0;
                    EDOM_INFO(v)->slice = 0;
                    EDOM_INFO(v)->period = WEIGHT_PERIOD;
                    vcpu_schedule_unlock(lock, v);
                }
            }
            else
            {
                /* Weight-driven domains with real-time execution */
                for_each_vcpu ( p, v )
                {
                    spinlock_t *lock = vcpu_schedule_lock(v);

                    EDOM_INFO(v)->weight = op->u.sedf.weight;
                    vcpu_schedule_unlock(lock, v);
                }
            }
        }
        else
        {
            /*
             * Sanity checking: note that disabling extra weight requires
             * that we set a non-zero slice.
             */
            if ( (op->u.sedf.period > PERIOD_MAX) ||
                 (op->u.sedf.period < PERIOD_MIN) ||
                 (op->u.sedf.slice  > op->u.sedf.period) ||
                 (op->u.sedf.slice  < SLICE_MIN) )
            {
                rc = -EINVAL;
                goto out;
            }

            /* Time-driven domains */
            for_each_vcpu ( p, v )
            {
                spinlock_t *lock = vcpu_schedule_lock(v);

                EDOM_INFO(v)->weight = 0;
                EDOM_INFO(v)->extraweight = 0;
                EDOM_INFO(v)->period_orig = 
                    EDOM_INFO(v)->period  = op->u.sedf.period;
                EDOM_INFO(v)->slice_orig  = 
                    EDOM_INFO(v)->slice   = op->u.sedf.slice;
                vcpu_schedule_unlock(lock, v);
            }
        }

        rc = sedf_adjust_weights(p->cpupool, nr_cpus, sumw, sumt);
        if ( rc )
            goto out;

        for_each_vcpu ( p, v )
        {
            spinlock_t *lock = vcpu_schedule_lock(v);

            EDOM_INFO(v)->status  = 
                (EDOM_INFO(v)->status &
                 ~EXTRA_AWARE) | (op->u.sedf.extratime & EXTRA_AWARE);
            EDOM_INFO(v)->latency = op->u.sedf.latency;
            extraq_check(v);
            vcpu_schedule_unlock(lock, v);
        }
    }
    else if ( op->cmd == XEN_DOMCTL_SCHEDOP_getinfo )
    {
        if ( p->vcpu[0] == NULL )
        {
            rc = -EINVAL;
            goto out;
        }

        op->u.sedf.period    = EDOM_INFO(p->vcpu[0])->period;
        op->u.sedf.slice     = EDOM_INFO(p->vcpu[0])->slice;
        op->u.sedf.extratime = EDOM_INFO(p->vcpu[0])->status & EXTRA_AWARE;
        op->u.sedf.latency   = EDOM_INFO(p->vcpu[0])->latency;
        op->u.sedf.weight    = EDOM_INFO(p->vcpu[0])->weight;
    }

out:
    spin_unlock_irqrestore(&prv->lock, flags);

    xfree(sumt);
    xfree(sumw);

    return rc;
}

static struct sedf_priv_info _sedf_priv;

const struct scheduler sched_sedf_def = {
    .name           = "Simple EDF Scheduler",
    .opt_name       = "sedf",
    .sched_id       = XEN_SCHEDULER_SEDF,
    .sched_data     = &_sedf_priv,
    
    .init_domain    = sedf_init_domain,
    .destroy_domain = sedf_destroy_domain,

    .insert_vcpu    = sedf_insert_vcpu,

    .alloc_vdata    = sedf_alloc_vdata,
    .free_vdata     = sedf_free_vdata,
    .alloc_pdata    = sedf_alloc_pdata,
    .free_pdata     = sedf_free_pdata,
    .alloc_domdata  = sedf_alloc_domdata,
    .free_domdata   = sedf_free_domdata,

    .init           = sedf_init,
    .deinit         = sedf_deinit,

    .do_schedule    = sedf_do_schedule,
    .pick_cpu       = sedf_pick_cpu,
    .dump_cpu_state = sedf_dump_cpu_state,
    .sleep          = sedf_sleep,
    .wake           = sedf_wake,
    .adjust         = sedf_adjust,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
