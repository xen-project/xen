/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002-2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2002-2003 University of Cambridge
 * (C) 2004      - Mark Williamson - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: common/schedule.c
 *      Author: Rolf Neugebauer & Keir Fraser
 *              Updated for generic API by Mark Williamson
 *
 * Description: CPU scheduling
 *              implements A Borrowed Virtual Time scheduler.
 *              (see Duda & Cheriton SOSP'99)
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/slab.h>
#include <xen/softirq.h>

/* all per-domain BVT-specific scheduling info is stored here */
struct bvt_dom_info
{
    struct domain       *domain;          /* domain this info belongs to */
    struct list_head    run_list;         /* runqueue list pointers */
    unsigned long       mcu_advance;      /* inverse of weight */
    u32                 avt;              /* actual virtual time */
    u32                 evt;              /* effective virtual time */
    int                 warpback;         /* warp?  */
    long                warp;             /* virtual time warp */
    long                warpl;            /* warp limit */
    long                warpu;            /* unwarp time requirement */
    s_time_t            warped;           /* time it ran warped last time */
    s_time_t            uwarped;          /* time it ran unwarped last time */
};

struct bvt_cpu_info
{
    spinlock_t          run_lock;   /* protects runqueue */
    struct list_head    runqueue;   /* runqueue for given processor */ 
    unsigned long       svt;        /* XXX check this is unsigned long! */
};


#define BVT_INFO(p)   ((struct bvt_dom_info *)(p)->sched_priv)
#define CPU_INFO(cpu) ((struct bvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define RUNLIST(p)    ((struct list_head *)&(BVT_INFO(p)->run_list))
#define RUNQUEUE(cpu) ((struct list_head *)&(CPU_INFO(cpu)->runqueue))
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

/* SLAB cache for struct bvt_dom_info objects */
static xmem_cache_t *dom_info_cache;

/*
 * Wrappers for run-queue management. Must be called with the run_lock
 * held.
 */
static inline void __add_to_runqueue_head(struct domain *d)
{
    list_add(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __add_to_runqueue_tail(struct domain *d)
{
    list_add_tail(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __del_from_runqueue(struct domain *d)
{
    struct list_head *runlist = RUNLIST(d);
    list_del(runlist);
    runlist->next = NULL;
}

static inline int __task_on_runqueue(struct domain *d)
{
    return (RUNLIST(d))->next != NULL;
}

/*
 * Calculate the effective virtual time for a domain. Take into account 
 * warping limits
 */
static void __calc_evt(struct bvt_dom_info *inf)
{
    s_time_t now = NOW();

    if ( inf->warpback ) 
    {
        if ( ((now - inf->warped) < inf->warpl) &&
             ((now - inf->uwarped) > inf->warpu) )
        {
            /* allowed to warp */
            inf->evt = inf->avt - inf->warp;
        } 
        else 
        {
            /* warped for too long -> unwarp */
            inf->evt      = inf->avt;
            inf->uwarped  = now;
            inf->warpback = 0;
        }
    } 
    else 
    {
        inf->evt = inf->avt;
    }
}

/**
 * bvt_alloc_task - allocate BVT private structures for a task
 * @p:              task to allocate private structures for
 *
 * Returns non-zero on failure.
 */
int bvt_alloc_task(struct domain *p)
{
    p->sched_priv = xmem_cache_alloc(dom_info_cache);
    if ( p->sched_priv == NULL )
        return -1;
    
    return 0;
}

/*
 * Add and remove a domain
 */
void bvt_add_task(struct domain *p) 
{
    struct bvt_dom_info *inf = BVT_INFO(p);
    ASSERT(inf != NULL);
    ASSERT(p   != NULL);

    inf->mcu_advance = MCU_ADVANCE;
    inf->domain = p;
    
    if ( p->domain == IDLE_DOMAIN_ID )
    {
        inf->avt = inf->evt = ~0U;
    } 
    else 
    {
        /* Set avt and evt to system virtual time. */
        inf->avt         = CPU_SVT(p->processor);
        inf->evt         = CPU_SVT(p->processor);
        /* Set some default values here. */
        inf->warpback    = 0;
        inf->warp        = 0;
        inf->warpl       = 0;
        inf->warpu       = 0;
    }

    return;
}

int bvt_init_idle_task(struct domain *p)
{
    unsigned long flags;

    if(bvt_alloc_task(p) < 0) return -1;

    bvt_add_task(p);

    spin_lock_irqsave(&CPU_INFO(p->processor)->run_lock, flags);
    
    set_bit(DF_RUNNING, &p->flags);
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);
        
    spin_unlock_irqrestore(&CPU_INFO(p->processor)->run_lock, flags);

    return 0;
}

void bvt_wake(struct domain *d)
{
    unsigned long       flags;
    struct bvt_dom_info *inf = BVT_INFO(d);
    struct domain       *curr;
    s_time_t            now, min_time;
    int                 cpu = d->processor;

    /* The runqueue accesses must be protected */
    spin_lock_irqsave(&CPU_INFO(cpu)->run_lock, flags);
    
    /* If on the runqueue already then someone has done the wakeup work. */
    if ( unlikely(__task_on_runqueue(d)) )
    {
        spin_unlock_irqrestore(&CPU_INFO(cpu)->run_lock, flags);
        return;
    }

    __add_to_runqueue_head(d);

    now = NOW();

    /* Set the BVT parameters. AVT should always be updated 
        if CPU migration ocurred.*/
    if ( inf->avt < CPU_SVT(cpu) || 
            unlikely(test_bit(DF_MIGRATED, &d->flags)) )
        inf->avt = CPU_SVT(cpu);

    /* Deal with warping here. */
    inf->warpback  = 1;
    inf->warped    = now;
    __calc_evt(inf);
    spin_unlock_irqrestore(&CPU_INFO(cpu)->run_lock, flags);
    
    /* Access to schedule_data protected by schedule_lock */
    spin_lock_irqsave(&schedule_data[cpu].schedule_lock, flags);
    
    curr = schedule_data[cpu].curr;

    /* Currently-running domain should run at least for ctx_allow. */
    min_time = curr->lastschd + curr->min_slice;

    spin_unlock_irqrestore(&schedule_data[cpu].schedule_lock, flags);   
    if ( is_idle_task(curr) || (min_time <= now) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    else if ( schedule_data[cpu].s_timer.expires > (min_time + TIME_SLOP) )
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);

}


static void bvt_sleep(struct domain *d)
{
    unsigned long flags;
    
    if ( test_bit(DF_RUNNING, &d->flags) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    else 
    {
        /* The runqueue accesses must be protected */
        spin_lock_irqsave(&CPU_INFO(d->processor)->run_lock, flags);
        
        
        if ( __task_on_runqueue(d) )
            __del_from_runqueue(d);

        spin_unlock_irqrestore(&CPU_INFO(d->processor)->run_lock, flags);    
    }
}

/**
 * bvt_free_task - free BVT private structures for a task
 * @p:             task
 */
void bvt_free_task(struct domain *p)
{
    ASSERT( p->sched_priv != NULL );
    xmem_cache_free( dom_info_cache, p->sched_priv );
}


/* 
 * Block the currently-executing domain until a pertinent event occurs.
 */
static void bvt_do_block(struct domain *p)
{
    BVT_INFO(p)->warpback = 0; 
}

/* Control the scheduler. */
int bvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct bvt_ctl *params = &cmd->u.bvt;

    if ( cmd->direction == SCHED_INFO_PUT )
    { 
        ctx_allow = params->ctx_allow;
    }
    else
    {
        params->ctx_allow = ctx_allow;
    }
    
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
int bvt_adjdom(struct domain *p,
               struct sched_adjdom_cmd *cmd)
{
    struct bvt_adjdom *params = &cmd->u.bvt;
    unsigned long flags;

    if ( cmd->direction == SCHED_INFO_PUT )
    {
        unsigned long mcu_adv = params->mcu_adv,
            warp  = params->warp,
            warpl = params->warpl,
            warpu = params->warpu;
        
        struct bvt_dom_info *inf = BVT_INFO(p);
        
        DPRINTK("Get domain %u bvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );

        /* Sanity -- this can avoid divide-by-zero. */
        if ( mcu_adv == 0 )
            return -EINVAL;
        
        spin_lock_irqsave(&CPU_INFO(p->processor)->run_lock, flags);   
        inf->mcu_advance = mcu_adv;
        inf->warp = warp;
        inf->warpl = warpl;
        inf->warpu = warpu;

        DPRINTK("Set domain %u bvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );

        spin_unlock_irqrestore(&CPU_INFO(p->processor)->run_lock, flags);
    }
    else if ( cmd->direction == SCHED_INFO_GET )
    {
        struct bvt_dom_info *inf = BVT_INFO(p);

        spin_lock_irqsave(&CPU_INFO(p->processor)->run_lock, flags);   
        params->mcu_adv = inf->mcu_advance;
        params->warp    = inf->warp;
        params->warpl   = inf->warpl;
        params->warpu   = inf->warpu;
        spin_unlock_irqrestore(&CPU_INFO(p->processor)->run_lock, flags);
    }
    
    return 0;
}


/* 
 * The main function
 * - deschedule the current domain.
 * - pick a new domain.
 *   i.e., the domain with lowest EVT.
 *   The runqueue should be ordered by EVT so that is easy.
 */
static task_slice_t bvt_do_schedule(s_time_t now)
{
    unsigned long flags;
    struct domain *prev = current, *next = NULL, *next_prime, *p; 
    struct list_head   *tmp;
    int                 cpu = prev->processor;
    s32                 r_time;     /* time for new dom to run */
    s32                 ranfor;     /* assume we never run longer than 2.1s! */
    s32                 mcus;
    u32                 next_evt, next_prime_evt, min_avt;
    struct bvt_dom_info *prev_inf       = BVT_INFO(prev),
                        *p_inf          = NULL,
                        *next_inf       = NULL,
                        *next_prime_inf = NULL;
    task_slice_t        ret;


    ASSERT(prev->sched_priv != NULL);
    ASSERT(prev_inf != NULL);
    spin_lock_irqsave(&CPU_INFO(cpu)->run_lock, flags);

    ASSERT(__task_on_runqueue(prev));

    if ( likely(!is_idle_task(prev)) ) 
    {
        ranfor = (s32)(now - prev->lastschd);
        /* Calculate mcu and update avt. */
        mcus = (ranfor + MCU - 1) / MCU;
        prev_inf->avt += mcus * prev_inf->mcu_advance;
        
        __calc_evt(prev_inf);
        
        __del_from_runqueue(prev);
        
        if ( domain_runnable(prev) )
            __add_to_runqueue_tail(prev);
    }

 
    /* We should at least have the idle task */
    ASSERT(!list_empty(RUNQUEUE(cpu)));

    /*
     * scan through the run queue and pick the task with the lowest evt
     * *and* the task the second lowest evt.
     * this code is O(n) but we expect n to be small.
     */
    next_inf        = BVT_INFO(schedule_data[cpu].idle);
    next_prime_inf  = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each ( tmp, RUNQUEUE(cpu) )
    {
        p_inf = list_entry(tmp, struct bvt_dom_info, run_list);

        if ( p_inf->evt < next_evt )
        {
            next_prime_inf  = next_inf;
            next_prime_evt  = next_evt;
            next_inf        = p_inf;
            next_evt        = p_inf->evt;
        } 
        else if ( next_prime_evt == ~0U )
        {
            next_prime_evt  = p_inf->evt;
            next_prime_inf  = p_inf;
        } 
        else if ( p_inf->evt < next_prime_evt )
        {
            next_prime_evt  = p_inf->evt;
            next_prime_inf  = p_inf;
        }

        /* Determine system virtual time. */
        if ( p_inf->avt < min_avt )
            min_avt = p_inf->avt;
    }
    
    spin_unlock_irqrestore(&CPU_INFO(cpu)->run_lock, flags);
 
    /* Extract the domain pointers from the dom infos */
    next        = next_inf->domain;
    next_prime  = next_prime_inf->domain;
    
    /* Update system virtual time. */
    if ( min_avt != ~0U )
        CPU_SVT(cpu) = min_avt;

    /* check for virtual time overrun on this cpu */
    if ( CPU_SVT(cpu) >= 0xf0000000 )
    {
        u_long t_flags;
        
        write_lock_irqsave(&tasklist_lock, t_flags); 
        
        for_each_domain ( p )
        {
            if ( p->processor == cpu )
            {
                p_inf = BVT_INFO(p);
                p_inf->evt -= 0xe0000000;
                p_inf->avt -= 0xe0000000;
            }
        } 
        
        write_unlock_irqrestore(&tasklist_lock, t_flags); 
        
        CPU_SVT(cpu) -= 0xe0000000;
    }

    /* work out time for next run through scheduler */
    if ( is_idle_task(next) ) 
    {
        r_time = ctx_allow;
        goto sched_done;
    }

    if ( (next_prime == NULL) || is_idle_task(next_prime) )
    {
        /* We have only one runnable task besides the idle task. */
        r_time = 10 * ctx_allow;     /* RN: random constant */
        goto sched_done;
    }

    /*
     * If we are here then we have two runnable tasks.
     * Work out how long 'next' can run till its evt is greater than
     * 'next_prime's evt. Take context switch allowance into account.
     */
    ASSERT(next_prime_inf->evt >= next_inf->evt);
    
    r_time = ((next_prime_inf->evt - next_inf->evt)/next_inf->mcu_advance)
        + ctx_allow;

    ASSERT(r_time >= ctx_allow);

 sched_done:
    next->min_slice = ctx_allow;
    ret.task = next;
    ret.time = r_time;
    return ret;
}


static void bvt_dump_runq_el(struct domain *p)
{
    struct bvt_dom_info *inf = BVT_INFO(p);
    
    printk("mcua=0x%04lX ev=0x%08X av=0x%08X ",
           inf->mcu_advance, inf->evt, inf->avt);
}

static void bvt_dump_settings(void)
{
    printk("BVT: mcu=0x%08Xns ctx_allow=0x%08Xns ", (u32)MCU, (s32)ctx_allow );
}

static void bvt_dump_cpu_state(int i)
{
    unsigned long flags;
    struct list_head *list, *queue;
    int loop = 0;
    struct bvt_dom_info *d_inf;
    struct domain *d;
    
    spin_lock_irqsave(&CPU_INFO(i)->run_lock, flags);
    printk("svt=0x%08lX ", CPU_SVT(i));

    queue = RUNQUEUE(i);
    printk("QUEUE rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
        (unsigned long) queue->next, (unsigned long) queue->prev);

    list_for_each ( list, queue )
    {
        d_inf = list_entry(list, struct bvt_dom_info, run_list);
        d = d_inf->domain;
        printk("%3d: %u has=%c ", loop++, d->domain,
              test_bit(DF_RUNNING, &d->flags) ? 'T':'F');
        bvt_dump_runq_el(d);
        printk("c=0x%X%08X\n", (u32)(d->cpu_time>>32), (u32)d->cpu_time);
        printk("         l: %lx n: %lx  p: %lx\n",
            (unsigned long)list, (unsigned long)list->next,
            (unsigned long)list->prev);
    }
    spin_unlock_irqrestore(&CPU_INFO(i)->run_lock, flags);        
}

/* We use cache to create the bvt_dom_infos 
   this functions makes sure that the run_list
   is initialised properly. The new domain needs
   NOT to appear as to be on the runqueue */
static void cache_constructor(void *arg1, xmem_cache_t *arg2, unsigned long arg3)
{
    struct bvt_dom_info *dom_inf = (struct bvt_dom_info*)arg1;
    dom_inf->run_list.next = NULL;
    dom_inf->run_list.prev = NULL;
}

/* Initialise the data structures. */
int bvt_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
    {
        schedule_data[i].sched_priv = xmalloc(sizeof(struct bvt_cpu_info));
       
        if ( schedule_data[i].sched_priv == NULL )
        {
            printk("Failed to allocate BVT scheduler per-CPU memory!\n");
            return -1;
        }

        INIT_LIST_HEAD(RUNQUEUE(i));
        spin_lock_init(&CPU_INFO(i)->run_lock);
        
        CPU_SVT(i) = 0; /* XXX do I really need to do this? */
    }

    dom_info_cache = xmem_cache_create("BVT dom info",
                                       sizeof(struct bvt_dom_info),
                                       0, 0, cache_constructor, NULL);

    if ( dom_info_cache == NULL )
    {
        printk("BVT: Failed to allocate domain info SLAB cache");
        return -1;
    }

    return 0;
}



struct scheduler sched_bvt_def = {
    .name     = "Borrowed Virtual Time",
    .opt_name = "bvt",
    .sched_id = SCHED_BVT,
    
    .init_scheduler = bvt_init_scheduler,
    .init_idle_task = bvt_init_idle_task,
    .alloc_task     = bvt_alloc_task,
    .add_task       = bvt_add_task,
    .free_task      = bvt_free_task,
    .do_block       = bvt_do_block,
    .do_schedule    = bvt_do_schedule,
    .control        = bvt_ctl,
    .adjdom         = bvt_adjdom,
    .dump_settings  = bvt_dump_settings,
    .dump_cpu_state = bvt_dump_cpu_state,
    .sleep          = bvt_sleep,
    .wake           = bvt_wake,
};

