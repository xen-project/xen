/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004      Grzegorz Milos - University of Cambridge
 * Based on the implementation of the BVT scheduler by Rolf Neugebauer
 * and Mark Williamson (look in sched_bvt.c)
 ****************************************************************************
 *
 *        File: common/sched_fair_bvt.c
 *      Author: Grzegorz Milos
 *
 * Description: CPU scheduling
 *              implements Fair Borrowed Virtual Time Scheduler.
 *              FBVT is modification of BVT (see Duda & Cheriton SOSP'99)
 *              which tries to allocate fair shares of processor even 
 *              when there is mix between CPU and I/O bound domains.
 *              TODO - more information about the scheduler in TODO
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
#include <xen/trace.h>

/* For tracing - TODO - put all the defines in some common hearder file */
#define TRC_SCHED_FBVT_DO_SCHED             0x00020000
#define TRC_SCHED_FBVT_DO_SCHED_UPDATE      0x00020001

/* all per-domain BVT-specific scheduling info is stored here */
struct fbvt_dom_info
{
    struct domain       *domain;          /* domain this info belongs to */
    struct list_head    run_list;         /* runqueue pointers */
    unsigned long       mcu_advance;      /* inverse of weight */
    u32                 avt;              /* actual virtual time */
    u32                 evt;              /* effective virtual time */
    u32                 time_slept;       /* amount of time slept */
    int                 warpback;         /* warp?  */
    long                warp;             /* virtual time warp */
    long                warpl;            /* warp limit */
    long                warpu;            /* unwarp time requirement */
    s_time_t            warped;           /* time it ran warped last time */
    s_time_t            uwarped;          /* time it ran unwarped last time */
};

struct fbvt_cpu_info
{
    struct list_head    runqueue;
    unsigned long       svt;
    u32                 vtb;       /* virtual time bonus */
    u32                 r_time;    /* last time to run */  
};


#define FBVT_INFO(p)  ((struct fbvt_dom_info *)(p)->sched_priv)
#define CPU_INFO(cpu) ((struct fbvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define RUNLIST(p)    ((struct list_head *)&(FBVT_INFO(p)->run_list))
#define RUNQUEUE(cpu) ((struct list_head *)&(CPU_INFO(cpu)->runqueue))
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)
#define LAST_VTB(cpu) (CPU_INFO(cpu)->vtb)
#define R_TIME(cpu)   (CPU_INFO(cpu)->r_time) 

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */
static s32 max_vtb   = (s32)MILLISECS(5);

static xmem_cache_t *dom_info_cache;

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
static void __calc_evt(struct fbvt_dom_info *inf)
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
 * fbvt_alloc_task - allocate FBVT private structures for a task
 * @p:              task to allocate private structures for
 *
 * Returns non-zero on failure.
 */
int fbvt_alloc_task(struct domain *d)
{
    if ( (d->sched_priv = xmem_cache_alloc(dom_info_cache)) == NULL )
        return -1;
    memset(d->sched_priv, 0, sizeof(struct fbvt_dom_info));
    return 0;
}

/*
 * Add and remove a domain
 */
void fbvt_add_task(struct domain *p) 
{
    struct fbvt_dom_info *inf = FBVT_INFO(p);

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
        inf->time_slept  = 0;
        inf->warpback    = 0;
        inf->warp        = 0;
        inf->warpl       = 0;
        inf->warpu       = 0;
    }

    return;
}

int fbvt_init_idle_task(struct domain *p)
{
    if ( fbvt_alloc_task(p) < 0 )
        return -1;

    fbvt_add_task(p);

    set_bit(DF_RUNNING, &p->flags);
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);

    return 0;
}
                                        
static void fbvt_wake(struct domain *d)
{
    struct fbvt_dom_info *inf = FBVT_INFO(d);
    struct domain        *curr;
    s_time_t             now, min_time;
    int                  cpu = d->processor;
    s32                  io_warp;

    if ( unlikely(__task_on_runqueue(d)) )
        return;

    __add_to_runqueue_head(d);
 
    now = NOW();

    /* Set the BVT parameters. */
    if ( inf->avt < CPU_SVT(cpu) )
    {
        /*
         * We want IO bound processes to gain dispatch precedence. It is 
         * especially for device driver domains. Therefore AVT 
         * not be updated to SVT but to a value marginally smaller.
         * Since frequently sleeping domains have high time_slept
         * values, the virtual time can be determined as:
         * SVT - const * TIME_SLEPT
         */
        io_warp = inf->time_slept/2;
        if ( io_warp > 1000 )
            io_warp = 1000;

        ASSERT(inf->time_slept + CPU_SVT(cpu) > inf->avt + io_warp);
        inf->time_slept += CPU_SVT(cpu) - inf->avt - io_warp;
        inf->avt = CPU_SVT(cpu) - io_warp;
    }

    /* Deal with warping here. */
    inf->warpback  = 1;
    inf->warped    = now;
    __calc_evt(inf);
 
    curr = schedule_data[cpu].curr;
 
    /* Currently-running domain should run at least for ctx_allow. */
    min_time = curr->lastschd + ctx_allow;
    
    if ( is_idle_task(curr) || (min_time <= now) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    else if ( schedule_data[cpu].s_timer.expires > (min_time + TIME_SLOP) )
        mod_ac_timer(&schedule_data[cpu].s_timer, min_time);
}


static void fbvt_sleep(struct domain *d)
{
    if ( test_bit(DF_RUNNING, &d->flags) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    else if ( __task_on_runqueue(d) )
        __del_from_runqueue(d);
}


/**
 * fbvt_free_task - free FBVT private structures for a task
 * @d:             task
 */
void fbvt_free_task(struct domain *d)
{
    ASSERT(d->sched_priv != NULL);
    xmem_cache_free(dom_info_cache, d->sched_priv);
}

/* 
 * Block the currently-executing domain until a pertinent event occurs.
 */
static void fbvt_do_block(struct domain *d)
{
    FBVT_INFO(d)->warpback = 0; 
}

/* Control the scheduler. */
int fbvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct fbvt_ctl *params = &cmd->u.fbvt;

    if ( cmd->direction == SCHED_INFO_PUT )
    { 
        ctx_allow = params->ctx_allow;
        /* The max_vtb should be of the order o the ctx_allow */
        max_vtb = ctx_allow;
    }
    else
    {
        params->ctx_allow = ctx_allow;
    }
    
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
int fbvt_adjdom(struct domain *p,
                struct sched_adjdom_cmd *cmd)
{
    struct fbvt_adjdom *params = &cmd->u.fbvt;

    if ( cmd->direction == SCHED_INFO_PUT )
    {
        unsigned long mcu_adv = params->mcu_adv,
            warp  = params->warp,
            warpl = params->warpl,
            warpu = params->warpu;
        
        struct fbvt_dom_info *inf = FBVT_INFO(p);
        
        DPRINTK("Get domain %u fbvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );

        /* Sanity -- this can avoid divide-by-zero. */
        if ( mcu_adv == 0 )
            return -EINVAL;
        
        inf->mcu_advance = mcu_adv;
        inf->warp = warp;
        inf->warpl = warpl;
        inf->warpu = warpu;

        DPRINTK("Set domain %u fbvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );
    }
    else if ( cmd->direction == SCHED_INFO_GET )
    {
        struct fbvt_dom_info *inf = FBVT_INFO(p);
        params->mcu_adv = inf->mcu_advance;
        params->warp    = inf->warp;
        params->warpl   = inf->warpl;
        params->warpu   = inf->warpu;
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
static task_slice_t fbvt_do_schedule(s_time_t now)
{
    struct domain *prev = current, *next = NULL, *next_prime, *p;
    struct list_head   *tmp;
    int                 cpu = prev->processor;
    s32                 r_time;     /* time for new dom to run */
    s32                 ranfor;     /* assume we never run longer than 2.1s! */
    s32                 mcus;
    u32                 next_evt, next_prime_evt, min_avt;
    u32                 sl_decrement;
    struct fbvt_dom_info *prev_inf       = FBVT_INFO(prev);
    struct fbvt_dom_info *p_inf          = NULL;
    struct fbvt_dom_info *next_inf       = NULL;
    struct fbvt_dom_info *next_prime_inf = NULL;
    task_slice_t        ret;

    ASSERT(prev->sched_priv != NULL);
    ASSERT(prev_inf != NULL);
    ASSERT(__task_on_runqueue(prev));

    if ( likely(!is_idle_task(prev)) ) 
    {
        ranfor = (s32)(now - prev->lastschd);
        /* Calculate mcu and update avt. */
        mcus = (ranfor + MCU - 1) / MCU;
        
        TRACE_3D(TRC_SCHED_FBVT_DO_SCHED_UPDATE, prev->domain, 
                 mcus, LAST_VTB(cpu));
    
        sl_decrement = mcus * LAST_VTB(cpu) / R_TIME(cpu);
        prev_inf->time_slept -=  sl_decrement;
        prev_inf->avt += mcus * prev_inf->mcu_advance - sl_decrement;
  
        /*if(mcus * prev_inf->mcu_advance < LAST_VTB(cpu))
          {
          ASSERT(prev_inf->time_slept >= mcus * prev_inf->mcu_advance);
          prev_inf->time_slept -= mcus * prev_inf->mcu_advance;
          }
          else
          {
          prev_inf->avt += mcus * prev_inf->mcu_advance - LAST_VTB(cpu);
  
          ASSERT(prev_inf->time_slept >= LAST_VTB(cpu));
          prev_inf->time_slept -= LAST_VTB(cpu);
          }*/
        
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
    next_inf        = FBVT_INFO(schedule_data[cpu].idle);
    next_prime_inf  = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each ( tmp, RUNQUEUE(cpu) )
    {
        p_inf = list_entry(tmp, struct fbvt_dom_info, run_list);

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

    /* Extract the domain pointers from the dom infos */
    next        = next_inf->domain;
    next_prime  = next_prime_inf->domain;
     

    /* Update system virtual time. */
    if ( min_avt != ~0U )
        CPU_SVT(cpu) = min_avt;

    /* check for virtual time overrun on this cpu */
    if ( CPU_SVT(cpu) >= 0xf0000000 )
    {
        ASSERT(!local_irq_is_enabled());

        write_lock(&tasklist_lock);

        for_each_domain ( p )
        {
            if ( p->processor == cpu )
            {
                p_inf = FBVT_INFO(p);
                p_inf->evt -= 0xe0000000;
                p_inf->avt -= 0xe0000000;
            }
        } 

        write_unlock(&tasklist_lock);

        CPU_SVT(cpu) -= 0xe0000000;
    }

    /* check for time_slept overrun for the domain we schedule to run*/
    if(next_inf->time_slept >= 0xf0000000)
    {
        printk("Domain %d is assigned more CPU then it is able to use.\n"
               "FBVT slept_time=%d, halving. Mcu_advance=%ld\n",next->domain, 
               next_inf->time_slept, next_inf->mcu_advance);

        next_inf->time_slept /= 2;
    }


    /*
     * In here we decide on Virtual Time Bonus. The idea is, for the
     * domains that have large time_slept values to be allowed to run
     * for longer. Thus regaining the share of CPU originally allocated.
     * This is acompanied by the warp mechanism (which moves IO-bound
     * domains earlier in virtual time). Together this should give quite
     * good control both for CPU and IO-bound domains.
     */
    LAST_VTB(cpu) = next_inf->time_slept/5;
    if(LAST_VTB(cpu) / next_inf->mcu_advance > max_vtb / MCU) 
        LAST_VTB(cpu) = max_vtb * next_inf->mcu_advance / MCU;


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
  
    ASSERT(LAST_VTB(cpu) >= 0);

    r_time = MCU * ((next_prime_inf->evt + LAST_VTB(cpu) - next_inf->evt)/next_inf->mcu_advance)
        + ctx_allow;

    ASSERT(r_time >= ctx_allow);

 sched_done:
    R_TIME(cpu) = r_time / MCU;
    TRACE_3D(TRC_SCHED_FBVT_DO_SCHED, next->domain, r_time, LAST_VTB(cpu));
    ret.task = next;
    ret.time = r_time;
    return ret;
}


static void fbvt_dump_runq_el(struct domain *p)
{
    struct fbvt_dom_info *inf = FBVT_INFO(p);

    printk("mcua=0x%04lX ev=0x%08X av=0x%08X ",
           inf->mcu_advance, inf->evt, inf->avt);
}

static void fbvt_dump_settings(void)
{
    printk("BVT: mcu=0x%08Xns ctx_allow=0x%08Xns ", (u32)MCU, (s32)ctx_allow );
}

static void fbvt_dump_cpu_state(int i)
{
    struct list_head *list, *queue;
    int loop = 0;
    struct fbvt_dom_info *d_inf;
    struct domain *d;

    printk("svt=0x%08lX ", CPU_SVT(i));

    queue = RUNQUEUE(i);
    printk("QUEUE rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
        (unsigned long) queue->next, (unsigned long) queue->prev);

    list_for_each ( list, queue )
    {
        d_inf = list_entry(list, struct fbvt_dom_info, run_list);
        d = d_inf->domain;
        printk("%3d: %u has=%c ", loop++, d->domain,
              test_bit(DF_RUNNING, &d->flags) ? 'T':'F');
        fbvt_dump_runq_el(d);
        printk("c=0x%X%08X\n", (u32)(d->cpu_time>>32), (u32)d->cpu_time);
        printk("         l: %lx n: %lx  p: %lx\n",
            (unsigned long)list, (unsigned long)list->next,
            (unsigned long)list->prev);
    }
}

/* Initialise the data structures. */
int fbvt_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
    {
        schedule_data[i].sched_priv = xmalloc(sizeof(struct fbvt_cpu_info));
        
        if ( schedule_data[i].sched_priv == NULL )
        {
            printk("Failed to allocate FBVT scheduler per-CPU memory!\n");
            return -1;
        }

        INIT_LIST_HEAD(RUNQUEUE(i));
 
        CPU_SVT(i) = 0; /* XXX do I really need to do this? */
    }

    dom_info_cache = xmem_cache_create(
        "FBVT dom info", sizeof(struct fbvt_dom_info), 0, 0, NULL, NULL);
    if ( dom_info_cache == NULL )
    {
        printk("FBVT: Failed to allocate domain info SLAB cache");
        return -1;
    }

    return 0;
}
 

struct scheduler sched_fbvt_def = {
    .name     = "Fair Borrowed Virtual Time",
    .opt_name = "fbvt",
    .sched_id = SCHED_FBVT,
    
    .init_scheduler = fbvt_init_scheduler,
    .init_idle_task = fbvt_init_idle_task,
    .alloc_task     = fbvt_alloc_task,
    .add_task       = fbvt_add_task,
    .free_task      = fbvt_free_task,
    .do_block       = fbvt_do_block,
    .do_schedule    = fbvt_do_schedule,
    .control        = fbvt_ctl,
    .adjdom         = fbvt_adjdom,
    .dump_settings  = fbvt_dump_settings,
    .dump_cpu_state = fbvt_dump_cpu_state,
    .sleep          = fbvt_sleep,
    .wake           = fbvt_wake,
};

