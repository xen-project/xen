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

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/sched.h>
#include <xeno/delay.h>
#include <xeno/event.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>
#include <xeno/interrupt.h>
#include <xeno/timer.h>
#include <xeno/perfc.h>
#include <xeno/sched-if.h>
#include <xeno/slab.h>

/* all per-domain BVT-specific scheduling info is stored here */
struct bvt_dom_info
{
    unsigned long mcu_advance;      /* inverse of weight */
    u32           avt;              /* actual virtual time */
    u32           evt;              /* effective virtual time */
    int           warpback;         /* warp?  */
    long          warp;             /* virtual time warp */
    long          warpl;            /* warp limit */
    long          warpu;            /* unwarp time requirement */
    s_time_t      warped;           /* time it ran warped last time */
    s_time_t      uwarped;          /* time it ran unwarped last time */
};

struct bvt_cpu_info
{
    unsigned long svt; /* XXX check this is unsigned long! */
};


#define BVT_INFO(p)   ((struct bvt_dom_info *)(p)->sched_priv)
#define CPU_INFO(cpu) ((struct bvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

/* SLAB cache for struct bvt_dom_info objects */
static kmem_cache_t *dom_info_cache;

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
int bvt_alloc_task(struct task_struct *p)
{
    if ( (BVT_INFO(p) = kmem_cache_alloc(dom_info_cache,GFP_KERNEL)) == NULL )
        return -1;
    
    return 0;
}

/*
 * Add and remove a domain
 */
void bvt_add_task(struct task_struct *p) 
{
    struct bvt_dom_info *inf = BVT_INFO(p);

    ASSERT(inf != NULL);
    ASSERT(p   != NULL);

    inf->mcu_advance = MCU_ADVANCE;

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

/**
 * bvt_free_task - free BVT private structures for a task
 * @p:             task
 */
void bvt_free_task(struct task_struct *p)
{
    ASSERT( p->sched_priv != NULL );
    kmem_cache_free( dom_info_cache, p->sched_priv );
}


void bvt_wake_up(struct task_struct *p)
{
    struct bvt_dom_info *inf = BVT_INFO(p);

    ASSERT(inf != NULL);

    /* set the BVT parameters */
    if (inf->avt < CPU_SVT(p->processor))
        inf->avt = CPU_SVT(p->processor);

    /* deal with warping here */
    inf->warpback  = 1;
    inf->warped    = NOW();
    __calc_evt(inf);
    __add_to_runqueue_head(p);
}

/* 
 * Block the currently-executing domain until a pertinent event occurs.
 */
static long bvt_do_block(struct task_struct *p)
{
    BVT_INFO(p)->warpback = 0; 
    return 0;
}

/* Control the scheduler. */
int bvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct bvt_ctl *params = &cmd->u.bvt;
    
    ctx_allow = params->ctx_allow;

    return 0;
}

/* Adjust scheduling parameter for a given domain. */
int bvt_adjdom(struct task_struct *p,
               struct sched_adjdom_cmd *cmd)
{
    struct bvt_adjdom *params = &cmd->u.bvt;
    unsigned long mcu_adv = params->mcu_adv,
                    warp  = params->warp,
                    warpl = params->warpl,
                    warpu = params->warpu;
    
    struct bvt_dom_info *inf = BVT_INFO(p);

    /* Sanity -- this can avoid divide-by-zero. */
    if ( mcu_adv == 0 )
        return -EINVAL;

    spin_lock_irq(&schedule_lock[p->processor]);   
    inf->mcu_advance = mcu_adv;
    inf->warp = warp;
    inf->warpl = warpl;
    inf->warpu = warpu;
    spin_unlock_irq(&schedule_lock[p->processor]); 

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
    struct task_struct *prev = current, *next = NULL, *next_prime, *p;
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

    if ( likely(!is_idle_task(prev)) ) 
    {
        ranfor = (s32)(now - prev->lastschd);
        /* Calculate mcu and update avt. */
        mcus = (ranfor + MCU - 1) / MCU;
        prev_inf->avt += mcus * prev_inf->mcu_advance;
        
        __calc_evt(prev_inf);
        
        __del_from_runqueue(prev);
        
        if ( likely(prev->state == TASK_RUNNING) )
            __add_to_runqueue_tail(prev);
    }

    /* We should at least have the idle task */
    ASSERT(!list_empty(&schedule_data[cpu].runqueue));

    /*
     * scan through the run queue and pick the task with the lowest evt
     * *and* the task the second lowest evt.
     * this code is O(n) but we expect n to be small.
     */
    next       = schedule_data[cpu].idle;
    next_prime = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each ( tmp, &schedule_data[cpu].runqueue )
    {
        p     = list_entry(tmp, struct task_struct, run_list);
        p_inf = BVT_INFO(p);

        if ( p_inf->evt < next_evt )
        {
            next_prime     = next;
            next_prime_evt = next_evt;
            next = p;
            next_evt = p_inf->evt;
        } 
        else if ( next_prime_evt == ~0U )
        {
            next_prime_evt = p_inf->evt;
            next_prime     = p;
        } 
        else if ( p_inf->evt < next_prime_evt )
        {
            next_prime_evt = p_inf->evt;
            next_prime     = p;
        }

        /* Determine system virtual time. */
        if ( p_inf->avt < min_avt )
            min_avt = p_inf->avt;
    }

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

    next_prime_inf = BVT_INFO(next_prime);
    next_inf       = BVT_INFO(next);

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


static void bvt_dump_runq_el(struct task_struct *p)
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
    printk("svt=0x%08lX ", CPU_SVT(i));
}


/* Initialise the data structures. */
int bvt_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
    {
        CPU_INFO(i) = kmalloc(sizeof(struct bvt_cpu_info), GFP_KERNEL);

        if ( CPU_INFO(i) == NULL )
        {
            printk("Failed to allocate BVT scheduler per-CPU memory!\n");
            return -1;
        }

        CPU_SVT(i) = 0; /* XXX do I really need to do this? */
    }

    dom_info_cache = kmem_cache_create("BVT dom info",
                                       sizeof(struct bvt_dom_info),
                                       0, 0, NULL, NULL);

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
    .alloc_task     = bvt_alloc_task,
    .add_task       = bvt_add_task,
    .free_task      = bvt_free_task,
    .wake_up        = bvt_wake_up,
    .do_block       = bvt_do_block,
    .do_schedule    = bvt_do_schedule,
    .control        = bvt_ctl,
    .adjdom         = bvt_adjdom,
    .dump_settings  = bvt_dump_settings,
    .dump_cpu_state = bvt_dump_cpu_state,
    .dump_runq_el   = bvt_dump_runq_el,
};

