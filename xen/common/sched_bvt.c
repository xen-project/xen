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
struct bvt_edom_info
{
    struct list_head    run_list;         /* runqueue list pointers */
    u32                 avt;              /* actual virtual time */
    u32                 evt;              /* effective virtual time */
    struct exec_domain  *exec_domain;
    struct bvt_dom_info *inf;
};

struct bvt_dom_info
{
    struct domain       *domain;          /* domain this info belongs to */
    u32                 mcu_advance;      /* inverse of weight */
    int                 warpback;         /* warp?  */
    int                 warp;             /* warp set and within the warp 
                                             limits*/
    s32                 warp_value;       /* virtual time warp */
    s_time_t            warpl;            /* warp limit */
    struct ac_timer     warp_timer;       /* deals with warpl */
    s_time_t            warpu;            /* unwarp time requirement */
    struct ac_timer     unwarp_timer;     /* deals with warpu */

    struct bvt_edom_info ed_inf[MAX_VIRT_CPUS];
};

struct bvt_cpu_info
{
    struct list_head    runqueue;
    unsigned long       svt;
};

#define BVT_INFO(p)   ((struct bvt_dom_info *)(p)->sched_priv)
#define EBVT_INFO(p)  ((struct bvt_edom_info *)(p)->ed_sched_priv)
#define CPU_INFO(cpu) ((struct bvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define RUNLIST(p)    ((struct list_head *)&(EBVT_INFO(p)->run_list))
#define RUNQUEUE(cpu) ((struct list_head *)&(CPU_INFO(cpu)->runqueue))
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

static inline void __add_to_runqueue_head(struct exec_domain *d)
{
    list_add(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __add_to_runqueue_tail(struct exec_domain *d)
{
    list_add_tail(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __del_from_runqueue(struct exec_domain *d)
{
    struct list_head *runlist = RUNLIST(d);
    list_del(runlist);
    runlist->next = NULL;
}

static inline int __task_on_runqueue(struct exec_domain *d)
{
    return (RUNLIST(d))->next != NULL;
}


/* Warp/unwarp timer functions */
static void warp_timer_fn(unsigned long pointer)
{
    struct bvt_dom_info *inf = (struct bvt_dom_info *)pointer;
    unsigned int cpu = inf->domain->exec_domain[0]->processor;
    
    spin_lock_irq(&schedule_data[cpu].schedule_lock);

    inf->warp = 0;

    /* unwarp equal to zero => stop warping */
    if ( inf->warpu == 0 )
    {
        inf->warpback = 0;
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);   
    }
    
    /* set unwarp timer */
    inf->unwarp_timer.expires = NOW() + inf->warpu;
    add_ac_timer(&inf->unwarp_timer);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);
}

static void unwarp_timer_fn(unsigned long pointer)
{
    struct bvt_dom_info *inf = (struct bvt_dom_info *)pointer;
    unsigned int cpu = inf->domain->exec_domain[0]->processor;

    spin_lock_irq(&schedule_data[cpu].schedule_lock);

    if ( inf->warpback )
    {
        inf->warp = 1;
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);   
    }
     
    spin_unlock_irq(&schedule_data[cpu].schedule_lock);
}

static inline u32 calc_avt(struct exec_domain *d, s_time_t now)
{
    u32 ranfor, mcus;
    struct bvt_dom_info *inf = BVT_INFO(d->domain);
    struct bvt_edom_info *einf = EBVT_INFO(d);
    
    ranfor = (u32)(now - d->lastschd);
    mcus = (ranfor + MCU - 1)/MCU;

    return einf->avt + mcus * inf->mcu_advance;
}

/*
 * Calculate the effective virtual time for a domain. Take into account 
 * warping limits
 */
static inline u32 calc_evt(struct exec_domain *d, u32 avt)
{
    struct bvt_dom_info *inf = BVT_INFO(d->domain);
    /* TODO The warp routines need to be rewritten GM */
 
    if ( inf->warp ) 
        return avt - inf->warp_value;
    else 
        return avt;
}

/**
 * bvt_alloc_task - allocate BVT private structures for a task
 * @p:              task to allocate private structures for
 *
 * Returns non-zero on failure.
 */
int bvt_alloc_task(struct exec_domain *ed)
{
    struct domain *d = ed->domain;
    if ( (d->sched_priv == NULL) ) {
        if ( (d->sched_priv = new(struct bvt_dom_info)) == NULL )
            return -1;
        memset(d->sched_priv, 0, sizeof(struct bvt_dom_info));
    }
    ed->ed_sched_priv = &BVT_INFO(d)->ed_inf[ed->eid];
    BVT_INFO(d)->ed_inf[ed->eid].inf = BVT_INFO(d);
    BVT_INFO(d)->ed_inf[ed->eid].exec_domain = ed;
    return 0;
}

/*
 * Add and remove a domain
 */
void bvt_add_task(struct exec_domain *d) 
{
    struct bvt_dom_info *inf = BVT_INFO(d->domain);
    struct bvt_edom_info *einf = EBVT_INFO(d);
    ASSERT(inf != NULL);
    ASSERT(d   != NULL);

    if (d->eid == 0) {
        inf->mcu_advance = MCU_ADVANCE;
        inf->domain      = d->domain;
        inf->warpback    = 0;
        /* Set some default values here. */
        inf->warp        = 0;
        inf->warp_value  = 0;
        inf->warpl       = MILLISECS(2000);
        inf->warpu       = MILLISECS(1000);
        /* initialise the timers */
        init_ac_timer(&inf->warp_timer);
        inf->warp_timer.cpu = d->processor;
        inf->warp_timer.data = (unsigned long)inf;
        inf->warp_timer.function = &warp_timer_fn;
        init_ac_timer(&inf->unwarp_timer);
        inf->unwarp_timer.cpu = d->processor;
        inf->unwarp_timer.data = (unsigned long)inf;
        inf->unwarp_timer.function = &unwarp_timer_fn;
    }

    einf->exec_domain = d;

    if ( d->domain->id == IDLE_DOMAIN_ID )
    {
        einf->avt = einf->evt = ~0U;
    } 
    else 
    {
        /* Set avt and evt to system virtual time. */
        einf->avt = CPU_SVT(d->processor);
        einf->evt = CPU_SVT(d->processor);
    }
}

int bvt_init_idle_task(struct exec_domain *p)
{
    if ( bvt_alloc_task(p) < 0 )
        return -1;

    bvt_add_task(p);

    set_bit(EDF_RUNNING, &p->ed_flags);
    if ( !__task_on_runqueue(p) )
        __add_to_runqueue_head(p);
        
    return 0;
}

void bvt_wake(struct exec_domain *d)
{
    struct bvt_edom_info *einf = EBVT_INFO(d);
    struct exec_domain  *curr;
    s_time_t            now, r_time;
    int                 cpu = d->processor;
    u32                 curr_evt;

    if ( unlikely(__task_on_runqueue(d)) )
        return;

    __add_to_runqueue_head(d);

    now = NOW();

    /* Set the BVT parameters. AVT should always be updated 
       if CPU migration ocurred.*/
    if ( einf->avt < CPU_SVT(cpu) || 
         unlikely(test_bit(EDF_MIGRATED, &d->ed_flags)) )
        einf->avt = CPU_SVT(cpu);

    /* Deal with warping here. */
    einf->evt = calc_evt(d, einf->avt);
    
    curr = schedule_data[cpu].curr;
    curr_evt = calc_evt(curr, calc_avt(curr, now));
    /* Calculate the time the current domain would run assuming
       the second smallest evt is of the newly woken domain */
    r_time = curr->lastschd +
        ((einf->evt - curr_evt) / BVT_INFO(curr->domain)->mcu_advance) +
        ctx_allow;

    if ( is_idle_task(curr->domain) || (einf->evt <= curr_evt) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    else if ( schedule_data[cpu].s_timer.expires > r_time )
        mod_ac_timer(&schedule_data[cpu].s_timer, r_time);
}


static void bvt_sleep(struct exec_domain *d)
{
    if ( test_bit(EDF_RUNNING, &d->ed_flags) )
        cpu_raise_softirq(d->processor, SCHEDULE_SOFTIRQ);
    else  if ( __task_on_runqueue(d) )
        __del_from_runqueue(d);
}

/**
 * bvt_free_task - free BVT private structures for a task
 * @d:             task
 */
void bvt_free_task(struct domain *d)
{
    ASSERT(d->sched_priv != NULL);
    xfree(d->sched_priv);
}

/* Control the scheduler. */
int bvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct bvt_ctl *params = &cmd->u.bvt;

    if ( cmd->direction == SCHED_INFO_PUT )
        ctx_allow = params->ctx_allow;
    else
        params->ctx_allow = ctx_allow;
    
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
int bvt_adjdom(
    struct domain *d, struct sched_adjdom_cmd *cmd)
{
    struct bvt_adjdom *params = &cmd->u.bvt;
    
    if ( cmd->direction == SCHED_INFO_PUT )
    {
        u32 mcu_adv = params->mcu_adv;
        u32 warpback  = params->warpback;
        s32 warpvalue = params->warpvalue;
        s_time_t warpl = params->warpl;
        s_time_t warpu = params->warpu;
        
        struct bvt_dom_info *inf = BVT_INFO(d);
        
        /* Sanity -- this can avoid divide-by-zero. */
        if ( (mcu_adv == 0) || (warpl < 0) || (warpu < 0) )
            return -EINVAL;

        inf->mcu_advance = mcu_adv;
        inf->warpback = warpback;  
        /* The warp should be the same as warpback */
        inf->warp = warpback;
        inf->warp_value = warpvalue;
        inf->warpl = MILLISECS(warpl);
        inf->warpu = MILLISECS(warpu);
        
        /* If the unwarp timer set up it needs to be removed */
        rem_ac_timer(&inf->unwarp_timer);
        /* If we stop warping the warp timer needs to be removed */
        if ( !warpback )
            rem_ac_timer(&inf->warp_timer);
    }
    else if ( cmd->direction == SCHED_INFO_GET )
    {
        struct bvt_dom_info *inf = BVT_INFO(d);
        params->mcu_adv     = inf->mcu_advance;
        params->warpvalue   = inf->warp_value;
        params->warpback    = inf->warpback;
        params->warpl       = inf->warpl;
        params->warpu       = inf->warpu;
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
    struct domain *d;
    struct exec_domain      *prev = current, *next = NULL, *next_prime, *ed; 
    int                 cpu = prev->processor;
    s32                 r_time;     /* time for new dom to run */
    u32                 next_evt, next_prime_evt, min_avt;
    struct bvt_dom_info *prev_inf       = BVT_INFO(prev->domain);
    struct bvt_edom_info *prev_einf       = EBVT_INFO(prev);
    struct bvt_edom_info *p_einf          = NULL;
    struct bvt_edom_info *next_einf       = NULL;
    struct bvt_edom_info *next_prime_einf = NULL;
    task_slice_t        ret;

    ASSERT(prev->ed_sched_priv != NULL);
    ASSERT(prev_einf != NULL);
    ASSERT(__task_on_runqueue(prev));

    if ( likely(!is_idle_task(prev->domain)) ) 
    {
        prev_einf->avt = calc_avt(prev, now);
        prev_einf->evt = calc_evt(prev, prev_einf->avt);
       
        if(prev_inf->warpback && prev_inf->warpl > 0)
            rem_ac_timer(&prev_inf->warp_timer);
        
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
    next_einf       = EBVT_INFO(schedule_data[cpu].idle);
    next_prime_einf  = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each_entry ( p_einf, RUNQUEUE(cpu), run_list )
    {
        if ( p_einf->evt < next_evt )
        {
            next_prime_einf  = next_einf;
            next_prime_evt  = next_evt;
            next_einf        = p_einf;
            next_evt        = p_einf->evt;
        } 
        else if ( next_prime_evt == ~0U )
        {
            next_prime_evt  = p_einf->evt;
            next_prime_einf  = p_einf;
        } 
        else if ( p_einf->evt < next_prime_evt )
        {
            next_prime_evt  = p_einf->evt;
            next_prime_einf  = p_einf;
        }

        /* Determine system virtual time. */
        if ( p_einf->avt < min_avt )
            min_avt = p_einf->avt;
    }
    
    if(next_einf->inf->warp && next_einf->inf->warpl > 0)
    {
        /* Set the timer up */ 
        next_einf->inf->warp_timer.expires = now + next_einf->inf->warpl;
        /* Add it to the heap */
        add_ac_timer(&next_einf->inf->warp_timer);
    }
   
    /* Extract the domain pointers from the dom infos */
    next        = next_einf->exec_domain;
    next_prime  = next_prime_einf->exec_domain;
    
    /* Update system virtual time. */
    if ( min_avt != ~0U )
        CPU_SVT(cpu) = min_avt;

    /* check for virtual time overrun on this cpu */
    if ( CPU_SVT(cpu) >= 0xf0000000 )
    {
        ASSERT(!local_irq_is_enabled());

        write_lock(&domlist_lock);
        
        for_each_domain ( d )
        {
            for_each_exec_domain (d, ed) {
                if ( ed->processor == cpu )
                {
                    p_einf = EBVT_INFO(ed);
                    p_einf->evt -= 0xe0000000;
                    p_einf->avt -= 0xe0000000;
                }
            }
        } 
        
        write_unlock(&domlist_lock);
        
        CPU_SVT(cpu) -= 0xe0000000;
    }

    /* work out time for next run through scheduler */
    if ( is_idle_task(next->domain) ) 
    {
        r_time = ctx_allow;
        goto sched_done;
    }

    if ( (next_prime == NULL) || is_idle_task(next_prime->domain) )
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
    ASSERT(next_prime_einf->evt >= next_einf->evt);
    
    r_time = ((next_prime_einf->evt - next_einf->evt)/next_einf->inf->mcu_advance)
        + ctx_allow;

    ASSERT(r_time >= ctx_allow);

 sched_done:
    ret.task = next;
    ret.time = r_time;
    return ret;
}


static void bvt_dump_runq_el(struct exec_domain *p)
{
    struct bvt_edom_info *inf = EBVT_INFO(p);
    
    printk("mcua=%d ev=0x%08X av=0x%08X ",
           inf->inf->mcu_advance, inf->evt, inf->avt);
}

static void bvt_dump_settings(void)
{
    printk("BVT: mcu=0x%08Xns ctx_allow=0x%08Xns ", (u32)MCU, (s32)ctx_allow );
}

static void bvt_dump_cpu_state(int i)
{
    struct list_head *queue;
    int loop = 0;
    struct bvt_edom_info *d_inf;
    struct exec_domain *d;
    
    printk("svt=0x%08lX ", CPU_SVT(i));

    queue = RUNQUEUE(i);
    printk("QUEUE rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
           (unsigned long) queue->next, (unsigned long) queue->prev);

    list_for_each_entry ( d_inf, queue, run_list )
    {
        d = d_inf->exec_domain;
        printk("%3d: %u has=%c ", loop++, d->domain->id,
               test_bit(EDF_RUNNING, &d->ed_flags) ? 'T':'F');
        bvt_dump_runq_el(d);
        printk("c=0x%X%08X\n", (u32)(d->cpu_time>>32), (u32)d->cpu_time);
        printk("         l: %p n: %p  p: %p\n",
               &d_inf->run_list, d_inf->run_list.next, d_inf->run_list.prev);
    }
}

/* Initialise the data structures. */
int bvt_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
    {
        schedule_data[i].sched_priv = xmalloc(struct bvt_cpu_info);
       
        if ( schedule_data[i].sched_priv == NULL )
        {
            printk("Failed to allocate BVT scheduler per-CPU memory!\n");
            return -1;
        }

        INIT_LIST_HEAD(RUNQUEUE(i));
        
        CPU_SVT(i) = 0; /* XXX do I really need to do this? */
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
    .do_schedule    = bvt_do_schedule,
    .control        = bvt_ctl,
    .adjdom         = bvt_adjdom,
    .dump_settings  = bvt_dump_settings,
    .dump_cpu_state = bvt_dump_cpu_state,
    .sleep          = bvt_sleep,
    .wake           = bvt_wake,
};
