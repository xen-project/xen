/****************************************************************************
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
#include <xen/softirq.h>

/* all per-domain BVT-specific scheduling info is stored here */
struct bvt_vcpu_info
{
    struct list_head    run_list;         /* runqueue list pointers */
    u32                 avt;              /* actual virtual time */
    u32                 evt;              /* effective virtual time */
    int                 migrated;         /* migrated to a new CPU */
    struct vcpu         *vcpu;
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

    struct bvt_vcpu_info vcpu_inf[MAX_VIRT_CPUS];
};

struct bvt_cpu_info
{
    struct list_head    runqueue;
    unsigned long       svt;
};

#define BVT_INFO(p)   ((struct bvt_dom_info *)(p)->sched_priv)
#define EBVT_INFO(p)  ((struct bvt_vcpu_info *)(p)->sched_priv)
#define CPU_INFO(cpu) ((struct bvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define RUNLIST(p)    ((struct list_head *)&(EBVT_INFO(p)->run_list))
#define RUNQUEUE(cpu) ((struct list_head *)&(CPU_INFO(cpu)->runqueue))
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
#define CTX_MIN        (s32)MICROSECS(10)     /* Low limit for ctx_allow */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */

static inline void __add_to_runqueue_head(struct vcpu *d)
{
    list_add(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __add_to_runqueue_tail(struct vcpu *d)
{
    list_add_tail(RUNLIST(d), RUNQUEUE(d->processor));
}

static inline void __del_from_runqueue(struct vcpu *d)
{
    struct list_head *runlist = RUNLIST(d);
    list_del(runlist);
    runlist->next = NULL;
}

static inline int __task_on_runqueue(struct vcpu *d)
{
    return (RUNLIST(d))->next != NULL;
}


/* Warp/unwarp timer functions */
static void warp_timer_fn(void *data)
{
    struct bvt_dom_info *inf = data;
    unsigned int cpu = inf->domain->vcpu[0]->processor;
    
    spin_lock_irq(&schedule_data[cpu].schedule_lock);

    inf->warp = 0;

    /* unwarp equal to zero => stop warping */
    if ( inf->warpu == 0 )
    {
        inf->warpback = 0;
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);   
    }
    
    set_ac_timer(&inf->unwarp_timer, NOW() + inf->warpu);

    spin_unlock_irq(&schedule_data[cpu].schedule_lock);
}

static void unwarp_timer_fn(void *data)
{
    struct bvt_dom_info *inf = data;
    unsigned int cpu = inf->domain->vcpu[0]->processor;

    spin_lock_irq(&schedule_data[cpu].schedule_lock);

    if ( inf->warpback )
    {
        inf->warp = 1;
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);   
    }
     
    spin_unlock_irq(&schedule_data[cpu].schedule_lock);
}

static inline u32 calc_avt(struct vcpu *d, s_time_t now)
{
    u32 ranfor, mcus;
    struct bvt_dom_info *inf = BVT_INFO(d->domain);
    struct bvt_vcpu_info *einf = EBVT_INFO(d);
    
    ranfor = (u32)(now - d->lastschd);
    mcus = (ranfor + MCU - 1)/MCU;

    return einf->avt + mcus * inf->mcu_advance;
}

/*
 * Calculate the effective virtual time for a domain. Take into account 
 * warping limits
 */
static inline u32 calc_evt(struct vcpu *d, u32 avt)
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
static int bvt_alloc_task(struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( (d->sched_priv == NULL) )
    {
        if ( (d->sched_priv = xmalloc(struct bvt_dom_info)) == NULL )
            return -1;
        memset(d->sched_priv, 0, sizeof(struct bvt_dom_info));
    }

    v->sched_priv = &BVT_INFO(d)->vcpu_inf[v->vcpu_id];

    BVT_INFO(d)->vcpu_inf[v->vcpu_id].inf = BVT_INFO(d);
    BVT_INFO(d)->vcpu_inf[v->vcpu_id].vcpu = v;

    return 0;
}

/*
 * Add and remove a domain
 */
static void bvt_add_task(struct vcpu *v) 
{
    struct bvt_dom_info *inf = BVT_INFO(v->domain);
    struct bvt_vcpu_info *einf = EBVT_INFO(v);
    ASSERT(inf != NULL);
    ASSERT(v   != NULL);

    /* Allocate per-CPU context if this is the first domain to be added. */
    if ( CPU_INFO(v->processor) == NULL )
    {
        schedule_data[v->processor].sched_priv = xmalloc(struct bvt_cpu_info);
        BUG_ON(CPU_INFO(v->processor) == NULL);
        INIT_LIST_HEAD(RUNQUEUE(v->processor));
        CPU_SVT(v->processor) = 0;
    }

    if ( v->vcpu_id == 0 )
    {
        inf->mcu_advance = MCU_ADVANCE;
        inf->domain      = v->domain;
        inf->warpback    = 0;
        /* Set some default values here. */
        inf->warp        = 0;
        inf->warp_value  = 0;
        inf->warpl       = MILLISECS(2000);
        inf->warpu       = MILLISECS(1000);
        /* Initialise the warp timers. */
        init_ac_timer(&inf->warp_timer, warp_timer_fn, inf, v->processor);
        init_ac_timer(&inf->unwarp_timer, unwarp_timer_fn, inf, v->processor);
    }

    einf->vcpu = v;

    if ( is_idle_domain(v->domain) )
    {
        einf->avt = einf->evt = ~0U;
        BUG_ON(__task_on_runqueue(v));
        __add_to_runqueue_head(v);
    } 
    else 
    {
        /* Set avt and evt to system virtual time. */
        einf->avt = CPU_SVT(v->processor);
        einf->evt = CPU_SVT(v->processor);
    }
}

static void bvt_wake(struct vcpu *v)
{
    struct bvt_vcpu_info *einf = EBVT_INFO(v);
    struct vcpu  *curr;
    s_time_t            now, r_time;
    int                 cpu = v->processor;
    u32                 curr_evt;

    if ( unlikely(__task_on_runqueue(v)) )
        return;

    __add_to_runqueue_head(v);

    now = NOW();

    /* Set the BVT parameters. AVT should always be updated 
       if CPU migration ocurred.*/
    if ( (einf->avt < CPU_SVT(cpu)) || einf->migrated )
    {
        einf->avt = CPU_SVT(cpu);
        einf->migrated = 0;
    }

    /* Deal with warping here. */
    einf->evt = calc_evt(v, einf->avt);
    
    curr = schedule_data[cpu].curr;
    curr_evt = calc_evt(curr, calc_avt(curr, now));
    /* Calculate the time the current domain would run assuming
       the second smallest evt is of the newly woken domain */
    r_time = curr->lastschd +
        ((einf->evt - curr_evt) / BVT_INFO(curr->domain)->mcu_advance) +
        ctx_allow;

    if ( is_idle_domain(curr->domain) || (einf->evt <= curr_evt) )
        cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
    else if ( schedule_data[cpu].s_timer.expires > r_time )
        set_ac_timer(&schedule_data[cpu].s_timer, r_time);
}


static void bvt_sleep(struct vcpu *v)
{
    if ( test_bit(_VCPUF_running, &v->vcpu_flags) )
        cpu_raise_softirq(v->processor, SCHEDULE_SOFTIRQ);
    else  if ( __task_on_runqueue(v) )
        __del_from_runqueue(v);
}


static int bvt_set_affinity(struct vcpu *v, cpumask_t *affinity)
{
    if ( v == current )
        return cpu_isset(v->processor, *affinity) ? 0 : -EBUSY;

    vcpu_pause(v);
    v->cpu_affinity = *affinity;
    v->processor = first_cpu(v->cpu_affinity);
    EBVT_INFO(v)->migrated = 1;
    vcpu_unpause(v);

    return 0;
}


/**
 * bvt_free_task - free BVT private structures for a task
 * @d:             task
 */
static void bvt_free_task(struct domain *d)
{
    ASSERT(d->sched_priv != NULL);
    xfree(d->sched_priv);
}

/* Control the scheduler. */
static int bvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct bvt_ctl *params = &cmd->u.bvt;

    if ( cmd->direction == SCHED_INFO_PUT )
        ctx_allow = params->ctx_allow;
    else
    {
        if ( ctx_allow < CTX_MIN )
            ctx_allow = CTX_MIN;
        params->ctx_allow = ctx_allow;
    }
    
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
static int bvt_adjdom(
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
static struct task_slice bvt_do_schedule(s_time_t now)
{
    struct domain *d;
    struct vcpu      *prev = current, *next = NULL, *next_prime, *ed; 
    int                 cpu = prev->processor;
    s32                 r_time;     /* time for new dom to run */
    u32                 next_evt, next_prime_evt, min_avt;
    struct bvt_dom_info *prev_inf       = BVT_INFO(prev->domain);
    struct bvt_vcpu_info *prev_einf       = EBVT_INFO(prev);
    struct bvt_vcpu_info *p_einf          = NULL;
    struct bvt_vcpu_info *next_einf       = NULL;
    struct bvt_vcpu_info *next_prime_einf = NULL;
    struct task_slice     ret;

    ASSERT(prev->sched_priv != NULL);
    ASSERT(prev_einf != NULL);
    ASSERT(__task_on_runqueue(prev));

    if ( likely(!is_idle_domain(prev->domain)) ) 
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
    
    if ( next_einf->inf->warp && next_einf->inf->warpl > 0 )
        set_ac_timer(&next_einf->inf->warp_timer, now + next_einf->inf->warpl);
   
    /* Extract the domain pointers from the dom infos */
    next        = next_einf->vcpu;
    next_prime  = next_prime_einf->vcpu;
    
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
            for_each_vcpu (d, ed) {
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
    if ( is_idle_domain(next->domain) ) 
    {
        r_time = ctx_allow;
        goto sched_done;
    }

    if ( (next_prime == NULL) || is_idle_domain(next_prime->domain) )
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


static void bvt_dump_runq_el(struct vcpu *p)
{
    struct bvt_vcpu_info *inf = EBVT_INFO(p);
    
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
    struct bvt_vcpu_info *vcpu_inf;
    struct vcpu *v;
    
    printk("svt=0x%08lX ", CPU_SVT(i));

    queue = RUNQUEUE(i);
    printk("QUEUE rq %lx   n: %lx, p: %lx\n",  (unsigned long)queue,
           (unsigned long) queue->next, (unsigned long) queue->prev);

    list_for_each_entry ( vcpu_inf, queue, run_list )
    {
        v = vcpu_inf->vcpu;
        printk("%3d: %u has=%c ", loop++, v->domain->domain_id,
               test_bit(_VCPUF_running, &v->vcpu_flags) ? 'T':'F');
        bvt_dump_runq_el(v);
        printk("c=0x%X%08X\n", (u32)(v->cpu_time>>32), (u32)v->cpu_time);
        printk("         l: %p n: %p  p: %p\n",
               &vcpu_inf->run_list, vcpu_inf->run_list.next,
               vcpu_inf->run_list.prev);
    }
}

struct scheduler sched_bvt_def = {
    .name     = "Borrowed Virtual Time",
    .opt_name = "bvt",
    .sched_id = SCHED_BVT,
    
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
    .set_affinity   = bvt_set_affinity
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
