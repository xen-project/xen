#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/spinlock.h>
#include <asm/ptrace.h>
#include <xeno/smp.h>
#include <asm/processor.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/dom0_ops.h>

#include <xeno/list.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>
#include <xeno/delay.h>
#include <xeno/rbtree.h>

#define STACK_SIZE (2*PAGE_SIZE)
#include <asm/current.h>

#define MAX_DOMAIN_NAME 16

extern unsigned long volatile jiffies;
extern rwlock_t tasklist_lock;

extern struct timeval xtime;

#include <xeno/spinlock.h>

extern struct mm_struct init_mm;

#define _HYP_EVENT_NEED_RESCHED 0
#define _HYP_EVENT_DIE          1

#define PF_DONEFPUINIT  0 /* Has the FPU been initialised for this task? */
#define PF_USEDFPU      1 /* Has this task used the FPU since last save? */
#define PF_GUEST_STTS   2 /* Has the guest OS requested 'stts'?          */
#define PF_CONSTRUCTED  3 /* Has the guest OS been fully built yet?      */
#define PF_IDLETASK     4 /* Is this one of the per-CPU idle domains?    */
#define PF_PRIVILEGED   5 /* Is this domain privileged?                  */

#include <xeno/vif.h>
#include <xeno/vbd.h>

#define IS_PRIV(_p) (test_bit(PF_PRIVILEGED, &(_p)->flags))

typedef struct event_channel_st
{
    u16 target_dom; /* Target domain (i.e. domain at remote end). */
#define ECF_TARGET_ID ((1<<10)-1) /* Channel identifier at remote end.    */
#define ECF_INUSE     (1<<10)     /* Is this channel descriptor in use?   */
#define ECF_CONNECTED (1<<11)     /* Is this channel connected to remote? */
    u16 flags;
} event_channel_t;

struct task_struct 
{
    /*
     * DO NOT CHANGE THE ORDER OF THE FOLLOWING.
     * Their offsets are hardcoded in entry.S
     */

    unsigned short processor;    /* 00: current processor */
    unsigned short hyp_events;   /* 02: pending intra-Xen events */

    /* An unsafe pointer into a shared data area. */
    shared_info_t *shared_info;  /* 04: shared data area */

    /*
     * Return vectors pushed to us by guest OS.
     * The stack frame for events is exactly that of an x86 hardware interrupt.
     * The stack frame for a failsafe callback is augmented with saved values
     * for segment registers %ds, %es, %fs and %gs:
     * 	%ds, %es, %fs, %gs, %eip, %cs, %eflags [, %oldesp, %oldss]
     */
    unsigned long event_selector;    /* 08: entry CS  */
    unsigned long event_address;     /* 12: entry EIP */

    /* Saved DS,ES,FS,GS immediately before return to guest OS. */
    unsigned long failsafe_selectors[4]; /* 16-32 */ 

    /*
     * END OF FIRST CACHELINE. Stuff above is touched a lot!
     */

    unsigned long failsafe_selector; /* 32: entry CS  */
    unsigned long failsafe_address;  /* 36: entry EIP */

    /*
     * From here on things can be added and shuffled without special attention
     */

    domid_t domain;

    spinlock_t       page_list_lock;
    struct list_head page_list;
    unsigned int     tot_pages; /* number of pages currently possesed */
    unsigned int     max_pages; /* max number of pages that can be possesed */

    /* Scheduling. */
    struct list_head run_list;
    int              has_cpu;
    int              state;         /* current run state */
    int              cpupinned;     /* true if pinned to curent CPU */
    s_time_t         lastschd;      /* time this domain was last scheduled */
    s_time_t         lastdeschd;    /* time this domain was last descheduled */
    s_time_t         cpu_time;      /* total CPU time received till now */
    s_time_t         wokenup;       /* time domain got woken up */
    struct ac_timer  timer;         /* one-shot timer for timeout values */

    /* BVT scheduler specific. */
    unsigned long mcu_advance;      /* inverse of weight */
    u32           avt;              /* actual virtual time */
    u32           evt;              /* effective virtual time */
    int           warpback;         /* warp?  */
    long          warp;             /* virtual time warp */
    long          warpl;            /* warp limit */
    long          warpu;            /* unwarp time requirement */
    s_time_t      warped;           /* time it ran warped last time */
    s_time_t      uwarped;          /* time it ran unwarped last time */

    /* Network I/O */
    net_vif_t *net_vif_list[MAX_DOMAIN_VIFS];

    /* Block I/O */
    blk_ring_t *blk_ring_base;
    BLK_RING_IDX blk_req_cons;  /* request consumer */
    BLK_RING_IDX blk_resp_prod; /* (private version of) response producer */
    struct list_head blkdev_list;
    spinlock_t blk_ring_lock;
    rb_root_t  vbd_rb;          /* mapping from 16-bit vdevices to vbds */
    spinlock_t vbd_lock;        /* protects VBD mapping */

    /* VM */
    struct mm_struct mm;

    mm_segment_t addr_limit;

    char name[MAX_DOMAIN_NAME];

    struct thread_struct thread;
    struct task_struct *next_list, *next_hash;

    /* Event channel information. */
    event_channel_t *event_channel;
    unsigned int     max_event_channel;
    spinlock_t       event_channel_lock;

    unsigned long flags;

    atomic_t refcnt;
};

/*
 * domain states 
 * TASK_RUNNING:         Domain is runable and should be on a run queue
 * TASK_INTERRUPTIBLE:   Domain is blocked by may be woken up by an event
 *                       or expiring timer
 * TASK_UNINTERRUPTIBLE: Domain is blocked but may not be woken up by an
 *                       arbitrary event or timer.
 * TASK_STOPPED:         Domain is stopped.
 * TASK_DYING:           Domain is about to cross over to the land of the dead.
 */

#define TASK_RUNNING             0
#define TASK_INTERRUPTIBLE       1
#define TASK_UNINTERRUPTIBLE     2
#define TASK_STOPPED             4
#define TASK_DYING               8

#include <asm/uaccess.h> /* for KERNEL_DS */

#define IDLE0_TASK(_t)           \
{                                \
    processor:   0,              \
    domain:      IDLE_DOMAIN_ID, \
    state:       TASK_RUNNING,   \
    has_cpu:     0,              \
    evt:         0xffffffff,     \
    avt:         0xffffffff,     \
    mm:          IDLE0_MM,       \
    addr_limit:  KERNEL_DS,      \
    thread:      INIT_THREAD,    \
    flags:       1<<PF_IDLETASK  \
}

extern struct task_struct idle0_task;

extern struct task_struct *idle_task[NR_CPUS];
#define IDLE_DOMAIN_ID   (~0ULL)
#define is_idle_task(_p) (test_bit(PF_IDLETASK, &(_p)->flags))

#include <xeno/slab.h>

extern kmem_cache_t *task_struct_cachep;
#define alloc_task_struct()  \
  ((struct task_struct *)kmem_cache_alloc(task_struct_cachep,GFP_KERNEL))
#define put_task_struct(_p) \
  if ( atomic_dec_and_test(&(_p)->refcnt) ) release_task(_p)
#define get_task_struct(_p)  \
  atomic_inc(&(_p)->refcnt)

extern struct task_struct *do_createdomain(
    domid_t dom_id, unsigned int cpu);
extern int setup_guestos(
    struct task_struct *p, dom0_createdomain_t *params, unsigned int num_vifs,
    char *data_start, unsigned long data_len, 
    char *cmdline, unsigned long initrd_len);
extern int final_setup_guestos(struct task_struct *p, dom0_builddomain_t *);

struct task_struct *find_domain_by_id(domid_t dom);
extern void release_task(struct task_struct *);
extern void __kill_domain(struct task_struct *p);
extern void kill_domain(void);
extern void kill_domain_with_errmsg(const char *err);
extern long kill_other_domain(domid_t dom, int force);
extern void stop_domain(void);
extern long stop_other_domain(domid_t dom);

/* arch/process.c */
void new_thread(struct task_struct *p,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info);

/* Linux puts these here for some reason! */
extern int request_irq(unsigned int,
                       void (*handler)(int, void *, struct pt_regs *),
                       unsigned long, const char *, void *);
extern void free_irq(unsigned int, void *);

extern unsigned long wait_init_idle;
#define init_idle() clear_bit(smp_processor_id(), &wait_init_idle);

extern spinlock_t schedule_lock[NR_CPUS] __cacheline_aligned;

/*
 * Scheduler functions (in schedule.c)
 */
#define set_current_state(_s) do { current->state = (_s); } while (0)
void scheduler_init(void);
void schedulers_start(void);
void sched_add_domain(struct task_struct *p);
int sched_rem_domain(struct task_struct *p);
long sched_bvtctl(unsigned long ctx_allow);
long sched_adjdom(domid_t dom, unsigned long mcu_adv, unsigned long warp, 
                  unsigned long warpl, unsigned long warpu);
void init_idle_task(void);
void __wake_up(struct task_struct *p);
void wake_up(struct task_struct *p);
unsigned long __reschedule(struct task_struct *p);
void reschedule(struct task_struct *p);

/* NB. Limited entry in Xen. Not for arbitrary use! */
asmlinkage void __enter_scheduler(void);
#define schedule() __schedule_not_callable_in_xen()

extern void switch_to(struct task_struct *prev, 
                      struct task_struct *next);


/* A compatibility hack for Linux drivers. */
#define MAX_SCHEDULE_TIMEOUT 0UL
static inline long schedule_timeout(long timeout)
{
    set_current_state(TASK_RUNNING);
    mdelay(timeout*(1000/HZ));
    return 0;
}

#define signal_pending(_p) \
    ((_p)->hyp_events ||   \
     ((_p)->shared_info->events & (_p)->shared_info->events_mask))

void domain_init(void);

int idle_cpu(int cpu); /* Is CPU 'cpu' idle right now? */

void startup_cpu_idle_loop(void);
void continue_cpu_idle_loop(void);

void continue_nonidle_task(void);

/* This task_hash and task_list are protected by the tasklist_lock. */
#define TASK_HASH_SIZE 256
#define TASK_HASH(_id) ((int)(_id)&(TASK_HASH_SIZE-1))
extern struct task_struct *task_hash[TASK_HASH_SIZE];
extern struct task_struct *task_list;

#define for_each_domain(_p) \
 for ( (_p) = task_list; (_p) != NULL; (_p) = (_p)->next_list )

extern void update_process_times(int user);

#include <asm/desc.h>
static inline void load_LDT(struct task_struct *p)
{
    unsigned int cpu;
    struct desc_struct *desc;
    unsigned long ents;

    if ( (ents = p->mm.ldt_ents) == 0 )
    {
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (0) );
    }
    else
    {
        cpu = smp_processor_id();
        desc = (struct desc_struct *)GET_GDT_ADDRESS(p) + __LDT(cpu);
        desc->a = ((LDT_VIRT_START&0xffff)<<16) | (ents*8-1);
        desc->b = (LDT_VIRT_START&(0xff<<24)) | 0x8200 | 
            ((LDT_VIRT_START&0xff0000)>>16);
        __asm__ __volatile__ ( "lldt %%ax" : : "a" (__LDT(cpu)<<3) );
    }
}

#endif
