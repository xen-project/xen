#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <asm/ptrace.h>
#include <xen/smp.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/dom0_ops.h>

#include <xen/list.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/delay.h>
#include <xen/rbtree.h>

#define STACK_SIZE (2*PAGE_SIZE)
#include <asm/current.h>

#define MAX_DOMAIN_NAME 16

extern unsigned long volatile jiffies;
extern rwlock_t tasklist_lock;

extern struct timeval xtime;

#include <xen/spinlock.h>

extern struct mm_struct init_mm;

#define _HYP_EVENT_NEED_RESCHED 0
#define _HYP_EVENT_DIE          1

#define PF_DONEFPUINIT  0 /* Has the FPU been initialised for this task? */
#define PF_USEDFPU      1 /* Has this task used the FPU since last save? */
#define PF_GUEST_STTS   2 /* Has the guest OS requested 'stts'?          */
#define PF_CONSTRUCTED  3 /* Has the guest OS been fully built yet?      */
#define PF_IDLETASK     4 /* Is this one of the per-CPU idle domains?    */
#define PF_PRIVILEGED   5 /* Is this domain privileged?                  */
#define PF_CONSOLEWRITEBUG 6 /* Has this domain used the obsolete console? */
#define PF_PHYSDEV      7 /* May this domain do IO to physical devices? */

#include <xen/vif.h>
#include <xen/vbd.h>

#define IS_PRIV(_p) (test_bit(PF_PRIVILEGED, &(_p)->flags))
#define IS_CAPABLE_PHYSDEV(_p) (test_bit(PF_PHYSDEV, &(_p)->flags))

struct task_struct;

typedef struct event_channel_st
{
#define ECS_FREE         0 /* Channel is available for use.                  */
#define ECS_UNBOUND      1 /* Channel is not bound to a particular source.   */
#define ECS_INTERDOMAIN  2 /* Channel is bound to another domain.            */
#define ECS_PIRQ         3 /* Channel is bound to a physical IRQ line.       */
#define ECS_VIRQ         4 /* Channel is bound to a virtual IRQ line.        */
    u16 state;
    union {
        struct {
            u16 port;
            struct task_struct *dom;
        } __attribute__ ((packed)) remote; /* state == ECS_CONNECTED */
        u16 pirq; /* state == ECS_PIRQ */
        u16 virq; /* state == ECS_VIRQ */
    } u;
} event_channel_t;

int  init_event_channels(struct task_struct *p);
void destroy_event_channels(struct task_struct *p);

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

    s_time_t         min_slice;     /* minimum time before reschedule */

    void *sched_priv;               /* scheduler-specific data */

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
    s_time_t create_time;

    struct thread_struct thread;
    struct task_struct *next_list, *next_hash;

    /* Event channel information. */
    event_channel_t *event_channel;
    unsigned int     max_event_channel;
    spinlock_t       event_channel_lock;

    /*
     * Interrupt to event-channel mappings. Updates should be protected by the 
     * domain's event-channel spinlock. Read accesses can also synchronise on 
     * the lock, but races don't usually matter.
     */
#define NR_PIRQS 128 /* Put this somewhere sane! */
    u16 pirq_to_evtchn[NR_PIRQS];
    u16 virq_to_evtchn[NR_VIRQS];
    u32 pirq_mask[NR_PIRQS/32];

    /* Physical I/O */
    spinlock_t       pcidev_lock;
    struct list_head pcidev_list;

    /* The following IO bitmap stuff is x86-dependent. */
    u64 io_bitmap_sel; /* Selector to tell us which part of the IO bitmap are
                        * "interesting" (i.e. have clear bits) */

    /* Handy macro - number of bytes of the IO bitmap, per selector bit. */
#define IOBMP_SELBIT_LWORDS ( IO_BITMAP_SIZE / 64 )
    unsigned long *io_bitmap; /* Pointer to task's IO bitmap or NULL */

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
 * TASK_PAUSED:          Task currently removed from scheduling.
 */

#define TASK_RUNNING             0
#define TASK_INTERRUPTIBLE       1
#define TASK_UNINTERRUPTIBLE     2
#define TASK_STOPPED             4
#define TASK_DYING               8
#define TASK_PAUSED             16

#include <asm/uaccess.h> /* for KERNEL_DS */

#define IDLE0_TASK(_t)           \
{                                \
    processor:   0,              \
    domain:      IDLE_DOMAIN_ID, \
    state:       TASK_RUNNING,   \
    has_cpu:     0,              \
    mm:          IDLE0_MM,       \
    addr_limit:  KERNEL_DS,      \
    thread:      INIT_THREAD,    \
    flags:       1<<PF_IDLETASK  \
}

extern struct task_struct idle0_task;

extern struct task_struct *idle_task[NR_CPUS];
#define IDLE_DOMAIN_ID   (~0ULL)
#define is_idle_task(_p) (test_bit(PF_IDLETASK, &(_p)->flags))

#include <xen/slab.h>

void free_task_struct(struct task_struct *p);
struct task_struct *alloc_task_struct();

#define put_task_struct(_p) \
  if ( atomic_dec_and_test(&(_p)->refcnt) ) release_task(_p)
#define get_task_struct(_p)  \
  atomic_inc(&(_p)->refcnt)

extern struct task_struct *do_createdomain(
    domid_t dom_id, unsigned int cpu);
extern int construct_dom0(struct task_struct *p, 
                          unsigned long alloc_start,
                          unsigned long alloc_end,
                          unsigned int num_vifs,
                          char *image_start, unsigned long image_len, 
                          char *initrd_start, unsigned long initrd_len,
                          char *cmdline);
extern int final_setup_guestos(struct task_struct *p, dom0_builddomain_t *);

struct task_struct *find_domain_by_id(domid_t dom);
struct task_struct *find_last_domain(void);
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
int  sched_rem_domain(struct task_struct *p);
long sched_ctl(struct sched_ctl_cmd *);
long sched_adjdom(struct sched_adjdom_cmd *);
int  sched_id();
void sched_pause_sync(struct task_struct *);
void init_idle_task(void);
void __wake_up(struct task_struct *p);
void wake_up(struct task_struct *p);
void reschedule(struct task_struct *p);
unsigned long __reschedule(struct task_struct *p);

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

#define signal_pending(_p)                                      \
    ( (_p)->hyp_events ||                                       \
      ((_p)->shared_info->vcpu_data[0].evtchn_upcall_pending && \
       !(_p)->shared_info->vcpu_data[0].evtchn_upcall_mask) )

void domain_init(void);

int idle_cpu(int cpu); /* Is CPU 'cpu' idle right now? */

void startup_cpu_idle_loop(void);
void continue_cpu_idle_loop(void);

void continue_nonidle_task(void);
void sched_prn_state(int state);

/* This task_hash and task_list are protected by the tasklist_lock. */
#define TASK_HASH_SIZE 256
#define TASK_HASH(_id) ((int)(_id)&(TASK_HASH_SIZE-1))
extern struct task_struct *task_hash[TASK_HASH_SIZE];
extern struct task_struct *task_list;

#define for_each_domain(_p) \
 for ( (_p) = task_list; (_p) != NULL; (_p) = (_p)->next_list )

extern void update_process_times(int user);

#endif /*_LINUX_SCHED_H */
