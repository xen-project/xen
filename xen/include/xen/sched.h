#ifndef __SCHED_H__
#define __SCHED_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#ifdef LINUX_2_6
#include <linux/thread_info.h>
#endif
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
#include <asm/atomic.h>

#define STACK_SIZE (2*PAGE_SIZE)
#include <asm/current.h>

#define MAX_DOMAIN_NAME 16

extern unsigned long volatile jiffies;
extern rwlock_t tasklist_lock;

#include <xen/spinlock.h>

struct domain;

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
            struct domain *dom;
        } __attribute__ ((packed)) remote; /* state == ECS_CONNECTED */
        u16 pirq; /* state == ECS_PIRQ */
        u16 virq; /* state == ECS_VIRQ */
    } u;
} event_channel_t;

int  init_event_channels(struct domain *d);
void destroy_event_channels(struct domain *d);

struct domain 
{
    /*
     * DO NOT CHANGE THE ORDER OF THE FOLLOWING.
     * Their offsets are hardcoded in entry.S
     */

    u32 processor;               /* 00: current processor */

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

    domid_t  domain;
    char     name[MAX_DOMAIN_NAME];
    s_time_t create_time;

    spinlock_t       page_alloc_lock; /* protects all the following fields  */
    struct list_head page_list;       /* linked list, of size tot_pages     */
    unsigned int     tot_pages;       /* number of pages currently possesed */
    unsigned int     max_pages;       /* maximum value for tot_pages        */
    unsigned int     xenheap_pages;   /* # pages allocated from Xen heap    */

    /* Scheduling. */
    struct list_head run_list;
    int              shutdown_code; /* code value from OS (if DF_SHUTDOWN). */
    s_time_t         lastschd;      /* time this domain was last scheduled */
    s_time_t         lastdeschd;    /* time this domain was last descheduled */
    s_time_t         cpu_time;      /* total CPU time received till now */
    s_time_t         wokenup;       /* time domain got woken up */
    struct ac_timer  timer;         /* one-shot timer for timeout values */
    s_time_t         min_slice;     /* minimum time before reschedule */
    void            *sched_priv;    /* scheduler-specific data */

    struct mm_struct mm;

    mm_segment_t addr_limit;

    struct thread_struct thread;
    struct domain *next_list, *next_hash;

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
    atomic_t pausecnt;
};

#include <asm/uaccess.h> /* for KERNEL_DS */

extern struct domain idle0_task;

extern struct domain *idle_task[NR_CPUS];
#define IDLE_DOMAIN_ID   (0x7FFFFFFFU)
#define is_idle_task(_p) (test_bit(DF_IDLETASK, &(_p)->flags))

#include <xen/slab.h>

void free_domain_struct(struct domain *d);
struct domain *alloc_domain_struct();

#define DOMAIN_DESTRUCTED (1<<31) /* assumes atomic_t is >= 32 bits */
#define put_domain(_d) \
  if ( atomic_dec_and_test(&(_d)->refcnt) ) domain_destruct(_d)
static inline int get_domain(struct domain *d)
{
    atomic_inc(&d->refcnt);
    return !(atomic_read(&d->refcnt) & DOMAIN_DESTRUCTED);
}
  
extern struct domain *do_createdomain(
    domid_t dom_id, unsigned int cpu);
extern int construct_dom0(struct domain *d, 
                          unsigned long alloc_start,
                          unsigned long alloc_end,
                          char *image_start, unsigned long image_len, 
                          char *initrd_start, unsigned long initrd_len,
                          char *cmdline);
extern int final_setup_guestos(struct domain *d, dom0_builddomain_t *);

struct domain *find_domain_by_id(domid_t dom);
struct domain *find_last_domain(void);
extern void domain_destruct(struct domain *d);
extern void domain_kill(struct domain *d);
extern void domain_crash(void);
extern void domain_shutdown(u8 reason);

void new_thread(struct domain *d,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info);

extern unsigned long wait_init_idle;
#define init_idle() clear_bit(smp_processor_id(), &wait_init_idle);

extern spinlock_t schedule_lock[NR_CPUS] __cacheline_aligned;

#define set_current_state(_s) do { current->state = (_s); } while (0)
void scheduler_init(void);
void schedulers_start(void);
void sched_add_domain(struct domain *d);
void sched_rem_domain(struct domain *d);
long sched_ctl(struct sched_ctl_cmd *);
long sched_adjdom(struct sched_adjdom_cmd *);
int  sched_id();
void init_idle_task(void);
void domain_wake(struct domain *d);
void domain_sleep(struct domain *d);
void pause_domain(struct domain *d);
void unpause_domain(struct domain *d);

void __enter_scheduler(void);

extern void switch_to(struct domain *prev, 
                      struct domain *next);

void domain_init(void);

int idle_cpu(int cpu); /* Is CPU 'cpu' idle right now? */

void startup_cpu_idle_loop(void);
void continue_cpu_idle_loop(void);

void continue_nonidle_task(void);

/* This task_hash and task_list are protected by the tasklist_lock. */
#define TASK_HASH_SIZE 256
#define TASK_HASH(_id) ((int)(_id)&(TASK_HASH_SIZE-1))
extern struct domain *task_hash[TASK_HASH_SIZE];
extern struct domain *task_list;

#define for_each_domain(_p) \
 for ( (_p) = task_list; (_p) != NULL; (_p) = (_p)->next_list )

#define DF_DONEFPUINIT  0 /* Has the FPU been initialised for this task?    */
#define DF_USEDFPU      1 /* Has this task used the FPU since last save?    */
#define DF_GUEST_STTS   2 /* Has the guest OS requested 'stts'?             */
#define DF_CONSTRUCTED  3 /* Has the guest OS been fully built yet?         */
#define DF_IDLETASK     4 /* Is this one of the per-CPU idle domains?       */
#define DF_PRIVILEGED   5 /* Is this domain privileged?                     */
#define DF_PHYSDEV      6 /* May this domain do IO to physical devices?     */
#define DF_BLOCKED      7 /* Domain is blocked waiting for an event.        */
#define DF_CTRLPAUSE    8 /* Domain is paused by controller software.       */
#define DF_SHUTDOWN     9 /* Guest shut itself down for some reason.        */
#define DF_CRASHED     10 /* Domain crashed inside Xen, cannot continue.    */
#define DF_DYING       11 /* Death rattle.                                  */
#define DF_RUNNING     12 /* Currently running on a CPU.                    */
#define DF_CPUPINNED   13 /* Disables auto-migration.                       */

static inline int domain_runnable(struct domain *d)
{
    return ( (atomic_read(&d->pausecnt) == 0) &&
             !(d->flags & ((1<<DF_BLOCKED)|(1<<DF_CTRLPAUSE)|
                           (1<<DF_SHUTDOWN)|(1<<DF_CRASHED))) );
}

static inline void domain_pause(struct domain *d)
{
    ASSERT(d != current);
    atomic_inc(&d->pausecnt);
    pause_domain(d);
}

static inline void domain_unpause(struct domain *d)
{
    ASSERT(d != current);
    if ( atomic_dec_and_test(&d->pausecnt) )
        unpause_domain(d);
}

static inline void domain_unblock(struct domain *d)
{
    if ( test_and_clear_bit(DF_BLOCKED, &d->flags) )
        domain_wake(d);
}

static inline void domain_pause_by_systemcontroller(struct domain *d)
{
    ASSERT(d != current);
    if ( !test_and_set_bit(DF_CTRLPAUSE, &d->flags) )
        pause_domain(d);
}

static inline void domain_unpause_by_systemcontroller(struct domain *d)
{
    if ( test_and_clear_bit(DF_CTRLPAUSE, &d->flags) )
        unpause_domain(d);
}


#define IS_PRIV(_d) (test_bit(DF_PRIVILEGED, &(_d)->flags))
#define IS_CAPABLE_PHYSDEV(_d) (test_bit(DF_PHYSDEV, &(_d)->flags))

#endif /* __SCHED_H__ */
