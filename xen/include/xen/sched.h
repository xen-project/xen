#ifndef __SCHED_H__
#define __SCHED_H__

#define STACK_SIZE (2*PAGE_SIZE)

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <asm/regs.h>
#include <xen/smp.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <public/xen.h>
#include <public/dom0_ops.h>
#include <xen/list.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/delay.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <xen/spinlock.h>
#include <xen/grant_table.h>

extern unsigned long volatile jiffies;
extern rwlock_t domlist_lock;

struct domain;

/* A global pointer to the initial domain (DOM0). */
extern struct domain *dom0;

typedef struct event_channel_st
{
#define ECS_FREE         0 /* Channel is available for use.                  */
#define ECS_UNBOUND      1 /* Channel is waiting to bind to a remote domain. */
#define ECS_INTERDOMAIN  2 /* Channel is bound to another domain.            */
#define ECS_PIRQ         3 /* Channel is bound to a physical IRQ line.       */
#define ECS_VIRQ         4 /* Channel is bound to a virtual IRQ line.        */
    u16 state;
    union {
        struct {
            domid_t remote_domid;
        } __attribute__ ((packed)) unbound; /* state == ECS_UNBOUND */
        struct {
            u16            remote_port;
            struct domain *remote_dom;
        } __attribute__ ((packed)) interdomain; /* state == ECS_INTERDOMAIN */
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

    domid_t  id;
    s_time_t create_time;

    spinlock_t       page_alloc_lock; /* protects all the following fields  */
    struct list_head page_list;       /* linked list, of size tot_pages     */
    struct list_head xenpage_list;    /* linked list, of size xenheap_pages */
    unsigned int     tot_pages;       /* number of pages currently possesed */
    unsigned int     max_pages;       /* maximum value for tot_pages        */
    unsigned int     xenheap_pages;   /* # pages allocated from Xen heap    */

    /* Scheduling. */
    int              shutdown_code; /* code value from OS (if DF_SHUTDOWN). */
    s_time_t         lastschd;      /* time this domain was last scheduled */
    s_time_t         lastdeschd;    /* time this domain was last descheduled */
    s_time_t         cpu_time;      /* total CPU time received till now */
    s_time_t         wokenup;       /* time domain got woken up */
    struct ac_timer  timer;         /* one-shot timer for timeout values */
    void            *sched_priv;    /* scheduler-specific data */

    struct mm_struct mm;

    struct thread_struct thread;
    struct domain *next_list, *next_hash;

    /* Event channel information. */
    event_channel_t *event_channel;
    unsigned int     max_event_channel;
    spinlock_t       event_channel_lock;

    grant_table_t *grant_table;

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
#define IOBMP_SELBIT_LWORDS (IO_BITMAP_SIZE / 64)
    unsigned long *io_bitmap; /* Pointer to task's IO bitmap or NULL */

    unsigned long flags;
    unsigned long vm_assist;

    atomic_t refcnt;
    atomic_t pausecnt;
};

struct domain_setup_info
{
    unsigned long v_start;
    unsigned long v_kernstart;
    unsigned long v_kernend;
    unsigned long v_kernentry;

    unsigned int use_writable_pagetables;
};

#include <asm/uaccess.h> /* for KERNEL_DS */

extern struct domain idle0_task;

extern struct domain *idle_task[NR_CPUS];
#define IDLE_DOMAIN_ID   (0x7FFFU)
#define is_idle_task(_p) (test_bit(DF_IDLETASK, &(_p)->flags))

void free_domain_struct(struct domain *d);
struct domain *alloc_domain_struct();

#define DOMAIN_DESTRUCTED (1<<31) /* assumes atomic_t is >= 32 bits */
#define put_domain(_d) \
  if ( atomic_dec_and_test(&(_d)->refcnt) ) domain_destruct(_d)

/*
 * Use this when you don't have an existing reference to @d. It returns
 * FALSE if @d is being destructed.
 */
static always_inline int get_domain(struct domain *d)
{
    atomic_t old, new, seen = d->refcnt;
    do
    {
        old = seen;
        if ( unlikely(_atomic_read(old) & DOMAIN_DESTRUCTED) )
            return 0;
        _atomic_set(new, _atomic_read(old) + 1);
        seen = atomic_compareandswap(old, new, &d->refcnt);
    }
    while ( unlikely(_atomic_read(seen) != _atomic_read(old)) );
    return 1;
}

/*
 * Use this when you already have, or are borrowing, a reference to @d.
 * In this case we know that @d cannot be destructed under our feet.
 */
static inline void get_knownalive_domain(struct domain *d)
{
    atomic_inc(&d->refcnt);
    ASSERT(!(atomic_read(&d->refcnt) & DOMAIN_DESTRUCTED));
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

void __enter_scheduler(void);

extern void switch_to(struct domain *prev, 
                      struct domain *next);

void domain_init(void);

int idle_cpu(int cpu); /* Is CPU 'cpu' idle right now? */

void startup_cpu_idle_loop(void);
void continue_cpu_idle_loop(void);

void continue_nonidle_task(void);

/* This domain_hash and domain_list are protected by the domlist_lock. */
#define DOMAIN_HASH_SIZE 256
#define DOMAIN_HASH(_id) ((int)(_id)&(DOMAIN_HASH_SIZE-1))
extern struct domain *domain_hash[DOMAIN_HASH_SIZE];
extern struct domain *domain_list;

#define for_each_domain(_p) \
 for ( (_p) = domain_list; (_p) != NULL; (_p) = (_p)->next_list )

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
#define DF_MIGRATED    14 /* Domain migrated between CPUs.                  */ 

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
    domain_sleep(d);
}

static inline void domain_unpause(struct domain *d)
{
    ASSERT(d != current);
    if ( atomic_dec_and_test(&d->pausecnt) )
        domain_wake(d);
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
        domain_sleep(d);
}

static inline void domain_unpause_by_systemcontroller(struct domain *d)
{
    if ( test_and_clear_bit(DF_CTRLPAUSE, &d->flags) )
        domain_wake(d);
}


#define IS_PRIV(_d) (test_bit(DF_PRIVILEGED, &(_d)->flags))
#define IS_CAPABLE_PHYSDEV(_d) (test_bit(DF_PHYSDEV, &(_d)->flags))

#define VM_ASSIST(_d,_t) (test_bit((_t), &(_d)->vm_assist))

#include <xen/slab.h>
#include <asm/domain.h>

#endif /* __SCHED_H__ */
