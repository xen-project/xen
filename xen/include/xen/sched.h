#ifndef __SCHED_H__
#define __SCHED_H__

#define STACK_SIZE (2*PAGE_SIZE)

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/cache.h>
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
#include <xen/irq_cpustat.h>

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
#define ECS_IPI          5 /* Channel is bound to a virtual IPI line.        */
    u16 state;
    union {
        struct {
            domid_t remote_domid;
        } __attribute__ ((packed)) unbound; /* state == ECS_UNBOUND */
        struct {
            u16                 remote_port;
            struct exec_domain *remote_dom;
        } __attribute__ ((packed)) interdomain; /* state == ECS_INTERDOMAIN */
        u16 pirq; /* state == ECS_PIRQ */
        u16 virq; /* state == ECS_VIRQ */
        u32 ipi_edom; /* state == ECS_IPI */
    } u;
} event_channel_t;

int  init_event_channels(struct domain *d);
void destroy_event_channels(struct domain *d);
int  init_exec_domain_event_channels(struct exec_domain *ed);

struct exec_domain 
{
    u32 processor;

    vcpu_info_t *vcpu_info;

    struct domain *domain;
    struct exec_domain *ed_next_list;
    int eid;

    struct mm_struct mm;

    struct thread_struct thread;

    struct ac_timer  timer;         /* one-shot timer for timeout values */

    s_time_t         lastschd;      /* time this domain was last scheduled */
    s_time_t         lastdeschd;    /* time this domain was last descheduled */
    s_time_t         cpu_time;      /* total CPU time received till now */
    s_time_t         wokenup;       /* time domain got woken up */
    void            *ed_sched_priv;    /* scheduler-specific data */

    unsigned long ed_flags;

    u16 virq_to_evtchn[NR_VIRQS];

    atomic_t pausecnt;

};

#if 01
#define LOCK_BIGLOCK(_d) spin_lock(&(_d)->big_lock)
#define UNLOCK_BIGLOCK(_d) spin_unlock(&(_d)->big_lock)
#else
#define LOCK_BIGLOCK(_d) (void)(_d)
#define UNLOCK_BIGLOCK(_d)
#endif

struct domain {
    domid_t          id;
    s_time_t         create_time;

    shared_info_t   *shared_info;     /* shared data area */
    spinlock_t       time_lock;

    spinlock_t       big_lock;

    l1_pgentry_t    *mm_perdomain_pt;

    spinlock_t       page_alloc_lock; /* protects all the following fields  */
    struct list_head page_list;       /* linked list, of size tot_pages     */
    struct list_head xenpage_list;    /* linked list, of size xenheap_pages */
    unsigned int     tot_pages;       /* number of pages currently possesed */
    unsigned int     max_pages;       /* maximum value for tot_pages        */
    unsigned int     xenheap_pages;   /* # pages allocated from Xen heap    */

    /* Scheduling. */
    int              shutdown_code; /* code value from OS (if DF_SHUTDOWN). */
    void            *sched_priv;    /* scheduler-specific data */

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
    u32 pirq_mask[NR_PIRQS/32];

    /* Physical I/O */
    spinlock_t       pcidev_lock;
    struct list_head pcidev_list;

    unsigned long d_flags;
    unsigned long vm_assist;

    atomic_t refcnt;

    struct exec_domain *exec_domain[MAX_VIRT_CPUS];
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

extern struct domain idle0_domain;
extern struct exec_domain idle0_exec_domain;

extern struct exec_domain *idle_task[NR_CPUS];
#define IDLE_DOMAIN_ID   (0x7FFFU)
#define is_idle_task(_p) (test_bit(DF_IDLETASK, &(_p)->d_flags))

struct exec_domain *alloc_exec_domain_struct(struct domain *d,
                                             unsigned long vcpu);

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

void new_thread(struct exec_domain *d,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info);

extern unsigned long wait_init_idle;
#define init_idle() clear_bit(smp_processor_id(), &wait_init_idle);

#define set_current_state(_s) do { current->state = (_s); } while (0)
void scheduler_init(void);
void schedulers_start(void);
void sched_add_domain(struct exec_domain *);
void sched_rem_domain(struct exec_domain *);
long sched_ctl(struct sched_ctl_cmd *);
long sched_adjdom(struct sched_adjdom_cmd *);
int  sched_id();
void init_idle_task(void);
void domain_wake(struct exec_domain *d);
void domain_sleep(struct exec_domain *d);

void __enter_scheduler(void);

extern void switch_to(struct exec_domain *prev, 
                      struct exec_domain *next);

void domain_init(void);

int idle_cpu(int cpu); /* Is CPU 'cpu' idle right now? */

void startup_cpu_idle_loop(void);

unsigned long hypercall_create_continuation(
    unsigned int op, unsigned int nr_args, ...);
#define hypercall_preempt_check() \
    (unlikely(softirq_pending(smp_processor_id())))

/* This domain_hash and domain_list are protected by the domlist_lock. */
#define DOMAIN_HASH_SIZE 256
#define DOMAIN_HASH(_id) ((int)(_id)&(DOMAIN_HASH_SIZE-1))
extern struct domain *domain_hash[DOMAIN_HASH_SIZE];
extern struct domain *domain_list;

#define for_each_domain(_p) \
 for ( (_p) = domain_list; (_p) != NULL; (_p) = (_p)->next_list )

#define for_each_exec_domain(_d,_ed) \
 for ( (_ed) = _d->exec_domain[0]; (_ed) != NULL; (_ed) = (_ed)->ed_next_list )

#define EDF_DONEFPUINIT  0 /* Has the FPU been initialised for this task?    */
#define EDF_USEDFPU      1 /* Has this task used the FPU since last save?    */
#define EDF_GUEST_STTS   2 /* Has the guest OS requested 'stts'?             */
#define  DF_CONSTRUCTED  3 /* Has the guest OS been fully built yet?         */
#define  DF_IDLETASK     4 /* Is this one of the per-CPU idle domains?       */
#define  DF_PRIVILEGED   5 /* Is this domain privileged?                     */
#define  DF_PHYSDEV      6 /* May this domain do IO to physical devices?     */
#define EDF_BLOCKED      7 /* Domain is blocked waiting for an event.        */
#define EDF_CTRLPAUSE    8 /* Domain is paused by controller software.       */
#define  DF_SHUTDOWN     9 /* Guest shut itself down for some reason.        */
#define  DF_CRASHED     10 /* Domain crashed inside Xen, cannot continue.    */
#define  DF_DYING       11 /* Death rattle.                                  */
#define EDF_RUNNING     12 /* Currently running on a CPU.                    */
#define EDF_CPUPINNED   13 /* Disables auto-migration.                       */
#define EDF_MIGRATED    14 /* Domain migrated between CPUs.                  */

static inline int domain_runnable(struct exec_domain *d)
{
    return ( (atomic_read(&d->pausecnt) == 0) &&
             !(d->ed_flags & ((1<<EDF_BLOCKED)|(1<<EDF_CTRLPAUSE))) &&
             !(d->domain->d_flags & ((1<<DF_SHUTDOWN)|(1<<DF_CRASHED))) );
}

static inline void exec_domain_pause(struct exec_domain *ed)
{
    ASSERT(ed != current);
    atomic_inc(&ed->pausecnt);
    domain_sleep(ed);
}

static inline void domain_pause(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain(d, ed)
        exec_domain_pause(ed);
}

static inline void exec_domain_unpause(struct exec_domain *ed)
{
    ASSERT(ed != current);
    if ( atomic_dec_and_test(&ed->pausecnt) )
        domain_wake(ed);
}

static inline void domain_unpause(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain(d, ed)
        exec_domain_unpause(ed);
}

static inline void exec_domain_unblock(struct exec_domain *ed)
{
    if ( test_and_clear_bit(EDF_BLOCKED, &ed->ed_flags) )
        domain_wake(ed);
}

static inline void domain_unblock(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain(d, ed)
        exec_domain_unblock(ed);
}

static inline void domain_pause_by_systemcontroller(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain(d, ed) {
        ASSERT(ed != current);
        if ( !test_and_set_bit(EDF_CTRLPAUSE, &ed->ed_flags) )
            domain_sleep(ed);
    }
}

static inline void domain_unpause_by_systemcontroller(struct domain *d)
{
    struct exec_domain *ed;

    for_each_exec_domain(d, ed) {
        if ( test_and_clear_bit(EDF_CTRLPAUSE, &ed->ed_flags) )
            domain_wake(ed);
    }
}


#define IS_PRIV(_d) (test_bit(DF_PRIVILEGED, &(_d)->d_flags))
#define IS_CAPABLE_PHYSDEV(_d) (test_bit(DF_PHYSDEV, &(_d)->d_flags))

#define VM_ASSIST(_d,_t) (test_bit((_t), &(_d)->vm_assist))

#include <xen/slab.h>
#include <xen/domain.h>

#endif /* __SCHED_H__ */
