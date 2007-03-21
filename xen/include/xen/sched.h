
#ifndef __SCHED_H__
#define __SCHED_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/smp.h>
#include <xen/shared.h>
#include <public/xen.h>
#include <public/domctl.h>
#include <public/vcpu.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/grant_table.h>
#include <xen/rangeset.h>
#include <asm/domain.h>
#include <xen/xenoprof.h>
#include <xen/rcupdate.h>
#include <xen/irq.h>

#ifdef CONFIG_COMPAT
#include <compat/vcpu.h>
DEFINE_XEN_GUEST_HANDLE(vcpu_runstate_info_compat_t);
#endif

extern unsigned long volatile jiffies;

/* A global pointer to the initial domain (DOM0). */
extern struct domain *dom0;

#ifndef CONFIG_COMPAT
#define MAX_EVTCHNS(d)     NR_EVENT_CHANNELS
#else
#define MAX_EVTCHNS(d)     (!IS_COMPAT(d) ? \
                            NR_EVENT_CHANNELS : \
                            sizeof(unsigned int) * sizeof(unsigned int) * 64)
#endif
#define EVTCHNS_PER_BUCKET 128
#define NR_EVTCHN_BUCKETS  (NR_EVENT_CHANNELS / EVTCHNS_PER_BUCKET)

struct evtchn
{
#define ECS_FREE         0 /* Channel is available for use.                  */
#define ECS_RESERVED     1 /* Channel is reserved.                           */
#define ECS_UNBOUND      2 /* Channel is waiting to bind to a remote domain. */
#define ECS_INTERDOMAIN  3 /* Channel is bound to another domain.            */
#define ECS_PIRQ         4 /* Channel is bound to a physical IRQ line.       */
#define ECS_VIRQ         5 /* Channel is bound to a virtual IRQ line.        */
#define ECS_IPI          6 /* Channel is bound to a virtual IPI line.        */
    u8  state;             /* ECS_* */
    u8  consumer_is_xen;   /* Consumed by Xen or by guest? */
    u16 notify_vcpu_id;    /* VCPU for local delivery notification */
    union {
        struct {
            domid_t remote_domid;
        } unbound;     /* state == ECS_UNBOUND */
        struct {
            u16            remote_port;
            struct domain *remote_dom;
        } interdomain; /* state == ECS_INTERDOMAIN */
        u16 pirq;      /* state == ECS_PIRQ */
        u16 virq;      /* state == ECS_VIRQ */
    } u;
};

int  evtchn_init(struct domain *d);
void evtchn_destroy(struct domain *d);

struct vcpu 
{
    int              vcpu_id;

    int              processor;

    vcpu_info_t     *vcpu_info;

    struct domain   *domain;

    struct vcpu     *next_in_list;

    uint64_t         periodic_period;
    uint64_t         periodic_last_event;
    struct timer     periodic_timer;
    struct timer     singleshot_timer;

    struct timer     poll_timer;    /* timeout for SCHEDOP_poll */

    void            *sched_priv;    /* scheduler-specific data */

    struct vcpu_runstate_info runstate;
#ifndef CONFIG_COMPAT
# define runstate_guest(v) ((v)->runstate_guest)
    XEN_GUEST_HANDLE(vcpu_runstate_info_t) runstate_guest; /* guest address */
#else
# define runstate_guest(v) ((v)->runstate_guest.native)
    union {
        XEN_GUEST_HANDLE(vcpu_runstate_info_t) native;
        XEN_GUEST_HANDLE(vcpu_runstate_info_compat_t) compat;
    } runstate_guest; /* guest address */
#endif

    unsigned long    vcpu_flags;

    spinlock_t       pause_lock;
    unsigned int     pause_count;

    u16              virq_to_evtchn[NR_VIRQS];

    /* Bitmask of CPUs on which this VCPU may run. */
    cpumask_t        cpu_affinity;

    unsigned long    nmi_addr;      /* NMI callback address. */

    /* Bitmask of CPUs which are holding onto this VCPU's state. */
    cpumask_t        vcpu_dirty_cpumask;

    struct arch_vcpu arch;
};

/* Per-domain lock can be recursively acquired in fault handlers. */
#define LOCK_BIGLOCK(_d) spin_lock_recursive(&(_d)->big_lock)
#define UNLOCK_BIGLOCK(_d) spin_unlock_recursive(&(_d)->big_lock)

struct domain
{
    domid_t          domain_id;

    shared_info_t   *shared_info;     /* shared data area */

    spinlock_t       big_lock;

    spinlock_t       page_alloc_lock; /* protects all the following fields  */
    struct list_head page_list;       /* linked list, of size tot_pages     */
    struct list_head xenpage_list;    /* linked list, of size xenheap_pages */
    unsigned int     tot_pages;       /* number of pages currently possesed */
    unsigned int     max_pages;       /* maximum value for tot_pages        */
    unsigned int     xenheap_pages;   /* # pages allocated from Xen heap    */

    /* Scheduling. */
    int              shutdown_code; /* code value from OS (if DOMF_shutdown) */
    void            *sched_priv;    /* scheduler-specific data */

    struct domain   *next_in_list;
    struct domain   *next_in_hashbucket;

    struct list_head rangesets;
    spinlock_t       rangesets_lock;

    /* Event channel information. */
    struct evtchn   *evtchn[NR_EVTCHN_BUCKETS];
    spinlock_t       evtchn_lock;

    struct grant_table *grant_table;

    /*
     * Interrupt to event-channel mappings. Updates should be protected by the 
     * domain's event-channel spinlock. Read accesses can also synchronise on 
     * the lock, but races don't usually matter.
     */
    u16              pirq_to_evtchn[NR_IRQS];
    DECLARE_BITMAP(pirq_mask, NR_IRQS);

    /* I/O capabilities (access to IRQs and memory-mapped I/O). */
    struct rangeset *iomem_caps;
    struct rangeset *irq_caps;

    unsigned long    domain_flags;

    /* Boolean: Is this an HVM guest? */
    char             is_hvm;

    /* Boolean: Is this guest fully privileged (aka dom0)? */
    char             is_privileged;

    spinlock_t       pause_lock;
    unsigned int     pause_count;

    unsigned long    vm_assist;

    atomic_t         refcnt;

    struct vcpu *vcpu[MAX_VIRT_CPUS];

    /* Bitmask of CPUs which are holding onto this domain's state. */
    cpumask_t        domain_dirty_cpumask;

    struct arch_domain arch;

    void *ssid; /* sHype security subject identifier */

    /* Control-plane tools handle for this domain. */
    xen_domain_handle_t handle;

    /* OProfile support. */
    struct xenoprof *xenoprof;
    int32_t time_offset_seconds;

    struct rcu_head rcu;
};

struct domain_setup_info
{
    /* Initialised by caller. */
    unsigned long image_addr;
    unsigned long image_len;
    /* Initialised by loader: Public. */
    unsigned long v_start;
    unsigned long v_end;
    unsigned long v_kernstart;
    unsigned long v_kernend;
    unsigned long v_kernentry;
#define PAEKERN_no           0
#define PAEKERN_yes          1
#define PAEKERN_extended_cr3 2
#define PAEKERN_bimodal      3
    unsigned int  pae_kernel;
    /* Initialised by loader: Private. */
    unsigned long elf_paddr_offset;
    unsigned int  load_symtab;
    unsigned long symtab_addr;
    unsigned long symtab_len;
};

extern struct vcpu *idle_vcpu[NR_CPUS];
#define IDLE_DOMAIN_ID   (0x7FFFU)
#define is_idle_domain(d) ((d)->domain_id == IDLE_DOMAIN_ID)
#define is_idle_vcpu(v)   (is_idle_domain((v)->domain))

#define DOMAIN_DESTROYED (1<<31) /* assumes atomic_t is >= 32 bits */
#define put_domain(_d) \
  if ( atomic_dec_and_test(&(_d)->refcnt) ) domain_destroy(_d)

/*
 * Use this when you don't have an existing reference to @d. It returns
 * FALSE if @d is being destroyed.
 */
static always_inline int get_domain(struct domain *d)
{
    atomic_t old, new, seen = d->refcnt;
    do
    {
        old = seen;
        if ( unlikely(_atomic_read(old) & DOMAIN_DESTROYED) )
            return 0;
        _atomic_set(new, _atomic_read(old) + 1);
        seen = atomic_compareandswap(old, new, &d->refcnt);
    }
    while ( unlikely(_atomic_read(seen) != _atomic_read(old)) );
    return 1;
}

/*
 * Use this when you already have, or are borrowing, a reference to @d.
 * In this case we know that @d cannot be destroyed under our feet.
 */
static inline void get_knownalive_domain(struct domain *d)
{
    atomic_inc(&d->refcnt);
    ASSERT(!(atomic_read(&d->refcnt) & DOMAIN_DESTROYED));
}

/* Obtain a reference to the currently-running domain. */
static inline struct domain *get_current_domain(void)
{
    struct domain *d = current->domain;
    get_knownalive_domain(d);
    return d;
}

struct domain *domain_create(domid_t domid, unsigned int domcr_flags);
 /* DOMCRF_hvm: Create an HVM domain, as opposed to a PV domain. */
#define _DOMCRF_hvm 0
#define DOMCRF_hvm  (1U<<_DOMCRF_hvm)

int construct_dom0(
    struct domain *d,
    unsigned long image_start, unsigned long image_len, 
    unsigned long initrd_start, unsigned long initrd_len,
    char *cmdline);

/*
 * rcu_lock_domain_by_id() is more efficient than get_domain_by_id().
 * This is the preferred function if the returned domain reference
 * is short lived,  but it cannot be used if the domain reference needs 
 * to be kept beyond the current scope (e.g., across a softirq).
 * The returned domain reference must be discarded using rcu_unlock_domain().
 */
struct domain *rcu_lock_domain_by_id(domid_t dom);

/* Finish a RCU critical region started by rcu_lock_domain_by_id(). */
static inline void rcu_unlock_domain(struct domain *d)
{
    rcu_read_unlock(&domlist_read_lock);
}

static inline struct domain *rcu_lock_domain(struct domain *d)
{
    rcu_read_lock(d);
    return d;
}

static inline struct domain *rcu_lock_current_domain(void)
{
    return rcu_lock_domain(current->domain);
}

struct domain *get_domain_by_id(domid_t dom);
void domain_destroy(struct domain *d);
void domain_kill(struct domain *d);
void domain_shutdown(struct domain *d, u8 reason);
void domain_pause_for_debugger(void);

/*
 * Mark specified domain as crashed. This function always returns, even if the
 * caller is the specified domain. The domain is not synchronously descheduled
 * from any processor.
 */
void __domain_crash(struct domain *d);
#define domain_crash(d) do {                                              \
    printk("domain_crash called from %s:%d\n", __FILE__, __LINE__);       \
    __domain_crash(d);                                                    \
} while (0)

/*
 * Mark current domain as crashed and synchronously deschedule from the local
 * processor. This function never returns.
 */
void __domain_crash_synchronous(void) __attribute__((noreturn));
#define domain_crash_synchronous() do {                                   \
    printk("domain_crash_sync called from %s:%d\n", __FILE__, __LINE__);  \
    __domain_crash_synchronous();                                         \
} while (0)

#define set_current_state(_s) do { current->state = (_s); } while (0)
void scheduler_init(void);
int  sched_init_vcpu(struct vcpu *v, unsigned int processor);
void sched_destroy_vcpu(struct vcpu *v);
int  sched_init_domain(struct domain *d);
void sched_destroy_domain(struct domain *d);
long sched_adjust(struct domain *, struct xen_domctl_scheduler_op *);
int  sched_id(void);
void vcpu_wake(struct vcpu *d);
void vcpu_sleep_nosync(struct vcpu *d);
void vcpu_sleep_sync(struct vcpu *d);

/*
 * Force synchronisation of given VCPU's state. If it is currently descheduled,
 * this call will ensure that all its state is committed to memory and that
 * no CPU is using critical state (e.g., page tables) belonging to the VCPU.
 */
void sync_vcpu_execstate(struct vcpu *v);

/*
 * Called by the scheduler to switch to another VCPU. This function must
 * call context_saved(@prev) when the local CPU is no longer running in
 * @prev's context, and that context is saved to memory. Alternatively, if
 * implementing lazy context switching, it suffices to ensure that invoking
 * sync_vcpu_execstate() will switch and commit @prev's state.
 */
void context_switch(
    struct vcpu *prev, 
    struct vcpu *next);

/*
 * As described above, context_switch() must call this function when the
 * local CPU is no longer running in @prev's context, and @prev's context is
 * saved to memory. Alternatively, if implementing lazy context switching,
 * ensure that invoking sync_vcpu_execstate() will switch and commit @prev.
 */
void context_saved(struct vcpu *prev);

/* Called by the scheduler to continue running the current VCPU. */
void continue_running(
    struct vcpu *same);

void startup_cpu_idle_loop(void);

/*
 * Creates a continuation to resume the current hypercall. The caller should
 * return immediately, propagating the value returned from this invocation.
 * The format string specifies the types and number of hypercall arguments.
 * It contains one character per argument as follows:
 *  'i' [unsigned] {char, int}
 *  'l' [unsigned] long
 *  'h' guest handle (XEN_GUEST_HANDLE(foo))
 */
unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...);

#define hypercall_preempt_check() (unlikely(    \
        softirq_pending(smp_processor_id()) |   \
        local_events_need_delivery()            \
    ))

/* Protect updates/reads (resp.) of domain_list and domain_hash. */
extern spinlock_t domlist_update_lock;
extern rcu_read_lock_t domlist_read_lock;

extern struct domain *domain_list;

/* Caller must hold the domlist_read_lock or domlist_update_lock. */
#define for_each_domain(_d)                     \
 for ( (_d) = rcu_dereference(domain_list);     \
       (_d) != NULL;                            \
       (_d) = rcu_dereference((_d)->next_in_list )) \

#define for_each_vcpu(_d,_v)                    \
 for ( (_v) = (_d)->vcpu[0];                    \
       (_v) != NULL;                            \
       (_v) = (_v)->next_in_list )

/*
 * Per-VCPU flags (vcpu_flags).
 */
 /* Has the FPU been initialised? */
#define _VCPUF_fpu_initialised 0
#define VCPUF_fpu_initialised  (1UL<<_VCPUF_fpu_initialised)
 /* Has the FPU been used since it was last saved? */
#define _VCPUF_fpu_dirtied     1
#define VCPUF_fpu_dirtied      (1UL<<_VCPUF_fpu_dirtied)
 /* Domain is blocked waiting for an event. */
#define _VCPUF_blocked         2
#define VCPUF_blocked          (1UL<<_VCPUF_blocked)
 /* Currently running on a CPU? */
#define _VCPUF_running         3
#define VCPUF_running          (1UL<<_VCPUF_running)
 /* Initialization completed. */
#define _VCPUF_initialised     4
#define VCPUF_initialised      (1UL<<_VCPUF_initialised)
 /* VCPU is offline. */
#define _VCPUF_down            5
#define VCPUF_down             (1UL<<_VCPUF_down)
 /* NMI callback pending for this VCPU? */
#define _VCPUF_nmi_pending     8
#define VCPUF_nmi_pending      (1UL<<_VCPUF_nmi_pending)
 /* Avoid NMI reentry by allowing NMIs to be masked for short periods. */
#define _VCPUF_nmi_masked      9
#define VCPUF_nmi_masked       (1UL<<_VCPUF_nmi_masked)
 /* VCPU is polling a set of event channels (SCHEDOP_poll). */
#define _VCPUF_polling         10
#define VCPUF_polling          (1UL<<_VCPUF_polling)
 /* VCPU is paused by the hypervisor? */
#define _VCPUF_paused          11
#define VCPUF_paused           (1UL<<_VCPUF_paused)
 /* VCPU is blocked awaiting an event to be consumed by Xen. */
#define _VCPUF_blocked_in_xen  12
#define VCPUF_blocked_in_xen   (1UL<<_VCPUF_blocked_in_xen)
 /* VCPU affinity has changed: migrating to a new CPU. */
#define _VCPUF_migrating       13
#define VCPUF_migrating        (1UL<<_VCPUF_migrating)

/*
 * Per-domain flags (domain_flags).
 */
 /* Guest shut itself down for some reason. */
#define _DOMF_shutdown         0
#define DOMF_shutdown          (1UL<<_DOMF_shutdown)
 /* Death rattle. */
#define _DOMF_dying            1
#define DOMF_dying             (1UL<<_DOMF_dying)
 /* Domain is paused by controller software. */
#define _DOMF_ctrl_pause       2
#define DOMF_ctrl_pause        (1UL<<_DOMF_ctrl_pause)
 /* Domain is being debugged by controller software. */
#define _DOMF_debugging        3
#define DOMF_debugging         (1UL<<_DOMF_debugging)
 /* Are any VCPUs polling event channels (SCHEDOP_poll)? */
#define _DOMF_polling          4
#define DOMF_polling           (1UL<<_DOMF_polling)
 /* Domain is paused by the hypervisor? */
#define _DOMF_paused           5
#define DOMF_paused            (1UL<<_DOMF_paused)
 /* Domain is a compatibility one? */
#define _DOMF_compat           6
#define DOMF_compat            (1UL<<_DOMF_compat)

static inline int vcpu_runnable(struct vcpu *v)
{
    return ( !(v->vcpu_flags &
               ( VCPUF_blocked |
                 VCPUF_down |
                 VCPUF_paused |
                 VCPUF_blocked_in_xen |
                 VCPUF_migrating )) &&
             !(v->domain->domain_flags &
               ( DOMF_shutdown |
                 DOMF_ctrl_pause |
                 DOMF_paused )));
}

void vcpu_pause(struct vcpu *v);
void vcpu_pause_nosync(struct vcpu *v);
void domain_pause(struct domain *d);
void vcpu_unpause(struct vcpu *v);
void domain_unpause(struct domain *d);
void domain_pause_by_systemcontroller(struct domain *d);
void domain_unpause_by_systemcontroller(struct domain *d);
void cpu_init(void);

void vcpu_force_reschedule(struct vcpu *v);
int vcpu_set_affinity(struct vcpu *v, cpumask_t *affinity);

void vcpu_runstate_get(struct vcpu *v, struct vcpu_runstate_info *runstate);

static inline void vcpu_unblock(struct vcpu *v)
{
    if ( test_and_clear_bit(_VCPUF_blocked, &v->vcpu_flags) )
        vcpu_wake(v);
}

#define IS_PRIV(_d) ((_d)->is_privileged)

#ifdef CONFIG_COMPAT
#define IS_COMPAT(_d)                                       \
    (test_bit(_DOMF_compat, &(_d)->domain_flags))
#else
#define IS_COMPAT(_d) 0
#endif

#define VM_ASSIST(_d,_t) (test_bit((_t), &(_d)->vm_assist))

#define is_hvm_domain(d) ((d)->is_hvm)
#define is_hvm_vcpu(v)   (is_hvm_domain(v->domain))

#endif /* __SCHED_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
