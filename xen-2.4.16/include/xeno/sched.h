#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/spinlock.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <xeno/smp.h>
#include <asm/processor.h>
#include <asm/current.h>
#include <hypervisor-ifs/hypervisor-if.h>
#include <xeno/dom0_ops.h>

extern unsigned long volatile jiffies;
extern rwlock_t tasklist_lock;

#include <xeno/spinlock.h>

struct mm_struct {
    unsigned long cpu_vm_mask;
    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l2_pgentry_t *perdomain_pt;
    pagetable_t  pagetable;
    /* Current LDT selector. */
    unsigned int ldt_sel;
    /* Next entry is passed to LGDT on domain switch. */
    char gdt[6];
};

/* Convenient accessor for mm.gdt. */
#define SET_GDT_ENTRIES(_p, _e) ((*(u16 *)((_p)->mm.gdt + 0)) = (_e))
#define SET_GDT_ADDRESS(_p, _a) ((*(u32 *)((_p)->mm.gdt + 2)) = (_a))
#define GET_GDT_ENTRIES(_p)     ((*(u16 *)((_p)->mm.gdt + 0)))
#define GET_GDT_ADDRESS(_p)     ((*(u32 *)((_p)->mm.gdt + 2)))

extern struct mm_struct init_mm;
#define IDLE0_MM                                                    \
{                                                                   \
    cpu_vm_mask: 0,                                                 \
    perdomain_pt: 0,                                                \
    pagetable:   mk_pagetable(__pa(idle0_pg_table))                 \
}

#define _HYP_EVENT_NEED_RESCHED 0
#define _HYP_EVENT_NET_RX       1
#define _HYP_EVENT_DIE          2
#define _HYP_EVENT_BLK_RX       3

#define PF_DONEFPUINIT  0x1  /* Has the FPU been initialised for this task? */
#define PF_USEDFPU      0x2  /* Has this task used the FPU since last save? */
#define PF_GUEST_STTS   0x4  /* Has the guest OS requested 'stts'?          */

#include <xeno/vif.h>
#include <xeno/block.h>

struct task_struct {

    int processor;
    int state;
	int hyp_events;
    unsigned int domain;

    /* An unsafe pointer into a shared data area. */
    shared_info_t *shared_info;
    
    struct list_head pg_head;
    unsigned int tot_pages;

    /* Network I/O */
    net_ring_t *net_ring_base;
    net_vif_t *net_vif_list[MAX_GUEST_VIFS];
    int num_net_vifs;

    /* Block I/O */
    blk_ring_t *blk_ring_base;
    struct list_head io_done_queue;
    spinlock_t io_done_queue_lock;

    int has_cpu, policy, counter;

    struct list_head run_list;
    
    struct mm_struct mm;

    mm_segment_t addr_limit;        /* thread address space:
                                       0-0xBFFFFFFF for user-thead
                                       0-0xFFFFFFFF for kernel-thread
                                     */

    /*
     * active_mm stays for now. It's entangled in the tricky TLB flushing
     * stuff which I haven't addressed yet. It stays until I'm man enough
     * to venture in.
     */
    struct mm_struct *active_mm;
    struct thread_struct thread;
    struct task_struct *prev_task, *next_task;
    
    unsigned long flags;
};

/*
 * domain states 
 * TASK_RUNNING:         Domain is runable and should be on a run queue
 * TASK_INTERRUPTIBLE:   Domain is blocked by may be woken up by an event
 *                       or expiring timer
 * TASK_UNINTERRUPTIBLE: Domain is blocked but may not be woken up by an
 *                       arbitrary event or timer.
 * TASK_WAIT:            Domains CPU allocation expired.
 * TASK_STOPPED:         not really used in Xen
 * TASK_DYING:           Domain is about to cross over to the land of the dead.
 */

#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_WAIT				4
#define TASK_DYING              16
/* #define TASK_STOPPED            8  not really used */

#define SCHED_YIELD             0x10

#include <asm/uaccess.h> /* for KERNEL_DS */

#define IDLE0_TASK(_t)           \
{                                \
    processor:   0,              \
    domain:      IDLE_DOMAIN_ID, \
    state:       TASK_RUNNING,   \
    has_cpu:     0,              \
    mm:          IDLE0_MM,       \
    addr_limit:  KERNEL_DS,      \
    active_mm:   &idle0_task.mm, \
    thread:      INIT_THREAD,    \
    prev_task:   &(_t),          \
    next_task:   &(_t)           \
}

#define IDLE_DOMAIN_ID   (~0)
#define is_idle_task(_p) ((_p)->domain == IDLE_DOMAIN_ID)

#ifndef IDLE0_TASK_SIZE
#define IDLE0_TASK_SIZE	2048*sizeof(long)
#endif

union task_union {
    struct task_struct task;
    unsigned long stack[IDLE0_TASK_SIZE/sizeof(long)];
};

extern union task_union idle0_task_union;
extern struct task_struct first_task_struct;

extern struct task_struct *do_newdomain(unsigned int dom_id, unsigned int cpu);
extern int setup_guestos(struct task_struct *p, dom0_newdomain_t *params);
extern int final_setup_guestos(struct task_struct *p, dom_meminfo_t *);

struct task_struct *find_domain_by_id(unsigned int dom);
extern void release_task(struct task_struct *);
extern void kill_domain(void);
extern void kill_domain_with_errmsg(const char *err);
extern long kill_other_domain(unsigned int dom);

/* arch/process.c */
void new_thread(struct task_struct *p,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info);
extern void flush_thread(void);
extern void exit_thread(void);

/* Linux puts these here for some reason! */
extern int request_irq(unsigned int,
                       void (*handler)(int, void *, struct pt_regs *),
                       unsigned long, const char *, void *);
extern void free_irq(unsigned int, void *);

extern unsigned long wait_init_idle;
#define init_idle() clear_bit(smp_processor_id(), &wait_init_idle);



/*
 * Scheduler functions (in schedule.c)
 */
#define set_current_state(_s) do { current->state = (_s); } while (0)
#define MAX_SCHEDULE_TIMEOUT LONG_MAX
void scheduler_init(void);
void schedulers_start(void);
void sched_add_domain(struct task_struct *p);
void sched_rem_domain(struct task_struct *p);
int  wake_up(struct task_struct *p);
long schedule_timeout(long timeout);
long do_yield(void);
void reschedule(struct task_struct *p);
asmlinkage void schedule(void);


#define signal_pending(_p) ((_p)->hyp_events || \
                            (_p)->shared_info->events)

void domain_init(void);

void cpu_idle(void);

#define REMOVE_LINKS(p) do { \
        (p)->next_task->prev_task = (p)->prev_task; \
        (p)->prev_task->next_task = (p)->next_task; \
        } while (0)

#define SET_LINKS(p) do { \
        (p)->next_task = &idle0_task; \
        (p)->prev_task = idle0_task.prev_task; \
        idle0_task.prev_task->next_task = (p); \
        idle0_task.prev_task = (p); \
        } while (0)

extern void update_process_times(int user);

#endif
