/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <linux/thread_info.h>

extern void arch_do_createdomain(struct exec_domain *);

extern int arch_final_setup_guestos(
    struct exec_domain *, full_execution_context_t *);

extern void domain_relinquish_memory(struct domain *);

struct arch_domain {
    struct mm_struct *active_mm;
    struct mm_struct *mm;
    int metaphysical_rid;
    int starting_rid;		/* first RID assigned to domain */
    int ending_rid;		/* one beyond highest RID assigned to domain */
    int rid_bits;		/* number of virtual rid bits (default: 18) */
    int breakimm;
    u64 xen_vastart;
    u64 xen_vaend;
    u64 shared_info_va;
};
#define metaphysical_rid arch.metaphysical_rid
#define starting_rid arch.starting_rid
#define ending_rid arch.ending_rid
#define rid_bits arch.rid_bits
#define breakimm arch.breakimm
#define xen_vastart arch.xen_vastart
#define xen_vaend arch.xen_vaend
#define shared_info_va arch.shared_info_va

struct arch_exec_domain {
    void *regs;	/* temporary until find a better way to do privops */
    struct thread_struct _thread;
    struct mm_struct *active_mm;
};
#define active_mm arch.active_mm
#define thread arch._thread

// FOLLOWING FROM linux-2.6.7/include/sched.h

struct mm_struct {
	struct vm_area_struct * mmap;		/* list of VMAs */
#ifndef XEN
	struct rb_root mm_rb;
#endif
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	unsigned long free_area_cache;		/* first hole */
	pgd_t * pgd;
	atomic_t mm_users;			/* How many users with user space? */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	int map_count;				/* number of VMAs */
#ifndef XEN
	struct rw_semaphore mmap_sem;
#endif
	spinlock_t page_table_lock;		/* Protects task page tables and mm->rss */

	struct list_head mmlist;		/* List of all active mm's.  These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long rss, total_vm, locked_vm;
	unsigned long def_flags;

	unsigned long saved_auxv[40]; /* for /proc/PID/auxv */

	unsigned dumpable:1;
#ifdef CONFIG_HUGETLB_PAGE
	int used_hugetlb;
#endif
#ifndef XEN
	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	mm_context_t context;

	/* coredumping support */
	int core_waiters;
	struct completion *core_startup_done, core_done;

	/* aio bits */
	rwlock_t		ioctx_list_lock;
	struct kioctx		*ioctx_list;

	struct kioctx		default_kioctx;
#endif
};

extern struct mm_struct init_mm;

#include <asm/uaccess.h> /* for KERNEL_DS */
#include <asm/pgtable.h>

#endif /* __ASM_DOMAIN_H__ */
