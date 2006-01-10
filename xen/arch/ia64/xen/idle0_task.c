#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

#define INIT_MM(name) \
{			 					\
	.pgd		= swapper_pg_dir, 			\
	.mm_users	= ATOMIC_INIT(2), 			\
	.mm_count	= ATOMIC_INIT(1), 			\
	.page_table_lock =  SPIN_LOCK_UNLOCKED, 		\
	.mmlist		= LIST_HEAD_INIT(name.mmlist),		\
}

#define IDLE0_EXEC_DOMAIN(_ed,_d)    \
{                                    \
    processor:   0,                  \
    mm:          0,                  \
    thread:      INIT_THREAD,        \
    domain:      (_d)                \
}

#define IDLE0_DOMAIN(_t)             \
{                                    \
    domain_id:   IDLE_DOMAIN_ID,     \
    refcnt:      ATOMIC_INIT(1)      \
}

struct mm_struct init_mm = INIT_MM(init_mm);
EXPORT_SYMBOL(init_mm);

struct domain idle0_domain = IDLE0_DOMAIN(idle0_domain);
#if 0
struct vcpu idle0_vcpu = IDLE0_EXEC_DOMAIN(idle0_vcpu,
                                                         &idle0_domain);
#endif


/*
 * Initial task structure.
 *
 * We need to make sure that this is properly aligned due to the way process stacks are
 * handled. This is done by having a special ".data.init_task" section...
 */
union {
	struct {
		struct domain task;
	} s;
	unsigned long stack[KERNEL_STACK_SIZE/sizeof (unsigned long)];
} init_task_mem asm ("init_task") __attribute__((section(".data.init_task")));
// = {{
	;
//.task =		IDLE0_EXEC_DOMAIN(init_task_mem.s.task,&idle0_domain),
//};
//};

EXPORT_SYMBOL(init_task);

