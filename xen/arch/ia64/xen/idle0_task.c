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

#define IDLE_VCPU(_v)    	     \
{                                    \
    processor:   0,                  \
    domain:      0                   \
}

struct mm_struct init_mm = INIT_MM(init_mm);
EXPORT_SYMBOL(init_mm);

/*
 * Initial task structure.
 *
 * We need to make sure that this is properly aligned due to the way process stacks are
 * handled. This is done by having a special ".data.init_task" section...
 */
union {
	struct {
		struct vcpu task;
	} s;
	unsigned long stack[KERNEL_STACK_SIZE/sizeof (unsigned long)];
} init_task_mem asm ("init_task") __attribute__((section(".data.init_task"))) = {{
	.task = IDLE_VCPU(init_task_mem.s.task)
}};

EXPORT_SYMBOL(init_task);

