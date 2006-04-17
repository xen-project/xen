#include <xen/config.h>
#include <xen/sched.h>
#include <asm/desc.h>

#define IDLE_VCPU(_v)    	     \
{                                    \
    processor:   0,                  \
    domain:      0                   \
}

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

