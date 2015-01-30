#include <mini-os/sched.h>
#include <mini-os/xmalloc.h>
#include <mini-os/console.h>

void arm_start_thread(void);

/* The AAPCS requires the callee (e.g. __arch_switch_threads) to preserve r4-r11. */
#define CALLEE_SAVED_REGISTERS 8

/* Architecture specific setup of thread creation */
struct thread* arch_create_thread(char *name, void (*function)(void *),
                                  void *data)
{
    struct thread *thread;

    thread = xmalloc(struct thread);
    /* We can't use lazy allocation here since the trap handler runs on the stack */
    thread->stack = (char *)alloc_pages(STACK_SIZE_PAGE_ORDER);
    thread->name = name;
    printk("Thread \"%s\": pointer: 0x%p, stack: 0x%p\n", name, thread,
            thread->stack);

    /* Save pointer to the thread on the stack, used by current macro */
    *((unsigned long *)thread->stack) = (unsigned long)thread;

    /* Push the details to pass to arm_start_thread onto the stack. */
    int *sp = (int *) (thread->stack + STACK_SIZE);
    *(--sp) = (int) function;
    *(--sp) = (int) data;

    /* We leave room for the 8 callee-saved registers which we will
     * try to restore on thread switch, even though they're not needed
     * for the initial switch. */
    thread->sp = (unsigned long) sp - 4 * CALLEE_SAVED_REGISTERS;

    thread->ip = (unsigned long) arm_start_thread;

    return thread;
}

void run_idle_thread(void)
{
    __asm__ __volatile__ ("mov sp, %0; bx %1"::
            "r"(idle_thread->sp + 4 * CALLEE_SAVED_REGISTERS),
            "r"(idle_thread->ip));
    /* Never arrive here! */
}
