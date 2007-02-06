#ifndef __SCHED_H__
#define __SCHED_H__

#include <list.h>
#include <time.h>
#include <arch_sched.h>

struct thread
{
    char *name;
    char *stack;
#if !defined(__ia64__)
    unsigned long sp;  /* Stack pointer */
    unsigned long ip;  /* Instruction pointer */
#else /* !defined(__ia64__) */
    thread_regs_t regs;
#endif /* !defined(__ia64__) */
    struct list_head thread_list;
    u32 flags;
    s_time_t wakeup_time;
};

extern struct thread *idle_thread;
void idle_thread_fn(void *unused);

#define RUNNABLE_FLAG   0x00000001

#define is_runnable(_thread)    (_thread->flags & RUNNABLE_FLAG)
#define set_runnable(_thread)   (_thread->flags |= RUNNABLE_FLAG)
#define clear_runnable(_thread) (_thread->flags &= ~RUNNABLE_FLAG)

#define switch_threads(prev, next) arch_switch_threads(prev, next)
 
    /* Architecture specific setup of thread creation. */
struct thread* arch_create_thread(char *name, void (*function)(void *),
                                  void *data);

void init_sched(void);
void run_idle_thread(void);
struct thread* create_thread(char *name, void (*function)(void *), void *data);
void schedule(void);

#define current get_current()


void wake(struct thread *thread);
void block(struct thread *thread);
void sleep(u32 millisecs);

#endif /* __SCHED_H__ */
