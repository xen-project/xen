#ifndef __SCHED_H__
#define __SCHED_H__

#include <list.h>

struct thread
{
    char *name;
    char *stack;
    unsigned long sp;  /* Stack pointer */
    unsigned long ip;  /* Instruction pointer */
    struct list_head thread_list;
    u32 flags;
};



void init_sched(void);
void run_idle_thread(void);
struct thread* create_thread(char *name, void (*function)(void *), void *data);
void schedule(void);

static inline struct thread* get_current(void)
{
    struct thread **current;
#ifdef __i386__    
    __asm__("andl %%esp,%0; ":"=r" (current) : "r" (~8191UL));
#else
    __asm__("andq %%rsp,%0; ":"=r" (current) : "r" (~8191UL));
#endif 
    return *current;
}
          
#define current get_current()


void wake(struct thread *thread);
void block(struct thread *thread);

#endif /* __SCHED_H__ */
