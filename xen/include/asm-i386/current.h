#ifndef _I386_CURRENT_H
#define _I386_CURRENT_H

struct task_struct;

static inline struct task_struct * get_current(void)
{
    struct task_struct *current;
    __asm__ ( "orl %%esp,%0; movl (%0),%0" 
              : "=r" (current) : "0" (4092UL) );
    return current;
}
 
#define current get_current()

static inline void set_current(struct task_struct *p)
{
    __asm__ ( "orl %%esp,%0; movl %1,(%0)" 
              : : "r" (4092UL), "r" (p) );    
}

static inline execution_context_t *get_execution_context(void)
{
    execution_context_t *execution_context;
    __asm__ ( "andl %%esp,%0; addl $4096-72,%0"
              : "=r" (execution_context) : "0" (~4095UL) );
    return execution_context;
}

static inline unsigned long get_stack_top(void)
{
    unsigned long p;
    __asm__ ( "orl %%esp,%0" 
              : "=r" (p) : "0" (4092UL) );
    return p;
}

#define schedule_tail(_p)                                         \
    __asm__ __volatile__ (                                        \
        "andl %%esp,%0; addl $4096-72,%0; movl %0,%%esp; jmp *%1" \
        : : "r" (~4095UL), "r" (unlikely(is_idle_task((_p))) ?    \
                                continue_cpu_idle_loop :          \
                                continue_nonidle_task) )


#endif /* !(_I386_CURRENT_H) */
