#ifndef _X86_CURRENT_H
#define _X86_CURRENT_H

struct domain;

#define STACK_RESERVED \
    (sizeof(execution_context_t) + sizeof(struct domain *))

static inline struct domain * get_current(void)
{
    struct domain *current;
    __asm__ ( "orl %%esp,%0; andl $~3,%0; movl (%0),%0" 
              : "=r" (current) : "0" (STACK_SIZE-4) );
    return current;
}
 
#define current get_current()

static inline void set_current(struct domain *p)
{
    __asm__ ( "orl %%esp,%0; andl $~3,%0; movl %1,(%0)" 
              : : "r" (STACK_SIZE-4), "r" (p) );    
}

static inline execution_context_t *get_execution_context(void)
{
    execution_context_t *execution_context;
    __asm__ ( "andl %%esp,%0; addl %2,%0"
              : "=r" (execution_context) 
              : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-STACK_RESERVED) );
    return execution_context;
}

/*
 * Get the top-of-stack, as stored in the per-CPU TSS. This is actually
 * 20 bytes below the real top of the stack to allow space for:
 *  domain pointer, DS, ES, FS, GS.
 */
static inline unsigned long get_stack_top(void)
{
    unsigned long p;
    __asm__ ( "andl %%esp,%0; addl %2,%0" 
              : "=r" (p)
              : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-20) );
    return p;
}

#define schedule_tail(_p)                                         \
    __asm__ __volatile__ (                                        \
        "andl %%esp,%0; addl %2,%0; movl %0,%%esp; jmp *%1"       \
        : : "r" (~(STACK_SIZE-1)),                                \
            "r" (unlikely(is_idle_task((_p))) ?                   \
                                continue_cpu_idle_loop :          \
                                continue_nonidle_task),           \
            "i" (STACK_SIZE-STACK_RESERVED) )


#endif /* _X86_CURRENT_H */
