/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

#ifndef _X86_CURRENT_H
#define _X86_CURRENT_H

struct domain;

#define STACK_RESERVED \
    (sizeof(execution_context_t) + sizeof(struct domain *))

static inline struct exec_domain *get_current(void)
{
    struct exec_domain *ed;
    __asm__ ( "orl %%esp,%0; andl $~3,%0; movl (%0),%0" 
              : "=r" (ed) : "0" (STACK_SIZE-4) );
    return ed;
}
 
#define current get_current()

static inline void set_current(struct exec_domain *ed)
{
    __asm__ ( "orl %%esp,%0; andl $~3,%0; movl %1,(%0)" 
              : : "r" (STACK_SIZE-4), "r" (ed) );    
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

#define reset_stack_and_jump(__fn)                                \
    __asm__ __volatile__ (                                        \
        "movl %0,%%esp; jmp "STR(__fn)                            \
        : : "r" (get_execution_context()) )

#define schedule_tail(_ed) ((_ed)->arch.schedule_tail)(_ed)

#endif /* _X86_CURRENT_H */
