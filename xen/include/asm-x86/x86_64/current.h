#ifndef _X86_64_CURRENT_H
#define _X86_64_CURRENT_H

#if !defined(__ASSEMBLY__)
struct domain;

#include <asm/pda.h>

#define STACK_RESERVED \
    (sizeof(execution_context_t))

static inline struct domain * get_current(void)
{
    struct domain *current;
    current = read_pda(pcurrent);
    return current;
}
 
#define current get_current()

static inline void set_current(struct domain *p)
{
    write_pda(pcurrent,p);
}

static inline execution_context_t *get_execution_context(void)
{
    execution_context_t *execution_context;
    __asm__( "andq %%rsp,%0; addq %2,%0"
	    : "=r" (execution_context)
	    : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-STACK_RESERVED) ); 
    return execution_context;
}

static inline unsigned long get_stack_top(void)
{
    unsigned long p;
    __asm__ ( "orq %%rsp,%0; andq $~7,%0" 
              : "=r" (p) : "0" (STACK_SIZE-8) );
    return p;
}

#define reset_stack_and_jump(__fn)                                \
    __asm__ __volatile__ (                                        \
        "movq %0,%%rsp; jmp "STR(__fn)                            \
        : : "r" (get_execution_context()) )

#define schedule_tail(_d) ((_d)->thread.schedule_tail)(_d)

#else

#ifndef ASM_OFFSET_H
#include <asm/offset.h> 
#endif

#define GET_CURRENT(reg) movq %gs:(pda_pcurrent),reg

#endif

#endif /* !(_X86_64_CURRENT_H) */
