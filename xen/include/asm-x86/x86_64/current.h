
#ifndef _X86_64_CURRENT_H
#define _X86_64_CURRENT_H

struct domain;

#define STACK_RESERVED \
    (sizeof(struct cpu_user_regs) + sizeof(struct domain *))

static inline struct exec_domain *get_current(void)
{
    struct exec_domain *ed;
    __asm__ ( "orq %%rsp,%0; andq $~7,%0; movq (%0),%0" 
              : "=r" (ed) : "0" (STACK_SIZE-8) );
    return ed;
}
 
#define current get_current()

static inline void set_current(struct exec_domain *ed)
{
    __asm__ ( "orq %%rsp,%0; andq $~7,%0; movq %1,(%0)" 
              : : "r" (STACK_SIZE-8), "r" (ed) );    
}

static inline struct cpu_user_regs *get_cpu_user_regs(void)
{
    struct cpu_user_regs *cpu_user_regs;
    __asm__( "andq %%rsp,%0; addq %2,%0"
	    : "=r" (cpu_user_regs)
	    : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-STACK_RESERVED) ); 
    return cpu_user_regs;
}

/*
 * Get the bottom-of-stack, as stored in the per-CPU TSS. This is actually
 * 64 bytes before the real bottom of the stack to allow space for:
 *  domain pointer, DS, ES, FS, GS, FS_BASE, GS_BASE_OS, GS_BASE_APP
 */
static inline unsigned long get_stack_bottom(void)
{
    unsigned long p;
    __asm__( "andq %%rsp,%0; addq %2,%0"
	    : "=r" (p)
	    : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-64) );
    return p;
}

#define reset_stack_and_jump(__fn)                                \
    __asm__ __volatile__ (                                        \
        "movq %0,%%rsp; jmp "STR(__fn)                            \
        : : "r" (get_cpu_user_regs()) )

#define schedule_tail(_ed) ((_ed)->arch.schedule_tail)(_ed)

#endif /* !(_X86_64_CURRENT_H) */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
