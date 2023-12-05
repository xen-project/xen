
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#include <asm/x86_64/regs.h>

#define guest_mode(r)                                                         \
({                                                                            \
    unsigned long diff = (uintptr_t)guest_cpu_user_regs() - (uintptr_t)(r);   \
    /* Frame pointer must point into current CPU stack. */                    \
    ASSERT(diff < STACK_SIZE);                                                \
    /* If not a guest frame, it must be a hypervisor frame. */                \
    if ( diff < PRIMARY_STACK_SIZE )                                          \
        ASSERT(!diff || ((r)->cs == __HYPERVISOR_CS));                        \
    /* Return TRUE if it's a guest frame. */                                  \
    !diff || ((r)->cs != __HYPERVISOR_CS);                                    \
})

#define read_sreg(name) ({                           \
    unsigned int __sel;                              \
    asm ( "mov %%" STR(name) ",%0" : "=r" (__sel) ); \
    __sel;                                           \
})

static inline void read_sregs(struct cpu_user_regs *regs)
{
    asm ( "mov %%ds, %0" : "=m" (regs->ds) );
    asm ( "mov %%es, %0" : "=m" (regs->es) );
    asm ( "mov %%fs, %0" : "=m" (regs->fs) );
    asm ( "mov %%gs, %0" : "=m" (regs->gs) );
}

#endif /* __X86_REGS_H__ */
