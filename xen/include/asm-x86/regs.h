
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#include <asm/x86_64/regs.h>

#define guest_mode(r)                                                         \
({                                                                            \
    unsigned long diff = (char *)guest_cpu_user_regs() - (char *)(r);         \
    /* Frame pointer must point into current CPU stack. */                    \
    ASSERT(diff < STACK_SIZE);                                                \
    /* If not a guest frame, it must be a hypervisor frame. */                \
    ASSERT((diff == 0) || (r->cs == __HYPERVISOR_CS));                        \
    /* Return TRUE if it's a guest frame. */                                  \
    (diff == 0);                                                              \
})

#define return_reg(v) ((v)->arch.user_regs.rax)

#endif /* __X86_REGS_H__ */
