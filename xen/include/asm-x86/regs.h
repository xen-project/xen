
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#ifdef __x86_64__
#include <asm/x86_64/regs.h>
#else
#include <asm/x86_32/regs.h>
#endif

enum EFLAGS {
    EF_CF   = 0x00000001,
    EF_PF   = 0x00000004,
    EF_AF   = 0x00000010,
    EF_ZF   = 0x00000040,
    EF_SF   = 0x00000080,
    EF_TF   = 0x00000100,
    EF_IE   = 0x00000200,
    EF_DF   = 0x00000400,
    EF_OF   = 0x00000800,
    EF_IOPL = 0x00003000,
    EF_IOPL_RING0 = 0x00000000,
    EF_IOPL_RING1 = 0x00001000,
    EF_IOPL_RING2 = 0x00002000,
    EF_NT   = 0x00004000,   /* nested task */
    EF_RF   = 0x00010000,   /* resume */
    EF_VM   = 0x00020000,   /* virtual mode */
    EF_AC   = 0x00040000,   /* alignment */
    EF_VIF  = 0x00080000,   /* virtual interrupt */
    EF_VIP  = 0x00100000,   /* virtual interrupt pending */
    EF_ID   = 0x00200000,   /* id */
};

#define GUEST_MODE(r)                                                         \
({                                                                            \
    unsigned long diff = (char *)guest_cpu_user_regs() - (char *)(r);         \
    /* Frame pointer must point into current CPU stack. */                    \
    ASSERT(diff < STACK_SIZE);                                                \
    /* If a guest frame, it must not be a ring 0 frame (unless HVM guest). */ \
    ASSERT((diff != 0) || VM86_MODE(r) || !RING_0(r) || HVM_DOMAIN(current)); \
    /* If not a guest frame, it must be a ring 0 frame. */                    \
    ASSERT((diff == 0) || (!VM86_MODE(r) && RING_0(r)));                      \
    /* Return TRUE if it's a guest frame. */                                  \
    (diff == 0);                                                              \
})

#endif /* __X86_REGS_H__ */
