
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#include <xen/types.h>
#include <public/xen.h>

#define ring_0(r)    (((r)->cs & 3) == 0)
#define ring_1(r)    (((r)->cs & 3) == 1)
#define ring_2(r)    (((r)->cs & 3) == 2)
#define ring_3(r)    (((r)->cs & 3) == 3)

#define guest_kernel_mode(v, r)                                 \
    (!is_pv_32bit_vcpu(v) ?                                     \
     (ring_3(r) && ((v)->arch.flags & TF_kernel_mode)) :        \
     (ring_1(r)))

#define permit_softint(dpl, v, r) \
    ((dpl) >= (guest_kernel_mode(v, r) ? 1 : 3))

/* Check for null trap callback handler: Is the EIP null? */
#define null_trap_bounce(v, tb) \
    (!is_pv_32bit_vcpu(v) ? ((tb)->eip == 0) : (((tb)->cs & ~3) == 0))

/* Number of bytes of on-stack execution state to be context-switched. */
/* NB. Segment registers and bases are not saved/restored on x86/64 stack. */
#define CTXT_SWITCH_STACK_BYTES (offsetof(struct cpu_user_regs, es))

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
