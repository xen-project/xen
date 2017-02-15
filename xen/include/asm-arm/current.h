#ifndef __ARM_CURRENT_H__
#define __ARM_CURRENT_H__

#include <xen/percpu.h>
#include <public/xen.h>

#include <asm/percpu.h>
#include <asm/processor.h>

#ifndef __ASSEMBLY__

struct vcpu;

/* Which VCPU is "current" on this PCPU. */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#define current            (this_cpu(curr_vcpu))
#define set_current(vcpu)  do { current = (vcpu); } while (0)

/* Per-VCPU state that lives at the top of the stack */
struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned long elr;
    unsigned int pad;
};

static inline struct cpu_info *get_cpu_info(void)
{
    register unsigned long sp asm ("sp");
    return (struct cpu_info *)((sp & ~(STACK_SIZE - 1)) + STACK_SIZE - sizeof(struct cpu_info));
}

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

#define switch_stack_and_jump(stack, fn)                                \
    asm volatile ("mov sp,%0; b " STR(fn) : : "r" (stack) : "memory" )

#define reset_stack_and_jump(fn) switch_stack_and_jump(get_cpu_info(), fn)

#endif

#endif /* __ARM_CURRENT_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
