/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_CURRENT_H__
#define __ASM_PPC_CURRENT_H__

#include <xen/percpu.h>

#include <asm/processor.h>

#ifndef __ASSEMBLY__

struct vcpu;

/* Which VCPU is "current" on this PCPU. */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#define current            (this_cpu(curr_vcpu))
#define set_current(vcpu)  do { current = (vcpu); } while (0)
#define get_cpu_current(cpu)  (per_cpu(curr_vcpu, cpu))

/* Per-VCPU state that lives at the top of the stack */
struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned long elr;
    unsigned int flags;
};

static inline struct cpu_info *get_cpu_info(void)
{
#ifdef __clang__
    unsigned long sp;

    asm ( "mr %0, 1" : "=r" (sp) );
#else
    register unsigned long sp asm ("r1");
#endif

    return (struct cpu_info *)((sp & ~(STACK_SIZE - 1)) +
                               STACK_SIZE - sizeof(struct cpu_info));
}

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

#define smp_processor_id()      0 /* TODO: Fix this */

#define get_per_cpu_offset()    smp_processor_id() /* TODO: Fix this */

#endif /* __ASSEMBLY__ */

#endif /* __ASM_PPC_CURRENT_H__ */
