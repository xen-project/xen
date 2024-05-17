/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <xen/lib.h>
#include <xen/percpu.h>
#include <asm/processor.h>

#ifndef __ASSEMBLY__

/* Which VCPU is "current" on this PCPU. */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#define current            this_cpu(curr_vcpu)
#define set_current(vcpu)  do { current = (vcpu); } while (0)
#define get_cpu_current(cpu)  per_cpu(curr_vcpu, cpu)

#define guest_cpu_user_regs() ({ BUG_ON("unimplemented"); NULL; })

#define switch_stack_and_jump(stack, fn) do {               \
    asm volatile (                                          \
            "mv sp, %0\n"                                   \
            "j " #fn :: "r" (stack), "X" (fn) : "memory" ); \
    unreachable();                                          \
} while ( false )

#define get_per_cpu_offset() __per_cpu_offset[smp_processor_id()]

#endif /* __ASSEMBLY__ */

#endif /* __ASM_CURRENT_H */
