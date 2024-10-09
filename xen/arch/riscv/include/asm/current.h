/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__CURRENT_H
#define ASM__RISCV__CURRENT_H

#include <xen/bug.h>
#include <xen/cache.h>
#include <xen/percpu.h>

#include <asm/processor.h>

#ifndef __ASSEMBLY__

register struct pcpu_info *tp asm ( "tp" );

struct pcpu_info {
    unsigned int processor_id; /* Xen CPU id */
    unsigned long hart_id; /* physical CPU id */
} __cacheline_aligned;

/* tp points to one of these */
extern struct pcpu_info pcpu_info[NR_CPUS];

#define set_processor_id(id)    do { \
    tp->processor_id = (id);         \
} while (0)

static inline unsigned int smp_processor_id(void)
{
    unsigned int id = tp->processor_id;

    BUG_ON(id >= NR_CPUS);

    return id;
}

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

#endif /* ASM__RISCV__CURRENT_H */
