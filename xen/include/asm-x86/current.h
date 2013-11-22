/******************************************************************************
 * current.h
 * 
 * Information structure that lives at the bottom of the per-cpu Xen stack.
 */

#ifndef __X86_CURRENT_H__
#define __X86_CURRENT_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <public/xen.h>
#include <asm/page.h>

struct vcpu;

struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned int processor_id;
    struct vcpu *current_vcpu;
    unsigned long per_cpu_offset;
    /* get_stack_bottom() must be 16-byte aligned */
    unsigned long __pad_for_stack_bottom;
};

static inline struct cpu_info *get_cpu_info(void)
{
    unsigned long tos;
    __asm__ ( "and %%rsp,%0" : "=r" (tos) : "0" (~(STACK_SIZE-1)) );
    return (struct cpu_info *)(tos + STACK_SIZE) - 1;
}

#define get_current()         (get_cpu_info()->current_vcpu)
#define set_current(vcpu)     (get_cpu_info()->current_vcpu = (vcpu))
#define current               (get_current())

#define get_processor_id()    (get_cpu_info()->processor_id)
#define set_processor_id(id)  do {                                      \
    struct cpu_info *ci__ = get_cpu_info();                             \
    ci__->per_cpu_offset = __per_cpu_offset[ci__->processor_id = (id)]; \
} while (0)

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

/*
 * Get the bottom-of-stack, as stored in the per-CPU TSS. This actually points
 * into the middle of cpu_info.guest_cpu_user_regs, at the section that
 * precisely corresponds to a CPU trap frame.
 */
#define get_stack_bottom()                      \
    ((unsigned long)&get_cpu_info()->guest_cpu_user_regs.es)

/*
 * Get the bottom-of-stack, as useful for printing stack traces.  This is the
 * highest word on the stack which might be part of a stack trace, and is the
 * adjacent word to a struct cpu_info on the stack.
 */
#define get_printable_stack_bottom(sp)          \
    ((sp & (~(STACK_SIZE-1))) +                 \
     (STACK_SIZE - sizeof(struct cpu_info) - sizeof(unsigned long)))

#define reset_stack_and_jump(__fn)              \
    __asm__ __volatile__ (                      \
        "mov %0,%%"__OP"sp; jmp %c1"            \
        : : "r" (guest_cpu_user_regs()), "i" (__fn) : "memory" )

#define schedule_tail(vcpu) (((vcpu)->arch.schedule_tail)(vcpu))

/*
 * Which VCPU's state is currently running on each CPU?
 * This is not necesasrily the same as 'current' as a CPU may be
 * executing a lazy state switch.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#endif /* __X86_CURRENT_H__ */
