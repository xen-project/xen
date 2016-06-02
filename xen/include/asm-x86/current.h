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

/*
 * Xen's cpu stacks are 8 pages (8-page aligned), arranged as:
 *
 * 7 - Primary stack (with a struct cpu_info at the top)
 * 6 - Primary stack
 * 5 - Optionally not preset (MEMORY_GUARD)
 * 4 - unused
 * 3 - Syscall trampolines
 * 2 - MCE IST stack
 * 1 - NMI IST stack
 * 0 - Double Fault IST stack
 */

/*
 * Identify which stack page the stack pointer is on.  Returns an index
 * as per the comment above.
 */
static inline unsigned int get_stack_page(unsigned long sp)
{
    return (sp & (STACK_SIZE-1)) >> PAGE_SHIFT;
}

struct vcpu;

struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned int processor_id;
    struct vcpu *current_vcpu;
    unsigned long per_cpu_offset;
    unsigned long cr4;
    /* get_stack_bottom() must be 16-byte aligned */
};

static inline struct cpu_info *get_cpu_info(void)
{
#ifdef __clang__
    /* Clang complains that sp in the else case is not initialised. */
    unsigned long sp;
    asm ( "mov %%rsp, %0" : "=r" (sp) );
#else
    register unsigned long sp asm("rsp");
#endif

    return (struct cpu_info *)((sp | (STACK_SIZE - 1)) + 1) - 1;
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
 * Get the reasonable stack bounds for stack traces and stack dumps.  Stack
 * dumps have a slightly larger range to include exception frames in the
 * printed information.  The returned word is inside the interesting range.
 */
unsigned long get_stack_trace_bottom(unsigned long sp);
unsigned long get_stack_dump_bottom (unsigned long sp);

#ifdef CONFIG_LIVEPATCH
# define CHECK_FOR_LIVEPATCH_WORK "call check_for_livepatch_work;"
#else
# define CHECK_FOR_LIVEPATCH_WORK ""
#endif

#define reset_stack_and_jump(__fn)                                      \
    ({                                                                  \
        __asm__ __volatile__ (                                          \
            "mov %0,%%"__OP"sp;"                                        \
            CHECK_FOR_LIVEPATCH_WORK                                      \
             "jmp %c1"                                                  \
            : : "r" (guest_cpu_user_regs()), "i" (__fn) : "memory" );   \
        unreachable();                                                  \
    })

/*
 * Schedule tail *should* be a terminal function pointer, but leave a bugframe
 * around just incase it returns, to save going back into the context
 * switching code and leaving a far more subtle crash to diagnose.
 */
#define schedule_tail(vcpu) do {                \
        (((vcpu)->arch.schedule_tail)(vcpu));   \
        BUG();                                  \
    } while (0)

/*
 * Which VCPU's state is currently running on each CPU?
 * This is not necesasrily the same as 'current' as a CPU may be
 * executing a lazy state switch.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#endif /* __X86_CURRENT_H__ */
