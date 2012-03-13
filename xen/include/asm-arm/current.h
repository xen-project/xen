#ifndef __ARM_CURRENT_H__
#define __ARM_CURRENT_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <public/xen.h>

#include <asm/percpu.h>

#ifndef __ASSEMBLY__

struct vcpu;

/*
 * Which VCPU is "current" on this PCPU.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

struct cpu_info {
    struct cpu_user_regs guest_cpu_user_regs;
    unsigned long elr;
    /* The following are valid iff this VCPU is current */
    unsigned int processor_id;
    unsigned long per_cpu_offset;
    unsigned int pad;
};

static inline struct cpu_info *get_cpu_info(void)
{
    register unsigned long sp asm ("sp");
    return (struct cpu_info *)((sp & ~(STACK_SIZE - 1)) + STACK_SIZE - sizeof(struct cpu_info));
}

#define get_processor_id()    (get_cpu_info()->processor_id)
#define set_processor_id(id)  do {                                      \
    struct cpu_info *ci__ = get_cpu_info();                             \
    ci__->per_cpu_offset = __per_cpu_offset[ci__->processor_id = (id)]; \
} while (0)

#define get_current()         (this_cpu(curr_vcpu))
#define __set_current(vcpu)   (this_cpu(curr_vcpu) = (vcpu))
#define set_current(vcpu)     do {                                      \
    int cpu = get_processor_id();                                       \
    vcpu->arch.cpu_info->processor_id = cpu;                            \
    vcpu->arch.cpu_info->per_cpu_offset = __per_cpu_offset[cpu];        \
    __set_current(vcpu);                                                \
} while (0)
#define current               (get_current())

#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)

#define reset_stack_and_jump(__fn)              \
    __asm__ __volatile__ (                      \
        "mov sp,%0; b "STR(__fn)      \
        : : "r" (guest_cpu_user_regs()) : "memory" )

#endif

#endif /* __ARM_CURRENT_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
