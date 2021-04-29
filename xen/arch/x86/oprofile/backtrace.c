/**
 * @file backtrace.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author David Smith
 * Modified for Xen by Amitabha Roy
 *
 */

#include <xen/types.h>
#include <asm/page.h>
#include <xen/xenoprof.h>
#include <xen/guest_access.h>

struct __packed frame_head {
    struct frame_head * ebp;
    unsigned long ret;
};
typedef struct frame_head frame_head_t;

struct __packed frame_head_32bit {
    uint32_t ebp;
    uint32_t ret;
};
typedef struct frame_head_32bit frame_head32_t;

static struct frame_head *
dump_hypervisor_backtrace(struct vcpu *vcpu, const struct frame_head *head,
                          int mode)
{
    if (!xenoprof_add_trace(vcpu, head->ret, mode))
        return 0;
    
    /* frame pointers should strictly progress back up the stack
     * (towards higher addresses) */
    if (head >= head->ebp)
        return NULL;
    
    return head->ebp;
}

static inline int is_32bit_vcpu(struct vcpu *vcpu)
{
    if (is_hvm_vcpu(vcpu))
        return !hvm_long_mode_active(vcpu);
    else
        return is_pv_32bit_vcpu(vcpu);
}

static struct frame_head *
dump_guest_backtrace(struct vcpu *vcpu, const struct frame_head *head,
                     int mode)
{
    /* Also check accessibility of one struct frame_head beyond. */
    frame_head_t bufhead[2];

    if ( is_32bit_vcpu(vcpu) )
    {
        frame_head32_t bufhead32[2];

        if ( raw_copy_from_guest(bufhead32, head, sizeof(bufhead32)) )
            return 0;
        bufhead[0].ebp = (struct frame_head *)(unsigned long)bufhead32[0].ebp;
        bufhead[0].ret = bufhead32[0].ret;
    }
    else if ( raw_copy_from_guest(bufhead, head, sizeof(bufhead)) )
        return 0;
    
    if ( !xenoprof_add_trace(vcpu, bufhead[0].ret, mode) )
        return 0;
    
    /* frame pointers should strictly progress back up the stack
     * (towards higher addresses) */
    if ( head >= bufhead[0].ebp )
        return NULL;
    
    return bufhead[0].ebp;
}

/*
 * |             | /\ Higher addresses
 * |             |
 * --------------- stack base (address of current_thread_info)
 * | thread info |
 * .             .
 * |    stack    |
 * --------------- saved regs->ebp value if valid (frame_head address)
 * .             .
 * --------------- saved regs->rsp value if x86_64
 * |             |
 * --------------- struct pt_regs * stored on stack if 32-bit
 * |             |
 * .             .
 * |             |
 * --------------- %esp
 * |             |
 * |             | \/ Lower addresses
 *
 * Thus, regs (or regs->rsp for x86_64) <-> stack base restricts the
 * valid(ish) ebp values. Note: (1) for x86_64, NMI and several other
 * exceptions use special stacks, maintained by the interrupt stack table
 * (IST). These stacks are set up in trap_init() in
 * arch/x86_64/kernel/traps.c. Thus, for x86_64, regs now does not point
 * to the kernel stack; instead, it points to some location on the NMI
 * stack. On the other hand, regs->rsp is the stack pointer saved when the
 * NMI occurred. (2) For 32-bit, regs->esp is not valid because the
 * processor does not save %esp on the kernel stack when interrupts occur
 * in the kernel mode.
 */
#if defined(CONFIG_FRAME_POINTER)
static int valid_hypervisor_stack(const struct frame_head *head,
				  const struct cpu_user_regs *regs)
{
    unsigned long headaddr = (unsigned long)head;
    unsigned long stack = (unsigned long)regs->rsp;
    unsigned long stack_base = (stack & ~(STACK_SIZE - 1)) + STACK_SIZE;

    return headaddr > stack && headaddr < stack_base;
}
#else
/* without fp, it's just junk */
static int valid_hypervisor_stack(const struct frame_head *head,
				  const struct cpu_user_regs *regs)
{
    return 0;
}
#endif

void xenoprof_backtrace(struct vcpu *vcpu, const struct cpu_user_regs *regs,
			unsigned long depth, int mode)
{
    const struct frame_head *head = (void *)regs->rbp;

    if (mode > 1) {
        while (depth-- && valid_hypervisor_stack(head, regs))
            head = dump_hypervisor_backtrace(vcpu, head, mode);
        return;
    }

    while (depth-- && head)
        head = dump_guest_backtrace(vcpu, head, mode);
}
