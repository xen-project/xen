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

#include<xen/types.h>
#include<asm/page.h>
#include<xen/xenoprof.h>
#include<xen/guest_access.h>

struct frame_head {
    struct frame_head * ebp;
    unsigned long ret;
} __attribute__((packed));
typedef struct frame_head frame_head_t;
DEFINE_XEN_GUEST_HANDLE(frame_head_t);

#ifdef CONFIG_X86_64
struct frame_head_32bit {
    uint32_t ebp;
    uint32_t ret;
} __attribute__((packed));
typedef struct frame_head_32bit frame_head32_t;
DEFINE_COMPAT_HANDLE(frame_head32_t);
#endif

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

#ifdef CONFIG_X86_64
static inline int is_32bit_vcpu(struct vcpu *vcpu)
{
    if (is_hvm_vcpu(vcpu))
        return !hvm_long_mode_enabled(vcpu);
    else
        return is_pv_32bit_vcpu(vcpu);
}
#endif

static struct frame_head *
dump_guest_backtrace(struct vcpu *vcpu, const struct frame_head *head,
                     int mode)
{
    frame_head_t bufhead;

#ifdef CONFIG_X86_64
    if ( is_32bit_vcpu(vcpu) )
    {
        __compat_handle_const_frame_head32_t guest_head =
            { .c = (unsigned long)head };
        frame_head32_t bufhead32;

        /* Also check accessibility of one struct frame_head beyond */
        if (!compat_handle_okay(guest_head, 2))
            return 0;
        if (__copy_from_compat(&bufhead32, guest_head, 1))
            return 0;
        bufhead.ebp = (struct frame_head *)(unsigned long)bufhead32.ebp;
        bufhead.ret = bufhead32.ret;
    }
    else
#endif
    {
        XEN_GUEST_HANDLE(const_frame_head_t) guest_head =
            const_guest_handle_from_ptr(head, frame_head_t);

        /* Also check accessibility of one struct frame_head beyond */
        if (!guest_handle_okay(guest_head, 2))
            return 0;
        if (__copy_from_guest(&bufhead, guest_head, 1))
            return 0;
    }
    
    if (!xenoprof_add_trace(vcpu, bufhead.ret, mode))
        return 0;
    
    /* frame pointers should strictly progress back up the stack
     * (towards higher addresses) */
    if (head >= bufhead.ebp)
        return NULL;
    
    return bufhead.ebp;
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
#ifdef CONFIG_X86_64
    unsigned long stack = (unsigned long)regs->rsp;
#else
    unsigned long stack = (unsigned long)regs;
#endif
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
    const struct frame_head *head = (void *)regs->ebp;

    if (mode > 1) {
        while (depth-- && valid_hypervisor_stack(head, regs))
            head = dump_hypervisor_backtrace(vcpu, head, mode);
        return;
    }

    while (depth-- && head)
        head = dump_guest_backtrace(vcpu, head, mode);
}
