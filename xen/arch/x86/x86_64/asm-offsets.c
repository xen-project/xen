/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/sched.h>

#define DEFINE(_sym, _val) \
    __asm__ __volatile__ ( "\n->" #_sym " %0 " #_val : : "i" (_val) )
#define BLANK() \
    __asm__ __volatile__ ( "\n->" : : )
#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

void __dummy__(void)
{
    OFFSET(XREGS_r15, struct xen_regs, r15);
    OFFSET(XREGS_r14, struct xen_regs, r14);
    OFFSET(XREGS_r13, struct xen_regs, r13);
    OFFSET(XREGS_r12, struct xen_regs, r12);
    OFFSET(XREGS_rbp, struct xen_regs, rbp);
    OFFSET(XREGS_rbx, struct xen_regs, rbx);
    OFFSET(XREGS_r11, struct xen_regs, r11);
    OFFSET(XREGS_r10, struct xen_regs, r10);
    OFFSET(XREGS_r9, struct xen_regs, r9);
    OFFSET(XREGS_r8, struct xen_regs, r8);
    OFFSET(XREGS_rax, struct xen_regs, rax);
    OFFSET(XREGS_rcx, struct xen_regs, rcx);
    OFFSET(XREGS_rdx, struct xen_regs, rdx);
    OFFSET(XREGS_rsi, struct xen_regs, rsi);
    OFFSET(XREGS_rdi, struct xen_regs, rdi);
    OFFSET(XREGS_error_code, struct xen_regs, error_code);
    OFFSET(XREGS_entry_vector, struct xen_regs, entry_vector);
    OFFSET(XREGS_rip, struct xen_regs, rip);
    OFFSET(XREGS_cs, struct xen_regs, cs);
    OFFSET(XREGS_eflags, struct xen_regs, eflags);
    OFFSET(XREGS_rsp, struct xen_regs, rsp);
    OFFSET(XREGS_ss, struct xen_regs, ss);
    BLANK();

    OFFSET(EDOMAIN_processor, struct exec_domain, processor);
    OFFSET(EDOMAIN_vcpu_info, struct exec_domain, vcpu_info);
    OFFSET(EDOMAIN_event_sel, struct exec_domain, thread.event_selector);
    OFFSET(EDOMAIN_event_addr, struct exec_domain, thread.event_address);
    OFFSET(EDOMAIN_failsafe_sel, struct exec_domain, thread.failsafe_selector);
    OFFSET(EDOMAIN_failsafe_addr, struct exec_domain, thread.failsafe_address);
    OFFSET(EDOMAIN_trap_bounce, struct exec_domain, thread.trap_bounce);
    OFFSET(EDOMAIN_thread_flags, struct exec_domain, thread.flags);
    BLANK();

    OFFSET(SHINFO_upcall_pending, shared_info_t, 
           vcpu_data[0].evtchn_upcall_pending);
    OFFSET(SHINFO_upcall_mask, shared_info_t, 
           vcpu_data[0].evtchn_upcall_mask);
    BLANK();

    OFFSET(TRAPBOUNCE_error_code, struct trap_bounce, error_code);
    OFFSET(TRAPBOUNCE_cr2, struct trap_bounce, cr2);
    OFFSET(TRAPBOUNCE_flags, struct trap_bounce, flags);
    OFFSET(TRAPBOUNCE_cs, struct trap_bounce, cs);
    OFFSET(TRAPBOUNCE_eip, struct trap_bounce, eip);
    BLANK();

    OFFSET(MULTICALL_op, multicall_entry_t, op);
    OFFSET(MULTICALL_arg0, multicall_entry_t, args[0]);
    OFFSET(MULTICALL_arg1, multicall_entry_t, args[1]);
    OFFSET(MULTICALL_arg2, multicall_entry_t, args[2]);
    OFFSET(MULTICALL_arg3, multicall_entry_t, args[3]);
    OFFSET(MULTICALL_arg4, multicall_entry_t, args[4]);
    OFFSET(MULTICALL_result, multicall_entry_t, args[5]);
}
