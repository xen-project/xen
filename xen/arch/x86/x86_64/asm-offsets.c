/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/config.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#ifdef CONFIG_COMPAT
#include <compat/xen.h>
#endif
#include <asm/fixmap.h>
#include <asm/hardirq.h>

#define DEFINE(_sym, _val) \
    __asm__ __volatile__ ( "\n->" #_sym " %0 " #_val : : "i" (_val) )
#define BLANK() \
    __asm__ __volatile__ ( "\n->" : : )
#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

/* base-2 logarithm */
#define __L2(_x)  (((_x) & 0x00000002) ?   1 : 0)
#define __L4(_x)  (((_x) & 0x0000000c) ? ( 2 + __L2( (_x)>> 2)) : __L2( _x))
#define __L8(_x)  (((_x) & 0x000000f0) ? ( 4 + __L4( (_x)>> 4)) : __L4( _x))
#define __L16(_x) (((_x) & 0x0000ff00) ? ( 8 + __L8( (_x)>> 8)) : __L8( _x))
#define LOG_2(_x) (((_x) & 0xffff0000) ? (16 + __L16((_x)>>16)) : __L16(_x))

void __dummy__(void)
{
    OFFSET(UREGS_r15, struct cpu_user_regs, r15);
    OFFSET(UREGS_r14, struct cpu_user_regs, r14);
    OFFSET(UREGS_r13, struct cpu_user_regs, r13);
    OFFSET(UREGS_r12, struct cpu_user_regs, r12);
    OFFSET(UREGS_rbp, struct cpu_user_regs, rbp);
    OFFSET(UREGS_rbx, struct cpu_user_regs, rbx);
    OFFSET(UREGS_r11, struct cpu_user_regs, r11);
    OFFSET(UREGS_r10, struct cpu_user_regs, r10);
    OFFSET(UREGS_r9, struct cpu_user_regs, r9);
    OFFSET(UREGS_r8, struct cpu_user_regs, r8);
    OFFSET(UREGS_rax, struct cpu_user_regs, rax);
    OFFSET(UREGS_rcx, struct cpu_user_regs, rcx);
    OFFSET(UREGS_rdx, struct cpu_user_regs, rdx);
    OFFSET(UREGS_rsi, struct cpu_user_regs, rsi);
    OFFSET(UREGS_rdi, struct cpu_user_regs, rdi);
    OFFSET(UREGS_error_code, struct cpu_user_regs, error_code);
    OFFSET(UREGS_entry_vector, struct cpu_user_regs, entry_vector);
    OFFSET(UREGS_rip, struct cpu_user_regs, rip);
    OFFSET(UREGS_cs, struct cpu_user_regs, cs);
    OFFSET(UREGS_eflags, struct cpu_user_regs, eflags);
    OFFSET(UREGS_rsp, struct cpu_user_regs, rsp);
    OFFSET(UREGS_ss, struct cpu_user_regs, ss);
    OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, es);
    DEFINE(UREGS_user_sizeof, sizeof(struct cpu_user_regs));
    BLANK();

    OFFSET(VCPU_processor, struct vcpu, processor);
    OFFSET(VCPU_domain, struct vcpu, domain);
    OFFSET(VCPU_vcpu_info, struct vcpu, vcpu_info);
    OFFSET(VCPU_trap_bounce, struct vcpu, arch.trap_bounce);
    OFFSET(VCPU_int80_bounce, struct vcpu, arch.int80_bounce);
    OFFSET(VCPU_thread_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_event_addr, struct vcpu,
           arch.guest_context.event_callback_eip);
    OFFSET(VCPU_event_sel, struct vcpu,
           arch.guest_context.event_callback_cs);
    OFFSET(VCPU_failsafe_addr, struct vcpu,
           arch.guest_context.failsafe_callback_eip);
    OFFSET(VCPU_failsafe_sel, struct vcpu,
           arch.guest_context.failsafe_callback_cs);
    OFFSET(VCPU_syscall_addr, struct vcpu,
           arch.guest_context.syscall_callback_eip);
    OFFSET(VCPU_kernel_sp, struct vcpu, arch.guest_context.kernel_sp);
    OFFSET(VCPU_kernel_ss, struct vcpu, arch.guest_context.kernel_ss);
    OFFSET(VCPU_guest_context_flags, struct vcpu, arch.guest_context.flags);
    OFFSET(VCPU_arch_guest_fpu_ctxt, struct vcpu, arch.guest_context.fpu_ctxt);
    OFFSET(VCPU_flags, struct vcpu, vcpu_flags);
    OFFSET(VCPU_nmi_addr, struct vcpu, nmi_addr);
    OFFSET(VCPU_nmi_pending, struct vcpu, nmi_pending);
    OFFSET(VCPU_nmi_masked, struct vcpu, nmi_masked);
    DEFINE(_VGCF_failsafe_disables_events, _VGCF_failsafe_disables_events);
    DEFINE(_VGCF_syscall_disables_events,  _VGCF_syscall_disables_events);
    BLANK();

    OFFSET(VCPU_svm_vmcb_pa, struct vcpu, arch.hvm_svm.vmcb_pa);
    OFFSET(VCPU_svm_vmcb, struct vcpu, arch.hvm_svm.vmcb);
    OFFSET(VCPU_svm_vmexit_tsc, struct vcpu, arch.hvm_svm.vmexit_tsc);
    BLANK();

    OFFSET(VCPU_vmx_launched, struct vcpu, arch.hvm_vmx.launched);
    OFFSET(VCPU_vmx_cr2, struct vcpu, arch.hvm_vmx.cpu_cr2);
    BLANK();

    OFFSET(DOMAIN_is_compat, struct domain, is_compat);
    BLANK();

    OFFSET(VMCB_rax, struct vmcb_struct, rax);
    OFFSET(VMCB_tsc_offset, struct vmcb_struct, tsc_offset);
    BLANK();

    OFFSET(VCPUINFO_upcall_pending, struct vcpu_info, evtchn_upcall_pending);
    OFFSET(VCPUINFO_upcall_mask, struct vcpu_info, evtchn_upcall_mask);
    BLANK();

#ifdef CONFIG_COMPAT
    OFFSET(COMPAT_VCPUINFO_upcall_pending, struct compat_vcpu_info, evtchn_upcall_pending);
    OFFSET(COMPAT_VCPUINFO_upcall_mask, struct compat_vcpu_info, evtchn_upcall_mask);
    BLANK();
#endif

    OFFSET(CPUINFO_current_vcpu, struct cpu_info, current_vcpu);
    DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));
    BLANK();

    OFFSET(TRAPBOUNCE_error_code, struct trap_bounce, error_code);
    OFFSET(TRAPBOUNCE_flags, struct trap_bounce, flags);
    OFFSET(TRAPBOUNCE_cs, struct trap_bounce, cs);
    OFFSET(TRAPBOUNCE_eip, struct trap_bounce, eip);
    BLANK();

#if PERF_COUNTERS
    DEFINE(PERFC_hypercalls, PERFC_hypercalls);
    DEFINE(PERFC_exceptions, PERFC_exceptions);
    BLANK();
#endif

    DEFINE(IRQSTAT_shift, LOG_2(sizeof(irq_cpustat_t)));
}
