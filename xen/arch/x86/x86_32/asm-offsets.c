/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/config.h>
#include <xen/perfc.h>
#include <xen/sched.h>
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
    OFFSET(UREGS_eax, struct cpu_user_regs, eax);
    OFFSET(UREGS_ebx, struct cpu_user_regs, ebx);
    OFFSET(UREGS_ecx, struct cpu_user_regs, ecx);
    OFFSET(UREGS_edx, struct cpu_user_regs, edx);
    OFFSET(UREGS_esi, struct cpu_user_regs, esi);
    OFFSET(UREGS_edi, struct cpu_user_regs, edi);
    OFFSET(UREGS_esp, struct cpu_user_regs, esp);
    OFFSET(UREGS_ebp, struct cpu_user_regs, ebp);
    OFFSET(UREGS_eip, struct cpu_user_regs, eip);
    OFFSET(UREGS_cs, struct cpu_user_regs, cs);
    OFFSET(UREGS_ds, struct cpu_user_regs, ds);
    OFFSET(UREGS_es, struct cpu_user_regs, es);
    OFFSET(UREGS_fs, struct cpu_user_regs, fs);
    OFFSET(UREGS_gs, struct cpu_user_regs, gs);
    OFFSET(UREGS_ss, struct cpu_user_regs, ss);
    OFFSET(UREGS_eflags, struct cpu_user_regs, eflags);
    OFFSET(UREGS_error_code, struct cpu_user_regs, error_code);
    OFFSET(UREGS_entry_vector, struct cpu_user_regs, entry_vector);
    OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, esp);
    DEFINE(UREGS_user_sizeof, sizeof(struct cpu_user_regs));
    BLANK();

    OFFSET(VCPU_processor, struct vcpu, processor);
    OFFSET(VCPU_vcpu_info, struct vcpu, vcpu_info);
    OFFSET(VCPU_trap_bounce, struct vcpu, arch.trap_bounce);
    OFFSET(VCPU_thread_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_event_sel, struct vcpu,
           arch.guest_context.event_callback_cs);
    OFFSET(VCPU_event_addr, struct vcpu, 
           arch.guest_context.event_callback_eip);
    OFFSET(VCPU_failsafe_sel, struct vcpu,
           arch.guest_context.failsafe_callback_cs);
    OFFSET(VCPU_failsafe_addr, struct vcpu,
           arch.guest_context.failsafe_callback_eip);
    OFFSET(VCPU_kernel_ss, struct vcpu,
           arch.guest_context.kernel_ss);
    OFFSET(VCPU_kernel_sp, struct vcpu,
           arch.guest_context.kernel_sp);
    OFFSET(VCPU_guest_context_flags, struct vcpu, arch.guest_context.flags);
    OFFSET(VCPU_arch_guest_fpu_ctxt, struct vcpu, arch.guest_context.fpu_ctxt);
    OFFSET(VCPU_flags, struct vcpu, vcpu_flags);
    OFFSET(VCPU_nmi_addr, struct vcpu, nmi_addr);
    OFFSET(VCPU_nmi_pending, struct vcpu, nmi_pending);
    OFFSET(VCPU_nmi_masked, struct vcpu, nmi_masked);
    DEFINE(_VGCF_failsafe_disables_events, _VGCF_failsafe_disables_events);
    BLANK();

    OFFSET(TSS_ss0, struct tss_struct, ss0);
    OFFSET(TSS_esp0, struct tss_struct, esp0);
    OFFSET(TSS_ss1, struct tss_struct, ss1);
    OFFSET(TSS_esp1, struct tss_struct, esp1);
    DEFINE(TSS_sizeof, sizeof(struct tss_struct));
    BLANK();

    OFFSET(VCPU_svm_vmcb_pa, struct vcpu, arch.hvm_svm.vmcb_pa);
    OFFSET(VCPU_svm_vmcb, struct vcpu, arch.hvm_svm.vmcb);
    OFFSET(VCPU_svm_vmexit_tsc, struct vcpu, arch.hvm_svm.vmexit_tsc);
    BLANK();

    OFFSET(VCPU_vmx_launched, struct vcpu, arch.hvm_vmx.launched);
    OFFSET(VCPU_vmx_cr2, struct vcpu, arch.hvm_vmx.cpu_cr2);
    BLANK();

    OFFSET(VMCB_rax, struct vmcb_struct, rax);
    OFFSET(VMCB_tsc_offset, struct vmcb_struct, tsc_offset);
    BLANK();

    OFFSET(VCPUINFO_upcall_pending, vcpu_info_t, evtchn_upcall_pending);
    OFFSET(VCPUINFO_upcall_mask, vcpu_info_t, evtchn_upcall_mask);
    BLANK();

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

    DEFINE(FIXMAP_apic_base, fix_to_virt(FIX_APIC_BASE));
    BLANK();

    DEFINE(IRQSTAT_shift, LOG_2(sizeof(irq_cpustat_t)));
}
