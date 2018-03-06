/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */
#define COMPILE_OFFSETS

#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/bitops.h>
#include <compat/xen.h>
#include <asm/fixmap.h>
#include <asm/hardirq.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>

#define DEFINE(_sym, _val)                                                 \
    asm volatile ("\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\"" \
                  : : "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" : : )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem));

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
    OFFSET(UREGS_saved_upcall_mask, struct cpu_user_regs, saved_upcall_mask);
    OFFSET(UREGS_rip, struct cpu_user_regs, rip);
    OFFSET(UREGS_cs, struct cpu_user_regs, cs);
    OFFSET(UREGS_eflags, struct cpu_user_regs, rflags);
    OFFSET(UREGS_rsp, struct cpu_user_regs, rsp);
    OFFSET(UREGS_ss, struct cpu_user_regs, ss);
    OFFSET(UREGS_ds, struct cpu_user_regs, ds);
    OFFSET(UREGS_es, struct cpu_user_regs, es);
    OFFSET(UREGS_fs, struct cpu_user_regs, fs);
    OFFSET(UREGS_gs, struct cpu_user_regs, gs);
    OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, es);
    DEFINE(UREGS_user_sizeof, sizeof(struct cpu_user_regs));
    BLANK();

    OFFSET(irq_caps_offset, struct domain, irq_caps);
    OFFSET(next_in_list_offset, struct domain, next_in_list);
    OFFSET(VCPU_processor, struct vcpu, processor);
    OFFSET(VCPU_domain, struct vcpu, domain);
    OFFSET(VCPU_vcpu_info, struct vcpu, vcpu_info);
    OFFSET(VCPU_trap_bounce, struct vcpu, arch.pv_vcpu.trap_bounce);
    OFFSET(VCPU_thread_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_event_addr, struct vcpu, arch.pv_vcpu.event_callback_eip);
    OFFSET(VCPU_event_sel, struct vcpu, arch.pv_vcpu.event_callback_cs);
    OFFSET(VCPU_failsafe_addr, struct vcpu,
           arch.pv_vcpu.failsafe_callback_eip);
    OFFSET(VCPU_failsafe_sel, struct vcpu,
           arch.pv_vcpu.failsafe_callback_cs);
    OFFSET(VCPU_syscall_addr, struct vcpu,
           arch.pv_vcpu.syscall_callback_eip);
    OFFSET(VCPU_syscall32_addr, struct vcpu,
           arch.pv_vcpu.syscall32_callback_eip);
    OFFSET(VCPU_syscall32_sel, struct vcpu,
           arch.pv_vcpu.syscall32_callback_cs);
    OFFSET(VCPU_syscall32_disables_events, struct vcpu,
           arch.pv_vcpu.syscall32_disables_events);
    OFFSET(VCPU_sysenter_addr, struct vcpu,
           arch.pv_vcpu.sysenter_callback_eip);
    OFFSET(VCPU_sysenter_sel, struct vcpu,
           arch.pv_vcpu.sysenter_callback_cs);
    OFFSET(VCPU_sysenter_disables_events, struct vcpu,
           arch.pv_vcpu.sysenter_disables_events);
    OFFSET(VCPU_trap_ctxt, struct vcpu, arch.pv_vcpu.trap_ctxt);
    OFFSET(VCPU_kernel_sp, struct vcpu, arch.pv_vcpu.kernel_sp);
    OFFSET(VCPU_kernel_ss, struct vcpu, arch.pv_vcpu.kernel_ss);
    OFFSET(VCPU_iopl, struct vcpu, arch.pv_vcpu.iopl);
    OFFSET(VCPU_guest_context_flags, struct vcpu, arch.vgc_flags);
    OFFSET(VCPU_cr3, struct vcpu, arch.cr3);
    OFFSET(VCPU_arch_msr, struct vcpu, arch.msr);
    OFFSET(VCPU_nmi_pending, struct vcpu, nmi_pending);
    OFFSET(VCPU_mce_pending, struct vcpu, mce_pending);
    OFFSET(VCPU_nmi_old_mask, struct vcpu, nmi_state.old_mask);
    OFFSET(VCPU_mce_old_mask, struct vcpu, mce_state.old_mask);
    OFFSET(VCPU_async_exception_mask, struct vcpu, async_exception_mask);
    DEFINE(VCPU_TRAP_NMI, VCPU_TRAP_NMI);
    DEFINE(VCPU_TRAP_MCE, VCPU_TRAP_MCE);
    DEFINE(_VGCF_failsafe_disables_events, _VGCF_failsafe_disables_events);
    DEFINE(_VGCF_syscall_disables_events,  _VGCF_syscall_disables_events);
    BLANK();

    OFFSET(VCPU_svm_vmcb_pa, struct vcpu, arch.hvm_svm.vmcb_pa);
    OFFSET(VCPU_svm_vmcb, struct vcpu, arch.hvm_svm.vmcb);
    OFFSET(VCPU_svm_vmcb_in_sync, struct vcpu, arch.hvm_svm.vmcb_in_sync);
    BLANK();

    OFFSET(VCPU_vmx_launched, struct vcpu, arch.hvm_vmx.launched);
    OFFSET(VCPU_vmx_realmode, struct vcpu, arch.hvm_vmx.vmx_realmode);
    OFFSET(VCPU_vmx_emulate, struct vcpu, arch.hvm_vmx.vmx_emulate);
    OFFSET(VCPU_vm86_seg_mask, struct vcpu, arch.hvm_vmx.vm86_segment_mask);
    OFFSET(VCPU_hvm_guest_cr2, struct vcpu, arch.hvm_vcpu.guest_cr[2]);
    BLANK();

    OFFSET(VCPU_nhvm_guestmode, struct vcpu, arch.hvm_vcpu.nvcpu.nv_guestmode);
    OFFSET(VCPU_nhvm_p2m, struct vcpu, arch.hvm_vcpu.nvcpu.nv_p2m);
    OFFSET(VCPU_nsvm_hap_enabled, struct vcpu, arch.hvm_vcpu.nvcpu.u.nsvm.ns_hap_enabled);
    BLANK();

    OFFSET(DOMAIN_is_32bit_pv, struct domain, arch.is_32bit_pv);
    BLANK();

    OFFSET(VMCB_rax, struct vmcb_struct, rax);
    OFFSET(VMCB_rip, struct vmcb_struct, rip);
    OFFSET(VMCB_rsp, struct vmcb_struct, rsp);
    OFFSET(VMCB_rflags, struct vmcb_struct, rflags);
    BLANK();

    OFFSET(VCPUINFO_upcall_pending, struct vcpu_info, evtchn_upcall_pending);
    OFFSET(VCPUINFO_upcall_mask, struct vcpu_info, evtchn_upcall_mask);
    BLANK();

    OFFSET(COMPAT_VCPUINFO_upcall_pending, struct compat_vcpu_info, evtchn_upcall_pending);
    OFFSET(COMPAT_VCPUINFO_upcall_mask, struct compat_vcpu_info, evtchn_upcall_mask);
    BLANK();

    OFFSET(CPUINFO_guest_cpu_user_regs, struct cpu_info, guest_cpu_user_regs);
    OFFSET(CPUINFO_processor_id, struct cpu_info, processor_id);
    OFFSET(CPUINFO_current_vcpu, struct cpu_info, current_vcpu);
    OFFSET(CPUINFO_cr4, struct cpu_info, cr4);
    OFFSET(CPUINFO_xen_cr3, struct cpu_info, xen_cr3);
    OFFSET(CPUINFO_pv_cr3, struct cpu_info, pv_cr3);
    OFFSET(CPUINFO_shadow_spec_ctrl, struct cpu_info, shadow_spec_ctrl);
    OFFSET(CPUINFO_use_shadow_spec_ctrl, struct cpu_info, use_shadow_spec_ctrl);
    OFFSET(CPUINFO_bti_ist_info, struct cpu_info, bti_ist_info);
    DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));
    BLANK();

    OFFSET(TRAPINFO_eip, struct trap_info, address);
    OFFSET(TRAPINFO_cs, struct trap_info, cs);
    OFFSET(TRAPINFO_flags, struct trap_info, flags);
    DEFINE(TRAPINFO_sizeof, sizeof(struct trap_info));
    BLANK();

    OFFSET(TRAPBOUNCE_error_code, struct trap_bounce, error_code);
    OFFSET(TRAPBOUNCE_flags, struct trap_bounce, flags);
    OFFSET(TRAPBOUNCE_cs, struct trap_bounce, cs);
    OFFSET(TRAPBOUNCE_eip, struct trap_bounce, eip);
    BLANK();

    OFFSET(VCPUMSR_spec_ctrl_raw, struct msr_vcpu_policy, spec_ctrl.raw);
    BLANK();

#ifdef CONFIG_PERF_COUNTERS
    DEFINE(ASM_PERFC_exceptions, PERFC_exceptions);
    BLANK();
#endif

    DEFINE(IRQSTAT_shift, ilog2(sizeof(irq_cpustat_t)));
    OFFSET(IRQSTAT_softirq_pending, irq_cpustat_t, __softirq_pending);
    BLANK();

    OFFSET(CPUINFO_features, struct cpuinfo_x86, x86_capability);
    BLANK();

    OFFSET(MB_flags, multiboot_info_t, flags);
    OFFSET(MB_cmdline, multiboot_info_t, cmdline);
    OFFSET(MB_mem_lower, multiboot_info_t, mem_lower);
    BLANK();

    DEFINE(MB2_fixed_sizeof, sizeof(multiboot2_fixed_t));
    OFFSET(MB2_fixed_total_size, multiboot2_fixed_t, total_size);
    OFFSET(MB2_tag_type, multiboot2_tag_t, type);
    OFFSET(MB2_tag_size, multiboot2_tag_t, size);
    OFFSET(MB2_load_base_addr, multiboot2_tag_load_base_addr_t, load_base_addr);
    OFFSET(MB2_mem_lower, multiboot2_tag_basic_meminfo_t, mem_lower);
    OFFSET(MB2_efi64_st, multiboot2_tag_efi64_t, pointer);
    OFFSET(MB2_efi64_ih, multiboot2_tag_efi64_ih_t, pointer);
    BLANK();

    DEFINE(l2_identmap_sizeof, sizeof(l2_identmap));
    BLANK();

    OFFSET(DOMAIN_vm_assist, struct domain, vm_assist);
}
