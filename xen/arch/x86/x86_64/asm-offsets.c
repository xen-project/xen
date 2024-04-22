/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */
#define COMPILE_OFFSETS

#ifdef CONFIG_PERF_COUNTERS
#include <xen/perfc.h>
#endif
#include <xen/sched.h>
#ifdef CONFIG_PV32
#include <compat/xen.h>
#endif
#include <asm/hardirq.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>

#ifdef CONFIG_VIDEO
# include "../boot/video.h"
#endif

#define DEFINE(_sym, _val)                                                 \
    asm volatile ( "\n.ascii\"==>#define " #_sym " %0 /* " #_val " */<==\""\
                   :: "i" (_val) )
#define BLANK()                                                            \
    asm volatile ( "\n.ascii\"==><==\"" )
#define OFFSET(_sym, _str, _mem)                                           \
    DEFINE(_sym, offsetof(_str, _mem))

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
    OFFSET(UREGS_eflags, struct cpu_user_regs, rflags);
    OFFSET(UREGS_rsp, struct cpu_user_regs, rsp);
    OFFSET(UREGS_ss, struct cpu_user_regs, ss);
    OFFSET(UREGS_kernel_sizeof, struct cpu_user_regs, es);
    BLANK();

    /*
     * EFRAME_* is for the entry/exit logic where %rsp is pointing at
     * UREGS_error_code and GPRs are still/already guest values.
     */
#define OFFSET_EF(sym, mem, ...)                                        \
    DEFINE(sym, offsetof(struct cpu_user_regs, mem) -                   \
                offsetof(struct cpu_user_regs, error_code) __VA_ARGS__)

    OFFSET_EF(EFRAME_entry_vector,    entry_vector);
    OFFSET_EF(EFRAME_rip,             rip);
    OFFSET_EF(EFRAME_cs,              cs);
    OFFSET_EF(EFRAME_eflags,          eflags);

    /*
     * These aren't real fields.  They're spare space, used by the IST
     * exit-to-xen path.
     */
    OFFSET_EF(EFRAME_shadow_scf,      eflags, +4);
    OFFSET_EF(EFRAME_shadow_sel,      eflags, +6);

    OFFSET_EF(EFRAME_rsp,             rsp);
    BLANK();

#undef OFFSET_EF

    OFFSET(VCPU_processor, struct vcpu, processor);
    OFFSET(VCPU_domain, struct vcpu, domain);
    OFFSET(VCPU_vcpu_info, struct vcpu, vcpu_info_area.map);
    OFFSET(VCPU_trap_bounce, struct vcpu, arch.pv.trap_bounce);
    OFFSET(VCPU_thread_flags, struct vcpu, arch.flags);
    OFFSET(VCPU_event_addr, struct vcpu, arch.pv.event_callback_eip);
    OFFSET(VCPU_event_sel, struct vcpu, arch.pv.event_callback_cs);
    OFFSET(VCPU_syscall_addr, struct vcpu, arch.pv.syscall_callback_eip);
    OFFSET(VCPU_syscall32_addr, struct vcpu, arch.pv.syscall32_callback_eip);
    OFFSET(VCPU_syscall32_sel, struct vcpu, arch.pv.syscall32_callback_cs);
    OFFSET(VCPU_syscall32_disables_events,
           struct vcpu, arch.pv.syscall32_disables_events);
    OFFSET(VCPU_sysenter_addr, struct vcpu, arch.pv.sysenter_callback_eip);
    OFFSET(VCPU_sysenter_sel, struct vcpu, arch.pv.sysenter_callback_cs);
    OFFSET(VCPU_sysenter_disables_events,
           struct vcpu, arch.pv.sysenter_disables_events);
    OFFSET(VCPU_trap_ctxt, struct vcpu, arch.pv.trap_ctxt);
    OFFSET(VCPU_kernel_sp, struct vcpu, arch.pv.kernel_sp);
    OFFSET(VCPU_kernel_ss, struct vcpu, arch.pv.kernel_ss);
    OFFSET(VCPU_iopl, struct vcpu, arch.pv.iopl);
    OFFSET(VCPU_guest_context_flags, struct vcpu, arch.pv.vgc_flags);
    OFFSET(VCPU_cr3, struct vcpu, arch.cr3);
    OFFSET(VCPU_arch_msrs, struct vcpu, arch.msrs);
    OFFSET(VCPU_nmi_pending, struct vcpu, arch.nmi_pending);
    OFFSET(VCPU_mce_pending, struct vcpu, arch.mce_pending);
    OFFSET(VCPU_nmi_old_mask, struct vcpu, arch.nmi_state.old_mask);
    OFFSET(VCPU_mce_old_mask, struct vcpu, arch.mce_state.old_mask);
    OFFSET(VCPU_async_exception_mask, struct vcpu, arch.async_exception_mask);
    DEFINE(VCPU_TRAP_NMI, VCPU_TRAP_NMI);
    DEFINE(VCPU_TRAP_MCE, VCPU_TRAP_MCE);
    DEFINE(_VGCF_syscall_disables_events,  _VGCF_syscall_disables_events);
    BLANK();

#ifdef CONFIG_HVM
    OFFSET(VCPU_svm_vmcb_pa, struct vcpu, arch.hvm.svm.vmcb_pa);
    OFFSET(VCPU_svm_vmcb, struct vcpu, arch.hvm.svm.vmcb);
    BLANK();

    OFFSET(VCPU_vmx_launched, struct vcpu, arch.hvm.vmx.launched);
    OFFSET(VCPU_vmx_realmode, struct vcpu, arch.hvm.vmx.vmx_realmode);
    OFFSET(VCPU_vmx_emulate, struct vcpu, arch.hvm.vmx.vmx_emulate);
    OFFSET(VCPU_vm86_seg_mask, struct vcpu, arch.hvm.vmx.vm86_segment_mask);
    OFFSET(VCPU_hvm_guest_cr2, struct vcpu, arch.hvm.guest_cr[2]);
    BLANK();

    OFFSET(VCPU_nhvm_guestmode, struct vcpu, arch.hvm.nvcpu.nv_guestmode);
    OFFSET(VCPU_nhvm_p2m, struct vcpu, arch.hvm.nvcpu.nv_p2m);
    OFFSET(VCPU_nsvm_hap_enabled, struct vcpu, arch.hvm.nvcpu.u.nsvm.ns_hap_enabled);
    BLANK();
#endif

#ifdef CONFIG_PV32
    OFFSET(DOMAIN_is_32bit_pv, struct domain, arch.pv.is_32bit);
    BLANK();

    OFFSET(COMPAT_VCPUINFO_upcall_pending, struct compat_vcpu_info, evtchn_upcall_pending);
    OFFSET(COMPAT_VCPUINFO_upcall_mask, struct compat_vcpu_info, evtchn_upcall_mask);
    BLANK();
#endif

#ifdef CONFIG_PV
    OFFSET(VCPUINFO_upcall_pending, struct vcpu_info, evtchn_upcall_pending);
    OFFSET(VCPUINFO_upcall_mask, struct vcpu_info, evtchn_upcall_mask);
    BLANK();
#endif

    OFFSET(CPUINFO_guest_cpu_user_regs, struct cpu_info, guest_cpu_user_regs);
    OFFSET(CPUINFO_error_code, struct cpu_info, guest_cpu_user_regs.error_code);
    OFFSET(CPUINFO_rip, struct cpu_info, guest_cpu_user_regs.rip);
    OFFSET(CPUINFO_processor_id, struct cpu_info, processor_id);
    OFFSET(CPUINFO_verw_sel, struct cpu_info, verw_sel);
    OFFSET(CPUINFO_current_vcpu, struct cpu_info, current_vcpu);
    OFFSET(CPUINFO_per_cpu_offset, struct cpu_info, per_cpu_offset);
    OFFSET(CPUINFO_cr4, struct cpu_info, cr4);
    OFFSET(CPUINFO_xen_cr3, struct cpu_info, xen_cr3);
    OFFSET(CPUINFO_pv_cr3, struct cpu_info, pv_cr3);
    OFFSET(CPUINFO_shadow_spec_ctrl, struct cpu_info, shadow_spec_ctrl);
    OFFSET(CPUINFO_xen_spec_ctrl, struct cpu_info, xen_spec_ctrl);
    OFFSET(CPUINFO_last_spec_ctrl, struct cpu_info, last_spec_ctrl);
    OFFSET(CPUINFO_scf, struct cpu_info, scf);
    OFFSET(CPUINFO_root_pgt_changed, struct cpu_info, root_pgt_changed);
    OFFSET(CPUINFO_use_pv_cr3, struct cpu_info, use_pv_cr3);
    DEFINE(CPUINFO_sizeof, sizeof(struct cpu_info));
    BLANK();

#ifdef CONFIG_PV
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
#endif

    OFFSET(VCPUMSR_spec_ctrl_raw, struct vcpu_msrs, spec_ctrl.raw);
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
    OFFSET(MB2_tag_string, multiboot2_tag_string_t, string);
    BLANK();

    OFFSET(DOMAIN_vm_assist, struct domain, vm_assist);
    BLANK();

#ifdef CONFIG_VIDEO
    OFFSET(BVI_cursor_pos,      struct boot_video_info, orig_x);
    OFFSET(BVI_video_mode,      struct boot_video_info, orig_video_mode);
    OFFSET(BVI_video_cols,      struct boot_video_info, orig_video_cols);
    OFFSET(BVI_video_lines,     struct boot_video_info, orig_video_lines);
    OFFSET(BVI_have_vga,        struct boot_video_info, orig_video_isVGA);
    OFFSET(BVI_font_points,     struct boot_video_info, orig_video_points);
    OFFSET(BVI_capabilities,    struct boot_video_info, capabilities);
    OFFSET(BVI_lfb_linelength,  struct boot_video_info, lfb_linelength);
    OFFSET(BVI_lfb_width,       struct boot_video_info, lfb_width);
    OFFSET(BVI_lfb_height,      struct boot_video_info, lfb_height);
    OFFSET(BVI_lfb_depth,       struct boot_video_info, lfb_depth);
    OFFSET(BVI_lfb_base,        struct boot_video_info, lfb_base);
    OFFSET(BVI_lfb_size,        struct boot_video_info, lfb_size);
    OFFSET(BVI_lfb_colors,      struct boot_video_info, colors);
    OFFSET(BVI_vesapm_seg,      struct boot_video_info, vesapm.seg);
    OFFSET(BVI_vesapm_off,      struct boot_video_info, vesapm.off);
    OFFSET(BVI_vesa_attrib,     struct boot_video_info, vesa_attrib);
    DEFINE(BVI_size,            sizeof(struct boot_video_info));
    BLANK();
#endif /* CONFIG_VIDEO */
}
