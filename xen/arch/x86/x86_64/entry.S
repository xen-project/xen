/*
 * Hypercall and fault low-level handling routines.
 *
 * Copyright (c) 2005, K A Fraser
 */

        .file "x86_64/entry.S"

#include <asm/asm_defns.h>
#include <asm/irq-vectors.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <public/xen.h>

/* %rsp: struct cpu_user_regs */
.macro ASSERT_CONTEXT_IS_XEN
#ifndef NDEBUG
        testb $3, UREGS_cs(%rsp)
        UNLIKELY_START(nz, ASSERT_XEN_\@)
        ASSERT_FAILED("INTERRUPTED XEN CONTEXT")
        __UNLIKELY_END(ASSERT_XEN_\@)
#endif
.endm

#ifdef CONFIG_PV
/* %rbx: struct vcpu */
FUNC_LOCAL(switch_to_kernel)
        leaq  VCPU_trap_bounce(%rbx),%rdx

        /* TB_eip = 32-bit syscall ? syscall32_addr : syscall_addr */
        mov   VCPU_syscall32_addr(%rbx), %rcx
        mov   VCPU_syscall_addr(%rbx), %rax
        cmpw  $FLAT_USER_CS32,UREGS_cs(%rsp)
        cmove %rcx, %rax

        /* TB_flags = VGCF_syscall_disables_events ? TBF_INTERRUPT : 0 */
        btl   $_VGCF_syscall_disables_events,VCPU_guest_context_flags(%rbx)
        setc  %cl
        leal  (,%rcx,TBF_INTERRUPT),%ecx

        /*
         * The PV ABI hardcodes the (guest-inaccessible and virtual)
         * SYSCALL_MASK MSR such that DF (and nothing else) would be cleared.
         * Note that the equivalent of IF (VGCF_syscall_disables_events) is
         * dealt with separately above.
         */
        mov   $~X86_EFLAGS_DF, %esi

        test  %rax, %rax
UNLIKELY_START(z, syscall_no_callback) /* TB_eip == 0 => #UD */
        mov   VCPU_trap_ctxt(%rbx), %rdi
        movl  $X86_EXC_UD, UREGS_entry_vector(%rsp)
        subq  $2, UREGS_rip(%rsp)
        mov   X86_EXC_UD * TRAPINFO_sizeof + TRAPINFO_eip(%rdi), %rax
        testb $4, X86_EXC_UD * TRAPINFO_sizeof + TRAPINFO_flags(%rdi)
        setnz %cl
        lea   TBF_EXCEPTION(, %rcx, TBF_INTERRUPT), %ecx
        or    $~0, %esi                 /* Don't clear DF */
UNLIKELY_END(syscall_no_callback)

        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        /* Conditionally clear DF */
        and   %esi, UREGS_eflags(%rsp)
/* %rbx: struct vcpu */
test_all_events:
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*test_softirqs:*/
        movl  VCPU_processor(%rbx), %eax
        shll  $IRQSTAT_shift, %eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip), %rcx
        cmpl  $0, (%rcx, %rax, 1)
        jne   process_softirqs

        /* Inject exception if pending. */
        lea   VCPU_trap_bounce(%rbx), %rdx
        testb $TBF_EXCEPTION, TRAPBOUNCE_flags(%rdx)
        jnz   .Lprocess_trapbounce

        cmpb  $0, VCPU_mce_pending(%rbx)
        jne   process_mce
.Ltest_guest_nmi:
        cmpb  $0, VCPU_nmi_pending(%rbx)
        jne   process_nmi
test_guest_events:
        movq  VCPU_vcpu_info(%rbx), %rax
        movzwl VCPUINFO_upcall_pending(%rax), %eax
        decl  %eax
        cmpl  $0xfe, %eax
        ja    restore_all_guest
/*process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx), %rdx
        movq  VCPU_event_addr(%rbx), %rax
        movq  %rax, TRAPBOUNCE_eip(%rdx)
        movb  $TBF_INTERRUPT, TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        jmp   test_all_events

/* %rbx: struct vcpu */
LABEL_LOCAL(process_softirqs)
        sti
        call do_softirq
        jmp  test_all_events

/* %rbx: struct vcpu, %rdx struct trap_bounce */
LABEL_LOCAL(.Lprocess_trapbounce)
        sti
.Lbounce_exception:
        call  create_bounce_frame
        jmp   test_all_events

/* %rbx: struct vcpu */
LABEL_LOCAL(process_mce)
        testb $1 << VCPU_TRAP_MCE, VCPU_async_exception_mask(%rbx)
        jnz  .Ltest_guest_nmi
        sti
        movb $0, VCPU_mce_pending(%rbx)
        call set_guest_machinecheck_trapbounce
        test %al, %al
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx), %edx # save mask for the
        movb %dl, VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE, %edx
        movb %dl, VCPU_async_exception_mask(%rbx)
        jmp  process_trap

/* %rbx: struct vcpu */
LABEL_LOCAL(process_nmi)
        testb $1 << VCPU_TRAP_NMI, VCPU_async_exception_mask(%rbx)
        jnz  test_guest_events
        sti
        movb $0, VCPU_nmi_pending(%rbx)
        call set_guest_nmi_trapbounce
        test %al, %al
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx), %edx # save mask for the
        movb %dl, VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI, %edx
        movb %dl, VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
process_trap:
        leaq VCPU_trap_bounce(%rbx), %rdx
        call create_bounce_frame
        jmp  test_all_events
END(switch_to_kernel)

        .section .text.entry, "ax", @progbits

/* %rbx: struct vcpu, interrupts disabled */
FUNC_LOCAL(restore_all_guest)
        ASSERT_INTERRUPTS_DISABLED

        /* Stash guest SPEC_CTRL value while we can read struct vcpu. */
        mov VCPU_arch_msrs(%rbx), %rdx
        mov VCPUMSR_spec_ctrl_raw(%rdx), %r15d

        /* Copy guest mappings and switch to per-CPU root page table. */
        mov   VCPU_cr3(%rbx), %r9
        GET_STACK_END(dx)
        mov   STACK_CPUINFO_FIELD(pv_cr3)(%rdx), %rdi
        test  %rdi, %rdi
        jz    .Lrag_keep_cr3
        mov   %rdi, %rax
        cmpb  $0, STACK_CPUINFO_FIELD(root_pgt_changed)(%rdx)
        je    .Lrag_copy_done
        movb  $0, STACK_CPUINFO_FIELD(root_pgt_changed)(%rdx)
        movabs $PADDR_MASK & PAGE_MASK, %rsi
        movabs $DIRECTMAP_VIRT_START, %rcx
        and   %rsi, %rdi
        and   %r9, %rsi
        add   %rcx, %rdi
        add   %rcx, %rsi
        mov   $ROOT_PAGETABLE_FIRST_XEN_SLOT, %ecx
        mov   root_table_offset(SH_LINEAR_PT_VIRT_START)*8(%rsi), %r8
        mov   %r8, root_table_offset(SH_LINEAR_PT_VIRT_START)*8(%rdi)
        rep movsq
        mov   $ROOT_PAGETABLE_ENTRIES - \
               ROOT_PAGETABLE_LAST_XEN_SLOT - 1, %ecx
        sub   $(ROOT_PAGETABLE_FIRST_XEN_SLOT - \
                ROOT_PAGETABLE_LAST_XEN_SLOT - 1) * 8, %rsi
        sub   $(ROOT_PAGETABLE_FIRST_XEN_SLOT - \
                ROOT_PAGETABLE_LAST_XEN_SLOT - 1) * 8, %rdi
        rep movsq
.Lrag_copy_done:
        mov   %r9, STACK_CPUINFO_FIELD(xen_cr3)(%rdx)
        movb  $1, STACK_CPUINFO_FIELD(use_pv_cr3)(%rdx)
        mov   %rax, %cr3
.Lrag_keep_cr3:

        /* Restore stashed SPEC_CTRL value. */
        mov   %r15d, %eax

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        SPEC_CTRL_EXIT_TO_PV    /* Req: a=spec_ctrl %rsp=regs/cpuinfo, Clob: cd */

        RESTORE_ALL
        BUILD_BUG_ON(TRAP_syscall & 0xff)
        testb $TRAP_syscall >> 8, EFRAME_entry_vector + 1(%rsp)
        jz    iret_exit_to_guest

        mov   EFRAME_eflags(%rsp), %r11
        andq  $~(X86_EFLAGS_IOPL | X86_EFLAGS_VM), %r11
        orq   $X86_EFLAGS_IF,%r11

        /* Don't use SYSRET path if the return address is not canonical. */
        mov   EFRAME_rip(%rsp), %rcx
        sarq  $47,%rcx
        incl  %ecx
        cmpl  $1,%ecx
        ja    .Lrestore_rcx_iret_exit_to_guest

#ifdef CONFIG_XEN_SHSTK
        /* Clear the supervisor shadow stack token busy bit. */
.macro rag_clrssbsy
        rdsspq %rcx
        clrssbsy (%rcx)
.endm
        ALTERNATIVE "", rag_clrssbsy, X86_FEATURE_XEN_SHSTK
#endif

        mov   EFRAME_rip(%rsp), %rcx

        SPEC_CTRL_COND_VERW     /* Req: %rsp=eframe                    Clob: efl */

        cmpw  $FLAT_USER_CS32, EFRAME_cs(%rsp)
        mov   EFRAME_rsp(%rsp), %rsp
        je    1f
        sysretq
1:      sysretl

LABEL_LOCAL(.Lrestore_rcx_iret_exit_to_guest)
        mov   EFRAME_rip(%rsp), %rcx
/* No special register assumptions. */
iret_exit_to_guest:
        andl  $~(X86_EFLAGS_IOPL | X86_EFLAGS_VM), EFRAME_eflags(%rsp)
        orb   $X86_EFLAGS_IF >> 8, EFRAME_eflags + 1(%rsp)

        SPEC_CTRL_COND_VERW     /* Req: %rsp=eframe                    Clob: efl */

        addq  $8,%rsp
.Lft0:  iretq
        _ASM_PRE_EXTABLE(.Lft0, handle_exception)
END(restore_all_guest)

/*
 * When entering SYSCALL from kernel mode:
 *  %rax                            = hypercall vector
 *  %rdi, %rsi, %rdx, %r10, %r8, %9 = hypercall arguments
 *  %rcx                            = SYSCALL-saved %rip
 *  NB. We must move %r10 to %rcx for C function-calling ABI.
 *
 * When entering SYSCALL from user mode:
 *  Vector directly to the registered arch.syscall_addr.
 *
 * Initial work is done by per-CPU trampolines.
 *  - Guest %rax stored in the %ss slot
 *  - Guest %rsp stored in %rax
 *  - Xen stack loaded, pointing at the %ss slot
 */
FUNC(lstar_enter)
#ifdef CONFIG_XEN_SHSTK
        ALTERNATIVE "", "setssbsy", X86_FEATURE_XEN_SHSTK
#endif
        push  %rax          /* Guest %rsp */
        movq  8(%rsp), %rax /* Restore guest %rax */
        movq  $FLAT_KERNEL_SS,8(%rsp)
        pushq %r11
        pushq $FLAT_KERNEL_CS64
        pushq %rcx
        pushq $0
        BUILD_BUG_ON(TRAP_syscall & 0xff)
        movb  $TRAP_syscall >> 8, EFRAME_entry_vector + 1(%rsp)
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_PV /* Req: %rsp=regs/cpuinfo, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        test  %rcx, %rcx
        jz    .Llstar_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.Llstar_cr3_okay:
        sti

        movq  STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx
        testb $TF_kernel_mode,VCPU_thread_flags(%rbx)
        jz    switch_to_kernel

        mov   %rsp, %rdi
        call  pv_hypercall
        jmp   test_all_events
END(lstar_enter)

/* See lstar_enter for entry register state. */
FUNC(cstar_enter)
#ifdef CONFIG_XEN_SHSTK
        ALTERNATIVE "", "setssbsy", X86_FEATURE_XEN_SHSTK
#endif
        push  %rax          /* Guest %rsp */
        movq  8(%rsp), %rax /* Restore guest %rax. */
        movq  $FLAT_USER_SS32, 8(%rsp) /* Assume a 64bit domain.  Compat handled lower. */
        pushq %r11
        pushq $FLAT_USER_CS32
        pushq %rcx
        pushq $0
        BUILD_BUG_ON(TRAP_syscall & 0xff)
        movb  $TRAP_syscall >> 8, EFRAME_entry_vector + 1(%rsp)
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_PV /* Req: %rsp=regs/cpuinfo, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        test  %rcx, %rcx
        jz    .Lcstar_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.Lcstar_cr3_okay:
        sti

        CR4_PV32_RESTORE /* Clob: ac */

        movq  STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx

#ifdef CONFIG_PV32
        movq  VCPU_domain(%rbx), %rcx
        cmpb  $0, DOMAIN_is_32bit_pv(%rcx)
        jne   compat_syscall
#endif
        jmp   switch_to_kernel
END(cstar_enter)

FUNC(sysenter_entry)
        ENDBR64
#ifdef CONFIG_XEN_SHSTK
        ALTERNATIVE "", "setssbsy", X86_FEATURE_XEN_SHSTK
#endif
        pushq $FLAT_USER_SS
        pushq $0
        pushfq
LABEL(sysenter_eflags_saved, 0)
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        pushq $3 /* ring 3 null cs */
        pushq $0 /* null rip */
        pushq $0
        BUILD_BUG_ON(TRAP_syscall & 0xff)
        movb  $TRAP_syscall >> 8, EFRAME_entry_vector + 1(%rsp)
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_PV /* Req: %rsp=regs/cpuinfo, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        /* PUSHF above has saved EFLAGS.IF clear (the caller had it set). */
        orb   $X86_EFLAGS_IF >> 8, UREGS_eflags + 1(%rsp)
        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        test  %rcx, %rcx
        jz    .Lsyse_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.Lsyse_cr3_okay:
        sti

        movq  STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx
        cmpb  $0,VCPU_sysenter_disables_events(%rbx)
        movq  VCPU_sysenter_addr(%rbx),%rax
        setne %cl
        testb $X86_EFLAGS_NT >> 8, UREGS_eflags + 1(%rsp)
        leaq  VCPU_trap_bounce(%rbx),%rdx
UNLIKELY_START(nz, sysenter_nt_set)
        pushfq
        andb  $~(X86_EFLAGS_NT >> 8), 1(%rsp)
        popfq
UNLIKELY_END(sysenter_nt_set)
        testq %rax,%rax
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, sysenter_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rsi
        movl  $X86_EXC_GP, UREGS_entry_vector(%rsp)
        movl  %eax,TRAPBOUNCE_error_code(%rdx)
        movq  X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_eip(%rsi),%rax
        testb $4, X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_flags(%rsi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(sysenter_gpf)
        movq  VCPU_domain(%rbx),%rdi
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
#ifdef CONFIG_PV32
        cmpb  $0, DOMAIN_is_32bit_pv(%rdi)
        jne   compat_sysenter
#endif
        jmp   .Lbounce_exception
END(sysenter_entry)

FUNC(entry_int80)
        ENDBR64
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        pushq $0
        movb  $0x80, EFRAME_entry_vector(%rsp)
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_PV /* Req: %rsp=regs/cpuinfo, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        test  %rcx, %rcx
        jz    .Lint80_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.Lint80_cr3_okay:
        sti

        cmpb  $0,untrusted_msi(%rip)
UNLIKELY_START(ne, msi_check)
        movl  $0x80,%edi
        call  check_for_unexpected_msi
UNLIKELY_END(msi_check)

        movq  STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx

        mov   VCPU_trap_ctxt(%rbx), %rsi
        mov   VCPU_domain(%rbx), %rax

        /*
         * if ( null_trap_info(v, &v->arch.pv.trap_ctxt[0x80]) )
         *    goto int80_slow_path;
         */
        mov    0x80 * TRAPINFO_sizeof + TRAPINFO_eip(%rsi), %rdi
        movzwl 0x80 * TRAPINFO_sizeof + TRAPINFO_cs (%rsi), %ecx

#ifdef CONFIG_PV32
        mov   %ecx, %edx
        and   $~3, %edx

        cmpb  $0, DOMAIN_is_32bit_pv(%rax)
        cmove %rdi, %rdx

        test  %rdx, %rdx
        jz    int80_slow_path
#else
        test  %rdi, %rdi
        jz    int80_slow_path
#endif

        /* Construct trap_bounce from trap_ctxt[0x80]. */
        lea   VCPU_trap_bounce(%rbx), %rdx
        mov   %cx, TRAPBOUNCE_cs(%rdx)
        mov   %rdi, TRAPBOUNCE_eip(%rdx)

        /* TB_flags = (TI_GET_IF(ti) ? TBF_INTERRUPT : 0); */
        testb $4, 0x80 * TRAPINFO_sizeof + TRAPINFO_flags(%rsi)
        setnz %cl
        lea   (, %rcx, TBF_INTERRUPT), %ecx
        mov   %cl, TRAPBOUNCE_flags(%rdx)

#ifdef CONFIG_PV32
        cmpb  $0, DOMAIN_is_32bit_pv(%rax)
        jne   compat_int80_direct_trap
#endif

        call  create_bounce_frame
        jmp   test_all_events

int80_slow_path:
        /* 
         * Setup entry vector and error code as if this was a GPF caused by an
         * IDT entry with DPL==0.
         */
        movl  $((0x80 << 3) | X86_XEC_IDT),UREGS_error_code(%rsp)
        movl  $X86_EXC_GP, UREGS_entry_vector(%rsp)
        /* A GPF wouldn't have incremented the instruction pointer. */
        subq  $2,UREGS_rip(%rsp)
        /*
         * While we've cleared xen_cr3 above already, normal exception handling
         * code has logic to restore the original value from %r15. Therefore we
         * need to set up %r14 here, while %r15 is required to still be zero.
         */
        GET_STACK_END(14)
        jmp   handle_exception_saved
END(entry_int80)

        /* create_bounce_frame & helpers don't need to be in .text.entry */
        .text

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS STACK:                     */
/*   { RCX, R11, [ERRCODE,] RIP, CS, RFLAGS, RSP, SS }                   */
/* %rdx: trap_bounce, %rbx: struct vcpu                                  */
/* On return only %rbx and %rdx are guaranteed non-clobbered.            */
FUNC_LOCAL(create_bounce_frame)
        ASSERT_INTERRUPTS_ENABLED
        testb $TF_kernel_mode,VCPU_thread_flags(%rbx)
        jnz   1f
        /* Push new frame at registered guest-OS stack base. */
        pushq %rdx
        movq  %rbx,%rdi
        call  toggle_guest_mode
        popq  %rdx
        movq  VCPU_kernel_sp(%rbx),%rsi
        jmp   2f
1:      /* In kernel context already: push new frame at existing %rsp. */
        movq  UREGS_rsp+8(%rsp),%rsi
        andb  $0xfc,UREGS_cs+8(%rsp)    # Indicate kernel context to guest.
2:      andq  $~0xf,%rsi                # Stack frames are 16-byte aligned.
        movq  $HYPERVISOR_VIRT_START+1,%rax
        cmpq  %rax,%rsi
        movq  $HYPERVISOR_VIRT_END+8*8,%rax
        sbb   %ecx,%ecx                 # In +ve address space? Then okay.
        cmpq  %rax,%rsi
        adc   %ecx,%ecx                 # Above Xen private area? Then okay.
UNLIKELY_START(g, create_bounce_frame_bad_sp)
        lea   UNLIKELY_DISPATCH_LABEL(create_bounce_frame_bad_sp)(%rip), %rdi
        jmp   asm_domain_crash_synchronous  /* Does not return */
__UNLIKELY_END(create_bounce_frame_bad_sp)

        guest_access_mask_ptr %rsi, %rax, %rcx

#define STORE_GUEST_STACK(reg, n) \
0:      movq  %reg,(n)*8(%rsi); \
        _ASM_EXTABLE(0b, domain_crash_page_fault_ ## n ## x8)

        subq  $7*8,%rsi
        movq  UREGS_ss+8(%rsp),%rax
        ALTERNATIVE "", stac, X86_FEATURE_XEN_SMAP
        movq  VCPU_domain(%rbx),%rdi
        STORE_GUEST_STACK(rax,6)        # SS
        movq  UREGS_rsp+8(%rsp),%rax
        STORE_GUEST_STACK(rax,5)        # RSP
        movq  VCPU_vcpu_info(%rbx),%rax
        pushq VCPUINFO_upcall_mask(%rax)
        testb $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        setnz %ch                       # TBF_INTERRUPT -> set upcall mask
        orb   %ch,VCPUINFO_upcall_mask(%rax)
        popq  %rax
        shlq  $32,%rax                  # Bits 32-39: saved_upcall_mask
        movw  UREGS_cs+8(%rsp),%ax      # Bits  0-15: CS
        STORE_GUEST_STACK(rax,3)        # CS / saved_upcall_mask
        shrq  $32,%rax
        testb $0xFF,%al                 # Bits 0-7: saved_upcall_mask
        setz  %ch                       # %ch == !saved_upcall_mask
        movl  UREGS_eflags+8(%rsp),%eax
        andl  $~(X86_EFLAGS_IF|X86_EFLAGS_IOPL),%eax
        addb  %ch,%ch                   # Bit 9 (EFLAGS.IF)
        orb   %ch,%ah                   # Fold EFLAGS.IF into %eax
        xorl  %ecx,%ecx                 # if ( VM_ASSIST(v->domain, architectural_iopl) )
        testb $1 << VMASST_TYPE_architectural_iopl,DOMAIN_vm_assist(%rdi)
        cmovnzl VCPU_iopl(%rbx),%ecx    # Bits 13:12 (EFLAGS.IOPL)
        orl   %ecx,%eax                 # Fold EFLAGS.IOPL into %eax
        STORE_GUEST_STACK(rax,4)        # RFLAGS
        movq  UREGS_rip+8(%rsp),%rax
        STORE_GUEST_STACK(rax,2)        # RIP
        testb $TBF_EXCEPTION_ERRCODE,TRAPBOUNCE_flags(%rdx)
        jz    1f
        subq  $8,%rsi
        movl  TRAPBOUNCE_error_code(%rdx),%eax
        STORE_GUEST_STACK(rax,2)        # ERROR CODE
1:
        movq  UREGS_r11+8(%rsp),%rax
        STORE_GUEST_STACK(rax,1)        # R11
        movq  UREGS_rcx+8(%rsp),%rax
        STORE_GUEST_STACK(rax,0)        # RCX
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP

#undef STORE_GUEST_STACK

        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        /* Also clear AC: alignment checks shouldn't trigger in kernel mode. */
        BUILD_BUG_ON(TRAP_syscall & 0xff)
        orb   $TRAP_syscall >> 8, UREGS_entry_vector+8+1(%rsp)
        andl  $~(X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|\
                 X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+8(%rsp)
        movq  $FLAT_KERNEL_SS,UREGS_ss+8(%rsp)
        movq  %rsi,UREGS_rsp+8(%rsp)
        movq  $FLAT_KERNEL_CS,UREGS_cs+8(%rsp)
        movq  TRAPBOUNCE_eip(%rdx),%rax
        testq %rax,%rax
UNLIKELY_START(z, create_bounce_frame_bad_bounce_ip)
        lea   UNLIKELY_DISPATCH_LABEL(create_bounce_frame_bad_bounce_ip)(%rip), %rdi
        jmp   asm_domain_crash_synchronous  /* Does not return */
__UNLIKELY_END(create_bounce_frame_bad_bounce_ip)
        movq  %rax,UREGS_rip+8(%rsp)

        /* Trapbounce complete.  Clobber state to avoid an erroneous second injection. */
        xor   %eax, %eax
        mov   %rax, TRAPBOUNCE_eip(%rdx)
        mov   %al,  TRAPBOUNCE_flags(%rdx)
        ret

        .pushsection .fixup, "ax", @progbits
        # Numeric tags below represent the intended overall %rsi adjustment.
domain_crash_page_fault_6x8:
        addq  $8,%rsi
domain_crash_page_fault_5x8:
        addq  $8,%rsi
domain_crash_page_fault_4x8:
        addq  $8,%rsi
domain_crash_page_fault_3x8:
        addq  $8,%rsi
domain_crash_page_fault_2x8:
        addq  $8,%rsi
domain_crash_page_fault_1x8:
        addq  $8,%rsi
domain_crash_page_fault_0x8:
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        movq  %rsi,%rdi
        call  show_page_walk
LABEL(dom_crash_sync_extable, 0)
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        # Get out of the guest-save area of the stack.
        GET_STACK_END(ax)
        leaq  STACK_CPUINFO_FIELD(guest_cpu_user_regs)(%rax),%rsp
        # create_bounce_frame() temporarily clobbers CS.RPL. Fix up.
#ifdef CONFIG_PV32
        movq  STACK_CPUINFO_FIELD(current_vcpu)(%rax), %rax
        movq  VCPU_domain(%rax),%rax
        cmpb  $0, DOMAIN_is_32bit_pv(%rax)
        sete  %al
        leal  (%rax,%rax,2),%eax
        orb   %al,UREGS_cs(%rsp)
#else
        orb   $3, UREGS_cs(%rsp)
#endif
        xorl  %edi,%edi
        jmp   asm_domain_crash_synchronous /* Does not return */
        .popsection
END(create_bounce_frame)
#endif /* CONFIG_PV */

/* --- CODE BELOW THIS LINE (MOSTLY) NOT GUEST RELATED --- */

        .text

/* No special register assumptions. */
#ifdef CONFIG_PV
FUNC(continue_pv_domain)
        ENDBR64

        /*
         * For speculative type confusion reasons, we're CALLed rather than
         * JMPed to.  Drop the return address.
         */
        add   $8, %rsp
#ifdef CONFIG_XEN_SHSTK
        ALTERNATIVE "", "mov $2, %eax; incsspd %eax", X86_FEATURE_XEN_SHSTK
#endif

        call  check_wakeup_from_wait
ret_from_intr:
        GET_CURRENT(bx)
        testb $3, UREGS_cs(%rsp)
        jz    restore_all_xen
#ifdef CONFIG_PV32
        movq  VCPU_domain(%rbx), %rax
        cmpb  $0, DOMAIN_is_32bit_pv(%rax)
        je    test_all_events
        jmp   compat_test_all_events
#else
        jmp   test_all_events
#endif
END(continue_pv_domain)
#else
FUNC_LOCAL(ret_from_intr, 0)
        ASSERT_CONTEXT_IS_XEN
        jmp   restore_all_xen
END(ret_from_intr)
#endif

        .section .init.text, "ax", @progbits
FUNC(early_page_fault)
        ENDBR64
        movb  $X86_EXC_PF, EFRAME_entry_vector(%rsp)
        SAVE_ALL
        movq  %rsp, %rdi
        call  do_early_page_fault
        jmp   restore_all_xen
END(early_page_fault)

        .section .text.entry, "ax", @progbits

/* %r12=ist_exit */
FUNC_LOCAL(restore_all_xen)

#ifdef CONFIG_DEBUG
        mov   %rsp, %rdi
        mov   %r12, %rsi
        call  check_ist_exit
#endif

        /*
         * Check whether we need to switch to the per-CPU page tables, in
         * case we return to late PV exit code (from an NMI or #MC).
         */
        GET_STACK_END(14)
        cmpb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
UNLIKELY_START(ne, exit_cr3)
        mov   STACK_CPUINFO_FIELD(pv_cr3)(%r14), %rax
        mov   %rax, %cr3
UNLIKELY_END(exit_cr3)

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        SPEC_CTRL_EXIT_TO_XEN /* Req: %r12=ist_exit %r14=end %rsp=regs, Clob: abcd */

        RESTORE_ALL adj=8

        /*
         * When the CPU pushed this exception frame, it zero-extended eflags.
         * For an IST exit, SPEC_CTRL_EXIT_TO_XEN stashed shadow copies of
         * scf and ver_sel above eflags, as we can't use any GPRs,
         * and we're at a random place on the stack, not in a CPUFINFO block.
         *
         * Account for ev/ec having already been popped off the stack.
         */
        SPEC_CTRL_COND_VERW \
            scf=STK_REL(EFRAME_shadow_scf, EFRAME_rip), \
            sel=STK_REL(EFRAME_shadow_sel, EFRAME_rip)

        iretq
END(restore_all_xen)

FUNC(common_interrupt)
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_INTR /* Req: %rsp=regs, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        mov   STACK_CPUINFO_FIELD(use_pv_cr3)(%r14), %bl
        mov   %rcx, %r15
        test  %rcx, %rcx
        jz    .Lintr_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        testb $3, UREGS_cs(%rsp)
        cmovnz %r12, %r15
        cmovnz %r12d, %ebx
.Lintr_cr3_okay:

        CR4_PV32_RESTORE /* Clob: ac */
        movq %rsp,%rdi
        callq do_IRQ
        mov   %r15, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        mov   %bl, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        jmp ret_from_intr
END(common_interrupt)

FUNC(entry_PF)
        ENDBR64
        movb  $X86_EXC_PF, EFRAME_entry_vector(%rsp)
END(entry_PF)
/* No special register assumptions. */
FUNC(handle_exception, 0)
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_INTR /* Req: %rsp=regs, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        mov   STACK_CPUINFO_FIELD(use_pv_cr3)(%r14), %r13b
        mov   %rcx, %r15
        test  %rcx, %rcx
        jz    .Lxcpt_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        testb $3, UREGS_cs(%rsp)
        cmovnz %r12, %r15
        cmovnz %r12d, %r13d
.Lxcpt_cr3_okay:

handle_exception_saved:
        mov   STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%rsp)
        jz    exception_with_ints_disabled

#if defined(CONFIG_PV32)
        ALTERNATIVE_2 "jmp .Lcr4_pv32_done", \
            __stringify(mov VCPU_domain(%rbx), %rax), X86_FEATURE_XEN_SMEP, \
            __stringify(mov VCPU_domain(%rbx), %rax), X86_FEATURE_XEN_SMAP

        testb $3,UREGS_cs(%rsp)
        jz    .Lcr4_pv32_done
        cmpb  $0,DOMAIN_is_32bit_pv(%rax)
        je    .Lcr4_pv32_done
        call  cr4_pv32_restore /* Clob: ac */
        /*
         * An NMI or #MC may occur between clearing CR4.SMEP / CR4.SMAP in
         * compat_restore_all_guest and it actually returning to guest
         * context, in which case the guest would run with the two features
         * enabled. The only bad that can happen from this is a kernel mode
         * #PF which the guest doesn't expect. Rather than trying to make the
         * NMI/#MC exit path honor the intended CR4 setting, simply check
         * whether the wrong CR4 was in use when the #PF occurred, and exit
         * back to the guest (which will in turn clear the two CR4 bits) to
         * re-execute the instruction. If we get back here, the CR4 bits
         * should then be found clear (unless another NMI/#MC occurred at
         * exactly the right time), and we'll continue processing the
         * exception as normal.
         */
        test  %rax,%rax
        jnz   .Lcr4_pv32_done
        /*
         * The below effectively is
         * if ( regs->entry_vector == X86_EXC_PF &&
         *      (regs->error_code & PFEC_page_present) &&
         *      !(regs->error_code & ~(PFEC_write_access|PFEC_insn_fetch)) )
         *     goto compat_test_all_events;
         */
        mov   $PFEC_page_present,%al
        cmpb  $X86_EXC_PF, UREGS_entry_vector(%rsp)
        jne   .Lcr4_pv32_done
        xor   UREGS_error_code(%rsp),%eax
        test  $~(PFEC_write_access|PFEC_insn_fetch),%eax
        jz    compat_test_all_events
.Lcr4_pv32_done:
#elif !defined(CONFIG_PV)
        ASSERT_CONTEXT_IS_XEN
#endif /* CONFIG_PV */
.Ldispatch_exceptions:
        mov   %rsp, %rdi
        movzbl UREGS_entry_vector(%rsp), %eax
#ifdef CONFIG_PERF_COUNTERS
        lea   per_cpu__perfcounters(%rip), %rcx
        add   STACK_CPUINFO_FIELD(per_cpu_offset)(%r14), %rcx
        incl  ASM_PERFC_exceptions * 4(%rcx, %rax, 4)
#endif

        /*
         * Dispatch to appropriate C handlers.
         *
         * The logic is implemented as an if/else chain.  DISPATCH() calls
         * need be in frequency order for best performance.
         */
#define DISPATCH(vec, handler)         \
        cmp   $vec, %al;               \
        jne   .L_ ## vec ## _done;     \
        call  handler;                 \
        jmp   .L_exn_dispatch_done;    \
.L_ ## vec ## _done:

        /*
         * IRQs kept off to derisk being hit by a nested interrupt before
         * reading %cr2. Otherwise a page fault in the nested interrupt handler
         * would corrupt %cr2.
         */
        DISPATCH(X86_EXC_PF, do_page_fault)

        /* Only re-enable IRQs if they were active before taking the fault */
        testb $X86_EFLAGS_IF >> 8, UREGS_eflags + 1(%rsp)
        jz    1f
        sti
1:

        DISPATCH(X86_EXC_GP, do_general_protection)
        DISPATCH(X86_EXC_UD, do_invalid_op)
        DISPATCH(X86_EXC_NM, do_device_not_available)
        DISPATCH(X86_EXC_BP, do_int3)

        /* Logically "if ( (1 << vec) & MASK ) { do_trap(); }" */
        mov   $(1 << X86_EXC_DE) | (1 << X86_EXC_OF) | (1 << X86_EXC_BR) |\
               (1 << X86_EXC_NP) | (1 << X86_EXC_SS) | (1 << X86_EXC_MF) |\
               (1 << X86_EXC_AC) | (1 << X86_EXC_XM), %edx
        bt    %eax, %edx
        jnc   .L_do_trap_done
        call  do_trap
        jmp   .L_exn_dispatch_done
.L_do_trap_done:

        DISPATCH(X86_EXC_CP, do_entry_CP)
#undef DISPATCH

        tailcall do_unhandled_trap

.L_exn_dispatch_done:
        mov   %r15, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        mov   %r13b, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
#ifdef CONFIG_PV
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
#ifdef CONFIG_PV32
        movq  VCPU_domain(%rbx),%rax
        cmpb  $0, DOMAIN_is_32bit_pv(%rax)
        jne   compat_test_all_events
#endif
        jmp   test_all_events
#else
        ASSERT_CONTEXT_IS_XEN
        jmp   restore_all_xen
#endif

/* No special register assumptions. */
exception_with_ints_disabled:
        testb $3,UREGS_cs(%rsp)         # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        movq  %rsp,%rdi
        call  search_pre_exception_table
        testq %rax,%rax                 # no fixup code for faulting EIP?
        jz    .Ldispatch_exceptions
        movq  %rax,UREGS_rip(%rsp)      # fixup regular stack

#ifdef CONFIG_XEN_SHSTK
        mov    $1, %edi
        rdsspq %rdi
        cmp    $1, %edi
        je     .L_exn_shstk_done
        wrssq  %rax, 1*8(%rdi)          # fixup shadow stack
.L_exn_shstk_done:
#endif
        subq  $8,UREGS_rsp(%rsp)        # add ec/ev to previous stack frame
        testb $15,UREGS_rsp(%rsp)       # return %rsp is now aligned?
        jz    1f                        # then there is a pad quadword already
        movq  %rsp,%rsi
        subq  $8,%rsp
        movq  %rsp,%rdi
        movq  $UREGS_kernel_sizeof/8,%rcx
        rep;  movsq                     # make room for ec/ev
1:      movq  UREGS_error_code(%rsp),%rax # ec/ev
        movq  %rax,UREGS_kernel_sizeof(%rsp)
        mov   %r15, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        mov   %r13b, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        jmp   restore_all_xen           # return to fixup code

/* No special register assumptions. */
FATAL_exception_with_ints_disabled:
        xorl  %esi,%esi
        movq  %rsp,%rdi
        tailcall fatal_trap
END(handle_exception)

FUNC(entry_DE)
        ENDBR64
        pushq $0
        /* no need to update exception type, already 0 */
        BUILD_BUG_ON(X86_EXC_DE)
        jmp   handle_exception
END(entry_DE)

FUNC(entry_MF)
        ENDBR64
        pushq $0
        movb  $X86_EXC_MF, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_MF)

FUNC(entry_XM)
        ENDBR64
        pushq $0
        movb  $X86_EXC_XM, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_XM)

FUNC(entry_NM)
        ENDBR64
        pushq $0
        movb  $X86_EXC_NM, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_NM)

FUNC(entry_DB)
        ENDBR64
        pushq $0
        movb  $X86_EXC_DB, EFRAME_entry_vector(%rsp)
        jmp   handle_ist_exception
END(entry_DB)

FUNC(entry_BP)
        ENDBR64
        pushq $0
        movb  $X86_EXC_BP, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_BP)

FUNC(entry_OF)
        ENDBR64
        pushq $0
        movb  $X86_EXC_OF, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_OF)

FUNC(entry_BR)
        ENDBR64
        pushq $0
        movb  $X86_EXC_BR, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_BR)

FUNC(entry_UD)
        ENDBR64
        pushq $0
        movb  $X86_EXC_UD, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_UD)

FUNC(entry_TS)
        ENDBR64
        movb  $X86_EXC_TS, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_TS)

FUNC(entry_NP)
        ENDBR64
        movb  $X86_EXC_NP, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_NP)

FUNC(entry_SS)
        ENDBR64
        movb  $X86_EXC_SS, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_SS)

FUNC(entry_GP)
        ENDBR64
        movb  $X86_EXC_GP, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_GP)

FUNC(entry_AC)
        ENDBR64
        movb  $X86_EXC_AC, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_AC)

FUNC(entry_CP)
        ENDBR64
        movb  $X86_EXC_CP, EFRAME_entry_vector(%rsp)
        jmp   handle_exception
END(entry_CP)

FUNC(entry_DF)
        ENDBR64
        movb  $X86_EXC_DF, EFRAME_entry_vector(%rsp)
        /* Set AC to reduce chance of further SMAP faults */
        ALTERNATIVE "", stac, X86_FEATURE_XEN_SMAP
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_INTR_IST /* Req: %rsp=regs, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rbx
        test  %rbx, %rbx
        jz    .Ldblf_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rbx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.Ldblf_cr3_okay:

        movq  %rsp,%rdi
        tailcall do_double_fault
END(entry_DF)

FUNC(entry_NMI)
        ENDBR64
        pushq $0
        movb  $X86_EXC_NMI, EFRAME_entry_vector(%rsp)
END(entry_NMI)

FUNC(handle_ist_exception)
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        SAVE_ALL

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_INTR_IST /* Req: %rsp=regs, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        mov   STACK_CPUINFO_FIELD(xen_cr3)(%r14), %rcx
        mov   STACK_CPUINFO_FIELD(use_pv_cr3)(%r14), %bl
        mov   %rcx, %r15
        test  %rcx, %rcx
        jz    .List_cr3_okay
        movb  $0, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)
        mov   %rcx, %cr3
        /* %r12 is still zero at this point. */
        mov   %r12, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
.List_cr3_okay:

#ifdef CONFIG_PV
        CR4_PV32_RESTORE /* Clob: ac */
        testb $3,UREGS_cs(%rsp)
        jz    1f
        /*
         * Interrupted guest context. Clear the restore value for xen_cr3
         * and copy the context to stack bottom.
         */
        xor   %r15d, %r15d
        xor   %ebx, %ebx
        GET_CPUINFO_FIELD(guest_cpu_user_regs,di)
        movq  %rsp,%rsi
        movl  $UREGS_kernel_sizeof/8,%ecx
        movq  %rdi,%rsp
        rep   movsq

#ifdef CONFIG_XEN_SHSTK
        /* Switch Shadow Stacks */
.macro ist_switch_shstk
        rdsspq %rdi
        clrssbsy (%rdi)
        /*
         * Switching supervisor shadow stacks is specially hard, as supervisor
         * and restore tokens are incompatible.
         *
         * For now, we only need to switch on to an unused primary shadow
         * stack, so use SETSSBSY for the purpose, exactly like the
         * SYSCALL/SYSENTER entry.
         *
         * Ideally, we'd want to CLRSSBSY after switching stacks, but that
         * will leave SSP zeroed so it not an option.  Instead, we transiently
         * have a zero SSP on this instruction boundary, and depend on IST for
         * NMI/#MC protection.
         */
        setssbsy
.endm
        ALTERNATIVE "", ist_switch_shstk, X86_FEATURE_XEN_SHSTK
#endif
1:
#else
        ASSERT_CONTEXT_IS_XEN
#endif
        movq  %rsp,%rdi
        movzbl UREGS_entry_vector(%rsp),%eax

#ifdef CONFIG_PERF_COUNTERS
        lea   per_cpu__perfcounters(%rip), %rcx
        add   STACK_CPUINFO_FIELD(per_cpu_offset)(%r14), %rcx
        incl  ASM_PERFC_exceptions * 4(%rcx, %rax, 4)
#endif

        /*
         * Dispatch to appropriate C handlers.
         *
         * The logic is implemented as an if/else chain.  DISPATCH() calls
         * need be in frequency order for best performance.
         */
#define DISPATCH(vec, handler)         \
        cmp   $vec, %al;               \
        jne   .L_ ## vec ## _done;     \
        call  handler;                 \
        jmp   .L_ist_dispatch_done;    \
.L_ ## vec ## _done:

        DISPATCH(X86_EXC_NMI, do_nmi)
        DISPATCH(X86_EXC_DB,  do_debug)
        DISPATCH(X86_EXC_MC,  do_machine_check)
#undef DISPATCH

        tailcall do_unhandled_trap

.L_ist_dispatch_done:
        mov   %r15, STACK_CPUINFO_FIELD(xen_cr3)(%r14)
        mov   %bl, STACK_CPUINFO_FIELD(use_pv_cr3)(%r14)

        /* This is an IST exit */
        mov   $1, %r12d

        cmpb  $X86_EXC_NMI, UREGS_entry_vector(%rsp)
        jne   ret_from_intr

        /* We want to get straight to the IRET on the NMI exit path. */
#ifdef CONFIG_PV
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        /* Send an IPI to ourselves to cover for the lack of event checking. */
        mov   STACK_CPUINFO_FIELD(processor_id)(%r14), %eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        je    1f
        movl  $EVENT_CHECK_VECTOR,%edi
        call  send_IPI_self
1:
        /* For restore_all_guest. */
        mov   STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx
#ifdef CONFIG_PV32
        movq  VCPU_domain(%rbx),%rax
        cmpb  $0,DOMAIN_is_32bit_pv(%rax)
        je    restore_all_guest
        jmp   compat_restore_all_guest
#else
        jmp   restore_all_guest
#endif
#else
        ASSERT_CONTEXT_IS_XEN
        jmp   restore_all_xen
#endif
END(handle_ist_exception)

FUNC(entry_MC)
        ENDBR64
        pushq $0
        movb  $X86_EXC_MC, EFRAME_entry_vector(%rsp)
        jmp   handle_ist_exception
END(entry_MC)

/* No op trap handler.  Required for kexec crash path. */
FUNC(trap_nop, 0)
        ENDBR64
        iretq
END(trap_nop)

/* Table of automatically generated entry points.  One per vector. */
        .pushsection .init.rodata, "a", @progbits
DATA(autogen_entrypoints, 8)
        /* pop into the .init.rodata section and record an entry point. */
        .macro entrypoint ent
        .pushsection .init.rodata, "a", @progbits
        .quad \ent
        .popsection
        .endm

        .popsection
FUNC_LOCAL(autogen_stubs, 0) /* Automatically generated stubs. */

        vec = 0
        .rept X86_NR_VECTORS

        /* Common interrupts, heading towards do_IRQ(). */
#if defined(CONFIG_PV32)
        .if vec >= FIRST_IRQ_VECTOR && vec != HYPERCALL_VECTOR && vec != LEGACY_SYSCALL_VECTOR
#elif defined(CONFIG_PV)
        .if vec >= FIRST_IRQ_VECTOR && vec != LEGACY_SYSCALL_VECTOR
#else
        .if vec >= FIRST_IRQ_VECTOR
#endif

        .align CONFIG_FUNCTION_ALIGNMENT, CODE_FILL
1:
        ENDBR64
        pushq $0
        movb  $vec, EFRAME_entry_vector(%rsp)
        jmp   common_interrupt

        entrypoint 1b

        /* Reserved exceptions, heading towards do_unhandled_trap(). */
        .elseif vec == X86_EXC_CSO || vec == X86_EXC_SPV || \
                vec == X86_EXC_VE  || (vec > X86_EXC_CP && vec < X86_EXC_NUM)

1:
        ENDBR64
        test  $8,%spl        /* 64bit exception frames are 16 byte aligned, but the word */
        jz    2f             /* size is 8 bytes.  Check whether the processor gave us an */
        pushq $0             /* error code, and insert an empty one if not.              */
2:      movb  $vec, EFRAME_entry_vector(%rsp)
        jmp   handle_exception

        entrypoint 1b

        /* Hand crafted entry points above. */
        .else
        entrypoint 0
        .endif

        vec = vec + 1
        .endr
END(autogen_stubs)

        .section .init.rodata, "a", @progbits
END(autogen_entrypoints)
