/*
 * Hypercall and fault low-level handling routines.
 *
 * Copyright (c) 2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>
#include <irq_vectors.h>

        ALIGN
/* %rbx: struct vcpu */
switch_to_kernel:
        leaq  VCPU_trap_bounce(%rbx),%rdx
        /* TB_eip = (32-bit syscall && syscall32_addr) ?
         *          syscall32_addr : syscall_addr */
        xor   %eax,%eax
        cmpw  $FLAT_USER_CS32,UREGS_cs(%rsp)
        cmoveq VCPU_syscall32_addr(%rbx),%rax
        testq %rax,%rax
        cmovzq VCPU_syscall_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        /* TB_flags = VGCF_syscall_disables_events ? TBF_INTERRUPT : 0 */
        btl   $_VGCF_syscall_disables_events,VCPU_guest_context_flags(%rbx)
        setc  %cl
        leal  (,%rcx,TBF_INTERRUPT),%ecx
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        andl  $~X86_EFLAGS_DF,UREGS_eflags(%rsp)
        jmp   test_all_events

/* %rbx: struct vcpu, interrupts disabled */
restore_all_guest:
        ASSERT_INTERRUPTS_DISABLED
        RESTORE_ALL
        testw $TRAP_syscall,4(%rsp)
        jz    iret_exit_to_guest

        /* Don't use SYSRET path if the return address is not canonical. */
        movq  8(%rsp),%rcx
        sarq  $47,%rcx
        incl  %ecx
        cmpl  $1,%ecx
        ja    .Lforce_iret

        cmpw  $FLAT_USER_CS32,16(%rsp)# CS
        movq  8(%rsp),%rcx            # RIP
        movq  24(%rsp),%r11           # RFLAGS
        movq  32(%rsp),%rsp           # RSP
        je    1f
        sysretq
1:      sysretl

.Lforce_iret:
        /* Mimic SYSRET behavior. */
        movq  8(%rsp),%rcx            # RIP
        movq  24(%rsp),%r11           # RFLAGS
        ALIGN
/* No special register assumptions. */
iret_exit_to_guest:
        addq  $8,%rsp
.Lft0:  iretq

.section .fixup,"ax"
.Lfx0:  sti
        SAVE_ALL
        movq  UREGS_error_code(%rsp),%rsi
        movq  %rsp,%rax
        andq  $~0xf,%rsp
        pushq $__HYPERVISOR_DS         # SS
        pushq %rax                     # RSP
        pushfq                         # RFLAGS
        pushq $__HYPERVISOR_CS         # CS
        leaq  .Ldf0(%rip),%rax
        pushq %rax                     # RIP
        pushq %rsi                     # error_code/entry_vector
        jmp   handle_exception
.Ldf0:  GET_CURRENT(%rbx)
        jmp   test_all_events
failsafe_callback:
        GET_CURRENT(%rbx)
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_failsafe_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  $TBF_FAILSAFE,TRAPBOUNCE_flags(%rdx)
        bt    $_VGCF_failsafe_disables_events,VCPU_guest_context_flags(%rbx)
        jnc   1f
        orb   $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
1:      call  create_bounce_frame
        jmp   test_all_events
.previous
        _ASM_PRE_EXTABLE(.Lft0, .Lfx0)
        _ASM_EXTABLE(.Ldf0, failsafe_callback)

        ALIGN
/* No special register assumptions. */
restore_all_xen:
        RESTORE_ALL adj=8
        iretq

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
 * Initial work is done by per-CPU stack trampolines. At this point %rsp
 * has been initialised to point at the correct Xen stack, and %rsp, %rflags
 * and %cs have been saved. All other registers are still to be saved onto
 * the stack, starting with %rip, and an appropriate %ss must be saved into
 * the space left by the trampoline.
 */
ENTRY(syscall_enter)
        sti
        movl  $FLAT_KERNEL_SS,24(%rsp)
        pushq %rcx
        pushq $0
        movq  24(%rsp),%r11 /* Re-load user RFLAGS into %r11 before saving */
        SAVE_VOLATILE TRAP_syscall
        GET_CURRENT(%rbx)
        movq  VCPU_domain(%rbx),%rcx
        testb $1,DOMAIN_is_32bit_pv(%rcx)
        jnz   compat_syscall
        testb $TF_kernel_mode,VCPU_thread_flags(%rbx)
        jz    switch_to_kernel

/*hypercall:*/
        movq  %r10,%rcx
        cmpq  $NR_hypercalls,%rax
        jae   bad_hypercall
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        pushq %rdi; pushq %rsi; pushq %rdx; pushq %rcx; pushq %r8 ; pushq %r9 
        leaq  hypercall_args_table(%rip),%r10
        movq  $6,%rcx
        sub   (%r10,%rax,1),%cl
        movq  %rsp,%rdi
        movl  $0xDEADBEEF,%eax
        rep   stosq
        popq  %r9 ; popq  %r8 ; popq  %rcx; popq  %rdx; popq  %rsi; popq  %rdi
        movq  UREGS_rax(%rsp),%rax
        pushq %rax
        pushq UREGS_rip+8(%rsp)
#define SHADOW_BYTES 16 /* Shadow EIP + shadow hypercall # */
#else
#define SHADOW_BYTES 0  /* No on-stack shadow state */
#endif
        cmpb  $0,tb_init_done(%rip)
UNLIKELY_START(ne, trace)
        call  __trace_hypercall_entry
        /* Restore the registers that __trace_hypercall_entry clobbered. */
        movq  UREGS_rax+SHADOW_BYTES(%rsp),%rax   /* Hypercall #  */
        movq  UREGS_rdi+SHADOW_BYTES(%rsp),%rdi   /* Arg 1        */
        movq  UREGS_rsi+SHADOW_BYTES(%rsp),%rsi   /* Arg 2        */
        movq  UREGS_rdx+SHADOW_BYTES(%rsp),%rdx   /* Arg 3        */
        movq  UREGS_r10+SHADOW_BYTES(%rsp),%rcx   /* Arg 4        */
        movq  UREGS_r8 +SHADOW_BYTES(%rsp),%r8    /* Arg 5        */
        movq  UREGS_r9 +SHADOW_BYTES(%rsp),%r9    /* Arg 6        */
#undef SHADOW_BYTES
UNLIKELY_END(trace)
        leaq  hypercall_table(%rip),%r10
        PERFC_INCR(hypercalls, %rax, %rbx)
        callq *(%r10,%rax,8)
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs used by this hypercall. */
        popq  %r10         # Shadow RIP
        cmpq  %r10,UREGS_rip+8(%rsp)
        popq  %rcx         # Shadow hypercall index
        jne   skip_clobber /* If RIP has changed then don't clobber. */
        leaq  hypercall_args_table(%rip),%r10
        movb  (%r10,%rcx,1),%cl
        movl  $0xDEADBEEF,%r10d
        cmpb  $1,%cl; jb skip_clobber; movq %r10,UREGS_rdi(%rsp)
        cmpb  $2,%cl; jb skip_clobber; movq %r10,UREGS_rsi(%rsp)
        cmpb  $3,%cl; jb skip_clobber; movq %r10,UREGS_rdx(%rsp)
        cmpb  $4,%cl; jb skip_clobber; movq %r10,UREGS_r10(%rsp)
        cmpb  $5,%cl; jb skip_clobber; movq %r10,UREGS_r8(%rsp)
        cmpb  $6,%cl; jb skip_clobber; movq %r10,UREGS_r9(%rsp)
skip_clobber:
#endif
        movq  %rax,UREGS_rax(%rsp)       # save the return value

/* %rbx: struct vcpu */
test_all_events:
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        jne   process_softirqs
        testb $1,VCPU_mce_pending(%rbx)
        jnz   process_mce
.Ltest_guest_nmi:
        testb $1,VCPU_nmi_pending(%rbx)
        jnz   process_nmi
test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        movzwl VCPUINFO_upcall_pending(%rax),%eax
        decl  %eax
        cmpl  $0xfe,%eax
        ja    restore_all_guest
/*process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_event_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        jmp   test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_softirqs:
        sti       
        SAVE_PRESERVED
        call do_softirq
        jmp  test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_mce:
        testb $1 << VCPU_TRAP_MCE,VCPU_async_exception_mask(%rbx)
        jnz  .Ltest_guest_nmi
        sti
        movb $0,VCPU_mce_pending(%rbx)
        call set_guest_machinecheck_trapbounce
        test %eax,%eax
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        jmp  process_trap

        ALIGN
/* %rbx: struct vcpu */
process_nmi:
        testb $1 << VCPU_TRAP_NMI,VCPU_async_exception_mask(%rbx)
        jnz  test_guest_events
        sti
        movb $0,VCPU_nmi_pending(%rbx)
        call set_guest_nmi_trapbounce
        test %eax,%eax
        jz   test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
process_trap:
        leaq VCPU_trap_bounce(%rbx),%rdx
        call create_bounce_frame
        jmp  test_all_events

bad_hypercall:
        movq $-ENOSYS,UREGS_rax(%rsp)
        jmp  test_all_events

ENTRY(sysenter_entry)
        sti
        pushq $FLAT_USER_SS
        pushq $0
        pushfq
GLOBAL(sysenter_eflags_saved)
        pushq $3 /* ring 3 null cs */
        pushq $0 /* null rip */
        pushq $0
        SAVE_VOLATILE TRAP_syscall
        GET_CURRENT(%rbx)
        cmpb  $0,VCPU_sysenter_disables_events(%rbx)
        movq  VCPU_sysenter_addr(%rbx),%rax
        setne %cl
        testl $X86_EFLAGS_NT,UREGS_eflags(%rsp)
        leaq  VCPU_trap_bounce(%rbx),%rdx
UNLIKELY_START(nz, sysenter_nt_set)
        pushfq
        andl  $~X86_EFLAGS_NT,(%rsp)
        popfq
        xorl  %eax,%eax
UNLIKELY_END(sysenter_nt_set)
        testq %rax,%rax
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, sysenter_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rsi
        SAVE_PRESERVED
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        movl  %eax,TRAPBOUNCE_error_code(%rdx)
        movq  TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_eip(%rsi),%rax
        testb $4,TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_flags(%rsi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(sysenter_gpf)
        movq  VCPU_domain(%rbx),%rdi
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        testb $1,DOMAIN_is_32bit_pv(%rdi)
        jnz   compat_sysenter
        jmp   .Lbounce_exception

ENTRY(int80_direct_trap)
        pushq $0
        SAVE_VOLATILE 0x80

        cmpb  $0,untrusted_msi(%rip)
UNLIKELY_START(ne, msi_check)
        movl  $0x80,%edi
        call  check_for_unexpected_msi
        LOAD_C_CLOBBERED
UNLIKELY_END(msi_check)

        GET_CURRENT(%rbx)

        /* Check that the callback is non-null. */
        leaq  VCPU_int80_bounce(%rbx),%rdx
        cmpb  $0,TRAPBOUNCE_flags(%rdx)
        jz    int80_slow_path

        movq  VCPU_domain(%rbx),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        jnz   compat_int80_direct_trap

        call  create_bounce_frame
        jmp   test_all_events

int80_slow_path:
        /* 
         * Setup entry vector and error code as if this was a GPF caused by an
         * IDT entry with DPL==0.
         */
        movl  $((0x80 << 3) | 0x2),UREGS_error_code(%rsp)
        SAVE_PRESERVED
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        /* A GPF wouldn't have incremented the instruction pointer. */
        subq  $2,UREGS_rip(%rsp)
        jmp   handle_exception_saved

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS STACK:                     */
/*   { RCX, R11, [DS-GS,] [CR2,] [ERRCODE,] RIP, CS, RFLAGS, RSP, SS }   */
/* %rdx: trap_bounce, %rbx: struct vcpu                                  */
/* On return only %rbx and %rdx are guaranteed non-clobbered.            */
create_bounce_frame:
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
        movq  $HYPERVISOR_VIRT_START,%rax
        cmpq  %rax,%rsi
        movq  $HYPERVISOR_VIRT_END+60,%rax
        sbb   %ecx,%ecx                 # In +ve address space? Then okay.
        cmpq  %rax,%rsi
        adc   %ecx,%ecx                 # Above Xen private area? Then okay.
UNLIKELY_START(g, create_bounce_frame_bad_sp)
        lea   UNLIKELY_DISPATCH_LABEL(create_bounce_frame_bad_sp)(%rip), %rdi
        jmp   asm_domain_crash_synchronous  /* Does not return */
__UNLIKELY_END(create_bounce_frame_bad_sp)
        movb  TRAPBOUNCE_flags(%rdx),%cl
        subq  $40,%rsi
        movq  UREGS_ss+8(%rsp),%rax
.Lft2:  movq  %rax,32(%rsi)             # SS
        movq  UREGS_rsp+8(%rsp),%rax
.Lft3:  movq  %rax,24(%rsi)             # RSP
        movq  VCPU_vcpu_info(%rbx),%rax
        pushq VCPUINFO_upcall_mask(%rax)
        testb $TBF_INTERRUPT,%cl
        setnz %ch                       # TBF_INTERRUPT -> set upcall mask
        orb   %ch,VCPUINFO_upcall_mask(%rax)
        popq  %rax
        shlq  $32,%rax                  # Bits 32-39: saved_upcall_mask
        movw  UREGS_cs+8(%rsp),%ax      # Bits  0-15: CS
.Lft4:  movq  %rax,8(%rsi)              # CS / saved_upcall_mask
        shrq  $32,%rax
        testb $0xFF,%al                 # Bits 0-7: saved_upcall_mask
        setz  %ch                       # %ch == !saved_upcall_mask
        movl  UREGS_eflags+8(%rsp),%eax
        andl  $~X86_EFLAGS_IF,%eax
        addb  %ch,%ch                   # Bit 9 (EFLAGS.IF)
        orb   %ch,%ah                   # Fold EFLAGS.IF into %eax
.Lft5:  movq  %rax,16(%rsi)             # RFLAGS
        movq  UREGS_rip+8(%rsp),%rax
.Lft6:  movq  %rax,(%rsi)               # RIP
        testb $TBF_EXCEPTION_ERRCODE,%cl
        jz    1f
        subq  $8,%rsi
        movl  TRAPBOUNCE_error_code(%rdx),%eax
.Lft7:  movq  %rax,(%rsi)               # ERROR CODE
1:      testb $TBF_FAILSAFE,%cl
UNLIKELY_START(nz, bounce_failsafe)
        subq  $32,%rsi
        movl  %gs,%eax
.Lft8:  movq  %rax,24(%rsi)             # GS
        movl  %fs,%eax
.Lft9:  movq  %rax,16(%rsi)             # FS
        movl  %es,%eax
.Lft10: movq  %rax,8(%rsi)              # ES
        movl  %ds,%eax
.Lft11: movq  %rax,(%rsi)               # DS
UNLIKELY_END(bounce_failsafe)
        subq  $16,%rsi
        movq  UREGS_r11+8(%rsp),%rax
.Lft12: movq  %rax,8(%rsi)              # R11
        movq  UREGS_rcx+8(%rsp),%rax
.Lft13: movq  %rax,(%rsi)               # RCX
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        /* Also clear AC: alignment checks shouldn't trigger in kernel mode. */
        orl   $TRAP_syscall,UREGS_entry_vector+8(%rsp)
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
        ret
        _ASM_EXTABLE(.Lft2,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft3,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft4,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft5,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft6,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft7,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft8,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft9,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft10, dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft11, dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft12, dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft13, dom_crash_sync_extable)

ENTRY(dom_crash_sync_extable)
        # Get out of the guest-save area of the stack.
        GET_STACK_BASE(%rax)
        leaq  STACK_CPUINFO_FIELD(guest_cpu_user_regs)(%rax),%rsp
        # create_bounce_frame() temporarily clobbers CS.RPL. Fix up.
        __GET_CURRENT(%rax)
        movq  VCPU_domain(%rax),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        setz  %al
        leal  (%rax,%rax,2),%eax
        orb   %al,UREGS_cs(%rsp)
        xorl  %edi,%edi
        jmp   asm_domain_crash_synchronous /* Does not return */

/* No special register assumptions. */
ENTRY(ret_from_intr)
        GET_CURRENT(%rbx)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        movq  VCPU_domain(%rbx),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        jz    test_all_events
        jmp   compat_test_all_events

ENTRY(page_fault)
        movl  $TRAP_page_fault,4(%rsp)
/* No special register assumptions. */
GLOBAL(handle_exception)
        SAVE_ALL
handle_exception_saved:
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%rsp)
        jz    exception_with_ints_disabled
        sti
1:      movq  %rsp,%rdi
        movzbl UREGS_entry_vector(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        GET_CURRENT(%rbx)
        PERFC_INCR(exceptions, %rax, %rbx)
        callq *(%rdx,%rax,8)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_domain(%rbx),%rax
        testb $1,DOMAIN_is_32bit_pv(%rax)
        jnz   compat_post_handle_exception
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    test_all_events
.Lbounce_exception:
        call  create_bounce_frame
        movb  $0,TRAPBOUNCE_flags(%rdx)
        jmp   test_all_events

/* No special register assumptions. */
exception_with_ints_disabled:
        testb $3,UREGS_cs(%rsp)         # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        movq  %rsp,%rdi
        call  search_pre_exception_table
        testq %rax,%rax                 # no fixup code for faulting EIP?
        jz    1b
        movq  %rax,UREGS_rip(%rsp)
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
        jmp   restore_all_xen           # return to fixup code

/* No special register assumptions. */
FATAL_exception_with_ints_disabled:
        movzbl UREGS_entry_vector(%rsp),%edi
        movq  %rsp,%rsi
        call  fatal_trap
        ud2

ENTRY(divide_error)
        pushq $0
        movl  $TRAP_divide_error,4(%rsp)
        jmp   handle_exception

ENTRY(coprocessor_error)
        pushq $0
        movl  $TRAP_copro_error,4(%rsp)
        jmp   handle_exception

ENTRY(simd_coprocessor_error)
        pushq $0
        movl  $TRAP_simd_error,4(%rsp)
        jmp   handle_exception

ENTRY(device_not_available)
        pushq $0
        movl  $TRAP_no_device,4(%rsp)
        jmp   handle_exception

ENTRY(debug)
        pushq $0
        movl  $TRAP_debug,4(%rsp)
        jmp   handle_exception

ENTRY(int3)
        pushq $0
        movl  $TRAP_int3,4(%rsp)
        jmp   handle_exception

ENTRY(overflow)
        pushq $0
        movl  $TRAP_overflow,4(%rsp)
        jmp   handle_exception

ENTRY(bounds)
        pushq $0
        movl  $TRAP_bounds,4(%rsp)
        jmp   handle_exception

ENTRY(invalid_op)
        pushq $0
        movl  $TRAP_invalid_op,4(%rsp)
        jmp   handle_exception

ENTRY(coprocessor_segment_overrun)
        pushq $0
        movl  $TRAP_copro_seg,4(%rsp)
        jmp   handle_exception

ENTRY(invalid_TSS)
        movl  $TRAP_invalid_tss,4(%rsp)
        jmp   handle_exception

ENTRY(segment_not_present)
        movl  $TRAP_no_segment,4(%rsp)
        jmp   handle_exception

ENTRY(stack_segment)
        movl  $TRAP_stack_error,4(%rsp)
        jmp   handle_exception

ENTRY(general_protection)
        movl  $TRAP_gp_fault,4(%rsp)
        jmp   handle_exception

ENTRY(alignment_check)
        movl  $TRAP_alignment_check,4(%rsp)
        jmp   handle_exception

ENTRY(spurious_interrupt_bug)
        pushq $0
        movl  $TRAP_spurious_int,4(%rsp)
        jmp   handle_exception

ENTRY(double_fault)
        movl  $TRAP_double_fault,4(%rsp)
        SAVE_ALL
        movq  %rsp,%rdi
        call  do_double_fault
        ud2

        .pushsection .init.text, "ax", @progbits
ENTRY(early_page_fault)
        SAVE_ALL
        movq  %rsp,%rdi
        call  do_early_page_fault
        jmp   restore_all_xen
        .popsection

ENTRY(nmi)
        pushq $0
        movl  $TRAP_nmi,4(%rsp)
handle_ist_exception:
        SAVE_ALL
        testb $3,UREGS_cs(%rsp)
        jz    1f
        /* Interrupted guest context. Copy the context to stack bottom. */
        GET_CPUINFO_FIELD(guest_cpu_user_regs,%rdi)
        movq  %rsp,%rsi
        movl  $UREGS_kernel_sizeof/8,%ecx
        movq  %rdi,%rsp
        rep   movsq
1:      movq  %rsp,%rdi
        movzbl UREGS_entry_vector(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        callq *(%rdx,%rax,8)
        cmpb  $TRAP_nmi,UREGS_entry_vector(%rsp)
        jne   ret_from_intr

        /* We want to get straight to the IRET on the NMI exit path. */
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        GET_CURRENT(%rbx)
        /* Send an IPI to ourselves to cover for the lack of event checking. */
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        je    1f
        movl  $EVENT_CHECK_VECTOR,%edi
        call  send_IPI_self
1:      movq  VCPU_domain(%rbx),%rax
        cmpb  $0,DOMAIN_is_32bit_pv(%rax)
        je    restore_all_guest
        jmp   compat_restore_all_guest

ENTRY(nmi_crash)
        pushq $0
        movl $TRAP_nmi,4(%rsp)
        SAVE_ALL
        movq %rsp,%rdi
        callq do_nmi_crash /* Does not return */
        ud2

ENTRY(machine_check)
        pushq $0
        movl  $TRAP_machine_check,4(%rsp)
        jmp   handle_ist_exception

/* Enable NMIs.  No special register assumptions. Only %rax is not preserved. */
ENTRY(enable_nmis)
        movq  %rsp, %rax /* Grab RSP before pushing */

        /* Set up stack frame */
        pushq $0               /* SS */
        pushq %rax             /* RSP */
        pushfq                 /* RFLAGS */
        pushq $__HYPERVISOR_CS /* CS */
        leaq  1f(%rip),%rax
        pushq %rax             /* RIP */

        iretq /* Disable the hardware NMI latch */
1:
        retq

/* No op trap handler.  Required for kexec crash path. */
GLOBAL(trap_nop)
        iretq



.section .rodata, "a", @progbits

ENTRY(exception_table)
        .quad do_divide_error
        .quad do_debug
        .quad do_nmi
        .quad do_int3
        .quad do_overflow
        .quad do_bounds
        .quad do_invalid_op
        .quad do_device_not_available
        .quad 0 # double_fault
        .quad do_coprocessor_segment_overrun
        .quad do_invalid_TSS
        .quad do_segment_not_present
        .quad do_stack_segment
        .quad do_general_protection
        .quad do_page_fault
        .quad do_spurious_interrupt_bug
        .quad do_coprocessor_error
        .quad do_alignment_check
        .quad do_machine_check
        .quad do_simd_coprocessor_error

ENTRY(hypercall_table)
        .quad do_set_trap_table     /*  0 */
        .quad do_mmu_update
        .quad do_set_gdt
        .quad do_stack_switch
        .quad do_set_callbacks
        .quad do_fpu_taskswitch     /*  5 */
        .quad do_sched_op_compat
        .quad do_platform_op
        .quad do_set_debugreg
        .quad do_get_debugreg
        .quad do_update_descriptor  /* 10 */
        .quad do_ni_hypercall
        .quad do_memory_op
        .quad do_multicall
        .quad do_update_va_mapping
        .quad do_set_timer_op       /* 15 */
        .quad do_event_channel_op_compat
        .quad do_xen_version
        .quad do_console_io
        .quad do_physdev_op_compat
        .quad do_grant_table_op     /* 20 */
        .quad do_vm_assist
        .quad do_update_va_mapping_otherdomain
        .quad do_iret
        .quad do_vcpu_op
        .quad do_set_segment_base   /* 25 */
        .quad do_mmuext_op
        .quad do_xsm_op
        .quad do_nmi_op
        .quad do_sched_op
        .quad do_callback_op        /* 30 */
        .quad do_xenoprof_op
        .quad do_event_channel_op
        .quad do_physdev_op
        .quad do_hvm_op
        .quad do_sysctl             /* 35 */
        .quad do_domctl
        .quad do_kexec_op
        .quad do_tmem_op
        .rept __HYPERVISOR_arch_0-((.-hypercall_table)/8)
        .quad do_ni_hypercall
        .endr
        .quad do_mca                /* 48 */
        .quad paging_domctl_continuation
        .rept NR_hypercalls-((.-hypercall_table)/8)
        .quad do_ni_hypercall
        .endr

ENTRY(hypercall_args_table)
        .byte 1 /* do_set_trap_table    */  /*  0 */
        .byte 4 /* do_mmu_update        */
        .byte 2 /* do_set_gdt           */
        .byte 2 /* do_stack_switch      */
        .byte 3 /* do_set_callbacks     */
        .byte 1 /* do_fpu_taskswitch    */  /*  5 */
        .byte 2 /* do_sched_op_compat   */
        .byte 1 /* do_platform_op       */
        .byte 2 /* do_set_debugreg      */
        .byte 1 /* do_get_debugreg      */
        .byte 2 /* do_update_descriptor */  /* 10 */
        .byte 0 /* do_ni_hypercall      */
        .byte 2 /* do_memory_op         */
        .byte 2 /* do_multicall         */
        .byte 3 /* do_update_va_mapping */
        .byte 1 /* do_set_timer_op      */  /* 15 */
        .byte 1 /* do_event_channel_op_compat */
        .byte 2 /* do_xen_version       */
        .byte 3 /* do_console_io        */
        .byte 1 /* do_physdev_op_compat */
        .byte 3 /* do_grant_table_op    */  /* 20 */
        .byte 2 /* do_vm_assist         */
        .byte 4 /* do_update_va_mapping_otherdomain */
        .byte 0 /* do_iret              */
        .byte 3 /* do_vcpu_op           */
        .byte 2 /* do_set_segment_base  */  /* 25 */
        .byte 4 /* do_mmuext_op         */
        .byte 1 /* do_xsm_op            */
        .byte 2 /* do_nmi_op            */
        .byte 2 /* do_sched_op          */
        .byte 2 /* do_callback_op       */  /* 30 */
        .byte 2 /* do_xenoprof_op       */
        .byte 2 /* do_event_channel_op  */
        .byte 2 /* do_physdev_op        */
        .byte 2 /* do_hvm_op            */
        .byte 1 /* do_sysctl            */  /* 35 */
        .byte 1 /* do_domctl            */
        .byte 2 /* do_kexec             */
        .byte 1 /* do_tmem_op           */
        .rept __HYPERVISOR_arch_0-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
        .byte 1 /* do_mca               */  /* 48 */
        .byte 1 /* paging_domctl_continuation */
        .rept NR_hypercalls-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
