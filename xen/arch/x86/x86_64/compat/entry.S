/*
 * Compatibility hypercall routines.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <asm/desc.h>
#include <public/xen.h>
#include <irq_vectors.h>

ENTRY(compat_hypercall)
        ASM_CLAC
        pushq $0
        SAVE_VOLATILE type=TRAP_syscall compat=1

        cmpb  $0,untrusted_msi(%rip)
UNLIKELY_START(ne, msi_check)
        movl  $HYPERCALL_VECTOR,%edi
        call  check_for_unexpected_msi
        LOAD_C_CLOBBERED
UNLIKELY_END(msi_check)

        GET_CURRENT(%rbx)

        cmpl  $NR_hypercalls,%eax
        jae   compat_bad_hypercall
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        pushq UREGS_rbx(%rsp); pushq %rcx; pushq %rdx; pushq %rsi; pushq %rdi
        pushq UREGS_rbp+5*8(%rsp)
        leaq  compat_hypercall_args_table(%rip),%r10
        movl  %eax,%eax
        movl  $6,%ecx
        subb  (%r10,%rax,1),%cl
        movq  %rsp,%rdi
        movl  $0xDEADBEEF,%eax
        rep   stosq
        popq  %r8 ; popq  %r9 ; xchgl %r8d,%r9d /* Args 5&6: zero extend */
        popq  %rdx; popq  %rcx; xchgl %edx,%ecx /* Args 3&4: zero extend */
        popq  %rdi; popq  %rsi; xchgl %edi,%esi /* Args 1&2: zero extend */
        movl  UREGS_rax(%rsp),%eax
        pushq %rax
        pushq UREGS_rip+8(%rsp)
#define SHADOW_BYTES 16 /* Shadow EIP + shadow hypercall # */
#else
        /* Relocate argument registers and zero-extend to 64 bits. */
        movl  %eax,%eax              /* Hypercall #  */
        xchgl %ecx,%esi              /* Arg 2, Arg 4 */
        movl  %edx,%edx              /* Arg 3        */
        movl  %edi,%r8d              /* Arg 5        */
        movl  %ebp,%r9d              /* Arg 6        */
        movl  UREGS_rbx(%rsp),%edi   /* Arg 1        */
#define SHADOW_BYTES 0  /* No on-stack shadow state */
#endif
        cmpb  $0,tb_init_done(%rip)
UNLIKELY_START(ne, compat_trace)
        call  __trace_hypercall_entry
        /* Restore the registers that __trace_hypercall_entry clobbered. */
        movl  UREGS_rax+SHADOW_BYTES(%rsp),%eax   /* Hypercall #  */
        movl  UREGS_rbx+SHADOW_BYTES(%rsp),%edi   /* Arg 1        */
        movl  UREGS_rcx+SHADOW_BYTES(%rsp),%esi   /* Arg 2        */
        movl  UREGS_rdx+SHADOW_BYTES(%rsp),%edx   /* Arg 3        */
        movl  UREGS_rsi+SHADOW_BYTES(%rsp),%ecx   /* Arg 4        */
        movl  UREGS_rdi+SHADOW_BYTES(%rsp),%r8d   /* Arg 5        */
        movl  UREGS_rbp+SHADOW_BYTES(%rsp),%r9d   /* Arg 6        */
#undef SHADOW_BYTES
UNLIKELY_END(compat_trace)
        leaq  compat_hypercall_table(%rip),%r10
        PERFC_INCR(hypercalls, %rax, %rbx)
        callq *(%r10,%rax,8)
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs used by this hypercall. */
        popq  %r10         # Shadow RIP
        cmpq  %r10,UREGS_rip+8(%rsp)
        popq  %rcx         # Shadow hypercall index
        jne   compat_skip_clobber /* If RIP has changed then don't clobber. */
        leaq  compat_hypercall_args_table(%rip),%r10
        movb  (%r10,%rcx,1),%cl
        movl  $0xDEADBEEF,%r10d
        testb %cl,%cl; jz compat_skip_clobber; movl %r10d,UREGS_rbx(%rsp)
        cmpb  $2, %cl; jb compat_skip_clobber; movl %r10d,UREGS_rcx(%rsp)
        cmpb  $3, %cl; jb compat_skip_clobber; movl %r10d,UREGS_rdx(%rsp)
        cmpb  $4, %cl; jb compat_skip_clobber; movl %r10d,UREGS_rsi(%rsp)
        cmpb  $5, %cl; jb compat_skip_clobber; movl %r10d,UREGS_rdi(%rsp)
        cmpb  $6, %cl; jb compat_skip_clobber; movl %r10d,UREGS_rbp(%rsp)
compat_skip_clobber:
#endif
        movl  %eax,UREGS_rax(%rsp)       # save the return value

/* %rbx: struct vcpu */
ENTRY(compat_test_all_events)
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*compat_test_softirqs:*/
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        jne   compat_process_softirqs
        testb $1,VCPU_mce_pending(%rbx)
        jnz   compat_process_mce
.Lcompat_test_guest_nmi:
        testb $1,VCPU_nmi_pending(%rbx)
        jnz   compat_process_nmi
compat_test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        movzwl COMPAT_VCPUINFO_upcall_pending(%rax),%eax
        decl  %eax
        cmpl  $0xfe,%eax
        ja    compat_restore_all_guest
/*compat_process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  VCPU_event_addr(%rbx),%eax
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  VCPU_event_sel(%rbx),%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        movb  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

        ALIGN
/* %rbx: struct vcpu */
compat_process_softirqs:
        sti
        andl  $~TRAP_regs_partial,UREGS_entry_vector(%rsp)
        call  do_softirq
        jmp   compat_test_all_events

	ALIGN
/* %rbx: struct vcpu */
compat_process_mce:
        testb $1 << VCPU_TRAP_MCE,VCPU_async_exception_mask(%rbx)
        jnz   .Lcompat_test_guest_nmi
        sti
        movb $0,VCPU_mce_pending(%rbx)
        call set_guest_machinecheck_trapbounce
        testl %eax,%eax
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        jmp   compat_process_trap

	ALIGN
/* %rbx: struct vcpu */
compat_process_nmi:
        testb $1 << VCPU_TRAP_NMI,VCPU_async_exception_mask(%rbx)
        jnz  compat_test_guest_events
        sti
        movb  $0,VCPU_nmi_pending(%rbx)
        call  set_guest_nmi_trapbounce
        testl %eax,%eax
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
compat_process_trap:
        leaq  VCPU_trap_bounce(%rbx),%rdx
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

compat_bad_hypercall:
        movl $-ENOSYS,UREGS_rax(%rsp)
        jmp  compat_test_all_events

/* %rbx: struct vcpu, interrupts disabled */
ENTRY(compat_restore_all_guest)
        ASSERT_INTERRUPTS_DISABLED
        RESTORE_ALL adj=8 compat=1
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
        jmp   compat_test_all_events
compat_failsafe_callback:
        GET_CURRENT(%rbx)
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  VCPU_failsafe_addr(%rbx),%eax
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  VCPU_failsafe_sel(%rbx),%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        movb  $TBF_FAILSAFE,TRAPBOUNCE_flags(%rdx)
        btq   $_VGCF_failsafe_disables_events,VCPU_guest_context_flags(%rbx)
        jnc   1f
        orb   $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
1:      call  compat_create_bounce_frame
        jmp   compat_test_all_events
.previous
        _ASM_PRE_EXTABLE(.Lft0, .Lfx0)
        _ASM_EXTABLE(.Ldf0, compat_failsafe_callback)

/* %rdx: trap_bounce, %rbx: struct vcpu */
ENTRY(compat_post_handle_exception)
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    compat_test_all_events
.Lcompat_bounce_exception:
        call  compat_create_bounce_frame
        movb  $0,TRAPBOUNCE_flags(%rdx)
        jmp   compat_test_all_events

ENTRY(compat_syscall)
        cmpb  $0,VCPU_syscall32_disables_events(%rbx)
        movzwl VCPU_syscall32_sel(%rbx),%esi
        movq  VCPU_syscall32_addr(%rbx),%rax
        setne %cl
        leaq  VCPU_trap_bounce(%rbx),%rdx
        testl $~3,%esi
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, compat_syscall_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rdi
        movl  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        subl  $2,UREGS_rip(%rsp)
        movl  $0,TRAPBOUNCE_error_code(%rdx)
        movl  TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_eip(%rdi),%eax
        movzwl TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_cs(%rdi),%esi
        testb $4,TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_flags(%rdi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(compat_syscall_gpf)
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  %si,TRAPBOUNCE_cs(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        jmp   .Lcompat_bounce_exception

ENTRY(compat_sysenter)
        movq  VCPU_trap_ctxt(%rbx),%rcx
        cmpb  $TRAP_gp_fault,UREGS_entry_vector(%rsp)
        movzwl VCPU_sysenter_sel(%rbx),%eax
        movzwl TRAP_gp_fault * TRAPINFO_sizeof + TRAPINFO_cs(%rcx),%ecx
        cmovel %ecx,%eax
        testl $~3,%eax
        movl  $FLAT_COMPAT_USER_SS,UREGS_ss(%rsp)
        cmovzl %ecx,%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

ENTRY(compat_int80_direct_trap)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:            */
/*   {[ERRCODE,] EIP, CS, EFLAGS, [ESP, SS]}                             */
/* %rdx: trap_bounce, %rbx: struct vcpu                                  */
/* On return only %rbx and %rdx are guaranteed non-clobbered.            */
compat_create_bounce_frame:
        ASSERT_INTERRUPTS_ENABLED
        mov   %fs,%edi
        testb $2,UREGS_cs+8(%rsp)
        jz    1f
        /* Push new frame at registered guest-OS stack base. */
        movl  VCPU_kernel_sp(%rbx),%esi
.Lft1:  mov   VCPU_kernel_ss(%rbx),%fs
        subl  $2*4,%esi
        movl  UREGS_rsp+8(%rsp),%eax
.Lft2:  movl  %eax,%fs:(%rsi)
        movl  UREGS_ss+8(%rsp),%eax
.Lft3:  movl  %eax,%fs:4(%rsi)
        jmp   2f
1:      /* In kernel context already: push new frame at existing %rsp. */
        movl  UREGS_rsp+8(%rsp),%esi
.Lft4:  mov   UREGS_ss+8(%rsp),%fs
2:
        movb  TRAPBOUNCE_flags(%rdx),%cl
        subl  $3*4,%esi
        movq  VCPU_vcpu_info(%rbx),%rax
        pushq COMPAT_VCPUINFO_upcall_mask(%rax)
        testb $TBF_INTERRUPT,%cl
        setnz %ch                       # TBF_INTERRUPT -> set upcall mask
        orb   %ch,COMPAT_VCPUINFO_upcall_mask(%rax)
        popq  %rax
        shll  $16,%eax                  # Bits 16-23: saved_upcall_mask
        movw  UREGS_cs+8(%rsp),%ax      # Bits  0-15: CS
.Lft5:  movl  %eax,%fs:4(%rsi)          # CS / saved_upcall_mask
        shrl  $16,%eax
        testb %al,%al                   # Bits 0-7: saved_upcall_mask
        setz  %ch                       # %ch == !saved_upcall_mask
        movl  UREGS_eflags+8(%rsp),%eax
        andl  $~X86_EFLAGS_IF,%eax
        addb  %ch,%ch                   # Bit 9 (EFLAGS.IF)
        orb   %ch,%ah                   # Fold EFLAGS.IF into %eax
.Lft6:  movl  %eax,%fs:2*4(%rsi)        # EFLAGS
        movl  UREGS_rip+8(%rsp),%eax
.Lft7:  movl  %eax,%fs:(%rsi)           # EIP
        testb $TBF_EXCEPTION_ERRCODE,%cl
        jz    1f
        subl  $4,%esi
        movl  TRAPBOUNCE_error_code(%rdx),%eax
.Lft8:  movl  %eax,%fs:(%rsi)           # ERROR CODE
1:
        testb $TBF_FAILSAFE,%cl
UNLIKELY_START(nz, compat_bounce_failsafe)
        subl  $4*4,%esi
        movl  %gs,%eax
.Lft9:  movl  %eax,%fs:3*4(%rsi)        # GS
.Lft10: movl  %edi,%fs:2*4(%rsi)        # FS
        movl  %es,%eax
.Lft11: movl  %eax,%fs:1*4(%rsi)        # ES
        movl  %ds,%eax
.Lft12: movl  %eax,%fs:0*4(%rsi)        # DS
UNLIKELY_END(compat_bounce_failsafe)
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl  $~(X86_EFLAGS_VM|X86_EFLAGS_RF|\
                 X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+8(%rsp)
        mov   %fs,UREGS_ss+8(%rsp)
        movl  %esi,UREGS_rsp+8(%rsp)
.Lft13: mov   %edi,%fs
        movzwl TRAPBOUNCE_cs(%rdx),%eax
        /* Null selectors (0-3) are not allowed. */
        testl $~3,%eax
UNLIKELY_START(z, compat_bounce_null_selector)
        lea   UNLIKELY_DISPATCH_LABEL(compat_bounce_null_selector)(%rip), %rdi
        jmp   asm_domain_crash_synchronous  /* Does not return */
__UNLIKELY_END(compat_bounce_null_selector)
        movl  %eax,UREGS_cs+8(%rsp)
        movl  TRAPBOUNCE_eip(%rdx),%eax
        movl  %eax,UREGS_rip+8(%rsp)
        ret
.section .fixup,"ax"
.Lfx13:
        xorl  %edi,%edi
        jmp   .Lft13
.previous
        _ASM_EXTABLE(.Lft1,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft2,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft3,  compat_crash_page_fault_4)
        _ASM_EXTABLE(.Lft4,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft5,  compat_crash_page_fault_4)
        _ASM_EXTABLE(.Lft6,  compat_crash_page_fault_8)
        _ASM_EXTABLE(.Lft7,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft8,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft9,  compat_crash_page_fault_12)
        _ASM_EXTABLE(.Lft10, compat_crash_page_fault_8)
        _ASM_EXTABLE(.Lft11, compat_crash_page_fault_4)
        _ASM_EXTABLE(.Lft12, compat_crash_page_fault)
        _ASM_EXTABLE(.Lft13, .Lfx13)

compat_crash_page_fault_12:
        addl  $4,%esi
compat_crash_page_fault_8:
        addl  $4,%esi
compat_crash_page_fault_4:
        addl  $4,%esi
compat_crash_page_fault:
.Lft14: mov   %edi,%fs
        movl  %esi,%edi
        call  show_page_walk
        jmp   dom_crash_sync_extable
.section .fixup,"ax"
.Lfx14:
        xorl  %edi,%edi
        jmp   .Lft14
.previous
        _ASM_EXTABLE(.Lft14, .Lfx14)

.section .rodata, "a", @progbits

ENTRY(compat_hypercall_table)
        .quad compat_set_trap_table     /*  0 */
        .quad do_mmu_update
        .quad compat_set_gdt
        .quad do_stack_switch
        .quad compat_set_callbacks
        .quad do_fpu_taskswitch         /*  5 */
        .quad do_sched_op_compat
        .quad compat_platform_op
        .quad do_set_debugreg
        .quad do_get_debugreg
        .quad compat_update_descriptor  /* 10 */
        .quad compat_ni_hypercall
        .quad compat_memory_op
        .quad compat_multicall
        .quad compat_update_va_mapping
        .quad compat_set_timer_op       /* 15 */
        .quad do_event_channel_op_compat
        .quad compat_xen_version
        .quad do_console_io
        .quad compat_physdev_op_compat
        .quad compat_grant_table_op     /* 20 */
        .quad compat_vm_assist
        .quad compat_update_va_mapping_otherdomain
        .quad compat_iret
        .quad compat_vcpu_op
        .quad compat_ni_hypercall       /* 25 */
        .quad compat_mmuext_op
        .quad compat_xsm_op
        .quad compat_nmi_op
        .quad compat_sched_op
        .quad compat_callback_op        /* 30 */
        .quad compat_xenoprof_op
        .quad do_event_channel_op
        .quad compat_physdev_op
        .quad do_hvm_op
        .quad do_sysctl                 /* 35 */
        .quad do_domctl
        .quad compat_kexec_op
        .quad do_tmem_op
        .rept __HYPERVISOR_arch_0-((.-compat_hypercall_table)/8)
        .quad compat_ni_hypercall
        .endr
        .quad do_mca                    /* 48 */
        .quad paging_domctl_continuation
        .rept NR_hypercalls-((.-compat_hypercall_table)/8)
        .quad compat_ni_hypercall
        .endr

ENTRY(compat_hypercall_args_table)
        .byte 1 /* compat_set_trap_table    */  /*  0 */
        .byte 4 /* compat_mmu_update        */
        .byte 2 /* compat_set_gdt           */
        .byte 2 /* compat_stack_switch      */
        .byte 4 /* compat_set_callbacks     */
        .byte 1 /* compat_fpu_taskswitch    */  /*  5 */
        .byte 2 /* compat_sched_op_compat   */
        .byte 1 /* compat_platform_op       */
        .byte 2 /* compat_set_debugreg      */
        .byte 1 /* compat_get_debugreg      */
        .byte 4 /* compat_update_descriptor */  /* 10 */
        .byte 0 /* compat_ni_hypercall      */
        .byte 2 /* compat_memory_op         */
        .byte 2 /* compat_multicall         */
        .byte 4 /* compat_update_va_mapping */
        .byte 2 /* compat_set_timer_op      */  /* 15 */
        .byte 1 /* compat_event_channel_op_compat */
        .byte 2 /* compat_xen_version       */
        .byte 3 /* compat_console_io        */
        .byte 1 /* compat_physdev_op_compat */
        .byte 3 /* compat_grant_table_op    */  /* 20 */
        .byte 2 /* compat_vm_assist         */
        .byte 5 /* compat_update_va_mapping_otherdomain */
        .byte 0 /* compat_iret              */
        .byte 3 /* compat_vcpu_op           */
        .byte 0 /* compat_ni_hypercall      */  /* 25 */
        .byte 4 /* compat_mmuext_op         */
        .byte 1 /* do_xsm_op                */
        .byte 2 /* compat_nmi_op            */
        .byte 2 /* compat_sched_op          */
        .byte 2 /* compat_callback_op       */  /* 30 */
        .byte 2 /* compat_xenoprof_op       */
        .byte 2 /* compat_event_channel_op  */
        .byte 2 /* compat_physdev_op        */
        .byte 2 /* do_hvm_op                */
        .byte 1 /* do_sysctl                */  /* 35 */
        .byte 1 /* do_domctl                */
        .byte 2 /* compat_kexec_op          */
        .byte 1 /* do_tmem_op               */
        .rept __HYPERVISOR_arch_0-(.-compat_hypercall_args_table)
        .byte 0 /* compat_ni_hypercall      */
        .endr
        .byte 1 /* do_mca                   */
        .byte 1 /* paging_domctl_continuation      */
        .rept NR_hypercalls-(.-compat_hypercall_args_table)
        .byte 0 /* compat_ni_hypercall      */
        .endr
