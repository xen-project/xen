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

#define GET_GUEST_REGS(reg)                     \
        movq $~(STACK_SIZE-1),reg;              \
        andq %rsp,reg;                          \
        orq  $(STACK_SIZE-CPUINFO_sizeof),reg;

#define GET_CURRENT(reg)         \
        movq $STACK_SIZE-8, reg; \
        orq  %rsp, reg;          \
        andq $~7,reg;            \
        movq (reg),reg;

        ALIGN
ENTRY(compat_hypercall)
        pushq $0
        movl  $TRAP_syscall,4(%rsp)
        SAVE_ALL
        GET_CURRENT(%rbx)

        cmpl  $NR_hypercalls,%eax
        jae   compat_bad_hypercall
#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        pushq UREGS_rbx(%rsp); pushq %rcx; pushq %rdx; pushq %rsi; pushq %rdi
        pushq UREGS_rbp+5*8(%rsp)
        leaq  compat_hypercall_args_table(%rip),%r10
        movq  $6,%rcx
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
#else
        /* Relocate argument registers and zero-extend to 64 bits. */
        movl  %eax,%eax              /* Hypercall #  */
        xchgl %ecx,%esi              /* Arg 2, Arg 4 */
        movl  %edx,%edx              /* Arg 3        */
        movl  %edi,%r8d              /* Arg 5        */
        movl  %ebp,%r9d              /* Arg 6        */
        movl  UREGS_rbx(%rsp),%edi   /* Arg 1        */
#endif
        leaq  compat_hypercall_table(%rip),%r10
        PERFC_INCR(PERFC_hypercalls, %rax)
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
        cli                             # tests must not race interrupts
/*compat_test_softirqs:*/
        movl  VCPU_processor(%rbx),%eax
        shlq  $IRQSTAT_shift,%rax
        leaq  irq_stat(%rip),%rcx
        testl $~0,(%rcx,%rax,1)
        jnz   compat_process_softirqs
        btrq  $_VCPUF_nmi_pending,VCPU_flags(%rbx)
        jc    compat_process_nmi
compat_test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        testb $0xFF,COMPAT_VCPUINFO_upcall_mask(%rax)
        jnz   compat_restore_all_guest
        testb $0xFF,COMPAT_VCPUINFO_upcall_pending(%rax)
        jz    compat_restore_all_guest
/*compat_process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  VCPU_event_addr(%rbx),%eax
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  VCPU_event_sel(%rbx),%eax
        movl  %eax,TRAPBOUNCE_cs(%rdx)
        movw  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

        ALIGN
/* %rbx: struct vcpu */
compat_process_softirqs:
        sti
        call  do_softirq
        jmp   compat_test_all_events

	ALIGN
/* %rbx: struct vcpu */
compat_process_nmi:
        movl  VCPU_nmi_addr(%rbx),%eax
        testl %eax,%eax
        jz    compat_test_all_events
        btsq  $_VCPUF_nmi_masked,VCPU_flags(%rbx)
        jc    1f
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  $FLAT_COMPAT_KERNEL_CS,TRAPBOUNCE_cs(%rdx)
        movw  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events
1:
        btsq  $_VCPUF_nmi_pending,VCPU_flags(%rbx)
        jmp   compat_test_guest_events

compat_bad_hypercall:
        movl $-ENOSYS,UREGS_rax(%rsp)
        jmp  compat_test_all_events

/* %rbx: struct vcpu, interrupts disabled */
compat_restore_all_guest:
        RESTORE_ALL
        addq  $8,%rsp
.Lft0:  iretq

.section .fixup,"ax"
.Lfx0:  popq  -15*8-8(%rsp)            # error_code/entry_vector
        SAVE_ALL                       # 15*8 bytes pushed
        movq  -8(%rsp),%rsi            # error_code/entry_vector
        sti                            # after stack abuse (-1024(%rsp))
        pushq $__HYPERVISOR_DS         # SS
        leaq  8(%rsp),%rax
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
        movl  %eax,TRAPBOUNCE_cs(%rdx)
        movw  $TBF_FAILSAFE,TRAPBOUNCE_flags(%rdx)
        btq   $_VGCF_failsafe_disables_events,VCPU_guest_context_flags(%rbx)
        jnc   1f
        orw   $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
1:
        call  compat_create_bounce_frame
        jmp   compat_test_all_events
.previous
.section __pre_ex_table,"a"
	.quad .Lft0,.Lfx0
.previous
.section __ex_table,"a"
        .quad .Ldf0,compat_failsafe_callback
.previous

/* %rdx: trap_bounce, %rbx: struct vcpu */
ENTRY(compat_post_handle_exception)
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    compat_test_all_events
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:            */
/*   {[ERRCODE,] EIP, CS, EFLAGS, [ESP, SS]}                             */
/* %rdx: trap_bounce, %rbx: struct vcpu                                  */
/* On return only %rbx is guaranteed non-clobbered.                      */
compat_create_bounce_frame:
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
        shlb  $1,%ch                    # Bit 9 (EFLAGS.IF)
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
        jz    2f
        subl  $4*4,%esi
        movl  %gs,%eax
.Lft9:  movl  %eax,%fs:3*4(%rsi)        # GS
.Lft10: movl  %edi,%fs:2*4(%rsi)        # FS
        movl  %es,%eax
.Lft11: movl  %eax,%fs:1*4(%rsi)        # ES
        movl  %ds,%eax
.Lft12: movl  %eax,%fs:0*4(%rsi)        # DS
2:
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        movl  $TRAP_syscall,UREGS_entry_vector+8(%rsp)
        andl  $~(X86_EFLAGS_VM|X86_EFLAGS_RF|\
                 X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+8(%rsp)
        mov   %fs,UREGS_ss+8(%rsp)
        movl  %esi,UREGS_rsp+8(%rsp)
.Lft13: mov   %edi,%fs
        movzwl TRAPBOUNCE_cs(%rdx),%eax
        /* Null selectors (0-3) are not allowed. */
        testl $~3,%eax
        jz    domain_crash_synchronous
        movl  %eax,UREGS_cs+8(%rsp)
        movl  TRAPBOUNCE_eip(%rdx),%eax
        movl  %eax,UREGS_rip+8(%rsp)
        movb  $0,TRAPBOUNCE_flags(%rdx)
        ret
.section .fixup,"ax"
.Lfx13:
        xorl  %edi,%edi
        jmp   .Lft13
.previous
.section __ex_table,"a"
        .quad  .Lft1,domain_crash_synchronous  ,  .Lft2,compat_crash_page_fault
        .quad  .Lft3,compat_crash_page_fault_4 ,  .Lft4,domain_crash_synchronous
        .quad  .Lft5,compat_crash_page_fault_4 ,  .Lft6,compat_crash_page_fault_8
        .quad  .Lft7,compat_crash_page_fault   ,  .Lft8,compat_crash_page_fault
        .quad  .Lft9,compat_crash_page_fault_12, .Lft10,compat_crash_page_fault_8
        .quad .Lft11,compat_crash_page_fault_4 , .Lft12,compat_crash_page_fault
        .quad .Lft13,.Lfx13
.previous

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
        jmp   domain_crash_synchronous
.section .fixup,"ax"
.Lfx14:
        xorl  %edi,%edi
        jmp   .Lft14
.previous
.section __ex_table,"a"
        .quad .Lft14,.Lfx14
.previous

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
        .quad compat_acm_op
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
        .byte 1 /* compat_acm_op            */
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
        .rept NR_hypercalls-(.-compat_hypercall_args_table)
        .byte 0 /* compat_ni_hypercall      */
        .endr
