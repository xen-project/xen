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
/* %rbx: struct vcpu */
switch_to_kernel:
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_syscall_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $0,TRAPBOUNCE_flags(%rdx)
        bt    $_VGCF_syscall_disables_events,VCPU_guest_context_flags(%rbx)
        jnc   1f
        orw   $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
1:      call  create_bounce_frame
        jmp   test_all_events

/* %rbx: struct vcpu, interrupts disabled */
restore_all_guest:
        RESTORE_ALL
        testw $TRAP_syscall,4(%rsp)
        jz    iret_exit_to_guest

        addq  $8,%rsp
        popq  %rcx                    # RIP
        popq  %r11                    # CS
        cmpw  $FLAT_KERNEL_CS32,%r11
        popq  %r11                    # RFLAGS
        popq  %rsp                    # RSP
        je    1f
        sysretq
1:      sysretl

        ALIGN
/* No special register assumptions. */
iret_exit_to_guest:
        addq  $8,%rsp
.Lft1:  iretq

.section .fixup,"ax"
.Lfx1:  popq  -15*8-8(%rsp)            # error_code/entry_vector
        SAVE_ALL                       # 15*8 bytes pushed
        movq  -8(%rsp),%rsi            # error_code/entry_vector
        sti                            # after stack abuse (-1024(%rsp))
        pushq $__HYPERVISOR_DS         # SS
        leaq  8(%rsp),%rax
        pushq %rax                     # RSP
        pushf                          # RFLAGS
        pushq $__HYPERVISOR_CS         # CS
        leaq  .Ldf1(%rip),%rax
        pushq %rax                     # RIP
        pushq %rsi                     # error_code/entry_vector
        jmp   handle_exception
.Ldf1:  GET_CURRENT(%rbx)
        jmp   test_all_events
failsafe_callback:
        GET_CURRENT(%rbx)
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_failsafe_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $TBF_FAILSAFE,TRAPBOUNCE_flags(%rdx)
        bt    $_VGCF_failsafe_disables_events,VCPU_guest_context_flags(%rbx)
        jnc   1f
        orw   $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
1:      call  create_bounce_frame
        jmp   test_all_events
.previous
.section __pre_ex_table,"a"
        .quad .Lft1,.Lfx1
.previous
.section __ex_table,"a"
        .quad .Ldf1,failsafe_callback
.previous

        ALIGN
/* No special register assumptions. */
restore_all_xen:
        RESTORE_ALL
        addq  $8,%rsp
        iretq

/*
 * When entering SYSCALL from kernel mode:
 *  %rax                            = hypercall vector
 *  %rdi, %rsi, %rdx, %r10, %r8, %9 = hypercall arguments
 *  %r11, %rcx                      = SYSCALL-saved %rflags and %rip
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
        ALIGN
ENTRY(syscall_enter)
        sti
        movl  $FLAT_KERNEL_SS,24(%rsp)
        pushq %rcx
        pushq $0
        movl  $TRAP_syscall,4(%rsp)
        SAVE_ALL
        GET_CURRENT(%rbx)
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
#endif
        leaq  hypercall_table(%rip),%r10
        PERFC_INCR(PERFC_hypercalls, %rax)
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
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl  VCPU_processor(%rbx),%eax
        shl   $IRQSTAT_shift,%rax
        leaq  irq_stat(%rip),%rcx
        testl $~0,(%rcx,%rax,1)
        jnz   process_softirqs
        btr   $_VCPUF_nmi_pending,VCPU_flags(%rbx)
        jc    process_nmi
test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        testb $0xFF,VCPUINFO_upcall_mask(%rax)
        jnz   restore_all_guest
        testb $0xFF,VCPUINFO_upcall_pending(%rax)
        jz    restore_all_guest
/*process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movq  VCPU_event_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        jmp   test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_softirqs:
        sti       
        call do_softirq
        jmp  test_all_events

        ALIGN
/* %rbx: struct vcpu */
process_nmi:
        movq VCPU_nmi_addr(%rbx),%rax
        test %rax,%rax
        jz   test_all_events
        bts  $_VCPUF_nmi_masked,VCPU_flags(%rbx)
        jc   1f
        sti
        leaq VCPU_trap_bounce(%rbx),%rdx
        movq %rax,TRAPBOUNCE_eip(%rdx)
        movw $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call create_bounce_frame
        jmp  test_all_events
1:      bts  $_VCPUF_nmi_pending,VCPU_flags(%rbx)
        jmp  test_guest_events

bad_hypercall:
        movq $-ENOSYS,UREGS_rax(%rsp)
        jmp  test_all_events

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS STACK:                     */
/*   { RCX, R11, [DS-GS,] [CR2,] [ERRCODE,] RIP, CS, RFLAGS, RSP, SS }   */
/* %rdx: trap_bounce, %rbx: struct vcpu                           */
/* On return only %rbx is guaranteed non-clobbered.                      */
create_bounce_frame:
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
        jb    1f                        # In +ve address space? Then okay.
        movq  $HYPERVISOR_VIRT_END+60,%rax
        cmpq  %rax,%rsi
        jb    domain_crash_synchronous  # Above Xen private area? Then okay.
1:      movb  TRAPBOUNCE_flags(%rdx),%cl
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
        movq  UREGS_eflags+8(%rsp),%rax
        andq  $~X86_EFLAGS_IF,%rax
        shlb  $1,%ch                    # Bit 9 (EFLAGS.IF)
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
        jz    2f
        subq  $32,%rsi
        movl  %gs,%eax
.Lft8:  movq  %rax,24(%rsi)             # GS
        movl  %fs,%eax
.Lft9:  movq  %rax,16(%rsi)             # FS
        movl  %es,%eax
.Lft10: movq  %rax,8(%rsi)              # ES
        movl  %ds,%eax
.Lft11: movq  %rax,(%rsi)               # DS
2:      subq  $16,%rsi
        movq  UREGS_r11+8(%rsp),%rax
.Lft12: movq  %rax,8(%rsi)              # R11
        movq  UREGS_rcx+8(%rsp),%rax
.Lft13: movq  %rax,(%rsi)               # RCX
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        /* Also clear AC: alignment checks shouldn't trigger in kernel mode. */
        movl  $TRAP_syscall,UREGS_entry_vector+8(%rsp)
        andl  $~(X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|\
                 X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+8(%rsp)
        movq  $FLAT_KERNEL_SS,UREGS_ss+8(%rsp)
        movq  %rsi,UREGS_rsp+8(%rsp)
        movq  $FLAT_KERNEL_CS,UREGS_cs+8(%rsp)
        movq  TRAPBOUNCE_eip(%rdx),%rax
        testq %rax,%rax
        jz    domain_crash_synchronous
        movq  %rax,UREGS_rip+8(%rsp)
        movb  $0,TRAPBOUNCE_flags(%rdx)
        ret
.section __ex_table,"a"
        .quad  .Lft2,domain_crash_synchronous ,  .Lft3,domain_crash_synchronous
        .quad  .Lft4,domain_crash_synchronous ,  .Lft5,domain_crash_synchronous
        .quad  .Lft6,domain_crash_synchronous ,  .Lft7,domain_crash_synchronous
        .quad  .Lft8,domain_crash_synchronous ,  .Lft9,domain_crash_synchronous
        .quad .Lft10,domain_crash_synchronous , .Lft11,domain_crash_synchronous
        .quad .Lft12,domain_crash_synchronous , .Lft13,domain_crash_synchronous
.previous

domain_crash_synchronous_string:
        .asciz "domain_crash_sync called from entry.S\n"

ENTRY(domain_crash_synchronous)
        # Get out of the guest-save area of the stack.
        GET_GUEST_REGS(%rax)
        movq  %rax,%rsp
        # create_bounce_frame() temporarily clobbers CS.RPL. Fix up.
#ifdef CONFIG_COMPAT
        movq  CPUINFO_current_vcpu(%rax),%rax
        movq  VCPU_domain(%rax),%rax
        btl   $_DOMF_compat,DOMAIN_domain_flags(%rax)
        setnc %al
        leal  (%rax,%rax,2),%eax
        orb   %al,UREGS_cs(%rsp)
#else
        orb   $3,UREGS_cs(%rsp)
#endif
        # printk(domain_crash_synchronous_string)
        leaq  domain_crash_synchronous_string(%rip),%rdi
        xorl  %eax,%eax
        call  printk
        jmp  __domain_crash_synchronous

        ALIGN
/* No special register assumptions. */
ENTRY(ret_from_intr)
        GET_CURRENT(%rbx)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
#ifndef CONFIG_COMPAT
        jmp   test_all_events
#else
        movq  VCPU_domain(%rbx),%rax
        btl   $_DOMF_compat,DOMAIN_domain_flags(%rax)
        jnc   test_all_events
        jmp   compat_test_all_events
#endif

        ALIGN
/* No special register assumptions. */
ENTRY(handle_exception)
        SAVE_ALL
        testb $X86_EFLAGS_IF>>8,UREGS_eflags+1(%rsp)
        jz    exception_with_ints_disabled
        sti
        movq  %rsp,%rdi
        movl  UREGS_entry_vector(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        GET_CURRENT(%rbx)
        PERFC_INCR(PERFC_exceptions, %rax)
        callq *(%rdx,%rax,8)
        testb $3,UREGS_cs(%rsp)
        jz    restore_all_xen
        leaq  VCPU_trap_bounce(%rbx),%rdx
#ifdef CONFIG_COMPAT
        movq  VCPU_domain(%rbx),%rax
        btl   $_DOMF_compat,DOMAIN_domain_flags(%rax)
        jc    compat_post_handle_exception
#endif
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    test_all_events
        call  create_bounce_frame
        jmp   test_all_events

/* No special register assumptions. */
exception_with_ints_disabled:
        testb $3,UREGS_cs(%rsp)         # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        movq  %rsp,%rdi
        call  search_pre_exception_table
        testq %rax,%rax                 # no fixup code for faulting EIP?
        jz    FATAL_exception_with_ints_disabled
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
        movl  UREGS_entry_vector(%rsp),%edi
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

ENTRY(page_fault)
        movl  $TRAP_page_fault,4(%rsp)
        jmp   handle_exception

ENTRY(machine_check)
        pushq $0
        movl  $TRAP_machine_check,4(%rsp)
        jmp   handle_exception

ENTRY(spurious_interrupt_bug)
        pushq $0
        movl  $TRAP_spurious_int,4(%rsp)
        jmp   handle_exception

ENTRY(double_fault)
        SAVE_ALL
        movq  %rsp,%rdi
        call  do_double_fault
        ud2

ENTRY(early_page_fault)
        SAVE_ALL
        movq  %rsp,%rdi
        call  do_early_page_fault
        jmp   restore_all_xen

ENTRY(nmi)
        pushq $0
        SAVE_ALL
        testb $3,UREGS_cs(%rsp)
        jz    nmi_in_hypervisor_mode
        /* Interrupted guest context. Copy the context to stack bottom. */
        GET_GUEST_REGS(%rbx)
        movl  $UREGS_kernel_sizeof/8,%ecx
1:      popq  %rax
        movq  %rax,(%rbx)
        addq  $8,%rbx
        loop  1b
        subq  $UREGS_kernel_sizeof,%rbx
        movq  %rbx,%rsp
nmi_in_hypervisor_mode:
        movq  %rsp,%rdi
        call  do_nmi
        jmp   ret_from_intr

.data

ENTRY(exception_table)
        .quad do_divide_error
        .quad do_debug
        .quad 0 # nmi
        .quad do_int3
        .quad do_overflow
        .quad do_bounds
        .quad do_invalid_op
        .quad math_state_restore
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
        .quad do_acm_op
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
        .byte 1 /* do_acm_op            */
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
        .rept NR_hypercalls-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
