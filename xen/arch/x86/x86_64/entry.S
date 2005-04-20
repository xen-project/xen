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

#define GET_CURRENT(reg)         \
        movq $STACK_SIZE-8, reg; \
        orq  %rsp, reg;          \
        andq $~7,reg;            \
        movq (reg),reg;

        ALIGN
/* %rbx: struct exec_domain, interrupts disabled */
switch_to_kernel:
        leaq  EDOMAIN_trap_bounce(%rbx),%rdx
        movq  EDOMAIN_syscall_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $0,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame

/* %rbx: struct exec_domain */
restore_all_guest:
        RESTORE_ALL
        testw $TRAP_syscall,4(%rsp)
        jz    iret_exit_to_guest

        addq  $8,%rsp
        popq  %rcx                    # RIP
        popq  %r11                    # CS
        cmpw  $__GUEST_CS32,%r11
        popq  %r11                    # RFLAGS
        cli                           # No interrupts after stack switch
        popq  %rsp                    # RSP
        je    1f
        sysretq
1:      sysretl

        ALIGN
/* No special register assumptions. */
iret_exit_to_guest:
        addq  $8,%rsp
FLT1:   iretq

.section .fixup,"ax"
FIX1:   popq  -15*8-8(%rsp)            # error_code/entry_vector
        SAVE_ALL                       # 15*8 bytes pushed
        movq  -8(%rsp),%rsi            # error_code/entry_vector
        sti                            # after stack abuse (-1024(%rsp))
        pushq $__HYPERVISOR_DS         # SS
        leaq  8(%rsp),%rax
        pushq %rax                     # RSP
        pushf                          # RFLAGS
        pushq $__HYPERVISOR_CS         # CS
        leaq  DBLFLT1(%rip),%rax
        pushq %rax                     # RIP
        pushq %rsi                     # error_code/entry_vector
        jmp   error_code
DBLFLT1:GET_CURRENT(%rbx)
        jmp   test_all_events
failsafe_callback:
        GET_CURRENT(%rbx)
        leaq  EDOMAIN_trap_bounce(%rbx),%rdx
        movq  EDOMAIN_failsafe_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $TBF_FAILSAFE,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        jmp   test_all_events
.previous
.section __pre_ex_table,"a"
	.quad FLT1,FIX1
.previous
.section __ex_table,"a"
        .quad DBLFLT1,failsafe_callback
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
        movl  $__GUEST_SS,24(%rsp)
        pushq %rcx
        pushq $0
        movl  $TRAP_syscall,4(%rsp)
        SAVE_ALL
        GET_CURRENT(%rbx)
        testb $TF_kernel_mode,EDOMAIN_thread_flags(%rbx)
        jz    switch_to_kernel

/*hypercall:*/
        sti
        movq  %r10,%rcx
        andq  $(NR_hypercalls-1),%rax
        leaq  SYMBOL_NAME(hypercall_table)(%rip),%r10
        PERFC_INCR(PERFC_hypercalls, %rax)
        callq *(%r10,%rax,8)
        movq %rax,XREGS_rax(%rsp)       # save the return value

/* %rbx: struct exec_domain */
test_all_events:
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movl  EDOMAIN_processor(%rbx),%eax
        shl   $6,%rax                    # sizeof(irq_cpustat) == 64
        leaq  SYMBOL_NAME(irq_stat)(%rip),%rcx
        testl $~0,(%rcx,%rax,1)
        jnz   process_softirqs
/*test_guest_events:*/
        movq  EDOMAIN_vcpu_info(%rbx),%rax
        testb $0xFF,VCPUINFO_upcall_mask(%rax)
        jnz   restore_all_guest
        testb $0xFF,VCPUINFO_upcall_pending(%rax)
        jz    restore_all_guest
/*process_guest_events:*/
        sti
        leaq  EDOMAIN_trap_bounce(%rbx),%rdx
        movq  EDOMAIN_event_addr(%rbx),%rax
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  create_bounce_frame
        movq  EDOMAIN_vcpu_info(%rbx),%rax
        movb  $1,VCPUINFO_upcall_mask(%rax) # Upcalls masked during delivery
        jmp   test_all_events

#ifdef CONFIG_VMX
/*
 * At VMExit time the processor saves the guest selectors, rsp, rip, 
 * and rflags. Therefore we don't save them, but simply decrement 
 * the kernel stack pointer to make it consistent with the stack frame 
 * at usual interruption time. The rflags of the host is not saved by VMX, 
 * and we set it to the fixed value.
 *
 * We also need the room, especially because orig_eax field is used 
 * by do_IRQ(). Compared the xen_regs, we skip pushing for the following:
 *   (13) u64 gs_base_user;                 
 *   (12) u64 gs_base_kernel;                 
 *   (11) u64 fs_base;                 
 *   (10) u64 gs;                 
 *   (9)  u64 fs;
 *   (8)  u64 ds;
 *   (7)  u64 es;
 *               <- get_stack_bottom() (= HOST_ESP)
 *   (6)  u64 ss;
 *   (5)  u64 rsp;
 *   (4)  u64 rflags;
 *   (3)  u64 cs;
 *   (2)  u64 rip;
 * (2/1)  u32 entry_vector;
 * (1/1)  u32 error_code;
 * However, get_stack_bottom() actually returns 64 bytes before the real
 * bottom of the stack to allow space for:
 * domain pointer, DS, ES, FS, GS. Therefore, we effectively skip 6 registers.
 */
#define VMX_MONITOR_RFLAGS	0x202 /* IF on */
#define NR_SKIPPED_REGS	6	/* See the above explanation */
#define VMX_SAVE_ALL_NOSEGREGS \
        pushq $VMX_MONITOR_RFLAGS; \
        popfq; \
        subq $(NR_SKIPPED_REGS*8), %rsp; \
        pushq %rdi; \
        pushq %rsi; \
        pushq %rdx; \
        pushq %rcx; \
        pushq %rax; \
        pushq %r8;  \
        pushq %r9;  \
        pushq %r10; \
        pushq %r11; \
        pushq %rbx; \
        pushq %rbp; \
        pushq %r12; \
        pushq %r13; \
        pushq %r14; \
        pushq %r15; \

ENTRY(vmx_asm_vmexit_handler)
        /* selectors are restored/saved by VMX */
        VMX_SAVE_ALL_NOSEGREGS
        call SYMBOL_NAME(vmx_vmexit_handler)
        jmp vmx_asm_do_resume

ENTRY(vmx_asm_do_launch)
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rax
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi
        addq $(NR_SKIPPED_REGS*8), %rsp
        /* VMLUANCH */
        .byte 0x0f,0x01,0xc2
        pushfq
        call SYMBOL_NAME(vm_launch_fail)
        hlt
        
        ALIGN
        
ENTRY(vmx_asm_do_resume)
vmx_test_all_events:
        GET_CURRENT(%rbx)
/* test_all_events: */
        xorq %rcx,%rcx
        notq %rcx
        cli                             # tests must not race interrupts
/*test_softirqs:*/  
        movq EDOMAIN_processor(%rbx),%rax
#if 0
        shl  $6,%rax                    # sizeof(irq_cpustat) == 64
        test %rcx,SYMBOL_NAME(irq_stat)(%rax,1)
#endif
        jnz  vmx_process_softirqs

vmx_restore_all_guest:
        call SYMBOL_NAME(load_cr2)
        /* 
         * Check if we are going back to VMX-based VM
         * By this time, all the setups in the VMCS must be complete.
         */
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rax
        popq %rcx
        popq %rdx
        popq %rsi
        popq %rdi
        addq $(NR_SKIPPED_REGS*8), %rsp
        /* VMRESUME */
        .byte 0x0f,0x01,0xc3
        pushfq
        call SYMBOL_NAME(vm_resume_fail)
        /* Should never reach here */
        hlt

        ALIGN
vmx_process_softirqs:
        sti       
        call SYMBOL_NAME(do_softirq)
        jmp  vmx_test_all_events
#endif

        ALIGN
/* %rbx: struct exec_domain */
process_softirqs:
        sti       
        call SYMBOL_NAME(do_softirq)
        jmp  test_all_events

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS STACK:                     */
/*   { RCX, R11, [DS-GS,] [CR2,] [ERRCODE,] RIP, CS, RFLAGS, RSP, SS }   */
/* %rdx: trap_bounce, %rbx: struct exec_domain                           */
/* On return only %rbx is guaranteed non-clobbered.                      */
create_bounce_frame:
        testb $TF_kernel_mode,EDOMAIN_thread_flags(%rbx)
        jnz   1f
        /* Push new frame at registered guest-OS stack base. */
        pushq %rdx
        movq  %rbx,%rdi
        call  SYMBOL_NAME(toggle_guest_mode)
        popq  %rdx
        movq  EDOMAIN_kernel_sp(%rbx),%rsi
        jmp   2f
1:      /* In kernel context already: push new frame at existing %rsp. */
        movq  XREGS_rsp+8(%rsp),%rsi
        andb  $0xfc,XREGS_cs+8(%rsp)    # Indicate kernel context to guest.
2:      movq  $HYPERVISOR_VIRT_START,%rax
        cmpq  %rax,%rsi
        jb    1f                        # In +ve address space? Then okay.
        movq  $HYPERVISOR_VIRT_END+60,%rax
        cmpq  %rax,%rsi
        jb    domain_crash_synchronous  # Above Xen private area? Then okay.
1:      subq  $40,%rsi
        movq  XREGS_ss+8(%rsp),%rax
FLT2:   movq  %rax,32(%rsi)             # SS
        movq  XREGS_rsp+8(%rsp),%rax
FLT3:   movq  %rax,24(%rsi)             # RSP
        movq  XREGS_eflags+8(%rsp),%rax
FLT4:   movq  %rax,16(%rsi)             # RFLAGS
        movq  XREGS_cs+8(%rsp),%rax
FLT5:   movq  %rax,8(%rsi)              # CS
        movq  XREGS_rip+8(%rsp),%rax
FLT6:   movq  %rax,(%rsi)               # RIP
        movb  TRAPBOUNCE_flags(%rdx),%cl
        testb $TBF_EXCEPTION_ERRCODE,%cl
        jz    1f
        subq  $8,%rsi
        movl  TRAPBOUNCE_error_code(%rdx),%eax
FLT7:   movq  %rax,(%rsi)               # ERROR CODE
        testb $TBF_EXCEPTION_CR2,%cl
        jz    2f
        subq  $8,%rsi
        movq  TRAPBOUNCE_cr2(%rdx),%rax
FLT8:   movq  %rax,(%rsi)               # CR2
1:      testb $TBF_FAILSAFE,%cl
        jz    2f
        subq  $32,%rsi
        movl  %gs,%eax
FLT9:   movq  %rax,24(%rsi)             # GS
        movl  %fs,%eax
FLT10:  movq  %rax,16(%rsi)             # FS
        movl  %es,%eax
FLT11:  movq  %rax,8(%rsi)              # ES
        movl  %ds,%eax
FLT12:  movq  %rax,(%rsi)               # DS
2:      subq  $16,%rsi
        movq  XREGS_r11+8(%rsp),%rax
FLT13:  movq  %rax,8(%rsi)              # R11
        movq  XREGS_rcx+8(%rsp),%rax
FLT14:  movq  %rax,(%rsi)               # RCX
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        movq  $TRAP_syscall,XREGS_entry_vector+8(%rsp)
        andl  $0xfffcbeff,XREGS_eflags+8(%rsp)
        movq  $__GUEST_SS,XREGS_ss+8(%rsp)
        movq  %rsi,XREGS_rsp+8(%rsp)
        movq  $__GUEST_CS,XREGS_cs+8(%rsp)
        movq  TRAPBOUNCE_eip(%rdx),%rax
        movq  %rax,XREGS_rip+8(%rsp)
        movb  $0,TRAPBOUNCE_flags(%rdx)
        ret
.section __ex_table,"a"
        .quad  FLT2,domain_crash_synchronous ,  FLT3,domain_crash_synchronous
        .quad  FLT4,domain_crash_synchronous ,  FLT5,domain_crash_synchronous
        .quad  FLT6,domain_crash_synchronous ,  FLT7,domain_crash_synchronous
        .quad  FLT8,domain_crash_synchronous ,  FLT9,domain_crash_synchronous
        .quad FLT10,domain_crash_synchronous , FLT11,domain_crash_synchronous
        .quad FLT12,domain_crash_synchronous , FLT13,domain_crash_synchronous
        .quad FLT14,domain_crash_synchronous
.previous

        ALIGN
/* %rbx: struct exec_domain */
process_guest_exception_and_events:
        leaq  EDOMAIN_trap_bounce(%rbx),%rdx
        testb $TBF_EXCEPTION,TRAPBOUNCE_flags(%rdx)
        jz    test_all_events
        call  create_bounce_frame
        jmp   test_all_events

        ALIGN
/* No special register assumptions. */
ENTRY(ret_from_intr)
        GET_CURRENT(%rbx)
        testb $3,XREGS_cs(%rsp)
        jnz   test_all_events
        jmp   restore_all_xen

        ALIGN
/* No special register assumptions. */
error_code:
        SAVE_ALL
        testb $X86_EFLAGS_IF>>8,XREGS_eflags+1(%rsp)
        jz    exception_with_ints_disabled
        sti
        movq  %rsp,%rdi
        movl  XREGS_entry_vector(%rsp),%eax
        leaq  SYMBOL_NAME(exception_table)(%rip),%rdx
        GET_CURRENT(%rbx)
        PERFC_INCR(PERFC_exceptions, %rax)
        callq *(%rdx,%rax,8)
        testb $3,XREGS_cs(%rsp)
        jz    restore_all_xen
        jmp   process_guest_exception_and_events

/* No special register assumptions. */
exception_with_ints_disabled:
        testb $3,XREGS_cs(%rsp)         # interrupts disabled outside Xen?
        jnz   FATAL_exception_with_ints_disabled
        movq  %rsp,%rdi
        call  search_pre_exception_table
        testq %rax,%rax                 # no fixup code for faulting EIP?
        jz    FATAL_exception_with_ints_disabled
        movq  %rax,XREGS_rip(%rsp)
        subq  $8,XREGS_rsp(%rsp)        # add ec/ev to previous stack frame
        testb $15,XREGS_rsp(%rsp)       # return %rsp is now aligned?
        jz    1f                        # then there is a pad quadword already
        movq  %rsp,%rsi
        subq  $8,%rsp
        movq  %rsp,%rdi
        movq  $XREGS_kernel_sizeof/8,%rcx
        rep;  movsq                     # make room for ec/ev
1:      movq  XREGS_error_code(%rsp),%rax # ec/ev
        movq  %rax,XREGS_kernel_sizeof(%rsp)
        jmp   restore_all_xen           # return to fixup code

/* No special register assumptions. */
FATAL_exception_with_ints_disabled:
        movl  XREGS_entry_vector(%rsp),%edi
        movq  %rsp,%rsi
        call  SYMBOL_NAME(fatal_trap)
        ud2

ENTRY(divide_error)
        pushq $0
        movl  $TRAP_divide_error,4(%rsp)
        jmp   error_code

ENTRY(coprocessor_error)
        pushq $0
        movl  $TRAP_copro_error,4(%rsp)
	jmp   error_code

ENTRY(simd_coprocessor_error)
        pushq $0
        movl  $TRAP_simd_error,4(%rsp)
	jmp error_code

ENTRY(device_not_available)
        pushq $0
        movl  $TRAP_no_device,4(%rsp)
        jmp   error_code

ENTRY(debug)
        pushq $0
        movl  $TRAP_debug,4(%rsp)
	jmp   error_code

ENTRY(int3)
        pushq $0
	movl  $TRAP_int3,4(%rsp)
	jmp   error_code

ENTRY(overflow)
        pushq $0
	movl  $TRAP_overflow,4(%rsp)
	jmp   error_code

ENTRY(bounds)
        pushq $0
	movl  $TRAP_bounds,4(%rsp)
	jmp   error_code

ENTRY(invalid_op)
        pushq $0
	movl  $TRAP_invalid_op,4(%rsp)
	jmp   error_code

ENTRY(coprocessor_segment_overrun)
        pushq $0
	movl  $TRAP_copro_seg,4(%rsp)
	jmp   error_code

ENTRY(invalid_TSS)
        movl  $TRAP_invalid_tss,4(%rsp)
	jmp   error_code

ENTRY(segment_not_present)
        movl  $TRAP_no_segment,4(%rsp)
	jmp   error_code

ENTRY(stack_segment)
        movl  $TRAP_stack_error,4(%rsp)
	jmp   error_code

ENTRY(general_protection)
        movl  $TRAP_gp_fault,4(%rsp)
	jmp   error_code

ENTRY(alignment_check)
        movl  $TRAP_alignment_check,4(%rsp)
	jmp   error_code

ENTRY(page_fault)
        movl  $TRAP_page_fault,4(%rsp)
	jmp   error_code

ENTRY(machine_check)
        pushq $0
        movl  $TRAP_machine_check,4(%rsp)
	jmp   error_code

ENTRY(spurious_interrupt_bug)
        pushq $0
        movl  $TRAP_spurious_int,4(%rsp)
	jmp   error_code

ENTRY(double_fault)
        movl  $TRAP_double_fault,4(%rsp)
        jmp   error_code

ENTRY(nmi)
        pushq $0
        SAVE_ALL
        inb   $0x61,%al
        movl  %eax,%esi # reason
        movq  %rsp,%rdi # regs
        call  SYMBOL_NAME(do_nmi)
	jmp   restore_all_xen

.data

ENTRY(exception_table)
        .quad SYMBOL_NAME(do_divide_error)
        .quad SYMBOL_NAME(do_debug)
        .quad 0 # nmi
        .quad SYMBOL_NAME(do_int3)
        .quad SYMBOL_NAME(do_overflow)
        .quad SYMBOL_NAME(do_bounds)
        .quad SYMBOL_NAME(do_invalid_op)
        .quad SYMBOL_NAME(math_state_restore)
        .quad SYMBOL_NAME(do_double_fault)
        .quad SYMBOL_NAME(do_coprocessor_segment_overrun)
        .quad SYMBOL_NAME(do_invalid_TSS)
        .quad SYMBOL_NAME(do_segment_not_present)
        .quad SYMBOL_NAME(do_stack_segment)
        .quad SYMBOL_NAME(do_general_protection)
        .quad SYMBOL_NAME(do_page_fault)
        .quad SYMBOL_NAME(do_spurious_interrupt_bug)
        .quad SYMBOL_NAME(do_coprocessor_error)
        .quad SYMBOL_NAME(do_alignment_check)
        .quad SYMBOL_NAME(do_machine_check)
        .quad SYMBOL_NAME(do_simd_coprocessor_error)

ENTRY(hypercall_table)
        .quad SYMBOL_NAME(do_set_trap_table)     /*  0 */
        .quad SYMBOL_NAME(do_mmu_update)
        .quad SYMBOL_NAME(do_set_gdt)
        .quad SYMBOL_NAME(do_stack_switch)
        .quad SYMBOL_NAME(do_set_callbacks)
        .quad SYMBOL_NAME(do_fpu_taskswitch)     /*  5 */
        .quad SYMBOL_NAME(do_sched_op)
        .quad SYMBOL_NAME(do_dom0_op)
        .quad SYMBOL_NAME(do_set_debugreg)
        .quad SYMBOL_NAME(do_get_debugreg)
        .quad SYMBOL_NAME(do_update_descriptor)  /* 10 */
        .quad SYMBOL_NAME(do_ni_hypercall)
        .quad SYMBOL_NAME(do_dom_mem_op)
        .quad SYMBOL_NAME(do_multicall)
        .quad SYMBOL_NAME(do_update_va_mapping)
        .quad SYMBOL_NAME(do_set_timer_op)       /* 15 */
        .quad SYMBOL_NAME(do_event_channel_op)
        .quad SYMBOL_NAME(do_xen_version)
        .quad SYMBOL_NAME(do_console_io)
        .quad SYMBOL_NAME(do_physdev_op)
        .quad SYMBOL_NAME(do_grant_table_op)     /* 20 */
        .quad SYMBOL_NAME(do_vm_assist)
        .quad SYMBOL_NAME(do_update_va_mapping_otherdomain)
        .quad SYMBOL_NAME(do_switch_to_user)
        .quad SYMBOL_NAME(do_boot_vcpu)
        .quad SYMBOL_NAME(do_set_segment_base)   /* 25 */
        .quad SYMBOL_NAME(do_mmuext_op)
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .quad SYMBOL_NAME(do_ni_hypercall)
        .endr
