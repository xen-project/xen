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
#include <public/xen.h>


/*
 * %rax                            = hypercall vector
 * %rdi, %rsi, %rdx, %r10, %r8, %9 = hypercall arguments
 * %r11, %rcx                      = SYSCALL-saved %rflags and %rip
 * NB. We must move %r10 to %rcx for C function-calling ABI.
 */
ENTRY(hypercall)
        sti
        movl  $__GUEST_SS,8(%rsp)
        pushq %r11
        pushq $__GUEST_CS
        pushq %rcx
        pushq $0
        SAVE_ALL
        movq  %r10,%rcx
        andq  $(NR_hypercalls-1),%rax
        leaq  SYMBOL_NAME(hypercall_table)(%rip),%rcx
        callq *(%rcx,%rax,8)
        RESTORE_ALL
        addq  $8,%rsp
        popq  %rcx
        addq  $8,%rsp
        popq  %r11
        cli
        popq  %rsp
        sysretq
        
ENTRY(ret_from_intr)
restore_all_xen:
        RESTORE_ALL
        addq  $8,%rsp
        iretq

error_code:
        SAVE_ALL
        sti
        movq  %rsp,%rdi
        movl  XREGS_entry_vector(%rsp),%eax
        leaq  SYMBOL_NAME(exception_table)(%rip),%rdx
        callq *(%rdx,%rax,8)
        jmp   restore_all_xen

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
        movl  %esp,%edi # regs
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
        .quad SYMBOL_NAME(do_ni_hypercall) # do_set_fast_trap
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
        .quad SYMBOL_NAME(do_ni_hypercall) # do_switch_vm86
        .quad SYMBOL_NAME(do_boot_vcpu)
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .quad SYMBOL_NAME(do_ni_hypercall)
        .endr
