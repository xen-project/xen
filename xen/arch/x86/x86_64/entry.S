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

ENTRY(hypercall)
        iret

ENTRY(ret_from_intr)
restore_all_xen:
        popq  %r15
        popq  %r14
        popq  %r13
        popq  %r12
        popq  %rbp
        popq  %rbx
        popq  %r11
        popq  %r10
        popq  %r9
        popq  %r8
        popq  %rax
        popq  %rcx
        popq  %rdx
        popq  %rsi
        popq  %rdi
        addq  $8,%rsp
        iret

error_code:
        SAVE_ALL
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

ENTRY(nmi)
        iret

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
        .quad 0 # double fault
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
