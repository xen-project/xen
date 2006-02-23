#include <os.h>

.section __xen_guest
	.ascii	"GUEST_OS=Mini-OS"
	.ascii	",XEN_VER=xen-3.0"
	.ascii	",HYPERCALL_PAGE=0x2"
	.ascii	",LOADER=generic"
	.ascii	",PT_MODE_WRITABLE"
	.byte	0
.text

#define ENTRY(X) .globl X ; X :
.globl _start, shared_info, hypercall_page

#define SAVE_ALL \
        cld; \
        pushq %rdi; \
        pushq %rsi; \
        pushq %rdx; \
        pushq %rcx; \
        pushq %rax; \
        pushq %r8; \
        pushq %r9; \
        pushq %r10; \
        pushq %r11; \
        pushq %rbx; \
        pushq %rbp; \
        pushq %r12; \
        pushq %r13; \
        pushq %r14; \
        pushq %r15;

#define RESTORE_ALL \
        popq  %r15; \
        popq  %r14; \
        popq  %r13; \
        popq  %r12; \
        popq  %rbp; \
        popq  %rbx; \
        popq  %r11; \
        popq  %r10; \
        popq  %r9; \
        popq  %r8; \
        popq  %rax; \
        popq  %rcx; \
        popq  %rdx; \
        popq  %rsi; \
        popq  %rdi

_start:
        cld
        movq stack_start(%rip),%rsp
        movq %rsi,%rdi
        call start_kernel

stack_start:
        .quad stack+8192

        /* Unpleasant -- the PTE that maps this page is actually overwritten */
        /* to map the real shared-info page! :-)                             */
        .org 0x1000
shared_info:
        .org 0x2000

hypercall_page:
        .org 0x3000

ENTRY(hypervisor_callback)
        popq  %rcx
        popq  %r11
        iretq

ENTRY(failsafe_callback)
        popq  %rcx
        popq  %r11
        iretq

error_code:
        SAVE_ALL
        movq  %rsp,%rdi
        movl  15*8+4(%rsp),%eax
        leaq  exception_table(%rip),%rdx
        callq *(%rdx,%rax,8)
        RESTORE_ALL
        addq  $8,%rsp
        iretq
                        
ENTRY(divide_error)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_divide_error,4(%rsp)
        jmp   error_code
        
ENTRY(coprocessor_error)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_copro_error,4(%rsp)
        jmp   error_code

ENTRY(simd_coprocessor_error)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_simd_error,4(%rsp)
        jmp   error_code

ENTRY(device_not_available)
        popq  %rcx
        popq  %r11
        movl  $TRAP_no_device,4(%rsp)
        jmp   error_code

ENTRY(debug)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_debug,4(%rsp)
        jmp   error_code

ENTRY(int3)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_int3,4(%rsp)
        jmp   error_code

ENTRY(overflow)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_overflow,4(%rsp)
        jmp   error_code

ENTRY(bounds)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_bounds,4(%rsp)
        jmp   error_code

ENTRY(invalid_op)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_invalid_op,4(%rsp)
        jmp   error_code

ENTRY(coprocessor_segment_overrun)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_copro_seg,4(%rsp)
        jmp   error_code

ENTRY(invalid_TSS)
        popq  %rcx
        popq  %r11
        movl  $TRAP_invalid_tss,4(%rsp)
        jmp   error_code

ENTRY(segment_not_present)
        popq  %rcx
        popq  %r11
        movl  $TRAP_no_segment,4(%rsp)
        jmp   error_code

ENTRY(stack_segment)
        popq  %rcx
        popq  %r11
        movl  $TRAP_stack_error,4(%rsp)
        jmp   error_code

ENTRY(general_protection)
        popq  %rcx
        popq  %r11
        movl  $TRAP_gp_fault,4(%rsp)
        jmp   error_code

ENTRY(alignment_check)
        popq  %rcx
        popq  %r11
        movl  $TRAP_alignment_check,4(%rsp)
        jmp   error_code

ENTRY(virt_cr2)
        .quad 0
ENTRY(page_fault)
        popq  %rcx
        popq  %r11
        popq  virt_cr2(%rip)
        movl  $TRAP_page_fault,4(%rsp)
        jmp   error_code
        
ENTRY(machine_check)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_machine_check,4(%rsp)
        jmp   error_code

ENTRY(spurious_interrupt_bug)
        popq  %rcx
        popq  %r11
	pushq $0
        movl  $TRAP_spurious_int,4(%rsp)
        jmp   error_code

ENTRY(exception_table)
        .quad do_divide_error
        .quad do_debug
        .quad 0 # nmi
        .quad do_int3
        .quad do_overflow
        .quad do_bounds
        .quad do_invalid_op
        .quad 0
        .quad 0
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
