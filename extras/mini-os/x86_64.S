#include <os.h>

.section __xen_guest
        .asciz  "XEN_VER=2.0,LOADER=generic,PT_MODE_WRITABLE"
.text

#define ENTRY(X) .globl X ; X :
.globl _start, shared_info
                        
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

ENTRY(hypervisor_callback)

ENTRY(failsafe_callback)
      iret
                
ENTRY(divide_error)
	pushq $0

ENTRY(coprocessor_error)
	pushq $0

ENTRY(simd_coprocessor_error)
	pushq $0

ENTRY(device_not_available)
        iret

ENTRY(debug)
	pushq $0

ENTRY(int3)
	pushq $0

ENTRY(overflow)
	pushq $0

ENTRY(bounds)
	pushq $0

ENTRY(invalid_op)
	pushq $0

ENTRY(coprocessor_segment_overrun)
	pushq $0

ENTRY(double_fault)

ENTRY(invalid_TSS)

ENTRY(segment_not_present)

ENTRY(stack_segment)

ENTRY(general_protection)

ENTRY(alignment_check)

ENTRY(page_fault)

ENTRY(machine_check)
	pushq $0

ENTRY(spurious_interrupt_bug)
	pushq $0
