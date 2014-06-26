#include <mini-os/os.h>
#include <mini-os/x86/arch_limits.h>
#include <xen/features.h>

.section __xen_guest
	.ascii	"GUEST_OS=Mini-OS"
	.ascii	",XEN_VER=xen-3.0"
	.ascii	",VIRT_BASE=0x0" /* &_text from minios_x86_64.lds */
	.ascii	",ELF_PADDR_OFFSET=0x0"
	.ascii	",HYPERCALL_PAGE=0x2"
	.ascii	",LOADER=generic"
	.byte	0
.text

#define ENTRY(X) .globl X ; X :
.globl _start, shared_info, hypercall_page


_start:
        cld
        movq stack_start(%rip),%rsp
        andq $(~(__STACK_SIZE-1)), %rsp
        movq %rsi,%rdi
        call arch_init

stack_start:
        .quad stack+(2*__STACK_SIZE)

        /* Unpleasant -- the PTE that maps this page is actually overwritten */
        /* to map the real shared-info page! :-)                             */
        .org 0x1000
shared_info:
        .org 0x2000

hypercall_page:
        .org 0x3000


#define XEN_GET_VCPU_INFO(reg)	movq HYPERVISOR_shared_info,reg
#define XEN_PUT_VCPU_INFO(reg)
#define XEN_PUT_VCPU_INFO_fixup
#define XEN_LOCKED_BLOCK_EVENTS(reg)	movb $1,evtchn_upcall_mask(reg)
#define XEN_LOCKED_UNBLOCK_EVENTS(reg)	movb $0,evtchn_upcall_mask(reg)
#define XEN_TEST_PENDING(reg)	testb $0xFF,evtchn_upcall_pending(reg)

#define XEN_BLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
                    			XEN_LOCKED_BLOCK_EVENTS(reg)	; \
    				            XEN_PUT_VCPU_INFO(reg)

#define XEN_UNBLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
                				XEN_LOCKED_UNBLOCK_EVENTS(reg)	; \
    			            	XEN_PUT_VCPU_INFO(reg)


/* Offsets into shared_info_t. */                
#define evtchn_upcall_pending		/* 0 */
#define evtchn_upcall_mask		1

NMI_MASK = 0x80000000
KERNEL_CS_MASK = 0xfc

#define RAX       80
#define RDI      112
#define ORIG_RAX 120       /* + error_code */
#define RIP      128
#define CS       136
#define RFLAGS   144
#define RSP      152


/* Macros */
.macro zeroentry sym
	movq (%rsp),%rcx
	movq 8(%rsp),%r11
	addq $0x10,%rsp /* skip rcx and r11 */
	pushq $0	/* push error code/oldrax */
	pushq %rax	/* push real oldrax to the rdi slot */
	leaq  \sym(%rip),%rax
	jmp error_entry
.endm

.macro errorentry sym
	movq (%rsp),%rcx
	movq 8(%rsp),%r11
	addq $0x10,%rsp /* rsp points to the error code */
	pushq %rax
	leaq  \sym(%rip),%rax
	jmp error_entry
.endm

.macro RESTORE_ALL
	movq (%rsp),%r11
	movq 1*8(%rsp),%r10
	movq 2*8(%rsp),%r9
	movq 3*8(%rsp),%r8
	movq 4*8(%rsp),%rax
	movq 5*8(%rsp),%rcx
	movq 6*8(%rsp),%rdx
	movq 7*8(%rsp),%rsi
	movq 8*8(%rsp),%rdi
	addq $9*8+8,%rsp
.endm	

.macro RESTORE_REST
	movq (%rsp),%r15
	movq 1*8(%rsp),%r14
	movq 2*8(%rsp),%r13
	movq 3*8(%rsp),%r12
	movq 4*8(%rsp),%rbp
	movq 5*8(%rsp),%rbx
	addq $6*8,%rsp
.endm

.macro SAVE_REST
	subq $6*8,%rsp
	movq %rbx,5*8(%rsp)
	movq %rbp,4*8(%rsp)
	movq %r12,3*8(%rsp)
	movq %r13,2*8(%rsp)
	movq %r14,1*8(%rsp)
	movq %r15,(%rsp)
.endm

.macro HYPERVISOR_IRET flag
	testl $NMI_MASK,2*8(%rsp)
	jnz   2f

	testb $1,(xen_features+XENFEAT_supervisor_mode_kernel)
	jnz   1f

	/* Direct iret to kernel space. Correct CS and SS. */
	orb   $3,1*8(%rsp)
	orb   $3,4*8(%rsp)
1:	iretq

2:	/* Slow iret via hypervisor. */
	andl  $~NMI_MASK, 16(%rsp)
	pushq $\flag
	jmp  hypercall_page + (__HYPERVISOR_iret * 32)
.endm


/*
 * Exception entry point. This expects an error code/orig_rax on the stack
 * and the exception handler in %rax.	
 */ 		  				
ENTRY(error_entry)
	/* rdi slot contains rax, oldrax contains error code */
	cld	
	subq  $14*8,%rsp
	movq %rsi,13*8(%rsp)
	movq 14*8(%rsp),%rsi	/* load rax from rdi slot */
	movq %rdx,12*8(%rsp)
	movq %rcx,11*8(%rsp)
	movq %rsi,10*8(%rsp)	/* store rax */ 
	movq %r8, 9*8(%rsp)
	movq %r9, 8*8(%rsp)
	movq %r10,7*8(%rsp)
	movq %r11,6*8(%rsp)
	movq %rbx,5*8(%rsp) 
	movq %rbp,4*8(%rsp) 
	movq %r12,3*8(%rsp) 
	movq %r13,2*8(%rsp) 
	movq %r14,1*8(%rsp) 
	movq %r15,(%rsp) 

error_call_handler:
	movq %rdi, RDI(%rsp)
	movq %rsp,%rdi
	movq ORIG_RAX(%rsp),%rsi	# get error code 
	movq $-1,ORIG_RAX(%rsp)
	call *%rax
	jmp error_exit


/*
 * Xen event (virtual interrupt) entry point.
 */
ENTRY(hypervisor_callback)
	zeroentry hypervisor_callback2

ENTRY(hypervisor_callback2)
	movq %rdi, %rsp

	/* check against event re-entrant */
	movq RIP(%rsp),%rax
	cmpq $scrit,%rax
	jb 11f
	cmpq $ecrit,%rax
	jb  critical_region_fixup

11:	movq %gs:8,%rax
	incl %gs:0
	cmovzq %rax,%rsp
	pushq %rdi
	call do_hypervisor_callback
	popq %rsp
	decl %gs:0

error_exit:
retint_kernel:
	movl RFLAGS(%rsp), %eax
	shr $9, %eax			# EAX[0] == IRET_RFLAGS.IF
	XEN_GET_VCPU_INFO(%rsi)
	andb evtchn_upcall_mask(%rsi),%al
	andb $1,%al			# EAX[0] == IRET_RFLAGS.IF & event_mask
	jnz restore_all_enable_events	#        != 0 => enable event delivery
	XEN_PUT_VCPU_INFO(%rsi)

retint_restore_args:
	RESTORE_REST
	RESTORE_ALL
	HYPERVISOR_IRET 0

restore_all_enable_events:
	RESTORE_REST
	RESTORE_ALL
	pushq %rax                      # save rax for it will be clobbered later
	RSP_OFFSET=8                    # record the stack frame layout changes
	XEN_GET_VCPU_INFO(%rax)         # safe to use rax since it is saved
	XEN_UNBLOCK_EVENTS(%rax)

scrit:	/**** START OF CRITICAL REGION ****/
	XEN_TEST_PENDING(%rax)
	jz 12f
	XEN_LOCKED_BLOCK_EVENTS(%rax)   # if pending, mask events and handle
	                                # by jumping to hypervisor_prologue
12:	popq %rax                       # all registers restored from this point

restore_end:
	jnz hypervisor_prologue         # safe to jump out of critical region
	                                # because events are masked if ZF = 0
	HYPERVISOR_IRET 0
ecrit:  /**** END OF CRITICAL REGION ****/

# Set up the stack as Xen does before calling event callback
hypervisor_prologue:
	pushq %r11
	pushq %rcx
	jmp hypervisor_callback

# [How we do the fixup]. We want to merge the current stack frame with the
# just-interrupted frame. How we do this depends on where in the critical
# region the interrupted handler was executing, and so if rax has been
# restored. We determine by comparing interrupted rip with "restore_end".
# We always copy all registers below RIP from the current stack frame
# to the end of the previous activation frame so that we can continue
# as if we've never even reached 11 running in the old activation frame.

critical_region_fixup:
	# Set up source and destination region pointers
	leaq RIP(%rsp),%rsi   # esi points at end of src region
	# Acquire interrupted rsp which was saved-on-stack. This points to
	# the end of dst region. Note that it is not necessarily current rsp
	# plus 0xb0, because the second interrupt might align the stack frame.
	movq RSP(%rsp),%rdi   # edi points at end of dst region

	cmpq $restore_end,%rax
	jae  13f

	# If interrupted rip is before restore_end
	# then rax hasn't been restored yet
	movq (%rdi),%rax
	movq %rax, RAX(%rsp)  # save rax
	addq $RSP_OFFSET,%rdi

	# Set up the copy
13:	movq $RIP,%rcx
	shr  $3,%rcx          # convert bytes into count of 64-bit entities
15:	subq $8,%rsi          # pre-decrementing copy loop
	subq $8,%rdi
	movq (%rsi),%rax
	movq %rax,(%rdi)
	loop 15b
16:	movq %rdi,%rsp        # final rdi is top of merged stack
	andb $KERNEL_CS_MASK,CS(%rsp)      # CS might have changed
	jmp  11b



ENTRY(failsafe_callback)
        popq  %rcx
        popq  %r11
        iretq


ENTRY(coprocessor_error)
        zeroentry do_coprocessor_error


ENTRY(simd_coprocessor_error)
        zeroentry do_simd_coprocessor_error


ENTRY(device_not_available)
        zeroentry do_device_not_available


ENTRY(debug)
        zeroentry do_debug


ENTRY(int3)
        zeroentry do_int3

ENTRY(overflow)
        zeroentry do_overflow


ENTRY(bounds)
        zeroentry do_bounds
    
    
ENTRY(invalid_op)
        zeroentry do_invalid_op


ENTRY(coprocessor_segment_overrun)
        zeroentry do_coprocessor_segment_overrun


ENTRY(invalid_TSS)
        errorentry do_invalid_TSS


ENTRY(segment_not_present)
        errorentry do_segment_not_present


/* runs on exception stack */
ENTRY(stack_segment)
        errorentry do_stack_segment
                    

ENTRY(general_protection)
        errorentry do_general_protection


ENTRY(alignment_check)
        errorentry do_alignment_check


ENTRY(divide_error)
        zeroentry do_divide_error


ENTRY(spurious_interrupt_bug)
        zeroentry do_spurious_interrupt_bug
            

ENTRY(page_fault)
        errorentry do_page_fault





ENTRY(thread_starter)
        popq %rdi
        popq %rbx
        pushq $0
        xorq %rbp,%rbp
        call *%rbx
        call exit_thread 
        

ENTRY(__arch_switch_threads)
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rsp, (%rdi)		/* save ESP */
	movq (%rsi), %rsp		/* restore ESP */
	movq $1f, 8(%rdi)		/* save EIP */
	pushq 8(%rsi)			/* restore EIP */
	ret
1:
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	ret
