#include <os.h>
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


/* Offsets into shared_info_t. */                
#define evtchn_upcall_pending		/* 0 */
#define evtchn_upcall_mask		1

NMI_MASK = 0x80000000

#define RDI 112
#define ORIG_RAX 120       /* + error_code */ 
#define EFLAGS 144

#define REST_SKIP 6*8			
.macro SAVE_REST
	subq $REST_SKIP,%rsp
#	CFI_ADJUST_CFA_OFFSET	REST_SKIP
	movq %rbx,5*8(%rsp) 
#	CFI_REL_OFFSET	rbx,5*8
	movq %rbp,4*8(%rsp) 
#	CFI_REL_OFFSET	rbp,4*8
	movq %r12,3*8(%rsp) 
#	CFI_REL_OFFSET	r12,3*8
	movq %r13,2*8(%rsp) 
#	CFI_REL_OFFSET	r13,2*8
	movq %r14,1*8(%rsp) 
#	CFI_REL_OFFSET	r14,1*8
	movq %r15,(%rsp) 
#	CFI_REL_OFFSET	r15,0*8
.endm		


.macro RESTORE_REST
	movq (%rsp),%r15
#	CFI_RESTORE r15
	movq 1*8(%rsp),%r14
#	CFI_RESTORE r14
	movq 2*8(%rsp),%r13
#	CFI_RESTORE r13
	movq 3*8(%rsp),%r12
#	CFI_RESTORE r12
	movq 4*8(%rsp),%rbp
#	CFI_RESTORE rbp
	movq 5*8(%rsp),%rbx
#	CFI_RESTORE rbx
	addq $REST_SKIP,%rsp
#	CFI_ADJUST_CFA_OFFSET	-(REST_SKIP)
.endm


#define ARG_SKIP 9*8
.macro RESTORE_ARGS skiprax=0,addskip=0,skiprcx=0,skipr11=0,skipr8910=0,skiprdx=0
	.if \skipr11
	.else
	movq (%rsp),%r11
#	CFI_RESTORE r11
	.endif
	.if \skipr8910
	.else
	movq 1*8(%rsp),%r10
#	CFI_RESTORE r10
	movq 2*8(%rsp),%r9
#	CFI_RESTORE r9
	movq 3*8(%rsp),%r8
#	CFI_RESTORE r8
	.endif
	.if \skiprax
	.else
	movq 4*8(%rsp),%rax
#	CFI_RESTORE rax
	.endif
	.if \skiprcx
	.else
	movq 5*8(%rsp),%rcx
#	CFI_RESTORE rcx
	.endif
	.if \skiprdx
	.else
	movq 6*8(%rsp),%rdx
#	CFI_RESTORE rdx
	.endif
	movq 7*8(%rsp),%rsi
#	CFI_RESTORE rsi
	movq 8*8(%rsp),%rdi
#	CFI_RESTORE rdi
	.if ARG_SKIP+\addskip > 0
	addq $ARG_SKIP+\addskip,%rsp
#	CFI_ADJUST_CFA_OFFSET	-(ARG_SKIP+\addskip)
	.endif
.endm	


.macro HYPERVISOR_IRET flag
#    testb $3,1*8(%rsp)    /* Don't need to do that in Mini-os, as */
#	jnz   2f               /* there is no userspace? */
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
#	_frame RDI
	/* rdi slot contains rax, oldrax contains error code */
	cld	
	subq  $14*8,%rsp
#	CFI_ADJUST_CFA_OFFSET	(14*8)
	movq %rsi,13*8(%rsp)
#	CFI_REL_OFFSET	rsi,RSI
	movq 14*8(%rsp),%rsi	/* load rax from rdi slot */
	movq %rdx,12*8(%rsp)
#	CFI_REL_OFFSET	rdx,RDX
	movq %rcx,11*8(%rsp)
#	CFI_REL_OFFSET	rcx,RCX
	movq %rsi,10*8(%rsp)	/* store rax */ 
#	CFI_REL_OFFSET	rax,RAX
	movq %r8, 9*8(%rsp)
#	CFI_REL_OFFSET	r8,R8
	movq %r9, 8*8(%rsp)
#	CFI_REL_OFFSET	r9,R9
	movq %r10,7*8(%rsp)
#	CFI_REL_OFFSET	r10,R10
	movq %r11,6*8(%rsp)
#	CFI_REL_OFFSET	r11,R11
	movq %rbx,5*8(%rsp) 
#	CFI_REL_OFFSET	rbx,RBX
	movq %rbp,4*8(%rsp) 
#	CFI_REL_OFFSET	rbp,RBP
	movq %r12,3*8(%rsp) 
#	CFI_REL_OFFSET	r12,R12
	movq %r13,2*8(%rsp) 
#	CFI_REL_OFFSET	r13,R13
	movq %r14,1*8(%rsp) 
#	CFI_REL_OFFSET	r14,R14
	movq %r15,(%rsp) 
#	CFI_REL_OFFSET	r15,R15
#if 0        
	cmpl $__KERNEL_CS,CS(%rsp)
	je  error_kernelspace
#endif        
error_call_handler:
	movq %rdi, RDI(%rsp)            
	movq %rsp,%rdi
	movq ORIG_RAX(%rsp),%rsi	# get error code 
	movq $-1,ORIG_RAX(%rsp)
	call *%rax

.macro zeroentry sym
#	INTR_FRAME
    movq (%rsp),%rcx
    movq 8(%rsp),%r11
    addq $0x10,%rsp /* skip rcx and r11 */
	pushq $0	/* push error code/oldrax */ 
#	CFI_ADJUST_CFA_OFFSET 8
	pushq %rax	/* push real oldrax to the rdi slot */ 
#	CFI_ADJUST_CFA_OFFSET 8
	leaq  \sym(%rip),%rax
	jmp error_entry
#	CFI_ENDPROC
.endm	

.macro errorentry sym
#	XCPT_FRAME
        movq (%rsp),%rcx
        movq 8(%rsp),%r11
        addq $0x10,%rsp /* rsp points to the error code */
	pushq %rax
#	CFI_ADJUST_CFA_OFFSET 8
	leaq  \sym(%rip),%rax
	jmp error_entry
#	CFI_ENDPROC
.endm

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



ENTRY(hypervisor_callback)
    zeroentry hypervisor_callback2

ENTRY(hypervisor_callback2)
        movq %rdi, %rsp 
11:     movq %gs:8,%rax
        incl %gs:0
        cmovzq %rax,%rsp
        pushq %rdi
        call do_hypervisor_callback 
        popq %rsp
        decl %gs:0
        jmp error_exit

#        ALIGN
restore_all_enable_events:  
	XEN_UNBLOCK_EVENTS(%rsi)        # %rsi is already set up...

scrit:	/**** START OF CRITICAL REGION ****/
	XEN_TEST_PENDING(%rsi)
	jnz  14f			# process more events if necessary...
	XEN_PUT_VCPU_INFO(%rsi)
        RESTORE_ARGS 0,8,0
        HYPERVISOR_IRET 0
        
14:	XEN_LOCKED_BLOCK_EVENTS(%rsi)
	XEN_PUT_VCPU_INFO(%rsi)
	SAVE_REST
        movq %rsp,%rdi                  # set the argument again
	jmp  11b
ecrit:  /**** END OF CRITICAL REGION ****/


retint_kernel:
retint_restore_args:
	movl EFLAGS-REST_SKIP(%rsp), %eax
	shr $9, %eax			# EAX[0] == IRET_EFLAGS.IF
	XEN_GET_VCPU_INFO(%rsi)
	andb evtchn_upcall_mask(%rsi),%al
	andb $1,%al			# EAX[0] == IRET_EFLAGS.IF & event_mask
	jnz restore_all_enable_events	#        != 0 => enable event delivery
	XEN_PUT_VCPU_INFO(%rsi)
		
	RESTORE_ARGS 0,8,0
	HYPERVISOR_IRET 0


error_exit:		
	RESTORE_REST
/*	cli */
	XEN_BLOCK_EVENTS(%rsi)		
	jmp retint_kernel



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
#       INTR_FRAME
#       CFI_ADJUST_CFA_OFFSET 8 */
        zeroentry do_debug
#       CFI_ENDPROC


ENTRY(int3)
#       INTR_FRAME
#       CFI_ADJUST_CFA_OFFSET 8 */
        zeroentry do_int3
#       CFI_ENDPROC

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
#       XCPT_FRAME
        errorentry do_stack_segment
#       CFI_ENDPROC
                    

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
        call *%rbx
        call exit_thread 
        

