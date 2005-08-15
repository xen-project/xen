/*
 *  linux/arch/x86_64/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002  Andi Kleen SuSE Labs
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 * 
 *  $Id$
 *
 *  Jun Nakajima <jun.nakajima@intel.com>
 *  Asit Mallick <asit.k.mallick@intel.com>
 *      Modified for Xen
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after an interrupt and after each system call.
 * 
 * Normal syscalls and interrupts don't save a full stack frame, this is 
 * only done for syscall tracing, signals or fork/exec et.al.
 * 
 * A note on terminology:	 
 * - top of stack: Architecture defined interrupt frame from SS to RIP 
 * at the top of the kernel process stack.	
 * - partial stack frame: partially saved registers upto R11.
 * - full stack frame: Like partial stack frame, but all register saved. 
 *	
 * TODO:	 
 * - schedule it carefully for the final hardware.
 */

#define ASSEMBLY 1
#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/smp.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm_offset.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/errno.h>
#include <asm-xen/xen-public/arch-x86_64.h>

#include "irq_vectors.h"

#include "xen_entry.S"
	
	.code64

#ifndef CONFIG_PREEMPT
#define retint_kernel retint_restore_args
#endif	

/*
 * C code is not supposed to know about undefined top of stack. Every time 
 * a C function with an pt_regs argument is called from the SYSCALL based 
 * fast path FIXUP_TOP_OF_STACK is needed.
 * RESTORE_TOP_OF_STACK syncs the syscall state after any possible ptregs
 * manipulation.
 */        	

	/* %rsp:at FRAMEEND */ 
	.macro FIXUP_TOP_OF_STACK tmp
	movq    $__USER_CS,CS(%rsp)
	movq 	$-1,RCX(%rsp)
	.endm

	.macro RESTORE_TOP_OF_STACK tmp,offset=0
	.endm

	.macro FAKE_STACK_FRAME child_rip
	/* push in order ss, rsp, eflags, cs, rip */
	xorq %rax, %rax
	pushq %rax /* ss */
	CFI_ADJUST_CFA_OFFSET	8
	pushq %rax /* rsp */
	CFI_ADJUST_CFA_OFFSET	8
	CFI_OFFSET	rip,0
	pushq $(1<<9) /* eflags - interrupts on */
	CFI_ADJUST_CFA_OFFSET	8
	pushq $__KERNEL_CS /* cs */
	CFI_ADJUST_CFA_OFFSET	8
	pushq \child_rip /* rip */
	CFI_ADJUST_CFA_OFFSET	8
	CFI_OFFSET	rip,0
	pushq	%rax /* orig rax */
	CFI_ADJUST_CFA_OFFSET	8
	.endm

	.macro UNFAKE_STACK_FRAME
	addq $8*6, %rsp
	CFI_ADJUST_CFA_OFFSET	-(6*8)
	.endm

	.macro	CFI_DEFAULT_STACK
	CFI_ADJUST_CFA_OFFSET  (SS)
	CFI_OFFSET	r15,R15-SS
	CFI_OFFSET	r14,R14-SS
	CFI_OFFSET	r13,R13-SS
	CFI_OFFSET	r12,R12-SS
	CFI_OFFSET	rbp,RBP-SS
	CFI_OFFSET	rbx,RBX-SS
	CFI_OFFSET	r11,R11-SS
	CFI_OFFSET	r10,R10-SS
	CFI_OFFSET	r9,R9-SS
	CFI_OFFSET	r8,R8-SS
	CFI_OFFSET	rax,RAX-SS
	CFI_OFFSET	rcx,RCX-SS
	CFI_OFFSET	rdx,RDX-SS
	CFI_OFFSET	rsi,RSI-SS
	CFI_OFFSET	rdi,RDI-SS
	CFI_OFFSET	rsp,RSP-SS
	CFI_OFFSET	rip,RIP-SS
	.endm

        /*
         * Must be consistent with the definition in arch_x86_64.h:    
         *     struct switch_to_user {
         *        u64 rax, r11, rcx, flags, rip, cs, rflags, rsp, ss;
         *     };
         * #define VGCF_IN_SYSCALL (1<<8) 
         */
        .macro SWITCH_TO_USER flag
        subq $8*4,%rsp                   # reuse rip, cs, rflags, rsp, ss in the stack
        movq %rax,(%rsp)
        movq %r11,1*8(%rsp)
        movq %rcx,2*8(%rsp)              # we saved %rcx upon exceptions
        movq $\flag,3*8(%rsp)
        movq $__HYPERVISOR_switch_to_user,%rax
        syscall
        .endm

        .macro SWITCH_TO_KERNEL ssoff,adjust=0
	jc  1f
	orb  $1,\ssoff-\adjust+4(%rsp)
1:
        .endm

/*
 * A newly forked process directly context switches into this.
 */ 	
/* rdi:	prev */	
ENTRY(ret_from_fork)
	CFI_STARTPROC
	CFI_DEFAULT_STACK
	call schedule_tail
	GET_THREAD_INFO(%rcx)
	testl $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SECCOMP),threadinfo_flags(%rcx)
	jnz rff_trace
rff_action:	
	RESTORE_REST
	testl $3,CS-ARGOFFSET(%rsp)	# from kernel_thread?
	je   int_ret_from_sys_call
	testl $_TIF_IA32,threadinfo_flags(%rcx)
	jnz  int_ret_from_sys_call
	RESTORE_TOP_OF_STACK %rdi,ARGOFFSET
	jmp ret_from_sys_call
rff_trace:
	movq %rsp,%rdi
	call syscall_trace_leave
	GET_THREAD_INFO(%rcx)	
	jmp rff_action
	CFI_ENDPROC

/*
 * System call entry. Upto 6 arguments in registers are supported.
 *
 * SYSCALL does not save anything on the stack and does not change the
 * stack pointer.
 */
		
/*
 * Register setup:	
 * rax  system call number
 * rdi  arg0
 * rcx  return address for syscall/sysret, C arg3 
 * rsi  arg1
 * rdx  arg2	
 * r10  arg3 	(--> moved to rcx for C)
 * r8   arg4
 * r9   arg5
 * r11  eflags for syscall/sysret, temporary for C
 * r12-r15,rbp,rbx saved by C code, not touched. 		
 * 
 * Interrupts are off on entry.
 * Only called from user space.
 *
 * XXX	if we had a free scratch register we could save the RSP into the stack frame
 *      and report it properly in ps. Unfortunately we haven't.
 */ 			 		

ENTRY(system_call)
	CFI_STARTPROC
	SAVE_ARGS -8,0
	movq  %rax,ORIG_RAX-ARGOFFSET(%rsp) 
        XEN_UNBLOCK_EVENTS(%r11)        
	GET_THREAD_INFO(%rcx)
	testl $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SECCOMP),threadinfo_flags(%rcx)
	jnz tracesys
	cmpq $__NR_syscall_max,%rax
	ja badsys
	movq %r10,%rcx
	call *sys_call_table(,%rax,8)  # XXX:	 rip relative
	movq %rax,RAX-ARGOFFSET(%rsp)
/*
 * Syscall return path ending with SYSRET (fast path)
 * Has incomplete stack frame and undefined top of stack. 
 */		
	.globl ret_from_sys_call
ret_from_sys_call:
	movl $_TIF_ALLWORK_MASK,%edi
	/* edi:	flagmask */
sysret_check:		
	GET_THREAD_INFO(%rcx)
        XEN_BLOCK_EVENTS(%rsi)        
	movl threadinfo_flags(%rcx),%edx
	andl %edi,%edx
	jnz  sysret_careful 
        XEN_UNBLOCK_EVENTS(%rsi)                
	RESTORE_ARGS 0,8,0
        SWITCH_TO_USER VGCF_IN_SYSCALL

	/* Handle reschedules */
	/* edx:	work, edi: workmask */	
sysret_careful:
	bt $TIF_NEED_RESCHED,%edx
	jnc sysret_signal
        XEN_BLOCK_EVENTS(%rsi)        
	pushq %rdi
	call schedule
	popq  %rdi
	jmp sysret_check

	/* Handle a signal */ 
sysret_signal:
/*	sti */
        XEN_UNBLOCK_EVENTS(%rsi)        
	testl $(_TIF_SIGPENDING|_TIF_NOTIFY_RESUME|_TIF_SINGLESTEP),%edx
	jz    1f

	/* Really a signal */
	/* edx:	work flags (arg3) */
	leaq do_notify_resume(%rip),%rax
	leaq -ARGOFFSET(%rsp),%rdi # &pt_regs -> arg1
	xorl %esi,%esi # oldset -> arg2
	call ptregscall_common
1:	movl $_TIF_NEED_RESCHED,%edi
	jmp sysret_check
	
	/* Do syscall tracing */
tracesys:			 
	SAVE_REST
	movq $-ENOSYS,RAX(%rsp)
	FIXUP_TOP_OF_STACK %rdi
	movq %rsp,%rdi
	call syscall_trace_enter
	LOAD_ARGS ARGOFFSET  /* reload args from stack in case ptrace changed it */
	RESTORE_REST
	cmpq $__NR_syscall_max,%rax
	ja  1f
	movq %r10,%rcx	/* fixup for C */
	call *sys_call_table(,%rax,8)
	movq %rax,RAX-ARGOFFSET(%rsp)
1:	SAVE_REST
	movq %rsp,%rdi
	call syscall_trace_leave
	RESTORE_TOP_OF_STACK %rbx
	RESTORE_REST
	jmp ret_from_sys_call
		
badsys:
	movq $-ENOSYS,RAX-ARGOFFSET(%rsp)	
	jmp ret_from_sys_call

/* 
 * Syscall return path ending with IRET.
 * Has correct top of stack, but partial stack frame.
 */ 	
ENTRY(int_ret_from_sys_call)	
        XEN_BLOCK_EVENTS(%rsi)
	testb $3,CS-ARGOFFSET(%rsp)
        jnz 1f
        /* Need to set the proper %ss (not NULL) for ring 3 iretq */
        movl $__KERNEL_DS,SS-ARGOFFSET(%rsp)
        jmp retint_restore_args   # retrun from ring3 kernel
1:              
	movl $_TIF_ALLWORK_MASK,%edi
	/* edi:	mask to check */
int_with_check:
	GET_THREAD_INFO(%rcx)
	movl threadinfo_flags(%rcx),%edx
	andl %edi,%edx
	jnz   int_careful
	jmp   retint_restore_args

	/* Either reschedule or signal or syscall exit tracking needed. */
	/* First do a reschedule test. */
	/* edx:	work, edi: workmask */
int_careful:
	bt $TIF_NEED_RESCHED,%edx
	jnc  int_very_careful
/*	sti */
        XEN_UNBLOCK_EVENTS(%rsi)
	pushq %rdi
	call schedule
	popq %rdi
	cli
	jmp int_with_check

	/* handle signals and tracing -- both require a full stack frame */
int_very_careful:
/*	sti */
        XEN_UNBLOCK_EVENTS(%rsi)
	SAVE_REST
	/* Check for syscall exit trace */	
	testl $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP),%edx
	jz int_signal
	pushq %rdi
	leaq 8(%rsp),%rdi	# &ptregs -> arg1	
	call syscall_trace_leave
	popq %rdi
	andl $~(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP),%edi
	cli
	jmp int_restore_rest
	
int_signal:
	testl $(_TIF_NOTIFY_RESUME|_TIF_SIGPENDING|_TIF_SINGLESTEP),%edx
	jz 1f
	movq %rsp,%rdi		# &ptregs -> arg1
	xorl %esi,%esi		# oldset -> arg2
	call do_notify_resume
1:	movl $_TIF_NEED_RESCHED,%edi	
int_restore_rest:
	RESTORE_REST
	cli
	jmp int_with_check
	CFI_ENDPROC
		
/* 
 * Certain special system calls that need to save a complete full stack frame.
 */ 								
	
	.macro PTREGSCALL label,func,arg
	.globl \label
\label:
	leaq	\func(%rip),%rax
	leaq    -ARGOFFSET+8(%rsp),\arg /* 8 for return address */
	jmp	ptregscall_common
	.endm

	PTREGSCALL stub_clone, sys_clone, %r8
	PTREGSCALL stub_fork, sys_fork, %rdi
	PTREGSCALL stub_vfork, sys_vfork, %rdi
	PTREGSCALL stub_rt_sigsuspend, sys_rt_sigsuspend, %rdx
	PTREGSCALL stub_sigaltstack, sys_sigaltstack, %rdx
	PTREGSCALL stub_iopl, sys_iopl, %rsi

ENTRY(ptregscall_common)
	CFI_STARTPROC
	popq %r11
	CFI_ADJUST_CFA_OFFSET	-8
	SAVE_REST
	movq %r11, %r15
	FIXUP_TOP_OF_STACK %r11
	call *%rax
	RESTORE_TOP_OF_STACK %r11
	movq %r15, %r11
	RESTORE_REST
	pushq %r11
	CFI_ADJUST_CFA_OFFSET	8
	ret
	CFI_ENDPROC
	
ENTRY(stub_execve)
	CFI_STARTPROC
	popq %r11
	CFI_ADJUST_CFA_OFFSET	-8
	SAVE_REST
	movq %r11, %r15
	FIXUP_TOP_OF_STACK %r11
	call sys_execve
	GET_THREAD_INFO(%rcx)
	bt $TIF_IA32,threadinfo_flags(%rcx)
	jc exec_32bit
	RESTORE_TOP_OF_STACK %r11
	movq %r15, %r11
	RESTORE_REST
	push %r11
	ret

exec_32bit:
	CFI_ADJUST_CFA_OFFSET	REST_SKIP
	movq %rax,RAX(%rsp)
	RESTORE_REST
	jmp int_ret_from_sys_call
	CFI_ENDPROC
	
/*
 * sigreturn is special because it needs to restore all registers on return.
 * This cannot be done with SYSRET, so use the IRET return path instead.
 */                
ENTRY(stub_rt_sigreturn)
	CFI_STARTPROC
	addq $8, %rsp		
	SAVE_REST
	movq %rsp,%rdi
	FIXUP_TOP_OF_STACK %r11
	call sys_rt_sigreturn
	movq %rax,RAX(%rsp) # fixme, this could be done at the higher layer
	RESTORE_REST
	jmp int_ret_from_sys_call
	CFI_ENDPROC


/* 
 * Interrupt entry/exit.
 *
 * Interrupt entry points save only callee clobbered registers in fast path.
 *	
 * Entry runs with interrupts off.	
 */ 

/* 0(%rsp): interrupt number */ 
	.macro interrupt func
	CFI_STARTPROC	simple
	CFI_DEF_CFA	rsp,(SS-RDI)
	CFI_REL_OFFSET	rsp,(RSP-ORIG_RAX)
	CFI_REL_OFFSET	rip,(RIP-ORIG_RAX)
	cld
#ifdef CONFIG_DEBUG_INFO
	SAVE_ALL	
	movq %rsp,%rdi
	/*
	 * Setup a stack frame pointer.  This allows gdb to trace
	 * back to the original stack.
	 */
	movq %rsp,%rbp
	CFI_DEF_CFA_REGISTER	rbp
#else		
	SAVE_ARGS
	leaq -ARGOFFSET(%rsp),%rdi	# arg1 for handler
#endif	
#if 0 /* For Xen we don't need to do this */       
	testl $3,CS(%rdi)
	je 1f
	swapgs	
#endif        
1:	addl $1,%gs:pda_irqcount	# RED-PEN should check preempt count
	movq %gs:pda_irqstackptr,%rax
	cmoveq %rax,%rsp							
	pushq %rdi			# save old stack	
	call \func
	.endm

retint_check:			
	movl threadinfo_flags(%rcx),%edx
	andl %edi,%edx
	jnz  retint_careful
retint_restore_args:
        movb EVENT_MASK-REST_SKIP(%rsp), %al
        notb %al			# %al == ~saved_mask
        XEN_GET_VCPU_INFO(%rsi)
        andb evtchn_upcall_mask(%rsi),%al
	andb $1,%al			# %al == mask & ~saved_mask
	jnz restore_all_enable_events	# != 0 => reenable event delivery      
        XEN_PUT_VCPU_INFO(%rsi)
		
	RESTORE_ARGS 0,8,0						
	testb $3,8(%rsp)                # check CS
	jnz  user_mode
kernel_mode:
        orb   $3,1*8(%rsp)
	iretq
user_mode:
	SWITCH_TO_USER 0                        
	
	/* edi: workmask, edx: work */	
retint_careful:
	bt    $TIF_NEED_RESCHED,%edx
	jnc   retint_signal
	XEN_UNBLOCK_EVENTS(%rsi)
/*	sti */        
	pushq %rdi
	call  schedule
	popq %rdi		
	XEN_BLOCK_EVENTS(%rsi)		
	GET_THREAD_INFO(%rcx)
/*	cli */
	jmp retint_check
	
retint_signal:
	testl $(_TIF_SIGPENDING|_TIF_NOTIFY_RESUME|_TIF_SINGLESTEP),%edx
	jz    retint_restore_args
        XEN_UNBLOCK_EVENTS(%rsi)
	SAVE_REST
	movq $-1,ORIG_RAX(%rsp) 			
	xorq %rsi,%rsi		# oldset
	movq %rsp,%rdi		# &pt_regs
	call do_notify_resume
	RESTORE_REST
        XEN_BLOCK_EVENTS(%rsi)		
	movl $_TIF_NEED_RESCHED,%edi
	GET_THREAD_INFO(%rcx)
	jmp retint_check

#ifdef CONFIG_PREEMPT
	/* Returning to kernel space. Check if we need preemption */
	/* rcx:	 threadinfo. interrupts off. */
	.p2align
retint_kernel:	
	cmpl $0,threadinfo_preempt_count(%rcx)
	jnz  retint_restore_args
	bt  $TIF_NEED_RESCHED,threadinfo_flags(%rcx)
	jnc  retint_restore_args
	bt   $9,EFLAGS-ARGOFFSET(%rsp)	/* interrupts off? */
	jnc  retint_restore_args
	call preempt_schedule_irq
	jmp retint_kernel       /* check again */
#endif	
	CFI_ENDPROC
	
/*
 * APIC interrupts.
 */		
	.macro apicinterrupt num,func
	pushq $\num-256
	interrupt \func
	jmp error_entry
	CFI_ENDPROC
	.endm

#ifdef CONFIG_SMP	
ENTRY(reschedule_interrupt)
	apicinterrupt RESCHEDULE_VECTOR,smp_reschedule_interrupt

ENTRY(invalidate_interrupt)
	apicinterrupt INVALIDATE_TLB_VECTOR,smp_invalidate_interrupt

ENTRY(call_function_interrupt)
	apicinterrupt CALL_FUNCTION_VECTOR,smp_call_function_interrupt
#endif

#ifdef CONFIG_X86_LOCAL_APIC	
ENTRY(apic_timer_interrupt)
	apicinterrupt LOCAL_TIMER_VECTOR,smp_apic_timer_interrupt

ENTRY(error_interrupt)
	apicinterrupt ERROR_APIC_VECTOR,smp_error_interrupt

ENTRY(spurious_interrupt)
	apicinterrupt SPURIOUS_APIC_VECTOR,smp_spurious_interrupt
#endif
				
/*
 * Exception entry points.
 */ 		
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

#if 0
	/* error code is on the stack already */
	/* handle NMI like exceptions that can happen everywhere */
	.macro paranoidentry sym
        movq (%rsp),%rcx
        movq 8(%rsp),%r11
        addq $0x10,%rsp /* skip rcx and r11 */        
	SAVE_ALL
	cld
	movl $1,%ebx
	movl  $MSR_GS_BASE,%ecx
	rdmsr
	testl %edx,%edx
	js    1f
/*	swapgs */
	xorl  %ebx,%ebx
1:	movq %rsp,%rdi
	movq ORIG_RAX(%rsp),%rsi
	movq $-1,ORIG_RAX(%rsp)
	call \sym
	cli
	.endm
#endif
	
/*
 * Exception entry point. This expects an error code/orig_rax on the stack
 * and the exception handler in %rax.	
 */ 		  				
ENTRY(error_entry)
	CFI_STARTPROC	simple
	CFI_DEF_CFA	rsp,(SS-RDI)
	CFI_REL_OFFSET	rsp,(RSP-RDI)
	CFI_REL_OFFSET	rip,(RIP-RDI)
	/* rdi slot contains rax, oldrax contains error code */
	cld	
	subq  $14*8,%rsp
	CFI_ADJUST_CFA_OFFSET	(14*8)
	movq %rsi,13*8(%rsp)
	CFI_REL_OFFSET	rsi,RSI
	movq 14*8(%rsp),%rsi	/* load rax from rdi slot */
	movq %rdx,12*8(%rsp)
	CFI_REL_OFFSET	rdx,RDX
	movq %rcx,11*8(%rsp)
	CFI_REL_OFFSET	rcx,RCX
	movq %rsi,10*8(%rsp)	/* store rax */ 
	CFI_REL_OFFSET	rax,RAX
	movq %r8, 9*8(%rsp)
	CFI_REL_OFFSET	r8,R8
	movq %r9, 8*8(%rsp)
	CFI_REL_OFFSET	r9,R9
	movq %r10,7*8(%rsp)
	CFI_REL_OFFSET	r10,R10
	movq %r11,6*8(%rsp)
	CFI_REL_OFFSET	r11,R11
	movq %rbx,5*8(%rsp) 
	CFI_REL_OFFSET	rbx,RBX
	movq %rbp,4*8(%rsp) 
	CFI_REL_OFFSET	rbp,RBP
	movq %r12,3*8(%rsp) 
	CFI_REL_OFFSET	r12,R12
	movq %r13,2*8(%rsp) 
	CFI_REL_OFFSET	r13,R13
	movq %r14,1*8(%rsp) 
	CFI_REL_OFFSET	r14,R14
	movq %r15,(%rsp) 
	CFI_REL_OFFSET	r15,R15
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
error_exit:		
	RESTORE_REST
/*	cli */
	XEN_BLOCK_EVENTS(%rsi)		
	GET_THREAD_INFO(%rcx)	
	testb $3,CS-ARGOFFSET(%rsp)
	jz retint_kernel
	movl  threadinfo_flags(%rcx),%edx
	movl  $_TIF_WORK_MASK,%edi	
	andl  %edi,%edx
	jnz   retint_careful
	jmp   retint_restore_args

error_kernelspace:
         /*
         * We need to re-write the logic here because we don't do iretq to 
         * to return to user mode. It's still possible that we get trap/fault
         * in the kernel (when accessing buffers pointed to by system calls, 
         * for example).
         *
         */           
#if 0
	incl %ebx
       /* There are two places in the kernel that can potentially fault with
          usergs. Handle them here. The exception handlers after
	   iret run with kernel gs again, so don't set the user space flag.
	   B stepping K8s sometimes report an truncated RIP for IRET 
	   exceptions returning to compat mode. Check for these here too. */
	leaq iret_label(%rip),%rbp
	cmpq %rbp,RIP(%rsp) 
	je   error_swapgs
	movl %ebp,%ebp	/* zero extend */
	cmpq %rbp,RIP(%rsp) 
	je   error_swapgs
	cmpq $gs_change,RIP(%rsp)
        je   error_swapgs
	jmp  error_sti
#endif        
	
ENTRY(hypervisor_callback)
	zeroentry do_hypervisor_callback
        
/*
 * Copied from arch/xen/i386/kernel/entry.S
 */               
# A note on the "critical region" in our callback handler.
# We want to avoid stacking callback handlers due to events occurring
# during handling of the last event. To do this, we keep events disabled
# until we've done all processing. HOWEVER, we must enable events before
# popping the stack frame (can't be done atomically) and so it would still
# be possible to get enough handler activations to overflow the stack.
# Although unlikely, bugs of that kind are hard to track down, so we'd
# like to avoid the possibility.
# So, on entry to the handler we detect whether we interrupted an
# existing activation in its critical region -- if so, we pop the current
# activation and restart the handler using the previous one.
ENTRY(do_hypervisor_callback)   # do_hyperviosr_callback(struct *pt_regs)
# Since we don't modify %rdi, evtchn_do_upall(struct *pt_regs) will
# see the correct pointer to the pt_regs
        addq $8, %rsp            # we don't return, adjust the stack frame
11:	movb $0, EVENT_MASK(%rsp)         
	call evtchn_do_upcall
        jmp  error_exit

        ALIGN
restore_all_enable_events:  
	XEN_UNBLOCK_EVENTS(%rsi)        # %rsi is already set up...

scrit:	/**** START OF CRITICAL REGION ****/
	XEN_TEST_PENDING(%rsi)
	jnz  14f			# process more events if necessary...
	XEN_PUT_VCPU_INFO(%rsi)
        RESTORE_ARGS 0,8,0
        testb $3,8(%rsp)                # check CS
        jnz  crit_user_mode
        orb   $3,1*8(%rsp)
        iretq
crit_user_mode:
        SWITCH_TO_USER 0
        
14:	XEN_LOCKED_BLOCK_EVENTS(%rsi)
	XEN_PUT_VCPU_INFO(%rsi)
	SAVE_REST
        movq %rsp,%rdi                  # set the argument again
	jmp  11b
ecrit:  /**** END OF CRITICAL REGION ****/
# At this point, unlike on x86-32, we don't do the fixup to simplify the 
# code and the stack frame is more complex on x86-64.
# When the kernel is interrupted in the critical section, the kernel 
# will do IRET in that case, and everything will be restored at that point, 
# i.e. it just resumes from the next instruction interrupted with the same context. 
	
# Hypervisor uses this for application faults while it executes.
ENTRY(failsafe_callback)
	addq $0x10,%rsp /* skip rcx and r11 */	
1:	movl (%rsp),%ds
2:	movl 8(%rsp),%es
3:	movl 16(%rsp),%fs
4:	movl 24(%rsp),%gs
	addq $0x20,%rsp /* skip the above selectors */		
	SAVE_ALL
	jmp  error_exit
.section .fixup,"ax";	\
6:	movq $0,(%rsp);	\
	jmp 1b;		\
7:	movq $0,8(%rsp);	\
	jmp 2b;		\
8:	movq $0,16(%rsp);	\
	jmp 3b;		\
9:	movq $0,24(%rsp);	\
	jmp 4b;		\
.previous;		\
.section __ex_table,"a";\
	.align 16;	\
	.quad 1b,6b;	\
	.quad 2b,7b;	\
	.quad 3b,8b;	\
	.quad 4b,9b;	\
.previous
 
#if 0	      
        .section __ex_table,"a"
        .align 8
        .quad gs_change,bad_gs
        .previous
        .section .fixup,"ax"
	/* running with kernelgs */
bad_gs: 
/*	swapgs		*/	/* switch back to user gs */
	xorl %eax,%eax
        movl %eax,%gs
        jmp  2b
        .previous       
#endif
	
/*
 * Create a kernel thread.
 *
 * C extern interface:
 *	extern long kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
 *
 * asm input arguments:
 *	rdi: fn, rsi: arg, rdx: flags
 */
ENTRY(kernel_thread)
	CFI_STARTPROC
	FAKE_STACK_FRAME $child_rip
	SAVE_ALL

	# rdi: flags, rsi: usp, rdx: will be &pt_regs
	movq %rdx,%rdi
	orq  kernel_thread_flags(%rip),%rdi
	movq $-1, %rsi
	movq %rsp, %rdx

	xorl %r8d,%r8d
	xorl %r9d,%r9d
	
	# clone now
	call do_fork
	movq %rax,RAX(%rsp)
	xorl %edi,%edi

	/*
	 * It isn't worth to check for reschedule here,
	 * so internally to the x86_64 port you can rely on kernel_thread()
	 * not to reschedule the child before returning, this avoids the need
	 * of hacks for example to fork off the per-CPU idle tasks.
         * [Hopefully no generic code relies on the reschedule -AK]	
	 */
	RESTORE_ALL
	UNFAKE_STACK_FRAME
	ret
	CFI_ENDPROC

	
child_rip:
	/*
	 * Here we are in the child and the registers are set as they were
	 * at kernel_thread() invocation in the parent.
	 */
	movq %rdi, %rax
	movq %rsi, %rdi
	call *%rax
	# exit
	xorq %rdi, %rdi
	call do_exit

/*
 * execve(). This function needs to use IRET, not SYSRET, to set up all state properly.
 *
 * C extern interface:
 *	 extern long execve(char *name, char **argv, char **envp)
 *
 * asm input arguments:
 *	rdi: name, rsi: argv, rdx: envp
 *
 * We want to fallback into:
 *	extern long sys_execve(char *name, char **argv,char **envp, struct pt_regs regs)
 *
 * do_sys_execve asm fallback arguments:
 *	rdi: name, rsi: argv, rdx: envp, fake frame on the stack
 */
ENTRY(execve)
	CFI_STARTPROC
	FAKE_STACK_FRAME $0
	SAVE_ALL	
	call sys_execve
	movq %rax, RAX(%rsp)	
	RESTORE_REST
	testq %rax,%rax
	jne 1f
        jmp int_ret_from_sys_call
1:      RESTORE_ARGS
	UNFAKE_STACK_FRAME
	ret
	CFI_ENDPROC


 /*
 * Copy error_entry because of the different stack frame
 */                        
ENTRY(page_fault)
        movq (%rsp),%rcx
        movq 8(%rsp),%r11
        addq $0x10,%rsp         # now %rsp points to %cr2
        pushq %rax
        leaq do_page_fault(%rip),%rax
	cld	
	subq  $13*8,%rsp
	movq %rdx,12*8(%rsp)    # save %rdx
	movq 13*8(%rsp),%rdx	# load rax
	movq %rcx,11*8(%rsp)
	movq %rdx,10*8(%rsp)	# store rax
        movq %rsi,13*8(%rsp)    # now save %rsi
        movq 14*8(%rsp),%rdx    # load %cr2, 3rd argument
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
#if 0        
	cmpl $__KERNEL_CS,CS(%rsp)
	je  error_kernelspace
#endif
        /*
         * 1st and 2nd arguments are set by error_call_handler
         */
        jmp error_call_handler

ENTRY(coprocessor_error)
	zeroentry do_coprocessor_error

ENTRY(simd_coprocessor_error)
	zeroentry do_simd_coprocessor_error	

ENTRY(device_not_available)
	zeroentry math_state_restore

	/* runs on exception stack */
ENTRY(debug)
	CFI_STARTPROC
/*	pushq $0
	CFI_ADJUST_CFA_OFFSET 8	*/
	zeroentry do_debug
/*	jmp paranoid_exit */
	CFI_ENDPROC

#if 0
	/* runs on exception stack */	
ENTRY(nmi)
	CFI_STARTPROC
	pushq $-1
	CFI_ADJUST_CFA_OFFSET 8		
	paranoidentry do_nmi
	/*
 	 * "Paranoid" exit path from exception stack.
  	 * Paranoid because this is used by NMIs and cannot take
	 * any kernel state for granted.
	 * We don't do kernel preemption checks here, because only
	 * NMI should be common and it does not enable IRQs and
	 * cannot get reschedule ticks.
	 */
	/* ebx:	no swapgs flag */
paranoid_exit:
	testl %ebx,%ebx				/* swapgs needed? */
	jnz paranoid_restore
paranoid_swapgs:	
/*	swapgs */
paranoid_restore:	
	RESTORE_ALL 8
/*	iretq */
paranoid_userspace:	
	GET_THREAD_INFO(%rcx)
#	movl threadinfo_flags(%rcx),%edx
#	testl $_TIF_NEED_RESCHED,%edx
#	jnz paranoid_resched
#	testl $(_TIF_SIGPENDING|_TIF_NOTIFY_RESUME|_TIF_SINGLESTEP),%edx
#	jnz paranoid_signal
#	jmp paranoid_swapgs
#paranoid_resched:		
#/*	sti */
#	call schedule
#	jmp paranoid_exit
#paranoid_signal:		
	movl threadinfo_flags(%rcx),%ebx
	andl $_TIF_WORK_MASK,%ebx
	jz paranoid_swapgs
	movq %rsp,%rdi			/* &pt_regs */
	call sync_regs
	movq %rax,%rsp			/* switch stack for scheduling */
	testl $_TIF_NEED_RESCHED,%ebx
	jnz paranoid_schedule
	movl %ebx,%edx			/* arg3: thread flags */
/*	sti */
#	xorl %esi,%esi /* oldset */
#	movq %rsp,%rdi /* &pt_regs */
	xorl %esi,%esi 			/* arg2: oldset */
	movq %rsp,%rdi 			/* arg1: &pt_regs */
	call do_notify_resume
#	jmp paranoid_exit
	cli
	jmp paranoid_userspace
paranoid_schedule:
	sti
	call schedule
	cli
	jmp paranoid_userspace
	CFI_ENDPROC
#endif        

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

ENTRY(reserved)
	zeroentry do_reserved

#if 0
	/* runs on exception stack */
ENTRY(double_fault)
	CFI_STARTPROC
	paranoidentry do_double_fault
	jmp paranoid_exit
	CFI_ENDPROC
#endif

ENTRY(invalid_TSS)
	errorentry do_invalid_TSS

ENTRY(segment_not_present)
	errorentry do_segment_not_present

	/* runs on exception stack */
ENTRY(stack_segment)
	CFI_STARTPROC
	errorentry do_stack_segment
	CFI_ENDPROC

ENTRY(general_protection)
	errorentry do_general_protection

ENTRY(alignment_check)
	errorentry do_alignment_check

ENTRY(divide_error)
	zeroentry do_divide_error

ENTRY(spurious_interrupt_bug)
	zeroentry do_spurious_interrupt_bug

#ifdef CONFIG_X86_MCE
	/* runs on exception stack */
ENTRY(machine_check)
	CFI_STARTPROC
	pushq $0
	CFI_ADJUST_CFA_OFFSET 8	
	paranoidentry do_machine_check
	jmp paranoid_exit
	CFI_ENDPROC
#endif

ENTRY(call_debug)
       zeroentry do_call_debug


