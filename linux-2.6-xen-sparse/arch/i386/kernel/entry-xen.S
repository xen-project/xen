/*
 *  linux/arch/i386/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 *
 * I changed all the .align's to 4 (16 byte alignment), as that's faster
 * on a 486.
 *
 * Stack layout in 'ret_from_system_call':
 * 	ptrace needs to have all regs on the stack.
 *	if the order here is changed, it needs to be
 *	updated in fork.c:copy_process, signal.c:do_signal,
 *	ptrace.c and ptrace.h
 *
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *	24(%esp) - orig_eax
 *	28(%esp) - %eip
 *	2C(%esp) - %cs
 *	30(%esp) - %eflags
 *	34(%esp) - %oldesp
 *	38(%esp) - %oldss
 *
 * "current" is in register %ebx during any slow entries.
 */

#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/irqflags.h>
#include <asm/errno.h>
#include <asm/segment.h>
#include <asm/smp.h>
#include <asm/page.h>
#include <asm/desc.h>
#include <asm/dwarf2.h>
#include "irq_vectors.h"
#include <xen/interface/xen.h>

#define nr_syscalls ((syscall_table_size)/4)

EBX		= 0x00
ECX		= 0x04
EDX		= 0x08
ESI		= 0x0C
EDI		= 0x10
EBP		= 0x14
EAX		= 0x18
DS		= 0x1C
ES		= 0x20
ORIG_EAX	= 0x24
EIP		= 0x28
CS		= 0x2C
EFLAGS		= 0x30
OLDESP		= 0x34
OLDSS		= 0x38

CF_MASK		= 0x00000001
TF_MASK		= 0x00000100
IF_MASK		= 0x00000200
DF_MASK		= 0x00000400 
NT_MASK		= 0x00004000
VM_MASK		= 0x00020000
/* Pseudo-eflags. */
NMI_MASK	= 0x80000000

#ifndef CONFIG_XEN
#define DISABLE_INTERRUPTS	cli
#define ENABLE_INTERRUPTS	sti
#else
/* Offsets into shared_info_t. */
#define evtchn_upcall_pending		/* 0 */
#define evtchn_upcall_mask		1

#define sizeof_vcpu_shift		6

#ifdef CONFIG_SMP
#define GET_VCPU_INFO		movl TI_cpu(%ebp),%esi			; \
				shl  $sizeof_vcpu_shift,%esi		; \
				addl HYPERVISOR_shared_info,%esi
#else
#define GET_VCPU_INFO		movl HYPERVISOR_shared_info,%esi
#endif

#define __DISABLE_INTERRUPTS	movb $1,evtchn_upcall_mask(%esi)
#define __ENABLE_INTERRUPTS	movb $0,evtchn_upcall_mask(%esi)
#define DISABLE_INTERRUPTS	GET_VCPU_INFO				; \
				__DISABLE_INTERRUPTS
#define ENABLE_INTERRUPTS	GET_VCPU_INFO				; \
				__ENABLE_INTERRUPTS
#define __TEST_PENDING		testb $0xFF,evtchn_upcall_pending(%esi)
#endif

#ifdef CONFIG_PREEMPT
#define preempt_stop		cli; TRACE_IRQS_OFF
#else
#define preempt_stop
#define resume_kernel		restore_nocheck
#endif

.macro TRACE_IRQS_IRET
#ifdef CONFIG_TRACE_IRQFLAGS
	testl $IF_MASK,EFLAGS(%esp)     # interrupts off?
	jz 1f
	TRACE_IRQS_ON
1:
#endif
.endm

#ifdef CONFIG_VM86
#define resume_userspace_sig	check_userspace
#else
#define resume_userspace_sig	resume_userspace
#endif

#define SAVE_ALL \
	cld; \
	pushl %es; \
	CFI_ADJUST_CFA_OFFSET 4;\
	/*CFI_REL_OFFSET es, 0;*/\
	pushl %ds; \
	CFI_ADJUST_CFA_OFFSET 4;\
	/*CFI_REL_OFFSET ds, 0;*/\
	pushl %eax; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET eax, 0;\
	pushl %ebp; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ebp, 0;\
	pushl %edi; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET edi, 0;\
	pushl %esi; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET esi, 0;\
	pushl %edx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET edx, 0;\
	pushl %ecx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ecx, 0;\
	pushl %ebx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ebx, 0;\
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es;

#define RESTORE_INT_REGS \
	popl %ebx;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE ebx;\
	popl %ecx;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE ecx;\
	popl %edx;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE edx;\
	popl %esi;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE esi;\
	popl %edi;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE edi;\
	popl %ebp;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE ebp;\
	popl %eax;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	CFI_RESTORE eax

#define RESTORE_REGS	\
	RESTORE_INT_REGS; \
1:	popl %ds;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	/*CFI_RESTORE ds;*/\
2:	popl %es;	\
	CFI_ADJUST_CFA_OFFSET -4;\
	/*CFI_RESTORE es;*/\
.section .fixup,"ax";	\
3:	movl $0,(%esp);	\
	jmp 1b;		\
4:	movl $0,(%esp);	\
	jmp 2b;		\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,3b;	\
	.long 2b,4b;	\
.previous

#define RING0_INT_FRAME \
	CFI_STARTPROC simple;\
	CFI_DEF_CFA esp, 3*4;\
	/*CFI_OFFSET cs, -2*4;*/\
	CFI_OFFSET eip, -3*4

#define RING0_EC_FRAME \
	CFI_STARTPROC simple;\
	CFI_DEF_CFA esp, 4*4;\
	/*CFI_OFFSET cs, -2*4;*/\
	CFI_OFFSET eip, -3*4

#define RING0_PTREGS_FRAME \
	CFI_STARTPROC simple;\
	CFI_DEF_CFA esp, OLDESP-EBX;\
	/*CFI_OFFSET cs, CS-OLDESP;*/\
	CFI_OFFSET eip, EIP-OLDESP;\
	/*CFI_OFFSET es, ES-OLDESP;*/\
	/*CFI_OFFSET ds, DS-OLDESP;*/\
	CFI_OFFSET eax, EAX-OLDESP;\
	CFI_OFFSET ebp, EBP-OLDESP;\
	CFI_OFFSET edi, EDI-OLDESP;\
	CFI_OFFSET esi, ESI-OLDESP;\
	CFI_OFFSET edx, EDX-OLDESP;\
	CFI_OFFSET ecx, ECX-OLDESP;\
	CFI_OFFSET ebx, EBX-OLDESP

ENTRY(ret_from_fork)
	CFI_STARTPROC
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	call schedule_tail
	GET_THREAD_INFO(%ebp)
	popl %eax
	CFI_ADJUST_CFA_OFFSET -4
	pushl $0x0202			# Reset kernel eflags
	CFI_ADJUST_CFA_OFFSET 4
	popfl
	CFI_ADJUST_CFA_OFFSET -4
	jmp syscall_exit
	CFI_ENDPROC

/*
 * Return to user mode is not as complex as all this looks,
 * but we want the default path for a system call return to
 * go as quickly as possible which is why some of this is
 * less clear than it otherwise should be.
 */

	# userspace resumption stub bypassing syscall exit tracing
	ALIGN
	RING0_PTREGS_FRAME
ret_from_exception:
	preempt_stop
ret_from_intr:
	GET_THREAD_INFO(%ebp)
check_userspace:
	movl EFLAGS(%esp), %eax		# mix EFLAGS and CS
	movb CS(%esp), %al
	testl $(VM_MASK | 2), %eax
	jz resume_kernel
ENTRY(resume_userspace)
	DISABLE_INTERRUPTS		# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done on
					# int/exception return?
	jne work_pending
	jmp restore_all

#ifdef CONFIG_PREEMPT
ENTRY(resume_kernel)
	cli
	cmpl $0,TI_preempt_count(%ebp)	# non-zero preempt_count ?
	jnz restore_nocheck
need_resched:
	movl TI_flags(%ebp), %ecx	# need_resched set ?
	testb $_TIF_NEED_RESCHED, %cl
	jz restore_all
	testl $IF_MASK,EFLAGS(%esp)     # interrupts off (exception path) ?
	jz restore_all
	call preempt_schedule_irq
	jmp need_resched
#endif
	CFI_ENDPROC

/* SYSENTER_RETURN points to after the "sysenter" instruction in
   the vsyscall page.  See vsyscall-sysentry.S, which defines the symbol.  */

	# sysenter call handler stub
ENTRY(sysenter_entry)
	CFI_STARTPROC simple
	CFI_DEF_CFA esp, 0
	CFI_REGISTER esp, ebp
	movl SYSENTER_stack_esp0(%esp),%esp
sysenter_past_esp:
	/*
	 * No need to follow this irqs on/off section: the syscall
	 * disabled irqs and here we enable it straight after entry:
	 */
	sti
	pushl $(__USER_DS)
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET ss, 0*/
	pushl %ebp
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET esp, 0
	pushfl
	CFI_ADJUST_CFA_OFFSET 4
	pushl $(__USER_CS)
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET cs, 0*/
	/*
	 * Push current_thread_info()->sysenter_return to the stack.
	 * A tiny bit of offset fixup is necessary - 4*4 means the 4 words
	 * pushed above; +8 corresponds to copy_thread's esp0 setting.
	 */
	pushl (TI_sysenter_return-THREAD_SIZE+8+4*4)(%esp)
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET eip, 0

/*
 * Load the potential sixth argument from user stack.
 * Careful about security.
 */
	cmpl $__PAGE_OFFSET-3,%ebp
	jae syscall_fault
1:	movl (%ebp),%ebp
.section __ex_table,"a"
	.align 4
	.long 1b,syscall_fault
.previous

	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	GET_THREAD_INFO(%ebp)

	/* Note, _TIF_SECCOMP is bit number 8, and so it needs testw and not testb */
	testw $(_TIF_SYSCALL_EMU|_TIF_SYSCALL_TRACE|_TIF_SECCOMP|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
	call *sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)
	DISABLE_INTERRUPTS
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	testw $_TIF_ALLWORK_MASK, %cx
	jne syscall_exit_work
/* if something modifies registers it must also disable sysexit */
	movl EIP(%esp), %edx
	movl OLDESP(%esp), %ecx
	xorl %ebp,%ebp
#ifdef CONFIG_XEN
	TRACE_IRQS_ON
	__ENABLE_INTERRUPTS
sysexit_scrit:	/**** START OF SYSEXIT CRITICAL REGION ****/
	__TEST_PENDING
	jnz  14f			# process more events if necessary...
	movl ESI(%esp), %esi
	sysexit
14:	__DISABLE_INTERRUPTS
sysexit_ecrit:	/**** END OF SYSEXIT CRITICAL REGION ****/
	push %esp
	call evtchn_do_upcall
	add  $4,%esp
	jmp  ret_from_intr
#else
	TRACE_IRQS_ON
	sti
	sysexit
#endif /* !CONFIG_XEN */
	CFI_ENDPROC


	# system call handler stub
ENTRY(system_call)
	RING0_INT_FRAME			# can't unwind into user space anyway
	pushl %eax			# save orig_eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
	testl $TF_MASK,EFLAGS(%esp)
	jz no_singlestep
	orl $_TIF_SINGLESTEP,TI_flags(%ebp)
no_singlestep:
					# system call tracing in operation / emulation
	/* Note, _TIF_SECCOMP is bit number 8, and so it needs testw and not testb */
	testw $(_TIF_SYSCALL_EMU|_TIF_SYSCALL_TRACE|_TIF_SECCOMP|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
syscall_call:
	call *sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)		# store the return value
syscall_exit:
	DISABLE_INTERRUPTS		# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	testw $_TIF_ALLWORK_MASK, %cx	# current->work
	jne syscall_exit_work

restore_all:
#ifndef CONFIG_XEN
	movl EFLAGS(%esp), %eax		# mix EFLAGS, SS and CS
	# Warning: OLDSS(%esp) contains the wrong/random values if we
	# are returning to the kernel.
	# See comments in process.c:copy_thread() for details.
	movb OLDSS(%esp), %ah
	movb CS(%esp), %al
	andl $(VM_MASK | (4 << 8) | 3), %eax
	cmpl $((4 << 8) | 3), %eax
	CFI_REMEMBER_STATE
	je ldt_ss			# returning to user-space with LDT SS
restore_nocheck:
#else
restore_nocheck:
	movl EFLAGS(%esp), %eax
	testl $(VM_MASK|NMI_MASK), %eax
	jnz hypervisor_iret
	shr $9, %eax			# EAX[0] == IRET_EFLAGS.IF
	GET_VCPU_INFO
	andb evtchn_upcall_mask(%esi),%al
	andb $1,%al			# EAX[0] == IRET_EFLAGS.IF & event_mask
	jnz restore_all_enable_events	#        != 0 => enable event delivery
#endif
	TRACE_IRQS_IRET
restore_nocheck_notrace:
	RESTORE_REGS
	addl $4, %esp
	CFI_ADJUST_CFA_OFFSET -4
1:	iret
.section .fixup,"ax"
iret_exc:
#ifndef CONFIG_XEN
	TRACE_IRQS_ON
	sti
#endif
	pushl $0			# no error code
	pushl $do_iret_error
	jmp error_code
.previous
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous

#ifndef CONFIG_XEN
	CFI_RESTORE_STATE
ldt_ss:
	larl OLDSS(%esp), %eax
	jnz restore_nocheck
	testl $0x00400000, %eax		# returning to 32bit stack?
	jnz restore_nocheck		# allright, normal return
	/* If returning to userspace with 16bit stack,
	 * try to fix the higher word of ESP, as the CPU
	 * won't restore it.
	 * This is an "official" bug of all the x86-compatible
	 * CPUs, which we can try to work around to make
	 * dosemu and wine happy. */
	subl $8, %esp		# reserve space for switch16 pointer
	CFI_ADJUST_CFA_OFFSET 8
	cli
	TRACE_IRQS_OFF
	movl %esp, %eax
	/* Set up the 16bit stack frame with switch32 pointer on top,
	 * and a switch16 pointer on top of the current frame. */
	call setup_x86_bogus_stack
	CFI_ADJUST_CFA_OFFSET -8	# frame has moved
	TRACE_IRQS_IRET
	RESTORE_REGS
	lss 20+4(%esp), %esp	# switch to 16bit stack
1:	iret
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous
	CFI_ENDPROC
#else
hypervisor_iret:
	andl $~NMI_MASK, EFLAGS(%esp)
	RESTORE_REGS
	addl $4, %esp
	jmp  hypercall_page + (__HYPERVISOR_iret * 32)
#endif

	# perform work that needs to be done immediately before resumption
	ALIGN
	RING0_PTREGS_FRAME		# can't unwind into user space anyway
work_pending:
	testb $_TIF_NEED_RESCHED, %cl
	jz work_notifysig
work_resched:
	call schedule
	DISABLE_INTERRUPTS		# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done other
					# than syscall tracing?
	jz restore_all
	testb $_TIF_NEED_RESCHED, %cl
	jnz work_resched

work_notifysig:				# deal with pending signals and
					# notify-resume requests
	testl $VM_MASK, EFLAGS(%esp)
	movl %esp, %eax
	jne work_notifysig_v86		# returning to kernel-space or
					# vm86-space
	xorl %edx, %edx
	call do_notify_resume
	jmp resume_userspace_sig

	ALIGN
work_notifysig_v86:
#ifdef CONFIG_VM86
	pushl %ecx			# save ti_flags for do_notify_resume
	CFI_ADJUST_CFA_OFFSET 4
	call save_v86_state		# %eax contains pt_regs pointer
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	movl %eax, %esp
	xorl %edx, %edx
	call do_notify_resume
	jmp resume_userspace_sig
#endif

	# perform syscall exit tracing
	ALIGN
syscall_trace_entry:
	movl $-ENOSYS,EAX(%esp)
	movl %esp, %eax
	xorl %edx,%edx
	call do_syscall_trace
	cmpl $0, %eax
	jne resume_userspace		# ret != 0 -> running under PTRACE_SYSEMU,
					# so must skip actual syscall
	movl ORIG_EAX(%esp), %eax
	cmpl $(nr_syscalls), %eax
	jnae syscall_call
	jmp syscall_exit

	# perform syscall exit tracing
	ALIGN
syscall_exit_work:
	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP), %cl
	jz work_pending
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS		# could let do_syscall_trace() call
					# schedule() instead
	movl %esp, %eax
	movl $1, %edx
	call do_syscall_trace
	jmp resume_userspace
	CFI_ENDPROC

	RING0_INT_FRAME			# can't unwind into user space anyway
syscall_fault:
	pushl %eax			# save orig_eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
	movl $-EFAULT,EAX(%esp)
	jmp resume_userspace

syscall_badsys:
	movl $-ENOSYS,EAX(%esp)
	jmp resume_userspace
	CFI_ENDPROC

#ifndef CONFIG_XEN
#define FIXUP_ESPFIX_STACK \
	movl %esp, %eax; \
	/* switch to 32bit stack using the pointer on top of 16bit stack */ \
	lss %ss:CPU_16BIT_STACK_SIZE-8, %esp; \
	/* copy data from 16bit stack to 32bit stack */ \
	call fixup_x86_bogus_stack; \
	/* put ESP to the proper location */ \
	movl %eax, %esp;
#define UNWIND_ESPFIX_STACK \
	pushl %eax; \
	CFI_ADJUST_CFA_OFFSET 4; \
	movl %ss, %eax; \
	/* see if on 16bit stack */ \
	cmpw $__ESPFIX_SS, %ax; \
	je 28f; \
27:	popl %eax; \
	CFI_ADJUST_CFA_OFFSET -4; \
.section .fixup,"ax"; \
28:	movl $__KERNEL_DS, %eax; \
	movl %eax, %ds; \
	movl %eax, %es; \
	/* switch to 32bit stack */ \
	FIXUP_ESPFIX_STACK; \
	jmp 27b; \
.previous

/*
 * Build the entry stubs and pointer table with
 * some assembler magic.
 */
.data
ENTRY(interrupt)
.text

vector=0
ENTRY(irq_entries_start)
	RING0_INT_FRAME
.rept NR_IRQS
	ALIGN
 .if vector
	CFI_ADJUST_CFA_OFFSET -4
 .endif
1:	pushl $~(vector)
	CFI_ADJUST_CFA_OFFSET 4
	jmp common_interrupt
.data
	.long 1b
.text
vector=vector+1
.endr

/*
 * the CPU automatically disables interrupts when executing an IRQ vector,
 * so IRQ-flags tracing has to follow that:
 */
	ALIGN
common_interrupt:
	SAVE_ALL
	TRACE_IRQS_OFF
	movl %esp,%eax
	call do_IRQ
	jmp ret_from_intr
	CFI_ENDPROC

#define BUILD_INTERRUPT(name, nr)	\
ENTRY(name)				\
	RING0_INT_FRAME;		\
	pushl $~(nr);			\
	CFI_ADJUST_CFA_OFFSET 4;	\
	SAVE_ALL;			\
	TRACE_IRQS_OFF			\
	movl %esp,%eax;			\
	call smp_/**/name;		\
	jmp ret_from_intr;		\
	CFI_ENDPROC

/* The include is where all of the SMP etc. interrupts come from */
#include "entry_arch.h"
#else
#define UNWIND_ESPFIX_STACK
#endif

ENTRY(divide_error)
	RING0_INT_FRAME
	pushl $0			# no error code
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_divide_error
	CFI_ADJUST_CFA_OFFSET 4
	ALIGN
error_code:
	pushl %ds
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET ds, 0*/
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET eax, 0
	xorl %eax, %eax
	pushl %ebp
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ebp, 0
	pushl %edi
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edi, 0
	pushl %esi
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET esi, 0
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edx, 0
	decl %eax			# eax = -1
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx, 0
	pushl %ebx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ebx, 0
	cld
	pushl %es
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET es, 0*/
	UNWIND_ESPFIX_STACK
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	/*CFI_REGISTER es, ecx*/
	movl ES(%esp), %edi		# get the function address
	movl ORIG_EAX(%esp), %edx	# get the error code
	movl %eax, ORIG_EAX(%esp)
	movl %ecx, ES(%esp)
	/*CFI_REL_OFFSET es, ES*/
	movl $(__USER_DS), %ecx
	movl %ecx, %ds
	movl %ecx, %es
	movl %esp,%eax			# pt_regs pointer
	call *%edi
	jmp ret_from_exception
	CFI_ENDPROC

#ifdef CONFIG_XEN
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
#
# The sysexit critical region is slightly different. sysexit
# atomically removes the entire stack frame. If we interrupt in the
# critical region we know that the entire frame is present and correct
# so we can simply throw away the new one.
ENTRY(hypervisor_callback)
	pushl %eax
	SAVE_ALL
	movl EIP(%esp),%eax
	cmpl $scrit,%eax
	jb   11f
	cmpl $ecrit,%eax
	jb   critical_region_fixup
	cmpl $sysexit_scrit,%eax
	jb   11f
	cmpl $sysexit_ecrit,%eax
	ja   11f
	addl $0x34,%esp			# Remove cs...ebx from stack frame.
11:	push %esp
	call evtchn_do_upcall
	add  $4,%esp
	jmp  ret_from_intr

        ALIGN
restore_all_enable_events:
	__ENABLE_INTERRUPTS
scrit:	/**** START OF CRITICAL REGION ****/
	__TEST_PENDING
	jnz  14f			# process more events if necessary...
	RESTORE_REGS
	addl $4, %esp
1:	iret
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous
14:	__DISABLE_INTERRUPTS
	jmp  11b
ecrit:  /**** END OF CRITICAL REGION ****/
# [How we do the fixup]. We want to merge the current stack frame with the
# just-interrupted frame. How we do this depends on where in the critical
# region the interrupted handler was executing, and so how many saved
# registers are in each frame. We do this quickly using the lookup table
# 'critical_fixup_table'. For each byte offset in the critical region, it
# provides the number of bytes which have already been popped from the
# interrupted stack frame.
critical_region_fixup:
	addl $critical_fixup_table-scrit,%eax
	movzbl (%eax),%eax		# %eax contains num bytes popped
	cmpb $0xff,%al                  # 0xff => vcpu_info critical region
	jne  15f
	GET_THREAD_INFO(%ebp)
        xorl %eax,%eax
15:	mov  %esp,%esi
	add  %eax,%esi			# %esi points at end of src region
	mov  %esp,%edi
	add  $0x34,%edi			# %edi points at end of dst region
	mov  %eax,%ecx
	shr  $2,%ecx			# convert words to bytes
	je   17f			# skip loop if nothing to copy
16:	subl $4,%esi			# pre-decrementing copy loop
	subl $4,%edi
	movl (%esi),%eax
	movl %eax,(%edi)
	loop 16b
17:	movl %edi,%esp			# final %edi is top of merged stack
	jmp  11b

critical_fixup_table:
	.byte 0xff,0xff,0xff		# testb $0xff,(%esi) = __TEST_PENDING
	.byte 0xff,0xff			# jnz  14f
	.byte 0x00			# pop  %ebx
	.byte 0x04			# pop  %ecx
	.byte 0x08			# pop  %edx
	.byte 0x0c			# pop  %esi
	.byte 0x10			# pop  %edi
	.byte 0x14			# pop  %ebp
	.byte 0x18			# pop  %eax
	.byte 0x1c			# pop  %ds
	.byte 0x20			# pop  %es
	.byte 0x24,0x24,0x24		# add  $4,%esp
	.byte 0x28			# iret
	.byte 0xff,0xff,0xff,0xff	# movb $1,1(%esi)
	.byte 0x00,0x00			# jmp  11b

# Hypervisor uses this for application faults while it executes.
# We get here for two reasons:
#  1. Fault while reloading DS, ES, FS or GS
#  2. Fault while executing IRET
# Category 1 we fix up by reattempting the load, and zeroing the segment
# register if the load fails.
# Category 2 we fix up by jumping to do_iret_error. We cannot use the
# normal Linux return path in this case because if we use the IRET hypercall
# to pop the stack frame we end up in an infinite loop of failsafe callbacks.
# We distinguish between categories by maintaining a status value in EAX.
ENTRY(failsafe_callback)
	pushl %eax
	movl $1,%eax
1:	mov 4(%esp),%ds
2:	mov 8(%esp),%es
3:	mov 12(%esp),%fs
4:	mov 16(%esp),%gs
	testl %eax,%eax
	popl %eax
	jz 5f
	addl $16,%esp		# EAX != 0 => Category 2 (Bad IRET)
	jmp iret_exc
5:	addl $16,%esp		# EAX == 0 => Category 1 (Bad segment)
	pushl $0
	SAVE_ALL
	jmp ret_from_exception
.section .fixup,"ax";		\
6:	xorl %eax,%eax;		\
	movl %eax,4(%esp);	\
	jmp 1b;			\
7:	xorl %eax,%eax;		\
	movl %eax,8(%esp);	\
	jmp 2b;			\
8:	xorl %eax,%eax;		\
	movl %eax,12(%esp);	\
	jmp 3b;			\
9:	xorl %eax,%eax;		\
	movl %eax,16(%esp);	\
	jmp 4b;			\
.previous;			\
.section __ex_table,"a";	\
	.align 4;		\
	.long 1b,6b;		\
	.long 2b,7b;		\
	.long 3b,8b;		\
	.long 4b,9b;		\
.previous
#endif

ENTRY(coprocessor_error)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_coprocessor_error
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(simd_coprocessor_error)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_simd_coprocessor_error
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(device_not_available)
	RING0_INT_FRAME
	pushl $-1			# mark this as an int
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
#ifndef CONFIG_XEN
	movl %cr0, %eax
	testl $0x4, %eax		# EM (math emulation bit)
	je device_available_emulate
	pushl $0			# temporary storage for ORIG_EIP
	CFI_ADJUST_CFA_OFFSET 4
	call math_emulate
	addl $4, %esp
	CFI_ADJUST_CFA_OFFSET -4
	jmp ret_from_exception
device_available_emulate:
#endif
	preempt_stop
	call math_state_restore
	jmp ret_from_exception
	CFI_ENDPROC

#ifndef CONFIG_XEN
/*
 * Debug traps and NMI can happen at the one SYSENTER instruction
 * that sets up the real kernel stack. Check here, since we can't
 * allow the wrong stack to be used.
 *
 * "SYSENTER_stack_esp0+12" is because the NMI/debug handler will have
 * already pushed 3 words if it hits on the sysenter instruction:
 * eflags, cs and eip.
 *
 * We just load the right stack, and push the three (known) values
 * by hand onto the new stack - while updating the return eip past
 * the instruction that would have done it for sysenter.
 */
#define FIX_STACK(offset, ok, label)		\
	cmpw $__KERNEL_CS,4(%esp);		\
	jne ok;					\
label:						\
	movl SYSENTER_stack_esp0+offset(%esp),%esp;	\
	pushfl;					\
	pushl $__KERNEL_CS;			\
	pushl $sysenter_past_esp
#endif /* CONFIG_XEN */

KPROBE_ENTRY(debug)
	RING0_INT_FRAME
#ifndef CONFIG_XEN
	cmpl $sysenter_entry,(%esp)
	jne debug_stack_correct
	FIX_STACK(12, debug_stack_correct, debug_esp_fix_insn)
debug_stack_correct:
#endif /* !CONFIG_XEN */
	pushl $-1			# mark this as an int
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	xorl %edx,%edx			# error code 0
	movl %esp,%eax			# pt_regs pointer
	call do_debug
	jmp ret_from_exception
	CFI_ENDPROC
	.previous .text
#ifndef CONFIG_XEN
/*
 * NMI is doubly nasty. It can happen _while_ we're handling
 * a debug fault, and the debug fault hasn't yet been able to
 * clear up the stack. So we first check whether we got  an
 * NMI on the sysenter entry path, but after that we need to
 * check whether we got an NMI on the debug path where the debug
 * fault happened on the sysenter path.
 */
ENTRY(nmi)
	RING0_INT_FRAME
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	movl %ss, %eax
	cmpw $__ESPFIX_SS, %ax
	popl %eax
	CFI_ADJUST_CFA_OFFSET -4
	je nmi_16bit_stack
	cmpl $sysenter_entry,(%esp)
	je nmi_stack_fixup
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	movl %esp,%eax
	/* Do not access memory above the end of our stack page,
	 * it might not exist.
	 */
	andl $(THREAD_SIZE-1),%eax
	cmpl $(THREAD_SIZE-20),%eax
	popl %eax
	CFI_ADJUST_CFA_OFFSET -4
	jae nmi_stack_correct
	cmpl $sysenter_entry,12(%esp)
	je nmi_debug_stack_check
nmi_stack_correct:
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_nmi
	jmp restore_nocheck_notrace
	CFI_ENDPROC

nmi_stack_fixup:
	FIX_STACK(12,nmi_stack_correct, 1)
	jmp nmi_stack_correct
nmi_debug_stack_check:
	cmpw $__KERNEL_CS,16(%esp)
	jne nmi_stack_correct
	cmpl $debug,(%esp)
	jb nmi_stack_correct
	cmpl $debug_esp_fix_insn,(%esp)
	ja nmi_stack_correct
	FIX_STACK(24,nmi_stack_correct, 1)
	jmp nmi_stack_correct

nmi_16bit_stack:
	RING0_INT_FRAME
	/* create the pointer to lss back */
	pushl %ss
	CFI_ADJUST_CFA_OFFSET 4
	pushl %esp
	CFI_ADJUST_CFA_OFFSET 4
	movzwl %sp, %esp
	addw $4, (%esp)
	/* copy the iret frame of 12 bytes */
	.rept 3
	pushl 16(%esp)
	CFI_ADJUST_CFA_OFFSET 4
	.endr
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	FIXUP_ESPFIX_STACK		# %eax == %esp
	CFI_ADJUST_CFA_OFFSET -20	# the frame has now moved
	xorl %edx,%edx			# zero error code
	call do_nmi
	RESTORE_REGS
	lss 12+4(%esp), %esp		# back to 16bit stack
1:	iret
	CFI_ENDPROC
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous
#else
ENTRY(nmi)
	RING0_INT_FRAME
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_nmi
	orl  $NMI_MASK, EFLAGS(%esp)
	jmp restore_all
	CFI_ENDPROC
#endif

KPROBE_ENTRY(int3)
	RING0_INT_FRAME
	pushl $-1			# mark this as an int
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_int3
	jmp ret_from_exception
	CFI_ENDPROC
	.previous .text

ENTRY(overflow)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_overflow
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(bounds)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_bounds
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(invalid_op)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_invalid_op
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(coprocessor_segment_overrun)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_coprocessor_segment_overrun
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(invalid_TSS)
	RING0_EC_FRAME
	pushl $do_invalid_TSS
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(segment_not_present)
	RING0_EC_FRAME
	pushl $do_segment_not_present
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

ENTRY(stack_segment)
	RING0_EC_FRAME
	pushl $do_stack_segment
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

KPROBE_ENTRY(general_protection)
	RING0_EC_FRAME
	pushl $do_general_protection
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC
	.previous .text

ENTRY(alignment_check)
	RING0_EC_FRAME
	pushl $do_alignment_check
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC

KPROBE_ENTRY(page_fault)
	RING0_EC_FRAME
	pushl $do_page_fault
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC
	.previous .text

#ifdef CONFIG_X86_MCE
ENTRY(machine_check)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl machine_check_vector
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC
#endif

#ifndef CONFIG_XEN
ENTRY(spurious_interrupt_bug)
	RING0_INT_FRAME
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
	pushl $do_spurious_interrupt_bug
	CFI_ADJUST_CFA_OFFSET 4
	jmp error_code
	CFI_ENDPROC
#endif /* !CONFIG_XEN */

#ifdef CONFIG_STACK_UNWIND
ENTRY(arch_unwind_init_running)
	CFI_STARTPROC
	movl	4(%esp), %edx
	movl	(%esp), %ecx
	leal	4(%esp), %eax
	movl	%ebx, EBX(%edx)
	xorl	%ebx, %ebx
	movl	%ebx, ECX(%edx)
	movl	%ebx, EDX(%edx)
	movl	%esi, ESI(%edx)
	movl	%edi, EDI(%edx)
	movl	%ebp, EBP(%edx)
	movl	%ebx, EAX(%edx)
	movl	$__USER_DS, DS(%edx)
	movl	$__USER_DS, ES(%edx)
	movl	%ebx, ORIG_EAX(%edx)
	movl	%ecx, EIP(%edx)
	movl	12(%esp), %ecx
	movl	$__KERNEL_CS, CS(%edx)
	movl	%ebx, EFLAGS(%edx)
	movl	%eax, OLDESP(%edx)
	movl	8(%esp), %eax
	movl	%ecx, 8(%esp)
	movl	EBX(%edx), %ebx
	movl	$__KERNEL_DS, OLDSS(%edx)
	jmpl	*%eax
	CFI_ENDPROC
ENDPROC(arch_unwind_init_running)
#endif

ENTRY(fixup_4gb_segment)
	pushl $do_fixup_4gb_segment
	jmp error_code

.section .rodata,"a"
#include "syscall_table.S"

syscall_table_size=(.-sys_call_table)
