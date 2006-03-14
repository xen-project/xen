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

#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/segment.h>
#include <asm/smp.h>
#include <asm/page.h>
#include <asm/desc.h>
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
EVENT_MASK	= 0x2E
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
#define preempt_stop		cli
#else
#define preempt_stop
#define resume_kernel		restore_nocheck
#endif

#define SAVE_ALL \
	cld; \
	pushl %es; \
	pushl %ds; \
	pushl %eax; \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx; \
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es;

#define RESTORE_INT_REGS \
	popl %ebx;	\
	popl %ecx;	\
	popl %edx;	\
	popl %esi;	\
	popl %edi;	\
	popl %ebp;	\
	popl %eax

#define RESTORE_REGS	\
	RESTORE_INT_REGS; \
1:	popl %ds;	\
2:	popl %es;	\
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


ENTRY(ret_from_fork)
	pushl %eax
	call schedule_tail
	GET_THREAD_INFO(%ebp)
	popl %eax
	jmp syscall_exit

/*
 * Return to user mode is not as complex as all this looks,
 * but we want the default path for a system call return to
 * go as quickly as possible which is why some of this is
 * less clear than it otherwise should be.
 */

	# userspace resumption stub bypassing syscall exit tracing
	ALIGN
ret_from_exception:
	preempt_stop
ret_from_intr:
	GET_THREAD_INFO(%ebp)
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

#ifdef CONFIG_X86_SYSENTER
/* SYSENTER_RETURN points to after the "sysenter" instruction in
   the vsyscall page.  See vsyscall-sysentry.S, which defines the symbol.  */

	# sysenter call handler stub
ENTRY(sysenter_entry)
	movl TSS_sysenter_esp0(%esp),%esp
sysenter_past_esp:
	sti
	pushl $(__USER_DS)
	pushl %ebp
	pushfl
	pushl $(__USER_CS)
	pushl $SYSENTER_RETURN

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
	SAVE_ALL
	GET_THREAD_INFO(%ebp)

	/* Note, _TIF_SECCOMP is bit number 8, and so it needs testw and not testb */
	testw $(_TIF_SYSCALL_EMU|_TIF_SYSCALL_TRACE|_TIF_SECCOMP|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
	call *sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)
	cli
	movl TI_flags(%ebp), %ecx
	testw $_TIF_ALLWORK_MASK, %cx
	jne syscall_exit_work
/* if something modifies registers it must also disable sysexit */
	movl EIP(%esp), %edx
	movl OLDESP(%esp), %ecx
	xorl %ebp,%ebp
	sti
	sysexit
#endif /* CONFIG_X86_SYSENTER */


	# system call handler stub
ENTRY(system_call)
	pushl %eax			# save orig_eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
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
	je ldt_ss			# returning to user-space with LDT SS
restore_nocheck:
#else
restore_nocheck:
	testl $(VM_MASK|NMI_MASK), EFLAGS(%esp)
	jnz hypervisor_iret
	movb EVENT_MASK(%esp), %al
	notb %al			# %al == ~saved_mask
	GET_VCPU_INFO
	andb evtchn_upcall_mask(%esi),%al
	andb $1,%al			# %al == mask & ~saved_mask
	jnz restore_all_enable_events	#     != 0 => reenable event delivery
#endif
	RESTORE_REGS
	addl $4, %esp
1:	iret
.section .fixup,"ax"
iret_exc:
#ifndef CONFIG_XEN
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
	cli
	movl %esp, %eax
	/* Set up the 16bit stack frame with switch32 pointer on top,
	 * and a switch16 pointer on top of the current frame. */
	call setup_x86_bogus_stack
	RESTORE_REGS
	lss 20+4(%esp), %esp	# switch to 16bit stack
1:	iret
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous
#else
hypervisor_iret:
	andl $~NMI_MASK, EFLAGS(%esp)
	RESTORE_REGS
	addl $4, %esp
	jmp  hypercall_page + (__HYPERVISOR_iret * 32)
#endif

	# perform work that needs to be done immediately before resumption
	ALIGN
work_pending:
	testb $_TIF_NEED_RESCHED, %cl
	jz work_notifysig
work_resched:
	call schedule
	DISABLE_INTERRUPTS		# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
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
	jmp resume_userspace

	ALIGN
work_notifysig_v86:
#ifdef CONFIG_VM86
	pushl %ecx			# save ti_flags for do_notify_resume
	call save_v86_state		# %eax contains pt_regs pointer
	popl %ecx
	movl %eax, %esp
	xorl %edx, %edx
	call do_notify_resume
	jmp resume_userspace
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
	ENABLE_INTERRUPTS		# could let do_syscall_trace() call
					# schedule() instead
	movl %esp, %eax
	movl $1, %edx
	call do_syscall_trace
	jmp resume_userspace

	ALIGN
syscall_fault:
	pushl %eax			# save orig_eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
	movl $-EFAULT,EAX(%esp)
	jmp resume_userspace

	ALIGN
syscall_badsys:
	movl $-ENOSYS,EAX(%esp)
	jmp resume_userspace

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
	movl %ss, %eax; \
	/* see if on 16bit stack */ \
	cmpw $__ESPFIX_SS, %ax; \
	jne 28f; \
	movl $__KERNEL_DS, %edx; \
	movl %edx, %ds; \
	movl %edx, %es; \
	/* switch to 32bit stack */ \
	FIXUP_ESPFIX_STACK \
28:	popl %eax;

/*
 * Build the entry stubs and pointer table with
 * some assembler magic.
 */
.data
ENTRY(interrupt)
.text

vector=0
ENTRY(irq_entries_start)
.rept NR_IRQS
	ALIGN
1:	pushl $vector-256
	jmp common_interrupt
.data
	.long 1b
.text
vector=vector+1
.endr

	ALIGN
common_interrupt:
	SAVE_ALL
	movl %esp,%eax
	call do_IRQ
	jmp ret_from_intr

#define BUILD_INTERRUPT(name, nr)	\
ENTRY(name)				\
	pushl $nr-256;			\
	SAVE_ALL			\
	movl %esp,%eax;			\
	call smp_/**/name;		\
	jmp ret_from_intr;

/* The include is where all of the SMP etc. interrupts come from */
#include "entry_arch.h"
#else
#define UNWIND_ESPFIX_STACK
#endif

ENTRY(divide_error)
	pushl $0			# no error code
	pushl $do_divide_error
	ALIGN
error_code:
	pushl %ds
	pushl %eax
	xorl %eax, %eax
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	decl %eax			# eax = -1
	pushl %ecx
	pushl %ebx
	cld
	pushl %es
	UNWIND_ESPFIX_STACK
	popl %ecx
	movl ES(%esp), %edi		# get the function address
	movl ORIG_EAX(%esp), %edx	# get the error code
	movl %eax, ORIG_EAX(%esp)
	movl %ecx, ES(%esp)
	movl $(__USER_DS), %ecx
	movl %ecx, %ds
	movl %ecx, %es
	movl %esp,%eax			# pt_regs pointer
	call *%edi
	jmp ret_from_exception

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
ENTRY(hypervisor_callback)
	pushl %eax
	SAVE_ALL
	movl EIP(%esp),%eax
	cmpl $scrit,%eax
	jb   11f
	cmpl $ecrit,%eax
	jb   critical_region_fixup
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
.section .fixup,"ax"
2:	pushl $0
	pushl $do_iret_error
	jmp error_code
.previous
.section __ex_table,"a"
	.align 4
	.long 1b,2b
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
ENTRY(failsafe_callback)
1:	popl %ds
2:	popl %es
3:	popl %fs
4:	popl %gs
	subl $4,%esp
	SAVE_ALL
	jmp  ret_from_exception
.section .fixup,"ax";	\
6:	movl $0,(%esp);	\
	jmp 1b;		\
7:	movl $0,(%esp);	\
	jmp 2b;		\
8:	movl $0,(%esp);	\
	jmp 3b;		\
9:	movl $0,(%esp);	\
	jmp 4b;		\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,6b;	\
	.long 2b,7b;	\
	.long 3b,8b;	\
	.long 4b,9b;	\
.previous
#endif

ENTRY(coprocessor_error)
	pushl $0
	pushl $do_coprocessor_error
	jmp error_code

ENTRY(simd_coprocessor_error)
	pushl $0
	pushl $do_simd_coprocessor_error
	jmp error_code

ENTRY(device_not_available)
	pushl $-1			# mark this as an int
	SAVE_ALL
#ifndef CONFIG_XEN
	movl %cr0, %eax
	testl $0x4, %eax		# EM (math emulation bit)
	je device_available_emulate
	pushl $0			# temporary storage for ORIG_EIP
	call math_emulate
	addl $4, %esp
	jmp ret_from_exception
device_available_emulate:
#endif
	preempt_stop
	call math_state_restore
	jmp ret_from_exception

#ifdef CONFIG_X86_SYSENTER
/*
 * Debug traps and NMI can happen at the one SYSENTER instruction
 * that sets up the real kernel stack. Check here, since we can't
 * allow the wrong stack to be used.
 *
 * "TSS_sysenter_esp0+12" is because the NMI/debug handler will have
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
	movl TSS_sysenter_esp0+offset(%esp),%esp;	\
	pushfl;					\
	pushl $__KERNEL_CS;			\
	pushl $sysenter_past_esp
#endif /* CONFIG_X86_SYSENTER */

KPROBE_ENTRY(debug)
#ifdef CONFIG_X86_SYSENTER
	cmpl $sysenter_entry,(%esp)
	jne debug_stack_correct
	FIX_STACK(12, debug_stack_correct, debug_esp_fix_insn)
debug_stack_correct:
#endif /* !CONFIG_X86_SYSENTER */
	pushl $-1			# mark this as an int
	SAVE_ALL
	xorl %edx,%edx			# error code 0
	movl %esp,%eax			# pt_regs pointer
	call do_debug
	jmp ret_from_exception
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
	pushl %eax
	movl %ss, %eax
	cmpw $__ESPFIX_SS, %ax
	popl %eax
	je nmi_16bit_stack
	cmpl $sysenter_entry,(%esp)
	je nmi_stack_fixup
	pushl %eax
	movl %esp,%eax
	/* Do not access memory above the end of our stack page,
	 * it might not exist.
	 */
	andl $(THREAD_SIZE-1),%eax
	cmpl $(THREAD_SIZE-20),%eax
	popl %eax
	jae nmi_stack_correct
	cmpl $sysenter_entry,12(%esp)
	je nmi_debug_stack_check
nmi_stack_correct:
	pushl %eax
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_nmi
	jmp restore_all

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
	/* create the pointer to lss back */
	pushl %ss
	pushl %esp
	movzwl %sp, %esp
	addw $4, (%esp)
	/* copy the iret frame of 12 bytes */
	.rept 3
	pushl 16(%esp)
	.endr
	pushl %eax
	SAVE_ALL
	FIXUP_ESPFIX_STACK		# %eax == %esp
	xorl %edx,%edx			# zero error code
	call do_nmi
	RESTORE_REGS
	lss 12+4(%esp), %esp		# back to 16bit stack
1:	iret
.section __ex_table,"a"
	.align 4
	.long 1b,iret_exc
.previous
#else
ENTRY(nmi)
	pushl %eax
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_nmi
	orl  $NMI_MASK, EFLAGS(%esp)
	jmp restore_all
#endif

KPROBE_ENTRY(int3)
	pushl $-1			# mark this as an int
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_int3
	jmp ret_from_exception
	.previous .text

ENTRY(overflow)
	pushl $0
	pushl $do_overflow
	jmp error_code

ENTRY(bounds)
	pushl $0
	pushl $do_bounds
	jmp error_code

ENTRY(invalid_op)
	pushl $0
	pushl $do_invalid_op
	jmp error_code

ENTRY(coprocessor_segment_overrun)
	pushl $0
	pushl $do_coprocessor_segment_overrun
	jmp error_code

ENTRY(invalid_TSS)
	pushl $do_invalid_TSS
	jmp error_code

ENTRY(segment_not_present)
	pushl $do_segment_not_present
	jmp error_code

ENTRY(stack_segment)
	pushl $do_stack_segment
	jmp error_code

KPROBE_ENTRY(general_protection)
	pushl $do_general_protection
	jmp error_code
	.previous .text

ENTRY(alignment_check)
	pushl $do_alignment_check
	jmp error_code

KPROBE_ENTRY(page_fault)
	pushl $do_page_fault
	jmp error_code
	.previous .text

#ifdef CONFIG_X86_MCE
ENTRY(machine_check)
	pushl $0
	pushl machine_check_vector
	jmp error_code
#endif

ENTRY(fixup_4gb_segment)
	pushl $do_fixup_4gb_segment
	jmp error_code

.section .rodata,"a"
#include "syscall_table.S"

syscall_table_size=(.-sys_call_table)
