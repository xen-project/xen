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
 * Stack layout in 'ret_to_user':
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
#include <linux/sys.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/smp.h>

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

/* Offsets into task_struct. */
state		=  0
flags		=  4
sigpending	=  8
addr_limit	= 12
exec_domain	= 16
need_resched	= 20
tsk_ptrace	= 24
processor	= 52

/* Offsets into shared_info_t. */
#define evtchn_upcall_pending /* 0 */
#define evtchn_upcall_mask       1

ENOSYS = 38


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
	movl $(__KERNEL_DS),%edx; \
	movl %edx,%ds; \
	movl %edx,%es;

#define RESTORE_ALL	\
	popl %ebx;	\
	popl %ecx;	\
	popl %edx;	\
	popl %esi;	\
	popl %edi;	\
	popl %ebp;	\
	popl %eax;	\
1:	popl %ds;	\
2:	popl %es;	\
	addl $4,%esp;	\
3:	iret;		\
.section .fixup,"ax";	\
4:	movl $0,(%esp);	\
	jmp 1b;		\
5:	movl $0,(%esp);	\
	jmp 2b;		\
6:	pushl %ss;	\
	popl %ds;	\
	pushl %ss;	\
	popl %es;	\
	pushl $11;	\
	call do_exit;	\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,4b;	\
	.long 2b,5b;	\
	.long 3b,6b;	\
.previous

#define GET_CURRENT(reg) \
	movl $-8192, reg; \
	andl %esp, reg

ENTRY(lcall7)
	pushfl			# We get a different stack layout with call
	pushl %eax		# gates, which has to be cleaned up later..
	SAVE_ALL
	movl EIP(%esp),%eax	# due to call gates, this is eflags, not eip..
	movl CS(%esp),%edx	# this is eip..
	movl EFLAGS(%esp),%ecx	# and this is cs..
	movl %eax,EFLAGS(%esp)	#
	andl $~(NT_MASK|TF_MASK|DF_MASK), %eax
	pushl %eax
	popfl
	movl %edx,EIP(%esp)	# Now we move them to their "normal" places
	movl %ecx,CS(%esp)	#
	movl %esp,%ebx
	pushl %ebx
	andl $-8192,%ebx	# GET_CURRENT
	movl exec_domain(%ebx),%edx	# Get the execution domain
	movl 4(%edx),%edx	# Get the lcall7 handler for the domain
	pushl $0x7
	call *%edx
	addl $4, %esp
	popl %eax
	jmp ret_to_user

ENTRY(lcall27)
	pushfl			# We get a different stack layout with call
	pushl %eax		# gates, which has to be cleaned up later..
	SAVE_ALL
	movl EIP(%esp),%eax	# due to call gates, this is eflags, not eip..
	movl CS(%esp),%edx	# this is eip..
	movl EFLAGS(%esp),%ecx	# and this is cs..
	movl %eax,EFLAGS(%esp)	#
	andl $~(NT_MASK|TF_MASK|DF_MASK), %eax
	pushl %eax
	popfl
	movl %edx,EIP(%esp)	# Now we move them to their "normal" places
	movl %ecx,CS(%esp)	#
	movl %esp,%ebx
	pushl %ebx
	andl $-8192,%ebx	# GET_CURRENT
	movl exec_domain(%ebx),%edx	# Get the execution domain
	movl 4(%edx),%edx	# Get the lcall7 handler for the domain
	pushl $0x27
	call *%edx
	addl $4, %esp
	popl %eax
	jmp ret_to_user

ENTRY(ret_from_fork)
	pushl %ebx
	call SYMBOL_NAME(schedule_tail)
	addl $4, %esp
	GET_CURRENT(%ebx)
	testb $0x02,tsk_ptrace(%ebx)	# PT_TRACESYS
	jne tracesys_exit
	jmp ret_to_user

/*
 * Return to user mode is not as complex as all this looks,
 * but we want the default path for a system call return to
 * go as quickly as possible which is why some of this is
 * less clear than it otherwise should be.
 */
ENTRY(system_call)
	pushl %eax			# save orig_eax
	SAVE_ALL
	GET_CURRENT(%ebx)
	testb $0x02,tsk_ptrace(%ebx)	# PT_TRACESYS
	jne tracesys
	cmpl $(NR_syscalls),%eax
	jae badsys
	call *SYMBOL_NAME(sys_call_table)(,%eax,4)
	movl %eax,EAX(%esp)		# save the return value
ret_to_user:
        movl SYMBOL_NAME(HYPERVISOR_shared_info),%esi
        movb $1,evtchn_upcall_mask(%esi) # make tests atomic
ret_to_user_nocli:
	cmpl $0,need_resched(%ebx)
	jne  reschedule
	cmpl $0,sigpending(%ebx)
	je   safesti                    # ensure need_resched updates are seen
/*signal_return:*/
	movb $0,evtchn_upcall_mask(%esi) # reenable event callbacks
	movl %esp,%eax
	xorl %edx,%edx
	call SYMBOL_NAME(do_signal)
	jmp  safesti

	ALIGN
restore_all:
	RESTORE_ALL

	ALIGN
tracesys:
	movl $-ENOSYS,EAX(%esp)
	call SYMBOL_NAME(syscall_trace)
	movl ORIG_EAX(%esp),%eax
	cmpl $(NR_syscalls),%eax
	jae tracesys_exit
	call *SYMBOL_NAME(sys_call_table)(,%eax,4)
	movl %eax,EAX(%esp)		# save the return value
tracesys_exit:
	call SYMBOL_NAME(syscall_trace)
	jmp ret_to_user
badsys:
	movl $-ENOSYS,EAX(%esp)
	jmp ret_to_user

	ALIGN
ENTRY(ret_from_intr)
	GET_CURRENT(%ebx)
ret_from_exception:
	movb CS(%esp),%al
	testl $2,%eax
	jne ret_to_user
	jmp restore_all

	ALIGN
reschedule:
        movb $0,evtchn_upcall_mask(%esi)  # reenable event callbacks
	call SYMBOL_NAME(schedule)        # test
	jmp  ret_to_user

ENTRY(divide_error)
	pushl $0		# no error code
	pushl $ SYMBOL_NAME(do_divide_error)
	ALIGN
error_code:
	pushl %ds
	pushl %eax
	xorl %eax,%eax
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	decl %eax			# eax = -1
	pushl %ecx
	pushl %ebx
	GET_CURRENT(%ebx)
	cld
	movl %es,%ecx
	movl ORIG_EAX(%esp), %esi	# get the error code
	movl ES(%esp), %edi		# get the function address
	movl %eax, ORIG_EAX(%esp)
	movl %ecx, ES(%esp)
	movl %esp,%edx
	pushl %esi			# push the error code
	pushl %edx			# push the pt_regs pointer
	movl $(__KERNEL_DS),%edx
	movl %edx,%ds
	movl %edx,%es
	call *%edi
	addl $8,%esp
	jmp ret_from_exception

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
        GET_CURRENT(%ebx)
        movl EIP(%esp),%eax
        cmpl $scrit,%eax
        jb   11f
        cmpl $ecrit,%eax
        jb   critical_region_fixup
11:     push %esp
        call evtchn_do_upcall
        add  $4,%esp
        movl SYMBOL_NAME(HYPERVISOR_shared_info),%esi
        movb CS(%esp),%cl
	test $2,%cl          # slow return to ring 2 or 3
	jne  ret_to_user_nocli
safesti:movb $0,evtchn_upcall_mask(%esi) # reenable event callbacks
scrit:  /**** START OF CRITICAL REGION ****/
        testb $0xFF,evtchn_upcall_pending(%esi)
        jnz  14f              # process more events if necessary...
        RESTORE_ALL
14:     movb $1,evtchn_upcall_mask(%esi)
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
        movzbl (%eax),%eax    # %eax contains num bytes popped
        mov  %esp,%esi
        add  %eax,%esi        # %esi points at end of src region
        mov  %esp,%edi
        add  $0x34,%edi       # %edi points at end of dst region
        mov  %eax,%ecx
        shr  $2,%ecx          # convert words to bytes
        je   16f              # skip loop if nothing to copy
15:     subl $4,%esi          # pre-decrementing copy loop
        subl $4,%edi
        movl (%esi),%eax
        movl %eax,(%edi)
        loop 15b
16:     movl %edi,%esp        # final %edi is top of merged stack
        jmp  11b
        
critical_fixup_table:        
        .byte 0x00,0x00,0x00                  # testb $0xFF,(%esi)
        .byte 0x00,0x00                       # jnz  14f
        .byte 0x00                            # pop  %ebx
        .byte 0x04                            # pop  %ecx
        .byte 0x08                            # pop  %edx
        .byte 0x0c                            # pop  %esi
        .byte 0x10                            # pop  %edi
        .byte 0x14                            # pop  %ebp
        .byte 0x18                            # pop  %eax
        .byte 0x1c                            # pop  %ds
        .byte 0x20                            # pop  %es
        .byte 0x24,0x24,0x24                  # add  $4,%esp
        .byte 0x28                            # iret
        .byte 0x00,0x00,0x00,0x00             # movb $1,4(%esi)
        .byte 0x00,0x00                       # jmp  11b

# Hypervisor uses this for application faults while it executes.
ENTRY(failsafe_callback)
1:      popl %ds
2:      popl %es
3:      popl %fs
4:      popl %gs
5:      iret
.section .fixup,"ax";	\
6:	movl $0,(%esp);	\
	jmp 1b;		\
7:	movl $0,(%esp);	\
	jmp 2b;		\
8:	movl $0,(%esp);	\
	jmp 3b;		\
9:	movl $0,(%esp);	\
	jmp 4b;		\
10:	pushl %ss;	\
	popl %ds;	\
	pushl %ss;	\
	popl %es;	\
	pushl $11;	\
	call do_exit;	\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,6b;	\
	.long 2b,7b;	\
	.long 3b,8b;	\
	.long 4b,9b;	\
	.long 5b,10b;	\
.previous
        
ENTRY(coprocessor_error)
	pushl $0
	pushl $ SYMBOL_NAME(do_coprocessor_error)
	jmp error_code

ENTRY(simd_coprocessor_error)
	pushl $0
	pushl $ SYMBOL_NAME(do_simd_coprocessor_error)
	jmp error_code

ENTRY(device_not_available)
	pushl $-1		# mark this as an int
	SAVE_ALL
	GET_CURRENT(%ebx)
	call SYMBOL_NAME(math_state_restore)
	jmp ret_from_exception

ENTRY(debug)
	pushl $0
	pushl $ SYMBOL_NAME(do_debug)
	jmp error_code

ENTRY(int3)
	pushl $0
	pushl $ SYMBOL_NAME(do_int3)
	jmp error_code

ENTRY(overflow)
	pushl $0
	pushl $ SYMBOL_NAME(do_overflow)
	jmp error_code

ENTRY(bounds)
	pushl $0
	pushl $ SYMBOL_NAME(do_bounds)
	jmp error_code

ENTRY(invalid_op)
	pushl $0
	pushl $ SYMBOL_NAME(do_invalid_op)
	jmp error_code

ENTRY(coprocessor_segment_overrun)
	pushl $0
	pushl $ SYMBOL_NAME(do_coprocessor_segment_overrun)
	jmp error_code

ENTRY(double_fault)
	pushl $ SYMBOL_NAME(do_double_fault)
	jmp error_code

ENTRY(invalid_TSS)
	pushl $ SYMBOL_NAME(do_invalid_TSS)
	jmp error_code

ENTRY(segment_not_present)
	pushl $ SYMBOL_NAME(do_segment_not_present)
	jmp error_code

ENTRY(stack_segment)
	pushl $ SYMBOL_NAME(do_stack_segment)
	jmp error_code

ENTRY(general_protection)
	pushl $ SYMBOL_NAME(do_general_protection)
	jmp error_code

ENTRY(alignment_check)
	pushl $ SYMBOL_NAME(do_alignment_check)
	jmp error_code

# This handler is special, because it gets an extra value on its stack,
# which is the linear faulting address.
#define PAGE_FAULT_STUB(_name1, _name2)                                  \
ENTRY(_name1)                                                            \
	pushl %ds                                                      ; \
	pushl %eax                                                     ; \
	xorl %eax,%eax                                                 ; \
	pushl %ebp                                                     ; \
	pushl %edi                                                     ; \
	pushl %esi                                                     ; \
	pushl %edx                                                     ; \
	decl %eax                      /* eax = -1 */                  ; \
	pushl %ecx                                                     ; \
	pushl %ebx                                                     ; \
	GET_CURRENT(%ebx)                                              ; \
	cld                                                            ; \
	movl %es,%ecx                                                  ; \
	movl ORIG_EAX(%esp), %esi      /* get the error code */        ; \
	movl ES(%esp), %edi            /* get the faulting address */  ; \
	movl %eax, ORIG_EAX(%esp)                                      ; \
	movl %ecx, ES(%esp)                                            ; \
	movl %esp,%edx                                                 ; \
        pushl %edi                     /* push the faulting address */ ; \
	pushl %esi                     /* push the error code */       ; \
	pushl %edx                     /* push the pt_regs pointer */  ; \
	movl $(__KERNEL_DS),%edx                                       ; \
	movl %edx,%ds                                                  ; \
	movl %edx,%es                                                  ; \
	call SYMBOL_NAME(_name2)                                       ; \
	addl $12,%esp                                                  ; \
	jmp ret_from_exception                                         ;
PAGE_FAULT_STUB(page_fault, do_page_fault)

ENTRY(machine_check)
	pushl $0
	pushl $ SYMBOL_NAME(do_machine_check)
	jmp error_code

ENTRY(fixup_4gb_segment)
	pushl $ SYMBOL_NAME(do_fixup_4gb_segment)
	jmp error_code

.data
ENTRY(sys_call_table)
	.long SYMBOL_NAME(sys_ni_syscall)	/* 0  -  old "setup()" system call*/
	.long SYMBOL_NAME(sys_exit)
	.long SYMBOL_NAME(sys_fork)
	.long SYMBOL_NAME(sys_read)
	.long SYMBOL_NAME(sys_write)
	.long SYMBOL_NAME(sys_open)		/* 5 */
	.long SYMBOL_NAME(sys_close)
	.long SYMBOL_NAME(sys_waitpid)
	.long SYMBOL_NAME(sys_creat)
	.long SYMBOL_NAME(sys_link)
	.long SYMBOL_NAME(sys_unlink)		/* 10 */
	.long SYMBOL_NAME(sys_execve)
	.long SYMBOL_NAME(sys_chdir)
	.long SYMBOL_NAME(sys_time)
	.long SYMBOL_NAME(sys_mknod)
	.long SYMBOL_NAME(sys_chmod)		/* 15 */
	.long SYMBOL_NAME(sys_lchown16)
	.long SYMBOL_NAME(sys_ni_syscall)				/* old break syscall holder */
	.long SYMBOL_NAME(sys_stat)
	.long SYMBOL_NAME(sys_lseek)
	.long SYMBOL_NAME(sys_getpid)		/* 20 */
	.long SYMBOL_NAME(sys_mount)
	.long SYMBOL_NAME(sys_oldumount)
	.long SYMBOL_NAME(sys_setuid16)
	.long SYMBOL_NAME(sys_getuid16)
	.long SYMBOL_NAME(sys_stime)		/* 25 */
	.long SYMBOL_NAME(sys_ptrace)
	.long SYMBOL_NAME(sys_alarm)
	.long SYMBOL_NAME(sys_fstat)
	.long SYMBOL_NAME(sys_pause)
	.long SYMBOL_NAME(sys_utime)		/* 30 */
	.long SYMBOL_NAME(sys_ni_syscall)				/* old stty syscall holder */
	.long SYMBOL_NAME(sys_ni_syscall)				/* old gtty syscall holder */
	.long SYMBOL_NAME(sys_access)
	.long SYMBOL_NAME(sys_nice)
	.long SYMBOL_NAME(sys_ni_syscall)	/* 35 */		/* old ftime syscall holder */
	.long SYMBOL_NAME(sys_sync)
	.long SYMBOL_NAME(sys_kill)
	.long SYMBOL_NAME(sys_rename)
	.long SYMBOL_NAME(sys_mkdir)
	.long SYMBOL_NAME(sys_rmdir)		/* 40 */
	.long SYMBOL_NAME(sys_dup)
	.long SYMBOL_NAME(sys_pipe)
	.long SYMBOL_NAME(sys_times)
	.long SYMBOL_NAME(sys_ni_syscall)				/* old prof syscall holder */
	.long SYMBOL_NAME(sys_brk)		/* 45 */
	.long SYMBOL_NAME(sys_setgid16)
	.long SYMBOL_NAME(sys_getgid16)
	.long SYMBOL_NAME(sys_signal)
	.long SYMBOL_NAME(sys_geteuid16)
	.long SYMBOL_NAME(sys_getegid16)	/* 50 */
	.long SYMBOL_NAME(sys_acct)
	.long SYMBOL_NAME(sys_umount)					/* recycled never used phys() */
	.long SYMBOL_NAME(sys_ni_syscall)				/* old lock syscall holder */
	.long SYMBOL_NAME(sys_ioctl)
	.long SYMBOL_NAME(sys_fcntl)		/* 55 */
	.long SYMBOL_NAME(sys_ni_syscall)				/* old mpx syscall holder */
	.long SYMBOL_NAME(sys_setpgid)
	.long SYMBOL_NAME(sys_ni_syscall)				/* old ulimit syscall holder */
	.long SYMBOL_NAME(sys_olduname)
	.long SYMBOL_NAME(sys_umask)		/* 60 */
	.long SYMBOL_NAME(sys_chroot)
	.long SYMBOL_NAME(sys_ustat)
	.long SYMBOL_NAME(sys_dup2)
	.long SYMBOL_NAME(sys_getppid)
	.long SYMBOL_NAME(sys_getpgrp)		/* 65 */
	.long SYMBOL_NAME(sys_setsid)
	.long SYMBOL_NAME(sys_sigaction)
	.long SYMBOL_NAME(sys_sgetmask)
	.long SYMBOL_NAME(sys_ssetmask)
	.long SYMBOL_NAME(sys_setreuid16)	/* 70 */
	.long SYMBOL_NAME(sys_setregid16)
	.long SYMBOL_NAME(sys_sigsuspend)
	.long SYMBOL_NAME(sys_sigpending)
	.long SYMBOL_NAME(sys_sethostname)
	.long SYMBOL_NAME(sys_setrlimit)	/* 75 */
	.long SYMBOL_NAME(sys_old_getrlimit)
	.long SYMBOL_NAME(sys_getrusage)
	.long SYMBOL_NAME(sys_gettimeofday)
	.long SYMBOL_NAME(sys_settimeofday)
	.long SYMBOL_NAME(sys_getgroups16)	/* 80 */
	.long SYMBOL_NAME(sys_setgroups16)
	.long SYMBOL_NAME(old_select)
	.long SYMBOL_NAME(sys_symlink)
	.long SYMBOL_NAME(sys_lstat)
	.long SYMBOL_NAME(sys_readlink)		/* 85 */
	.long SYMBOL_NAME(sys_uselib)
	.long SYMBOL_NAME(sys_swapon)
	.long SYMBOL_NAME(sys_reboot)
	.long SYMBOL_NAME(old_readdir)
	.long SYMBOL_NAME(old_mmap)		/* 90 */
	.long SYMBOL_NAME(sys_munmap)
	.long SYMBOL_NAME(sys_truncate)
	.long SYMBOL_NAME(sys_ftruncate)
	.long SYMBOL_NAME(sys_fchmod)
	.long SYMBOL_NAME(sys_fchown16)		/* 95 */
	.long SYMBOL_NAME(sys_getpriority)
	.long SYMBOL_NAME(sys_setpriority)
	.long SYMBOL_NAME(sys_ni_syscall)				/* old profil syscall holder */
	.long SYMBOL_NAME(sys_statfs)
	.long SYMBOL_NAME(sys_fstatfs)		/* 100 */
	.long SYMBOL_NAME(sys_ioperm)
	.long SYMBOL_NAME(sys_socketcall)
	.long SYMBOL_NAME(sys_syslog)
	.long SYMBOL_NAME(sys_setitimer)
	.long SYMBOL_NAME(sys_getitimer)	/* 105 */
	.long SYMBOL_NAME(sys_newstat)
	.long SYMBOL_NAME(sys_newlstat)
	.long SYMBOL_NAME(sys_newfstat)
	.long SYMBOL_NAME(sys_uname)
	.long SYMBOL_NAME(sys_iopl)		/* 110 */
	.long SYMBOL_NAME(sys_vhangup)
	.long SYMBOL_NAME(sys_ni_syscall)	/* old "idle" system call */
	.long SYMBOL_NAME(sys_ni_syscall) /* was VM86 */
	.long SYMBOL_NAME(sys_wait4)
	.long SYMBOL_NAME(sys_swapoff)		/* 115 */
	.long SYMBOL_NAME(sys_sysinfo)
	.long SYMBOL_NAME(sys_ipc)
	.long SYMBOL_NAME(sys_fsync)
	.long SYMBOL_NAME(sys_sigreturn)
	.long SYMBOL_NAME(sys_clone)		/* 120 */
	.long SYMBOL_NAME(sys_setdomainname)
	.long SYMBOL_NAME(sys_newuname)
	.long SYMBOL_NAME(sys_modify_ldt)
	.long SYMBOL_NAME(sys_adjtimex)
	.long SYMBOL_NAME(sys_mprotect)		/* 125 */
	.long SYMBOL_NAME(sys_sigprocmask)
	.long SYMBOL_NAME(sys_create_module)
	.long SYMBOL_NAME(sys_init_module)
	.long SYMBOL_NAME(sys_delete_module)
	.long SYMBOL_NAME(sys_get_kernel_syms)	/* 130 */
	.long SYMBOL_NAME(sys_quotactl)
	.long SYMBOL_NAME(sys_getpgid)
	.long SYMBOL_NAME(sys_fchdir)
	.long SYMBOL_NAME(sys_bdflush)
	.long SYMBOL_NAME(sys_sysfs)		/* 135 */
	.long SYMBOL_NAME(sys_personality)
	.long SYMBOL_NAME(sys_ni_syscall)	/* for afs_syscall */
	.long SYMBOL_NAME(sys_setfsuid16)
	.long SYMBOL_NAME(sys_setfsgid16)
	.long SYMBOL_NAME(sys_llseek)		/* 140 */
	.long SYMBOL_NAME(sys_getdents)
	.long SYMBOL_NAME(sys_select)
	.long SYMBOL_NAME(sys_flock)
	.long SYMBOL_NAME(sys_msync)
	.long SYMBOL_NAME(sys_readv)		/* 145 */
	.long SYMBOL_NAME(sys_writev)
	.long SYMBOL_NAME(sys_getsid)
	.long SYMBOL_NAME(sys_fdatasync)
	.long SYMBOL_NAME(sys_sysctl)
	.long SYMBOL_NAME(sys_mlock)		/* 150 */
	.long SYMBOL_NAME(sys_munlock)
	.long SYMBOL_NAME(sys_mlockall)
	.long SYMBOL_NAME(sys_munlockall)
	.long SYMBOL_NAME(sys_sched_setparam)
	.long SYMBOL_NAME(sys_sched_getparam)   /* 155 */
	.long SYMBOL_NAME(sys_sched_setscheduler)
	.long SYMBOL_NAME(sys_sched_getscheduler)
	.long SYMBOL_NAME(sys_sched_yield)
	.long SYMBOL_NAME(sys_sched_get_priority_max)
	.long SYMBOL_NAME(sys_sched_get_priority_min)  /* 160 */
	.long SYMBOL_NAME(sys_sched_rr_get_interval)
	.long SYMBOL_NAME(sys_nanosleep)
	.long SYMBOL_NAME(sys_mremap)
	.long SYMBOL_NAME(sys_setresuid16)
	.long SYMBOL_NAME(sys_getresuid16)	/* 165 */
	.long SYMBOL_NAME(sys_ni_syscall) /* was VM86 */
	.long SYMBOL_NAME(sys_query_module)
	.long SYMBOL_NAME(sys_poll)
	.long SYMBOL_NAME(sys_nfsservctl)
	.long SYMBOL_NAME(sys_setresgid16)	/* 170 */
	.long SYMBOL_NAME(sys_getresgid16)
	.long SYMBOL_NAME(sys_prctl)
	.long SYMBOL_NAME(sys_rt_sigreturn)
	.long SYMBOL_NAME(sys_rt_sigaction)
	.long SYMBOL_NAME(sys_rt_sigprocmask)	/* 175 */
	.long SYMBOL_NAME(sys_rt_sigpending)
	.long SYMBOL_NAME(sys_rt_sigtimedwait)
	.long SYMBOL_NAME(sys_rt_sigqueueinfo)
	.long SYMBOL_NAME(sys_rt_sigsuspend)
	.long SYMBOL_NAME(sys_pread)		/* 180 */
	.long SYMBOL_NAME(sys_pwrite)
	.long SYMBOL_NAME(sys_chown16)
	.long SYMBOL_NAME(sys_getcwd)
	.long SYMBOL_NAME(sys_capget)
	.long SYMBOL_NAME(sys_capset)           /* 185 */
	.long SYMBOL_NAME(sys_sigaltstack)
	.long SYMBOL_NAME(sys_sendfile)
	.long SYMBOL_NAME(sys_ni_syscall)		/* streams1 */
	.long SYMBOL_NAME(sys_ni_syscall)		/* streams2 */
	.long SYMBOL_NAME(sys_vfork)            /* 190 */
	.long SYMBOL_NAME(sys_getrlimit)
	.long SYMBOL_NAME(sys_mmap2)
	.long SYMBOL_NAME(sys_truncate64)
	.long SYMBOL_NAME(sys_ftruncate64)
	.long SYMBOL_NAME(sys_stat64)		/* 195 */
	.long SYMBOL_NAME(sys_lstat64)
	.long SYMBOL_NAME(sys_fstat64)
	.long SYMBOL_NAME(sys_lchown)
	.long SYMBOL_NAME(sys_getuid)
	.long SYMBOL_NAME(sys_getgid)		/* 200 */
	.long SYMBOL_NAME(sys_geteuid)
	.long SYMBOL_NAME(sys_getegid)
	.long SYMBOL_NAME(sys_setreuid)
	.long SYMBOL_NAME(sys_setregid)
	.long SYMBOL_NAME(sys_getgroups)	/* 205 */
	.long SYMBOL_NAME(sys_setgroups)
	.long SYMBOL_NAME(sys_fchown)
	.long SYMBOL_NAME(sys_setresuid)
	.long SYMBOL_NAME(sys_getresuid)
	.long SYMBOL_NAME(sys_setresgid)	/* 210 */
	.long SYMBOL_NAME(sys_getresgid)
	.long SYMBOL_NAME(sys_chown)
	.long SYMBOL_NAME(sys_setuid)
	.long SYMBOL_NAME(sys_setgid)
	.long SYMBOL_NAME(sys_setfsuid)		/* 215 */
	.long SYMBOL_NAME(sys_setfsgid)
	.long SYMBOL_NAME(sys_pivot_root)
	.long SYMBOL_NAME(sys_mincore)
	.long SYMBOL_NAME(sys_madvise)
	.long SYMBOL_NAME(sys_getdents64)	/* 220 */
	.long SYMBOL_NAME(sys_fcntl64)
	.long SYMBOL_NAME(sys_ni_syscall)	/* reserved for TUX */
	.long SYMBOL_NAME(sys_ni_syscall)	/* Reserved for Security */
	.long SYMBOL_NAME(sys_gettid)
	.long SYMBOL_NAME(sys_readahead)	/* 225 */
	.long SYMBOL_NAME(sys_setxattr)
	.long SYMBOL_NAME(sys_lsetxattr)
	.long SYMBOL_NAME(sys_fsetxattr)
	.long SYMBOL_NAME(sys_getxattr)
	.long SYMBOL_NAME(sys_lgetxattr)	/* 230 */
	.long SYMBOL_NAME(sys_fgetxattr)
	.long SYMBOL_NAME(sys_listxattr)
	.long SYMBOL_NAME(sys_llistxattr)
	.long SYMBOL_NAME(sys_flistxattr)
	.long SYMBOL_NAME(sys_removexattr)	/* 235 */
	.long SYMBOL_NAME(sys_lremovexattr)
	.long SYMBOL_NAME(sys_fremovexattr)
 	.long SYMBOL_NAME(sys_tkill)
	.long SYMBOL_NAME(sys_sendfile64)
	.long SYMBOL_NAME(sys_ni_syscall)	/* 240 reserved for futex */
	.long SYMBOL_NAME(sys_ni_syscall)	/* reserved for sched_setaffinity */
	.long SYMBOL_NAME(sys_ni_syscall)	/* reserved for sched_getaffinity */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_set_thread_area */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_get_thread_area */
	.long SYMBOL_NAME(sys_ni_syscall)	/* 245 sys_io_setup */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_io_destroy */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_io_getevents */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_io_submit */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_io_cancel */
	.long SYMBOL_NAME(sys_ni_syscall)	/* 250 sys_alloc_hugepages */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_free_hugepages */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_exit_group */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_lookup_dcookie */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_epoll_create */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_epoll_ctl 255 */
	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_epoll_wait */
 	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_remap_file_pages */
 	.long SYMBOL_NAME(sys_ni_syscall)	/* sys_set_tid_address */

	.rept NR_syscalls-(.-sys_call_table)/4
		.long SYMBOL_NAME(sys_ni_syscall)
	.endr
