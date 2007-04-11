/*
 * ia64/xen/entry.S
 *
 * Alternate kernel routines for Xen.  Heavily leveraged from
 *   ia64/kernel/entry.S
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@.hp.com>
 */

#include <asm/asmmacro.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/kregs.h>
#include <asm/asm-offsets.h>
#include <asm/pgtable.h>
#include <asm/percpu.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>

#ifdef CONFIG_XEN
#include "xenminstate.h"
#else
#include "minstate.h"
#endif

/*
 * prev_task <- ia64_switch_to(struct task_struct *next)
 *	With Ingo's new scheduler, interrupts are disabled when this routine gets
 *	called.  The code starting at .map relies on this.  The rest of the code
 *	doesn't care about the interrupt masking status.
 */
#ifdef CONFIG_XEN
GLOBAL_ENTRY(xen_switch_to)
	.prologue
	alloc r16=ar.pfs,1,0,0,0
	movl r22=running_on_xen;;
	ld4 r22=[r22];;
	cmp.eq p7,p0=r22,r0
(p7)	br.cond.sptk.many __ia64_switch_to;;
#else
GLOBAL_ENTRY(ia64_switch_to)
	.prologue
	alloc r16=ar.pfs,1,0,0,0
#endif
	DO_SAVE_SWITCH_STACK
	.body

	adds r22=IA64_TASK_THREAD_KSP_OFFSET,r13
	movl r25=init_task
	mov r27=IA64_KR(CURRENT_STACK)
	adds r21=IA64_TASK_THREAD_KSP_OFFSET,in0
	dep r20=0,in0,61,3		// physical address of "next"
	;;
	st8 [r22]=sp			// save kernel stack pointer of old task
	shr.u r26=r20,IA64_GRANULE_SHIFT
	cmp.eq p7,p6=r25,in0
	;;
	/*
	 * If we've already mapped this task's page, we can skip doing it again.
	 */
(p6)	cmp.eq p7,p6=r26,r27
(p6)	br.cond.dpnt .map
	;;
.done:
	ld8 sp=[r21]			// load kernel stack pointer of new task
#ifdef CONFIG_XEN
	// update "current" application register
	mov r8=IA64_KR_CURRENT
	mov r9=in0;;
	XEN_HYPER_SET_KR
#else
	mov IA64_KR(CURRENT)=in0	// update "current" application register
#endif
	mov r8=r13			// return pointer to previously running task
	mov r13=in0			// set "current" pointer
	;;
	DO_LOAD_SWITCH_STACK

#ifdef CONFIG_SMP
	sync.i				// ensure "fc"s done by this CPU are visible on other CPUs
#endif
	br.ret.sptk.many rp		// boogie on out in new context

.map:
#ifdef CONFIG_XEN
    movl r25=XSI_PSR_IC			// clear psr.ic
    ;;
    st4 [r25]=r0
    ;;
#else
	rsm psr.ic			// interrupts (psr.i) are already disabled here
#endif
	movl r25=PAGE_KERNEL
	;;
	srlz.d
	or r23=r25,r20			// construct PA | page properties
	mov r25=IA64_GRANULE_SHIFT<<2
	;;
#ifdef CONFIG_XEN
	movl r8=XSI_ITIR
	;;
	st8 [r8]=r25
	;;
	movl r8=XSI_IFA
	;;
	st8 [r8]=in0			 // VA of next task...
	;;
	mov r25=IA64_TR_CURRENT_STACK
	// remember last page we mapped...
	mov r8=IA64_KR_CURRENT_STACK
	mov r9=r26;;
	XEN_HYPER_SET_KR;;
#else
	mov cr.itir=r25
	mov cr.ifa=in0			// VA of next task...
	;;
	mov r25=IA64_TR_CURRENT_STACK
	mov IA64_KR(CURRENT_STACK)=r26	// remember last page we mapped...
#endif
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
#ifdef CONFIG_XEN
	;;
	srlz.d
	mov r9=1
	movl r8=XSI_PSR_IC
	;;
	st4 [r8]=r9
	;;
#else    
	ssm psr.ic			// reenable the psr.ic bit
	;;
	srlz.d
#endif
	br.cond.sptk .done
#ifdef CONFIG_XEN
END(xen_switch_to)
#else
END(ia64_switch_to)
#endif

	/*
	 * Invoke a system call, but do some tracing before and after the call.
	 * We MUST preserve the current register frame throughout this routine
	 * because some system calls (such as ia64_execve) directly
	 * manipulate ar.pfs.
	 */
#ifdef CONFIG_XEN
GLOBAL_ENTRY(xen_trace_syscall)
	PT_REGS_UNWIND_INFO(0)
	movl r16=running_on_xen;;
	ld4 r16=[r16];;
	cmp.eq p7,p0=r16,r0
(p7)	br.cond.sptk.many __ia64_trace_syscall;;
#else
GLOBAL_ENTRY(ia64_trace_syscall)
	PT_REGS_UNWIND_INFO(0)
#endif
	/*
	 * We need to preserve the scratch registers f6-f11 in case the system
	 * call is sigreturn.
	 */
	adds r16=PT(F6)+16,sp
	adds r17=PT(F7)+16,sp
	;;
 	stf.spill [r16]=f6,32
 	stf.spill [r17]=f7,32
	;;
 	stf.spill [r16]=f8,32
 	stf.spill [r17]=f9,32
	;;
 	stf.spill [r16]=f10
 	stf.spill [r17]=f11
	br.call.sptk.many rp=syscall_trace_enter // give parent a chance to catch syscall args
	adds r16=PT(F6)+16,sp
	adds r17=PT(F7)+16,sp
	;;
	ldf.fill f6=[r16],32
	ldf.fill f7=[r17],32
	;;
	ldf.fill f8=[r16],32
	ldf.fill f9=[r17],32
	;;
	ldf.fill f10=[r16]
	ldf.fill f11=[r17]
	// the syscall number may have changed, so re-load it and re-calculate the
	// syscall entry-point:
	adds r15=PT(R15)+16,sp			// r15 = &pt_regs.r15 (syscall #)
	;;
	ld8 r15=[r15]
	mov r3=NR_syscalls - 1
	;;
	adds r15=-1024,r15
	movl r16=sys_call_table
	;;
	shladd r20=r15,3,r16			// r20 = sys_call_table + 8*(syscall-1024)
	cmp.leu p6,p7=r15,r3
	;;
(p6)	ld8 r20=[r20]				// load address of syscall entry point
(p7)	movl r20=sys_ni_syscall
	;;
	mov b6=r20
	br.call.sptk.many rp=b6			// do the syscall
.strace_check_retval:
	cmp.lt p6,p0=r8,r0			// syscall failed?
	adds r2=PT(R8)+16,sp			// r2 = &pt_regs.r8
	adds r3=PT(R10)+16,sp			// r3 = &pt_regs.r10
	mov r10=0
(p6)	br.cond.sptk strace_error		// syscall failed ->
	;;					// avoid RAW on r10
.strace_save_retval:
.mem.offset 0,0; st8.spill [r2]=r8		// store return value in slot for r8
.mem.offset 8,0; st8.spill [r3]=r10		// clear error indication in slot for r10
	br.call.sptk.many rp=syscall_trace_leave // give parent a chance to catch return value
.ret3:
(pUStk)	cmp.eq.unc p6,p0=r0,r0			// p6 <- pUStk
	br.cond.sptk .work_pending_syscall_end

strace_error:
	ld8 r3=[r2]				// load pt_regs.r8
	sub r9=0,r8				// negate return value to get errno value
	;;
	cmp.ne p6,p0=r3,r0			// is pt_regs.r8!=0?
	adds r3=16,r2				// r3=&pt_regs.r10
	;;
(p6)	mov r10=-1
(p6)	mov r8=r9
	br.cond.sptk .strace_save_retval
#ifdef CONFIG_XEN
END(xen_trace_syscall)
#else
END(ia64_trace_syscall)
#endif

#ifdef CONFIG_XEN
GLOBAL_ENTRY(xen_ret_from_clone)
	PT_REGS_UNWIND_INFO(0)
	movl r16=running_on_xen;;
	ld4 r16=[r16];;
	cmp.eq p7,p0=r16,r0
(p7)	br.cond.sptk.many __ia64_ret_from_clone;;
#else	
GLOBAL_ENTRY(ia64_ret_from_clone)
	PT_REGS_UNWIND_INFO(0)
#endif	
{	/*
	 * Some versions of gas generate bad unwind info if the first instruction of a
	 * procedure doesn't go into the first slot of a bundle.  This is a workaround.
	 */
	nop.m 0
	nop.i 0
	/*
	 * We need to call schedule_tail() to complete the scheduling process.
	 * Called by ia64_switch_to() after do_fork()->copy_thread().  r8 contains the
	 * address of the previously executing task.
	 */
	br.call.sptk.many rp=ia64_invoke_schedule_tail
}
.ret8:
	adds r2=TI_FLAGS+IA64_TASK_SIZE,r13
	;;
	ld4 r2=[r2]
	;;
	mov r8=0
	and r2=_TIF_SYSCALL_TRACEAUDIT,r2
	;;
	cmp.ne p6,p0=r2,r0
(p6)	br.cond.spnt .strace_check_retval
	;;					// added stop bits to prevent r8 dependency
#ifdef CONFIG_XEN
	br.cond.sptk ia64_ret_from_syscall
END(xen_ret_from_clone)
#else
END(ia64_ret_from_clone)
#endif		
/*
 * ia64_leave_syscall(): Same as ia64_leave_kernel, except that it doesn't
 *	need to switch to bank 0 and doesn't restore the scratch registers.
 *	To avoid leaking kernel bits, the scratch registers are set to
 *	the following known-to-be-safe values:
 *
 *		  r1: restored (global pointer)
 *		  r2: cleared
 *		  r3: 1 (when returning to user-level)
 *	      r8-r11: restored (syscall return value(s))
 *		 r12: restored (user-level stack pointer)
 *		 r13: restored (user-level thread pointer)
 *		 r14: set to __kernel_syscall_via_epc
 *		 r15: restored (syscall #)
 *	     r16-r17: cleared
 *		 r18: user-level b6
 *		 r19: cleared
 *		 r20: user-level ar.fpsr
 *		 r21: user-level b0
 *		 r22: cleared
 *		 r23: user-level ar.bspstore
 *		 r24: user-level ar.rnat
 *		 r25: user-level ar.unat
 *		 r26: user-level ar.pfs
 *		 r27: user-level ar.rsc
 *		 r28: user-level ip
 *		 r29: user-level psr
 *		 r30: user-level cfm
 *		 r31: user-level pr
 *	      f6-f11: cleared
 *		  pr: restored (user-level pr)
 *		  b0: restored (user-level rp)
 *	          b6: restored
 *		  b7: set to __kernel_syscall_via_epc
 *	     ar.unat: restored (user-level ar.unat)
 *	      ar.pfs: restored (user-level ar.pfs)
 *	      ar.rsc: restored (user-level ar.rsc)
 *	     ar.rnat: restored (user-level ar.rnat)
 *	 ar.bspstore: restored (user-level ar.bspstore)
 *	     ar.fpsr: restored (user-level ar.fpsr)
 *	      ar.ccv: cleared
 *	      ar.csd: cleared
 *	      ar.ssd: cleared
 */
#ifdef CONFIG_XEN
GLOBAL_ENTRY(xen_leave_syscall)
	PT_REGS_UNWIND_INFO(0)
	movl r22=running_on_xen;;
	ld4 r22=[r22];;
	cmp.eq p7,p0=r22,r0
(p7)	br.cond.sptk.many __ia64_leave_syscall;;
#else
ENTRY(ia64_leave_syscall)
	PT_REGS_UNWIND_INFO(0)
#endif
	/*
	 * work.need_resched etc. mustn't get changed by this CPU before it returns to
	 * user- or fsys-mode, hence we disable interrupts early on.
	 *
	 * p6 controls whether current_thread_info()->flags needs to be check for
	 * extra work.  We always check for extra work when returning to user-level.
	 * With CONFIG_PREEMPT, we also check for extra work when the preempt_count
	 * is 0.  After extra work processing has been completed, execution
	 * resumes at .work_processed_syscall with p6 set to 1 if the extra-work-check
	 * needs to be redone.
	 */
#ifdef CONFIG_PREEMPT
	rsm psr.i				// disable interrupts
	cmp.eq pLvSys,p0=r0,r0			// pLvSys=1: leave from syscall
(pKStk) adds r20=TI_PRE_COUNT+IA64_TASK_SIZE,r13
	;;
	.pred.rel.mutex pUStk,pKStk
(pKStk) ld4 r21=[r20]			// r21 <- preempt_count
(pUStk)	mov r21=0			// r21 <- 0
	;;
	cmp.eq p6,p0=r21,r0		// p6 <- pUStk || (preempt_count == 0)
#else /* !CONFIG_PREEMPT */
#ifdef CONFIG_XEN
	movl r2=XSI_PSR_I_ADDR
	mov r18=1
	;;
	ld8 r2=[r2]
	;;
(pUStk)	st1 [r2]=r18
#else
(pUStk)	rsm psr.i
#endif
	cmp.eq pLvSys,p0=r0,r0		// pLvSys=1: leave from syscall
(pUStk)	cmp.eq.unc p6,p0=r0,r0		// p6 <- pUStk
#endif
.work_processed_syscall:
	adds r2=PT(LOADRS)+16,r12
	adds r3=PT(AR_BSPSTORE)+16,r12
	adds r18=TI_FLAGS+IA64_TASK_SIZE,r13
	;;
(p6)	ld4 r31=[r18]				// load current_thread_info()->flags
	ld8 r19=[r2],PT(B6)-PT(LOADRS)		// load ar.rsc value for "loadrs"
	nop.i 0
	;;
	mov r16=ar.bsp				// M2  get existing backing store pointer
	ld8 r18=[r2],PT(R9)-PT(B6)		// load b6
(p6)	and r15=TIF_WORK_MASK,r31		// any work other than TIF_SYSCALL_TRACE?
	;;
	ld8 r23=[r3],PT(R11)-PT(AR_BSPSTORE)	// load ar.bspstore (may be garbage)
(p6)	cmp4.ne.unc p6,p0=r15, r0		// any special work pending?
(p6)	br.cond.spnt .work_pending_syscall
	;;
	// start restoring the state saved on the kernel stack (struct pt_regs):
	ld8 r9=[r2],PT(CR_IPSR)-PT(R9)
	ld8 r11=[r3],PT(CR_IIP)-PT(R11)
(pNonSys) break 0		//      bug check: we shouldn't be here if pNonSys is TRUE!
	;;
	invala			// M0|1 invalidate ALAT
#ifdef CONFIG_XEN
	movl r28=XSI_PSR_I_ADDR
	movl r29=XSI_PSR_IC
	;;
	ld8 r28=[r28]
	mov r30=1
	;;
	st1	[r28]=r30
	st4	[r29]=r0	// note: clears both vpsr.i and vpsr.ic!
	;;
#else
	rsm psr.i | psr.ic	// M2   turn off interrupts and interruption collection
#endif
	cmp.eq p9,p0=r0,r0	// A    set p9 to indicate that we should restore cr.ifs

	ld8 r29=[r2],16		// M0|1 load cr.ipsr
	ld8 r28=[r3],16		// M0|1 load cr.iip
	mov r22=r0		// A    clear r22
	;;
	ld8 r30=[r2],16		// M0|1 load cr.ifs
	ld8 r25=[r3],16		// M0|1 load ar.unat
(pUStk) add r14=IA64_TASK_THREAD_ON_USTACK_OFFSET,r13
	;;
	ld8 r26=[r2],PT(B0)-PT(AR_PFS)	// M0|1 load ar.pfs
#ifdef CONFIG_XEN
(pKStk)	mov r21=r8
(pKStk)	XEN_HYPER_GET_PSR
	;;
(pKStk)	mov r22=r8
(pKStk)	mov r8=r21
	;;
#else    
(pKStk)	mov r22=psr			// M2   read PSR now that interrupts are disabled
#endif
	nop 0
	;;
	ld8 r21=[r2],PT(AR_RNAT)-PT(B0) // M0|1 load b0
	ld8 r27=[r3],PT(PR)-PT(AR_RSC)	// M0|1 load ar.rsc
	mov f6=f0			// F    clear f6
	;;
	ld8 r24=[r2],PT(AR_FPSR)-PT(AR_RNAT)	// M0|1 load ar.rnat (may be garbage)
	ld8 r31=[r3],PT(R1)-PT(PR)		// M0|1 load predicates
	mov f7=f0				// F    clear f7
	;;
	ld8 r20=[r2],PT(R12)-PT(AR_FPSR)	// M0|1 load ar.fpsr
	ld8.fill r1=[r3],16			// M0|1 load r1
(pUStk) mov r17=1				// A
	;;
(pUStk) st1 [r14]=r17				// M2|3
	ld8.fill r13=[r3],16			// M0|1
	mov f8=f0				// F    clear f8
	;;
	ld8.fill r12=[r2]			// M0|1 restore r12 (sp)
	ld8.fill r15=[r3]			// M0|1 restore r15
	mov b6=r18				// I0   restore b6

	addl r17=THIS_CPU(ia64_phys_stacked_size_p8),r0 // A
	mov f9=f0					// F    clear f9
(pKStk) br.cond.dpnt.many skip_rbs_switch		// B

	srlz.d				// M0   ensure interruption collection is off (for cover)
	shr.u r18=r19,16		// I0|1 get byte size of existing "dirty" partition
#ifdef CONFIG_XEN
	XEN_HYPER_COVER;
#else
	cover				// B    add current frame into dirty partition & set cr.ifs
#endif
	;;
(pUStk) ld4 r17=[r17]			// M0|1 r17 = cpu_data->phys_stacked_size_p8
	mov r19=ar.bsp			// M2   get new backing store pointer
	mov f10=f0			// F    clear f10

	nop.m 0
	movl r14=__kernel_syscall_via_epc // X
	;;
	mov.m ar.csd=r0			// M2   clear ar.csd
	mov.m ar.ccv=r0			// M2   clear ar.ccv
	mov b7=r14			// I0   clear b7 (hint with __kernel_syscall_via_epc)

	mov.m ar.ssd=r0			// M2   clear ar.ssd
	mov f11=f0			// F    clear f11
	br.cond.sptk.many rbs_switch	// B
#ifdef CONFIG_XEN
END(xen_leave_syscall)
#else
END(ia64_leave_syscall)
#endif

#ifdef CONFIG_XEN
GLOBAL_ENTRY(xen_leave_kernel)
	PT_REGS_UNWIND_INFO(0)
	movl r22=running_on_xen;;
	ld4 r22=[r22];;
	cmp.eq p7,p0=r22,r0
(p7)	br.cond.sptk.many __ia64_leave_kernel;;
#else
GLOBAL_ENTRY(ia64_leave_kernel)
	PT_REGS_UNWIND_INFO(0)
#endif
	/*
	 * work.need_resched etc. mustn't get changed by this CPU before it returns to
	 * user- or fsys-mode, hence we disable interrupts early on.
	 *
	 * p6 controls whether current_thread_info()->flags needs to be check for
	 * extra work.  We always check for extra work when returning to user-level.
	 * With CONFIG_PREEMPT, we also check for extra work when the preempt_count
	 * is 0.  After extra work processing has been completed, execution
	 * resumes at .work_processed_syscall with p6 set to 1 if the extra-work-check
	 * needs to be redone.
	 */
#ifdef CONFIG_PREEMPT
	rsm psr.i				// disable interrupts
	cmp.eq p0,pLvSys=r0,r0			// pLvSys=0: leave from kernel
(pKStk)	adds r20=TI_PRE_COUNT+IA64_TASK_SIZE,r13
	;;
	.pred.rel.mutex pUStk,pKStk
(pKStk)	ld4 r21=[r20]			// r21 <- preempt_count
(pUStk)	mov r21=0			// r21 <- 0
	;;
	cmp.eq p6,p0=r21,r0		// p6 <- pUStk || (preempt_count == 0)
#else
#ifdef CONFIG_XEN
(pUStk)	movl r17=XSI_PSR_I_ADDR
(pUStk)	mov r31=1
		;;
(pUStk) 	ld8 r17=[r17]
		;;
(pUStk)	st1 [r17]=r31
	;;
#else
(pUStk)	rsm psr.i
#endif
	cmp.eq p0,pLvSys=r0,r0		// pLvSys=0: leave from kernel
(pUStk)	cmp.eq.unc p6,p0=r0,r0		// p6 <- pUStk
#endif
.work_processed_kernel:
	adds r17=TI_FLAGS+IA64_TASK_SIZE,r13
	;;
(p6)	ld4 r31=[r17]				// load current_thread_info()->flags
	adds r21=PT(PR)+16,r12
	;;

	lfetch [r21],PT(CR_IPSR)-PT(PR)
	adds r2=PT(B6)+16,r12
	adds r3=PT(R16)+16,r12
	;;
	lfetch [r21]
	ld8 r28=[r2],8		// load b6
	adds r29=PT(R24)+16,r12

	ld8.fill r16=[r3],PT(AR_CSD)-PT(R16)
	adds r30=PT(AR_CCV)+16,r12
(p6)	and r19=TIF_WORK_MASK,r31		// any work other than TIF_SYSCALL_TRACE?
	;;
	ld8.fill r24=[r29]
	ld8 r15=[r30]		// load ar.ccv
(p6)	cmp4.ne.unc p6,p0=r19, r0		// any special work pending?
	;;
	ld8 r29=[r2],16		// load b7
	ld8 r30=[r3],16		// load ar.csd
(p6)	br.cond.spnt .work_pending
	;;
	ld8 r31=[r2],16		// load ar.ssd
	ld8.fill r8=[r3],16
	;;
	ld8.fill r9=[r2],16
	ld8.fill r10=[r3],PT(R17)-PT(R10)
	;;
	ld8.fill r11=[r2],PT(R18)-PT(R11)
	ld8.fill r17=[r3],16
	;;
	ld8.fill r18=[r2],16
	ld8.fill r19=[r3],16
	;;
	ld8.fill r20=[r2],16
	ld8.fill r21=[r3],16
	mov ar.csd=r30
	mov ar.ssd=r31
	;;
#ifdef CONFIG_XEN
	movl r23=XSI_PSR_I_ADDR
	movl r22=XSI_PSR_IC
	;;
	ld8 r23=[r23]
	mov r25=1
	;;
	st1 [r23]=r25
	st4 [r22]=r0		// note: clears both vpsr.i and vpsr.ic!
	;;
#else
	rsm psr.i | psr.ic	// initiate turning off of interrupt and interruption collection
#endif
	invala			// invalidate ALAT
	;;
	ld8.fill r22=[r2],24
	ld8.fill r23=[r3],24
	mov b6=r28
	;;
	ld8.fill r25=[r2],16
	ld8.fill r26=[r3],16
	mov b7=r29
	;;
	ld8.fill r27=[r2],16
	ld8.fill r28=[r3],16
	;;
	ld8.fill r29=[r2],16
	ld8.fill r30=[r3],24
	;;
	ld8.fill r31=[r2],PT(F9)-PT(R31)
	adds r3=PT(F10)-PT(F6),r3
	;;
	ldf.fill f9=[r2],PT(F6)-PT(F9)
	ldf.fill f10=[r3],PT(F8)-PT(F10)
	;;
	ldf.fill f6=[r2],PT(F7)-PT(F6)
	;;
	ldf.fill f7=[r2],PT(F11)-PT(F7)
	ldf.fill f8=[r3],32
	;;
	srlz.d	// ensure that inter. collection is off (VHPT is don't care, since text is pinned)
	mov ar.ccv=r15
	;;
	ldf.fill f11=[r2]
#ifdef CONFIG_XEN
	;;
	// r16-r31 all now hold bank1 values
	mov r15=ar.unat
	movl r2=XSI_BANK1_R16
	movl r3=XSI_BANK1_R16+8
	;;
.mem.offset 0,0; st8.spill [r2]=r16,16
.mem.offset 8,0; st8.spill [r3]=r17,16
	;;
.mem.offset 0,0; st8.spill [r2]=r18,16
.mem.offset 8,0; st8.spill [r3]=r19,16
	;;
.mem.offset 0,0; st8.spill [r2]=r20,16
.mem.offset 8,0; st8.spill [r3]=r21,16
	;;
.mem.offset 0,0; st8.spill [r2]=r22,16
.mem.offset 8,0; st8.spill [r3]=r23,16
	;;
.mem.offset 0,0; st8.spill [r2]=r24,16
.mem.offset 8,0; st8.spill [r3]=r25,16
	;;
.mem.offset 0,0; st8.spill [r2]=r26,16
.mem.offset 8,0; st8.spill [r3]=r27,16
	;;
.mem.offset 0,0; st8.spill [r2]=r28,16
.mem.offset 8,0; st8.spill [r3]=r29,16
	;;
.mem.offset 0,0; st8.spill [r2]=r30,16
.mem.offset 8,0; st8.spill [r3]=r31,16
	;;
	mov r3=ar.unat
	movl r2=XSI_B1NAT
	;;
	st8 [r2]=r3
	mov ar.unat=r15
	movl r2=XSI_BANKNUM;;
	st4 [r2]=r0;
#else
	bsw.0			// switch back to bank 0 (no stop bit required beforehand...)
#endif
	;;
(pUStk)	mov r18=IA64_KR(CURRENT)// M2 (12 cycle read latency)
	adds r16=PT(CR_IPSR)+16,r12
	adds r17=PT(CR_IIP)+16,r12

#ifdef CONFIG_XEN    
(pKStk)	mov r29=r8
(pKStk)	XEN_HYPER_GET_PSR
	;;
(pKStk)	mov r22=r8
(pKStk)	mov r8=r29
	;;
#else
(pKStk)	mov r22=psr		// M2 read PSR now that interrupts are disabled
#endif
	nop.i 0
	nop.i 0
	;;
	ld8 r29=[r16],16	// load cr.ipsr
	ld8 r28=[r17],16	// load cr.iip
	;;
	ld8 r30=[r16],16	// load cr.ifs
	ld8 r25=[r17],16	// load ar.unat
	;;
	ld8 r26=[r16],16	// load ar.pfs
	ld8 r27=[r17],16	// load ar.rsc
	cmp.eq p9,p0=r0,r0	// set p9 to indicate that we should restore cr.ifs
	;;
	ld8 r24=[r16],16	// load ar.rnat (may be garbage)
	ld8 r23=[r17],16	// load ar.bspstore (may be garbage)
	;;
	ld8 r31=[r16],16	// load predicates
	ld8 r21=[r17],16	// load b0
	;;
	ld8 r19=[r16],16	// load ar.rsc value for "loadrs"
	ld8.fill r1=[r17],16	// load r1
	;;
	ld8.fill r12=[r16],16
	ld8.fill r13=[r17],16
(pUStk)	adds r18=IA64_TASK_THREAD_ON_USTACK_OFFSET,r18
	;;
	ld8 r20=[r16],16	// ar.fpsr
	ld8.fill r15=[r17],16
	;;
	ld8.fill r14=[r16],16
	ld8.fill r2=[r17]
(pUStk)	mov r17=1
	;;
	ld8.fill r3=[r16]
(pUStk)	st1 [r18]=r17		// restore current->thread.on_ustack
	shr.u r18=r19,16	// get byte size of existing "dirty" partition
	;;
	mov r16=ar.bsp		// get existing backing store pointer
	addl r17=THIS_CPU(ia64_phys_stacked_size_p8),r0
	;;
	ld4 r17=[r17]		// r17 = cpu_data->phys_stacked_size_p8
(pKStk)	br.cond.dpnt skip_rbs_switch

	/*
	 * Restore user backing store.
	 *
	 * NOTE: alloc, loadrs, and cover can't be predicated.
	 */
(pNonSys) br.cond.dpnt dont_preserve_current_frame

#ifdef CONFIG_XEN
	XEN_HYPER_COVER;
#else
	cover				// add current frame into dirty partition and set cr.ifs
#endif
	;;
	mov r19=ar.bsp			// get new backing store pointer
rbs_switch:
	sub r16=r16,r18			// krbs = old bsp - size of dirty partition
	cmp.ne p9,p0=r0,r0		// clear p9 to skip restore of cr.ifs
	;;
	sub r19=r19,r16			// calculate total byte size of dirty partition
	add r18=64,r18			// don't force in0-in7 into memory...
	;;
	shl r19=r19,16			// shift size of dirty partition into loadrs position
	;;
dont_preserve_current_frame:
	/*
	 * To prevent leaking bits between the kernel and user-space,
	 * we must clear the stacked registers in the "invalid" partition here.
	 * Not pretty, but at least it's fast (3.34 registers/cycle on Itanium,
	 * 5 registers/cycle on McKinley).
	 */
#	define pRecurse	p6
#	define pReturn	p7
#ifdef CONFIG_ITANIUM
#	define Nregs	10
#else
#	define Nregs	14
#endif
	alloc loc0=ar.pfs,2,Nregs-2,2,0
	shr.u loc1=r18,9		// RNaTslots <= floor(dirtySize / (64*8))
	sub r17=r17,r18			// r17 = (physStackedSize + 8) - dirtySize
	;;
	mov ar.rsc=r19			// load ar.rsc to be used for "loadrs"
	shladd in0=loc1,3,r17
	mov in1=0
	;;
	TEXT_ALIGN(32)
rse_clear_invalid:
#ifdef CONFIG_ITANIUM
	// cycle 0
 { .mii
	alloc loc0=ar.pfs,2,Nregs-2,2,0
	cmp.lt pRecurse,p0=Nregs*8,in0	// if more than Nregs regs left to clear, (re)curse
	add out0=-Nregs*8,in0
}{ .mfb
	add out1=1,in1			// increment recursion count
	nop.f 0
	nop.b 0				// can't do br.call here because of alloc (WAW on CFM)
	;;
}{ .mfi	// cycle 1
	mov loc1=0
	nop.f 0
	mov loc2=0
}{ .mib
	mov loc3=0
	mov loc4=0
(pRecurse) br.call.sptk.many b0=rse_clear_invalid

}{ .mfi	// cycle 2
	mov loc5=0
	nop.f 0
	cmp.ne pReturn,p0=r0,in1	// if recursion count != 0, we need to do a br.ret
}{ .mib
	mov loc6=0
	mov loc7=0
(pReturn) br.ret.sptk.many b0
}
#else /* !CONFIG_ITANIUM */
	alloc loc0=ar.pfs,2,Nregs-2,2,0
	cmp.lt pRecurse,p0=Nregs*8,in0	// if more than Nregs regs left to clear, (re)curse
	add out0=-Nregs*8,in0
	add out1=1,in1			// increment recursion count
	mov loc1=0
	mov loc2=0
	;;
	mov loc3=0
	mov loc4=0
	mov loc5=0
	mov loc6=0
	mov loc7=0
(pRecurse) br.call.dptk.few b0=rse_clear_invalid
	;;
	mov loc8=0
	mov loc9=0
	cmp.ne pReturn,p0=r0,in1	// if recursion count != 0, we need to do a br.ret
	mov loc10=0
	mov loc11=0
(pReturn) br.ret.dptk.many b0
#endif /* !CONFIG_ITANIUM */
#	undef pRecurse
#	undef pReturn
	;;
	alloc r17=ar.pfs,0,0,0,0	// drop current register frame
	;;
	loadrs
	;;
skip_rbs_switch:
	mov ar.unat=r25		// M2
(pKStk)	extr.u r22=r22,21,1	// I0 extract current value of psr.pp from r22
(pLvSys)mov r19=r0		// A  clear r19 for leave_syscall, no-op otherwise
	;;
(pUStk)	mov ar.bspstore=r23	// M2
(pKStk)	dep r29=r22,r29,21,1	// I0 update ipsr.pp with psr.pp
(pLvSys)mov r16=r0		// A  clear r16 for leave_syscall, no-op otherwise
	;;
#ifdef CONFIG_XEN
	movl r25=XSI_IPSR
	;;
	st8[r25]=r29,XSI_IFS_OFS-XSI_IPSR_OFS
	;;
#else
	mov cr.ipsr=r29		// M2
#endif
	mov ar.pfs=r26		// I0
(pLvSys)mov r17=r0		// A  clear r17 for leave_syscall, no-op otherwise

#ifdef CONFIG_XEN
(p9)	st8 [r25]=r30
	;;
	adds r25=XSI_IIP_OFS-XSI_IFS_OFS,r25
	;;
#else
(p9)	mov cr.ifs=r30		// M2
#endif
	mov b0=r21		// I0
(pLvSys)mov r18=r0		// A  clear r18 for leave_syscall, no-op otherwise

	mov ar.fpsr=r20		// M2
#ifdef CONFIG_XEN
	st8	[r25]=r28
#else
	mov cr.iip=r28		// M2
#endif
	nop 0
	;;
(pUStk)	mov ar.rnat=r24		// M2 must happen with RSE in lazy mode
	nop 0
(pLvSys)mov r2=r0

	mov ar.rsc=r27		// M2
	mov pr=r31,-1		// I0
#ifdef CONFIG_XEN
	;;
	XEN_HYPER_RFI;
#else
	rfi			// B
#endif

	/*
	 * On entry:
	 *	r20 = &current->thread_info->pre_count (if CONFIG_PREEMPT)
	 *	r31 = current->thread_info->flags
	 * On exit:
	 *	p6 = TRUE if work-pending-check needs to be redone
	 */
.work_pending_syscall:
	add r2=-8,r2
	add r3=-8,r3
	;;
	st8 [r2]=r8
	st8 [r3]=r10
.work_pending:
	tbit.z p6,p0=r31,TIF_NEED_RESCHED		// current_thread_info()->need_resched==0?
(p6)	br.cond.sptk.few .notify
#ifdef CONFIG_PREEMPT
(pKStk) dep r21=-1,r0,PREEMPT_ACTIVE_BIT,1
	;;
(pKStk) st4 [r20]=r21
	ssm psr.i		// enable interrupts
#endif
	br.call.spnt.many rp=schedule
.ret9:	cmp.eq p6,p0=r0,r0				// p6 <- 1
#ifdef CONFIG_XEN
	movl r2=XSI_PSR_I_ADDR
	mov r20=1
	;;
	ld8 r2=[r2]
	;;
	st1 [r2]=r20
#else
	rsm psr.i		// disable interrupts
#endif
	;;
#ifdef CONFIG_PREEMPT
(pKStk)	adds r20=TI_PRE_COUNT+IA64_TASK_SIZE,r13
	;;
(pKStk)	st4 [r20]=r0		// preempt_count() <- 0
#endif
(pLvSys)br.cond.sptk.few  .work_pending_syscall_end
	br.cond.sptk.many .work_processed_kernel	// re-check

.notify:
(pUStk)	br.call.spnt.many rp=notify_resume_user
.ret10:	cmp.ne p6,p0=r0,r0				// p6 <- 0
(pLvSys)br.cond.sptk.few  .work_pending_syscall_end
	br.cond.sptk.many .work_processed_kernel	// don't re-check

.work_pending_syscall_end:
	adds r2=PT(R8)+16,r12
	adds r3=PT(R10)+16,r12
	;;
	ld8 r8=[r2]
	ld8 r10=[r3]
	br.cond.sptk.many .work_processed_syscall	// re-check

#ifdef CONFIG_XEN
END(xen_leave_kernel)
#else
END(ia64_leave_kernel)
#endif
