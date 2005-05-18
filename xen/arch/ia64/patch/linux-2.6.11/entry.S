--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/arch/ia64/kernel/entry.S	2005-03-01 23:37:50.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/arch/ia64/entry.S	2005-05-18 12:40:51.000000000 -0700
@@ -46,6 +46,7 @@
 
 #include "minstate.h"
 
+#ifndef XEN
 	/*
 	 * execve() is special because in case of success, we need to
 	 * setup a null register window frame.
@@ -174,6 +175,7 @@
 	mov rp=loc0
 	br.ret.sptk.many rp
 END(sys_clone)
+#endif /* !XEN */
 
 /*
  * prev_task <- ia64_switch_to(struct task_struct *next)
@@ -191,7 +193,11 @@
 	movl r25=init_task
 	mov r27=IA64_KR(CURRENT_STACK)
 	adds r21=IA64_TASK_THREAD_KSP_OFFSET,in0
+#ifdef XEN
+	dep r20=0,in0,60,4		// physical address of "next"
+#else
 	dep r20=0,in0,61,3		// physical address of "next"
+#endif
 	;;
 	st8 [r22]=sp			// save kernel stack pointer of old task
 	shr.u r26=r20,IA64_GRANULE_SHIFT
@@ -220,6 +226,16 @@
 	br.ret.sptk.many rp		// boogie on out in new context
 
 .map:
+#ifdef XEN
+	// avoid overlapping with kernel TR
+	movl r25=KERNEL_START
+	dep  r23=0,in0,0,KERNEL_TR_PAGE_SHIFT
+	;;
+	cmp.eq p7,p0=r25,r23
+	;;
+(p7)	mov IA64_KR(CURRENT_STACK)=r26	// remember last page we mapped...
+(p7)	br.cond.sptk .done
+#endif
 	rsm psr.ic			// interrupts (psr.i) are already disabled here
 	movl r25=PAGE_KERNEL
 	;;
@@ -376,7 +392,11 @@
  *	- b7 holds address to return to
  *	- must not touch r8-r11
  */
+#ifdef XEN
+GLOBAL_ENTRY(load_switch_stack)
+#else
 ENTRY(load_switch_stack)
+#endif
 	.prologue
 	.altrp b7
 
@@ -470,6 +490,7 @@
 	br.cond.sptk.many b7
 END(load_switch_stack)
 
+#ifndef XEN
 GLOBAL_ENTRY(__ia64_syscall)
 	.regstk 6,0,0,0
 	mov r15=in5				// put syscall number in place
@@ -588,6 +609,7 @@
 }
 .ret4:	br.cond.sptk ia64_leave_kernel
 END(ia64_strace_leave_kernel)
+#endif
 
 GLOBAL_ENTRY(ia64_ret_from_clone)
 	PT_REGS_UNWIND_INFO(0)
@@ -604,6 +626,15 @@
 	 */
 	br.call.sptk.many rp=ia64_invoke_schedule_tail
 }
+#ifdef XEN
+	// new domains are cloned but not exec'ed so switch to user mode here
+	cmp.ne pKStk,pUStk=r0,r0
+#ifdef CONFIG_VTI
+	br.cond.spnt ia64_leave_hypervisor
+#else // CONFIG_VTI
+	br.cond.spnt ia64_leave_kernel
+#endif // CONFIG_VTI
+#else
 .ret8:
 	adds r2=TI_FLAGS+IA64_TASK_SIZE,r13
 	;;
@@ -614,6 +645,7 @@
 	;;
 	cmp.ne p6,p0=r2,r0
 (p6)	br.cond.spnt .strace_check_retval
+#endif
 	;;					// added stop bits to prevent r8 dependency
 END(ia64_ret_from_clone)
 	// fall through
@@ -700,19 +732,25 @@
 .work_processed_syscall:
 	adds r2=PT(LOADRS)+16,r12
 	adds r3=PT(AR_BSPSTORE)+16,r12
+#ifndef XEN
 	adds r18=TI_FLAGS+IA64_TASK_SIZE,r13
 	;;
 (p6)	ld4 r31=[r18]				// load current_thread_info()->flags
+#endif
 	ld8 r19=[r2],PT(B6)-PT(LOADRS)		// load ar.rsc value for "loadrs"
 	mov b7=r0		// clear b7
 	;;
 	ld8 r23=[r3],PT(R11)-PT(AR_BSPSTORE)	// load ar.bspstore (may be garbage)
 	ld8 r18=[r2],PT(R9)-PT(B6)		// load b6
+#ifndef XEN
 (p6)	and r15=TIF_WORK_MASK,r31		// any work other than TIF_SYSCALL_TRACE?
+#endif
 	;;
 	mov r16=ar.bsp				// M2  get existing backing store pointer
+#ifndef XEN
 (p6)	cmp4.ne.unc p6,p0=r15, r0		// any special work pending?
 (p6)	br.cond.spnt .work_pending_syscall
+#endif
 	;;
 	// start restoring the state saved on the kernel stack (struct pt_regs):
 	ld8 r9=[r2],PT(CR_IPSR)-PT(R9)
@@ -757,7 +795,11 @@
 	;;
 	ld8.fill r12=[r2]	// restore r12 (sp)
 	ld8.fill r15=[r3]	// restore r15
+#ifdef XEN
+	movl r3=THIS_CPU(ia64_phys_stacked_size_p8)
+#else
 	addl r3=THIS_CPU(ia64_phys_stacked_size_p8),r0
+#endif
 	;;
 (pUStk)	ld4 r3=[r3]		// r3 = cpu_data->phys_stacked_size_p8
 (pUStk) st1 [r14]=r17
@@ -814,9 +856,18 @@
 (pUStk)	cmp.eq.unc p6,p0=r0,r0		// p6 <- pUStk
 #endif
 .work_processed_kernel:
+#ifdef XEN
+	alloc loc0=ar.pfs,0,1,1,0
+	adds out0=16,r12
+	;;
+(p6)	br.call.sptk.many b0=deliver_pending_interrupt
+	mov ar.pfs=loc0
+	mov r31=r0
+#else
 	adds r17=TI_FLAGS+IA64_TASK_SIZE,r13
 	;;
 (p6)	ld4 r31=[r17]				// load current_thread_info()->flags
+#endif
 	adds r21=PT(PR)+16,r12
 	;;
 
@@ -828,17 +879,20 @@
 	ld8 r28=[r2],8		// load b6
 	adds r29=PT(R24)+16,r12
 
-	ld8.fill r16=[r3],PT(AR_CSD)-PT(R16)
+	ld8.fill r16=[r3]
 	adds r30=PT(AR_CCV)+16,r12
 (p6)	and r19=TIF_WORK_MASK,r31		// any work other than TIF_SYSCALL_TRACE?
 	;;
+	adds r3=PT(AR_CSD)-PT(R16),r3
 	ld8.fill r24=[r29]
 	ld8 r15=[r30]		// load ar.ccv
 (p6)	cmp4.ne.unc p6,p0=r19, r0		// any special work pending?
 	;;
 	ld8 r29=[r2],16		// load b7
 	ld8 r30=[r3],16		// load ar.csd
+#ifndef XEN
 (p6)	br.cond.spnt .work_pending
+#endif
 	;;
 	ld8 r31=[r2],16		// load ar.ssd
 	ld8.fill r8=[r3],16
@@ -934,7 +988,11 @@
 	shr.u r18=r19,16	// get byte size of existing "dirty" partition
 	;;
 	mov r16=ar.bsp		// get existing backing store pointer
+#ifdef XEN
+	movl r17=THIS_CPU(ia64_phys_stacked_size_p8)
+#else
 	addl r17=THIS_CPU(ia64_phys_stacked_size_p8),r0
+#endif
 	;;
 	ld4 r17=[r17]		// r17 = cpu_data->phys_stacked_size_p8
 (pKStk)	br.cond.dpnt skip_rbs_switch
@@ -1069,6 +1127,7 @@
 	mov pr=r31,-1		// I0
 	rfi			// B
 
+#ifndef XEN
 	/*
 	 * On entry:
 	 *	r20 = &current->thread_info->pre_count (if CONFIG_PREEMPT)
@@ -1130,6 +1189,7 @@
 	ld8 r8=[r2]
 	ld8 r10=[r3]
 	br.cond.sptk.many .work_processed_syscall	// re-check
+#endif
 
 END(ia64_leave_kernel)
 
@@ -1166,6 +1226,7 @@
 	br.ret.sptk.many rp
 END(ia64_invoke_schedule_tail)
 
+#ifndef XEN
 	/*
 	 * Setup stack and call do_notify_resume_user().  Note that pSys and pNonSys need to
 	 * be set up by the caller.  We declare 8 input registers so the system call
@@ -1264,6 +1325,7 @@
 	mov ar.unat=r9
 	br.many b7
 END(sys_rt_sigreturn)
+#endif
 
 GLOBAL_ENTRY(ia64_prepare_handle_unaligned)
 	.prologue
@@ -1278,6 +1340,7 @@
 	br.cond.sptk.many rp				// goes to ia64_leave_kernel
 END(ia64_prepare_handle_unaligned)
 
+#ifndef XEN
 	//
 	// unw_init_running(void (*callback)(info, arg), void *arg)
 	//
@@ -1585,3 +1648,4 @@
 	data8 sys_ni_syscall
 
 	.org sys_call_table + 8*NR_syscalls	// guard against failures to increase NR_syscalls
+#endif
