--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/entry.S	2005-01-23 13:23:36.000000000 -0700
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/entry.S	2004-12-17 13:47:03.000000000 -0700
@@ -35,7 +35,9 @@
 
 #include <asm/asmmacro.h>
 #include <asm/cache.h>
+#ifndef XEN
 #include <asm/errno.h>
+#endif
 #include <asm/kregs.h>
 #include <asm/offsets.h>
 #include <asm/pgtable.h>
@@ -46,6 +48,23 @@
 
 #include "minstate.h"
 
+#ifdef XEN
+#define	sys_execve 0
+#define do_fork 0
+#define	syscall_trace 0
+#define schedule 0
+#define do_notify_resume_user 0
+#define ia64_rt_sigsuspend 0
+#define ia64_rt_sigreturn 0
+#define	ia64_handle_unaligned 0
+#define	errno 0
+#define	sys_ni_syscall 0
+#define unw_init_frame_info 0
+#define sys_call_table 0
+#endif
+
+	/*
+
 	/*
 	 * execve() is special because in case of success, we need to
 	 * setup a null register window frame.
@@ -178,11 +197,14 @@
 	DO_SAVE_SWITCH_STACK
 	.body
 
+#ifdef XEN
+//#undef IA64_TASK_THREAD_KSP_OFFSET
+//#define	IA64_TASK_THREAD_KSP_OFFSET	0x38
 	adds r22=IA64_TASK_THREAD_KSP_OFFSET,r13
 	movl r25=init_task
 	mov r27=IA64_KR(CURRENT_STACK)
 	adds r21=IA64_TASK_THREAD_KSP_OFFSET,in0
-	dep r20=0,in0,61,3		// physical address of "current"
+	dep r20=0,in0,50,14		// physical address of "current"
 	;;
 	st8 [r22]=sp			// save kernel stack pointer of old task
 	shr.u r26=r20,IA64_GRANULE_SHIFT
@@ -194,6 +216,22 @@
 (p6)	cmp.eq p7,p6=r26,r27
 (p6)	br.cond.dpnt .map
 	;;
+#else
+	adds r22=IA64_TASK_THREAD_KSP_OFFSET,r13
+	mov r27=IA64_KR(CURRENT_STACK)
+	dep r20=0,in0,61,3		// physical address of "current"
+	;;
+	st8 [r22]=sp			// save kernel stack pointer of old task
+	shr.u r26=r20,IA64_GRANULE_SHIFT
+	adds r21=IA64_TASK_THREAD_KSP_OFFSET,in0
+	;;
+	/*
+	 * If we've already mapped this task's page, we can skip doing it again.
+	 */
+	cmp.eq p7,p6=r26,r27
+(p6)	br.cond.dpnt .map
+	;;
+#endif
 .done:
 (p6)	ssm psr.ic			// if we we had to map, renable the psr.ic bit FIRST!!!
 	;;
@@ -211,6 +249,16 @@
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
@@ -367,7 +415,11 @@
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
 
@@ -595,6 +647,11 @@
 	 */
 	br.call.sptk.many rp=ia64_invoke_schedule_tail
 }
+#ifdef XEN
+	// new domains are cloned but not exec'ed so switch to user mode here
+	cmp.ne pKStk,pUStk=r0,r0
+	br.cond.spnt ia64_leave_kernel
+#else
 .ret8:
 	adds r2=TI_FLAGS+IA64_TASK_SIZE,r13
 	;;
@@ -603,6 +660,7 @@
 	mov r8=0
 	tbit.nz p6,p0=r2,TIF_SYSCALL_TRACE
 (p6)	br.cond.spnt .strace_check_retval
+#endif
 	;;					// added stop bits to prevent r8 dependency
 END(ia64_ret_from_clone)
 	// fall through
@@ -684,9 +742,14 @@
 #endif /* CONFIG_PREEMPT */
 	adds r16=PT(LOADRS)+16,r12
 	adds r17=PT(AR_BSPSTORE)+16,r12
+#ifdef XEN
+	mov r31=r0
+	;;
+#else
 	adds r18=TI_FLAGS+IA64_TASK_SIZE,r13
 	;;
 (p6)	ld4 r31=[r18]				// load current_thread_info()->flags
+#endif
 	ld8 r19=[r16],PT(B6)-PT(LOADRS)		// load ar.rsc value for "loadrs"
 	nop.i 0
 	;;
@@ -745,7 +808,11 @@
 	mov b7=r0		// clear b7
 	;;
 (pUStk) st1 [r14]=r3
+#ifdef XEN
+	movl r17=THIS_CPU(ia64_phys_stacked_size_p8)
+#else
 	addl r17=THIS_CPU(ia64_phys_stacked_size_p8),r0
+#endif
 	;;
 	mov r16=ar.bsp		// get existing backing store pointer
 	srlz.i			// ensure interruption collection is off
@@ -796,9 +863,18 @@
 	;;
 (p6)	cmp.eq.unc p6,p0=r21,r0		// p6 <- p6 && (r21 == 0)
 #endif /* CONFIG_PREEMPT */
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
 
@@ -912,7 +988,11 @@
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
@@ -1264,6 +1344,7 @@
 	br.ret.sptk.many rp
 END(unw_init_running)
 
+#ifndef XEN
 	.rodata
 	.align 8
 	.globl sys_call_table
@@ -1526,3 +1607,4 @@
 	data8 sys_ni_syscall
 
 	.org sys_call_table + 8*NR_syscalls	// guard against failures to increase NR_syscalls
+#endif
