 ivt.S |  254 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 1 files changed, 254 insertions(+)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/ivt.S
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/ivt.S	2005-04-07 10:29:00.565766924 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/ivt.S	2005-04-07 10:29:50.923594750 -0500
@@ -1,3 +1,21 @@
+
+#ifdef XEN
+//#define CONFIG_DISABLE_VHPT	// FIXME: change when VHPT is enabled??
+// these are all hacked out for now as the entire IVT
+// will eventually be replaced... just want to use it
+// for startup code to handle TLB misses
+//#define ia64_leave_kernel 0
+//#define ia64_ret_from_syscall 0
+//#define ia64_handle_irq 0
+//#define ia64_fault 0
+#define ia64_illegal_op_fault 0
+#define ia64_prepare_handle_unaligned 0
+#define ia64_bad_break 0
+#define ia64_trace_syscall 0
+#define sys_call_table 0
+#define sys_ni_syscall 0
+#include <asm/vhpt.h>
+#endif
 /*
  * arch/ia64/kernel/ivt.S
  *
@@ -77,6 +95,13 @@
 	mov r19=n;;			/* prepare to save predicates */		\
 	br.sptk.many dispatch_to_fault_handler
 
+#ifdef XEN
+#define REFLECT(n)									\
+	mov r31=pr;									\
+	mov r19=n;;			/* prepare to save predicates */		\
+	br.sptk.many dispatch_reflection
+#endif
+
 	.section .text.ivt,"ax"
 
 	.align 32768	// align on 32KB boundary
@@ -214,6 +239,13 @@ END(vhpt_miss)
 // 0x0400 Entry 1 (size 64 bundles) ITLB (21)
 ENTRY(itlb_miss)
 	DBG_FAULT(1)
+#ifdef XEN
+	VHPT_CCHAIN_LOOKUP(itlb_miss,i)
+#ifdef VHPT_GLOBAL
+	br.cond.sptk page_fault
+	;;
+#endif
+#endif
 	/*
 	 * The ITLB handler accesses the L3 PTE via the virtually mapped linear
 	 * page table.  If a nested TLB miss occurs, we switch into physical
@@ -258,6 +290,13 @@ END(itlb_miss)
 // 0x0800 Entry 2 (size 64 bundles) DTLB (9,48)
 ENTRY(dtlb_miss)
 	DBG_FAULT(2)
+#ifdef XEN
+	VHPT_CCHAIN_LOOKUP(dtlb_miss,d)
+#ifdef VHPT_GLOBAL
+	br.cond.sptk page_fault
+	;;
+#endif
+#endif
 	/*
 	 * The DTLB handler accesses the L3 PTE via the virtually mapped linear
 	 * page table.  If a nested TLB miss occurs, we switch into physical
@@ -302,6 +341,13 @@ END(dtlb_miss)
 // 0x0c00 Entry 3 (size 64 bundles) Alt ITLB (19)
 ENTRY(alt_itlb_miss)
 	DBG_FAULT(3)
+#ifdef XEN
+//#ifdef VHPT_GLOBAL
+//	VHPT_CCHAIN_LOOKUP(alt_itlb_miss,i)
+//	br.cond.sptk page_fault
+//	;;
+//#endif
+#endif
 	mov r16=cr.ifa		// get address that caused the TLB miss
 	movl r17=PAGE_KERNEL
 	mov r21=cr.ipsr
@@ -340,6 +386,13 @@ END(alt_itlb_miss)
 // 0x1000 Entry 4 (size 64 bundles) Alt DTLB (7,46)
 ENTRY(alt_dtlb_miss)
 	DBG_FAULT(4)
+#ifdef XEN
+//#ifdef VHPT_GLOBAL
+//	VHPT_CCHAIN_LOOKUP(alt_dtlb_miss,d)
+//	br.cond.sptk page_fault
+//	;;
+//#endif
+#endif
 	mov r16=cr.ifa		// get address that caused the TLB miss
 	movl r17=PAGE_KERNEL
 	mov r20=cr.isr
@@ -369,6 +422,17 @@ ENTRY(alt_dtlb_miss)
 	cmp.ne p8,p0=r0,r23
 (p9)	cmp.eq.or.andcm p6,p7=IA64_ISR_CODE_LFETCH,r22	// check isr.code field
 (p8)	br.cond.spnt page_fault
+#ifdef XEN
+	;;
+	// FIXME: inadequate test, this is where we test for Xen address
+	// note that 0xf000 (cached) and 0xd000 (uncached) addresses
+	// should be OK.  (Though no I/O is done in Xen, EFI needs uncached
+	// addresses and some domain EFI calls are passed through)
+	tbit.nz p0,p8=r16,60
+(p8)	br.cond.spnt page_fault
+//(p8)	br.cond.spnt 0
+	;;
+#endif
 
 	dep r21=-1,r21,IA64_PSR_ED_BIT,1
 	or r19=r19,r17		// insert PTE control bits into r19
@@ -449,6 +513,9 @@ END(nested_dtlb_miss)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x1800 Entry 6 (size 64 bundles) Instruction Key Miss (24)
 ENTRY(ikey_miss)
+#ifdef XEN
+	REFLECT(6)
+#endif
 	DBG_FAULT(6)
 	FAULT(6)
 END(ikey_miss)
@@ -461,9 +528,16 @@ ENTRY(page_fault)
 	srlz.i
 	;;
 	SAVE_MIN_WITH_COVER
+#ifdef XEN
+	alloc r15=ar.pfs,0,0,4,0
+	mov out0=cr.ifa
+	mov out1=cr.isr
+	mov out3=cr.itir
+#else
 	alloc r15=ar.pfs,0,0,3,0
 	mov out0=cr.ifa
 	mov out1=cr.isr
+#endif
 	adds r3=8,r2				// set up second base pointer
 	;;
 	ssm psr.ic | PSR_DEFAULT_BITS
@@ -484,6 +558,9 @@ END(page_fault)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x1c00 Entry 7 (size 64 bundles) Data Key Miss (12,51)
 ENTRY(dkey_miss)
+#ifdef XEN
+	REFLECT(7)
+#endif
 	DBG_FAULT(7)
 	FAULT(7)
 END(dkey_miss)
@@ -492,6 +569,9 @@ END(dkey_miss)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x2000 Entry 8 (size 64 bundles) Dirty-bit (54)
 ENTRY(dirty_bit)
+#ifdef XEN
+	REFLECT(8)
+#endif
 	DBG_FAULT(8)
 	/*
 	 * What we do here is to simply turn on the dirty bit in the PTE.  We need to
@@ -554,6 +634,9 @@ END(dirty_bit)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x2400 Entry 9 (size 64 bundles) Instruction Access-bit (27)
 ENTRY(iaccess_bit)
+#ifdef XEN
+	REFLECT(9)
+#endif
 	DBG_FAULT(9)
 	// Like Entry 8, except for instruction access
 	mov r16=cr.ifa				// get the address that caused the fault
@@ -619,6 +702,9 @@ END(iaccess_bit)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x2800 Entry 10 (size 64 bundles) Data Access-bit (15,55)
 ENTRY(daccess_bit)
+#ifdef XEN
+	REFLECT(10)
+#endif
 	DBG_FAULT(10)
 	// Like Entry 8, except for data access
 	mov r16=cr.ifa				// get the address that caused the fault
@@ -687,6 +773,16 @@ ENTRY(break_fault)
 	 * to prevent leaking bits from kernel to user level.
 	 */
 	DBG_FAULT(11)
+#ifdef XEN
+	mov r16=cr.isr
+	mov r17=cr.iim
+	mov r31=pr
+	;;
+	cmp.eq p7,p0=r0,r17			// is this a psuedo-cover?
+	// FIXME: may also need to check slot==2?
+(p7)	br.sptk.many dispatch_privop_fault
+	br.sptk.many dispatch_break_fault
+#endif
 	mov r16=IA64_KR(CURRENT)		// r16 = current task; 12 cycle read lat.
 	mov r17=cr.iim
 	mov r18=__IA64_BREAK_SYSCALL
@@ -697,7 +793,9 @@ ENTRY(break_fault)
 	mov r27=ar.rsc
 	mov r26=ar.pfs
 	mov r28=cr.iip
+#ifndef XEN
 	mov r31=pr				// prepare to save predicates
+#endif
 	mov r20=r1
 	;;
 	adds r16=IA64_TASK_THREAD_ON_USTACK_OFFSET,r16
@@ -797,6 +895,36 @@ END(interrupt)
 	DBG_FAULT(13)
 	FAULT(13)
 
+#ifdef XEN
+	// There is no particular reason for this code to be here, other than that
+	// there happens to be space here that would go unused otherwise.  If this
+	// fault ever gets "unreserved", simply moved the following code to a more
+	// suitable spot...
+
+ENTRY(dispatch_break_fault)
+	SAVE_MIN_WITH_COVER
+	;;
+	alloc r14=ar.pfs,0,0,4,0 // now it's safe (must be first in insn group!)
+	mov out0=cr.ifa
+	adds out1=16,sp
+	mov out2=cr.isr		// FIXME: pity to make this slow access twice
+	mov out3=cr.iim		// FIXME: pity to make this slow access twice
+
+	ssm psr.ic | PSR_DEFAULT_BITS
+	;;
+	srlz.i					// guarantee that interruption collection is on
+	;;
+(p15)	ssm psr.i				// restore psr.i
+	adds r3=8,r2				// set up second base pointer
+	;;
+	SAVE_REST
+	movl r14=ia64_leave_kernel
+	;;
+	mov rp=r14
+	br.sptk.many ia64_prepare_handle_break
+END(dispatch_break_fault)
+#endif
+
 	.org ia64_ivt+0x3800
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x3800 Entry 14 (size 64 bundles) Reserved
@@ -850,9 +978,11 @@ END(interrupt)
 	 *	- ar.fpsr: set to kernel settings
 	 */
 GLOBAL_ENTRY(ia64_syscall_setup)
+#ifndef XEN
 #if PT(B6) != 0
 # error This code assumes that b6 is the first field in pt_regs.
 #endif
+#endif
 	st8 [r1]=r19				// save b6
 	add r16=PT(CR_IPSR),r1			// initialize first base pointer
 	add r17=PT(R11),r1			// initialize second base pointer
@@ -992,6 +1122,37 @@ END(dispatch_illegal_op_fault)
 	DBG_FAULT(16)
 	FAULT(16)
 
+#ifdef XEN
+	// There is no particular reason for this code to be here, other than that
+	// there happens to be space here that would go unused otherwise.  If this
+	// fault ever gets "unreserved", simply moved the following code to a more
+	// suitable spot...
+
+ENTRY(dispatch_privop_fault)
+	SAVE_MIN_WITH_COVER
+	;;
+	alloc r14=ar.pfs,0,0,4,0		// now it's safe (must be first in insn group!)
+	mov out0=cr.ifa
+	adds out1=16,sp
+	mov out2=cr.isr		// FIXME: pity to make this slow access twice
+	mov out3=cr.itir
+
+	ssm psr.ic | PSR_DEFAULT_BITS
+	;;
+	srlz.i					// guarantee that interruption collection is on
+	;;
+(p15)	ssm psr.i				// restore psr.i
+	adds r3=8,r2				// set up second base pointer
+	;;
+	SAVE_REST
+	movl r14=ia64_leave_kernel
+	;;
+	mov rp=r14
+	br.sptk.many ia64_prepare_handle_privop
+END(dispatch_privop_fault)
+#endif
+
+
 	.org ia64_ivt+0x4400
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x4400 Entry 17 (size 64 bundles) Reserved
@@ -1108,6 +1269,9 @@ END(dispatch_to_fault_handler)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5000 Entry 20 (size 16 bundles) Page Not Present (10,22,49)
 ENTRY(page_not_present)
+#ifdef XEN
+	REFLECT(20)
+#endif
 	DBG_FAULT(20)
 	mov r16=cr.ifa
 	rsm psr.dt
@@ -1128,6 +1292,9 @@ END(page_not_present)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5100 Entry 21 (size 16 bundles) Key Permission (13,25,52)
 ENTRY(key_permission)
+#ifdef XEN
+	REFLECT(21)
+#endif
 	DBG_FAULT(21)
 	mov r16=cr.ifa
 	rsm psr.dt
@@ -1141,6 +1308,9 @@ END(key_permission)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5200 Entry 22 (size 16 bundles) Instruction Access Rights (26)
 ENTRY(iaccess_rights)
+#ifdef XEN
+	REFLECT(22)
+#endif
 	DBG_FAULT(22)
 	mov r16=cr.ifa
 	rsm psr.dt
@@ -1154,6 +1324,9 @@ END(iaccess_rights)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5300 Entry 23 (size 16 bundles) Data Access Rights (14,53)
 ENTRY(daccess_rights)
+#ifdef XEN
+	REFLECT(23)
+#endif
 	DBG_FAULT(23)
 	mov r16=cr.ifa
 	rsm psr.dt
@@ -1171,8 +1344,13 @@ ENTRY(general_exception)
 	mov r16=cr.isr
 	mov r31=pr
 	;;
+#ifdef XEN
+	cmp4.ge p6,p0=0x20,r16
+(p6)	br.sptk.many dispatch_privop_fault
+#else
 	cmp4.eq p6,p0=0,r16
 (p6)	br.sptk.many dispatch_illegal_op_fault
+#endif
 	;;
 	mov r19=24		// fault number
 	br.sptk.many dispatch_to_fault_handler
@@ -1182,6 +1360,9 @@ END(general_exception)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5500 Entry 25 (size 16 bundles) Disabled FP-Register (35)
 ENTRY(disabled_fp_reg)
+#ifdef XEN
+	REFLECT(25)
+#endif
 	DBG_FAULT(25)
 	rsm psr.dfh		// ensure we can access fph
 	;;
@@ -1195,6 +1376,9 @@ END(disabled_fp_reg)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5600 Entry 26 (size 16 bundles) Nat Consumption (11,23,37,50)
 ENTRY(nat_consumption)
+#ifdef XEN
+	REFLECT(26)
+#endif
 	DBG_FAULT(26)
 	FAULT(26)
 END(nat_consumption)
@@ -1203,6 +1387,10 @@ END(nat_consumption)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5700 Entry 27 (size 16 bundles) Speculation (40)
 ENTRY(speculation_vector)
+#ifdef XEN
+	// this probably need not reflect...
+	REFLECT(27)
+#endif
 	DBG_FAULT(27)
 	/*
 	 * A [f]chk.[as] instruction needs to take the branch to the recovery code but
@@ -1246,6 +1434,9 @@ END(speculation_vector)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5900 Entry 29 (size 16 bundles) Debug (16,28,56)
 ENTRY(debug_vector)
+#ifdef XEN
+	REFLECT(29)
+#endif
 	DBG_FAULT(29)
 	FAULT(29)
 END(debug_vector)
@@ -1254,6 +1445,9 @@ END(debug_vector)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5a00 Entry 30 (size 16 bundles) Unaligned Reference (57)
 ENTRY(unaligned_access)
+#ifdef XEN
+	REFLECT(30)
+#endif
 	DBG_FAULT(30)
 	mov r16=cr.ipsr
 	mov r31=pr		// prepare to save predicates
@@ -1265,6 +1459,9 @@ END(unaligned_access)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5b00 Entry 31 (size 16 bundles) Unsupported Data Reference (57)
 ENTRY(unsupported_data_reference)
+#ifdef XEN
+	REFLECT(31)
+#endif
 	DBG_FAULT(31)
 	FAULT(31)
 END(unsupported_data_reference)
@@ -1273,6 +1470,9 @@ END(unsupported_data_reference)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5c00 Entry 32 (size 16 bundles) Floating-Point Fault (64)
 ENTRY(floating_point_fault)
+#ifdef XEN
+	REFLECT(32)
+#endif
 	DBG_FAULT(32)
 	FAULT(32)
 END(floating_point_fault)
@@ -1281,6 +1481,9 @@ END(floating_point_fault)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5d00 Entry 33 (size 16 bundles) Floating Point Trap (66)
 ENTRY(floating_point_trap)
+#ifdef XEN
+	REFLECT(33)
+#endif
 	DBG_FAULT(33)
 	FAULT(33)
 END(floating_point_trap)
@@ -1289,6 +1492,9 @@ END(floating_point_trap)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5e00 Entry 34 (size 16 bundles) Lower Privilege Transfer Trap (66)
 ENTRY(lower_privilege_trap)
+#ifdef XEN
+	REFLECT(34)
+#endif
 	DBG_FAULT(34)
 	FAULT(34)
 END(lower_privilege_trap)
@@ -1297,6 +1503,9 @@ END(lower_privilege_trap)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x5f00 Entry 35 (size 16 bundles) Taken Branch Trap (68)
 ENTRY(taken_branch_trap)
+#ifdef XEN
+	REFLECT(35)
+#endif
 	DBG_FAULT(35)
 	FAULT(35)
 END(taken_branch_trap)
@@ -1305,6 +1514,9 @@ END(taken_branch_trap)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x6000 Entry 36 (size 16 bundles) Single Step Trap (69)
 ENTRY(single_step_trap)
+#ifdef XEN
+	REFLECT(36)
+#endif
 	DBG_FAULT(36)
 	FAULT(36)
 END(single_step_trap)
@@ -1361,6 +1573,9 @@ END(single_step_trap)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x6900 Entry 45 (size 16 bundles) IA-32 Exeception (17,18,29,41,42,43,44,58,60,61,62,72,73,75,76,77)
 ENTRY(ia32_exception)
+#ifdef XEN
+	REFLECT(45)
+#endif
 	DBG_FAULT(45)
 	FAULT(45)
 END(ia32_exception)
@@ -1369,6 +1584,9 @@ END(ia32_exception)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x6a00 Entry 46 (size 16 bundles) IA-32 Intercept  (30,31,59,70,71)
 ENTRY(ia32_intercept)
+#ifdef XEN
+	REFLECT(46)
+#endif
 	DBG_FAULT(46)
 #ifdef	CONFIG_IA32_SUPPORT
 	mov r31=pr
@@ -1399,6 +1617,9 @@ END(ia32_intercept)
 /////////////////////////////////////////////////////////////////////////////////////////
 // 0x6b00 Entry 47 (size 16 bundles) IA-32 Interrupt  (74)
 ENTRY(ia32_interrupt)
+#ifdef XEN
+	REFLECT(47)
+#endif
 	DBG_FAULT(47)
 #ifdef CONFIG_IA32_SUPPORT
 	mov r31=pr
@@ -1528,6 +1749,39 @@ END(ia32_interrupt)
 	DBG_FAULT(67)
 	FAULT(67)
 
+#ifdef XEN
+	.org ia64_ivt+0x8000
+ENTRY(dispatch_reflection)
+	/*
+	 * Input:
+	 *	psr.ic:	off
+	 *	r19:	intr type (offset into ivt, see ia64_int.h)
+	 *	r31:	contains saved predicates (pr)
+	 */
+	SAVE_MIN_WITH_COVER_R19
+	alloc r14=ar.pfs,0,0,5,0
+	mov out4=r15
+	mov out0=cr.ifa
+	adds out1=16,sp
+	mov out2=cr.isr
+	mov out3=cr.iim
+//	mov out3=cr.itir
+
+	ssm psr.ic | PSR_DEFAULT_BITS
+	;;
+	srlz.i					// guarantee that interruption collection is on
+	;;
+(p15)	ssm psr.i				// restore psr.i
+	adds r3=8,r2				// set up second base pointer
+	;;
+	SAVE_REST
+	movl r14=ia64_leave_kernel
+	;;
+	mov rp=r14
+	br.sptk.many ia64_prepare_handle_reflection
+END(dispatch_reflection)
+#endif
+
 #ifdef CONFIG_IA32_SUPPORT
 
 	/*
