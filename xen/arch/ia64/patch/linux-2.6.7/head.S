--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/head.S	2005-01-23 13:23:36.000000000 -0700
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/head.S	2004-12-17 13:47:03.000000000 -0700
@@ -1,3 +1,8 @@
+#ifdef XEN
+#define	console_print	printf
+#define kernel_thread_helper 0
+#define sys_exit 0
+#endif
 /*
  * Here is where the ball gets rolling as far as the kernel is concerned.
  * When control is transferred to _start, the bootload has already
@@ -166,7 +171,11 @@
 	dep r18=0,r3,0,12
 	;;
 	or r18=r17,r18
+#ifdef XEN
+	dep r2=-1,r3,50,14	// IMVA of task
+#else
 	dep r2=-1,r3,61,3	// IMVA of task
+#endif
 	;;
 	mov r17=rr[r2]
 	;;
@@ -205,7 +214,11 @@
 	;;
 	mov ar.rsc=0x3		// place RSE in eager mode
 
+#ifdef XEN
+(isBP)	dep r28=-1,r28,50,14	// make address virtual
+#else
 (isBP)	dep r28=-1,r28,61,3	// make address virtual
+#endif
 (isBP)	movl r2=ia64_boot_param
 	;;
 (isBP)	st8 [r2]=r28		// save the address of the boot param area passed by the bootloader
@@ -238,14 +251,30 @@
 	br.call.sptk.many rp=sys_fw_init
 .ret1:
 #endif
+#ifdef XEN
+	alloc r2=ar.pfs,8,0,2,0
+	;;
+#define fake_mbi_magic 0
+#define MULTIBOOT_INFO_SIZE	1024
+	.rodata
+fake_mbi:
+	.skip MULTIBOOT_INFO_SIZE
+	.previous
+	movl out0=fake_mbi
+	;;
+	br.call.sptk.many rp=cmain
+#else
 	br.call.sptk.many rp=start_kernel
+#endif
 .ret2:	addl r3=@ltoff(halt_msg),gp
 	;;
 	alloc r2=ar.pfs,8,0,2,0
 	;;
 	ld8 out0=[r3]
 	br.call.sptk.many b0=console_print
+	;;
 self:	br.sptk.many self		// endless loop
+	;;
 END(_start)
 
 GLOBAL_ENTRY(ia64_save_debug_regs)
@@ -781,8 +810,13 @@
 	movl r18=KERNEL_START
 	dep r3=0,r3,KERNEL_TR_PAGE_SHIFT,64-KERNEL_TR_PAGE_SHIFT
 	dep r14=0,r14,KERNEL_TR_PAGE_SHIFT,64-KERNEL_TR_PAGE_SHIFT
+#ifdef XEN
+	dep r17=-1,r17,50,14
+	dep sp=-1,sp,50,14
+#else
 	dep r17=-1,r17,61,3
 	dep sp=-1,sp,61,3
+#endif
 	;;
 	or r3=r3,r18
 	or r14=r14,r18
@@ -838,7 +872,12 @@
  * intermediate precision so that we can produce a full 64-bit result.
  */
 GLOBAL_ENTRY(sched_clock)
+#ifdef XEN
+	break 0;;	// FIX IA64_CPUINFO_NSEC_PER_CYC_OFFSET
+	//movl r8=THIS_CPU(cpu_info) + IA64_CPUINFO_NSEC_PER_CYC_OFFSET
+#else
 	addl r8=THIS_CPU(cpu_info) + IA64_CPUINFO_NSEC_PER_CYC_OFFSET,r0
+#endif
 	mov.m r9=ar.itc		// fetch cycle-counter				(35 cyc)
 	;;
 	ldf8 f8=[r8]
