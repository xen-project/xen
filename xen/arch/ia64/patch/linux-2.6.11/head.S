--- ../../linux-2.6.11/arch/ia64/kernel/head.S	2005-03-02 00:38:13.000000000 -0700
+++ arch/ia64/head.S	2005-04-28 10:51:19.000000000 -0600
@@ -187,7 +187,11 @@
 	dep r18=0,r3,0,12
 	;;
 	or r18=r17,r18
+#ifdef XEN
+	dep r2=-1,r3,60,4	// IMVA of task
+#else
 	dep r2=-1,r3,61,3	// IMVA of task
+#endif
 	;;
 	mov r17=rr[r2]
 	shr.u r16=r3,IA64_GRANULE_SHIFT
@@ -227,7 +231,11 @@
 	;;
 	mov ar.rsc=0x3		// place RSE in eager mode
 
+#ifdef XEN
+(isBP)	dep r28=-1,r28,60,4	// make address virtual
+#else
 (isBP)	dep r28=-1,r28,61,3	// make address virtual
+#endif
 (isBP)	movl r2=ia64_boot_param
 	;;
 (isBP)	st8 [r2]=r28		// save the address of the boot param area passed by the bootloader
@@ -254,7 +262,9 @@
 	br.call.sptk.many b0=console_print
 
 self:	hint @pause
+	;;
 	br.sptk.many self		// endless loop
+	;;
 END(_start)
 
 GLOBAL_ENTRY(ia64_save_debug_regs)
@@ -850,7 +860,11 @@
  * intermediate precision so that we can produce a full 64-bit result.
  */
 GLOBAL_ENTRY(sched_clock)
+#ifdef XEN
+	movl r8=THIS_CPU(cpu_info) + IA64_CPUINFO_NSEC_PER_CYC_OFFSET
+#else
 	addl r8=THIS_CPU(cpu_info) + IA64_CPUINFO_NSEC_PER_CYC_OFFSET,r0
+#endif
 	mov.m r9=ar.itc		// fetch cycle-counter				(35 cyc)
 	;;
 	ldf8 f8=[r8]
