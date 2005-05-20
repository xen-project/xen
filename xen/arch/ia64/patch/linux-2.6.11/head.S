--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/arch/ia64/kernel/head.S	2005-03-01 23:38:13.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/arch/ia64/head.S	2005-05-18 12:40:50.000000000 -0700
@@ -76,21 +76,21 @@
 	 * We initialize all of them to prevent inadvertently assuming
 	 * something about the state of address translation early in boot.
 	 */
-	mov r6=((ia64_rid(IA64_REGION_ID_KERNEL, (0<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r6=((ia64_rid(IA64_REGION_ID_KERNEL, (0<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r7=(0<<61)
-	mov r8=((ia64_rid(IA64_REGION_ID_KERNEL, (1<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r8=((ia64_rid(IA64_REGION_ID_KERNEL, (1<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r9=(1<<61)
-	mov r10=((ia64_rid(IA64_REGION_ID_KERNEL, (2<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r10=((ia64_rid(IA64_REGION_ID_KERNEL, (2<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r11=(2<<61)
-	mov r12=((ia64_rid(IA64_REGION_ID_KERNEL, (3<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r12=((ia64_rid(IA64_REGION_ID_KERNEL, (3<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r13=(3<<61)
-	mov r14=((ia64_rid(IA64_REGION_ID_KERNEL, (4<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r14=((ia64_rid(IA64_REGION_ID_KERNEL, (4<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r15=(4<<61)
-	mov r16=((ia64_rid(IA64_REGION_ID_KERNEL, (5<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
+	movl r16=((ia64_rid(IA64_REGION_ID_KERNEL, (5<<61)) << 8) | (PAGE_SHIFT << 2) | 1)
 	movl r17=(5<<61)
-	mov r18=((ia64_rid(IA64_REGION_ID_KERNEL, (6<<61)) << 8) | (IA64_GRANULE_SHIFT << 2))
+	movl r18=((ia64_rid(IA64_REGION_ID_KERNEL, (6<<61)) << 8) | (IA64_GRANULE_SHIFT << 2))
 	movl r19=(6<<61)
-	mov r20=((ia64_rid(IA64_REGION_ID_KERNEL, (7<<61)) << 8) | (IA64_GRANULE_SHIFT << 2))
+	movl r20=((ia64_rid(IA64_REGION_ID_KERNEL, (7<<61)) << 8) | (IA64_GRANULE_SHIFT << 2))
 	movl r21=(7<<61)
 	;;
 	mov rr[r7]=r6
@@ -129,8 +129,13 @@
 	/*
 	 * Switch into virtual mode:
 	 */
+#ifdef CONFIG_VTI
+	movl r16=(IA64_PSR_IT|IA64_PSR_IC|IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_DFH \
+		  |IA64_PSR_DI)
+#else // CONFIG_VTI
 	movl r16=(IA64_PSR_IT|IA64_PSR_IC|IA64_PSR_DT|IA64_PSR_RT|IA64_PSR_DFH|IA64_PSR_BN \
 		  |IA64_PSR_DI)
+#endif // CONFIG_VTI
 	;;
 	mov cr.ipsr=r16
 	movl r17=1f
@@ -143,7 +148,11 @@
 1:	// now we are in virtual mode
 
 	// set IVT entry point---can't access I/O ports without it
+#ifdef CONFIG_VTI
+    movl r3=vmx_ia64_ivt
+#else // CONFIG_VTI
 	movl r3=ia64_ivt
+#endif // CONFIG_VTI
 	;;
 	mov cr.iva=r3
 	movl r2=FPSR_DEFAULT
@@ -187,7 +196,11 @@
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
@@ -207,8 +220,15 @@
 
 .load_current:
 	// load the "current" pointer (r13) and ar.k6 with the current task
+#ifdef CONFIG_VTI
+	mov r21=r2		// virtual address
+	;;
+	bsw.1
+	;;
+#else // CONFIG_VTI
 	mov IA64_KR(CURRENT)=r2		// virtual address
 	mov IA64_KR(CURRENT_STACK)=r16
+#endif // CONFIG_VTI
 	mov r13=r2
 	/*
 	 * Reserve space at the top of the stack for "struct pt_regs".  Kernel threads
@@ -227,7 +247,11 @@
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
@@ -254,7 +278,9 @@
 	br.call.sptk.many b0=console_print
 
 self:	hint @pause
+	;;
 	br.sptk.many self		// endless loop
+	;;
 END(_start)
 
 GLOBAL_ENTRY(ia64_save_debug_regs)
@@ -850,7 +876,11 @@
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
