 head.S |   34 ++++++++++++++++++++++++++++++++++
 1 files changed, 34 insertions(+)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/head.S
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/head.S	2005-04-07 10:56:19.225128582 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/head.S	2005-04-07 11:00:21.718513399 -0500
@@ -1,3 +1,8 @@
+#ifdef XEN
+#define	console_print	printf
+#define kernel_thread_helper 0
+#define sys_exit 0
+#endif
 /*
  * Here is where the ball gets rolling as far as the kernel is concerned.
  * When control is transferred to _start, the bootload has already
@@ -187,7 +192,11 @@ start_ap:
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
@@ -227,7 +236,11 @@ start_ap:
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
@@ -245,7 +258,21 @@ start_ap:
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
@@ -254,7 +281,9 @@ start_ap:
 	br.call.sptk.many b0=console_print
 
 self:	hint @pause
+	;;
 	br.sptk.many self		// endless loop
+	;;
 END(_start)
 
 GLOBAL_ENTRY(ia64_save_debug_regs)
@@ -850,7 +879,12 @@ END(ia64_delay_loop)
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
