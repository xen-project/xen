--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/kregs.h	2004-06-15 23:19:01.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/kregs.h	2004-09-17 18:27:22.000000000 -0600
@@ -30,6 +30,10 @@
 #define IA64_TR_PALCODE		1	/* itr1: maps PALcode as required by EFI */
 #define IA64_TR_PERCPU_DATA	1	/* dtr1: percpu data */
 #define IA64_TR_CURRENT_STACK	2	/* dtr2: maps kernel's memory- & register-stacks */
+#ifdef XEN
+#define IA64_TR_SHARED_INFO	3	/* dtr3: page shared with domain */
+#define	IA64_TR_VHPT		4	/* dtr4: vhpt */
+#endif
 
 /* Processor status register bits: */
 #define IA64_PSR_BE_BIT		1
