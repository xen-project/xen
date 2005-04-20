 kregs.h |    4 ++++
 1 files changed, 4 insertions(+)

Index: linux-2.6.11/include/asm-ia64/kregs.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/kregs.h	2005-03-02 01:37:49.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/kregs.h	2005-03-19 13:44:24.362628092 -0600
@@ -31,6 +31,10 @@
 #define IA64_TR_PALCODE		1	/* itr1: maps PALcode as required by EFI */
 #define IA64_TR_PERCPU_DATA	1	/* dtr1: percpu data */
 #define IA64_TR_CURRENT_STACK	2	/* dtr2: maps kernel's memory- & register-stacks */
+#ifdef XEN
+#define IA64_TR_SHARED_INFO	3	/* dtr3: page shared with domain */
+#define	IA64_TR_VHPT		4	/* dtr4: vhpt */
+#endif
 
 /* Processor status register bits: */
 #define IA64_PSR_BE_BIT		1
