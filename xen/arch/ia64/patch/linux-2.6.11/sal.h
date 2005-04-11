 sal.h |   17 +++++++++++++++++
 1 files changed, 17 insertions(+)

Index: linux-2.6.11-xendiffs/include/asm-ia64/sal.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/asm-ia64/sal.h	2005-04-08 12:00:53.510988510 -0500
+++ linux-2.6.11-xendiffs/include/asm-ia64/sal.h	2005-04-08 12:02:17.778587216 -0500
@@ -36,6 +36,7 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/bcd.h>
+#include <linux/preempt.h>
 #include <linux/spinlock.h>
 #include <linux/efi.h>
 
@@ -650,7 +651,23 @@ ia64_sal_freq_base (unsigned long which,
 {
 	struct ia64_sal_retval isrv;
 
+//#ifdef XEN
+#if 0
+	unsigned long *x = (unsigned long *)ia64_sal;
+	unsigned long *inst = (unsigned long *)*x;
+	unsigned long __ia64_sc_flags;
+	struct ia64_fpreg __ia64_sc_fr[6];
+printf("ia64_sal_freq_base: about to save_scratch_fpregs\n");
+	ia64_save_scratch_fpregs(__ia64_sc_fr);
+	spin_lock_irqsave(&sal_lock, __ia64_sc_flags);
+printf("ia64_sal_freq_base: about to call, ia64_sal=%p, ia64_sal[0]=%p, ia64_sal[1]=%p\n",x,x[0],x[1]);
+printf("first inst=%p,%p\n",inst[0],inst[1]);
+	isrv = (*ia64_sal)(SAL_FREQ_BASE, which, 0, 0, 0, 0, 0, 0);
+	spin_unlock_irqrestore(&sal_lock, __ia64_sc_flags);
+	ia64_load_scratch_fpregs(__ia64_sc_fr);
+#else
 	SAL_CALL(isrv, SAL_FREQ_BASE, which, 0, 0, 0, 0, 0, 0);
+#endif
 	*ticks_per_second = isrv.v0;
 	*drift_info = isrv.v1;
 	return isrv.status;
