--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/sal.h	2004-06-15 23:20:04.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/sal.h	2004-10-27 13:55:23.000000000 -0600
@@ -646,7 +646,23 @@
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
