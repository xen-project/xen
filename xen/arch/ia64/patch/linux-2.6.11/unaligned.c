--- ../../linux-2.6.11/arch/ia64/kernel/unaligned.c	2005-03-02 00:38:25.000000000 -0700
+++ arch/ia64/unaligned.c	2005-04-28 15:40:13.000000000 -0600
@@ -437,7 +437,11 @@
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 setreg (unsigned long regnum, unsigned long val, int nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -611,7 +615,11 @@
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 getreg (unsigned long regnum, unsigned long *val, int *nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -1294,6 +1302,9 @@
 void
 ia64_handle_unaligned (unsigned long ifa, struct pt_regs *regs)
 {
+#ifdef XEN
+printk("ia64_handle_unaligned: called, not working yet\n");
+#else
 	struct ia64_psr *ipsr = ia64_psr(regs);
 	mm_segment_t old_fs = get_fs();
 	unsigned long bundle[2];
@@ -1502,4 +1513,5 @@
 	si.si_imm = 0;
 	force_sig_info(SIGBUS, &si, current);
 	goto done;
+#endif
 }
