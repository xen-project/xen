--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/current.h	2004-06-15 23:19:52.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/current.h	2004-08-25 19:28:12.000000000 -0600
@@ -12,6 +12,14 @@
  * In kernel mode, thread pointer (r13) is used to point to the current task
  * structure.
  */
+#ifdef XEN
+struct domain;
+#define get_current()	((struct exec_domain *) ia64_getreg(_IA64_REG_TP))
+#define current get_current()
+//#define set_current(d)	ia64_setreg(_IA64_REG_TP,(void *)d);
+#define set_current(d)		(ia64_r13 = (void *)d)
+#else
 #define current	((struct task_struct *) ia64_getreg(_IA64_REG_TP))
+#endif
 
 #endif /* _ASM_IA64_CURRENT_H */
