 current.h |    8 ++++++++
 1 files changed, 8 insertions(+)

Index: linux-2.6.11/include/asm-ia64/current.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/current.h	2005-03-02 01:38:19.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/current.h	2005-03-19 12:39:41.410955288 -0600
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
