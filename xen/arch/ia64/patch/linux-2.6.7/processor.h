--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/processor.h	2005-01-23 13:23:36.000000000 -0700
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/processor.h	2004-08-25 19:28:13.000000000 -0600
@@ -406,12 +406,16 @@
  */
 
 /* Return TRUE if task T owns the fph partition of the CPU we're running on. */
+#ifdef XEN
+#define ia64_is_local_fpu_owner(t) 0
+#else
 #define ia64_is_local_fpu_owner(t)								\
 ({												\
 	struct task_struct *__ia64_islfo_task = (t);						\
 	(__ia64_islfo_task->thread.last_fph_cpu == smp_processor_id()				\
 	 && __ia64_islfo_task == (struct task_struct *) ia64_get_kr(IA64_KR_FPU_OWNER));	\
 })
+#endif
 
 /* Mark task T as owning the fph partition of the CPU we're running on. */
 #define ia64_set_local_fpu_owner(t) do {						\
