 processor.h |    4 ++++
 1 files changed, 4 insertions(+)

Index: linux-2.6.11/include/asm-ia64/processor.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/processor.h	2005-03-02 01:37:58.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/processor.h	2005-03-19 14:26:01.062135543 -0600
@@ -408,12 +408,16 @@ extern void ia64_setreg_unknown_kr (void
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
