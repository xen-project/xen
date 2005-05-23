--- /home/adsharma/xeno-unstable-ia64-staging.bk/xen/../../linux-2.6.11/include/asm-ia64/processor.h	2005-03-01 23:37:58.000000000 -0800
+++ /home/adsharma/xeno-unstable-ia64-staging.bk/xen/include/asm-ia64/processor.h	2005-05-20 09:36:02.000000000 -0700
@@ -94,7 +94,11 @@
 #ifdef CONFIG_NUMA
 #include <asm/nodedata.h>
 #endif
+#ifdef XEN
+#include <asm/xenprocessor.h>
+#endif
 
+#ifndef XEN
 /* like above but expressed as bitfields for more efficient access: */
 struct ia64_psr {
 	__u64 reserved0 : 1;
@@ -133,6 +137,7 @@
 	__u64 bn : 1;
 	__u64 reserved4 : 19;
 };
+#endif
 
 /*
  * CPU type, hardware bug flags, and per-CPU state.  Frequently used
@@ -408,12 +413,14 @@
  */
 
 /* Return TRUE if task T owns the fph partition of the CPU we're running on. */
+#ifndef XEN
 #define ia64_is_local_fpu_owner(t)								\
 ({												\
 	struct task_struct *__ia64_islfo_task = (t);						\
 	(__ia64_islfo_task->thread.last_fph_cpu == smp_processor_id()				\
 	 && __ia64_islfo_task == (struct task_struct *) ia64_get_kr(IA64_KR_FPU_OWNER));	\
 })
+#endif
 
 /* Mark task T as owning the fph partition of the CPU we're running on. */
 #define ia64_set_local_fpu_owner(t) do {						\
