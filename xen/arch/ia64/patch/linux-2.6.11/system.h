 system.h |   15 +++++++++++++++
 1 files changed, 15 insertions(+)

Index: linux-2.6.11-xendiffs/include/asm-ia64/system.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/asm-ia64/system.h	2005-04-07 10:39:11.066701457 -0500
+++ linux-2.6.11-xendiffs/include/asm-ia64/system.h	2005-04-07 10:40:19.540544127 -0500
@@ -24,8 +24,16 @@
  * 0xa000000000000000+2*PERCPU_PAGE_SIZE
  * - 0xa000000000000000+3*PERCPU_PAGE_SIZE remain unmapped (guard page)
  */
+#ifdef XEN
+//#define KERNEL_START		 0xf000000100000000
+#define KERNEL_START		 0xf000000004000000
+#define PERCPU_ADDR		 0xf100000000000000-PERCPU_PAGE_SIZE
+#define SHAREDINFO_ADDR		 0xf100000000000000
+#define VHPT_ADDR		 0xf200000000000000
+#else
 #define KERNEL_START		 __IA64_UL_CONST(0xa000000100000000)
 #define PERCPU_ADDR		(-PERCPU_PAGE_SIZE)
+#endif
 
 #ifndef __ASSEMBLY__
 
@@ -218,9 +226,13 @@ extern void ia64_load_extra (struct task
 # define PERFMON_IS_SYSWIDE() (0)
 #endif
 
+#ifdef XEN
+#define IA64_HAS_EXTRA_STATE(t) 0
+#else
 #define IA64_HAS_EXTRA_STATE(t)							\
 	((t)->thread.flags & (IA64_THREAD_DBG_VALID|IA64_THREAD_PM_VALID)	\
 	 || IS_IA32_PROCESS(ia64_task_regs(t)) || PERFMON_IS_SYSWIDE())
+#endif
 
 #define __switch_to(prev,next,last) do {							 \
 	if (IA64_HAS_EXTRA_STATE(prev))								 \
@@ -249,6 +261,9 @@ extern void ia64_load_extra (struct task
 #else
 # define switch_to(prev,next,last)	__switch_to(prev, next, last)
 #endif
+//#ifdef XEN
+//#undef switch_to
+//#endif
 
 /*
  * On IA-64, we don't want to hold the runqueue's lock during the low-level context-switch,
