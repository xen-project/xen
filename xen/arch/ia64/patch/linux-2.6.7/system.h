--- ../../linux-2.6.7/include/asm-ia64/system.h	2005-01-31 11:15:23.000000000 -0700
+++ include/asm-ia64/system.h	2005-03-14 11:31:12.000000000 -0700
@@ -24,8 +24,16 @@
  * 0xa000000000000000+2*PERCPU_PAGE_SIZE
  * - 0xa000000000000000+3*PERCPU_PAGE_SIZE remain unmapped (guard page)
  */
+#ifdef XEN
+//#define KERNEL_START		 0xfffc000100000000
+#define KERNEL_START		 0xfffc000004000000
+#define PERCPU_ADDR		 0xfffd000000000000-PERCPU_PAGE_SIZE
+#define SHAREDINFO_ADDR		 0xfffd000000000000
+#define VHPT_ADDR		 0xfffe000000000000
+#else
 #define KERNEL_START		 0xa000000100000000
 #define PERCPU_ADDR		(-PERCPU_PAGE_SIZE)
+#endif
 
 #ifndef __ASSEMBLY__
 
@@ -218,9 +226,13 @@
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
@@ -249,6 +261,9 @@
 #else
 # define switch_to(prev,next,last)	__switch_to(prev, next, last)
 #endif
+//#ifdef XEN
+//#undef switch_to
+//#endif
 
 /*
  * On IA-64, we don't want to hold the runqueue's lock during the low-level context-switch,
