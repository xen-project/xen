--- /home/adsharma/xeno-unstable-ia64-staging.bk/xen/../../linux-2.6.11/include/asm-ia64/system.h	2005-03-01 23:38:07.000000000 -0800
+++ /home/adsharma/xeno-unstable-ia64-staging.bk/xen/include/asm-ia64/system.h	2005-05-20 09:36:02.000000000 -0700
@@ -18,14 +18,19 @@
 #include <asm/page.h>
 #include <asm/pal.h>
 #include <asm/percpu.h>
+#ifdef XEN
+#include <asm/xensystem.h>
+#endif
 
 #define GATE_ADDR		__IA64_UL_CONST(0xa000000000000000)
 /*
  * 0xa000000000000000+2*PERCPU_PAGE_SIZE
  * - 0xa000000000000000+3*PERCPU_PAGE_SIZE remain unmapped (guard page)
  */
+#ifndef XEN
 #define KERNEL_START		 __IA64_UL_CONST(0xa000000100000000)
 #define PERCPU_ADDR		(-PERCPU_PAGE_SIZE)
+#endif
 
 #ifndef __ASSEMBLY__
 
@@ -218,6 +223,7 @@
 # define PERFMON_IS_SYSWIDE() (0)
 #endif
 
+#ifndef XEN
 #define IA64_HAS_EXTRA_STATE(t)							\
 	((t)->thread.flags & (IA64_THREAD_DBG_VALID|IA64_THREAD_PM_VALID)	\
 	 || IS_IA32_PROCESS(ia64_task_regs(t)) || PERFMON_IS_SYSWIDE())
@@ -230,6 +236,7 @@
 	ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);			 \
 	(last) = ia64_switch_to((next));							 \
 } while (0)
+#endif 
 
 #ifdef CONFIG_SMP
 /*
