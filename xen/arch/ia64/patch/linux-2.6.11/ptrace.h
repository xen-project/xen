--- /home/adsharma/disk2/xen-ia64/test3.bk/xen/../../linux-2.6.11/include/asm-ia64/ptrace.h	2005-03-01 23:38:38.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/test3.bk/xen/include/asm-ia64/ptrace.h	2005-05-18 14:00:53.000000000 -0700
@@ -95,6 +95,9 @@
  * (because the memory stack pointer MUST ALWAYS be aligned this way)
  *
  */
+#ifdef CONFIG_VTI
+#include "vmx_ptrace.h"
+#else  //CONFIG_VTI
 struct pt_regs {
 	/* The following registers are saved by SAVE_MIN: */
 	unsigned long b6;		/* scratch */
@@ -170,6 +173,7 @@
 	struct ia64_fpreg f10;		/* scratch */
 	struct ia64_fpreg f11;		/* scratch */
 };
+#endif // CONFIG_VTI
 
 /*
  * This structure contains the addition registers that need to
