--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/minstate.h	2004-06-15 23:19:52.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/minstate.h	2004-12-15 16:36:00.000000000 -0700
@@ -3,6 +3,11 @@
 #include <asm/cache.h>
 
 #include "entry.h"
+#ifdef XEN
+//this can be removed when offsets.h is properly generated
+#undef IA64_TASK_THREAD_ON_USTACK_OFFSET
+#define IA64_TASK_THREAD_ON_USTACK_OFFSET 0x34
+#endif
 
 /*
  * For ivt.s we want to access the stack virtually so we don't have to disable translation
