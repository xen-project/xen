--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/slab.h	2004-06-15 23:20:26.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/slab.h	2004-08-25 19:28:13.000000000 -0600
@@ -83,7 +83,11 @@
 			goto found; \
 		else \
 			i++;
+#ifdef XEN
+#include <linux/kmalloc_sizes.h>
+#else
 #include "kmalloc_sizes.h"
+#endif
 #undef CACHE
 		{
 			extern void __you_cannot_kmalloc_that_much(void);
