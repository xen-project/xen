 slab.h |    4 ++++
 1 files changed, 4 insertions(+)

Index: linux-2.6.11/include/linux/slab.h
===================================================================
--- linux-2.6.11.orig/include/linux/slab.h	2005-03-02 01:38:33.000000000 -0600
+++ linux-2.6.11/include/linux/slab.h	2005-03-19 14:35:19.301871922 -0600
@@ -91,7 +91,11 @@ static inline void *kmalloc(size_t size,
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
