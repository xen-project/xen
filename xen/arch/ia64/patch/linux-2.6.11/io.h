--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/asm-ia64/io.h	2005-03-01 23:38:34.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/io.h	2005-05-18 12:40:50.000000000 -0700
@@ -23,7 +23,11 @@
 #define __SLOW_DOWN_IO	do { } while (0)
 #define SLOW_DOWN_IO	do { } while (0)
 
+#ifdef XEN
+#define __IA64_UNCACHED_OFFSET	0xd000000000000000UL	/* region 6 */
+#else
 #define __IA64_UNCACHED_OFFSET	0xc000000000000000UL	/* region 6 */
+#endif
 
 /*
  * The legacy I/O space defined by the ia64 architecture supports only 65536 ports, but
