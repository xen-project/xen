--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/io.h	2004-06-15 23:18:57.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/io.h	2004-11-05 16:53:36.000000000 -0700
@@ -23,7 +23,11 @@
 #define __SLOW_DOWN_IO	do { } while (0)
 #define SLOW_DOWN_IO	do { } while (0)
 
+#ifdef XEN
+#define __IA64_UNCACHED_OFFSET	0xdffc000000000000	/* region 6 */
+#else
 #define __IA64_UNCACHED_OFFSET	0xc000000000000000	/* region 6 */
+#endif
 
 /*
  * The legacy I/O space defined by the ia64 architecture supports only 65536 ports, but
