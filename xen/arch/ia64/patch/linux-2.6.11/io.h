 io.h |    4 ++++
 1 files changed, 4 insertions(+)

Index: linux-2.6.11/include/asm-ia64/io.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/io.h	2005-03-02 01:38:34.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/io.h	2005-03-19 13:42:06.541900818 -0600
@@ -23,7 +23,11 @@
 #define __SLOW_DOWN_IO	do { } while (0)
 #define SLOW_DOWN_IO	do { } while (0)
 
+#ifdef XEN
+#define __IA64_UNCACHED_OFFSET	0xdffc000000000000UL	/* region 6 */
+#else
 #define __IA64_UNCACHED_OFFSET	0xc000000000000000UL	/* region 6 */
+#endif
 
 /*
  * The legacy I/O space defined by the ia64 architecture supports only 65536 ports, but
