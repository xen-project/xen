--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/types.h	2004-06-15 23:19:01.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/types.h	2004-11-11 17:08:30.000000000 -0700
@@ -1,5 +1,12 @@
 #ifndef _ASM_IA64_TYPES_H
 #define _ASM_IA64_TYPES_H
+#ifdef XEN
+#ifndef __ASSEMBLY__
+typedef unsigned long ssize_t;
+typedef unsigned long size_t;
+typedef long long loff_t;
+#endif
+#endif
 
 /*
  * This file is never included by application software unless explicitly requested (e.g.,
