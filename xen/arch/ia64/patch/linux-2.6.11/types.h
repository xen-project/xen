 types.h |    7 +++++++
 1 files changed, 7 insertions(+)

Index: linux-2.6.11/include/asm-ia64/types.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/types.h	2005-03-02 01:37:49.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/types.h	2005-03-19 14:58:47.628750770 -0600
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
