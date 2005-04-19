--- ../../linux-2.6.11/include/asm-ia64/types.h	2005-03-04 10:26:30.000000000 -0700
+++ include/asm-ia64/types.h	2005-04-11 15:23:49.000000000 -0600
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
@@ -61,6 +68,28 @@
 typedef __s64 s64;
 typedef __u64 u64;
 
+#ifdef XEN
+/*
+ * Below are truly Linux-specific types that should never collide with
+ * any application/library that wants linux/types.h.
+ */
+
+#ifdef __CHECKER__
+#define __bitwise __attribute__((bitwise))
+#else
+#define __bitwise
+#endif
+
+typedef __u16 __bitwise __le16;
+typedef __u16 __bitwise __be16;
+typedef __u32 __bitwise __le32;
+typedef __u32 __bitwise __be32;
+#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
+typedef __u64 __bitwise __le64;
+typedef __u64 __bitwise __be64;
+#endif
+#endif
+
 #define BITS_PER_LONG 64
 
 /* DMA addresses are 64-bits wide, in general.  */
