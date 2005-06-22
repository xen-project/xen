--- ../../linux-2.6.11/include/asm-ia64/uaccess.h	2005-03-02 00:37:53.000000000 -0700
+++ include/asm-ia64/uaccess.h	2005-06-21 21:53:20.000000000 -0600
@@ -32,6 +32,10 @@
  *	David Mosberger-Tang <davidm@hpl.hp.com>
  */
 
+#ifdef CONFIG_VTI
+#include <asm/vmx_uaccess.h>
+#else // CONFIG_VTI
+
 #include <linux/compiler.h>
 #include <linux/errno.h>
 #include <linux/sched.h>
@@ -60,6 +64,11 @@
  * address TASK_SIZE is never valid.  We also need to make sure that the address doesn't
  * point inside the virtually mapped linear page table.
  */
+#ifdef XEN
+/* VT-i reserves bit 60 for the VMM; guest addresses have bit 60 = bit 59 */
+#define IS_VMM_ADDRESS(addr) ((((addr) >> 60) ^ ((addr) >> 59)) & 1)
+#define __access_ok(addr, size, segment) (!IS_VMM_ADDRESS((unsigned long)(addr)))
+#else
 #define __access_ok(addr, size, segment)						\
 ({											\
 	__chk_user_ptr(addr);								\
@@ -67,6 +76,7 @@
 	 && ((segment).seg == KERNEL_DS.seg						\
 	     || likely(REGION_OFFSET((unsigned long) (addr)) < RGN_MAP_LIMIT)));	\
 })
+#endif
 #define access_ok(type, addr, size)	__access_ok((addr), (size), get_fs())
 
 static inline int
@@ -343,6 +353,7 @@
 	__su_ret;						\
 })
 
+#endif // CONFIG_VTI
 /* Generic code can't deal with the location-relative format that we use for compactness.  */
 #define ARCH_HAS_SORT_EXTABLE
 #define ARCH_HAS_SEARCH_EXTABLE
