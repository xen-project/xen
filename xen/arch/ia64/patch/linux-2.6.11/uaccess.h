--- ../../linux-2.6.11/include/asm-ia64/uaccess.h	2005-06-06 10:36:23.000000000 -0600
+++ include/asm-ia64/uaccess.h	2005-06-10 18:08:06.000000000 -0600
@@ -60,6 +60,11 @@
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
@@ -67,6 +72,7 @@
 	 && ((segment).seg == KERNEL_DS.seg						\
 	     || likely(REGION_OFFSET((unsigned long) (addr)) < RGN_MAP_LIMIT)));	\
 })
+#endif
 #define access_ok(type, addr, size)	__access_ok((addr), (size), get_fs())
 
 static inline int
