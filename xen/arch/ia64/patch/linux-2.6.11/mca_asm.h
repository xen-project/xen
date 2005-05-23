--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/asm-ia64/mca_asm.h	2005-03-01 23:38:38.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/mca_asm.h	2005-05-18 12:40:19.000000000 -0700
@@ -26,8 +26,13 @@
  * direct mapped to physical addresses.
  *	1. Lop off bits 61 thru 63 in the virtual address
  */
+#ifdef XEN
+#define INST_VA_TO_PA(addr)							\
+	dep	addr	= 0, addr, 60, 4
+#else // XEN
 #define INST_VA_TO_PA(addr)							\
 	dep	addr	= 0, addr, 61, 3
+#endif // XEN
 /*
  * This macro converts a data virtual address to a physical address
  * Right now for simulation purposes the virtual addresses are
@@ -42,9 +47,15 @@
  * direct mapped to physical addresses.
  *	1. Put 0x7 in bits 61 thru 63.
  */
+#ifdef XEN
+#define DATA_PA_TO_VA(addr,temp)							\
+	mov	temp	= 0xf	;;							\
+	dep	addr	= temp, addr, 60, 4
+#else // XEN
 #define DATA_PA_TO_VA(addr,temp)							\
 	mov	temp	= 0x7	;;							\
 	dep	addr	= temp, addr, 61, 3
+#endif // XEN
 
 #define GET_THIS_PADDR(reg, var)		\
 	mov	reg = IA64_KR(PER_CPU_DATA);;	\
