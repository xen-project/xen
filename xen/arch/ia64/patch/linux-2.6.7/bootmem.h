--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/bootmem.h	2004-06-15 23:19:52.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/bootmem.h	2004-08-25 19:28:13.000000000 -0600
@@ -41,7 +41,9 @@
 extern void __init free_bootmem (unsigned long addr, unsigned long size);
 extern void * __init __alloc_bootmem (unsigned long size, unsigned long align, unsigned long goal);
 #ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
+#ifndef XEN
 extern void __init reserve_bootmem (unsigned long addr, unsigned long size);
+#endif
 #define alloc_bootmem(x) \
 	__alloc_bootmem((x), SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
 #define alloc_bootmem_low(x) \
