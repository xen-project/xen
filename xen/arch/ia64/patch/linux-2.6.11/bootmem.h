 bootmem.h |    2 ++
 1 files changed, 2 insertions(+)

Index: linux-2.6.11/include/linux/bootmem.h
===================================================================
--- linux-2.6.11.orig/include/linux/bootmem.h	2005-03-02 01:38:25.000000000 -0600
+++ linux-2.6.11/include/linux/bootmem.h	2005-03-19 12:39:36.915887729 -0600
@@ -41,7 +41,9 @@ extern unsigned long __init init_bootmem
 extern void __init free_bootmem (unsigned long addr, unsigned long size);
 extern void * __init __alloc_bootmem (unsigned long size, unsigned long align, unsigned long goal);
 #ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
+#ifndef XEN
 extern void __init reserve_bootmem (unsigned long addr, unsigned long size);
+#endif
 #define alloc_bootmem(x) \
 	__alloc_bootmem((x), SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
 #define alloc_bootmem_low(x) \
