--- ../../linux-2.6.11/arch/ia64/lib/swiotlb.c	2005-03-02 00:38:17.000000000 -0700
+++ arch/ia64/lib/swiotlb.c	2005-05-02 13:04:15.000000000 -0600
@@ -49,6 +49,15 @@
  */
 #define IO_TLB_SHIFT 11
 
+#ifdef XEN
+#define __order_to_size(_order) (1 << (_order+PAGE_SHIFT))
+#define alloc_bootmem_low_pages(_x) alloc_xenheap_pages(get_order(_x))
+#define alloc_bootmem_low(_x) alloc_xenheap_pages(get_order(_x))
+#define alloc_bootmem(_x) alloc_xenheap_pages(get_order(_x))
+#define __get_free_pages(_x,_y) alloc_xenheap_pages(__order_to_size(_y))
+#define free_pages(_x,_y) free_xenheap_pages(_x,_y)
+#endif
+
 int swiotlb_force;
 
 /*
@@ -388,8 +397,10 @@
 	 * When the mapping is small enough return a static buffer to limit
 	 * the damage, or panic when the transfer is too big.
 	 */
+#ifndef XEN
 	printk(KERN_ERR "PCI-DMA: Out of SW-IOMMU space for %lu bytes at "
 	       "device %s\n", size, dev ? dev->bus_id : "?");
+#endif
 
 	if (size > io_tlb_overflow && do_panic) {
 		if (dir == PCI_DMA_FROMDEVICE || dir == PCI_DMA_BIDIRECTIONAL)
