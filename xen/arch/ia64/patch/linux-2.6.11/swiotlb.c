 swiotlb.c |   21 +++++++++++++--------
 1 files changed, 13 insertions(+), 8 deletions(-)

Index: linux-2.6.11-xendiffs/arch/ia64/lib/swiotlb.c
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/lib/swiotlb.c	2005-04-08 12:13:54.040202667 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/lib/swiotlb.c	2005-04-08 12:19:09.170367318 -0500
@@ -124,8 +124,11 @@ swiotlb_init_with_default_size (size_t d
 	/*
 	 * Get IO TLB memory from the low pages
 	 */
-	io_tlb_start = alloc_bootmem_low_pages(io_tlb_nslabs *
-					       (1 << IO_TLB_SHIFT));
+	/* FIXME: Do we really need swiotlb in HV? If all memory trunks
+	 * presented to guest as <4G, are actually <4G in machine range,
+	 * no DMA intevention from HV...
+	 */
+	io_tlb_start = alloc_xenheap_pages(get_order(io_tlb_nslabs * (1 << IO_TLB_SHIFT)));
 	if (!io_tlb_start)
 		panic("Cannot allocate SWIOTLB buffer");
 	io_tlb_end = io_tlb_start + io_tlb_nslabs * (1 << IO_TLB_SHIFT);
@@ -135,16 +138,16 @@ swiotlb_init_with_default_size (size_t d
 	 * to find contiguous free memory regions of size up to IO_TLB_SEGSIZE
 	 * between io_tlb_start and io_tlb_end.
 	 */
-	io_tlb_list = alloc_bootmem(io_tlb_nslabs * sizeof(int));
+	io_tlb_list = alloc_xenheap_pages(get_order(io_tlb_nslabs * sizeof(int)));
 	for (i = 0; i < io_tlb_nslabs; i++)
  		io_tlb_list[i] = IO_TLB_SEGSIZE - OFFSET(i, IO_TLB_SEGSIZE);
 	io_tlb_index = 0;
-	io_tlb_orig_addr = alloc_bootmem(io_tlb_nslabs * sizeof(char *));
+	io_tlb_orig_addr = alloc_xenheap_pages(get_order(io_tlb_nslabs * sizeof(char *)));
 
 	/*
 	 * Get the overflow emergency buffer
 	 */
-	io_tlb_overflow_buffer = alloc_bootmem_low(io_tlb_overflow);
+	io_tlb_overflow_buffer = alloc_xenheap_pages(get_order(io_tlb_overflow));
 	printk(KERN_INFO "Placing software IO TLB between 0x%lx - 0x%lx\n",
 	       virt_to_phys(io_tlb_start), virt_to_phys(io_tlb_end));
 }
@@ -328,13 +331,13 @@ swiotlb_alloc_coherent(struct device *hw
 	 */
 	flags |= GFP_DMA;
 
-	ret = (void *)__get_free_pages(flags, order);
+	ret = (void *)alloc_xenheap_pages(get_order(size));
 	if (ret && address_needs_mapping(hwdev, virt_to_phys(ret))) {
 		/*
 		 * The allocated memory isn't reachable by the device.
 		 * Fall back on swiotlb_map_single().
 		 */
-		free_pages((unsigned long) ret, order);
+		free_xenheap_pages((unsigned long) ret, order);
 		ret = NULL;
 	}
 	if (!ret) {
@@ -372,7 +375,7 @@ swiotlb_free_coherent(struct device *hwd
 {
 	if (!(vaddr >= (void *)io_tlb_start
                     && vaddr < (void *)io_tlb_end))
-		free_pages((unsigned long) vaddr, get_order(size));
+		free_xenheap_pages((unsigned long) vaddr, get_order(size));
 	else
 		/* DMA_TO_DEVICE to avoid memcpy in unmap_single */
 		swiotlb_unmap_single (hwdev, dma_handle, size, DMA_TO_DEVICE);
@@ -388,8 +391,10 @@ swiotlb_full(struct device *dev, size_t 
 	 * When the mapping is small enough return a static buffer to limit
 	 * the damage, or panic when the transfer is too big.
 	 */
+#ifndef XEN
 	printk(KERN_ERR "PCI-DMA: Out of SW-IOMMU space for %lu bytes at "
 	       "device %s\n", size, dev ? dev->bus_id : "?");
+#endif
 
 	if (size > io_tlb_overflow && do_panic) {
 		if (dir == PCI_DMA_FROMDEVICE || dir == PCI_DMA_BIDIRECTIONAL)
