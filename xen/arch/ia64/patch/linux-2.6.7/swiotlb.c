--- ../../linux-2.6.7/arch/ia64/lib/swiotlb.c	2004-06-15 23:19:43.000000000 -0600
+++ arch/ia64/lib/swiotlb.c	2005-03-23 14:54:05.000000000 -0700
@@ -100,7 +100,11 @@
 	/*
 	 * Get IO TLB memory from the low pages
 	 */
-	io_tlb_start = alloc_bootmem_low_pages(io_tlb_nslabs * (1 << IO_TLB_SHIFT));
+	/* FIXME: Do we really need swiotlb in HV? If all memory trunks
+	 * presented to guest as <4G, are actually <4G in machine range,
+	 * no DMA intevention from HV...
+	 */
+	io_tlb_start = alloc_xenheap_pages(get_order(io_tlb_nslabs * (1 << IO_TLB_SHIFT)));
 	if (!io_tlb_start)
 		BUG();
 	io_tlb_end = io_tlb_start + io_tlb_nslabs * (1 << IO_TLB_SHIFT);
@@ -110,11 +114,11 @@
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
 
 	printk(KERN_INFO "Placing software IO TLB between 0x%p - 0x%p\n",
 	       (void *) io_tlb_start, (void *) io_tlb_end);
@@ -279,7 +283,7 @@
 	/* XXX fix me: the DMA API should pass us an explicit DMA mask instead: */
 	flags |= GFP_DMA;
 
-	ret = (void *)__get_free_pages(flags, get_order(size));
+	ret = (void *)alloc_xenheap_pages(get_order(size));
 	if (!ret)
 		return NULL;
 
@@ -294,7 +298,7 @@
 void
 swiotlb_free_coherent (struct device *hwdev, size_t size, void *vaddr, dma_addr_t dma_handle)
 {
-	free_pages((unsigned long) vaddr, get_order(size));
+	free_xenheap_pages((unsigned long) vaddr, get_order(size));
 }
 
 /*
