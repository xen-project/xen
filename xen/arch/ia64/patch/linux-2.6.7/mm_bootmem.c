--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/mm/bootmem.c	2004-06-15 23:19:09.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/mm_bootmem.c	2004-12-17 13:47:03.000000000 -0700
@@ -10,7 +10,9 @@
  */
 
 #include <linux/mm.h>
+#ifndef XEN
 #include <linux/kernel_stat.h>
+#endif
 #include <linux/swap.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
@@ -55,6 +57,9 @@
 	bdata->node_bootmem_map = phys_to_virt(mapstart << PAGE_SHIFT);
 	bdata->node_boot_start = (start << PAGE_SHIFT);
 	bdata->node_low_pfn = end;
+#ifdef XEN
+//printk("init_bootmem_core: mapstart=%lx,start=%lx,end=%lx,bdata->node_bootmem_map=%lx,bdata->node_boot_start=%lx,bdata->node_low_pfn=%lx\n",mapstart,start,end,bdata->node_bootmem_map,bdata->node_boot_start,bdata->node_low_pfn);
+#endif
 
 	/*
 	 * Initially all pages are reserved - setup_arch() has to
@@ -146,6 +151,9 @@
 	unsigned long i, start = 0, incr, eidx;
 	void *ret;
 
+#ifdef XEN
+//printf("__alloc_bootmem_core(%lx,%lx,%lx,%lx) called\n",bdata,size,align,goal);
+#endif
 	if(!size) {
 		printk("__alloc_bootmem_core(): zero-sized request\n");
 		BUG();
@@ -153,6 +161,9 @@
 	BUG_ON(align & (align-1));
 
 	eidx = bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT);
+#ifdef XEN
+//printf("__alloc_bootmem_core: eidx=%lx\n",eidx);
+#endif
 	offset = 0;
 	if (align &&
 	    (bdata->node_boot_start & (align - 1UL)) != 0)
@@ -182,6 +193,9 @@
 		unsigned long j;
 		i = find_next_zero_bit(bdata->node_bootmem_map, eidx, i);
 		i = ALIGN(i, incr);
+#ifdef XEN
+//if (i >= eidx) goto fail_block;
+#endif
 		if (test_bit(i, bdata->node_bootmem_map))
 			continue;
 		for (j = i + 1; j < i + areasize; ++j) {
@@ -203,6 +217,9 @@
 	return NULL;
 
 found:
+#ifdef XEN
+//printf("__alloc_bootmem_core: start=%lx\n",start);
+#endif
 	bdata->last_success = start << PAGE_SHIFT;
 	BUG_ON(start >= eidx);
 
@@ -262,6 +279,9 @@
 	page = virt_to_page(phys_to_virt(bdata->node_boot_start));
 	idx = bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT);
 	map = bdata->node_bootmem_map;
+#ifdef XEN
+//printk("free_all_bootmem_core: bdata=%lx, bdata->node_boot_start=%lx, bdata->node_low_pfn=%lx, bdata->node_bootmem_map=%lx\n",bdata,bdata->node_boot_start,bdata->node_low_pfn,bdata->node_bootmem_map);
+#endif
 	for (i = 0; i < idx; ) {
 		unsigned long v = ~map[i / BITS_PER_LONG];
 		if (v) {
@@ -285,6 +305,9 @@
 	 * Now free the allocator bitmap itself, it's not
 	 * needed anymore:
 	 */
+#ifdef XEN
+//printk("About to free the allocator bitmap itself\n");
+#endif
 	page = virt_to_page(bdata->node_bootmem_map);
 	count = 0;
 	for (i = 0; i < ((bdata->node_low_pfn-(bdata->node_boot_start >> PAGE_SHIFT))/8 + PAGE_SIZE-1)/PAGE_SIZE; i++,page++) {
@@ -327,6 +350,9 @@
 	return(init_bootmem_core(&contig_page_data, start, 0, pages));
 }
 
+#ifdef XEN
+#undef reserve_bootmem
+#endif
 #ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
 void __init reserve_bootmem (unsigned long addr, unsigned long size)
 {
