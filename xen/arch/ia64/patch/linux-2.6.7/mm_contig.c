--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/mm/contig.c	2004-06-15 23:19:12.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/mm_contig.c	2004-10-05 18:09:45.000000000 -0600
@@ -15,11 +15,23 @@
  * memory.
  */
 #include <linux/config.h>
+#ifdef XEN
+#include <xen/sched.h>
+#endif
 #include <linux/bootmem.h>
 #include <linux/efi.h>
 #include <linux/mm.h>
 #include <linux/swap.h>
 
+#ifdef XEN
+#undef reserve_bootmem
+unsigned long max_mapnr;
+unsigned long num_physpages;
+extern struct page *zero_page_memmap_ptr;
+struct page *mem_map;
+#define MAX_DMA_ADDRESS ~0UL	// FIXME???
+#endif
+
 #include <asm/meminit.h>
 #include <asm/pgalloc.h>
 #include <asm/pgtable.h>
@@ -80,6 +92,9 @@
 {
 	unsigned long *max_pfnp = arg, pfn;
 
+#ifdef XEN
+//printf("find_max_pfn: start=%lx, end=%lx, *arg=%lx\n",start,end,*(unsigned long *)arg);
+#endif
 	pfn = (PAGE_ALIGN(end - 1) - PAGE_OFFSET) >> PAGE_SHIFT;
 	if (pfn > *max_pfnp)
 		*max_pfnp = pfn;
@@ -149,6 +164,9 @@
 	/* first find highest page frame number */
 	max_pfn = 0;
 	efi_memmap_walk(find_max_pfn, &max_pfn);
+#ifdef XEN
+//printf("find_memory: efi_memmap_walk returns max_pfn=%lx\n",max_pfn);
+#endif
 
 	/* how many bytes to cover all the pages */
 	bootmap_size = bootmem_bootmap_pages(max_pfn) << PAGE_SHIFT;
@@ -242,6 +260,9 @@
 	efi_memmap_walk(count_pages, &num_physpages);
 
 	max_dma = virt_to_phys((void *) MAX_DMA_ADDRESS) >> PAGE_SHIFT;
+#ifdef XEN
+//printf("paging_init: num_physpages=%lx, max_dma=%lx\n",num_physpages,max_dma);
+#endif
 
 #ifdef CONFIG_VIRTUAL_MEM_MAP
 	memset(zholes_size, 0, sizeof(zholes_size));
@@ -265,7 +286,13 @@
 
 	max_gap = 0;
 	efi_memmap_walk(find_largest_hole, (u64 *)&max_gap);
+#ifdef XEN
+//printf("paging_init: max_gap=%lx\n",max_gap);
+#endif
 	if (max_gap < LARGE_GAP) {
+#ifdef XEN
+//printf("paging_init: no large gap\n");
+#endif
 		vmem_map = (struct page *) 0;
 		free_area_init_node(0, &contig_page_data, NULL, zones_size, 0,
 				    zholes_size);
@@ -274,6 +301,9 @@
 		unsigned long map_size;
 
 		/* allocate virtual_mem_map */
+#ifdef XEN
+//printf("paging_init: large gap, allocating virtual_mem_map\n");
+#endif
 
 		map_size = PAGE_ALIGN(max_low_pfn * sizeof(struct page));
 		vmalloc_end -= map_size;
@@ -293,6 +323,10 @@
 		zones_size[ZONE_DMA] = max_dma;
 		zones_size[ZONE_NORMAL] = max_low_pfn - max_dma;
 	}
+#ifdef XEN
+//printf("paging_init: zones_size[ZONE_DMA]=%lx, zones_size[ZONE_NORMAL]=%lx, max_low_pfn=%lx\n",
+//zones_size[ZONE_DMA],zones_size[ZONE_NORMAL],max_low_pfn);
+#endif
 	free_area_init(zones_size);
 #endif /* !CONFIG_VIRTUAL_MEM_MAP */
 	zero_page_memmap_ptr = virt_to_page(ia64_imva(empty_zero_page));
