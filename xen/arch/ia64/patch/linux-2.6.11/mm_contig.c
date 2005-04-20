 contig.c |  172 +++++++++++++++++----------------------------------------------
 1 files changed, 48 insertions(+), 124 deletions(-)

Index: linux-2.6.11-xendiffs/arch/ia64/mm/contig.c
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/mm/contig.c	2005-04-07 11:02:50.227598140 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/mm/contig.c	2005-04-07 11:05:21.724931959 -0500
@@ -15,11 +15,21 @@
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
+extern struct page *zero_page_memmap_ptr;
+struct page *mem_map;
+#define MAX_DMA_ADDRESS ~0UL	// FIXME???
+#endif
+
 #include <asm/meminit.h>
 #include <asm/pgalloc.h>
 #include <asm/pgtable.h>
@@ -38,30 +48,7 @@ static unsigned long num_dma_physpages;
 void
 show_mem (void)
 {
-	int i, total = 0, reserved = 0;
-	int shared = 0, cached = 0;
-
-	printk("Mem-info:\n");
-	show_free_areas();
-
-	printk("Free swap:       %6ldkB\n", nr_swap_pages<<(PAGE_SHIFT-10));
-	i = max_mapnr;
-	while (i-- > 0) {
-		if (!pfn_valid(i))
-			continue;
-		total++;
-		if (PageReserved(mem_map+i))
-			reserved++;
-		else if (PageSwapCache(mem_map+i))
-			cached++;
-		else if (page_count(mem_map + i))
-			shared += page_count(mem_map + i) - 1;
-	}
-	printk("%d pages of RAM\n", total);
-	printk("%d reserved pages\n", reserved);
-	printk("%d pages shared\n", shared);
-	printk("%d pages swap cached\n", cached);
-	printk("%ld pages in page table cache\n", pgtable_cache_size);
+	printk("Dummy show_mem\n");
 }
 
 /* physical address where the bootmem map is located */
@@ -81,6 +68,9 @@ find_max_pfn (unsigned long start, unsig
 {
 	unsigned long *max_pfnp = arg, pfn;
 
+#ifdef XEN
+//printf("find_max_pfn: start=%lx, end=%lx, *arg=%lx\n",start,end,*(unsigned long *)arg);
+#endif
 	pfn = (PAGE_ALIGN(end - 1) - PAGE_OFFSET) >> PAGE_SHIFT;
 	if (pfn > *max_pfnp)
 		*max_pfnp = pfn;
@@ -134,41 +124,6 @@ find_bootmap_location (unsigned long sta
 	return 0;
 }
 
-/**
- * find_memory - setup memory map
- *
- * Walk the EFI memory map and find usable memory for the system, taking
- * into account reserved areas.
- */
-void
-find_memory (void)
-{
-	unsigned long bootmap_size;
-
-	reserve_memory();
-
-	/* first find highest page frame number */
-	max_pfn = 0;
-	efi_memmap_walk(find_max_pfn, &max_pfn);
-
-	/* how many bytes to cover all the pages */
-	bootmap_size = bootmem_bootmap_pages(max_pfn) << PAGE_SHIFT;
-
-	/* look for a location to hold the bootmap */
-	bootmap_start = ~0UL;
-	efi_memmap_walk(find_bootmap_location, &bootmap_size);
-	if (bootmap_start == ~0UL)
-		panic("Cannot find %ld bytes for bootmap\n", bootmap_size);
-
-	bootmap_size = init_bootmem(bootmap_start >> PAGE_SHIFT, max_pfn);
-
-	/* Free all available memory, then mark bootmem-map as being in use. */
-	efi_memmap_walk(filter_rsvd_memory, free_bootmem);
-	reserve_bootmem(bootmap_start, bootmap_size);
-
-	find_initrd();
-}
-
 #ifdef CONFIG_SMP
 /**
  * per_cpu_init - setup per-cpu variables
@@ -228,72 +183,41 @@ count_dma_pages (u64 start, u64 end, voi
 void
 paging_init (void)
 {
-	unsigned long max_dma;
-	unsigned long zones_size[MAX_NR_ZONES];
-#ifdef CONFIG_VIRTUAL_MEM_MAP
-	unsigned long zholes_size[MAX_NR_ZONES];
-	unsigned long max_gap;
-#endif
-
-	/* initialize mem_map[] */
-
-	memset(zones_size, 0, sizeof(zones_size));
-
-	num_physpages = 0;
-	efi_memmap_walk(count_pages, &num_physpages);
-
-	max_dma = virt_to_phys((void *) MAX_DMA_ADDRESS) >> PAGE_SHIFT;
-
-#ifdef CONFIG_VIRTUAL_MEM_MAP
-	memset(zholes_size, 0, sizeof(zholes_size));
+	struct pfn_info *pg;
+	/* Allocate and map the machine-to-phys table */
+	if ((pg = alloc_domheap_pages(NULL, 10)) == NULL)
+		panic("Not enough memory to bootstrap Xen.\n");
+	memset(page_to_virt(pg), 0x55, 16UL << 20);
 
-	num_dma_physpages = 0;
-	efi_memmap_walk(count_dma_pages, &num_dma_physpages);
+	/* Other mapping setup */
 
-	if (max_low_pfn < max_dma) {
-		zones_size[ZONE_DMA] = max_low_pfn;
-		zholes_size[ZONE_DMA] = max_low_pfn - num_dma_physpages;
-	} else {
-		zones_size[ZONE_DMA] = max_dma;
-		zholes_size[ZONE_DMA] = max_dma - num_dma_physpages;
-		if (num_physpages > num_dma_physpages) {
-			zones_size[ZONE_NORMAL] = max_low_pfn - max_dma;
-			zholes_size[ZONE_NORMAL] =
-				((max_low_pfn - max_dma) -
-				 (num_physpages - num_dma_physpages));
-		}
-	}
-
-	max_gap = 0;
-	efi_memmap_walk(find_largest_hole, (u64 *)&max_gap);
-	if (max_gap < LARGE_GAP) {
-		vmem_map = (struct page *) 0;
-		free_area_init_node(0, &contig_page_data, zones_size, 0,
-				    zholes_size);
-	} else {
-		unsigned long map_size;
-
-		/* allocate virtual_mem_map */
-
-		map_size = PAGE_ALIGN(max_low_pfn * sizeof(struct page));
-		vmalloc_end -= map_size;
-		vmem_map = (struct page *) vmalloc_end;
-		efi_memmap_walk(create_mem_map_page_table, NULL);
-
-		mem_map = contig_page_data.node_mem_map = vmem_map;
-		free_area_init_node(0, &contig_page_data, zones_size,
-				    0, zholes_size);
-
-		printk("Virtual mem_map starts at 0x%p\n", mem_map);
-	}
-#else /* !CONFIG_VIRTUAL_MEM_MAP */
-	if (max_low_pfn < max_dma)
-		zones_size[ZONE_DMA] = max_low_pfn;
-	else {
-		zones_size[ZONE_DMA] = max_dma;
-		zones_size[ZONE_NORMAL] = max_low_pfn - max_dma;
-	}
-	free_area_init(zones_size);
-#endif /* !CONFIG_VIRTUAL_MEM_MAP */
 	zero_page_memmap_ptr = virt_to_page(ia64_imva(empty_zero_page));
 }
+
+struct pfn_info *frame_table;
+unsigned long frame_table_size;
+unsigned long max_page;
+
+/* FIXME: postpone support to machines with big holes between physical memorys.
+ * Current hack allows only efi memdesc upto 4G place. (See efi.c)
+ */
+#ifndef CONFIG_VIRTUAL_MEM_MAP
+#define FT_ALIGN_SIZE	(16UL << 20)
+void __init init_frametable(void)
+{
+	unsigned long i, p;
+	frame_table_size = max_page * sizeof(struct pfn_info);
+	frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;
+
+	/* Request continuous trunk from boot allocator, since HV
+	 * address is identity mapped */
+	p = alloc_boot_pages(frame_table_size, FT_ALIGN_SIZE);
+	if (p == 0)
+		panic("Not enough memory for frame table.\n");
+
+	frame_table = __va(p);
+	memset(frame_table, 0, frame_table_size);
+	printk("size of frame_table: %lukB\n",
+		frame_table_size >> 10);
+}
+#endif
