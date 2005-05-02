--- ../../linux-2.6.11/arch/ia64/mm/contig.c	2005-03-02 00:37:55.000000000 -0700
+++ arch/ia64/mm_contig.c	2005-04-28 16:13:52.000000000 -0600
@@ -35,6 +35,7 @@
  *
  * Just walks the pages in the system and describes where they're allocated.
  */
+#ifndef XEN
 void
 show_mem (void)
 {
@@ -63,6 +64,7 @@
 	printk("%d pages swap cached\n", cached);
 	printk("%ld pages in page table cache\n", pgtable_cache_size);
 }
+#endif
 
 /* physical address where the bootmem map is located */
 unsigned long bootmap_start;
@@ -140,6 +142,7 @@
  * Walk the EFI memory map and find usable memory for the system, taking
  * into account reserved areas.
  */
+#ifndef XEN
 void
 find_memory (void)
 {
@@ -168,6 +171,7 @@
 
 	find_initrd();
 }
+#endif
 
 #ifdef CONFIG_SMP
 /**
@@ -225,6 +229,7 @@
  * Set up the page tables.
  */
 
+#ifndef XEN
 void
 paging_init (void)
 {
@@ -297,3 +302,4 @@
 #endif /* !CONFIG_VIRTUAL_MEM_MAP */
 	zero_page_memmap_ptr = virt_to_page(ia64_imva(empty_zero_page));
 }
+#endif /* !CONFIG_XEN */
