--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/mm/page_alloc.c	2004-06-15 23:18:57.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/page_alloc.c	2004-12-17 13:47:03.000000000 -0700
@@ -19,20 +19,28 @@
 #include <linux/mm.h>
 #include <linux/swap.h>
 #include <linux/interrupt.h>
+#ifndef XEN
 #include <linux/pagemap.h>
+#endif
 #include <linux/bootmem.h>
 #include <linux/compiler.h>
 #include <linux/module.h>
+#ifndef XEN
 #include <linux/suspend.h>
 #include <linux/pagevec.h>
 #include <linux/blkdev.h>
+#endif
 #include <linux/slab.h>
+#ifndef XEN
 #include <linux/notifier.h>
+#endif
 #include <linux/topology.h>
+#ifndef XEN
 #include <linux/sysctl.h>
 #include <linux/cpu.h>
 
 #include <asm/tlbflush.h>
+#endif
 
 DECLARE_BITMAP(node_online_map, MAX_NUMNODES);
 struct pglist_data *pgdat_list;
@@ -71,6 +79,9 @@
 
 static void bad_page(const char *function, struct page *page)
 {
+#ifdef XEN
+printk("bad_page: called but disabled\n");
+#else
 	printk(KERN_EMERG "Bad page state at %s (in process '%s', page %p)\n",
 		function, current->comm, page);
 	printk(KERN_EMERG "flags:0x%08lx mapping:%p mapcount:%d count:%d\n",
@@ -91,6 +102,7 @@
 	set_page_count(page, 0);
 	page->mapping = NULL;
 	page->mapcount = 0;
+#endif
 }
 
 #ifndef CONFIG_HUGETLB_PAGE
@@ -218,6 +230,7 @@
 
 static inline void free_pages_check(const char *function, struct page *page)
 {
+#ifndef XEN
 	if (	page_mapped(page) ||
 		page->mapping != NULL ||
 		page_count(page) != 0 ||
@@ -233,6 +246,7 @@
 			1 << PG_swapcache |
 			1 << PG_writeback )))
 		bad_page(function, page);
+#endif
 	if (PageDirty(page))
 		ClearPageDirty(page);
 }
@@ -276,6 +290,9 @@
 
 void __free_pages_ok(struct page *page, unsigned int order)
 {
+#ifdef XEN
+printk("__free_pages_ok: called but disabled\n");
+#else
 	LIST_HEAD(list);
 	int i;
 
@@ -285,6 +302,7 @@
 	list_add(&page->lru, &list);
 	kernel_map_pages(page, 1<<order, 0);
 	free_pages_bulk(page_zone(page), 1, &list, order);
+#endif
 }
 
 #define MARK_USED(index, order, area) \
@@ -330,6 +348,7 @@
  */
 static void prep_new_page(struct page *page, int order)
 {
+#ifndef XEN
 	if (page->mapping || page_mapped(page) ||
 	    (page->flags & (
 			1 << PG_private	|
@@ -343,11 +362,14 @@
 			1 << PG_swapcache |
 			1 << PG_writeback )))
 		bad_page(__FUNCTION__, page);
+#endif
 
 	page->flags &= ~(1 << PG_uptodate | 1 << PG_error |
 			1 << PG_referenced | 1 << PG_arch_1 |
 			1 << PG_checked | 1 << PG_mappedtodisk);
+#ifndef XEN
 	page->private = 0;
+#endif
 	set_page_refs(page, order);
 }
 
@@ -590,13 +612,17 @@
 	unsigned long min;
 	struct zone **zones;
 	struct page *page;
+#ifndef XEN
 	struct reclaim_state reclaim_state;
+#endif
 	struct task_struct *p = current;
 	int i;
 	int alloc_type;
 	int do_retry;
 
+#ifndef XEN
 	might_sleep_if(wait);
+#endif
 
 	zones = zonelist->zones;  /* the list of zones suitable for gfp_mask */
 	if (zones[0] == NULL)     /* no zones in the zonelist */
@@ -610,12 +636,14 @@
 
 		min = (1<<order) + z->protection[alloc_type];
 
+#ifndef XEN
 		/*
 		 * We let real-time tasks dip their real-time paws a little
 		 * deeper into reserves.
 		 */
 		if (rt_task(p))
 			min -= z->pages_low >> 1;
+#endif
 
 		if (z->free_pages >= min ||
 				(!wait && z->free_pages >= z->pages_high)) {
@@ -627,9 +655,11 @@
 		}
 	}
 
+#ifndef XEN
 	/* we're somewhat low on memory, failed to find what we needed */
 	for (i = 0; zones[i] != NULL; i++)
 		wakeup_kswapd(zones[i]);
+#endif
 
 	/* Go through the zonelist again, taking __GFP_HIGH into account */
 	for (i = 0; zones[i] != NULL; i++) {
@@ -639,8 +669,10 @@
 
 		if (gfp_mask & __GFP_HIGH)
 			min -= z->pages_low >> 2;
+#ifndef XEN
 		if (rt_task(p))
 			min -= z->pages_low >> 1;
+#endif
 
 		if (z->free_pages >= min ||
 				(!wait && z->free_pages >= z->pages_high)) {
@@ -654,6 +686,7 @@
 
 	/* here we're in the low on memory slow path */
 
+#ifndef XEN
 rebalance:
 	if ((p->flags & (PF_MEMALLOC | PF_MEMDIE)) && !in_interrupt()) {
 		/* go through the zonelist yet again, ignoring mins */
@@ -681,6 +714,7 @@
 
 	p->reclaim_state = NULL;
 	p->flags &= ~PF_MEMALLOC;
+#endif
 
 	/* go through the zonelist yet one more time */
 	for (i = 0; zones[i] != NULL; i++) {
@@ -698,6 +732,11 @@
 		}
 	}
 
+#ifdef XEN
+printk(KERN_WARNING "%s: page allocation failure."
+			" order:%d, mode:0x%x\n",
+			"(xen tasks have no comm)", order, gfp_mask);
+#else
 	/*
 	 * Don't let big-order allocations loop unless the caller explicitly
 	 * requests that.  Wait for some write requests to complete then retry.
@@ -724,6 +763,7 @@
 			p->comm, order, gfp_mask);
 		dump_stack();
 	}
+#endif
 	return NULL;
 got_pg:
 	kernel_map_pages(page, 1 << order, 1);
@@ -808,6 +848,7 @@
 
 EXPORT_SYMBOL(get_zeroed_page);
 
+#ifndef XEN
 void __pagevec_free(struct pagevec *pvec)
 {
 	int i = pagevec_count(pvec);
@@ -815,10 +856,15 @@
 	while (--i >= 0)
 		free_hot_cold_page(pvec->pages[i], pvec->cold);
 }
+#endif
 
 fastcall void __free_pages(struct page *page, unsigned int order)
 {
+#ifdef XEN
+	if (!PageReserved(page)) {
+#else
 	if (!PageReserved(page) && put_page_testzero(page)) {
+#endif
 		if (order == 0)
 			free_hot_page(page);
 		else
@@ -914,6 +960,13 @@
 	return nr_free_zone_pages(GFP_HIGHUSER & GFP_ZONEMASK);
 }
 
+#ifdef XEN
+unsigned int nr_free_highpages (void)
+{
+printf("nr_free_highpages: called but not implemented\n");
+}
+#endif
+
 #ifdef CONFIG_HIGHMEM
 unsigned int nr_free_highpages (void)
 {
@@ -1022,6 +1075,7 @@
 
 void si_meminfo(struct sysinfo *val)
 {
+#ifndef XEN
 	val->totalram = totalram_pages;
 	val->sharedram = 0;
 	val->freeram = nr_free_pages();
@@ -1034,6 +1088,7 @@
 	val->freehigh = 0;
 #endif
 	val->mem_unit = PAGE_SIZE;
+#endif
 }
 
 EXPORT_SYMBOL(si_meminfo);
@@ -1165,7 +1220,9 @@
 		printk("= %lukB\n", K(total));
 	}
 
+#ifndef XEN
 	show_swap_cache_info();
+#endif
 }
 
 /*
@@ -1530,6 +1587,9 @@
 		zone->wait_table_size = wait_table_size(size);
 		zone->wait_table_bits =
 			wait_table_bits(zone->wait_table_size);
+#ifdef XEN
+//printf("free_area_init_core-1: calling alloc_bootmem_node(%lx,%lx)\n",pgdat,zone->wait_table_size * sizeof(wait_queue_head_t));
+#endif
 		zone->wait_table = (wait_queue_head_t *)
 			alloc_bootmem_node(pgdat, zone->wait_table_size
 						* sizeof(wait_queue_head_t));
@@ -1584,6 +1644,9 @@
 			 */
 			bitmap_size = (size-1) >> (i+4);
 			bitmap_size = LONG_ALIGN(bitmap_size+1);
+#ifdef XEN
+//printf("free_area_init_core-2: calling alloc_bootmem_node(%lx,%lx)\n",pgdat, bitmap_size);
+#endif
 			zone->free_area[i].map = 
 			  (unsigned long *) alloc_bootmem_node(pgdat, bitmap_size);
 		}
@@ -1601,6 +1664,9 @@
 	calculate_zone_totalpages(pgdat, zones_size, zholes_size);
 	if (!node_mem_map) {
 		size = (pgdat->node_spanned_pages + 1) * sizeof(struct page);
+#ifdef XEN
+//printf("free_area_init_node: calling alloc_bootmem_node(%lx,%lx)\n",pgdat,size);
+#endif
 		node_mem_map = alloc_bootmem_node(pgdat, size);
 	}
 	pgdat->node_mem_map = node_mem_map;
@@ -1784,6 +1850,7 @@
 
 #endif /* CONFIG_PROC_FS */
 
+#ifndef XEN
 #ifdef CONFIG_HOTPLUG_CPU
 static int page_alloc_cpu_notify(struct notifier_block *self,
 				 unsigned long action, void *hcpu)
@@ -2011,3 +2078,4 @@
 	setup_per_zone_protection();
 	return 0;
 }
+#endif
