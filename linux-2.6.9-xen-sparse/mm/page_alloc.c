/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/config.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>

#include <asm/tlbflush.h>

DECLARE_BITMAP(node_online_map, MAX_NUMNODES);
struct pglist_data *pgdat_list;
unsigned long totalram_pages;
unsigned long totalhigh_pages;
long nr_swap_pages;
int numnodes = 1;
int sysctl_lower_zone_protection = 0;

EXPORT_SYMBOL(totalram_pages);
EXPORT_SYMBOL(nr_swap_pages);

/*
 * Used by page_zone() to look up the address of the struct zone whose
 * id is encoded in the upper bits of page->flags
 */
struct zone *zone_table[1 << (ZONES_SHIFT + NODES_SHIFT)];
EXPORT_SYMBOL(zone_table);

static char *zone_names[MAX_NR_ZONES] = { "DMA", "Normal", "HighMem" };
int min_free_kbytes = 1024;

unsigned long __initdata nr_kernel_pages;
unsigned long __initdata nr_all_pages;

/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int bad_range(struct zone *zone, struct page *page)
{
	if (page_to_pfn(page) >= zone->zone_start_pfn + zone->spanned_pages)
		return 1;
	if (page_to_pfn(page) < zone->zone_start_pfn)
		return 1;
	if (zone != page_zone(page))
		return 1;
	return 0;
}

static void bad_page(const char *function, struct page *page)
{
	printk(KERN_EMERG "Bad page state at %s (in process '%s', page %p)\n",
		function, current->comm, page);
	printk(KERN_EMERG "flags:0x%0*lx mapping:%p mapcount:%d count:%d\n",
		(int)(2*sizeof(page_flags_t)), (unsigned long)page->flags,
		page->mapping, page_mapcount(page), page_count(page));
	printk(KERN_EMERG "Backtrace:\n");
	dump_stack();
	printk(KERN_EMERG "Trying to fix it up, but a reboot is needed\n");
	page->flags &= ~(1 << PG_private	|
			1 << PG_locked	|
			1 << PG_lru	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_swapcache |
			1 << PG_writeback);
	set_page_count(page, 0);
	reset_page_mapcount(page);
	page->mapping = NULL;
}

#ifndef CONFIG_HUGETLB_PAGE
#define prep_compound_page(page, order) do { } while (0)
#define destroy_compound_page(page, order) do { } while (0)
#else
/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page".
 *
 * The remaining PAGE_SIZE pages are called "tail pages".
 *
 * All pages have PG_compound set.  All pages have their ->private pointing at
 * the head page (even the head page has this).
 *
 * The first tail page's ->mapping, if non-zero, holds the address of the
 * compound page's put_page() function.
 *
 * The order of the allocation is stored in the first tail page's ->index
 * This is only for debug at present.  This usage means that zero-order pages
 * may not be compound.
 */
static void prep_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	page[1].mapping = NULL;
	page[1].index = order;
	for (i = 0; i < nr_pages; i++) {
		struct page *p = page + i;

		SetPageCompound(p);
		p->private = (unsigned long)page;
	}
}

static void destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	if (!PageCompound(page))
		return;

	if (page[1].index != order)
		bad_page(__FUNCTION__, page);

	for (i = 0; i < nr_pages; i++) {
		struct page *p = page + i;

		if (!PageCompound(p))
			bad_page(__FUNCTION__, page);
		if (p->private != (unsigned long)page)
			bad_page(__FUNCTION__, page);
		ClearPageCompound(p);
	}
}
#endif		/* CONFIG_HUGETLB_PAGE */

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep one bit for each pair of blocks, which
 * is set to 1 iff only one of the pair is allocated.  So when we
 * are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were   
 * free, the remainder of the region must be split into blocks.   
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.            
 *
 * -- wli
 */

static inline void __free_pages_bulk (struct page *page, struct page *base,
		struct zone *zone, struct free_area *area, unsigned int order)
{
	unsigned long page_idx, index, mask;

	if (order)
		destroy_compound_page(page, order);
	mask = (~0UL) << order;
	page_idx = page - base;
	if (page_idx & ~mask)
		BUG();
	index = page_idx >> (1 + order);

	zone->free_pages += 1 << order;
	while (order < MAX_ORDER-1) {
		struct page *buddy1, *buddy2;

		BUG_ON(area >= zone->free_area + MAX_ORDER);
		if (!__test_and_change_bit(index, area->map))
			/*
			 * the buddy page is still allocated.
			 */
			break;

		/* Move the buddy up one level. */
		buddy1 = base + (page_idx ^ (1 << order));
		buddy2 = base + page_idx;
		BUG_ON(bad_range(zone, buddy1));
		BUG_ON(bad_range(zone, buddy2));
		list_del(&buddy1->lru);
		mask <<= 1;
		order++;
		area++;
		index >>= 1;
		page_idx &= mask;
	}
	list_add(&(base + page_idx)->lru, &area->free_list);
}

static inline void free_pages_check(const char *function, struct page *page)
{
	if (	page_mapped(page) ||
		page->mapping != NULL ||
		page_count(page) != 0 ||
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_reclaim	|
			1 << PG_slab	|
			1 << PG_swapcache |
			1 << PG_writeback )))
		bad_page(function, page);
	if (PageDirty(page))
		ClearPageDirty(page);
}

/*
 * Frees a list of pages. 
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free, or 0 for all on the list.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static int
free_pages_bulk(struct zone *zone, int count,
		struct list_head *list, unsigned int order)
{
	unsigned long flags;
	struct free_area *area;
	struct page *base, *page = NULL;
	int ret = 0;

	base = zone->zone_mem_map;
	area = zone->free_area + order;
	spin_lock_irqsave(&zone->lock, flags);
	zone->all_unreclaimable = 0;
	zone->pages_scanned = 0;
	while (!list_empty(list) && count--) {
		page = list_entry(list->prev, struct page, lru);
		/* have to delete it as __free_pages_bulk list manipulates */
		list_del(&page->lru);
		__free_pages_bulk(page, base, zone, area, order);
		ret++;
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	return ret;
}

void __free_pages_ok(struct page *page, unsigned int order)
{
	LIST_HEAD(list);
	int i;

	arch_free_page(page, order);

	mod_page_state(pgfree, 1 << order);
	for (i = 0 ; i < (1 << order) ; ++i)
		free_pages_check(__FUNCTION__, page + i);
	list_add(&page->lru, &list);
	kernel_map_pages(page, 1<<order, 0);
	free_pages_bulk(page_zone(page), 1, &list, order);
}

#define MARK_USED(index, order, area) \
	__change_bit((index) >> (1+(order)), (area)->map)

/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- wli
 */
static inline struct page *
expand(struct zone *zone, struct page *page,
	 unsigned long index, int low, int high, struct free_area *area)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;
		BUG_ON(bad_range(zone, &page[size]));
		list_add(&page[size].lru, &area->free_list);
		MARK_USED(index + size, high, area);
	}
	return page;
}

static inline void set_page_refs(struct page *page, int order)
{
#ifdef CONFIG_MMU
	set_page_count(page, 1);
#else
	int i;

	/*
	 * We need to reference all the pages for this order, otherwise if
	 * anyone accesses one of the pages with (get/put) it will be freed.
	 */
	for (i = 0; i < (1 << order); i++)
		set_page_count(page+i, 1);
#endif /* CONFIG_MMU */
}

/*
 * This page is about to be returned from the page allocator
 */
static void prep_new_page(struct page *page, int order)
{
	if (page->mapping || page_mapped(page) ||
	    (page->flags & (
			1 << PG_private	|
			1 << PG_locked	|
			1 << PG_lru	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_reclaim	|
			1 << PG_swapcache |
			1 << PG_writeback )))
		bad_page(__FUNCTION__, page);

	page->flags &= ~(1 << PG_uptodate | 1 << PG_error |
			1 << PG_referenced | 1 << PG_arch_1 |
			1 << PG_checked | 1 << PG_mappedtodisk);
	page->private = 0;
	set_page_refs(page, order);
}

/* 
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static struct page *__rmqueue(struct zone *zone, unsigned int order)
{
	struct free_area * area;
	unsigned int current_order;
	struct page *page;
	unsigned int index;

	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = zone->free_area + current_order;
		if (list_empty(&area->free_list))
			continue;

		page = list_entry(area->free_list.next, struct page, lru);
		list_del(&page->lru);
		index = page - zone->zone_mem_map;
		if (current_order != MAX_ORDER-1)
			MARK_USED(index, current_order, area);
		zone->free_pages -= 1UL << order;
		return expand(zone, page, index, order, current_order, area);
	}

	return NULL;
}

/* 
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int rmqueue_bulk(struct zone *zone, unsigned int order, 
			unsigned long count, struct list_head *list)
{
	unsigned long flags;
	int i;
	int allocated = 0;
	struct page *page;
	
	spin_lock_irqsave(&zone->lock, flags);
	for (i = 0; i < count; ++i) {
		page = __rmqueue(zone, order);
		if (page == NULL)
			break;
		allocated++;
		list_add_tail(&page->lru, list);
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	return allocated;
}

#if defined(CONFIG_PM) || defined(CONFIG_HOTPLUG_CPU)
static void __drain_pages(unsigned int cpu)
{
	struct zone *zone;
	int i;

	for_each_zone(zone) {
		struct per_cpu_pageset *pset;

		pset = &zone->pageset[cpu];
		for (i = 0; i < ARRAY_SIZE(pset->pcp); i++) {
			struct per_cpu_pages *pcp;

			pcp = &pset->pcp[i];
			pcp->count -= free_pages_bulk(zone, pcp->count,
						&pcp->list, 0);
		}
	}
}
#endif /* CONFIG_PM || CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_PM
int is_head_of_free_region(struct page *page)
{
        struct zone *zone = page_zone(page);
        unsigned long flags;
	int order;
	struct list_head *curr;

	/*
	 * Should not matter as we need quiescent system for
	 * suspend anyway, but...
	 */
	spin_lock_irqsave(&zone->lock, flags);
	for (order = MAX_ORDER - 1; order >= 0; --order)
		list_for_each(curr, &zone->free_area[order].free_list)
			if (page == list_entry(curr, struct page, lru)) {
				spin_unlock_irqrestore(&zone->lock, flags);
				return 1 << order;
			}
	spin_unlock_irqrestore(&zone->lock, flags);
        return 0;
}

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 */
void drain_local_pages(void)
{
	unsigned long flags;

	local_irq_save(flags);	
	__drain_pages(smp_processor_id());
	local_irq_restore(flags);	
}
#endif /* CONFIG_PM */

static void zone_statistics(struct zonelist *zonelist, struct zone *z)
{
#ifdef CONFIG_NUMA
	unsigned long flags;
	int cpu;
	pg_data_t *pg = z->zone_pgdat;
	pg_data_t *orig = zonelist->zones[0]->zone_pgdat;
	struct per_cpu_pageset *p;

	local_irq_save(flags);
	cpu = smp_processor_id();
	p = &z->pageset[cpu];
	if (pg == orig) {
		z->pageset[cpu].numa_hit++;
	} else {
		p->numa_miss++;
		zonelist->zones[0]->pageset[cpu].numa_foreign++;
	}
	if (pg == NODE_DATA(numa_node_id()))
		p->local_node++;
	else
		p->other_node++;
	local_irq_restore(flags);
#endif
}

/*
 * Free a 0-order page
 */
static void FASTCALL(free_hot_cold_page(struct page *page, int cold));
static void fastcall free_hot_cold_page(struct page *page, int cold)
{
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;

	if (PageForeign(page))
		return (PageForeignDestructor(page))(page);

	arch_free_page(page, 0);

	kernel_map_pages(page, 1, 0);
	inc_page_state(pgfree);
	if (PageAnon(page))
		page->mapping = NULL;
	free_pages_check(__FUNCTION__, page);
	pcp = &zone->pageset[get_cpu()].pcp[cold];
	local_irq_save(flags);
	if (pcp->count >= pcp->high)
		pcp->count -= free_pages_bulk(zone, pcp->batch, &pcp->list, 0);
	list_add(&page->lru, &pcp->list);
	pcp->count++;
	local_irq_restore(flags);
	put_cpu();
}

void fastcall free_hot_page(struct page *page)
{
	free_hot_cold_page(page, 0);
}
	
void fastcall free_cold_page(struct page *page)
{
	free_hot_cold_page(page, 1);
}

/*
 * Really, prep_compound_page() should be called from __rmqueue_bulk().  But
 * we cheat by calling it from here, in the order > 0 path.  Saves a branch
 * or two.
 */

static struct page *
buffered_rmqueue(struct zone *zone, int order, int gfp_flags)
{
	unsigned long flags;
	struct page *page = NULL;
	int cold = !!(gfp_flags & __GFP_COLD);

	if (order == 0) {
		struct per_cpu_pages *pcp;

		pcp = &zone->pageset[get_cpu()].pcp[cold];
		local_irq_save(flags);
		if (pcp->count <= pcp->low)
			pcp->count += rmqueue_bulk(zone, 0,
						pcp->batch, &pcp->list);
		if (pcp->count) {
			page = list_entry(pcp->list.next, struct page, lru);
			list_del(&page->lru);
			pcp->count--;
		}
		local_irq_restore(flags);
		put_cpu();
	}

	if (page == NULL) {
		spin_lock_irqsave(&zone->lock, flags);
		page = __rmqueue(zone, order);
		spin_unlock_irqrestore(&zone->lock, flags);
	}

	if (page != NULL) {
		BUG_ON(bad_range(zone, page));
		mod_page_state_zone(zone, pgalloc, 1 << order);
		prep_new_page(page, order);
		if (order && (gfp_flags & __GFP_COMP))
			prep_compound_page(page, order);
	}
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 *
 * Herein lies the mysterious "incremental min".  That's the
 *
 *	local_low = z->pages_low;
 *	min += local_low;
 *
 * thing.  The intent here is to provide additional protection to low zones for
 * allocation requests which _could_ use higher zones.  So a GFP_HIGHMEM
 * request is not allowed to dip as deeply into the normal zone as a GFP_KERNEL
 * request.  This preserves additional space in those lower zones for requests
 * which really do need memory from those zones.  It means that on a decent
 * sized machine, GFP_HIGHMEM and GFP_KERNEL requests basically leave the DMA
 * zone untouched.
 */
struct page * fastcall
__alloc_pages(unsigned int gfp_mask, unsigned int order,
		struct zonelist *zonelist)
{
	const int wait = gfp_mask & __GFP_WAIT;
	unsigned long min;
	struct zone **zones, *z;
	struct page *page;
	struct reclaim_state reclaim_state;
	struct task_struct *p = current;
	int i;
	int alloc_type;
	int do_retry;
	int can_try_harder;

	might_sleep_if(wait);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or is the caller has realtime scheduling
	 * policy
	 */
	can_try_harder = (unlikely(rt_task(p)) && !in_interrupt()) || !wait;

	zones = zonelist->zones;  /* the list of zones suitable for gfp_mask */

	if (unlikely(zones[0] == NULL)) {
		/* Should this ever happen?? */
		return NULL;
	}

	alloc_type = zone_idx(zones[0]);

	/* Go through the zonelist once, looking for a zone with enough free */
	for (i = 0; (z = zones[i]) != NULL; i++) {
		min = z->pages_low + (1<<order) + z->protection[alloc_type];

		if (z->free_pages < min)
			continue;

		page = buffered_rmqueue(z, order, gfp_mask);
		if (page)
			goto got_pg;
	}

	for (i = 0; (z = zones[i]) != NULL; i++)
		wakeup_kswapd(z);

	/*
	 * Go through the zonelist again. Let __GFP_HIGH and allocations
	 * coming from realtime tasks to go deeper into reserves
	 */
	for (i = 0; (z = zones[i]) != NULL; i++) {
		min = z->pages_min;
		if (gfp_mask & __GFP_HIGH)
			min /= 2;
		if (can_try_harder)
			min -= min / 4;
		min += (1<<order) + z->protection[alloc_type];

		if (z->free_pages < min)
			continue;

		page = buffered_rmqueue(z, order, gfp_mask);
		if (page)
			goto got_pg;
	}

	/* This allocation should allow future memory freeing. */
	if ((p->flags & (PF_MEMALLOC | PF_MEMDIE)) && !in_interrupt()) {
		/* go through the zonelist yet again, ignoring mins */
		for (i = 0; (z = zones[i]) != NULL; i++) {
			page = buffered_rmqueue(z, order, gfp_mask);
			if (page)
				goto got_pg;
		}
		goto nopage;
	}

	/* Atomic allocations - we can't balance anything */
	if (!wait)
		goto nopage;

rebalance:
	/* We now go into synchronous reclaim */
	p->flags |= PF_MEMALLOC;
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	try_to_free_pages(zones, gfp_mask, order);

	p->reclaim_state = NULL;
	p->flags &= ~PF_MEMALLOC;

	/* go through the zonelist yet one more time */
	for (i = 0; (z = zones[i]) != NULL; i++) {
		min = z->pages_min;
		if (gfp_mask & __GFP_HIGH)
			min /= 2;
		if (can_try_harder)
			min -= min / 4;
		min += (1<<order) + z->protection[alloc_type];

		if (z->free_pages < min)
			continue;

		page = buffered_rmqueue(z, order, gfp_mask);
		if (page)
			goto got_pg;
	}

	/*
	 * Don't let big-order allocations loop unless the caller explicitly
	 * requests that.  Wait for some write requests to complete then retry.
	 *
	 * In this implementation, __GFP_REPEAT means __GFP_NOFAIL for order
	 * <= 3, but that may not be true in other implementations.
	 */
	do_retry = 0;
	if (!(gfp_mask & __GFP_NORETRY)) {
		if ((order <= 3) || (gfp_mask & __GFP_REPEAT))
			do_retry = 1;
		if (gfp_mask & __GFP_NOFAIL)
			do_retry = 1;
	}
	if (do_retry) {
		blk_congestion_wait(WRITE, HZ/50);
		goto rebalance;
	}

nopage:
	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
		printk(KERN_WARNING "%s: page allocation failure."
			" order:%d, mode:0x%x\n",
			p->comm, order, gfp_mask);
		dump_stack();
	}
	return NULL;
got_pg:
	zone_statistics(zonelist, z);
	kernel_map_pages(page, 1 << order, 1);
	return page;
}

EXPORT_SYMBOL(__alloc_pages);

/*
 * Common helper functions.
 */
fastcall unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	struct page * page;
	page = alloc_pages(gfp_mask, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}

EXPORT_SYMBOL(__get_free_pages);

fastcall unsigned long get_zeroed_page(unsigned int gfp_mask)
{
	struct page * page;

	/*
	 * get_zeroed_page() returns a 32-bit address, which cannot represent
	 * a highmem page
	 */
	BUG_ON(gfp_mask & __GFP_HIGHMEM);

	page = alloc_pages(gfp_mask, 0);
	if (page) {
		void *address = page_address(page);
		clear_page(address);
		return (unsigned long) address;
	}
	return 0;
}

EXPORT_SYMBOL(get_zeroed_page);

void __pagevec_free(struct pagevec *pvec)
{
	int i = pagevec_count(pvec);

	while (--i >= 0)
		free_hot_cold_page(pvec->pages[i], pvec->cold);
}

fastcall void __free_pages(struct page *page, unsigned int order)
{
	if (!PageReserved(page) && put_page_testzero(page)) {
		if (order == 0)
			free_hot_page(page);
		else
			__free_pages_ok(page, order);
	}
}

EXPORT_SYMBOL(__free_pages);

fastcall void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

/*
 * Total amount of free (allocatable) RAM:
 */
unsigned int nr_free_pages(void)
{
	unsigned int sum = 0;
	struct zone *zone;

	for_each_zone(zone)
		sum += zone->free_pages;

	return sum;
}

EXPORT_SYMBOL(nr_free_pages);

#ifdef CONFIG_NUMA
unsigned int nr_free_pages_pgdat(pg_data_t *pgdat)
{
	unsigned int i, sum = 0;

	for (i = 0; i < MAX_NR_ZONES; i++)
		sum += pgdat->node_zones[i].free_pages;

	return sum;
}
#endif

static unsigned int nr_free_zone_pages(int offset)
{
	pg_data_t *pgdat;
	unsigned int sum = 0;

	for_each_pgdat(pgdat) {
		struct zonelist *zonelist = pgdat->node_zonelists + offset;
		struct zone **zonep = zonelist->zones;
		struct zone *zone;

		for (zone = *zonep++; zone; zone = *zonep++) {
			unsigned long size = zone->present_pages;
			unsigned long high = zone->pages_high;
			if (size > high)
				sum += size - high;
		}
	}

	return sum;
}

/*
 * Amount of free RAM allocatable within ZONE_DMA and ZONE_NORMAL
 */
unsigned int nr_free_buffer_pages(void)
{
	return nr_free_zone_pages(GFP_USER & GFP_ZONEMASK);
}

/*
 * Amount of free RAM allocatable within all zones
 */
unsigned int nr_free_pagecache_pages(void)
{
	return nr_free_zone_pages(GFP_HIGHUSER & GFP_ZONEMASK);
}

#ifdef CONFIG_HIGHMEM
unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_pgdat(pgdat)
		pages += pgdat->node_zones[ZONE_HIGHMEM].free_pages;

	return pages;
}
#endif

#ifdef CONFIG_NUMA
static void show_node(struct zone *zone)
{
	printk("Node %d ", zone->zone_pgdat->node_id);
}
#else
#define show_node(zone)	do { } while (0)
#endif

/*
 * Accumulate the page_state information across all CPUs.
 * The result is unavoidably approximate - it can change
 * during and after execution of this function.
 */
DEFINE_PER_CPU(struct page_state, page_states) = {0};
EXPORT_PER_CPU_SYMBOL(page_states);

atomic_t nr_pagecache = ATOMIC_INIT(0);
EXPORT_SYMBOL(nr_pagecache);
#ifdef CONFIG_SMP
DEFINE_PER_CPU(long, nr_pagecache_local) = 0;
#endif

void __get_page_state(struct page_state *ret, int nr)
{
	int cpu = 0;

	memset(ret, 0, sizeof(*ret));
	while (cpu < NR_CPUS) {
		unsigned long *in, *out, off;

		if (!cpu_possible(cpu)) {
			cpu++;
			continue;
		}

		in = (unsigned long *)&per_cpu(page_states, cpu);
		cpu++;
		if (cpu < NR_CPUS && cpu_possible(cpu))
			prefetch(&per_cpu(page_states, cpu));
		out = (unsigned long *)ret;
		for (off = 0; off < nr; off++)
			*out++ += *in++;
	}
}

void get_page_state(struct page_state *ret)
{
	int nr;

	nr = offsetof(struct page_state, GET_PAGE_STATE_LAST);
	nr /= sizeof(unsigned long);

	__get_page_state(ret, nr + 1);
}

void get_full_page_state(struct page_state *ret)
{
	__get_page_state(ret, sizeof(*ret) / sizeof(unsigned long));
}

unsigned long __read_page_state(unsigned offset)
{
	unsigned long ret = 0;
	int cpu;

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		unsigned long in;

		if (!cpu_possible(cpu))
			continue;

		in = (unsigned long)&per_cpu(page_states, cpu) + offset;
		ret += *((unsigned long *)in);
	}
	return ret;
}

void __get_zone_counts(unsigned long *active, unsigned long *inactive,
			unsigned long *free, struct pglist_data *pgdat)
{
	struct zone *zones = pgdat->node_zones;
	int i;

	*active = 0;
	*inactive = 0;
	*free = 0;
	for (i = 0; i < MAX_NR_ZONES; i++) {
		*active += zones[i].nr_active;
		*inactive += zones[i].nr_inactive;
		*free += zones[i].free_pages;
	}
}

void get_zone_counts(unsigned long *active,
		unsigned long *inactive, unsigned long *free)
{
	struct pglist_data *pgdat;

	*active = 0;
	*inactive = 0;
	*free = 0;
	for_each_pgdat(pgdat) {
		unsigned long l, m, n;
		__get_zone_counts(&l, &m, &n, pgdat);
		*active += l;
		*inactive += m;
		*free += n;
	}
}

void si_meminfo(struct sysinfo *val)
{
	val->totalram = totalram_pages;
	val->sharedram = 0;
	val->freeram = nr_free_pages();
	val->bufferram = nr_blockdev_pages();
#ifdef CONFIG_HIGHMEM
	val->totalhigh = totalhigh_pages;
	val->freehigh = nr_free_highpages();
#else
	val->totalhigh = 0;
	val->freehigh = 0;
#endif
	val->mem_unit = PAGE_SIZE;
}

EXPORT_SYMBOL(si_meminfo);

#ifdef CONFIG_NUMA
void si_meminfo_node(struct sysinfo *val, int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);

	val->totalram = pgdat->node_present_pages;
	val->freeram = nr_free_pages_pgdat(pgdat);
	val->totalhigh = pgdat->node_zones[ZONE_HIGHMEM].present_pages;
	val->freehigh = pgdat->node_zones[ZONE_HIGHMEM].free_pages;
	val->mem_unit = PAGE_SIZE;
}
#endif

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void show_free_areas(void)
{
	struct page_state ps;
	int cpu, temperature;
	unsigned long active;
	unsigned long inactive;
	unsigned long free;
	struct zone *zone;

	for_each_zone(zone) {
		show_node(zone);
		printk("%s per-cpu:", zone->name);

		if (!zone->present_pages) {
			printk(" empty\n");
			continue;
		} else
			printk("\n");

		for (cpu = 0; cpu < NR_CPUS; ++cpu) {
			struct per_cpu_pageset *pageset;

			if (!cpu_possible(cpu))
				continue;

			pageset = zone->pageset + cpu;

			for (temperature = 0; temperature < 2; temperature++)
				printk("cpu %d %s: low %d, high %d, batch %d\n",
					cpu,
					temperature ? "cold" : "hot",
					pageset->pcp[temperature].low,
					pageset->pcp[temperature].high,
					pageset->pcp[temperature].batch);
		}
	}

	get_page_state(&ps);
	get_zone_counts(&active, &inactive, &free);

	printk("\nFree pages: %11ukB (%ukB HighMem)\n",
		K(nr_free_pages()),
		K(nr_free_highpages()));

	printk("Active:%lu inactive:%lu dirty:%lu writeback:%lu "
		"unstable:%lu free:%u slab:%lu mapped:%lu pagetables:%lu\n",
		active,
		inactive,
		ps.nr_dirty,
		ps.nr_writeback,
		ps.nr_unstable,
		nr_free_pages(),
		ps.nr_slab,
		ps.nr_mapped,
		ps.nr_page_table_pages);

	for_each_zone(zone) {
		int i;

		show_node(zone);
		printk("%s"
			" free:%lukB"
			" min:%lukB"
			" low:%lukB"
			" high:%lukB"
			" active:%lukB"
			" inactive:%lukB"
			" present:%lukB"
			"\n",
			zone->name,
			K(zone->free_pages),
			K(zone->pages_min),
			K(zone->pages_low),
			K(zone->pages_high),
			K(zone->nr_active),
			K(zone->nr_inactive),
			K(zone->present_pages)
			);
		printk("protections[]:");
		for (i = 0; i < MAX_NR_ZONES; i++)
			printk(" %lu", zone->protection[i]);
		printk("\n");
	}

	for_each_zone(zone) {
		struct list_head *elem;
 		unsigned long nr, flags, order, total = 0;

		show_node(zone);
		printk("%s: ", zone->name);
		if (!zone->present_pages) {
			printk("empty\n");
			continue;
		}

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			nr = 0;
			list_for_each(elem, &zone->free_area[order].free_list)
				++nr;
			total += nr << order;
			printk("%lu*%lukB ", nr, K(1UL) << order);
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		printk("= %lukB\n", K(total));
	}

	show_swap_cache_info();
}

/*
 * Builds allocation fallback zone lists.
 */
static int __init build_zonelists_node(pg_data_t *pgdat, struct zonelist *zonelist, int j, int k)
{
	switch (k) {
		struct zone *zone;
	default:
		BUG();
	case ZONE_HIGHMEM:
		zone = pgdat->node_zones + ZONE_HIGHMEM;
		if (zone->present_pages) {
#ifndef CONFIG_HIGHMEM
			BUG();
#endif
			zonelist->zones[j++] = zone;
		}
	case ZONE_NORMAL:
		zone = pgdat->node_zones + ZONE_NORMAL;
		if (zone->present_pages)
			zonelist->zones[j++] = zone;
	case ZONE_DMA:
		zone = pgdat->node_zones + ZONE_DMA;
		if (zone->present_pages)
			zonelist->zones[j++] = zone;
	}

	return j;
}

#ifdef CONFIG_NUMA
#define MAX_NODE_LOAD (numnodes)
static int __initdata node_load[MAX_NUMNODES];
/**
 * find_next_best_node - find the next node that should appear in a given
 *    node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: pointer to the bitmap of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 * It returns -1 if no node is found.
 */
static int __init find_next_best_node(int node, void *used_node_mask)
{
	int i, n, val;
	int min_val = INT_MAX;
	int best_node = -1;

	for (i = 0; i < numnodes; i++) {
		cpumask_t tmp;

		/* Start from local node */
		n = (node+i)%numnodes;

		/* Don't want a node to appear more than once */
		if (test_bit(n, used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Give preference to headless and unused nodes */
		tmp = node_to_cpumask(n);
		if (!cpus_empty(tmp))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		set_bit(best_node, used_node_mask);

	return best_node;
}

static void __init build_zonelists(pg_data_t *pgdat)
{
	int i, j, k, node, local_node;
	int prev_node, load;
	struct zonelist *zonelist;
	DECLARE_BITMAP(used_mask, MAX_NUMNODES);

	/* initialize zonelists */
	for (i = 0; i < GFP_ZONETYPES; i++) {
		zonelist = pgdat->node_zonelists + i;
		memset(zonelist, 0, sizeof(*zonelist));
		zonelist->zones[0] = NULL;
	}

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id;
	load = numnodes;
	prev_node = local_node;
	bitmap_zero(used_mask, MAX_NUMNODES);
	while ((node = find_next_best_node(local_node, used_mask)) >= 0) {
		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local_node, node) !=
				node_distance(local_node, prev_node))
			node_load[node] += load;
		prev_node = node;
		load--;
		for (i = 0; i < GFP_ZONETYPES; i++) {
			zonelist = pgdat->node_zonelists + i;
			for (j = 0; zonelist->zones[j] != NULL; j++);

			k = ZONE_NORMAL;
			if (i & __GFP_HIGHMEM)
				k = ZONE_HIGHMEM;
			if (i & __GFP_DMA)
				k = ZONE_DMA;

	 		j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
			zonelist->zones[j] = NULL;
		}
	}
}

#else	/* CONFIG_NUMA */

static void __init build_zonelists(pg_data_t *pgdat)
{
	int i, j, k, node, local_node;

	local_node = pgdat->node_id;
	for (i = 0; i < GFP_ZONETYPES; i++) {
		struct zonelist *zonelist;

		zonelist = pgdat->node_zonelists + i;
		memset(zonelist, 0, sizeof(*zonelist));

		j = 0;
		k = ZONE_NORMAL;
		if (i & __GFP_HIGHMEM)
			k = ZONE_HIGHMEM;
		if (i & __GFP_DMA)
			k = ZONE_DMA;

 		j = build_zonelists_node(pgdat, zonelist, j, k);
 		/*
 		 * Now we build the zonelist so that it contains the zones
 		 * of all the other nodes.
 		 * We don't want to pressure a particular node, so when
 		 * building the zones for node N, we make sure that the
 		 * zones coming right after the local ones are those from
 		 * node N+1 (modulo N)
 		 */
 		for (node = local_node + 1; node < numnodes; node++)
 			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
 		for (node = 0; node < local_node; node++)
 			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
 
		zonelist->zones[j] = NULL;
	}
}

#endif	/* CONFIG_NUMA */

void __init build_all_zonelists(void)
{
	int i;

	for(i = 0 ; i < numnodes ; i++)
		build_zonelists(NODE_DATA(i));
	printk("Built %i zonelists\n", numnodes);
}

/*
 * Helper functions to size the waitqueue hash table.
 * Essentially these want to choose hash table sizes sufficiently
 * large so that collisions trying to wait on pages are rare.
 * But in fact, the number of active page waitqueues on typical
 * systems is ridiculously low, less than 200. So this is even
 * conservative, even though it seems large.
 *
 * The constant PAGES_PER_WAITQUEUE specifies the ratio of pages to
 * waitqueues, i.e. the size of the waitq table given the number of pages.
 */
#define PAGES_PER_WAITQUEUE	256

static inline unsigned long wait_table_size(unsigned long pages)
{
	unsigned long size = 1;

	pages /= PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	/*
	 * Once we have dozens or even hundreds of threads sleeping
	 * on IO we've got bigger problems than wait queue collision.
	 * Limit the size of the wait table to a reasonable size.
	 */
	size = min(size, 4096UL);

	return max(size, 4UL);
}

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long wait_table_bits(unsigned long size)
{
	return ffz(~size);
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

static void __init calculate_zone_totalpages(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	unsigned long realtotalpages, totalpages = 0;
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		totalpages += zones_size[i];
	pgdat->node_spanned_pages = totalpages;

	realtotalpages = totalpages;
	if (zholes_size)
		for (i = 0; i < MAX_NR_ZONES; i++)
			realtotalpages -= zholes_size[i];
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id, realtotalpages);
}


/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 */
void __init memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn)
{
	struct page *start = pfn_to_page(start_pfn);
	struct page *page;

	for (page = start; page < (start + size); page++) {
		set_page_zone(page, NODEZONE(nid, zone));
		set_page_count(page, 0);
		reset_page_mapcount(page);
		SetPageReserved(page);
		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
		/* The shift won't overflow because ZONE_NORMAL is below 4G. */
		if (!is_highmem_idx(zone))
			set_page_address(page, __va(start_pfn << PAGE_SHIFT));
#endif
		start_pfn++;
	}
}

/*
 * Page buddy system uses "index >> (i+1)", where "index" is
 * at most "size-1".
 *
 * The extra "+3" is to round down to byte size (8 bits per byte
 * assumption). Thus we get "(size-1) >> (i+4)" as the last byte
 * we can access.
 *
 * The "+1" is because we want to round the byte allocation up
 * rather than down. So we should have had a "+7" before we shifted
 * down by three. Also, we have to add one as we actually _use_ the
 * last bit (it's [0,n] inclusive, not [0,n[).
 *
 * So we actually had +7+1 before we shift down by 3. But
 * (n+8) >> 3 == (n >> 3) + 1 (modulo overflows, which we do not have).
 *
 * Finally, we LONG_ALIGN because all bitmap operations are on longs.
 */
unsigned long pages_to_bitmap_size(unsigned long order, unsigned long nr_pages)
{
	unsigned long bitmap_size;

	bitmap_size = (nr_pages-1) >> (order+4);
	bitmap_size = LONG_ALIGN(bitmap_size+1);

	return bitmap_size;
}

void zone_init_free_lists(struct pglist_data *pgdat, struct zone *zone, unsigned long size)
{
	int order;
	for (order = 0; ; order++) {
		unsigned long bitmap_size;

		INIT_LIST_HEAD(&zone->free_area[order].free_list);
		if (order == MAX_ORDER-1) {
			zone->free_area[order].map = NULL;
			break;
		}

		bitmap_size = pages_to_bitmap_size(order, size);
		zone->free_area[order].map =
		  (unsigned long *) alloc_bootmem_node(pgdat, bitmap_size);
	}
}

#ifndef __HAVE_ARCH_MEMMAP_INIT
#define memmap_init(size, nid, zone, start_pfn) \
	memmap_init_zone((size), (nid), (zone), (start_pfn))
#endif

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 */
static void __init free_area_init_core(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	unsigned long i, j;
	const unsigned long zone_required_alignment = 1UL << (MAX_ORDER-1);
	int cpu, nid = pgdat->node_id;
	unsigned long zone_start_pfn = pgdat->node_start_pfn;

	pgdat->nr_zones = 0;
	init_waitqueue_head(&pgdat->kswapd_wait);
	
	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize;
		unsigned long batch;

		zone_table[NODEZONE(nid, j)] = zone;
		realsize = size = zones_size[j];
		if (zholes_size)
			realsize -= zholes_size[j];

		if (j == ZONE_DMA || j == ZONE_NORMAL)
			nr_kernel_pages += realsize;
		nr_all_pages += realsize;

		zone->spanned_pages = size;
		zone->present_pages = realsize;
		zone->name = zone_names[j];
		spin_lock_init(&zone->lock);
		spin_lock_init(&zone->lru_lock);
		zone->zone_pgdat = pgdat;
		zone->free_pages = 0;

		zone->temp_priority = zone->prev_priority = DEF_PRIORITY;

		/*
		 * The per-cpu-pages pools are set to around 1000th of the
		 * size of the zone.  But no more than 1/4 of a meg - there's
		 * no point in going beyond the size of L2 cache.
		 *
		 * OK, so we don't know how big the cache is.  So guess.
		 */
		batch = zone->present_pages / 1024;
		if (batch * PAGE_SIZE > 256 * 1024)
			batch = (256 * 1024) / PAGE_SIZE;
		batch /= 4;		/* We effectively *= 4 below */
		if (batch < 1)
			batch = 1;

		for (cpu = 0; cpu < NR_CPUS; cpu++) {
			struct per_cpu_pages *pcp;

			pcp = &zone->pageset[cpu].pcp[0];	/* hot */
			pcp->count = 0;
			pcp->low = 2 * batch;
			pcp->high = 6 * batch;
			pcp->batch = 1 * batch;
			INIT_LIST_HEAD(&pcp->list);

			pcp = &zone->pageset[cpu].pcp[1];	/* cold */
			pcp->count = 0;
			pcp->low = 0;
			pcp->high = 2 * batch;
			pcp->batch = 1 * batch;
			INIT_LIST_HEAD(&pcp->list);
		}
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%lu\n",
				zone_names[j], realsize, batch);
		INIT_LIST_HEAD(&zone->active_list);
		INIT_LIST_HEAD(&zone->inactive_list);
		zone->nr_scan_active = 0;
		zone->nr_scan_inactive = 0;
		zone->nr_active = 0;
		zone->nr_inactive = 0;
		if (!size)
			continue;

		/*
		 * The per-page waitqueue mechanism uses hashed waitqueues
		 * per zone.
		 */
		zone->wait_table_size = wait_table_size(size);
		zone->wait_table_bits =
			wait_table_bits(zone->wait_table_size);
		zone->wait_table = (wait_queue_head_t *)
			alloc_bootmem_node(pgdat, zone->wait_table_size
						* sizeof(wait_queue_head_t));

		for(i = 0; i < zone->wait_table_size; ++i)
			init_waitqueue_head(zone->wait_table + i);

		pgdat->nr_zones = j+1;

		zone->zone_mem_map = pfn_to_page(zone_start_pfn);
		zone->zone_start_pfn = zone_start_pfn;

		if ((zone_start_pfn) & (zone_required_alignment-1))
			printk("BUG: wrong zone alignment, it will crash\n");

		memmap_init(size, nid, j, zone_start_pfn);

		zone_start_pfn += size;

		zone_init_free_lists(pgdat, zone, zone->spanned_pages);
	}
}

void __init node_alloc_mem_map(struct pglist_data *pgdat)
{
	unsigned long size;

	size = (pgdat->node_spanned_pages + 1) * sizeof(struct page);
	pgdat->node_mem_map = alloc_bootmem_node(pgdat, size);
#ifndef CONFIG_DISCONTIGMEM
	mem_map = contig_page_data.node_mem_map;
#endif
}

void __init free_area_init_node(int nid, struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long node_start_pfn,
		unsigned long *zholes_size)
{
	pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;
	calculate_zone_totalpages(pgdat, zones_size, zholes_size);

	if (!pfn_to_page(node_start_pfn))
		node_alloc_mem_map(pgdat);

	free_area_init_core(pgdat, zones_size, zholes_size);
}

#ifndef CONFIG_DISCONTIGMEM
static bootmem_data_t contig_bootmem_data;
struct pglist_data contig_page_data = { .bdata = &contig_bootmem_data };

EXPORT_SYMBOL(contig_page_data);

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_node(0, &contig_page_data, zones_size,
			__pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
}
#endif

#ifdef CONFIG_PROC_FS

#include <linux/seq_file.h>

static void *frag_start(struct seq_file *m, loff_t *pos)
{
	pg_data_t *pgdat;
	loff_t node = *pos;

	for (pgdat = pgdat_list; pgdat && node; pgdat = pgdat->pgdat_next)
		--node;

	return pgdat;
}

static void *frag_next(struct seq_file *m, void *arg, loff_t *pos)
{
	pg_data_t *pgdat = (pg_data_t *)arg;

	(*pos)++;
	return pgdat->pgdat_next;
}

static void frag_stop(struct seq_file *m, void *arg)
{
}

/* 
 * This walks the freelist for each zone. Whilst this is slow, I'd rather 
 * be slow here than slow down the fast path by keeping stats - mjbligh
 */
static int frag_show(struct seq_file *m, void *arg)
{
	pg_data_t *pgdat = (pg_data_t *)arg;
	struct zone *zone;
	struct zone *node_zones = pgdat->node_zones;
	unsigned long flags;
	int order;

	for (zone = node_zones; zone - node_zones < MAX_NR_ZONES; ++zone) {
		if (!zone->present_pages)
			continue;

		spin_lock_irqsave(&zone->lock, flags);
		seq_printf(m, "Node %d, zone %8s ", pgdat->node_id, zone->name);
		for (order = 0; order < MAX_ORDER; ++order) {
			unsigned long nr_bufs = 0;
			struct list_head *elem;

			list_for_each(elem, &(zone->free_area[order].free_list))
				++nr_bufs;
			seq_printf(m, "%6lu ", nr_bufs);
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		seq_putc(m, '\n');
	}
	return 0;
}

struct seq_operations fragmentation_op = {
	.start	= frag_start,
	.next	= frag_next,
	.stop	= frag_stop,
	.show	= frag_show,
};

static char *vmstat_text[] = {
	"nr_dirty",
	"nr_writeback",
	"nr_unstable",
	"nr_page_table_pages",
	"nr_mapped",
	"nr_slab",

	"pgpgin",
	"pgpgout",
	"pswpin",
	"pswpout",
	"pgalloc_high",

	"pgalloc_normal",
	"pgalloc_dma",
	"pgfree",
	"pgactivate",
	"pgdeactivate",

	"pgfault",
	"pgmajfault",
	"pgrefill_high",
	"pgrefill_normal",
	"pgrefill_dma",

	"pgsteal_high",
	"pgsteal_normal",
	"pgsteal_dma",
	"pgscan_kswapd_high",
	"pgscan_kswapd_normal",

	"pgscan_kswapd_dma",
	"pgscan_direct_high",
	"pgscan_direct_normal",
	"pgscan_direct_dma",
	"pginodesteal",

	"slabs_scanned",
	"kswapd_steal",
	"kswapd_inodesteal",
	"pageoutrun",
	"allocstall",

	"pgrotated",
};

static void *vmstat_start(struct seq_file *m, loff_t *pos)
{
	struct page_state *ps;

	if (*pos >= ARRAY_SIZE(vmstat_text))
		return NULL;

	ps = kmalloc(sizeof(*ps), GFP_KERNEL);
	m->private = ps;
	if (!ps)
		return ERR_PTR(-ENOMEM);
	get_full_page_state(ps);
	ps->pgpgin /= 2;		/* sectors -> kbytes */
	ps->pgpgout /= 2;
	return (unsigned long *)ps + *pos;
}

static void *vmstat_next(struct seq_file *m, void *arg, loff_t *pos)
{
	(*pos)++;
	if (*pos >= ARRAY_SIZE(vmstat_text))
		return NULL;
	return (unsigned long *)m->private + *pos;
}

static int vmstat_show(struct seq_file *m, void *arg)
{
	unsigned long *l = arg;
	unsigned long off = l - (unsigned long *)m->private;

	seq_printf(m, "%s %lu\n", vmstat_text[off], *l);
	return 0;
}

static void vmstat_stop(struct seq_file *m, void *arg)
{
	kfree(m->private);
	m->private = NULL;
}

struct seq_operations vmstat_op = {
	.start	= vmstat_start,
	.next	= vmstat_next,
	.stop	= vmstat_stop,
	.show	= vmstat_show,
};

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_HOTPLUG_CPU
static int page_alloc_cpu_notify(struct notifier_block *self,
				 unsigned long action, void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	long *count;

	if (action == CPU_DEAD) {
		/* Drain local pagecache count. */
		count = &per_cpu(nr_pagecache_local, cpu);
		atomic_add(*count, &nr_pagecache);
		*count = 0;
		local_irq_disable();
		__drain_pages(cpu);
		local_irq_enable();
	}
	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */

void __init page_alloc_init(void)
{
	hotcpu_notifier(page_alloc_cpu_notify, 0);
}

static unsigned long higherzone_val(struct zone *z, int max_zone,
					int alloc_type)
{
	int z_idx = zone_idx(z);
	struct zone *higherzone;
	unsigned long pages;

	/* there is no higher zone to get a contribution from */
	if (z_idx == MAX_NR_ZONES-1)
		return 0;

	higherzone = &z->zone_pgdat->node_zones[z_idx+1];

	/* We always start with the higher zone's protection value */
	pages = higherzone->protection[alloc_type];

	/*
	 * We get a lower-zone-protection contribution only if there are
	 * pages in the higher zone and if we're not the highest zone
	 * in the current zonelist.  e.g., never happens for GFP_DMA. Happens
	 * only for ZONE_DMA in a GFP_KERNEL allocation and happens for ZONE_DMA
	 * and ZONE_NORMAL for a GFP_HIGHMEM allocation.
	 */
	if (higherzone->present_pages && z_idx < alloc_type)
		pages += higherzone->pages_low * sysctl_lower_zone_protection;

	return pages;
}

/*
 * setup_per_zone_protection - called whenver min_free_kbytes or
 *	sysctl_lower_zone_protection changes.  Ensures that each zone
 *	has a correct pages_protected value, so an adequate number of
 *	pages are left in the zone after a successful __alloc_pages().
 *
 *	This algorithm is way confusing.  I tries to keep the same behavior
 *	as we had with the incremental min iterative algorithm.
 */
static void setup_per_zone_protection(void)
{
	struct pglist_data *pgdat;
	struct zone *zones, *zone;
	int max_zone;
	int i, j;

	for_each_pgdat(pgdat) {
		zones = pgdat->node_zones;

		for (i = 0, max_zone = 0; i < MAX_NR_ZONES; i++)
			if (zones[i].present_pages)
				max_zone = i;

		/*
		 * For each of the different allocation types:
		 * GFP_DMA -> GFP_KERNEL -> GFP_HIGHMEM
		 */
		for (i = 0; i < GFP_ZONETYPES; i++) {
			/*
			 * For each of the zones:
			 * ZONE_HIGHMEM -> ZONE_NORMAL -> ZONE_DMA
			 */
			for (j = MAX_NR_ZONES-1; j >= 0; j--) {
				zone = &zones[j];

				/*
				 * We never protect zones that don't have memory
				 * in them (j>max_zone) or zones that aren't in
				 * the zonelists for a certain type of
				 * allocation (j>=i).  We have to assign these
				 * to zero because the lower zones take
				 * contributions from the higher zones.
				 */
				if (j > max_zone || j >= i) {
					zone->protection[i] = 0;
					continue;
				}
				/*
				 * The contribution of the next higher zone
				 */
				zone->protection[i] = higherzone_val(zone,
								max_zone, i);
			}
		}
	}
}

/*
 * setup_per_zone_pages_min - called when min_free_kbytes changes.  Ensures 
 *	that the pages_{min,low,high} values for each zone are set correctly 
 *	with respect to min_free_kbytes.
 */
static void setup_per_zone_pages_min(void)
{
	unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10);
	unsigned long lowmem_pages = 0;
	struct zone *zone;
	unsigned long flags;

	/* Calculate total number of !ZONE_HIGHMEM pages */
	for_each_zone(zone) {
		if (!is_highmem(zone))
			lowmem_pages += zone->present_pages;
	}

	for_each_zone(zone) {
		spin_lock_irqsave(&zone->lru_lock, flags);
		if (is_highmem(zone)) {
			/*
			 * Often, highmem doesn't need to reserve any pages.
			 * But the pages_min/low/high values are also used for
			 * batching up page reclaim activity so we need a
			 * decent value here.
			 */
			int min_pages;

			min_pages = zone->present_pages / 1024;
			if (min_pages < SWAP_CLUSTER_MAX)
				min_pages = SWAP_CLUSTER_MAX;
			if (min_pages > 128)
				min_pages = 128;
			zone->pages_min = min_pages;
		} else {
			/* if it's a lowmem zone, reserve a number of pages 
			 * proportionate to the zone's size.
			 */
			zone->pages_min = (pages_min * zone->present_pages) / 
			                   lowmem_pages;
		}

		zone->pages_low = zone->pages_min * 2;
		zone->pages_high = zone->pages_min * 3;
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}
}

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (16MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 *	min_free_kbytes = sqrt(lowmem_kbytes)
 *
 * which yields
 *
 * 16MB:	128k
 * 32MB:	181k
 * 64MB:	256k
 * 128MB:	362k
 * 256MB:	512k
 * 512MB:	724k
 * 1024MB:	1024k
 * 2048MB:	1448k
 * 4096MB:	2048k
 * 8192MB:	2896k
 * 16384MB:	4096k
 */
static int __init init_per_zone_pages_min(void)
{
	unsigned long lowmem_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);

	min_free_kbytes = int_sqrt(lowmem_kbytes);
	if (min_free_kbytes < 128)
		min_free_kbytes = 128;
	if (min_free_kbytes > 16384)
		min_free_kbytes = 16384;
	setup_per_zone_pages_min();
	setup_per_zone_protection();
	return 0;
}
module_init(init_per_zone_pages_min)

/*
 * min_free_kbytes_sysctl_handler - just a wrapper around proc_dointvec() so 
 *	that we can call two helper functions whenever min_free_kbytes
 *	changes.
 */
int min_free_kbytes_sysctl_handler(ctl_table *table, int write, 
		struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec(table, write, file, buffer, length, ppos);
	setup_per_zone_pages_min();
	setup_per_zone_protection();
	return 0;
}

/*
 * lower_zone_protection_sysctl_handler - just a wrapper around
 *	proc_dointvec() so that we can call setup_per_zone_protection()
 *	whenever sysctl_lower_zone_protection changes.
 */
int lower_zone_protection_sysctl_handler(ctl_table *table, int write,
		 struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, file, buffer, length, ppos);
	setup_per_zone_protection();
	return 0;
}

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int consider_highmem,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask)
{
	unsigned long long max;
	unsigned long log2qty, size;
	void *table;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = consider_highmem ? nr_all_pages : nr_kernel_pages;
		numentries += (1UL << (20 - PAGE_SHIFT)) - 1;
		numentries >>= 20 - PAGE_SHIFT;
		numentries <<= 20 - PAGE_SHIFT;

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);
	}
	/* rounded up to nearest power of 2 in size */
	numentries = 1UL << (long_log2(numentries) + 1);

	/* limit allocation size to 1/16 total memory */
	max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
	do_div(max, bucketsize);

	if (numentries > max)
		numentries = max;

	log2qty = long_log2(numentries);

	do {
		size = bucketsize << log2qty;
		table = alloc_bootmem(size);
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk("%s hash table entries: %d (order: %d, %lu bytes)\n",
	       tablename,
	       (1U << log2qty),
	       long_log2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}
