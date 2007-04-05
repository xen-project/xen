/******************************************************************************
 * balloon.c
 *
 * Xen balloon driver - enables returning/claiming memory to/from Xen.
 *
 * Copyright (c) 2003, B Dragovic
 * Copyright (c) 2003-2004, M Williamson, K Fraser
 * Copyright (c) 2005 Dan M. Smith, IBM Corporation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <xen/xen_proc.h>
#include <asm/hypervisor.h>
#include <xen/balloon.h>
#include <xen/interface/memory.h>
#include <asm/maddr.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <xen/xenbus.h>
#include "common.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *balloon_pde;
#endif

static DEFINE_MUTEX(balloon_mutex);

/*
 * Protects atomic reservation decrease/increase against concurrent increases.
 * Also protects non-atomic updates of current_pages and driver_pages, and
 * balloon lists.
 */
DEFINE_SPINLOCK(balloon_lock);

struct balloon_stats balloon_stats;

/* We increase/decrease in batches which fit in a page */
static unsigned long frame_list[PAGE_SIZE / sizeof(unsigned long)];

/* VM /proc information for memory */
extern unsigned long totalram_pages;

/* List of ballooned pages, threaded through the mem_map array. */
static LIST_HEAD(ballooned_pages);

/* Main work function, always executed in process context. */
static void balloon_process(void *unused);
static DECLARE_WORK(balloon_worker, balloon_process, NULL);
static struct timer_list balloon_timer;

/* When ballooning out (allocating memory to return to Xen) we don't really 
   want the kernel to try too hard since that can trigger the oom killer. */
#define GFP_BALLOON \
	(GFP_HIGHUSER | __GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC)

#define PAGE_TO_LIST(p) (&(p)->lru)
#define LIST_TO_PAGE(l) list_entry((l), struct page, lru)
#define UNLIST_PAGE(p)				\
	do {					\
		list_del(PAGE_TO_LIST(p));	\
		PAGE_TO_LIST(p)->next = NULL;	\
		PAGE_TO_LIST(p)->prev = NULL;	\
	} while(0)

#define IPRINTK(fmt, args...) \
	printk(KERN_INFO "xen_mem: " fmt, ##args)
#define WPRINTK(fmt, args...) \
	printk(KERN_WARNING "xen_mem: " fmt, ##args)

/* balloon_append: add the given page to the balloon. */
static void balloon_append(struct page *page)
{
	/* Lowmem is re-populated first, so highmem pages go at list tail. */
	if (PageHighMem(page)) {
		list_add_tail(PAGE_TO_LIST(page), &ballooned_pages);
		bs.balloon_high++;
	} else {
		list_add(PAGE_TO_LIST(page), &ballooned_pages);
		bs.balloon_low++;
	}
}

/* balloon_retrieve: rescue a page from the balloon, if it is not empty. */
static struct page *balloon_retrieve(void)
{
	struct page *page;

	if (list_empty(&ballooned_pages))
		return NULL;

	page = LIST_TO_PAGE(ballooned_pages.next);
	UNLIST_PAGE(page);

	if (PageHighMem(page))
		bs.balloon_high--;
	else
		bs.balloon_low--;

	return page;
}

static struct page *balloon_first_page(void)
{
	if (list_empty(&ballooned_pages))
		return NULL;
	return LIST_TO_PAGE(ballooned_pages.next);
}

static struct page *balloon_next_page(struct page *page)
{
	struct list_head *next = PAGE_TO_LIST(page)->next;
	if (next == &ballooned_pages)
		return NULL;
	return LIST_TO_PAGE(next);
}

static void balloon_alarm(unsigned long unused)
{
	schedule_work(&balloon_worker);
}

static unsigned long current_target(void)
{
	unsigned long target = min(bs.target_pages, bs.hard_limit);
	if (target > (bs.current_pages + bs.balloon_low + bs.balloon_high))
		target = bs.current_pages + bs.balloon_low + bs.balloon_high;
	return target;
}

static int increase_reservation(unsigned long nr_pages)
{
	unsigned long  pfn, i, flags;
	struct page   *page;
	long           rc;
	struct xen_memory_reservation reservation = {
		.address_bits = 0,
		.extent_order = 0,
		.domid        = DOMID_SELF
	};

	if (nr_pages > ARRAY_SIZE(frame_list))
		nr_pages = ARRAY_SIZE(frame_list);

	balloon_lock(flags);

	page = balloon_first_page();
	for (i = 0; i < nr_pages; i++) {
		BUG_ON(page == NULL);
		frame_list[i] = page_to_pfn(page);;
		page = balloon_next_page(page);
	}

	set_xen_guest_handle(reservation.extent_start, frame_list);
	reservation.nr_extents   = nr_pages;
	rc = HYPERVISOR_memory_op(
		XENMEM_populate_physmap, &reservation);
	if (rc < nr_pages) {
		if (rc > 0) {
			int ret;

			/* We hit the Xen hard limit: reprobe. */
			reservation.nr_extents = rc;
			ret = HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					&reservation);
			BUG_ON(ret != rc);
		}
		if (rc >= 0)
			bs.hard_limit = (bs.current_pages + rc -
					 bs.driver_pages);
		goto out;
	}

	for (i = 0; i < nr_pages; i++) {
		page = balloon_retrieve();
		BUG_ON(page == NULL);

		pfn = page_to_pfn(page);
		BUG_ON(!xen_feature(XENFEAT_auto_translated_physmap) &&
		       phys_to_machine_mapping_valid(pfn));

		set_phys_to_machine(pfn, frame_list[i]);

#ifdef CONFIG_XEN
		/* Link back into the page tables if not highmem. */
		if (pfn < max_low_pfn) {
			int ret;
			ret = HYPERVISOR_update_va_mapping(
				(unsigned long)__va(pfn << PAGE_SHIFT),
				pfn_pte_ma(frame_list[i], PAGE_KERNEL),
				0);
			BUG_ON(ret);
		}
#endif

		/* Relinquish the page back to the allocator. */
		ClearPageReserved(page);
		init_page_count(page);
		__free_page(page);
	}

	bs.current_pages += nr_pages;
	totalram_pages = bs.current_pages;

 out:
	balloon_unlock(flags);

	return 0;
}

static int decrease_reservation(unsigned long nr_pages)
{
	unsigned long  pfn, i, flags;
	struct page   *page;
	void          *v;
	int            need_sleep = 0;
	int ret;
	struct xen_memory_reservation reservation = {
		.address_bits = 0,
		.extent_order = 0,
		.domid        = DOMID_SELF
	};

	if (nr_pages > ARRAY_SIZE(frame_list))
		nr_pages = ARRAY_SIZE(frame_list);

	for (i = 0; i < nr_pages; i++) {
		if ((page = alloc_page(GFP_BALLOON)) == NULL) {
			nr_pages = i;
			need_sleep = 1;
			break;
		}

		pfn = page_to_pfn(page);
		frame_list[i] = pfn_to_mfn(pfn);

		if (!PageHighMem(page)) {
			v = phys_to_virt(pfn << PAGE_SHIFT);
			scrub_pages(v, 1);
#ifdef CONFIG_XEN
			ret = HYPERVISOR_update_va_mapping(
				(unsigned long)v, __pte_ma(0), 0);
			BUG_ON(ret);
#endif
		}
#ifdef CONFIG_XEN_SCRUB_PAGES
		else {
			v = kmap(page);
			scrub_pages(v, 1);
			kunmap(page);
		}
#endif
	}

#ifdef CONFIG_XEN
	/* Ensure that ballooned highmem pages don't have kmaps. */
	kmap_flush_unused();
	flush_tlb_all();
#endif

	balloon_lock(flags);

	/* No more mappings: invalidate P2M and add to balloon. */
	for (i = 0; i < nr_pages; i++) {
		pfn = mfn_to_pfn(frame_list[i]);
		set_phys_to_machine(pfn, INVALID_P2M_ENTRY);
		balloon_append(pfn_to_page(pfn));
	}

	set_xen_guest_handle(reservation.extent_start, frame_list);
	reservation.nr_extents   = nr_pages;
	ret = HYPERVISOR_memory_op(XENMEM_decrease_reservation, &reservation);
	BUG_ON(ret != nr_pages);

	bs.current_pages -= nr_pages;
	totalram_pages = bs.current_pages;

	balloon_unlock(flags);

	return need_sleep;
}

/*
 * We avoid multiple worker processes conflicting via the balloon mutex.
 * We may of course race updates of the target counts (which are protected
 * by the balloon lock), or with changes to the Xen hard limit, but we will
 * recover from these in time.
 */
static void balloon_process(void *unused)
{
	int need_sleep = 0;
	long credit;

	mutex_lock(&balloon_mutex);

	do {
		credit = current_target() - bs.current_pages;
		if (credit > 0)
			need_sleep = (increase_reservation(credit) != 0);
		if (credit < 0)
			need_sleep = (decrease_reservation(-credit) != 0);

#ifndef CONFIG_PREEMPT
		if (need_resched())
			schedule();
#endif
	} while ((credit != 0) && !need_sleep);

	/* Schedule more work if there is some still to be done. */
	if (current_target() != bs.current_pages)
		mod_timer(&balloon_timer, jiffies + HZ);

	mutex_unlock(&balloon_mutex);
}

/* Resets the Xen limit, sets new target, and kicks off processing. */
void balloon_set_new_target(unsigned long target)
{
	/* No need for lock. Not read-modify-write updates. */
	bs.hard_limit   = ~0UL;
	bs.target_pages = target;
	schedule_work(&balloon_worker);
}

static struct xenbus_watch target_watch =
{
	.node = "memory/target"
};

/* React to a change in the target key */
static void watch_target(struct xenbus_watch *watch,
			 const char **vec, unsigned int len)
{
	unsigned long long new_target;
	int err;

	err = xenbus_scanf(XBT_NIL, "memory", "target", "%llu", &new_target);
	if (err != 1) {
		/* This is ok (for domain0 at least) - so just return */
		return;
	}

	/* The given memory/target value is in KiB, so it needs converting to
	 * pages. PAGE_SHIFT converts bytes to pages, hence PAGE_SHIFT - 10.
	 */
	balloon_set_new_target(new_target >> (PAGE_SHIFT - 10));
}

static int balloon_init_watcher(struct notifier_block *notifier,
				unsigned long event,
				void *data)
{
	int err;

	err = register_xenbus_watch(&target_watch);
	if (err)
		printk(KERN_ERR "Failed to set balloon watcher\n");

	return NOTIFY_DONE;
}

#ifdef CONFIG_PROC_FS
static int balloon_write(struct file *file, const char __user *buffer,
			 unsigned long count, void *data)
{
	char memstring[64], *endchar;
	unsigned long long target_bytes;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count <= 1)
		return -EBADMSG; /* runt */
	if (count > sizeof(memstring))
		return -EFBIG;   /* too long */

	if (copy_from_user(memstring, buffer, count))
		return -EFAULT;
	memstring[sizeof(memstring)-1] = '\0';

	target_bytes = memparse(memstring, &endchar);
	balloon_set_new_target(target_bytes >> PAGE_SHIFT);

	return count;
}

static int balloon_read(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
	int len;

	len = sprintf(
		page,
		"Current allocation: %8lu kB\n"
		"Requested target:   %8lu kB\n"
		"Low-mem balloon:    %8lu kB\n"
		"High-mem balloon:   %8lu kB\n"
		"Driver pages:       %8lu kB\n"
		"Xen hard limit:     ",
		PAGES2KB(bs.current_pages), PAGES2KB(bs.target_pages), 
		PAGES2KB(bs.balloon_low), PAGES2KB(bs.balloon_high),
		PAGES2KB(bs.driver_pages));

	if (bs.hard_limit != ~0UL)
		len += sprintf(page + len, "%8lu kB\n",
			       PAGES2KB(bs.hard_limit));
	else
		len += sprintf(page + len, "     ??? kB\n");

	*eof = 1;
	return len;
}
#endif

static struct notifier_block xenstore_notifier;

static int __init balloon_init(void)
{
#if defined(CONFIG_X86) && defined(CONFIG_XEN) 
	unsigned long pfn;
	struct page *page;
#endif

	if (!is_running_on_xen())
		return -ENODEV;

	IPRINTK("Initialising balloon driver.\n");

#ifdef CONFIG_XEN
	bs.current_pages = min(xen_start_info->nr_pages, max_pfn);
	totalram_pages   = bs.current_pages;
#else 
	bs.current_pages = totalram_pages; 
#endif
	bs.target_pages  = bs.current_pages;
	bs.balloon_low   = 0;
	bs.balloon_high  = 0;
	bs.driver_pages  = 0UL;
	bs.hard_limit    = ~0UL;

	init_timer(&balloon_timer);
	balloon_timer.data = 0;
	balloon_timer.function = balloon_alarm;
    
#ifdef CONFIG_PROC_FS
	if ((balloon_pde = create_xen_proc_entry("balloon", 0644)) == NULL) {
		WPRINTK("Unable to create /proc/xen/balloon.\n");
		return -1;
	}

	balloon_pde->read_proc  = balloon_read;
	balloon_pde->write_proc = balloon_write;
#endif
	balloon_sysfs_init();

#if defined(CONFIG_X86) && defined(CONFIG_XEN) 
	/* Initialise the balloon with excess memory space. */
	for (pfn = xen_start_info->nr_pages; pfn < max_pfn; pfn++) {
		page = pfn_to_page(pfn);
		if (!PageReserved(page))
			balloon_append(page);
	}
#endif

	target_watch.callback = watch_target;
	xenstore_notifier.notifier_call = balloon_init_watcher;

	register_xenstore_notifier(&xenstore_notifier);
    
	return 0;
}

subsys_initcall(balloon_init);

static void balloon_exit(void) 
{
    /* XXX - release balloon here */
    return; 
}

module_exit(balloon_exit); 

void balloon_update_driver_allowance(long delta)
{
	unsigned long flags;

	balloon_lock(flags);
	bs.driver_pages += delta;
	balloon_unlock(flags);
}

#ifdef CONFIG_XEN
static int dealloc_pte_fn(
	pte_t *pte, struct page *pmd_page, unsigned long addr, void *data)
{
	unsigned long mfn = pte_mfn(*pte);
	int ret;
	struct xen_memory_reservation reservation = {
		.nr_extents   = 1,
		.extent_order = 0,
		.domid        = DOMID_SELF
	};
	set_xen_guest_handle(reservation.extent_start, &mfn);
	set_pte_at(&init_mm, addr, pte, __pte_ma(0));
	set_phys_to_machine(__pa(addr) >> PAGE_SHIFT, INVALID_P2M_ENTRY);
	ret = HYPERVISOR_memory_op(XENMEM_decrease_reservation, &reservation);
	BUG_ON(ret != 1);
	return 0;
}
#endif

struct page **alloc_empty_pages_and_pagevec(int nr_pages)
{
	unsigned long vaddr, flags;
	struct page *page, **pagevec;
	int i, ret;

	pagevec = kmalloc(sizeof(page) * nr_pages, GFP_KERNEL);
	if (pagevec == NULL)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		page = pagevec[i] = alloc_page(GFP_KERNEL);
		if (page == NULL)
			goto err;

		vaddr = (unsigned long)page_address(page);

		scrub_pages(vaddr, 1);

		balloon_lock(flags);

		if (xen_feature(XENFEAT_auto_translated_physmap)) {
			unsigned long gmfn = page_to_pfn(page);
			struct xen_memory_reservation reservation = {
				.nr_extents   = 1,
				.extent_order = 0,
				.domid        = DOMID_SELF
			};
			set_xen_guest_handle(reservation.extent_start, &gmfn);
			ret = HYPERVISOR_memory_op(XENMEM_decrease_reservation,
						   &reservation);
			if (ret == 1)
				ret = 0; /* success */
		} else {
#ifdef CONFIG_XEN
			ret = apply_to_page_range(&init_mm, vaddr, PAGE_SIZE,
						  dealloc_pte_fn, NULL);
#else
			/* Cannot handle non-auto translate mode. */
			ret = 1;
#endif
		}

		if (ret != 0) {
			balloon_unlock(flags);
			__free_page(page);
			goto err;
		}

		totalram_pages = --bs.current_pages;

		balloon_unlock(flags);
	}

 out:
	schedule_work(&balloon_worker);
#ifdef CONFIG_XEN
	flush_tlb_all();
#endif
	return pagevec;

 err:
	balloon_lock(flags);
	while (--i >= 0)
		balloon_append(pagevec[i]);
	balloon_unlock(flags);
	kfree(pagevec);
	pagevec = NULL;
	goto out;
}

void free_empty_pages_and_pagevec(struct page **pagevec, int nr_pages)
{
	unsigned long flags;
	int i;

	if (pagevec == NULL)
		return;

	balloon_lock(flags);
	for (i = 0; i < nr_pages; i++) {
		BUG_ON(page_count(pagevec[i]) != 1);
		balloon_append(pagevec[i]);
	}
	balloon_unlock(flags);

	kfree(pagevec);

	schedule_work(&balloon_worker);
}

void balloon_release_driver_page(struct page *page)
{
	unsigned long flags;

	balloon_lock(flags);
	balloon_append(page);
	bs.driver_pages--;
	balloon_unlock(flags);

	schedule_work(&balloon_worker);
}

EXPORT_SYMBOL_GPL(balloon_update_driver_allowance);
EXPORT_SYMBOL_GPL(alloc_empty_pages_and_pagevec);
EXPORT_SYMBOL_GPL(free_empty_pages_and_pagevec);
EXPORT_SYMBOL_GPL(balloon_release_driver_page);

MODULE_LICENSE("Dual BSD/GPL");
