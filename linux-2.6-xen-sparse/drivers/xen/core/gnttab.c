/******************************************************************************
 * gnttab.c
 * 
 * Granting foreign access to our memory reservation.
 * 
 * Copyright (c) 2005, Christopher Clark
 * Copyright (c) 2004-2005, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <xen/interface/xen.h>
#include <asm/fixmap.h>
#include <asm/uaccess.h>
#include <xen/public/privcmd.h>
#include <xen/gnttab.h>
#include <asm/synch_bitops.h>

#if 1
#define ASSERT(_p)							      \
	if ( !(_p) ) { printk(KERN_ALERT"Assertion '%s': line %d, file %s\n", \
	#_p , __LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p) ((void)0)
#endif

#define WPRINTK(fmt, args...)				\
	printk(KERN_WARNING "xen_grant: " fmt, ##args)


EXPORT_SYMBOL(gnttab_grant_foreign_access);
EXPORT_SYMBOL(gnttab_end_foreign_access_ref);
EXPORT_SYMBOL(gnttab_end_foreign_access);
EXPORT_SYMBOL(gnttab_query_foreign_access);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer);
EXPORT_SYMBOL(gnttab_end_foreign_transfer_ref);
EXPORT_SYMBOL(gnttab_end_foreign_transfer);
EXPORT_SYMBOL(gnttab_alloc_grant_references);
EXPORT_SYMBOL(gnttab_free_grant_references);
EXPORT_SYMBOL(gnttab_free_grant_reference);
EXPORT_SYMBOL(gnttab_claim_grant_reference);
EXPORT_SYMBOL(gnttab_release_grant_reference);
EXPORT_SYMBOL(gnttab_request_free_callback);
EXPORT_SYMBOL(gnttab_grant_foreign_access_ref);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer_ref);

/* External tools reserve first few grant table entries. */
#define NR_RESERVED_ENTRIES 8

#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))
#define GNTTAB_LIST_END (NR_GRANT_ENTRIES + 1)

static grant_ref_t gnttab_list[NR_GRANT_ENTRIES];
static int gnttab_free_count;
static grant_ref_t gnttab_free_head;
static spinlock_t gnttab_list_lock = SPIN_LOCK_UNLOCKED;

static grant_entry_t *shared;

static struct gnttab_free_callback *gnttab_free_callback_list = NULL;

static int
get_free_entries(int count)
{
	unsigned long flags;
	int ref;
	grant_ref_t head;
	spin_lock_irqsave(&gnttab_list_lock, flags);
	if (gnttab_free_count < count) {
		spin_unlock_irqrestore(&gnttab_list_lock, flags);
		return -1;
	}
	ref = head = gnttab_free_head;
	gnttab_free_count -= count;
	while (count-- > 1)
		head = gnttab_list[head];
	gnttab_free_head = gnttab_list[head];
	gnttab_list[head] = GNTTAB_LIST_END;
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
	return ref;
}

#define get_free_entry() get_free_entries(1)

static void
do_free_callbacks(void)
{
	struct gnttab_free_callback *callback, *next;

	callback = gnttab_free_callback_list;
	gnttab_free_callback_list = NULL;

	while (callback != NULL) {
		next = callback->next;
		if (gnttab_free_count >= callback->count) {
			callback->next = NULL;
			callback->fn(callback->arg);
		} else {
			callback->next = gnttab_free_callback_list;
			gnttab_free_callback_list = callback;
		}
		callback = next;
	}
}

static inline void
check_free_callbacks(void)
{
	if (unlikely(gnttab_free_callback_list))
		do_free_callbacks();
}

static void
put_free_entry(grant_ref_t ref)
{
	unsigned long flags;
	spin_lock_irqsave(&gnttab_list_lock, flags);
	gnttab_list[ref] = gnttab_free_head;
	gnttab_free_head = ref;
	gnttab_free_count++;
	check_free_callbacks();
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

/*
 * Public grant-issuing interface functions
 */

int
gnttab_grant_foreign_access(domid_t domid, unsigned long frame, int readonly)
{
	int ref;
    
	if (unlikely((ref = get_free_entry()) == -1))
		return -ENOSPC;

	shared[ref].frame = frame;
	shared[ref].domid = domid;
	wmb();
	shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);

	return ref;
}

void
gnttab_grant_foreign_access_ref(grant_ref_t ref, domid_t domid,
				unsigned long frame, int readonly)
{
	shared[ref].frame = frame;
	shared[ref].domid = domid;
	wmb();
	shared[ref].flags = GTF_permit_access | (readonly ? GTF_readonly : 0);
}


int
gnttab_query_foreign_access(grant_ref_t ref)
{
	u16 nflags;

	nflags = shared[ref].flags;

	return (nflags & (GTF_reading|GTF_writing));
}

int
gnttab_end_foreign_access_ref(grant_ref_t ref, int readonly)
{
	u16 flags, nflags;

	nflags = shared[ref].flags;
	do {
		if ( (flags = nflags) & (GTF_reading|GTF_writing) ) {
			printk(KERN_ALERT "WARNING: g.e. still in use!\n");
			return 0;
		}
	}
	while ((nflags = synch_cmpxchg(&shared[ref].flags, flags, 0)) !=
	       flags);

	return 1;
}

void
gnttab_end_foreign_access(grant_ref_t ref, int readonly, unsigned long page)
{
	if (gnttab_end_foreign_access_ref(ref, readonly)) {
		put_free_entry(ref);
		if (page != 0) {
			free_page(page);
		}
	}
	else {
		/* XXX This needs to be fixed so that the ref and page are
		   placed on a list to be freed up later. */
		printk(KERN_WARNING
		       "WARNING: leaking g.e. and page still in use!\n");
	}
}

int
gnttab_grant_foreign_transfer(domid_t domid, unsigned long pfn)
{
	int ref;

	if (unlikely((ref = get_free_entry()) == -1))
		return -ENOSPC;
	gnttab_grant_foreign_transfer_ref(ref, domid, pfn);

	return ref;
}

void
gnttab_grant_foreign_transfer_ref(grant_ref_t ref, domid_t domid,
				  unsigned long pfn)
{
	shared[ref].frame = pfn;
	shared[ref].domid = domid;
	wmb();
	shared[ref].flags = GTF_accept_transfer;
}

unsigned long
gnttab_end_foreign_transfer_ref(grant_ref_t ref)
{
	unsigned long frame;
	u16           flags;

	/*
         * If a transfer is not even yet started, try to reclaim the grant
         * reference and return failure (== 0).
         */
	while (!((flags = shared[ref].flags) & GTF_transfer_committed)) {
		if ( synch_cmpxchg(&shared[ref].flags, flags, 0) == flags )
			return 0;
		cpu_relax();
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed)) {
		flags = shared[ref].flags;
		cpu_relax();
	}

	/* Read the frame number /after/ reading completion status. */
	rmb();
	frame = shared[ref].frame;
	BUG_ON(frame == 0);

	return frame;
}

unsigned long
gnttab_end_foreign_transfer(grant_ref_t ref)
{
	unsigned long frame = gnttab_end_foreign_transfer_ref(ref);
	put_free_entry(ref);
	return frame;
}

void
gnttab_free_grant_reference(grant_ref_t ref)
{

	put_free_entry(ref);
}

void
gnttab_free_grant_references(grant_ref_t head)
{
	grant_ref_t ref;
	unsigned long flags;
	int count = 1;
	if (head == GNTTAB_LIST_END)
		return;
	spin_lock_irqsave(&gnttab_list_lock, flags);
	ref = head;
	while (gnttab_list[ref] != GNTTAB_LIST_END) {
		ref = gnttab_list[ref];
		count++;
	}
	gnttab_list[ref] = gnttab_free_head;
	gnttab_free_head = head;
	gnttab_free_count += count;
	check_free_callbacks();
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

int
gnttab_alloc_grant_references(u16 count, grant_ref_t *head)
{
	int h = get_free_entries(count);

	if (h == -1)
		return -ENOSPC;

	*head = h;

	return 0;
}

int
gnttab_claim_grant_reference(grant_ref_t *private_head)
{
	grant_ref_t g = *private_head;
	if (unlikely(g == GNTTAB_LIST_END))
		return -ENOSPC;
	*private_head = gnttab_list[g];
	return g;
}

void
gnttab_release_grant_reference(grant_ref_t *private_head, grant_ref_t  release)
{
	gnttab_list[release] = *private_head;
	*private_head = release;
}

void
gnttab_request_free_callback(struct gnttab_free_callback *callback,
			     void (*fn)(void *), void *arg, u16 count)
{
	unsigned long flags;
	spin_lock_irqsave(&gnttab_list_lock, flags);
	if (callback->next)
		goto out;
	callback->fn = fn;
	callback->arg = arg;
	callback->count = count;
	callback->next = gnttab_free_callback_list;
	gnttab_free_callback_list = callback;
	check_free_callbacks();
 out:
	spin_unlock_irqrestore(&gnttab_list_lock, flags);
}

int
gnttab_resume(void)
{
	gnttab_setup_table_t setup;
	unsigned long        frames[NR_GRANT_FRAMES];
	int                  i;

	setup.dom        = DOMID_SELF;
	setup.nr_frames  = NR_GRANT_FRAMES;
	setup.frame_list = frames;

	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1));
	BUG_ON(setup.status != 0);

#ifdef __ia64__
	shared = __va(frames[0] << PAGE_SHIFT);
	printk("grant table at %p\n", shared);
#else
	for (i = 0; i < NR_GRANT_FRAMES; i++)
		set_fixmap(FIX_GNTTAB_END - i, frames[i] << PAGE_SHIFT);
#endif

	return 0;
}

int
gnttab_suspend(void)
{
	int i;

	for (i = 0; i < NR_GRANT_FRAMES; i++)
		clear_fixmap(FIX_GNTTAB_END - i);

	return 0;
}

static int __init
gnttab_init(void)
{
	int i;

	if (xen_init() < 0)
		return -ENODEV;

	BUG_ON(gnttab_resume());

#ifndef __ia64__
	shared = (grant_entry_t *)fix_to_virt(FIX_GNTTAB_END);
#endif

	for (i = NR_RESERVED_ENTRIES; i < NR_GRANT_ENTRIES; i++)
		gnttab_list[i] = i + 1;
	gnttab_free_count = NR_GRANT_ENTRIES - NR_RESERVED_ENTRIES;
	gnttab_free_head  = NR_RESERVED_ENTRIES;

	printk("Grant table initialized\n");
	return 0;
}

core_initcall(gnttab_init);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
