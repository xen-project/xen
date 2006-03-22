/******************************************************************************
 * arch/xen/drivers/blkif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/blkif/frontend
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Copyright (c) 2005, Christopher Clark
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

#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <xen/balloon.h>
#include <asm/hypervisor.h>
#include "common.h"

/*
 * These are rather arbitrary. They are fairly large because adjacent requests
 * pulled from a communication ring are quite likely to end up being part of
 * the same scatter/gather request at the disc.
 * 
 * ** TRY INCREASING 'blkif_reqs' IF WRITE SPEEDS SEEM TOO LOW **
 * 
 * This will increase the chances of being able to write whole tracks.
 * 64 should be enough to keep us competitive with Linux.
 */
static int blkif_reqs = 64;
module_param_named(reqs, blkif_reqs, int, 0);
MODULE_PARM_DESC(reqs, "Number of blkback requests to allocate");

static int mmap_pages;

/* Run-time switchable: /sys/module/blkback/parameters/ */
static unsigned int log_stats = 0;
static unsigned int debug_lvl = 0;
module_param(log_stats, int, 0644);
module_param(debug_lvl, int, 0644);

/*
 * Each outstanding request that we've passed to the lower device layers has a 
 * 'pending_req' allocated to it. Each buffer_head that completes decrements 
 * the pendcnt towards zero. When it hits zero, the specified domain has a 
 * response queued for it, with the saved 'id' passed back.
 */
typedef struct {
	blkif_t       *blkif;
	unsigned long  id;
	int            nr_pages;
	atomic_t       pendcnt;
	unsigned short operation;
	int            status;
	struct list_head free_list;
} pending_req_t;

static pending_req_t *pending_reqs;
static struct list_head pending_free;
static spinlock_t pending_free_lock = SPIN_LOCK_UNLOCKED;
static DECLARE_WAIT_QUEUE_HEAD(pending_free_wq);

#define BLKBACK_INVALID_HANDLE (~0)

static unsigned long mmap_vstart;
static unsigned long *pending_vaddrs;
static grant_handle_t *pending_grant_handles;

static inline int vaddr_pagenr(pending_req_t *req, int seg)
{
	return (req - pending_reqs) * BLKIF_MAX_SEGMENTS_PER_REQUEST + seg;
}

static inline unsigned long vaddr(pending_req_t *req, int seg)
{
	return pending_vaddrs[vaddr_pagenr(req, seg)];
}

#define pending_handle(_req, _seg) \
	(pending_grant_handles[vaddr_pagenr(_req, _seg)])


#ifdef CONFIG_XEN_BLKDEV_TAP_BE
/*
 * If the tap driver is used, we may get pages belonging to either the tap
 * or (more likely) the real frontend.  The backend must specify which domain
 * a given page belongs to in update_va_mapping though.  For the moment, 
 * the tap rewrites the ID field of the request to contain the request index
 * and the id of the real front end domain.
 */
#define BLKTAP_COOKIE 0xbeadfeed
static inline domid_t ID_TO_DOM(unsigned long id) { return (id >> 16); }
#endif

static int do_block_io_op(blkif_t *blkif);
static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req);
static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st);

/******************************************************************
 * misc small helpers
 */
static pending_req_t* alloc_req(void)
{
	pending_req_t *req = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pending_free_lock, flags);
	if (!list_empty(&pending_free)) {
		req = list_entry(pending_free.next, pending_req_t, free_list);
		list_del(&req->free_list);
	}
	spin_unlock_irqrestore(&pending_free_lock, flags);
	return req;
}

static void free_req(pending_req_t *req)
{
	unsigned long flags;
	int was_empty;

	spin_lock_irqsave(&pending_free_lock, flags);
	was_empty = list_empty(&pending_free);
	list_add(&req->free_list, &pending_free);
	spin_unlock_irqrestore(&pending_free_lock, flags);
	if (was_empty)
		wake_up(&pending_free_wq);
}

static void unplug_queue(blkif_t *blkif)
{
	if (blkif->plug == NULL)
		return;
	if (blkif->plug->unplug_fn)
		blkif->plug->unplug_fn(blkif->plug);
	blk_put_queue(blkif->plug);
	blkif->plug = NULL;
}

static void plug_queue(blkif_t *blkif, struct bio *bio)
{
	request_queue_t *q = bdev_get_queue(bio->bi_bdev);

	if (q == blkif->plug)
		return;
	unplug_queue(blkif);
	blk_get_queue(q);
	blkif->plug = q;
}

static void fast_flush_area(pending_req_t *req)
{
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int i, invcount = 0;
	grant_handle_t handle;
	int ret;

	for (i = 0; i < req->nr_pages; i++) {
		handle = pending_handle(req, i);
		if (handle == BLKBACK_INVALID_HANDLE)
			continue;
		unmap[invcount].host_addr    = vaddr(req, i);
		unmap[invcount].dev_bus_addr = 0;
		unmap[invcount].handle       = handle;
		pending_handle(req, i) = BLKBACK_INVALID_HANDLE;
		invcount++;
	}

	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, unmap, invcount);
	BUG_ON(ret);
}

/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static void print_stats(blkif_t *blkif)
{
	printk(KERN_DEBUG "%s: oo %3d  |  rd %4d  |  wr %4d\n",
	       current->comm, blkif->st_oo_req,
	       blkif->st_rd_req, blkif->st_wr_req);
	blkif->st_print = jiffies + msecs_to_jiffies(10 * 1000);
	blkif->st_rd_req = 0;
	blkif->st_wr_req = 0;
	blkif->st_oo_req = 0;
}

int blkif_schedule(void *arg)
{
	blkif_t          *blkif = arg;

	blkif_get(blkif);
	if (debug_lvl)
		printk(KERN_DEBUG "%s: started\n", current->comm);
	for (;;) {
		if (kthread_should_stop()) {
			/* asked to quit? */
			if (!atomic_read(&blkif->io_pending))
				break;
			if (debug_lvl)
				printk(KERN_DEBUG "%s: I/O pending, "
				       "delaying exit\n", current->comm);
		}

		if (!atomic_read(&blkif->io_pending)) {
			/* Wait for work to do. */
			wait_event_interruptible(
				blkif->wq,
				(atomic_read(&blkif->io_pending) ||
				 kthread_should_stop()));
		} else if (list_empty(&pending_free)) {
			/* Wait for pending_req becoming available. */
			wait_event_interruptible(
				pending_free_wq,
				!list_empty(&pending_free));
		}

		if (blkif->status != CONNECTED) {
			/* make sure we are connected */
			if (debug_lvl)
				printk(KERN_DEBUG "%s: not connected "
				       "(%d pending)\n",
				       current->comm,
				       atomic_read(&blkif->io_pending));
			wait_event_interruptible(
				blkif->wq,
				(blkif->status == CONNECTED ||
				 kthread_should_stop()));
			continue;
		}

		/* Schedule I/O */
		atomic_set(&blkif->io_pending, 0);
		if (do_block_io_op(blkif))
			atomic_inc(&blkif->io_pending);
		unplug_queue(blkif);

		if (log_stats && time_after(jiffies, blkif->st_print))
			print_stats(blkif);
	}

	if (log_stats)
		print_stats(blkif);
	if (debug_lvl)
		printk(KERN_DEBUG "%s: exiting\n", current->comm);
	blkif->xenblkd = NULL;
	blkif_put(blkif);
	return 0;
}

/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */

static void __end_block_io_op(pending_req_t *pending_req, int uptodate)
{
	/* An error fails the entire request. */
	if (!uptodate) {
		DPRINTK("Buffer not up-to-date at end of operation\n");
		pending_req->status = BLKIF_RSP_ERROR;
	}

	if (atomic_dec_and_test(&pending_req->pendcnt)) {
		fast_flush_area(pending_req);
		make_response(pending_req->blkif, pending_req->id,
			      pending_req->operation, pending_req->status);
		blkif_put(pending_req->blkif);
		free_req(pending_req);
	}
}

static int end_block_io_op(struct bio *bio, unsigned int done, int error)
{
	if (bio->bi_size != 0)
		return 1;
	__end_block_io_op(bio->bi_private, !error);
	bio_put(bio);
	return error;
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
	blkif_t *blkif = dev_id;

	atomic_inc(&blkif->io_pending);
	wake_up(&blkif->wq);
	return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int do_block_io_op(blkif_t *blkif)
{
	blkif_back_ring_t *blk_ring = &blkif->blk_ring;
	blkif_request_t *req;
	pending_req_t *pending_req;
	RING_IDX rc, rp;
	int more_to_do = 0;

	rc = blk_ring->req_cons;
	rp = blk_ring->sring->req_prod;
	rmb(); /* Ensure we see queued requests up to 'rp'. */

	while ((rc != rp) && !RING_REQUEST_CONS_OVERFLOW(blk_ring, rc)) {

		pending_req = alloc_req();
		if (NULL == pending_req) {
			blkif->st_oo_req++;
			more_to_do = 1;
			break;
		}

		req = RING_GET_REQUEST(blk_ring, rc);
		blk_ring->req_cons = ++rc; /* before make_response() */

		switch (req->operation) {
		case BLKIF_OP_READ:
			blkif->st_rd_req++;
			dispatch_rw_block_io(blkif, req, pending_req);
			break;
		case BLKIF_OP_WRITE:
			blkif->st_wr_req++;
			dispatch_rw_block_io(blkif, req, pending_req);
			break;
		default:
			DPRINTK("error: unknown block io operation [%d]\n",
				req->operation);
			make_response(blkif, req->id, req->operation,
				      BLKIF_RSP_ERROR);
			free_req(pending_req);
			break;
		}
	}
	return more_to_do;
}

static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req)
{
	extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]); 
	int operation = (req->operation == BLKIF_OP_WRITE) ? WRITE : READ;
	struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct phys_req preq;
	struct { 
		unsigned long buf; unsigned int nsec;
	} seg[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int nseg;
	struct bio *bio = NULL, *biolist[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	int ret, i, nbio = 0;

	/* Check that number of segments is sane. */
	nseg = req->nr_segments;
	if (unlikely(nseg == 0) || 
	    unlikely(nseg > BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
		DPRINTK("Bad number of segments in request (%d)\n", nseg);
		goto fail_response;
	}

	preq.dev           = req->handle;
	preq.sector_number = req->sector_number;
	preq.nr_sects      = 0;

	pending_req->blkif     = blkif;
	pending_req->id        = req->id;
	pending_req->operation = operation;
	pending_req->status    = BLKIF_RSP_OKAY;
	pending_req->nr_pages  = nseg;

	for (i = 0; i < nseg; i++) {
		seg[i].nsec = req->seg[i].last_sect -
			req->seg[i].first_sect + 1;

		if ((req->seg[i].last_sect >= (PAGE_SIZE >> 9)) ||
		    (seg[i].nsec <= 0))
			goto fail_response;
		preq.nr_sects += seg[i].nsec;

		map[i].host_addr = vaddr(pending_req, i);
		map[i].dom = blkif->domid;
		map[i].ref = req->seg[i].gref;
		map[i].flags = GNTMAP_host_map;
		if ( operation == WRITE )
			map[i].flags |= GNTMAP_readonly;
	}

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, nseg);
	BUG_ON(ret);

	for (i = 0; i < nseg; i++) {
		if (unlikely(map[i].status != 0)) {
			DPRINTK("invalid buffer -- could not remap it\n");
			goto fail_flush;
		}

		pending_handle(pending_req, i) = map[i].handle;
#ifdef __ia64__
		pending_vaddrs[vaddr_pagenr(pending_req, i)] =
			(unsigned long)gnttab_map_vaddr(map[i]);
#else
		set_phys_to_machine(__pa(vaddr(
			pending_req, i)) >> PAGE_SHIFT,
			FOREIGN_FRAME(map[i].dev_bus_addr >> PAGE_SHIFT));
#endif
		seg[i].buf  = map[i].dev_bus_addr | 
			(req->seg[i].first_sect << 9);
	}

	if (vbd_translate(&preq, blkif, operation) != 0) {
		DPRINTK("access denied: %s of [%llu,%llu] on dev=%04x\n", 
			operation == READ ? "read" : "write",
			preq.sector_number,
			preq.sector_number + preq.nr_sects, preq.dev); 
		goto fail_flush;
	}

	for (i = 0; i < nseg; i++) {
		if (((int)preq.sector_number|(int)seg[i].nsec) &
		    ((bdev_hardsect_size(preq.bdev) >> 9) - 1)) {
			DPRINTK("Misaligned I/O request from domain %d",
				blkif->domid);
			goto fail_put_bio;
		}

		while ((bio == NULL) ||
		       (bio_add_page(bio,
				     virt_to_page(vaddr(pending_req, i)),
				     seg[i].nsec << 9,
				     seg[i].buf & ~PAGE_MASK) == 0)) {
			bio = biolist[nbio++] = bio_alloc(GFP_KERNEL, nseg-i);
			if (unlikely(bio == NULL))
				goto fail_put_bio;
                
			bio->bi_bdev    = preq.bdev;
			bio->bi_private = pending_req;
			bio->bi_end_io  = end_block_io_op;
			bio->bi_sector  = preq.sector_number;
		}

		preq.sector_number += seg[i].nsec;
	}

	plug_queue(blkif, bio);
	atomic_set(&pending_req->pendcnt, nbio);
	blkif_get(blkif);

	for (i = 0; i < nbio; i++)
		submit_bio(operation, biolist[i]);

	return;

 fail_put_bio:
	for (i = 0; i < (nbio-1); i++)
		bio_put(biolist[i]);
 fail_flush:
	fast_flush_area(pending_req);
 fail_response:
	make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
	free_req(pending_req);
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st)
{
	blkif_response_t *resp;
	unsigned long     flags;
	blkif_back_ring_t *blk_ring = &blkif->blk_ring;
	int more_to_do = 0;
	int notify;

	spin_lock_irqsave(&blkif->blk_ring_lock, flags);

	/* Place on the response ring for the relevant domain. */ 
	resp = RING_GET_RESPONSE(blk_ring, blk_ring->rsp_prod_pvt);
	resp->id        = id;
	resp->operation = op;
	resp->status    = st;
	blk_ring->rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(blk_ring, notify);

	if (blk_ring->rsp_prod_pvt == blk_ring->req_cons) {
		/*
		 * Tail check for pending requests. Allows frontend to avoid
		 * notifications if requests are already in flight (lower
		 * overheads and promotes batching).
		 */
		RING_FINAL_CHECK_FOR_REQUESTS(blk_ring, more_to_do);

	} else if (RING_HAS_UNCONSUMED_REQUESTS(blk_ring)) {
		more_to_do = 1;

	}
	spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);

	if (more_to_do) {
		atomic_inc(&blkif->io_pending);
		wake_up(&blkif->wq);
	}
	if (notify)
		notify_remote_via_irq(blkif->irq);
}

static int __init blkif_init(void)
{
	struct page *page;
	int i;

	if (xen_init() < 0)
		return -ENODEV;

	mmap_pages            = blkif_reqs * BLKIF_MAX_SEGMENTS_PER_REQUEST;
	pending_reqs          = kmalloc(sizeof(pending_reqs[0]) *
					blkif_reqs, GFP_KERNEL);
	pending_grant_handles = kmalloc(sizeof(pending_grant_handles[0]) *
					mmap_pages, GFP_KERNEL);
	pending_vaddrs        = kmalloc(sizeof(pending_vaddrs[0]) *
					mmap_pages, GFP_KERNEL);
	if (!pending_reqs || !pending_grant_handles || !pending_vaddrs) {
		kfree(pending_reqs);
		kfree(pending_grant_handles);
		kfree(pending_vaddrs);
		printk("%s: out of memory\n", __FUNCTION__);
		return -ENOMEM;
	}

	blkif_interface_init();
	
#ifdef __ia64__
	extern unsigned long alloc_empty_foreign_map_page_range(
		unsigned long pages);
	mmap_vstart = (unsigned long)
		alloc_empty_foreign_map_page_range(mmap_pages);
#else /* ! ia64 */
	page = balloon_alloc_empty_page_range(mmap_pages);
	BUG_ON(page == NULL);
	mmap_vstart = (unsigned long)pfn_to_kaddr(page_to_pfn(page));
#endif
	printk("%s: reqs=%d, pages=%d, mmap_vstart=0x%lx\n",
	       __FUNCTION__, blkif_reqs, mmap_pages, mmap_vstart);
	BUG_ON(mmap_vstart == 0);
	for (i = 0; i < mmap_pages; i++) {
		pending_vaddrs[i] = mmap_vstart + (i << PAGE_SHIFT);
		pending_grant_handles[i] = BLKBACK_INVALID_HANDLE;
	}

	memset(pending_reqs, 0, sizeof(pending_reqs));
	INIT_LIST_HEAD(&pending_free);

	for (i = 0; i < blkif_reqs; i++)
		list_add_tail(&pending_reqs[i].free_list, &pending_free);
    
	blkif_xenbus_init();
	__unsafe(THIS_MODULE);
	return 0;
}

module_init(blkif_init);

static void blkif_exit(void)
{
	BUG();
}

module_exit(blkif_exit);

MODULE_LICENSE("Dual BSD/GPL");

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
