/******************************************************************************
 * blkfront.c
 * 
 * XenLinux virtual block-device driver.
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004, Christian Limpach
 * Copyright (c) 2004, Andrew Warfield
 * Copyright (c) 2005, Christopher Clark
 * Copyright (c) 2005, XenSource Ltd
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

#include <linux/version.h>
#include "block.h"
#include <linux/cdrom.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <xen/evtchn.h>
#include <xen/xenbus.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/protocols.h>
#include <xen/gnttab.h>
#include <asm/hypervisor.h>
#include <asm/maddr.h>

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#define BLKIF_STATE_DISCONNECTED 0
#define BLKIF_STATE_CONNECTED    1
#define BLKIF_STATE_SUSPENDED    2

#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST * BLK_RING_SIZE)
#define GRANT_INVALID_REF	0

static void connect(struct blkfront_info *);
static void blkfront_closing(struct xenbus_device *);
static int blkfront_remove(struct xenbus_device *);
static int talk_to_backend(struct xenbus_device *, struct blkfront_info *);
static int setup_blkring(struct xenbus_device *, struct blkfront_info *);

static void kick_pending_request_queues(struct blkfront_info *);

static irqreturn_t blkif_int(int irq, void *dev_id, struct pt_regs *ptregs);
static void blkif_restart_queue(void *arg);
static void blkif_recover(struct blkfront_info *);
static void blkif_completion(struct blk_shadow *);
static void blkif_free(struct blkfront_info *, int);


/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffer for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Initialised state.
 */
static int blkfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err, vdevice, i;
	struct blkfront_info *info;

	/* FIXME: Use dynamic device id if this is not set. */
	err = xenbus_scanf(XBT_NIL, dev->nodename,
			   "virtual-device", "%i", &vdevice);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading virtual-device");
		return err;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}

	info->xbdev = dev;
	info->vdevice = vdevice;
	info->connected = BLKIF_STATE_DISCONNECTED;
	INIT_WORK(&info->work, blkif_restart_queue, (void *)info);

	for (i = 0; i < BLK_RING_SIZE; i++)
		info->shadow[i].req.id = i+1;
	info->shadow[BLK_RING_SIZE-1].req.id = 0x0fffffff;

	/* Front end dir is a number, which is used as the id. */
	info->handle = simple_strtoul(strrchr(dev->nodename,'/')+1, NULL, 0);
	dev->dev.driver_data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		kfree(info);
		dev->dev.driver_data = NULL;
		return err;
	}

	return 0;
}


/**
 * We are reconnecting to the backend, due to a suspend/resume, or a backend
 * driver restart.  We tear down our blkif structure and recreate it, but
 * leave the device-layer structures intact so that this is transparent to the
 * rest of the kernel.
 */
static int blkfront_resume(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->dev.driver_data;
	int err;

	DPRINTK("blkfront_resume: %s\n", dev->nodename);

	blkif_free(info, info->connected == BLKIF_STATE_CONNECTED);

	err = talk_to_backend(dev, info);
	if (info->connected == BLKIF_STATE_SUSPENDED && !err)
		blkif_recover(info);

	return err;
}


/* Common code used when first setting up, and when resuming. */
static int talk_to_backend(struct xenbus_device *dev,
			   struct blkfront_info *info)
{
	const char *message = NULL;
	struct xenbus_transaction xbt;
	int err;

	/* Create shared ring, alloc event channel. */
	err = setup_blkring(dev, info);
	if (err)
		goto out;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_blkring;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "ring-ref","%u", info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
			    irq_to_evtchn_port(info->irq));
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename, "protocol", "%s",
			    XEN_IO_PROTO_ABI_NATIVE);
	if (err) {
		message = "writing protocol";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_blkring;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);

	return 0;

 abort_transaction:
	xenbus_transaction_end(xbt, 1);
	if (message)
		xenbus_dev_fatal(dev, err, "%s", message);
 destroy_blkring:
	blkif_free(info, 0);
 out:
	return err;
}


static int setup_blkring(struct xenbus_device *dev,
			 struct blkfront_info *info)
{
	blkif_sring_t *sring;
	int err;

	info->ring_ref = GRANT_INVALID_REF;

	sring = (blkif_sring_t *)__get_free_page(GFP_KERNEL);
	if (!sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&info->ring, sring, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(info->ring.sring));
	if (err < 0) {
		free_page((unsigned long)sring);
		info->ring.sring = NULL;
		goto fail;
	}
	info->ring_ref = err;

	err = bind_listening_port_to_irqhandler(
		dev->otherend_id, blkif_int, SA_SAMPLE_RANDOM, "blkif", info);
	if (err <= 0) {
		xenbus_dev_fatal(dev, err,
				 "bind_listening_port_to_irqhandler");
		goto fail;
	}
	info->irq = err;

	return 0;
fail:
	blkif_free(info, 0);
	return err;
}


/**
 * Callback received when the backend's state changes.
 */
static void backend_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct blkfront_info *info = dev->dev.driver_data;
	struct block_device *bd;

	DPRINTK("blkfront:backend_changed.\n");

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateConnected:
		connect(info);
		break;

	case XenbusStateClosing:
		bd = bdget(info->dev);
		if (bd == NULL)
			xenbus_dev_fatal(dev, -ENODEV, "bdget failed");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
		down(&bd->bd_sem);
#else
		mutex_lock(&bd->bd_mutex);
#endif
		if (info->users > 0)
			xenbus_dev_error(dev, -EBUSY,
					 "Device in use; refusing to close");
		else
			blkfront_closing(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
		up(&bd->bd_sem);
#else
		mutex_unlock(&bd->bd_mutex);
#endif
		bdput(bd);
		break;
	}
}


/* ** Connection ** */


/*
 * Invoked when the backend is finally 'ready' (and has told produced
 * the details about the physical device - #sectors, size, etc).
 */
static void connect(struct blkfront_info *info)
{
	unsigned long long sectors;
	unsigned long sector_size;
	unsigned int binfo;
	int err;

	if ((info->connected == BLKIF_STATE_CONNECTED) ||
	    (info->connected == BLKIF_STATE_SUSPENDED) )
		return;

	DPRINTK("blkfront.c:connect:%s.\n", info->xbdev->otherend);

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "sectors", "%Lu", &sectors,
			    "info", "%u", &binfo,
			    "sector-size", "%lu", &sector_size,
			    NULL);
	if (err) {
		xenbus_dev_fatal(info->xbdev, err,
				 "reading backend fields at %s",
				 info->xbdev->otherend);
		return;
	}

	err = xenbus_gather(XBT_NIL, info->xbdev->otherend,
			    "feature-barrier", "%lu", &info->feature_barrier,
			    NULL);
	if (err)
		info->feature_barrier = 0;

	err = xlvbd_add(sectors, info->vdevice, binfo, sector_size, info);
	if (err) {
		xenbus_dev_fatal(info->xbdev, err, "xlvbd_add at %s",
				 info->xbdev->otherend);
		return;
	}

	(void)xenbus_switch_state(info->xbdev, XenbusStateConnected);

	/* Kick pending requests. */
	spin_lock_irq(&blkif_io_lock);
	info->connected = BLKIF_STATE_CONNECTED;
	kick_pending_request_queues(info);
	spin_unlock_irq(&blkif_io_lock);

	add_disk(info->gd);
}

/**
 * Handle the change of state of the backend to Closing.  We must delete our
 * device-layer structures now, to ensure that writes are flushed through to
 * the backend.  Once is this done, we can switch to Closed in
 * acknowledgement.
 */
static void blkfront_closing(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->dev.driver_data;
	unsigned long flags;

	DPRINTK("blkfront_closing: %s removed\n", dev->nodename);

	if (info->rq == NULL)
		goto out;

	spin_lock_irqsave(&blkif_io_lock, flags);
	/* No more blkif_request(). */
	blk_stop_queue(info->rq);
	/* No more gnttab callback work. */
	gnttab_cancel_free_callback(&info->callback);
	spin_unlock_irqrestore(&blkif_io_lock, flags);

	/* Flush gnttab callback work. Must be done with no locks held. */
	flush_scheduled_work();

	xlvbd_del(info);

 out:
	xenbus_frontend_closed(dev);
}


static int blkfront_remove(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->dev.driver_data;

	DPRINTK("blkfront_remove: %s removed\n", dev->nodename);

	blkif_free(info, 0);

	kfree(info);

	return 0;
}


static inline int GET_ID_FROM_FREELIST(
	struct blkfront_info *info)
{
	unsigned long free = info->shadow_free;
	BUG_ON(free > BLK_RING_SIZE);
	info->shadow_free = info->shadow[free].req.id;
	info->shadow[free].req.id = 0x0fffffee; /* debug */
	return free;
}

static inline void ADD_ID_TO_FREELIST(
	struct blkfront_info *info, unsigned long id)
{
	info->shadow[id].req.id  = info->shadow_free;
	info->shadow[id].request = 0;
	info->shadow_free = id;
}

static inline void flush_requests(struct blkfront_info *info)
{
	int notify;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

	if (notify)
		notify_remote_via_irq(info->irq);
}

static void kick_pending_request_queues(struct blkfront_info *info)
{
	if (!RING_FULL(&info->ring)) {
		/* Re-enable calldowns. */
		blk_start_queue(info->rq);
		/* Kick things off immediately. */
		do_blkif_request(info->rq);
	}
}

static void blkif_restart_queue(void *arg)
{
	struct blkfront_info *info = (struct blkfront_info *)arg;
	spin_lock_irq(&blkif_io_lock);
	if (info->connected == BLKIF_STATE_CONNECTED)
		kick_pending_request_queues(info);
	spin_unlock_irq(&blkif_io_lock);
}

static void blkif_restart_queue_callback(void *arg)
{
	struct blkfront_info *info = (struct blkfront_info *)arg;
	schedule_work(&info->work);
}

int blkif_open(struct inode *inode, struct file *filep)
{
	struct blkfront_info *info = inode->i_bdev->bd_disk->private_data;
	info->users++;
	return 0;
}


int blkif_release(struct inode *inode, struct file *filep)
{
	struct blkfront_info *info = inode->i_bdev->bd_disk->private_data;
	info->users--;
	if (info->users == 0) {
		/* Check whether we have been instructed to close.  We will
		   have ignored this request initially, as the device was
		   still mounted. */
		struct xenbus_device * dev = info->xbdev;
		enum xenbus_state state = xenbus_read_driver_state(dev->otherend);

		if (state == XenbusStateClosing)
			blkfront_closing(dev);
	}
	return 0;
}


int blkif_ioctl(struct inode *inode, struct file *filep,
		unsigned command, unsigned long argument)
{
	int i;

	DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
		      command, (long)argument, inode->i_rdev);

	switch (command) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	case HDIO_GETGEO: {
		struct block_device *bd = inode->i_bdev;
		struct hd_geometry geo;
		int ret;

                if (!argument)
                        return -EINVAL;

		geo.start = get_start_sect(bd);
		ret = blkif_getgeo(bd, &geo);
		if (ret)
			return ret;

		if (copy_to_user((struct hd_geometry __user *)argument, &geo,
				 sizeof(geo)))
                        return -EFAULT;

                return 0;
	}
#endif
	case CDROMMULTISESSION:
		DPRINTK("FIXME: support multisession CDs later\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char __user *)(argument + i)))
				return -EFAULT;
		return 0;

	default:
		/*printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		  command);*/
		return -EINVAL; /* same return as native Linux */
	}

	return 0;
}


int blkif_getgeo(struct block_device *bd, struct hd_geometry *hg)
{
	/* We don't have real geometry info, but let's at least return
	   values consistent with the size of the device */
	sector_t nsect = get_capacity(bd->bd_disk);
	sector_t cylinders = nsect;

	hg->heads = 0xff;
	hg->sectors = 0x3f;
	sector_div(cylinders, hg->heads * hg->sectors);
	hg->cylinders = cylinders;
	if ((sector_t)(hg->cylinders + 1) * hg->heads * hg->sectors < nsect)
		hg->cylinders = 0xffff;
	return 0;
}


/*
 * blkif_queue_request
 *
 * request block io
 *
 * id: for guest use only.
 * operation: BLKIF_OP_{READ,WRITE,PROBE}
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 */
static int blkif_queue_request(struct request *req)
{
	struct blkfront_info *info = req->rq_disk->private_data;
	unsigned long buffer_mfn;
	blkif_request_t *ring_req;
	struct bio *bio;
	struct bio_vec *bvec;
	int idx;
	unsigned long id;
	unsigned int fsect, lsect;
	int ref;
	grant_ref_t gref_head;

	if (unlikely(info->connected != BLKIF_STATE_CONNECTED))
		return 1;

	if (gnttab_alloc_grant_references(
		BLKIF_MAX_SEGMENTS_PER_REQUEST, &gref_head) < 0) {
		gnttab_request_free_callback(
			&info->callback,
			blkif_restart_queue_callback,
			info,
			BLKIF_MAX_SEGMENTS_PER_REQUEST);
		return 1;
	}

	/* Fill out a communications ring structure. */
	ring_req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);
	id = GET_ID_FROM_FREELIST(info);
	info->shadow[id].request = (unsigned long)req;

	ring_req->id = id;
	ring_req->sector_number = (blkif_sector_t)req->sector;
	ring_req->handle = info->handle;

	ring_req->operation = rq_data_dir(req) ?
		BLKIF_OP_WRITE : BLKIF_OP_READ;
	if (blk_barrier_rq(req))
		ring_req->operation = BLKIF_OP_WRITE_BARRIER;

	ring_req->nr_segments = 0;
	rq_for_each_bio (bio, req) {
		bio_for_each_segment (bvec, bio, idx) {
			BUG_ON(ring_req->nr_segments
			       == BLKIF_MAX_SEGMENTS_PER_REQUEST);
			buffer_mfn = page_to_phys(bvec->bv_page) >> PAGE_SHIFT;
			fsect = bvec->bv_offset >> 9;
			lsect = fsect + (bvec->bv_len >> 9) - 1;
			/* install a grant reference. */
			ref = gnttab_claim_grant_reference(&gref_head);
			BUG_ON(ref == -ENOSPC);

			gnttab_grant_foreign_access_ref(
				ref,
				info->xbdev->otherend_id,
				buffer_mfn,
				rq_data_dir(req) );

			info->shadow[id].frame[ring_req->nr_segments] =
				mfn_to_pfn(buffer_mfn);

			ring_req->seg[ring_req->nr_segments] =
				(struct blkif_request_segment) {
					.gref       = ref,
					.first_sect = fsect,
					.last_sect  = lsect };

			ring_req->nr_segments++;
		}
	}

	info->ring.req_prod_pvt++;

	/* Keep a private copy so we can reissue requests when recovering. */
	info->shadow[id].req = *ring_req;

	gnttab_free_grant_references(gref_head);

	return 0;
}

/*
 * do_blkif_request
 *  read a block; request is in a request queue
 */
void do_blkif_request(request_queue_t *rq)
{
	struct blkfront_info *info = NULL;
	struct request *req;
	int queued;

	DPRINTK("Entered do_blkif_request\n");

	queued = 0;

	while ((req = elv_next_request(rq)) != NULL) {
		info = req->rq_disk->private_data;
		if (!blk_fs_request(req)) {
			end_request(req, 0);
			continue;
		}

		if (RING_FULL(&info->ring))
			goto wait;

		DPRINTK("do_blk_req %p: cmd %p, sec %llx, "
			"(%u/%li) buffer:%p [%s]\n",
			req, req->cmd, (long long)req->sector,
			req->current_nr_sectors,
			req->nr_sectors, req->buffer,
			rq_data_dir(req) ? "write" : "read");


		blkdev_dequeue_request(req);
		if (blkif_queue_request(req)) {
			blk_requeue_request(rq, req);
		wait:
			/* Avoid pointless unplugs. */
			blk_stop_queue(rq);
			break;
		}

		queued++;
	}

	if (queued != 0)
		flush_requests(info);
}


static irqreturn_t blkif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
	struct request *req;
	blkif_response_t *bret;
	RING_IDX i, rp;
	unsigned long flags;
	struct blkfront_info *info = (struct blkfront_info *)dev_id;
	int uptodate;

	spin_lock_irqsave(&blkif_io_lock, flags);

	if (unlikely(info->connected != BLKIF_STATE_CONNECTED)) {
		spin_unlock_irqrestore(&blkif_io_lock, flags);
		return IRQ_HANDLED;
	}

 again:
	rp = info->ring.sring->rsp_prod;
	rmb(); /* Ensure we see queued responses up to 'rp'. */

	for (i = info->ring.rsp_cons; i != rp; i++) {
		unsigned long id;
		int ret;

		bret = RING_GET_RESPONSE(&info->ring, i);
		id   = bret->id;
		req  = (struct request *)info->shadow[id].request;

		blkif_completion(&info->shadow[id]);

		ADD_ID_TO_FREELIST(info, id);

		uptodate = (bret->status == BLKIF_RSP_OKAY);
		switch (bret->operation) {
		case BLKIF_OP_WRITE_BARRIER:
			if (unlikely(bret->status == BLKIF_RSP_EOPNOTSUPP)) {
				printk("blkfront: %s: write barrier op failed\n",
				       info->gd->disk_name);
				uptodate = -EOPNOTSUPP;
				info->feature_barrier = 0;
			        xlvbd_barrier(info);
			}
			/* fall through */
		case BLKIF_OP_READ:
		case BLKIF_OP_WRITE:
			if (unlikely(bret->status != BLKIF_RSP_OKAY))
				DPRINTK("Bad return from blkdev data "
					"request: %x\n", bret->status);

			ret = end_that_request_first(req, uptodate,
				req->hard_nr_sectors);
			BUG_ON(ret);
			end_that_request_last(req, uptodate);
			break;
		default:
			BUG();
		}
	}

	info->ring.rsp_cons = i;

	if (i != info->ring.req_prod_pvt) {
		int more_to_do;
		RING_FINAL_CHECK_FOR_RESPONSES(&info->ring, more_to_do);
		if (more_to_do)
			goto again;
	} else
		info->ring.sring->rsp_event = i + 1;

	kick_pending_request_queues(info);

	spin_unlock_irqrestore(&blkif_io_lock, flags);

	return IRQ_HANDLED;
}

static void blkif_free(struct blkfront_info *info, int suspend)
{
	/* Prevent new requests being issued until we fix things up. */
	spin_lock_irq(&blkif_io_lock);
	info->connected = suspend ?
		BLKIF_STATE_SUSPENDED : BLKIF_STATE_DISCONNECTED;
	/* No more blkif_request(). */
	if (info->rq)
		blk_stop_queue(info->rq);
	/* No more gnttab callback work. */
	gnttab_cancel_free_callback(&info->callback);
	spin_unlock_irq(&blkif_io_lock);

	/* Flush gnttab callback work. Must be done with no locks held. */
	flush_scheduled_work();

	/* Free resources associated with old device channel. */
	if (info->ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)info->ring.sring);
		info->ring_ref = GRANT_INVALID_REF;
		info->ring.sring = NULL;
	}
	if (info->irq)
		unbind_from_irqhandler(info->irq, info);
	info->irq = 0;
}

static void blkif_completion(struct blk_shadow *s)
{
	int i;
	for (i = 0; i < s->req.nr_segments; i++)
		gnttab_end_foreign_access(s->req.seg[i].gref, 0, 0UL);
}

static void blkif_recover(struct blkfront_info *info)
{
	int i;
	blkif_request_t *req;
	struct blk_shadow *copy;
	int j;

	/* Stage 1: Make a safe copy of the shadow state. */
	copy = kmalloc(sizeof(info->shadow), GFP_KERNEL | __GFP_NOFAIL);
	memcpy(copy, info->shadow, sizeof(info->shadow));

	/* Stage 2: Set up free list. */
	memset(&info->shadow, 0, sizeof(info->shadow));
	for (i = 0; i < BLK_RING_SIZE; i++)
		info->shadow[i].req.id = i+1;
	info->shadow_free = info->ring.req_prod_pvt;
	info->shadow[BLK_RING_SIZE-1].req.id = 0x0fffffff;

	/* Stage 3: Find pending requests and requeue them. */
	for (i = 0; i < BLK_RING_SIZE; i++) {
		/* Not in use? */
		if (copy[i].request == 0)
			continue;

		/* Grab a request slot and copy shadow state into it. */
		req = RING_GET_REQUEST(
			&info->ring, info->ring.req_prod_pvt);
		*req = copy[i].req;

		/* We get a new request id, and must reset the shadow state. */
		req->id = GET_ID_FROM_FREELIST(info);
		memcpy(&info->shadow[req->id], &copy[i], sizeof(copy[i]));

		/* Rewrite any grant references invalidated by susp/resume. */
		for (j = 0; j < req->nr_segments; j++)
			gnttab_grant_foreign_access_ref(
				req->seg[j].gref,
				info->xbdev->otherend_id,
				pfn_to_mfn(info->shadow[req->id].frame[j]),
				rq_data_dir(
					(struct request *)
					info->shadow[req->id].request));
		info->shadow[req->id].req = *req;

		info->ring.req_prod_pvt++;
	}

	kfree(copy);

	(void)xenbus_switch_state(info->xbdev, XenbusStateConnected);

	spin_lock_irq(&blkif_io_lock);

	/* Now safe for us to use the shared ring */
	info->connected = BLKIF_STATE_CONNECTED;

	/* Send off requeued requests */
	flush_requests(info);

	/* Kick any other new requests queued since we resumed */
	kick_pending_request_queues(info);

	spin_unlock_irq(&blkif_io_lock);
}


/* ** Driver Registration ** */


static struct xenbus_device_id blkfront_ids[] = {
	{ "vbd" },
	{ "" }
};


static struct xenbus_driver blkfront = {
	.name = "vbd",
	.owner = THIS_MODULE,
	.ids = blkfront_ids,
	.probe = blkfront_probe,
	.remove = blkfront_remove,
	.resume = blkfront_resume,
	.otherend_changed = backend_changed,
};


static int __init xlblk_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	return xenbus_register_frontend(&blkfront);
}
module_init(xlblk_init);


static void xlblk_exit(void)
{
	return xenbus_unregister_driver(&blkfront);
}
module_exit(xlblk_exit);

MODULE_LICENSE("Dual BSD/GPL");
