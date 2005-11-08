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

#if 1
#define ASSERT(p)							   \
	if (!(p)) { printk("Assertion '%s' failed, line %d, file %s", #p , \
	__LINE__, __FILE__); *(int*)0=0; }
#else
#define ASSERT(_p)
#endif

#include <linux/version.h>
#include "block.h"
#include <linux/cdrom.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/xen-public/grant_table.h>
#include <asm-xen/gnttab.h>
#include <asm/hypervisor.h>

#define BLKIF_STATE_DISCONNECTED 0
#define BLKIF_STATE_CONNECTED    1

#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST * BLKIF_RING_SIZE)
#define GRANT_INVALID_REF	0

static void kick_pending_request_queues(struct blkfront_info *info);

static void blkif_completion(struct blk_shadow *s);

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
	RING_PUSH_REQUESTS(&info->ring);
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
	return 0;
}


int blkif_release(struct inode *inode, struct file *filep)
{
	return 0;
}


int blkif_ioctl(struct inode *inode, struct file *filep,
                unsigned command, unsigned long argument)
{
	int i;

	DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
		      command, (long)argument, inode->i_rdev);

	switch ( command )
	{
	case HDIO_GETGEO:
		/* return ENOSYS to use defaults */
		return -ENOSYS;

	case CDROMMULTISESSION:
		DPRINTK("FIXME: support multisession CDs later\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char *)(argument + i)))
				return -EFAULT;
		return 0;

	default:
		/*printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		  command);*/
		return -EINVAL; /* same return as native Linux */
	}

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
	ring_req->operation = rq_data_dir(req) ?
		BLKIF_OP_WRITE : BLKIF_OP_READ;
	ring_req->sector_number = (blkif_sector_t)req->sector;
	ring_req->handle = info->handle;

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
			ASSERT(ref != -ENOSPC);

			gnttab_grant_foreign_access_ref(
				ref,
				info->backend_id,
				buffer_mfn,
				rq_data_dir(req) );

			info->shadow[id].frame[ring_req->nr_segments] =
				mfn_to_pfn(buffer_mfn);

			ring_req->frame_and_sects[ring_req->nr_segments] =
				blkif_fas_from_gref(ref, fsect, lsect);

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

		DPRINTK("do_blk_req %p: cmd %p, sec %lx, "
			"(%u/%li) buffer:%p [%s]\n",
			req, req->cmd, req->sector, req->current_nr_sectors,
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

	spin_lock_irqsave(&blkif_io_lock, flags);

	if (unlikely(info->connected != BLKIF_STATE_CONNECTED)) {
		spin_unlock_irqrestore(&blkif_io_lock, flags);
		return IRQ_HANDLED;
	}

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

		switch (bret->operation) {
		case BLKIF_OP_READ:
		case BLKIF_OP_WRITE:
			if (unlikely(bret->status != BLKIF_RSP_OKAY))
				DPRINTK("Bad return from blkdev data "
					"request: %x\n", bret->status);

			ret = end_that_request_first(
				req, (bret->status == BLKIF_RSP_OKAY),
				req->hard_nr_sectors);
			BUG_ON(ret);
			end_that_request_last(req);
			break;
		default:
			BUG();
		}
	}

	info->ring.rsp_cons = i;

	kick_pending_request_queues(info);

	spin_unlock_irqrestore(&blkif_io_lock, flags);

	return IRQ_HANDLED;
}

static void blkif_free(struct blkfront_info *info)
{
	/* Prevent new requests being issued until we fix things up. */
	spin_lock_irq(&blkif_io_lock);
	info->connected = BLKIF_STATE_DISCONNECTED;
	spin_unlock_irq(&blkif_io_lock);

	/* Free resources associated with old device channel. */
	if (info->ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)info->ring.sring);
		info->ring_ref = GRANT_INVALID_REF;
		info->ring.sring = NULL;
	}
	if (info->irq)
		unbind_from_irqhandler(info->irq, info); 
	info->evtchn = info->irq = 0;
}

static void blkif_recover(struct blkfront_info *info)
{
	int i;
	blkif_request_t *req;
	struct blk_shadow *copy;
	int j;

	/* Stage 1: Make a safe copy of the shadow state. */
	copy = (struct blk_shadow *)kmalloc(sizeof(info->shadow), GFP_KERNEL);
	BUG_ON(copy == NULL);
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
				blkif_gref_from_fas(req->frame_and_sects[j]),
				info->backend_id,
				pfn_to_mfn(info->shadow[req->id].frame[j]),
				rq_data_dir(
					(struct request *)
					info->shadow[req->id].request));
		info->shadow[req->id].req = *req;

		info->ring.req_prod_pvt++;
	}

	kfree(copy);

	/* info->ring->req_prod will be set when we flush_requests().*/
	wmb();

	/* Kicks things back into life. */
	flush_requests(info);

	/* Now safe to let other people use the interface. */
	info->connected = BLKIF_STATE_CONNECTED;
}

static void blkif_connect(struct blkfront_info *info, u16 evtchn)
{
	int err = 0;

	info->evtchn = evtchn;

	err = bind_evtchn_to_irqhandler(
		info->evtchn, blkif_int, SA_SAMPLE_RANDOM, "blkif", info);
	if (err <= 0) {
		WPRINTK("bind_evtchn_to_irqhandler failed (err=%d)\n", err);
		return;
	}

	info->irq = err;
}


static struct xenbus_device_id blkfront_ids[] = {
	{ "vbd" },
	{ "" }
};

static void watch_for_status(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	struct blkfront_info *info;
	unsigned int binfo;
	unsigned long sectors, sector_size;
	int err;
	const char *node;

	node = vec[XS_WATCH_PATH];

	info = container_of(watch, struct blkfront_info, watch);
	node += strlen(watch->node);

	/* FIXME: clean up when error on the other end. */
	if ((info->connected == BLKIF_STATE_CONNECTED) || info->mi)
		return;

	err = xenbus_gather(NULL, watch->node,
			    "sectors", "%lu", &sectors,
			    "info", "%u", &binfo,
			    "sector-size", "%lu", &sector_size,
			    NULL);
	if (err) {
		xenbus_dev_error(info->xbdev, err,
				 "reading backend fields at %s", watch->node);
		return;
	}

	info->connected = BLKIF_STATE_CONNECTED;
	xlvbd_add(sectors, info->vdevice, binfo, sector_size, info);

	xenbus_dev_ok(info->xbdev);

	/* Kick pending requests. */
	spin_lock_irq(&blkif_io_lock);
	kick_pending_request_queues(info);
	spin_unlock_irq(&blkif_io_lock);
}

static int setup_blkring(struct xenbus_device *dev, struct blkfront_info *info)
{
	blkif_sring_t *sring;
	int err;
	evtchn_op_t op = {
		.cmd = EVTCHNOP_alloc_unbound,
		.u.alloc_unbound.dom = DOMID_SELF,
		.u.alloc_unbound.remote_dom = info->backend_id };

	info->ring_ref = GRANT_INVALID_REF;

	sring = (void *)__get_free_page(GFP_KERNEL);
	if (!sring) {
		xenbus_dev_error(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&info->ring, sring, PAGE_SIZE);

	err = gnttab_grant_foreign_access(info->backend_id,
					  virt_to_mfn(info->ring.sring), 0);
	if (err == -ENOSPC) {
		free_page((unsigned long)info->ring.sring);
		info->ring.sring = 0;
		xenbus_dev_error(dev, err, "granting access to ring page");
		return err;
	}
	info->ring_ref = err;

	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)info->ring.sring);
		info->ring_ref = GRANT_INVALID_REF;
		info->ring.sring = NULL;
		xenbus_dev_error(dev, err, "allocating event channel");
		return err;
	}

	blkif_connect(info, op.u.alloc_unbound.port);

	return 0;
}

/* Common code used when first setting up, and when resuming. */
static int talk_to_backend(struct xenbus_device *dev,
			   struct blkfront_info *info)
{
	char *backend;
	const char *message;
	struct xenbus_transaction *xbt;
	int err;

	backend = NULL;
	err = xenbus_gather(NULL, dev->nodename,
			    "backend-id", "%i", &info->backend_id,
			    "backend", NULL, &backend,
			    NULL);
	if (XENBUS_EXIST_ERR(err))
		goto out;
	if (backend && strlen(backend) == 0) {
		err = -ENOENT;
		goto out;
	}
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading %s/backend or backend-id",
				 dev->nodename);
		goto out;
	}

	/* Create shared ring, alloc event channel. */
	err = setup_blkring(dev, info);
	if (err) {
		xenbus_dev_error(dev, err, "setting up block ring");
		goto out;
	}

again:
	xbt = xenbus_transaction_start();
	if (IS_ERR(xbt)) {
		xenbus_dev_error(dev, err, "starting transaction");
		goto destroy_blkring;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "ring-ref","%u", info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_error(dev, err, "completing transaction");
		goto destroy_blkring;
	}

	info->watch.node = backend;
	info->watch.callback = watch_for_status;
	err = register_xenbus_watch(&info->watch);
	if (err) {
		message = "registering watch on backend";
		goto destroy_blkring;
	}

	info->backend = backend;

	return 0;

 abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_error(dev, err, "%s", message);
 destroy_blkring:
	blkif_free(info);
 out:
	if (backend)
		kfree(backend);
	return err;
}

/* Setup supplies the backend dir, virtual device.

   We place an event channel and shared frame entries.
   We watch backend to wait if it's ok. */
static int blkfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err, vdevice, i;
	struct blkfront_info *info;

	/* FIXME: Use dynamic device id if this is not set. */
	err = xenbus_scanf(NULL, dev->nodename,
			   "virtual-device", "%i", &vdevice);
	if (XENBUS_EXIST_ERR(err))
		return err;
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading virtual-device");
		return err;
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_error(dev, err, "allocating info structure");
		return err;
	}
	info->xbdev = dev;
	info->vdevice = vdevice;
	info->connected = BLKIF_STATE_DISCONNECTED;
	info->mi = NULL;
	INIT_WORK(&info->work, blkif_restart_queue, (void *)info);

	info->shadow_free = 0;
	memset(info->shadow, 0, sizeof(info->shadow));
	for (i = 0; i < BLK_RING_SIZE; i++)
		info->shadow[i].req.id = i+1;
	info->shadow[BLK_RING_SIZE-1].req.id = 0x0fffffff;

	/* Front end dir is a number, which is used as the id. */
	info->handle = simple_strtoul(strrchr(dev->nodename,'/')+1, NULL, 0);
	dev->data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		kfree(info);
		dev->data = NULL;
		return err;
	}

	{
		unsigned int len = max(XS_WATCH_PATH, XS_WATCH_TOKEN) + 1;
		const char *vec[len];

		vec[XS_WATCH_PATH] = info->watch.node;
		vec[XS_WATCH_TOKEN] = NULL;

		/* Call once in case entries already there. */
		watch_for_status(&info->watch, vec, len);
	}

	return 0;
}

static int blkfront_remove(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->data;

	if (info->backend)
		unregister_xenbus_watch(&info->watch);

	if (info->mi)
		xlvbd_del(info);

	blkif_free(info);

	kfree(info->backend);
	kfree(info);

	return 0;
}

static int blkfront_suspend(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->data;

	unregister_xenbus_watch(&info->watch);
	kfree(info->backend);
	info->backend = NULL;

	return 0;
}

static int blkfront_resume(struct xenbus_device *dev)
{
	struct blkfront_info *info = dev->data;
	int err;

	blkif_free(info);

	err = talk_to_backend(dev, info);
	if (!err)
		blkif_recover(info);

	return err;
}

static struct xenbus_driver blkfront = {
	.name = "vbd",
	.owner = THIS_MODULE,
	.ids = blkfront_ids,
	.probe = blkfront_probe,
	.remove = blkfront_remove,
	.resume = blkfront_resume,
	.suspend = blkfront_suspend,
};

static int __init xlblk_init(void)
{
	if (xen_init() < 0)
		return -ENODEV;

	xenbus_register_driver(&blkfront);
	return 0;
}

module_init(xlblk_init);

static void blkif_completion(struct blk_shadow *s)
{
	int i;
	for (i = 0; i < s->req.nr_segments; i++)
		gnttab_end_foreign_access(
			blkif_gref_from_fas(s->req.frame_and_sects[i]), 0, 0UL);
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
