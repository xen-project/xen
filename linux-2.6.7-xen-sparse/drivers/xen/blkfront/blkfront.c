/******************************************************************************
 * block.c
 * 
 * XenLinux virtual block-device driver.
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004, Christian Limpach
 */

#include "block.h"
#include <linux/cdrom.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <scsi/scsi.h>
#include <asm-xen/ctrl_if.h>

typedef unsigned char byte; /* from linux/ide.h */

#define BLKIF_STATE_CLOSED       0
#define BLKIF_STATE_DISCONNECTED 1
#define BLKIF_STATE_CONNECTED    2
static unsigned int blkif_state = BLKIF_STATE_CLOSED;
static unsigned int blkif_evtchn, blkif_irq;

static int blkif_control_rsp_valid;
static blkif_response_t blkif_control_rsp;

static blkif_ring_t *blk_ring;
static BLKIF_RING_IDX resp_cons; /* Response consumer for comms ring. */
static BLKIF_RING_IDX req_prod;  /* Private request producer.         */

static blkif_ring_t *blk_ring_rec; /* Private copy of requests, used for
                                    * recovery.  Responses not stored here. */
static BLKIF_RING_IDX resp_cons_rec; /* Copy of response consumer, used for
                                      * recovery */
static int recovery = 0;           /* "Recovery in progress" flag.  Protected
                                    * by the blkif_io_lock */

/* We plug the I/O ring if the driver is suspended or if the ring is full. */
#define	BLKIF_RING_FULL	(((req_prod - resp_cons) == BLKIF_RING_SIZE) || \
			 (blkif_state != BLKIF_STATE_CONNECTED))

/*
 * Request queues with outstanding work, but ring is currently full.
 * We need no special lock here, as we always access this with the
 * blkif_io_lock held. We only need a small maximum list.
 */
#define MAX_PENDING 8
static request_queue_t *pending_queues[MAX_PENDING];
static int nr_pending;

static inline void flush_requests(void)
{

        blk_ring->req_prod = req_prod;

        notify_via_evtchn(blkif_evtchn);
}


#if 0
/*
 * blkif_update_int/update-vbds_task - handle VBD update events.
 *  Schedule a task for keventd to run, which will update the VBDs and perform 
 *  the corresponding updates to our view of VBD state.
 */
static struct tq_struct update_tq;
static void update_vbds_task(void *unused)
{ 
    xlvbd_update_vbds();
}
#endif


int blkif_open(struct inode *inode, struct file *filep)
{
	struct gendisk *gd = inode->i_bdev->bd_disk;
	struct xlbd_disk_info *di = (struct xlbd_disk_info *)gd->private_data;

	/* Update of usage count is protected by per-device semaphore. */
	di->mi->usage++;

	return 0;
}


int blkif_release(struct inode *inode, struct file *filep)
{
	struct gendisk *gd = inode->i_bdev->bd_disk;
	struct xlbd_disk_info *di = (struct xlbd_disk_info *)gd->private_data;

	/*
	 * When usage drops to zero it may allow more VBD updates to occur.
	 * Update of usage count is protected by a per-device semaphore.
	 */
	if (--di->mi->usage == 0) {
#if 0
		update_tq.routine = update_vbds_task;
		schedule_task(&update_tq);
#endif
	}

	return 0;
}


int blkif_ioctl(struct inode *inode, struct file *filep,
                          unsigned command, unsigned long argument)
{
	/*  struct gendisk *gd = inode->i_bdev->bd_disk; */

	DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
	    command, (long)argument, inode->i_rdev); 
  
	switch (command) {

	case HDIO_GETGEO:
		/* return ENOSYS to use defaults */
		return -ENOSYS;

	default:
		printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		       command);
		return -ENOSYS;
	}

	return 0;
}

#if 0
/* check media change: should probably do something here in some cases :-) */
int blkif_check(kdev_t dev)
{
    DPRINTK("blkif_check\n");
    return 0;
}

int blkif_revalidate(kdev_t dev)
{
    struct block_device *bd;
    struct gendisk *gd;
    xen_block_t *disk;
    unsigned long capacity;
    int i, rc = 0;
    
    if ( (bd = bdget(dev)) == NULL )
        return -EINVAL;

    /*
     * Update of partition info, and check of usage count, is protected
     * by the per-block-device semaphore.
     */
    down(&bd->bd_sem);

    if ( ((gd = get_gendisk(dev)) == NULL) ||
         ((disk = xldev_to_xldisk(dev)) == NULL) ||
         ((capacity = gd->part[MINOR(dev)].nr_sects) == 0) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( disk->usage > 1 )
    {
        rc = -EBUSY;
        goto out;
    }

    /* Only reread partition table if VBDs aren't mapped to partitions. */
    if ( !(gd->flags[MINOR(dev) >> gd->minor_shift] & GENHD_FL_VIRT_PARTNS) )
    {
        for ( i = gd->max_p - 1; i >= 0; i-- )
        {
            invalidate_device(dev+i, 1);
            gd->part[MINOR(dev+i)].start_sect = 0;
            gd->part[MINOR(dev+i)].nr_sects   = 0;
            gd->sizes[MINOR(dev+i)]           = 0;
        }

        grok_partitions(gd, MINOR(dev)>>gd->minor_shift, gd->max_p, capacity);
    }

 out:
    up(&bd->bd_sem);
    bdput(bd);
    return rc;
}
#endif


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
	struct xlbd_disk_info *di =
		(struct xlbd_disk_info *)req->rq_disk->private_data;
	unsigned long buffer_ma;
	blkif_request_t *ring_req;
	struct bio *bio;
	struct bio_vec *bvec;
	int idx, s;
        unsigned int fsect, lsect;

        if (unlikely(blkif_state != BLKIF_STATE_CONNECTED))
                return 1;

	/* Fill out a communications ring structure. */
	ring_req = &blk_ring->ring[MASK_BLKIF_IDX(req_prod)].req;
	ring_req->id = (unsigned long)req;
	ring_req->operation = rq_data_dir(req) ? BLKIF_OP_WRITE :
		BLKIF_OP_READ;
	ring_req->sector_number = (blkif_sector_t)req->sector;
	ring_req->device = di->xd_device;

	s = 0;
	ring_req->nr_segments = 0;
	rq_for_each_bio(bio, req) {
		bio_for_each_segment(bvec, bio, idx) {
			buffer_ma = page_to_phys(bvec->bv_page);
			if (unlikely((buffer_ma & ((1<<9)-1)) != 0))
				BUG();

                        fsect = bvec->bv_offset >> 9;
                        lsect = fsect + (bvec->bv_len >> 9) - 1;
                        if (unlikely(lsect > 7))
                                BUG();

			ring_req->frame_and_sects[ring_req->nr_segments++] =
				buffer_ma | (fsect << 3) | lsect;
			s += bvec->bv_len >> 9;
		}
	}

	req_prod++;

        /* Keep a private copy so we can reissue requests when recovering. */
        blk_ring_rec->ring[MASK_BLKIF_IDX(blk_ring_rec->req_prod)].req =
                *ring_req;
        blk_ring_rec->req_prod++;

        return 0;
}

/*
 * do_blkif_request
 *  read a block; request is in a request queue
 */
void do_blkif_request(request_queue_t *rq)
{
	struct request *req;
	int queued;

	DPRINTK("Entered do_blkif_request\n"); 

	queued = 0;

	while ((req = elv_next_request(rq)) != NULL) {
		if (!blk_fs_request(req)) {
			end_request(req, 0);
			continue;
		}

		if (BLKIF_RING_FULL) {
			blk_stop_queue(rq);
			break;
		}
		DPRINTK("do_blkif_request %p: cmd %p, sec %lx, (%u/%li) buffer:%p [%s]\n",
		    req, req->cmd, req->sector, req->current_nr_sectors,
		    req->nr_sectors, req->buffer,
		    rq_data_dir(req) ? "write" : "read");
                blkdev_dequeue_request(req);
		if (blkif_queue_request(req)) {
                        blk_stop_queue(rq);
                        break;
                }
		queued++;
	}

	if (queued != 0)
		flush_requests();
}


static void kick_pending_request_queues(void)
{
    /* We kick pending request queues if the ring is reasonably empty. */
    if ( (nr_pending != 0) && 
         ((req_prod - resp_cons) < (BLKIF_RING_SIZE >> 1)) )
    {
        /* Attempt to drain the queue, but bail if the ring becomes full. */
        while ( (nr_pending != 0) && !BLKIF_RING_FULL )
            do_blkif_request(pending_queues[--nr_pending]);
    }
}


static irqreturn_t blkif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
	struct request *req;
	blkif_response_t *bret;
	BLKIF_RING_IDX i; 
	unsigned long flags; 

	spin_lock_irqsave(&blkif_io_lock, flags);     

        if (unlikely(blkif_state == BLKIF_STATE_CLOSED || recovery)) {
                printk("Bailed out\n");
        
                spin_unlock_irqrestore(&blkif_io_lock, flags);
                return IRQ_HANDLED;
        }

	for (i = resp_cons; i != blk_ring->resp_prod; i++) {
		bret = &blk_ring->ring[MASK_BLKIF_IDX(i)].resp;
		switch (bret->operation) {
		case BLKIF_OP_READ:
		case BLKIF_OP_WRITE:
			if (unlikely(bret->status != BLKIF_RSP_OKAY))
				DPRINTK("Bad return from blkdev data request: %lx\n",
				    bret->status);
			req = (struct request *)bret->id;
                        /* XXXcl pass up status */
			if (unlikely(end_that_request_first(req, 1,
			    req->hard_nr_sectors)))
				BUG();

			end_that_request_last(req);
			break;
                case BLKIF_OP_PROBE:
                        memcpy(&blkif_control_rsp, bret, sizeof(*bret));
                        blkif_control_rsp_valid = 1;
                        break;
     		default:
			BUG();
		}
	}
    
	resp_cons = i;
        resp_cons_rec = i;

	if (xlbd_blk_queue &&
            test_bit(QUEUE_FLAG_STOPPED, &xlbd_blk_queue->queue_flags)) {
		blk_start_queue(xlbd_blk_queue);
		/* XXXcl call to request_fn should not be needed but
                 * we get stuck without...  needs investigating
		 */
		xlbd_blk_queue->request_fn(xlbd_blk_queue);
	}

	spin_unlock_irqrestore(&blkif_io_lock, flags);

	return IRQ_HANDLED;
}


void blkif_control_send(blkif_request_t *req, blkif_response_t *rsp)
{
    unsigned long flags;

 retry:
    while ( (req_prod - resp_cons) == BLKIF_RING_SIZE )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    spin_lock_irqsave(&blkif_io_lock, flags);
    if ( (req_prod - resp_cons) == BLKIF_RING_SIZE )
    {
        spin_unlock_irqrestore(&blkif_io_lock, flags);
        goto retry;
    }

    memcpy(&blk_ring->ring[MASK_BLKIF_IDX(req_prod)].req, req, sizeof(*req));
    memcpy(&blk_ring_rec->ring[MASK_BLKIF_IDX(blk_ring_rec->req_prod++)].req,
           req, sizeof(*req));
    req_prod++;
    flush_requests();

    spin_unlock_irqrestore(&blkif_io_lock, flags);

    while ( !blkif_control_rsp_valid )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    memcpy(rsp, &blkif_control_rsp, sizeof(*rsp));
    blkif_control_rsp_valid = 0;
}


static void blkif_status_change(blkif_fe_interface_status_changed_t *status)
{
    ctrl_msg_t                   cmsg;
    blkif_fe_interface_connect_t up;

    if ( status->handle != 0 )
    {
        printk(KERN_WARNING "Status change on unsupported blkif %d\n",
               status->handle);
        return;
    }

    switch ( status->status )
    {
    case BLKIF_INTERFACE_STATUS_DESTROYED:
        printk(KERN_WARNING "Unexpected blkif-DESTROYED message in state %d\n",
               blkif_state);
        break;

    case BLKIF_INTERFACE_STATUS_DISCONNECTED:
        if ( blkif_state != BLKIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected blkif-DISCONNECTED message"
                   " in state %d\n", blkif_state);

            printk(KERN_INFO "VBD driver recovery in progress\n");
            
            /* Prevent new requests being issued until we fix things up. */
            spin_lock_irq(&blkif_io_lock);
            recovery = 1;
            blkif_state = BLKIF_STATE_DISCONNECTED;
            spin_unlock_irq(&blkif_io_lock);

            /* Free resources associated with old device channel. */
            free_page((unsigned long)blk_ring);
            free_irq(blkif_irq, NULL);
            unbind_evtchn_from_irq(blkif_evtchn);
        }

        /* Move from CLOSED to DISCONNECTED state. */
        blk_ring = (blkif_ring_t *)__get_free_page(GFP_KERNEL);
        blk_ring->req_prod = blk_ring->resp_prod = resp_cons = req_prod = 0;
        blkif_state  = BLKIF_STATE_DISCONNECTED;

        /* Construct an interface-CONNECT message for the domain controller. */
        cmsg.type      = CMSG_BLKIF_FE;
        cmsg.subtype   = CMSG_BLKIF_FE_INTERFACE_CONNECT;
        cmsg.length    = sizeof(blkif_fe_interface_connect_t);
        up.handle      = 0;
        up.shmem_frame = virt_to_machine(blk_ring) >> PAGE_SHIFT;
        memcpy(cmsg.msg, &up, sizeof(up));
        
        /* Tell the controller to bring up the interface. */
        ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
        break;

    case BLKIF_INTERFACE_STATUS_CONNECTED:
        if ( blkif_state == BLKIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected blkif-CONNECTED message"
                   " in state %d\n", blkif_state);
            break;
        }

        blkif_evtchn = status->evtchn;
        blkif_irq = bind_evtchn_to_irq(blkif_evtchn);
        (void)request_irq(blkif_irq, blkif_int, 0, "blkif", NULL);

        if ( recovery )
        {
            int i;

	    /* Shouldn't need the blkif_io_lock here - the device is
	     * plugged and the recovery flag prevents the interrupt handler
	     * changing anything. */

            /* Reissue requests from the private block ring. */
            for ( i = 0;
		  resp_cons_rec < blk_ring_rec->req_prod;
                  resp_cons_rec++, i++ )
            {
                blk_ring->ring[i].req
                    = blk_ring_rec->ring[MASK_BLKIF_IDX(resp_cons_rec)].req;
            }

            /* Reset the private block ring to match the new ring. */
            memcpy(blk_ring_rec, blk_ring, sizeof(*blk_ring));
            resp_cons_rec = 0;

            /* blk_ring->req_prod will be set when we flush_requests().*/
            blk_ring_rec->req_prod = req_prod = i;

            wmb();

            /* Switch off recovery mode, using a memory barrier to ensure that
             * it's seen before we flush requests - we don't want to miss any
             * interrupts. */
            recovery = 0;
            wmb();

            /* Kicks things back into life. */
            flush_requests();
        }
        else
        {
            /* Probe for discs that are attached to the interface. */
            xlvbd_init();
        }

        blkif_state = BLKIF_STATE_CONNECTED;
        
        /* Kick pending requests. */
        spin_lock_irq(&blkif_io_lock);
        kick_pending_request_queues();
        spin_unlock_irq(&blkif_io_lock);

        break;

    default:
        printk(KERN_WARNING "Status change to unknown value %d\n", 
               status->status);
        break;
    }
}


static void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED:
        if ( msg->length != sizeof(blkif_fe_interface_status_changed_t) )
            goto parse_error;
        blkif_status_change((blkif_fe_interface_status_changed_t *)
                            &msg->msg[0]);
        break;        
#if 0
    case CMSG_BLKIF_FE_VBD_STATUS_CHANGED:
        update_tq.routine = update_vbds_task;
        schedule_task(&update_tq);
        break;
#endif
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}


int __init xlblk_init(void)
{
    ctrl_msg_t                       cmsg;
    blkif_fe_driver_status_changed_t st;

    if ( (start_info.flags & SIF_INITDOMAIN) 
        || (start_info.flags & SIF_BLK_BE_DOMAIN) )
        return 0;

    printk(KERN_INFO "Initialising Xen virtual block device\n");

    blk_ring_rec = (blkif_ring_t *)__get_free_page(GFP_KERNEL);
    memset(blk_ring_rec, 0, sizeof(*blk_ring_rec));

    (void)ctrl_if_register_receiver(CMSG_BLKIF_FE, blkif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_BLKIF_FE;
    cmsg.subtype   = CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED;
    cmsg.length    = sizeof(blkif_fe_driver_status_changed_t);
    st.status      = BLKIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);

    /*
     * We should read 'nr_interfaces' from response message and wait
     * for notifications before proceeding. For now we assume that we
     * will be notified of exactly one interface.
     */
    while ( blkif_state != BLKIF_STATE_CONNECTED )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    return 0;
#if 0
	int error; 

	reset_xlblk_interface();

	xlblk_response_irq = bind_virq_to_irq(VIRQ_BLKDEV);
	xlblk_update_irq   = bind_virq_to_irq(VIRQ_VBD_UPD);

	error = request_irq(xlblk_response_irq, xlblk_response_int, 
			    SA_SAMPLE_RANDOM, "blkdev", NULL);
	if (error) {
		printk(KERN_ALERT "Could not allocate receive interrupt\n");
		goto fail;
	}

	error = request_irq(xlblk_update_irq, xlblk_update_int,
			    0, "blkdev", NULL);
	if (error) {
		printk(KERN_ALERT
		       "Could not allocate block update interrupt\n");
		goto fail;
	}

	(void)xlvbd_init();

	return 0;

 fail:
	return error;
#endif
}


static void __exit xlblk_cleanup(void)
{
    /* XXX FIXME */
    BUG();
#if 0
	/*  xlvbd_cleanup(); */
	free_irq(xlblk_response_irq, NULL);
	free_irq(xlblk_update_irq, NULL);
	unbind_virq_from_irq(VIRQ_BLKDEV);
	unbind_virq_from_irq(VIRQ_VBD_UPD);
#endif
}


module_init(xlblk_init);
module_exit(xlblk_cleanup);


void blkdev_suspend(void)
{
}


void blkdev_resume(void)
{
}
