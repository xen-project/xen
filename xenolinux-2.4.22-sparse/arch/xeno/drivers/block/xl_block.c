/******************************************************************************
 * xl_block.c
 * 
 * Xenolinux virtual block-device driver.
 * 
 */

#include "xl_block.h"
#include <linux/blk.h>
#include <linux/cdrom.h>

typedef unsigned char byte; /* from linux/ide.h */

#define XLBLK_RESPONSE_IRQ _EVENT_BLKDEV
#define DEBUG_IRQ          _EVENT_DEBUG 

#define STATE_ACTIVE    0
#define STATE_SUSPENDED 1
#define STATE_CLOSED    2
static unsigned int state = STATE_SUSPENDED;

static blk_ring_t *blk_ring;
static unsigned int resp_cons; /* Response consumer for comms ring. */
static unsigned int req_prod;  /* Private request producer.         */

#define XDI_MAX 64 
static xen_disk_info_t xlblk_disk_info; /* information about our disks/VBDs */

/* We plug the I/O ring if the driver is suspended or if the ring is full. */
#define RING_PLUGGED ((BLK_RING_INC(req_prod) == resp_cons) || \
                      (state != STATE_ACTIVE))

/*
 * Request queues with outstanding work, but ring is currently full.
 * We need no special lock here, as we always access this with the
 * io_request_lock held. We only need a small maximum list.
 */
#define MAX_PENDING 8
static request_queue_t *pending_queues[MAX_PENDING];
static int nr_pending;

static kdev_t        sg_dev;
static int           sg_operation = -1;
static unsigned long sg_next_sect;
#define DISABLE_SCATTERGATHER() (sg_operation = -1)

static inline void signal_requests_to_xen(void)
{
    block_io_op_t op; 

    DISABLE_SCATTERGATHER();
    blk_ring->req_prod = req_prod;

    op.cmd = BLOCK_IO_OP_SIGNAL; 
    HYPERVISOR_block_io_op(&op);
    return;
}

static inline xl_disk_t *xldev_to_xldisk(kdev_t xldev)
{
    struct gendisk *gd = xldev_to_gendisk(xldev);
    return (xl_disk_t *)gd->real_devices + 
        (MINOR(xldev) >> gd->minor_shift);
}


int xenolinux_block_open(struct inode *inode, struct file *filep)
{
    short xldev = inode->i_rdev; 
    struct gendisk *gd = xldev_to_gendisk(xldev);
    xl_disk_t *disk = xldev_to_xldisk(inode->i_rdev);
    short minor = MINOR(xldev); 

    if(!gd->part[minor].nr_sects) { 
	/* Device either doesn't exist, or has zero capacity; we use 
	   a few cheesy heuristics to return the relevant error code */
	if(disk->capacity || (minor & (gd->max_p - 1))) { 
	    // we have a real device, but no such partition, or we just 
	    // have a partition number so guess this is the problem 
	    return -ENXIO;     // no such device or address 
	} else if (gd->flags[minor >> gd->minor_shift] & GENHD_FL_REMOVABLE) {
	    // this is a removable device => assume that media is missing 
	    return -ENOMEDIUM; // media not present (this is a guess) 
	} else 
	    // just go for the general 'no such device' error
	    return -ENODEV;    // no such device
    }


    disk->usage++;
    DPRINTK("xenolinux_block_open\n");
    return 0;
}


int xenolinux_block_release(struct inode *inode, struct file *filep)
{
    xl_disk_t *disk = xldev_to_xldisk(inode->i_rdev);
    disk->usage--;
    DPRINTK("xenolinux_block_release\n");
    return 0;
}


int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
			  unsigned command, unsigned long argument)
{
    kdev_t dev = inode->i_rdev;
    struct hd_geometry *geo = (struct hd_geometry *)argument;
    struct gendisk *gd;     
    struct hd_struct *part; 

    /* NB. No need to check permissions. That is done for us. */
    
    DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, dev: 0x%04x\n",
                  command, (long) argument, dev); 
  
    gd = xldev_to_gendisk(dev);
    part = &gd->part[MINOR(dev)]; 

    switch ( command )
    {
    case BLKGETSIZE:
        DPRINTK_IOCTL("   BLKGETSIZE: %x %lx\n", BLKGETSIZE, part->nr_sects); 
	return put_user(part->nr_sects, (unsigned long *) argument);

    case BLKRRPART:                               /* re-read partition table */
        DPRINTK_IOCTL("   BLKRRPART: %x\n", BLKRRPART); 
        return xenolinux_block_revalidate(dev);

    case BLKSSZGET:
	return hardsect_size[MAJOR(dev)][MINOR(dev)]; 

    case BLKBSZGET:                                        /* get block size */
        DPRINTK_IOCTL("   BLKBSZGET: %x\n", BLKBSZGET);
        break;

    case BLKBSZSET:                                        /* set block size */
        DPRINTK_IOCTL("   BLKBSZSET: %x\n", BLKBSZSET);
	break;

    case BLKRASET:                                         /* set read-ahead */
        DPRINTK_IOCTL("   BLKRASET: %x\n", BLKRASET);
	break;

    case BLKRAGET:                                         /* get read-ahead */
        DPRINTK_IOCTL("   BLKRAFET: %x\n", BLKRAGET);
	break;

    case HDIO_GETGEO:
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO: %x\n", HDIO_GETGEO);
	if (!argument) return -EINVAL;
	if (put_user(0x00,  (unsigned long *) &geo->start)) return -EFAULT;
	if (put_user(0xff,  (byte *)&geo->heads)) return -EFAULT;
	if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
	if (put_user(0x106, (unsigned short *)&geo->cylinders)) return -EFAULT;
	return 0;

    case HDIO_GETGEO_BIG: 
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO_BIG: %x\n", HDIO_GETGEO_BIG);
	if (!argument) return -EINVAL;
	if (put_user(0x00,  (unsigned long *) &geo->start))  return -EFAULT;
	if (put_user(0xff,  (byte *)&geo->heads))   return -EFAULT;
	if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
	if (put_user(0x106, (unsigned int *) &geo->cylinders)) return -EFAULT;
	return 0;

    case CDROMMULTISESSION:
        DPRINTK("FIXME: support multisession CDs later\n");
        memset((struct cdrom_multisession *)argument, 0, 
               sizeof(struct cdrom_multisession));
        return 0;

    default:
        printk("ioctl %08x not supported by xl_block\n", command);
	return -ENOSYS;
    }
    
    return 0;
}

/* check media change: should probably do something here in some cases :-) */
int xenolinux_block_check(kdev_t dev)
{
    DPRINTK("xenolinux_block_check\n");
    return 0;
}

int xenolinux_block_revalidate(kdev_t dev)
{
    struct gendisk *gd = xldev_to_gendisk(dev);
    xl_disk_t *disk = xldev_to_xldisk(dev);
    unsigned long flags;
    int i, disk_nr = MINOR(dev) >> gd->minor_shift; 
    
    DPRINTK("xenolinux_block_revalidate: %d\n", dev);

    spin_lock_irqsave(&io_request_lock, flags);
    if ( disk->usage > 1 )
    {
        spin_unlock_irqrestore(&io_request_lock, flags);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&io_request_lock, flags);

    for ( i = gd->nr_real - 1; i >= 0; i-- )
    {
        invalidate_device(dev+i, 1);
        gd->part[MINOR(dev+i)].start_sect = 0;
        gd->part[MINOR(dev+i)].nr_sects = 0;
    }

#if 0
    /* VBDs can change under our feet. Check if that has happened. */
    if ( MAJOR(dev) == XLVIRT_MAJOR )
    {
        xen_disk_info_t *xdi = kmalloc(sizeof(*xdi), GFP_KERNEL);
        if ( xdi != NULL )
        {
            memset(xdi, 0, sizeof(*xdi));
            xenolinux_control_msg(XEN_BLOCK_PROBE, 
                                  (char *)xdi, sizeof(*xdi));
            for ( i = 0; i < xdi->count; i++ )
                if ( IS_VIRTUAL_XENDEV(xdi->disks[i].device) &&
                     ((xdi->disks[i].device & XENDEV_IDX_MASK) == disk_nr) )
                    ((xl_disk_t *)gd->real_devices)[disk_nr].capacity =
                        xdi->disks[i].capacity;
            kfree(xdi);
        }
    }
#endif

    grok_partitions(gd, disk_nr, gd->nr_real, disk->capacity);

    return 0;
}


/*
 * hypervisor_request
 *
 * request block io 
 * 
 * id: for guest use only.
 * operation: XEN_BLOCK_{READ,WRITE,PROBE,VBD*}
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 */
static int hypervisor_request(unsigned long   id,
                              int             operation,
                              char *          buffer,
                              unsigned long   sector_number,
                              unsigned short  nr_sectors,
                              kdev_t          device)
{
    unsigned long buffer_ma = phys_to_machine(virt_to_phys(buffer)); 
    struct gendisk *gd;
    blk_ring_req_entry_t *req;
    struct buffer_head *bh;

    if ( nr_sectors >= (1<<9) ) BUG();
    if ( (buffer_ma & ((1<<9)-1)) != 0 ) BUG();

    if ( state == STATE_CLOSED )
        return 1;

    switch ( operation )
    {

    case XEN_BLOCK_READ:
    case XEN_BLOCK_WRITE:

	/* Get the appropriate gendisk */
	gd = xldev_to_gendisk(device); 

	/* Update the sector_number we'll pass down as appropriate; note 
	   that we could sanity check that resulting sector will be in 
	   this partition, but this will happen in xen anyhow */
	sector_number += gd->part[MINOR(device)].start_sect;

        if ( (sg_operation == operation) &&
             (sg_dev == device) &&
             (sg_next_sect == sector_number) )
        {
            req = &blk_ring->ring[(req_prod-1)&(BLK_RING_SIZE-1)].req;
            bh = (struct buffer_head *)id;
            bh->b_reqnext = (struct buffer_head *)req->id;
            req->id = id;
            req->buffer_and_sects[req->nr_segments] = buffer_ma | nr_sectors;
            if ( ++req->nr_segments < MAX_BLK_SEGS )
                sg_next_sect += nr_sectors;
            else
                DISABLE_SCATTERGATHER();
            return 0;
        }
        else if ( RING_PLUGGED )
        {
            return 1;
        }
        else
        {
            sg_operation = operation;
            sg_dev       = device;
            sg_next_sect = sector_number + nr_sectors;
        }
        break;

    default:
        panic("unknown op %d\n", operation);
    }

    /* Fill out a communications ring structure. */
    req = &blk_ring->ring[req_prod].req;
    req->id            = id;
    req->operation     = operation;
    req->sector_number = sector_number;
    req->device        = device; 
    req->nr_segments   = 1;
    req->buffer_and_sects[0] = buffer_ma | nr_sectors;
    req_prod = BLK_RING_INC(req_prod);

    return 0;
}


/*
 * do_xlblk_request
 *  read a block; request is in a request queue
 */
void do_xlblk_request(request_queue_t *rq)
{
    struct request *req;
    struct buffer_head *bh, *next_bh;
    int rw, nsect, full, queued = 0;
    
    DPRINTK("xlblk.c::do_xlblk_request for '%s'\n", DEVICE_NAME); 

    while ( !rq->plugged && !list_empty(&rq->queue_head))
    {
	if ( (req = blkdev_entry_next_request(&rq->queue_head)) == NULL ) 
	    goto out;
		
        DPRINTK("do_xlblk_request %p: cmd %i, sec %lx, (%li/%li) bh:%p\n",
                req, req->cmd, req->sector,
                req->current_nr_sectors, req->nr_sectors, req->bh);

        rw = req->cmd;
        if ( rw == READA ) rw = READ;
        if ((rw != READ) && (rw != WRITE))
            panic("XenoLinux Virtual Block Device: bad cmd: %d\n", rw);

	req->errors = 0;

        bh = req->bh;
        while ( bh != NULL )
	{
            next_bh = bh->b_reqnext;
            bh->b_reqnext = NULL;

            full = hypervisor_request(
                (unsigned long)bh,
                (rw == READ) ? XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
                bh->b_data, bh->b_rsector, bh->b_size>>9, bh->b_rdev);

	    if(full) { 

		bh->b_reqnext = next_bh;
		pending_queues[nr_pending++] = rq;
		if ( nr_pending >= MAX_PENDING ) BUG();
		goto out; 

            }

            queued++;

            /* Dequeue the buffer head from the request. */
            nsect = bh->b_size >> 9;
            bh = req->bh = next_bh;
            
            if ( bh != NULL )
            {
                /* There's another buffer head to do. Update the request. */
                req->hard_sector += nsect;
                req->hard_nr_sectors -= nsect;
                req->sector = req->hard_sector;
                req->nr_sectors = req->hard_nr_sectors;
                req->current_nr_sectors = bh->b_size >> 9;
                req->buffer = bh->b_data;
            }
            else
            {
                /* That was the last buffer head. Finalise the request. */
                if ( end_that_request_first(req, 1, "XenBlk") ) BUG();
                blkdev_dequeue_request(req);
                end_that_request_last(req);
            }
        }
    }

 out:
    if ( queued != 0 ) signal_requests_to_xen();
}


static void kick_pending_request_queues(void)
{
    /* We kick pending request queues if the ring is reasonably empty. */
    if ( (nr_pending != 0) && 
         (((req_prod - resp_cons) & (BLK_RING_SIZE - 1)) < 
          (BLK_RING_SIZE >> 1)) )
    {
        /* Attempt to drain the queue, but bail if the ring becomes full. */
        while ( nr_pending != 0 )
        {
            do_xlblk_request(pending_queues[--nr_pending]);
            if ( RING_PLUGGED ) break;
        }
    }
}


static void xlblk_response_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    int i; 
    unsigned long flags; 
    struct buffer_head *bh, *next_bh;

    if ( state == STATE_CLOSED )
        return;
    
    spin_lock_irqsave(&io_request_lock, flags);	    

    for ( i  = resp_cons;
	  i != blk_ring->resp_prod;
	  i  = BLK_RING_INC(i) )
    {
	blk_ring_resp_entry_t *bret = &blk_ring->ring[i].resp;
	switch (bret->operation)
	{
        case XEN_BLOCK_READ:
        case XEN_BLOCK_WRITE:
            if ( bret->status )
                DPRINTK("Bad return from blkdev data request: %lx\n",
                        bret->status);
            for ( bh = (struct buffer_head *)bret->id; 
                  bh != NULL; 
                  bh = next_bh )
            {
                next_bh = bh->b_reqnext;
                bh->b_reqnext = NULL;
                bh->b_end_io(bh, !bret->status);
            }
	    break;
	    
        default:
            BUG();
	}
    }
    
    resp_cons = i;

    kick_pending_request_queues();

    spin_unlock_irqrestore(&io_request_lock, flags);
}



static void reset_xlblk_interface(void)
{
    block_io_op_t op; 

    nr_pending = 0;

    op.cmd = BLOCK_IO_OP_RESET;
    if ( HYPERVISOR_block_io_op(&op) != 0 )
        printk(KERN_ALERT "Possible blkdev trouble: couldn't reset ring\n");

    op.cmd = BLOCK_IO_OP_RING_ADDRESS;
    (void)HYPERVISOR_block_io_op(&op);

    set_fixmap(FIX_BLKRING_BASE, op.u.ring_mfn << PAGE_SHIFT);
    blk_ring = (blk_ring_t *)fix_to_virt(FIX_BLKRING_BASE);
    blk_ring->req_prod = blk_ring->resp_prod = resp_cons = req_prod = 0;

    wmb();
    state = STATE_ACTIVE;
}


int __init xlblk_init(void)
{
    int error; 
    block_io_op_t op; 

    reset_xlblk_interface();

    error = request_irq(XLBLK_RESPONSE_IRQ, xlblk_response_int, 
                        SA_SAMPLE_RANDOM, "blkdev", NULL);
    if ( error )
    {
	printk(KERN_ALERT "Could not allocate receive interrupt\n");
	goto fail;
    }

    /* Setup our [empty] disk information structure */
    xlblk_disk_info.max   = XDI_MAX; 
    xlblk_disk_info.disks = kmalloc(XDI_MAX * sizeof(xen_disk_t), GFP_KERNEL);
    xlblk_disk_info.count = 0; 

    /* Probe for disk information. */
    memset(&op, 0, sizeof(op)); 
    op.cmd = BLOCK_IO_OP_VBD_PROBE; 
    op.u.probe_params.domain = 0; 
    memcpy(&op.u.probe_params.xdi, &xlblk_disk_info, sizeof(xlblk_disk_info)); 

    error = HYPERVISOR_block_io_op(&op); 

    if ( error )
    {
        printk(KERN_ALERT "Could not probe disks (%d)\n", error);
        free_irq(XLBLK_RESPONSE_IRQ, NULL);
        goto fail;
    }

    /* copy back the [updated] count parameter */
    xlblk_disk_info.count = op.u.probe_params.xdi.count; 

    /* Pass the information to our virtual block device susbystem. */
    xlvbd_init(&xlblk_disk_info);

    return 0;

 fail:
    return error;
}

static void __exit xlblk_cleanup(void)
{
    xlvbd_cleanup();
    free_irq(XLBLK_RESPONSE_IRQ, NULL);
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif


void blkdev_suspend(void)
{
    state = STATE_SUSPENDED;
    wmb();

    while ( resp_cons != blk_ring->req_prod )
    {
        barrier();
        current->state = TASK_INTERRUPTIBLE;
        schedule_timeout(1);
    }

    wmb();
    state = STATE_CLOSED;
    wmb();

    clear_fixmap(FIX_BLKRING_BASE);
}


void blkdev_resume(void)
{
    reset_xlblk_interface();
    spin_lock_irq(&io_request_lock);
    kick_pending_request_queues();
    spin_unlock_irq(&io_request_lock);
}
