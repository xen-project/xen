/******************************************************************************
 * xl_block.c
 * 
 * Xenolinux virtual block-device driver.
 * 
 */

#include "xl_block.h"
#include <linux/blk.h>

typedef unsigned char byte; /* from linux/ide.h */

#define XLBLK_MAX 32

#define XLBLK_RESPONSE_IRQ _EVENT_BLK_RESP
#define DEBUG_IRQ          _EVENT_DEBUG 

#define PARTN_SHIFT 4

static blk_ring_t *blk_ring;
static unsigned int resp_cons; /* Response consumer for comms ring. */
static unsigned int req_prod;  /* Private request producer.         */
static xen_disk_info_t xlblk_disk_info;
static int xlblk_control_msg_pending;

#define RING_FULL (BLK_RING_INC(req_prod) == resp_cons)

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
    DISABLE_SCATTERGATHER();
    blk_ring->req_prod = req_prod;
    HYPERVISOR_block_io_op();
}

/* Convert from a XenoLinux major device to the Xen-level 'physical' device */
static inline unsigned short xldev_to_physdev(kdev_t xldev) 
{
    unsigned short physdev = 0;

    switch ( MAJOR(xldev) ) 
    { 
    case XLIDE_MAJOR: 
        physdev = XENDEV_IDE;
	break; 
	
    case XLSCSI_MAJOR: 
        physdev = XENDEV_SCSI;
	break; 

    case XLVIRT_MAJOR:
        physdev = XENDEV_VIRTUAL;
        break;
    } 

    if ( physdev == 0 ) BUG();

    physdev += (MINOR(xldev) >> PARTN_SHIFT);

    return physdev;
}


static inline struct gendisk *xldev_to_gendisk(kdev_t xldev) 
{
    struct gendisk *gd = NULL;

    switch ( MAJOR(xldev) ) 
    { 
    case XLIDE_MAJOR: 
        gd = xlide_gendisk;
	break; 
	
    case XLSCSI_MAJOR: 
        gd = xlscsi_gendisk;
	break; 

    case XLVIRT_MAJOR:
        gd = xlsegment_gendisk;
        break;
    }

    if ( gd == NULL ) BUG();

    return gd;
}


static inline xl_disk_t *xldev_to_xldisk(kdev_t xldev)
{
    struct gendisk *gd = xldev_to_gendisk(xldev);
    return (xl_disk_t *)gd->real_devices + (MINOR(xldev) >> PARTN_SHIFT);
}


int xenolinux_block_open(struct inode *inode, struct file *filep)
{
    xl_disk_t *disk = xldev_to_xldisk(inode->i_rdev);
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
    
    DPRINTK("xenolinux_block_ioctl\n"); 

    /* check permissions */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!inode)                  return -EINVAL;

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
        if ( !capable(CAP_SYS_ADMIN) ) return -EACCES;
        return xenolinux_block_revalidate(dev);

    case BLKSSZGET:
	switch ( MAJOR(dev) )
        {
	case XLIDE_MAJOR: 
	    DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET, 
			  xlide_hwsect(MINOR(dev)));
	    return xlide_hwsect(MINOR(dev)); 

	case XLSCSI_MAJOR: 
	    DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET,
			  xlscsi_hwsect(MINOR(dev)));
	    return xlscsi_hwsect(MINOR(dev)); 

        case XLVIRT_MAJOR:
	    DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET, 
			  xlsegment_hwsect(MINOR(dev)));
	    return xlsegment_hwsect(MINOR(dev)); 

	default: 
	    printk(KERN_ALERT "BLKSSZGET ioctl() on bogus disk!\n"); 
            return 0;
	}

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

    default:
        DPRINTK_IOCTL("   eh? unknown ioctl\n");
	break;
    }
    
    return 0;
}

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
    int i;
    
    spin_lock_irqsave(&io_request_lock, flags);
    if ( disk->usage > 1 )
    {
        spin_unlock_irqrestore(&io_request_lock, flags);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&io_request_lock, flags);

    for ( i = 0; i < (1 << PARTN_SHIFT); i++ )
    {
        invalidate_device(dev + i, 1);
        gd->part[dev + i].start_sect = 0;
        gd->part[dev + i].nr_sects = 0;
    }

    grok_partitions(gd, MINOR(dev) >> PARTN_SHIFT,
                    1 << PARTN_SHIFT, disk->capacity);

    return 0;
}


/*
 * hypervisor_request
 *
 * request block io 
 * 
 * id: for guest use only.
 * operation: XEN_BLOCK_{READ,WRITE,PROBE*,SEG*}
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
    kdev_t phys_device = (kdev_t) 0;
    struct gendisk *gd;
    blk_ring_req_entry_t *req;
    struct buffer_head *bh;

    if ( nr_sectors >= (1<<9) ) BUG();
    if ( (buffer_ma & ((1<<9)-1)) != 0 ) BUG();

    switch ( operation )
    {
    case XEN_BLOCK_SEG_CREATE:
    case XEN_BLOCK_SEG_DELETE:
    case XEN_BLOCK_PROBE_BLK:
    case XEN_BLOCK_PROBE_SEG:
        if ( RING_FULL ) return 1;
	phys_device = (kdev_t) 0;
	sector_number = 0;
        DISABLE_SCATTERGATHER();
        break;

    case XEN_BLOCK_READ:
    case XEN_BLOCK_WRITE:
        phys_device = xldev_to_physdev(device);
	gd = xldev_to_gendisk(device); 
	sector_number += gd->part[MINOR(device)].start_sect;
        if ( (sg_operation == operation) &&
             (sg_dev == phys_device) &&
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
        else if ( RING_FULL )
        {
            return 1;
        }
        else
        {
            sg_operation = operation;
            sg_dev       = phys_device;
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
    req->device        = phys_device;
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

            if ( full )
            {
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


static void xlblk_response_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    int i; 
    unsigned long flags; 
    struct buffer_head *bh, *next_bh;
    
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
                printk(KERN_ALERT "Bad return from blkdev data request\n");
            for ( bh = (struct buffer_head *)bret->id; 
                  bh != NULL; 
                  bh = next_bh )
            {
                next_bh = bh->b_reqnext;
                bh->b_reqnext = NULL;
                bh->b_end_io(bh, !bret->status);
            }
	    break;
	    
        case XEN_BLOCK_SEG_CREATE:
        case XEN_BLOCK_SEG_DELETE:
        case XEN_BLOCK_PROBE_SEG:
        case XEN_BLOCK_PROBE_BLK:
            if ( bret->status )
                printk(KERN_ALERT "Bad return from blkdev control request\n");
            xlblk_control_msg_pending = 0;
            break;
	  
        default:
            BUG();
	}
    }
    
    resp_cons = i;

    /* We kick pending request queues if the ring is reasonably empty. */
    if ( (nr_pending != 0) && 
         (((req_prod - resp_cons) & (BLK_RING_SIZE - 1)) < 
          (BLK_RING_SIZE >> 1)) )
    {
        /* Attempt to drain the queue, but bail if the ring becomes full. */
        while ( nr_pending != 0 )
        {
            do_xlblk_request(pending_queues[--nr_pending]);
            if ( RING_FULL ) break;
        }
    }

    spin_unlock_irqrestore(&io_request_lock, flags);
}


/* Send a synchronous message to Xen. */
int xenolinux_control_msg(int operation, char *buffer, int size)
{
    unsigned long flags;
    char *aligned_buf;

    /* We copy from an aligned buffer, as interface needs sector alignment. */
    aligned_buf = (char *)get_free_page(GFP_KERNEL);
    if ( aligned_buf == NULL ) BUG();

    xlblk_control_msg_pending = 1;
    spin_lock_irqsave(&io_request_lock, flags);
    /* Note that size gets rounded up to a sector-sized boundary. */
    if ( hypervisor_request(0, operation, aligned_buf, 0, (size+511)/512, 0) )
        return -EAGAIN;
    signal_requests_to_xen();
    spin_unlock_irqrestore(&io_request_lock, flags);
    while ( xlblk_control_msg_pending ) barrier();

    memcpy(buffer, aligned_buf, size);
    free_page((unsigned long)aligned_buf);
    
    return 0;
}


int __init xlblk_init(void)
{
    int error;

    xlblk_control_msg_pending = 0;
    nr_pending = 0;

    /* This mapping was created early at boot time. */
    blk_ring = (blk_ring_t *)fix_to_virt(FIX_BLKRING_BASE);
    blk_ring->req_prod = blk_ring->resp_prod = resp_cons = req_prod = 0;
    
    error = request_irq(XLBLK_RESPONSE_IRQ, xlblk_response_int, 
                        SA_SAMPLE_RANDOM, "xlblk-response", NULL);
    if ( error )
    {
	printk(KERN_ALERT "Could not allocate receive interrupt\n");
	goto fail;
    }

    /* Probe for disk information. */
    memset(&xlblk_disk_info, 0, sizeof(xlblk_disk_info));
    error = xenolinux_control_msg(XEN_BLOCK_PROBE_BLK, 
                                  (char *)&xlblk_disk_info,
                                  sizeof(xen_disk_info_t));
    if ( error )
    {
        printk(KERN_ALERT "Could not probe disks (%d)\n", error);
        free_irq(XLBLK_RESPONSE_IRQ, NULL);
        goto fail;
    }

    /* Pass the information to our fake IDE and SCSI susbystems. */
    xlide_init(&xlblk_disk_info);
    xlscsi_init(&xlblk_disk_info);

    return 0;

 fail:
    return error;
}

static void __exit xlblk_cleanup(void)
{
    xlide_cleanup();
    xlscsi_cleanup();
    free_irq(XLBLK_RESPONSE_IRQ, NULL);
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif
