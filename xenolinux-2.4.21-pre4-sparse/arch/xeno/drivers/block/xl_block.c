/******************************************************************************
 * xl_block.c
 * 
 * Xenolinux virtual block-device driver.
 * 
 */

#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/blkdev.h>
#include <linux/major.h>

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char	byte; 

extern int  xlide_init(int xidx, int idx); 
extern int  xlide_hwsect(int minor); 
extern void xlide_cleanup(void); 
extern int  xlscsi_init(int xidx, int idx);
extern int  xlscsi_hwsect(int minor); 
extern void xlscsi_cleanup(void); 

static int nide = 0;    // number of IDE devices we have 
static int nscsi = 0;   // number of SCSI devices we have 


#define XLBLK_MAX 32 /* XXX SMH: this the max of XLIDE_MAX and XLSCSI_MAX */

#define XLBLK_RESPONSE_IRQ _EVENT_BLK_RESP

#define DEBUG_IRQ    _EVENT_DEBUG 

#if 0
#define DPRINTK(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#define DPRINTK_IOCTL(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

static blk_ring_t *blk_ring;
static unsigned int resp_cons; /* Response consumer for comms ring. */

static xen_disk_info_t xlblk_disk_info;
atomic_t xlblk_control_count;

void xlblk_ide_register_disk(int, unsigned long);
void do_xlseg_requestX (request_queue_t *rq);
int hypervisor_request(void *          id,
                       int             operation,
                       char *          buffer,
                       unsigned long   block_number,
                       unsigned short  block_size,
                       kdev_t          device,
		       struct gendisk *gd);

/* ------------------------------------------------------------------------
 */

/* Convert from a XenoLinux (major,minor) to the Xen-level 'physical' device */
static kdev_t xldev_to_physdev(kdev_t xldev) 
{
    int xlmajor = MAJOR(xldev); 
    int major, minor; 

    switch(xlmajor) { 
    case XLIDE_MAJOR: 
	major = IDE0_MAJOR; 
	minor = 0; /* we do minor offsetting manually by addition */
	break; 
	
    case XLSCSI_MAJOR: 
	major = SCSI_DISK0_MAJOR; 
	minor = 0; /* we do minor offsetting manually by addition */
	break; 

    default: 
	panic("xldev_to_physdev: unhandled major %d\n", xlmajor); 
	break; 
    } 

    return MKDEV(major, minor); 
}


/*
** Locate the gendisk structure associated with a particular xenolinux disk; 
** this requires a scan of the xen_disk_info[] array currently which kind of
** sucks. However we can clean this whole area up later (i.e. post SOSP). 
*/
struct gendisk *xldev_to_gendisk(kdev_t xldev, int *t) 
{
    int i, j, posn, type; 

    switch(MAJOR(xldev)) { 
	
    case XLIDE_MAJOR: 
	type = 1; 
	posn = 1; 
	break; 
	
    case XLSCSI_MAJOR: 
	type = 2; 
	posn = 1; 
	break; 

    default: 
	panic("xldev_to_gendisk: unhandled major %d\n", MAJOR(xldev)); 
	break; 
    } 


    for ( i = j = 0; i < xen_disk_info.count; i++ ) {
	if(xen_disk_info.disks[i].type == type)
	    if(++j == posn)
		break; 
    }

    if(t) 
	*t = type; 

    return (xen_disk_info.disks[i].gendisk); 
}

int xenolinux_block_open(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_block_open\n"); 
    return 0;
}

int xenolinux_block_release(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_block_release\n");
    return 0;
}



int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
			  unsigned command, unsigned long argument)
{
    int minor_dev, type;
    struct hd_geometry *geo = (struct hd_geometry *)argument;
    struct gendisk *gd;     
    struct hd_struct *part; 
    
    DPRINTK("xenolinux_block_ioctl\n"); 

    /* check permissions */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!inode)                  return -EINVAL;

    minor_dev = MINOR(inode->i_rdev);
    if (minor_dev >= XLBLK_MAX)  return -ENODEV;
    
    DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, minor: 0x%x\n",
                  command, (long) argument, minor_dev); 
  
    gd = xldev_to_gendisk(inode->i_rdev, &type); 
    part = &gd->part[minor_dev]; 

    switch (command)
    {
    case BLKGETSIZE:
        DPRINTK_IOCTL("   BLKGETSIZE: %x %lx\n", BLKGETSIZE, part->nr_sects); 
	return put_user(part->nr_sects, (unsigned long *) argument);

    case BLKRRPART:                               /* re-read partition table */
        DPRINTK_IOCTL("   BLKRRPART: %x\n", BLKRRPART); 
	break;

    case BLKSSZGET:
	switch(type) {
	case 1: 
	    DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET, 
			  xlide_hwsect(minor_dev));
	    return xlide_hwsect(minor_dev); 
	    break; 
	case 2: 
	    DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET,
			  xlscsi_hwsect(minor_dev));
	    return xlscsi_hwsect(minor_dev); 
	    break; 

	default: 
	    printk("BLKSSZGET ioctl() on bogus type %d disk!\n", type); 
	    return 0; 

	}

    case BLKBSZSET:                                        /* set block size */
        DPRINTK_IOCTL("   BLKBSZSET: %x\n", BLKBSZSET);
	break;

    case BLKRASET:                                         /* set read-ahead */
        DPRINTK_IOCTL("   BLKRASET: %x\n", BLKRASET);
	break;

    case BLKRAGET:                                         /* get read-ahead */
        DPRINTK_IOCTL("   BLKRAFET: %x\n", BLKRAGET);
	break;

    case BLKSSZGET:                                       /* get sector size */
        DPRINTK_IOCTL("   BLKSSZGET: %x 0x%x\n", BLKSSZGET,
                      xlblk_hardsect_size[minor_dev]);
	return xlblk_hardsect_size[minor_dev]; 

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
    DPRINTK("xenolinux_block_revalidate\n"); 
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
 * block_number:  block to read
 * block_size:  size of each block
 * device:  xhd or vhd
 * gd: partition information if XEN_BLOCK_{READ,WRITE}
 */
int hypervisor_request(void *          id,
                       int             operation,
                       char *          buffer,
                       unsigned long   block_number,
                       unsigned short  block_size,
                       kdev_t          device,
		       struct gendisk *gd)
{
    int position;
    void *buffer_ma; 
    kdev_t phys_device = (kdev_t) 0;
    unsigned long sector_number = 0;
 
    /*
     * Bail if there's no room in the request communication ring. This may be 
     * because we have a whole bunch of outstanding responses to process. No 
     * matter, as the response handler will kick the request queue.
     */
    if ( BLK_RING_INC(blk_ring->req_prod) == resp_cons )
        return 1;

    buffer_ma = (void *)phys_to_machine(virt_to_phys(buffer)); 

    switch ( operation )
    {
    case XEN_BLOCK_SEG_CREATE:
    case XEN_BLOCK_SEG_DELETE:
    case XEN_BLOCK_PROBE_BLK:
    case XEN_BLOCK_PROBE_SEG:
	phys_device = (kdev_t) 0;
	sector_number = 0;
        break;

    case XEN_BLOCK_READ:
    case XEN_BLOCK_WRITE:
        phys_device =  xldev_to_physdev(device); 
	if (!IS_XHD_MAJOR(MAJOR(device)))
            phys_device = MAJOR(device);
	/* Compute real buffer location on disk */
	sector_number = block_number;
	gd = xldev_to_gendisk(device, NULL); 
	sector_number += gd->part[MINOR(device)].start_sect;
        break;

    default:
        panic("unknown op %d\n", operation);
    }

    /* Fill out a communications ring structure & trap to the hypervisor */
    position = blk_ring->req_prod;
    blk_ring->ring[position].req.id            = id;
    blk_ring->ring[position].req.operation     = operation;
    blk_ring->ring[position].req.buffer        = buffer_ma;
    blk_ring->ring[position].req.block_number  = block_number;
    blk_ring->ring[position].req.block_size    = block_size;
    blk_ring->ring[position].req.device        = phys_device;
    blk_ring->ring[position].req.sector_number = sector_number;

    blk_ring->req_prod = BLK_RING_INC(position);

    return 0;
}


/*
 * do_xlblk_request
 *  read a block; request is in a request queue
 */
void do_xlblk_request (request_queue_t *rq)
{
    struct request *req;
    struct buffer_head *bh;
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
            full = hypervisor_request(
                bh, (rw == READ) ? XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
                bh->b_data, bh->b_rsector, bh->b_size, bh->b_dev,
		(struct gendisk *)xlblk_disk_info.disks[0].gendisk);

            if ( full ) goto out;

            queued++;

            /* Dequeue the buffer head from the request. */
            nsect = bh->b_size >> 9;
            req->bh = bh->b_reqnext;
            bh->b_reqnext = NULL;
            bh = req->bh;
            
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
    if ( queued != 0 ) HYPERVISOR_block_io_op();
}


static struct block_device_operations xenolinux_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};

static void xlblk_response_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    int i; 
    unsigned long flags; 
    struct buffer_head *bh;
    
    spin_lock_irqsave(&io_request_lock, flags);	    

    for ( i  = resp_cons;
	  i != blk_ring->resp_prod;
	  i  = BLK_RING_INC(i) )
    {
	blk_ring_resp_entry_t *bret = &blk_ring->ring[i].resp;
	switch (bret->operation)
	{
	  case XEN_BLOCK_READ :
  	  case XEN_BLOCK_WRITE :
	    if ( (bh = bret->id) != NULL ) bh->b_end_io(bh, 1);
	    break;
	    
	  case XEN_BLOCK_SEG_CREATE :
	  case XEN_BLOCK_SEG_DELETE :
	  case XEN_BLOCK_PROBE_SEG :
	    atomic_dec(&xlblk_control_count);
	    break;
	  
	  default:
	    break;
	}
    }
    
    resp_cons = i;

    /* KAF: We can push work down at this point. We have the lock. */
    for (i = 0; i < xen_disk_info.count; i++) {
	/*
	** XXX SMH: this is pretty broken ... 
	**     a) should really only kick devs w/ outstanding work 
	**     b) should cover /all/ devs, not just first IDE & SCSI
	** KAF will fix this I'm sure. 
	*/
	do_xlblk_request(BLK_DEFAULT_QUEUE(IDE0_MAJOR));
	do_xlblk_request(BLK_DEFAULT_QUEUE(SCSI_DISK0_MAJOR));
        do_xlseg_requestX(BLK_DEFAULT_QUEUE(XLSEG_MAJOR));
    }

    spin_unlock_irqrestore(&io_request_lock, flags);
}


int __init xlblk_init(void)
{
    int i, error, result;

    atomic_set(&xlblk_control_count, 0);

    /* This mapping was created early at boot time. */
    blk_ring = (blk_ring_t *)fix_to_virt(FIX_BLKRING_BASE);
    blk_ring->req_prod = blk_ring->resp_prod = resp_cons = 0;
    
    error = request_irq(XLBLK_RESPONSE_IRQ, xlblk_response_int, 0, 
			"xlblk-response", NULL);
    if (error) {
	printk(KERN_ALERT "Could not allocate receive interrupt\n");
	goto fail;
    }

    /* probe for disk information */
    memset (&xlblk_disk_info, 0, sizeof(xlblk_disk_info));
    xlblk_disk_info.count = 0;

    if ( hypervisor_request(NULL, XEN_BLOCK_PROBE_BLK, 
			    (char *) &xlblk_disk_info,
                            0, 0, (kdev_t) 0, 
			    (struct gendisk *) NULL))
        BUG();
    HYPERVISOR_block_io_op();
    while ( blk_ring->resp_prod != 1 ) barrier();
    for ( i = 0; i < xlblk_disk_info.count; i++ )
    { 
	/* 
	** SMH: initialize all the disks we found; this is complicated a 
	** bit by the fact that we have both IDE and SCSI disks underneath 
	*/
	printk (KERN_ALERT "  %2d: type: %d, capacity: %ld\n",
		i, xlblk_disk_info.disks[i].type, 
		xlblk_disk_info.disks[i].capacity);
	
	switch(xen_disk_info.disks[i].type) { 
	case 1: 
	    xlide_init(i, nide++); 
	    break; 
	case 2: 
	    xlscsi_init(i, nscsi++); 
	    break; 
	default: 
	    printk("Unknown Xen disk type %d\n", xen_disk_info.disks[i].type);
	    break; 
	}
    }

    return 0;

 fail:
    return error;
}

static void __exit xlblk_cleanup(void)
{
    int i; 

    for ( i = 0; i < xen_disk_info.count; i++ )
    { 
	switch(xen_disk_info.disks[i].type) { 
	case 1: 
	    xlide_cleanup(); 
	    break; 
	case 2: 
	    xlscsi_cleanup(); 
	    break; 
	default: 
	    printk("Unknown Xen disk type %d\n", xen_disk_info.disks[i].type);
	    break; 
	}

    }

    return;
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif
