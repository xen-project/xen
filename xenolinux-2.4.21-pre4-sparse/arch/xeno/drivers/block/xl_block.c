/******************************************************************************
 * xl_block.c
 * 
 * Xenolinux virtual block-device driver (xhd).
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

#define MAJOR_NR XLBLK_MAJOR   /* force defns in blk.h, must precede include */
static int xlblk_major = XLBLK_MAJOR;
#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char	byte; 

#define XLBLK_MAX 32 /* Maximum minor devices we support */
#define XLBLK_MAJOR_NAME "xhd"
#define IDE_PARTN_BITS 6                           /* from ide.h::PARTN_BITS */
#define IDE_PARTN_MASK ((1<<IDE_PARTN_BITS)-1)     /* from ide.h::PARTN_MASK */
static int xlblk_blk_size[XLBLK_MAX];
static int xlblk_blksize_size[XLBLK_MAX];
static int xlblk_read_ahead; 
static int xlblk_hardsect_size[XLBLK_MAX];
static int xlblk_max_sectors[XLBLK_MAX];

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

static int xenolinux_block_open(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_block_open\n"); 
    return 0;
}

static int xenolinux_block_release(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_block_release\n");
    return 0;
}

static int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
			  unsigned command, unsigned long argument)
{
    int minor_dev;
    struct hd_geometry *geo = (struct hd_geometry *)argument;

    DPRINTK("xenolinux_block_ioctl\n"); 

    /* check permissions */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!inode)                  return -EINVAL;
    minor_dev = MINOR(inode->i_rdev);
    if (minor_dev >= XLBLK_MAX)  return -ENODEV;
    
    DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, minor: 0x%x\n",
                  command, (long) argument, minor_dev); 
  
    switch (command)
    {
    case BLKGETSIZE:                                             /* get size */
        DPRINTK_IOCTL("   BLKGETSIZE: %x %lx\n", BLKGETSIZE, 
                      (long) xlblk_disk_info.disks[0].capacity); 
	return put_user(xlblk_disk_info.disks[0].capacity, 
			(unsigned long *) argument);

    case BLKRRPART:                               /* re-read partition table */
        DPRINTK_IOCTL("   BLKRRPART: %x\n", BLKRRPART); 
	break;

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

static int xenolinux_block_check(kdev_t dev)
{
    DPRINTK("xenolinux_block_check\n");
    return 0;
}

static int xenolinux_block_revalidate(kdev_t dev)
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
        /* only accept requests for xhd and vhd devices */
	if (!IS_XHD_MAJOR(MAJOR(device)) && !IS_VHD_MAJOR(MAJOR(device)))
	    panic("error: xl_block::hypervisor_request: "
                  "unknown device [0x%x]\n", device);
	phys_device = MAJOR(device);

	/* Compute real buffer location on disk.
	 * note: gd will be null when we read the partition table.
	 */
	sector_number = block_number;
	if ( gd != NULL )
	{
	  sector_number += gd->part[MINOR(device)&IDE_PARTN_MASK].start_sect;
	}

	/*
	if (IS_VHD_MAJOR(MAJOR(device)))
	{
	  printk (KERN_ALERT "%lx + %lx = %lx (%x)\n",
		  block_number,
		  gd->part[MINOR(device)&IDE_PARTN_MASK].start_sect,
		  sector_number, device);
	}
	*/
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
static void do_xlblk_request (request_queue_t *rq)
{
    struct request *req;
    struct buffer_head *bh;
    int rw, nsect, full, queued = 0;
    
    DPRINTK("xlblk.c::do_xlblk_request for '%s'\n", DEVICE_NAME); 

    while ( !rq->plugged && !QUEUE_EMPTY )
    {
	if ( (req = CURRENT) == NULL ) goto out;
		
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
    /* aho: okay, so this is a bit of a hack.  we'll kick every queue... */
    do_xlblk_request(BLK_DEFAULT_QUEUE(XLBLK_MAJOR));
    do_xlseg_requestX(BLK_DEFAULT_QUEUE(XLSEG_MAJOR));
    
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
    printk (KERN_ALERT "xhd block device probe:\n");
    for ( i = 0; i < xlblk_disk_info.count; i++ )
    { 
	printk (KERN_ALERT "  %2d: type: %d, capacity: %ld\n",
		i, xlblk_disk_info.disks[i].type, 
		xlblk_disk_info.disks[i].capacity);
    }
    
    SET_MODULE_OWNER(&xenolinux_block_fops);
    result = register_blkdev(xlblk_major, "block", &xenolinux_block_fops);
    if (result < 0) {
	printk (KERN_ALERT "xenolinux block: can't get major %d\n",
		xlblk_major);
	return result;
    }

    /* initialize global arrays in drivers/block/ll_rw_block.c */
    for (i = 0; i < XLBLK_MAX; i++) {
	xlblk_blk_size[i]      = xlblk_disk_info.disks[0].capacity;
	xlblk_blksize_size[i]  = 512;
	xlblk_hardsect_size[i] = 512;
	xlblk_max_sectors[i]   = 128;
    }
    xlblk_read_ahead  = 8; 

    blk_size[xlblk_major]      = xlblk_blk_size;
    blksize_size[xlblk_major]  = xlblk_blksize_size;
    hardsect_size[xlblk_major] = xlblk_hardsect_size;
    read_ahead[xlblk_major]    = xlblk_read_ahead; 
    max_sectors[xlblk_major]   = xlblk_max_sectors;

    blk_init_queue(BLK_DEFAULT_QUEUE(xlblk_major), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(xlblk_major), 0);

    xlblk_ide_register_disk(0, xlblk_disk_info.disks[0].capacity);

    printk(KERN_ALERT 
	   "XenoLinux Virtual Block Device Driver installed [device: %d]\n",
	   xlblk_major);
    return 0;

 fail:
    return error;
}

void xlblk_ide_register_disk(int idx, unsigned long capacity)
{
    int units;
    int minors;
    struct gendisk *gd;

    /* plagarized from ide-probe.c::init_gendisk */
    
    units = 2; /* from ide.h::MAX_DRIVES */

    minors    = units * (1<<IDE_PARTN_BITS);
    gd        = kmalloc (sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc (minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc (minors * sizeof(struct hd_struct), GFP_KERNEL);
    memset(gd->part, 0, minors * sizeof(struct hd_struct));
    
    gd->major        = xlblk_major;  
    gd->major_name   = XLBLK_MAJOR_NAME;
    gd->minor_shift  = IDE_PARTN_BITS; 
    gd->max_p	     = 1<<IDE_PARTN_BITS;
    gd->nr_real	     = units;           
    gd->real_devices = NULL;          
    gd->next	     = NULL;            
    gd->fops         = &xenolinux_block_fops;
    gd->de_arr       = kmalloc (sizeof *gd->de_arr * units, GFP_KERNEL);
    gd->flags	     = kmalloc (sizeof *gd->flags * units, GFP_KERNEL);

    if (gd->de_arr)  
	memset (gd->de_arr, 0, sizeof *gd->de_arr * units);

    if (gd->flags) 
	memset (gd->flags, 0, sizeof *gd->flags * units);

    add_gendisk(gd);

    xlblk_disk_info.disks[idx].gendisk = gd;

    register_disk(gd, MKDEV(xlblk_major, 0), 1<<IDE_PARTN_BITS,
		  &xenolinux_block_fops, capacity);

    {
      int loop = 0;
      printk (KERN_ALERT "Partition Table: (capacity: %lx)\n", capacity);
      for (loop = 0; loop < minors; loop++)
      {
	if (gd->part[loop].start_sect && gd->part[loop].nr_sects)
	{
	  printk (KERN_ALERT 
		  "  %2d: 0x%6lx %8ld    0x%6lx %7ld\n", loop,
		  gd->part[loop].start_sect, gd->part[loop].start_sect,
		  gd->part[loop].nr_sects, gd->part[loop].nr_sects);
	}
      }
    }

    return;
}



static void __exit xlblk_cleanup(void)
{
    /* CHANGE FOR MULTIQUEUE */
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(xlblk_major));

    /* clean up global arrays */
    read_ahead[xlblk_major] = 0;

    if (blk_size[xlblk_major]) 
	kfree(blk_size[xlblk_major]);
    blk_size[xlblk_major] = NULL;

    if (blksize_size[xlblk_major]) 
	kfree(blksize_size[xlblk_major]);
    blksize_size[xlblk_major] = NULL;

    if (hardsect_size[xlblk_major]) 
	kfree(hardsect_size[xlblk_major]);
    hardsect_size[xlblk_major] = NULL;
    
    /* XXX: free each gendisk */
    if (unregister_blkdev(xlblk_major, "block"))
	printk(KERN_ALERT
	       "XenoLinux Virtual Block Device Driver uninstalled w/ errs\n");
    else
	printk(KERN_ALERT 
	       "XenoLinux Virtual Block Device Driver uninstalled\n");

    return;
}


#ifdef MODULE
module_init(xlblk_init);
module_exit(xlblk_cleanup);
#endif
