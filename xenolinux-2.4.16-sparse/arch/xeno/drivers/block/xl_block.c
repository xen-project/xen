#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <linux/fs.h>
#include <linux/hdreg.h>                               /* HDIO_GETGEO, et al */
#include <linux/blkdev.h>
#include <linux/major.h>

/* NOTE: this is drive independent, so no inclusion of ide.h */

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/io.h>
#include <asm/uaccess.h>                                       /* put_user() */

#define MAJOR_NR XLBLK_MAJOR   /* force defns in blk.h, must preceed include */
static int xlblk_major = XLBLK_MAJOR;

#include <linux/blk.h>           /* must come after definition of MAJOR_NR!! */

/* instead of including linux/ide.h to pick up the definitiong of byte
 * (and consequently screwing up blk.h, we'll just copy the definition */
typedef unsigned char	byte; 

void xlblk_ide_register_disk(int, unsigned long);

#define XLBLK_MAX 2                                /* very arbitrary */
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

typedef struct xlblk_device
{
  struct buffer_head *bh;
  unsigned int tx_count;                  /* number of used slots in tx ring */
} xlblk_device_t;

xlblk_device_t xlblk_device;

#define XLBLK_DEBUG       0
#define XLBLK_DEBUG_IOCTL 0

static blk_ring_t *blk_ring;

/* 
 * disk management
 */

xen_disk_info_t xen_disk_info;

/* some declarations */
void hypervisor_request(void *         id,
			int            operation,
			char *         buffer,
			unsigned long  block_number,
			unsigned short block_size,
			kdev_t         device,
			int            mode);


/* ------------------------------------------------------------------------
 */

static int xenolinux_block_open(struct inode *inode, struct file *filep)
{
    if (XLBLK_DEBUG)
	printk (KERN_ALERT "xenolinux_block_open\n"); 

    return 0;
}

static int xenolinux_block_release(struct inode *inode, struct file *filep)
{
    if (XLBLK_DEBUG)
	printk (KERN_ALERT "xenolinux_block_release\n");

    return 0;
}

static int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
			  unsigned command, unsigned long argument)
{
    int minor_dev;
    struct hd_geometry *geo = (struct hd_geometry *)argument;

    if (XLBLK_DEBUG_IOCTL)
	printk (KERN_ALERT "xenolinux_block_ioctl\n"); 

    /* check permissions */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!inode)                  return -EINVAL;
    minor_dev = MINOR(inode->i_rdev);
    if (minor_dev >= XLBLK_MAX)  return -ENODEV;
    
    if (XLBLK_DEBUG_IOCTL)
	printk (KERN_ALERT "   command: 0x%x, argument: 0x%lx, minor: 0x%x\n",
		command, (long) argument, minor_dev); 
  
    switch (command) {

    case BLKGETSIZE:
	if (XLBLK_DEBUG_IOCTL) 
	    printk (KERN_ALERT
		    "   BLKGETSIZE: %x %lx\n", BLKGETSIZE, 
		    (long) xen_disk_info.disks[0].capacity); 
	return put_user(xen_disk_info.disks[0].capacity, 
			(unsigned long *) argument);

    case BLKRRPART:
	if (XLBLK_DEBUG_IOCTL)
	    printk (KERN_ALERT "   BLKRRPART: %x\n", BLKRRPART); 
	break;

    case BLKSSZGET:
	if (XLBLK_DEBUG_IOCTL)
	    printk (KERN_ALERT "   BLKSSZGET: %x 0x%x\n", BLKSSZGET,
		    xlblk_hardsect_size[minor_dev]);
	return xlblk_hardsect_size[minor_dev]; 

    case HDIO_GETGEO:

	if (XLBLK_DEBUG_IOCTL)
	    printk (KERN_ALERT "   HDIO_GETGEO: %x\n", HDIO_GETGEO);

	if (!argument) return -EINVAL;
	if (put_user(0x00,  (unsigned long *) &geo->start)) return -EFAULT;
	if (put_user(0xff,  (byte *)&geo->heads)) return -EFAULT;
	if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
	if (put_user(0x106, (unsigned short *)&geo->cylinders)) return -EFAULT;
	return 0;

    case HDIO_GETGEO_BIG: 

	if (XLBLK_DEBUG_IOCTL) 
	    printk (KERN_ALERT "   HDIO_GETGEO_BIG: %x\n", HDIO_GETGEO_BIG);

	if (!argument) return -EINVAL;
	if (put_user(0x00,  (unsigned long *) &geo->start))  return -EFAULT;
	if (put_user(0xff,  (byte *)&geo->heads))   return -EFAULT;
	if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
	if (put_user(0x106, (unsigned int *) &geo->cylinders)) return -EFAULT;

	return 0;

    default:
	if (XLBLK_DEBUG_IOCTL) 
	    printk (KERN_ALERT "   eh? unknown ioctl\n");
	break;
    }
    
    return 0;
}

static int xenolinux_block_check(kdev_t dev)
{
    if (XLBLK_DEBUG) 
      printk (KERN_ALERT "xenolinux_block_check\n");
    return 0;
}

static int xenolinux_block_revalidate(kdev_t dev)
{
    if (XLBLK_DEBUG) 
	printk (KERN_ALERT "xenolinux_block_revalidate\n"); 
    return 0;
}

/*
 * hypervisor_request
 *
 * request block io 
 * 
 * id: for guest use only.
 * operation: XEN_BLOCK_READ, XEN_BLOCK_WRITE or XEN_BLOCK_PROBE
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 * block_number:  block to read
 * block_size:  size of each block
 * device:  ide/hda is 768 or 0x300
 * mode: XEN_BLOCK_SYNC or XEN_BLOCK_ASYNC.  async requests
 *   will queue until a sync request is issued.
 */

void hypervisor_request(void *         id,
			int            operation,
			char *         buffer,
			unsigned long  block_number,
			unsigned short block_size,
			kdev_t         device,
			int            mode)
{
    int position;
    void *buffer_pa, *buffer_ma; 
    kdev_t phys_device = (kdev_t) 0;
    unsigned long sector_number = 0;
    struct gendisk *gd; 
    

    buffer_pa = (void *)virt_to_phys(buffer); 
    buffer_ma = (void *)phys_to_machine((unsigned long)buffer_pa); 

    if (operation == XEN_BLOCK_PROBE) {
	phys_device = (kdev_t) 0;
	sector_number = 0;

    } else if (operation == XEN_BLOCK_READ || operation == XEN_BLOCK_WRITE) {

	/*
	 * map logial major device to the physical device number 
	 *
	 *           XLBLK_MAJOR -> IDE0_MAJOR  (123 -> 3)
	 */
	if (MAJOR(device) == XLBLK_MAJOR) 
	    phys_device = MKDEV(IDE0_MAJOR, 0);
	else {
	    printk (KERN_ALERT "error: xl_block::hypervisor_request: "
		    "unknown device [0x%x]\n", device);
	    BUG();
	}

	/*
	 * compute real buffer location on disk
	 * (from ll_rw_block.c::submit_bh)
	 */


	sector_number = block_number /* * block_size >> 9 */;

	if((gd = (struct gendisk *)xen_disk_info.disks[0].gendisk) != NULL)
	    sector_number += gd->part[MINOR(device)&IDE_PARTN_MASK].start_sect;
    }


    if (BLK_REQ_RING_INC(blk_ring->req_prod) == blk_ring->req_cons) {
	printk (KERN_ALERT "hypervisor_request: req_cons: %d, req_prod:%d",
		blk_ring->req_cons, blk_ring->req_prod);
	BUG(); 
    }
    
    /* Fill out a communications ring structure & trap to the hypervisor */
    position = blk_ring->req_prod;
    blk_ring->req_ring[position].id            = id;
    blk_ring->req_ring[position].priority      = mode;
    blk_ring->req_ring[position].operation     = operation;
    blk_ring->req_ring[position].buffer        = buffer_ma;
    blk_ring->req_ring[position].block_number  = block_number;
    blk_ring->req_ring[position].block_size    = block_size;
    blk_ring->req_ring[position].device        = phys_device;
    blk_ring->req_ring[position].sector_number = sector_number;

    blk_ring->req_prod = BLK_REQ_RING_INC(blk_ring->req_prod);

    switch(mode) { 

    case XEN_BLOCK_SYNC:  
	/* trap into hypervisor */
	HYPERVISOR_block_io_op();
	break; 

    case XEN_BLOCK_ASYNC:
	/* for now, do nothing.  the request will go in the ring and
	   the next sync request will trigger the hypervisor to act */
	printk("Oh dear-- ASYNC xen block of doom!\n"); 
	break; 

    default: 
	/* ummm, unknown mode. */
	printk("xl_block thingy: unknown mode %d\n", mode); 
	BUG();
    }

    return;
}


/*
 * do_xlblk_request
 *
 * read a block; request is in a request queue
 *
 * TO DO: should probably release the io_request_lock and then re-acquire
 *        (see LDD p. 338)
 */
static void do_xlblk_request (request_queue_t *rq)
{
    struct request *req;
    
    if (XLBLK_DEBUG)
	printk (KERN_ALERT "xlblk.c::do_xlblk_request for '%s'\n", 
		DEVICE_NAME); 
    
    while (!QUEUE_EMPTY)
    {
	struct buffer_head *bh;
	unsigned long offset;
	unsigned long length;
	int rw;
	
	if(rq->plugged) 
	    return ; 
	
	req = CURRENT;
	
	if (XLBLK_DEBUG) 
	    printk (KERN_ALERT
		    "do_xlblk_request %p: cmd %i, sec %lx, (%li) bh:%p\n",
		    req, req->cmd, req->sector,
		    req->current_nr_sectors, req->bh);
	
	/* is there space in the tx ring for this request?
	 * if the ring is full, then leave the request in the queue
	 *
	 * THIS IS A BIT BOGUS SINCE XEN COULD BE UPDATING REQ_CONS
	 * AT THE SAME TIME
	 */
        if (BLK_RESP_RING_INC(blk_ring->req_prod) == blk_ring->req_cons)
        {
            printk (KERN_ALERT "OOPS, TX LOOKS FULL  cons: %d  prod: %d\n",
                    blk_ring->req_cons, blk_ring->req_prod);
            BUG(); 
            break;
        }
	
	req->errors = 0;
	blkdev_dequeue_request(req);
	
	bh = req->bh;
	
	while (bh)
	{
	    offset = bh->b_rsector << 9;
	    length = bh->b_size;
	    
	    rw = req->cmd;
	    if (rw == READA)  rw= READ;
	    if ((rw != READ) && (rw != WRITE)) {
		printk (KERN_ALERT
			"XenoLinux Virtual Block Device: bad cmd: %d\n", rw);
		BUG();
	    }

	    hypervisor_request (req, rw == READ ? 
				XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
				bh->b_data, bh->b_rsector, bh->b_size, 
				bh->b_dev, XEN_BLOCK_SYNC);
	    bh = bh->b_reqnext;
	}

	blkdev_dequeue_request(req);

    }

    return;
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
    struct request *req;
    int loop;
    u_long flags; 
    
    for (loop = blk_ring->resp_cons;
	 loop != blk_ring->resp_prod;
	 loop = BLK_RESP_RING_INC(loop)) {

	blk_ring_resp_entry_t *bret = &blk_ring->resp_ring[loop];
	
	req = (struct request *)bret->id;
        if ( req == NULL ) continue; /* probes have NULL id */

	spin_lock_irqsave(&io_request_lock, flags);
	    
	if (!end_that_request_first(req, 1, "XenBlk"))
	    end_that_request_last(req);
	spin_unlock_irqrestore(&io_request_lock, flags);
	
    }
    
    blk_ring->resp_cons = loop;
}


int __init xlblk_init(void)
{
    int loop, error, result;

    /* This mapping was created early at boot time. */
    blk_ring = (blk_ring_t *)FIX_BLKRING_BASE;

    blk_ring->req_prod = blk_ring->req_cons = 0;
    blk_ring->resp_prod = blk_ring->resp_cons = 0;
    
    error = request_irq(XLBLK_RESPONSE_IRQ, xlblk_response_int, 0, 
			"xlblk-response", &xlblk_device);
    if (error) {
	printk(KERN_ALERT "Could not allocate receive interrupt\n");
	goto fail;
    }

    memset (&xen_disk_info, 0, sizeof(xen_disk_info));
    xen_disk_info.count = 0;

    hypervisor_request(NULL, XEN_BLOCK_PROBE, (char *) &xen_disk_info,
		       0, 0, (kdev_t) 0, XEN_BLOCK_SYNC);
    for (loop = 0; loop < xen_disk_info.count; loop++) 
	printk (KERN_ALERT "  %2d: type: %d, capacity: %ld\n",
		loop, xen_disk_info.disks[loop].type, 
		xen_disk_info.disks[loop].capacity);

    
    SET_MODULE_OWNER(&xenolinux_block_fops);
    result = register_blkdev(xlblk_major, "block", &xenolinux_block_fops);
    if (result < 0) {
	printk (KERN_ALERT "xenolinux block: can't get major %d\n",
		xlblk_major);
	return result;
    }

    /* initialize global arrays in drivers/block/ll_rw_block.c */
    for (loop = 0; loop < XLBLK_MAX; loop++) {
	xlblk_blk_size[loop]      = xen_disk_info.disks[0].capacity;
	xlblk_blksize_size[loop]  = 512;
	xlblk_hardsect_size[loop] = 512;
	xlblk_max_sectors[loop]   = 128;
    }
    xlblk_read_ahead  = 8; 

    blk_size[xlblk_major]      = xlblk_blk_size;
    blksize_size[xlblk_major]  = xlblk_blksize_size;
    hardsect_size[xlblk_major] = xlblk_hardsect_size;
    read_ahead[xlblk_major]    = xlblk_read_ahead; 
    max_sectors[xlblk_major]   = xlblk_max_sectors;

    blk_init_queue(BLK_DEFAULT_QUEUE(xlblk_major), do_xlblk_request);
    /* 
    ** XXX SMH: we don't leave req on queue => are happy for evelator
    ** to reorder things including it. (main reason for this decision
    ** is that it works while 'standard' case doesn't. Ho hum). 
    */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(xlblk_major), 0);

    xlblk_ide_register_disk(0, xen_disk_info.disks[0].capacity);

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

    xen_disk_info.disks[idx].gendisk = gd;

    /* default disk size is just a big number.  in the future, we
       need a message to probe the devices to determine the actual size */
    register_disk(gd, MKDEV(xlblk_major, 0), 1<<IDE_PARTN_BITS,
		  &xenolinux_block_fops, capacity);

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
