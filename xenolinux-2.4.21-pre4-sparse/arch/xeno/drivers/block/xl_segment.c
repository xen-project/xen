/******************************************************************************
 * xl_segment.c
 * 
 * Xenolinux virtual block-device driver (vhd).
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

#define MAJOR_NR XLSEG_MAJOR   /* force defns in blk.h, must precede include */
static int xlseg_major = XLSEG_MAJOR;
#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char	byte; 

#define XLSEG_MAX 32 /* Maximum minor devices we support */
#define XLSEG_MAJOR_NAME "xhd"

static int xlseg_blk_size[XLSEG_MAX];
static int xlseg_blksize_size[XLSEG_MAX];
static int xlseg_read_ahead; 
static int xlseg_hardsect_size[XLSEG_MAX];
static int xlseg_max_sectors[XLSEG_MAX];

extern atomic_t xlblk_control_count;                           /* xl_block.c */

int hypervisor_request(void *          id,
                       int             operation,
                       char *          buffer,
                       unsigned long   block_number,
                       unsigned short  block_size,
                       kdev_t          device,
		       struct gendisk *gd);
void xlseg_register_disk(int idx, unsigned long capacity);

#if 0
#define DPRINTK(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#define DPRINTK_IOCTL(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

static xen_disk_info_t xlseg_disk_info;

/* ------------------------------------------------------------------------
 */

static int xenolinux_segment_open(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_segment_release\n");
    return 0;
}

static int xenolinux_segment_release(struct inode *inode, struct file *filep)
{
    DPRINTK("xenolinux_segment_release\n");
    return 0;
}

static int xenolinux_segment_ioctl(struct inode *inode, struct file *filep,
				   unsigned command, unsigned long argument)
{
    int minor_dev;
    struct hd_geometry *geo = (struct hd_geometry *)argument;
    struct gendisk *gd = (struct gendisk *)xlseg_disk_info.disks[0].gendisk;

    DPRINTK("xenolinux_segment_ioctl\n"); 

    /* check permissions */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!inode)                  return -EINVAL;
    minor_dev = MINOR(inode->i_rdev);
    if (minor_dev >= XLSEG_MAX)  return -ENODEV;
    
    DPRINTK_IOCTL("command: 0x%x, argument: 0x%lx, minor: 0x%x\n",
                  command, (long) argument, minor_dev); 
  
    switch (command)
    {
      case BLKGETSIZE:
	if (gd != NULL)
	{
	  printk(KERN_ALERT "minordev: %d\n", minor_dev);
	  printk(KERN_ALERT "[0] start: %lx\n", gd->part[0].start_sect);
	  printk(KERN_ALERT "[0] count: %lx\n", gd->part[0].nr_sects);
	  printk(KERN_ALERT "[1] start: %lx\n", gd->part[1].start_sect);
	  printk(KERN_ALERT "[1] count: %lx\n", gd->part[1].nr_sects);
	  printk(KERN_ALERT "[2] start: %lx\n", gd->part[2].start_sect);
	  printk(KERN_ALERT "[2] count: %lx\n", gd->part[2].nr_sects);
	  
	  DPRINTK_IOCTL("   BLKGETSIZE gd: %x %lx\n", BLKGETSIZE, 
			gd->part[minor_dev].nr_sects);
	  return put_user(gd->part[minor_dev].nr_sects,
			  (unsigned long *)argument);
	}
	else
	{
	  DPRINTK_IOCTL("   BLKGETSIZE disk: %x %lx\n", BLKGETSIZE, 
			xlseg_disk_info.disks[0].capacity);
	  return put_user(xlseg_disk_info.disks[0].capacity,
			  (unsigned long *) argument);
	}
		      
      case BLKRRPART:
        DPRINTK_IOCTL("   BLKRRPART: \n"); 
	/* we don't have re-validate drive yet...  so you need to reboot! */
	break;

      case BLKSSZGET:
        DPRINTK_IOCTL("   BLKSSZGET: %d\n",
		      xlseg_hardsect_size[minor_dev]);
	return xlseg_hardsect_size[minor_dev]; 

      case HDIO_GETGEO:
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO: \n");
	if (!argument) return -EINVAL;
	if (put_user(0x00,  (unsigned long *) &geo->start)) return -EFAULT;
	if (put_user(0xff,  (byte *)&geo->heads)) return -EFAULT;
	if (put_user(0x3f,  (byte *)&geo->sectors)) return -EFAULT;
	if (put_user(0x106, (unsigned short *)&geo->cylinders)) return -EFAULT;
	return 0;

      case HDIO_GETGEO_BIG: 
        /* note: these values are complete garbage */
        DPRINTK_IOCTL("   HDIO_GETGEO_BIG\n");
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

static int xenolinux_segment_check(kdev_t dev)
{
    DPRINTK("xenolinux_segment_check\n");
    return 0;
}

static int xenolinux_segment_revalidate(kdev_t dev)
{
    DPRINTK("xenolinux_segment_revalidate\n"); 
    return 0;
}

void do_xlseg_requestX (request_queue_t *rq)
{
  /* this is a bit dumb.  do_xlseg_request is defined in blk.h
     and this is thus static. but we have cooperative
     device drivers... */
  do_xlseg_request(rq);
}

/*
 * do_xlseg_request
 * read a block; request is in a request queue
 */
static void do_xlseg_request (request_queue_t *rq)
{
    struct request *req;
    struct buffer_head *bh;
    int rw, nsect, full, queued = 0;
    
    /*     DPRINTK("do_xlseg_request for '%s'\n", DEVICE_NAME); */

    while ( !rq->plugged && !QUEUE_EMPTY )
    {
	if ( (req = CURRENT) == NULL ) goto out;
		
        DPRINTK("do_xlseg_request %p: cmd %i, sec %lx, (%li/%li) bh:%p\n",
                req, req->cmd, req->sector,
                req->current_nr_sectors, req->nr_sectors, req->bh);

        rw = req->cmd;
        if ( rw == READA ) rw = READ;
        if ((rw != READ) && (rw != WRITE))
            panic("XenoLinux Virtual Segment Device: bad cmd: %d\n", rw);

	req->errors = 0;

        bh = req->bh;
        while ( bh != NULL )
	{
            full = hypervisor_request(
                bh, (rw == READ) ? XEN_BLOCK_READ : XEN_BLOCK_WRITE, 
                bh->b_data, bh->b_rsector, bh->b_size, bh->b_dev,
		(struct gendisk *)xlseg_disk_info.disks[0].gendisk);
            
            if ( full ) 
	    {
	      goto out;
	    }

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
                if ( end_that_request_first(req, 1, "XenSeg") ) BUG();
                blkdev_dequeue_request(req);
                end_that_request_last(req);
            }
        }
    }

 out:
    if ( queued != 0 ) HYPERVISOR_block_io_op();
}


static struct block_device_operations xenolinux_segment_fops = 
{
    open:               xenolinux_segment_open,
    release:            xenolinux_segment_release,
    ioctl:              xenolinux_segment_ioctl,
    check_media_change: xenolinux_segment_check,
    revalidate:         xenolinux_segment_revalidate,
};


int __init xlseg_init(void)
{
    int i, result;
    int counter;

    /* probe for disk information */
    memset (&xlseg_disk_info, 0, sizeof(xlseg_disk_info));
    xlseg_disk_info.count = 0;


    {
      /* get lock xlblk_control_lock     */
      counter = atomic_read(&xlblk_control_count);
      atomic_inc(&xlblk_control_count);
      /* release lock xlblk_control_lock */
    }
    if ( hypervisor_request(NULL, XEN_BLOCK_PROBE_SEG, 
			    (char *) &xlseg_disk_info,
                            0, 0, (kdev_t) 0,
			    (struct gendisk *)NULL) )
        BUG();
    HYPERVISOR_block_io_op();
    while (atomic_read(&xlblk_control_count) != counter) barrier();

    printk (KERN_ALERT "vhd block device probe:\n");
    for ( i = 0; i < xlseg_disk_info.count; i++ )
    { 
	printk (KERN_ALERT "  %2d: type: %d, capacity: %ld\n",
		i, xlseg_disk_info.disks[i].type, 
		xlseg_disk_info.disks[i].capacity);
    }

    SET_MODULE_OWNER(&xenolinux_segment_fops);
    result = register_blkdev(xlseg_major, "segment", &xenolinux_segment_fops);
    if (result < 0) {
	printk (KERN_ALERT "xenolinux segment: can't get major %d\n",
		xlseg_major);
	return result;
    }

    /* initialize global arrays in drivers/block/ll_rw_block.c */
    for (i = 0; i < XLSEG_MAX; i++) 
    {
      xlseg_blk_size[i]      = xlseg_disk_info.disks[0].capacity ;
      xlseg_blksize_size[i]  = 512;
      xlseg_hardsect_size[i] = 512;
      xlseg_max_sectors[i]   = 128;
    }
    xlseg_read_ahead  = 8; 

    blk_size[xlseg_major]      = xlseg_blk_size;
    blksize_size[xlseg_major]  = xlseg_blksize_size;
    hardsect_size[xlseg_major] = xlseg_hardsect_size;
    read_ahead[xlseg_major]    = xlseg_read_ahead; 
    max_sectors[xlseg_major]   = xlseg_max_sectors;

    blk_init_queue(BLK_DEFAULT_QUEUE(xlseg_major), do_xlseg_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(xlseg_major), 0);

    xlseg_register_disk(0, xlseg_disk_info.disks[0].capacity);

    printk(KERN_ALERT 
	   "XenoLinux Virtual Segment Device Driver installed [device: %d]\n",
	   xlseg_major);
    return 0;
}

void xlseg_register_disk(int idx, unsigned long capacity)
{
    int units;
    int minors;
    struct gendisk *gd;

    /* plagarized from ide-probe.c::init_gendisk */
    
    units = 2; /* from ide.h::MAX_DRIVES */

#define IDE_PARTN_BITS 6                           /* from ide.h::PARTN_BITS */

    minors    = units * (1<<IDE_PARTN_BITS);
    gd        = kmalloc (sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc (minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc (minors * sizeof(struct hd_struct), GFP_KERNEL);
    memset(gd->part, 0, minors * sizeof(struct hd_struct));
    
    gd->major        = xlseg_major;  
    gd->major_name   = XLSEG_MAJOR_NAME;
    gd->minor_shift  = IDE_PARTN_BITS; 
    gd->max_p	     = 1<<IDE_PARTN_BITS;
    gd->nr_real	     = units;           
    gd->real_devices = NULL;          
    gd->next	     = NULL;            
    gd->fops         = &xenolinux_segment_fops;
    gd->de_arr       = kmalloc (sizeof *gd->de_arr * units, GFP_KERNEL);
    gd->flags	     = kmalloc (sizeof *gd->flags * units, GFP_KERNEL);

    if (gd->de_arr)  
	memset (gd->de_arr, 0, sizeof *gd->de_arr * units);

    if (gd->flags) 
	memset (gd->flags, 0, sizeof *gd->flags * units);

    add_gendisk(gd);

    xlseg_disk_info.disks[idx].gendisk = gd;

    register_disk(gd, MKDEV(xlseg_major, 0), 1<<IDE_PARTN_BITS,
		  &xenolinux_segment_fops, capacity);

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


static void __exit xlseg_cleanup(void)
{
    /* CHANGE FOR MULTIQUEUE */
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(xlseg_major));

    /* clean up global arrays */
    read_ahead[xlseg_major] = 0;

    if (blk_size[xlseg_major]) 
	kfree(blk_size[xlseg_major]);
    blk_size[xlseg_major] = NULL;

    if (blksize_size[xlseg_major]) 
	kfree(blksize_size[xlseg_major]);
    blksize_size[xlseg_major] = NULL;

    if (hardsect_size[xlseg_major]) 
	kfree(hardsect_size[xlseg_major]);
    hardsect_size[xlseg_major] = NULL;
    
    /* XXX: free each gendisk */
    if (unregister_blkdev(xlseg_major, "block"))
	printk(KERN_ALERT
	       "XenoLinux Virtual Segment Device Driver uninstalled w/ errs\n");
    else
	printk(KERN_ALERT 
	       "XenoLinux Virtual Segment Device Driver uninstalled\n");

    return;
}


#ifdef MODULE
module_init(xlseg_init);
module_exit(xlseg_cleanup);
#endif
