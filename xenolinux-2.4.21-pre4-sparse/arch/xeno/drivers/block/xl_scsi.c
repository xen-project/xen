/******************************************************************************
 * xl_scsi.c
 * 
 * Xenolinux virtual SCSI block-device driver.
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

#define MAJOR_NR XLSCSI_MAJOR   /* force defns in blk.h, must precede include */
static int xlscsi_major = XLSCSI_MAJOR;
#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char	byte; 

void xlscsi_ide_register_disk(int, unsigned long);

#define SCSI_DISKS_PER_MAJOR 16    /* max number of devices per scsi major */
#define XLSCSI_MAX 32              /* maximum minor devices we support */
#define XLSCSI_MAJOR_NAME "xsd"

static int xlscsi_blk_size[XLSCSI_MAX];
static int xlscsi_blksize_size[XLSCSI_MAX];
static int xlscsi_read_ahead; 
static int xlscsi_hardsect_size[XLSCSI_MAX];
static int xlscsi_max_sectors[XLSCSI_MAX];

#if 0
#define DPRINTK(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#define DPRINTK_IOCTL(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

extern xen_disk_info_t xen_disk_info;

extern int xenolinux_block_open(struct inode *inode, struct file *filep);
extern int xenolinux_block_release(struct inode *inode, struct file *filep);
extern int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
				 unsigned command, unsigned long argument);
extern int xenolinux_block_check(kdev_t dev);
extern int xenolinux_block_revalidate(kdev_t dev);


extern void do_xlblk_request (request_queue_t *rq); 

static struct block_device_operations xlscsi_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};


/* tiny inteface fn */
int xlscsi_hwsect(int minor) 
{
    return xlscsi_hardsect_size[minor]; 
} 


void xlscsi_register_disk(int xidx, int idx)
{
    int minors;
    struct gendisk *gd;
    unsigned long capacity; 

    minors    = XLSCSI_MAX; 
    gd        = kmalloc (sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc (minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc (minors * sizeof(struct hd_struct), GFP_KERNEL);
    memset(gd->part, 0, minors * sizeof(struct hd_struct));
    
    if(idx > 0) 
	printk("xlscsi_register_disk: need fix to handle "
	       "multiple SCSI majors!\n"); 
    
    gd->major        = xlscsi_major;       /* XXX should be idx-specific */
    gd->major_name   = XLSCSI_MAJOR_NAME;  /* XXX should be idx-specific */
    gd->minor_shift  = 4; 
    gd->max_p	     = 1<<4; 
    gd->nr_real	     = SCSI_DISKS_PER_MAJOR; 
    gd->real_devices = NULL;          
    gd->next	     = NULL;            
    gd->fops         = &xlscsi_block_fops;
    gd->de_arr       = kmalloc (sizeof *gd->de_arr * SCSI_DISKS_PER_MAJOR, 
				GFP_KERNEL);
    gd->flags	     = kmalloc (sizeof *gd->flags * SCSI_DISKS_PER_MAJOR, 
				GFP_KERNEL);

    if (gd->de_arr)  
	memset (gd->de_arr, 0, sizeof *gd->de_arr * SCSI_DISKS_PER_MAJOR);

    if (gd->flags) 
	memset (gd->flags, 0, sizeof *gd->flags * SCSI_DISKS_PER_MAJOR);

    add_gendisk(gd);

    xen_disk_info.disks[xidx].gendisk = gd;

    /* XXX major below should be idx-specific */
    register_disk(gd, MKDEV(xlscsi_major, 0), 1<<4, &xlscsi_block_fops, 
		  xen_disk_info.disks[xidx].capacity);

    return;
}


/*
** Initialize a XenoLinux SCSI disk; the 'xidx' is the index into the 
** xen_disk_info array so we can grab interesting values; the 'idx' is 
** a count of the number of XLSCSI disks we've seen so far, starting at 0
** XXX SMH: this is all so ugly because the xen_disk_info() structure and 
** array doesn't really give us what we want. Ho hum. To be tidied someday. 
*/
int xlscsi_init(int xidx, int idx)
{
    int i, major, result;

    SET_MODULE_OWNER(&xlscsi_block_fops);

    major  = xlscsi_major + idx;   /* XXX asume we have linear major space */
    
    /* XXX SMH: 'name' below should vary for different major values */
    result = register_blkdev(major, XLSCSI_MAJOR_NAME, &xlscsi_block_fops);

    if (result < 0) {
	printk (KERN_ALERT "XL SCSI: can't get major %d\n", major);
	return result;
    }

    /* initialize global arrays in drivers/block/ll_rw_block.c */
    for (i = 0; i < XLSCSI_MAX; i++) {
	xlscsi_blk_size[i]      = xen_disk_info.disks[xidx].capacity;
	xlscsi_blksize_size[i]  = 512;
	xlscsi_hardsect_size[i] = 512;
	xlscsi_max_sectors[i]   = 128;
    }
    xlscsi_read_ahead  = 8; 

    blk_size[major]      = xlscsi_blk_size;
    blksize_size[major]  = xlscsi_blksize_size;
    hardsect_size[major] = xlscsi_hardsect_size;
    read_ahead[major]    = xlscsi_read_ahead; 
    max_sectors[major]   = xlscsi_max_sectors;

    blk_init_queue(BLK_DEFAULT_QUEUE(major), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(major), 0);
    
    xlscsi_register_disk(xidx, idx);

    printk(KERN_ALERT 
	   "XenoLinux Virtual SCSI Device Driver installed [device: %d]\n",
	   major);
    return 0;
}



void xlscsi_cleanup(void)
{
    /* CHANGE FOR MULTIQUEUE */
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(xlscsi_major));

    /* clean up global arrays */
    read_ahead[xlscsi_major] = 0;

    if (blk_size[xlscsi_major]) 
	kfree(blk_size[xlscsi_major]);
    blk_size[xlscsi_major] = NULL;

    if (blksize_size[xlscsi_major]) 
	kfree(blksize_size[xlscsi_major]);
    blksize_size[xlscsi_major] = NULL;

    if (hardsect_size[xlscsi_major]) 
	kfree(hardsect_size[xlscsi_major]);
    hardsect_size[xlscsi_major] = NULL;
    
    /* XXX: free each gendisk */
    if (unregister_blkdev(xlscsi_major, XLSCSI_MAJOR_NAME))
	printk(KERN_ALERT
	       "XenoLinux Virtual SCSI Device Driver uninstalled w/ errs\n");
    else
	printk(KERN_ALERT 
	       "XenoLinux Virtual SCSI Device Driver uninstalled\n");

    return;
}

