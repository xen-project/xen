/******************************************************************************
 * xl_ide.c
 * 
 * Xenolinux virtual IDE block-device driver.
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

#define MAJOR_NR XLIDE_MAJOR   /* force defns in blk.h, must precede include */
static int xlide_major = XLIDE_MAJOR;
#include <linux/blk.h>

void xlide_ide_register_disk(int, unsigned long);

#define XLIDE_MAX 32 /* Maximum minor devices we support */
#define XLIDE_MAJOR_NAME "xhd"
#define IDE_PARTN_BITS 6                           /* from ide.h::PARTN_BITS */
#define IDE_PARTN_MASK ((1<<IDE_PARTN_BITS)-1)     /* from ide.h::PARTN_MASK */
static int xlide_blk_size[XLIDE_MAX];
static int xlide_blksize_size[XLIDE_MAX];
static int xlide_read_ahead; 
static int xlide_hardsect_size[XLIDE_MAX];
static int xlide_max_sectors[XLIDE_MAX];

extern xen_disk_info_t xen_disk_info;


extern int xenolinux_block_open(struct inode *inode, struct file *filep);
extern int xenolinux_block_release(struct inode *inode, struct file *filep);
extern int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
				 unsigned command, unsigned long argument);
extern int xenolinux_block_check(kdev_t dev);
extern int xenolinux_block_revalidate(kdev_t dev);


extern void do_xlblk_request (request_queue_t *rq); 


static struct block_device_operations xlide_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};


/* tiny inteface fn */
int xlide_hwsect(int minor) 
{
    return xlide_hardsect_size[minor]; 
} 


void xlide_register_disk(int xidx, int idx)
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
    
    gd->major        = xlide_major;         /* XXX should be idx-specific */
    gd->major_name   = XLIDE_MAJOR_NAME;    /* XXX should be idx-specific */
    gd->minor_shift  = IDE_PARTN_BITS; 
    gd->max_p	     = 1<<IDE_PARTN_BITS;
    gd->nr_real	     = units;           
    gd->real_devices = NULL;          
    gd->next	     = NULL;            
    gd->fops         = &xlide_block_fops;
    gd->de_arr       = kmalloc (sizeof *gd->de_arr * units, GFP_KERNEL);
    gd->flags	     = kmalloc (sizeof *gd->flags * units, GFP_KERNEL);

    if (gd->de_arr)  
	memset (gd->de_arr, 0, sizeof *gd->de_arr * units);

    if (gd->flags) 
	memset (gd->flags, 0, sizeof *gd->flags * units);

    add_gendisk(gd);

    xen_disk_info.disks[xidx].gendisk = gd;

    /* XXX major should be idx-specific */
    register_disk(gd, MKDEV(xlide_major, 0), 1<<IDE_PARTN_BITS, 
		  &xlide_block_fops, xen_disk_info.disks[xidx].capacity);

    return;
}



/*
** Initialize a XenoLinux IDE disk; the 'xidx' is the index into the 
** xen_disk_info array so we can grab interesting values; the 'idx' is 
** a count of the number of XLSCSI disks we've seen so far, starting at 0
** XXX SMH: this is all so ugly because the xen_disk_info() structure and 
** array doesn't really give us what we want. Ho hum. To be tidied someday. 
*/
int xlide_init(int xidx, int idx) 
{
    int i, major, result;

    SET_MODULE_OWNER(&xlide_block_fops);

    major  = xlide_major + idx;  /* XXX assume we have a linear major space */

    /* XXX SMH: name below should vary with major */
    result = register_blkdev(major, XLIDE_MAJOR_NAME, &xlide_block_fops);
    if (result < 0) {
	printk (KERN_ALERT "XL IDE: can't get major %d\n",
		major);
	return result;
    }

    /* initialize global arrays in drivers/block/ll_rw_block.c */
    for (i = 0; i < XLIDE_MAX; i++) {
	xlide_blk_size[i]      = xen_disk_info.disks[0].capacity;
	xlide_blksize_size[i]  = 512;
	xlide_hardsect_size[i] = 512;
	xlide_max_sectors[i]   = 128;
    }
    xlide_read_ahead  = 8; 

    blk_size[major]      = xlide_blk_size;
    blksize_size[major]  = xlide_blksize_size;
    hardsect_size[major] = xlide_hardsect_size;
    read_ahead[major]    = xlide_read_ahead; 
    max_sectors[major]   = xlide_max_sectors;

    blk_init_queue(BLK_DEFAULT_QUEUE(major), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(major), 0);

    xlide_register_disk(xidx, idx); 

    printk(KERN_ALERT 
	   "XenoLinux Virtual IDE Device Driver installed [device: %d]\n",
	   major);

    return 0;
}


void xlide_cleanup(void)
{
    /* CHANGE FOR MULTIQUEUE */
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(xlide_major));

    /* clean up global arrays */
    read_ahead[xlide_major] = 0;

    if (blk_size[xlide_major]) 
	kfree(blk_size[xlide_major]);
    blk_size[xlide_major] = NULL;

    if (blksize_size[xlide_major]) 
	kfree(blksize_size[xlide_major]);
    blksize_size[xlide_major] = NULL;

    if (hardsect_size[xlide_major]) 
	kfree(hardsect_size[xlide_major]);
    hardsect_size[xlide_major] = NULL;
    
    /* XXX: free each gendisk */
    if (unregister_blkdev(xlide_major, XLIDE_MAJOR_NAME))
	printk(KERN_ALERT
	       "XenoLinux Virtual IDE Device Driver uninstalled w/ errs\n");
    else
	printk(KERN_ALERT 
	       "XenoLinux Virtual IDE Device Driver uninstalled\n");

    return;
}

