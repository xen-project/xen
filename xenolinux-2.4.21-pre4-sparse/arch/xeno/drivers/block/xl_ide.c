/******************************************************************************
 * xl_ide.c
 * 
 * Xenolinux virtual IDE block-device driver.
 * 
 */

#include "xl_block.h"

#define MAJOR_NR XLIDE_MAJOR 
#include <linux/blk.h>

/* We support up to 16 devices of up to 16 partitions each. */
#define XLIDE_MAX         256
#define XLIDE_MAJOR_NAME "xhd"
#define IDE_PARTN_BITS    4
static int xlide_blksize_size[XLIDE_MAX];
static int xlide_hardsect_size[XLIDE_MAX];
static int xlide_max_sectors[XLIDE_MAX];

struct gendisk *xlide_gendisk = NULL;

static struct block_device_operations xlide_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};


int xlide_hwsect(int minor) 
{
    return xlide_hardsect_size[minor]; 
} 


int xlide_init(xen_disk_info_t *xdi) 
{
    int i, result, units, minors, disk;
    struct gendisk *gd;

    /* If we don't have any usable IDE devices we may as well bail now. */
    units = 0;
    for ( i = 0; i < xdi->count; i++ )
        if ( IS_IDE_XENDEV(xdi->disks[i].device) &&
             ((xdi->disks[i].device & XENDEV_IDX_MASK) < 16) ) units++;
    if ( units == 0 ) return 0;

    SET_MODULE_OWNER(&xlide_block_fops);

    result = register_blkdev(XLIDE_MAJOR, XLIDE_MAJOR_NAME, 
                             &xlide_block_fops);
    if ( result < 0 )
    {
	printk (KERN_ALERT "XL IDE: can't get major %d\n", XLIDE_MAJOR);
	return result;
    }

    /* Initialize global arrays. */
    for ( i = 0; i < XLIDE_MAX; i++ )
    {
	xlide_blksize_size[i]  = 512;
	xlide_hardsect_size[i] = 512;
	xlide_max_sectors[i]   = 128;
    }

    blk_size[XLIDE_MAJOR]      = NULL;
    blksize_size[XLIDE_MAJOR]  = xlide_blksize_size;
    hardsect_size[XLIDE_MAJOR] = xlide_hardsect_size;
    max_sectors[XLIDE_MAJOR]   = xlide_max_sectors;
    read_ahead[XLIDE_MAJOR]    = 8;

    blk_init_queue(BLK_DEFAULT_QUEUE(XLIDE_MAJOR), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(XLIDE_MAJOR), 0);

    /* We may register up to 16 devices in a sparse identifier space. */
    units = 16;

    /* Construct an appropriate gendisk structure. */
    minors    = units * (1<<IDE_PARTN_BITS);
    gd        = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc(minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc(minors * sizeof(struct hd_struct), GFP_KERNEL);
    gd->major        = XLIDE_MAJOR;
    gd->major_name   = XLIDE_MAJOR_NAME;
    gd->minor_shift  = IDE_PARTN_BITS; 
    gd->max_p	     = 1<<IDE_PARTN_BITS;
    gd->nr_real	     = units;           
    gd->real_devices = kmalloc(units * sizeof(xl_disk_t), GFP_KERNEL);
    gd->next	     = NULL;            
    gd->fops         = &xlide_block_fops;
    gd->de_arr       = kmalloc(sizeof(*gd->de_arr) * units, GFP_KERNEL);
    gd->flags	     = kmalloc(sizeof(*gd->flags) * units, GFP_KERNEL);
    memset(gd->sizes, 0, minors * sizeof(int));
    memset(gd->part,  0, minors * sizeof(struct hd_struct));
    memset(gd->de_arr, 0, sizeof(*gd->de_arr) * units);
    memset(gd->flags, 0, sizeof(*gd->flags) * units);
    memset(gd->real_devices, 0, sizeof(xl_disk_t) * units);
    xlide_gendisk = gd;
    add_gendisk(gd);
    
    /* Now register each disk in turn. */
    for ( i = 0; i < xdi->count; i++ )
    {
        disk = xdi->disks[i].device & XENDEV_IDX_MASK;

        /* We can use the first 16 IDE devices. */
        if ( !IS_IDE_XENDEV(xdi->disks[i].device) || (disk >= 16) ) continue;

        ((xl_disk_t *)gd->real_devices)[disk].capacity =
            xdi->disks[i].capacity;
        register_disk(gd, 
                      MKDEV(XLIDE_MAJOR, disk<<IDE_PARTN_BITS), 
                      1<<IDE_PARTN_BITS, 
                      &xlide_block_fops, 
                      xdi->disks[i].capacity);
    }

    printk(KERN_ALERT 
	   "XenoLinux Virtual IDE Device Driver installed [device: %d]\n",
	   XLIDE_MAJOR);

    return 0;
}


void xlide_cleanup(void)
{
    if ( xlide_gendisk == NULL ) return;

    blk_cleanup_queue(BLK_DEFAULT_QUEUE(XLIDE_MAJOR));

    xlide_gendisk = NULL;

    read_ahead[XLIDE_MAJOR] = 0;

    if ( blksize_size[XLIDE_MAJOR] != NULL )
    { 
	kfree(blksize_size[XLIDE_MAJOR]);
        blksize_size[XLIDE_MAJOR] = NULL;
    }

    if ( hardsect_size[XLIDE_MAJOR] != NULL )
    { 
	kfree(hardsect_size[XLIDE_MAJOR]);
        hardsect_size[XLIDE_MAJOR] = NULL;
    }
    
    if ( max_sectors[XLIDE_MAJOR] != NULL )
    { 
	kfree(max_sectors[XLIDE_MAJOR]);
        max_sectors[XLIDE_MAJOR] = NULL;
    }
    
    if ( unregister_blkdev(XLIDE_MAJOR, XLIDE_MAJOR_NAME) != 0 )
    {
	printk(KERN_ALERT
	       "XenoLinux Virtual IDE Device Driver uninstalled w/ errs\n");
    }
}

