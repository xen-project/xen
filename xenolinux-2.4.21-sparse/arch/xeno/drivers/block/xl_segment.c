/******************************************************************************
 * xl_segment.c
 * 
 * Xenolinux virtual block-device driver (xvd).
 * 
 */

#include "xl_block.h"

#define MAJOR_NR XLVIRT_MAJOR
#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char byte; 

#define XLVIRT_MAX        256
#define XLVIRT_MAJOR_NAME "xvd"
static int xlseg_blksize_size[XLVIRT_MAX];
static int xlseg_hardsect_size[XLVIRT_MAX];
static int xlseg_max_sectors[XLVIRT_MAX];

struct gendisk *xlsegment_gendisk = NULL;

static xen_disk_info_t xlseg_disk_info;

static struct block_device_operations xlsegment_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};


int xlsegment_hwsect(int minor) 
{
    return xlseg_hardsect_size[minor]; 
} 


int __init xlseg_init(void)
{
    int i, result, units, minors, disk;
    xen_disk_info_t *xdi = &xlseg_disk_info;
    struct gendisk *gd;

    SET_MODULE_OWNER(&xlsegment_block_fops);

    /* Probe for disk information. */
    memset(xdi, 0, sizeof(*xdi));
    xenolinux_control_msg(XEN_BLOCK_PROBE_SEG, (char *)xdi, sizeof(*xdi));

    DPRINTK("xvd block device probe:\n");
    for ( i = 0; i < xdi->count; i++ )
    { 
	DPRINTK("  %2d: device: %d, capacity: %ld\n",
		i, xdi->disks[i].device, xdi->disks[i].capacity);
    }

    result = register_blkdev(XLVIRT_MAJOR, XLVIRT_MAJOR_NAME,
                             &xlsegment_block_fops);
    if ( result < 0 )
    {
	printk(KERN_ALERT "XL Segment: can't get major %d\n", XLVIRT_MAJOR);
	return result;
    }

    /* Initialize global arrays. */
    for (i = 0; i < XLVIRT_MAX; i++) 
    {
        xlseg_blksize_size[i]  = 512;
        xlseg_hardsect_size[i] = 512;
        xlseg_max_sectors[i]   = 128;
    }

    blk_size[XLVIRT_MAJOR]      = NULL;
    blksize_size[XLVIRT_MAJOR]  = xlseg_blksize_size;
    hardsect_size[XLVIRT_MAJOR] = xlseg_hardsect_size;
    max_sectors[XLVIRT_MAJOR]   = xlseg_max_sectors;
    read_ahead[XLVIRT_MAJOR]    = 8;

    blk_init_queue(BLK_DEFAULT_QUEUE(XLVIRT_MAJOR), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(XLVIRT_MAJOR), 0);

    units = XLVIRT_MAX >> XLVIRT_PARTN_SHIFT;

    /* Construct an appropriate gendisk structure. */
    minors    = units * (1<<XLVIRT_PARTN_SHIFT);
    gd        = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc(minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc(minors * sizeof(struct hd_struct), GFP_KERNEL);
    gd->major        = XLVIRT_MAJOR;
    gd->major_name   = XLVIRT_MAJOR_NAME;
    gd->minor_shift  = XLVIRT_PARTN_SHIFT; 
    gd->max_p	     = 1<<XLVIRT_PARTN_SHIFT;
    gd->nr_real	     = units;           
    gd->real_devices = kmalloc(units * sizeof(xl_disk_t), GFP_KERNEL);
    gd->next	     = NULL;            
    gd->fops         = &xlsegment_block_fops;
    gd->de_arr       = kmalloc(sizeof(*gd->de_arr) * units, GFP_KERNEL);
    gd->flags	     = kmalloc(sizeof(*gd->flags) * units, GFP_KERNEL);
    memset(gd->sizes, 0, minors * sizeof(int));
    memset(gd->part,  0, minors * sizeof(struct hd_struct));
    memset(gd->de_arr, 0, sizeof(*gd->de_arr) * units);
    memset(gd->flags, 0, sizeof(*gd->flags) * units);
    memset(gd->real_devices, 0, sizeof(xl_disk_t) * units);
    xlsegment_gendisk = gd;
    add_gendisk(gd);

    /* Now register each disk in turn. */
    for ( i = 0; i < xdi->count; i++ )
    {
        disk = xdi->disks[i].device & XENDEV_IDX_MASK;

        if ( !IS_VIRTUAL_XENDEV(xdi->disks[i].device) || 
             (disk >= XLVIRT_DEVS_PER_MAJOR) )
            continue;

        ((xl_disk_t *)gd->real_devices)[disk].capacity =
            xdi->disks[i].capacity;
        register_disk(gd, 
                      MKDEV(XLVIRT_MAJOR, disk<<XLVIRT_PARTN_SHIFT), 
                      1<<XLVIRT_PARTN_SHIFT, 
                      &xlsegment_block_fops, 
                      xdi->disks[i].capacity);
    }

    printk(KERN_ALERT 
	   "XenoLinux Virtual Segment Device Driver installed [device: %d]\n",
	   XLVIRT_MAJOR);

    return 0;
}


static void __exit xlseg_cleanup(void)
{
    if ( xlsegment_gendisk == NULL ) return;

    blk_cleanup_queue(BLK_DEFAULT_QUEUE(XLVIRT_MAJOR));

    xlsegment_gendisk = NULL;

    read_ahead[XLVIRT_MAJOR] = 0;

    if ( blksize_size[XLVIRT_MAJOR] != NULL )
    { 
	kfree(blksize_size[XLVIRT_MAJOR]);
        blksize_size[XLVIRT_MAJOR] = NULL;
    }

    if ( hardsect_size[XLVIRT_MAJOR] != NULL )
    { 
	kfree(hardsect_size[XLVIRT_MAJOR]);
        hardsect_size[XLVIRT_MAJOR] = NULL;
    }
    
    if ( max_sectors[XLVIRT_MAJOR] != NULL )
    { 
	kfree(max_sectors[XLVIRT_MAJOR]);
        max_sectors[XLVIRT_MAJOR] = NULL;
    }
    
    if ( unregister_blkdev(XLVIRT_MAJOR, XLVIRT_MAJOR_NAME) != 0 )
    {
	printk(KERN_ALERT
	       "XenoLinux Virtual Segment Device Driver"
               " uninstalled w/ errs\n");
    }
}


#ifdef MODULE
module_init(xlseg_init);
module_exit(xlseg_cleanup);
#endif
