/******************************************************************************
 * xl_scsi.c
 * 
 * Xenolinux virtual SCSI block-device driver.
 * 
 */

#include "xl_block.h"

#define MAJOR_NR XLSCSI_MAJOR
#include <linux/blk.h>

/* We support up to 16 devices of up to 16 partitions each. */
#define XLSCSI_MAX        256
#define XLSCSI_MAJOR_NAME "xsd"
#define SCSI_PARTN_BITS   4
static int xlscsi_blksize_size[XLSCSI_MAX];
static int xlscsi_hardsect_size[XLSCSI_MAX];
static int xlscsi_max_sectors[XLSCSI_MAX];

struct gendisk *xlscsi_gendisk = NULL;

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


int xlscsi_init(xen_disk_info_t *xdi) 
{
    int i, result, units, minors, disk;
    struct gendisk *gd;

    /* If we don't have any usable SCSI devices we may as well bail now. */
    units = 0;
    for ( i = 0; i < xdi->count; i++ )
        if ( IS_SCSI_XENDEV(xdi->disks[i].device) &&
             ((xdi->disks[i].device & XENDEV_IDX_MASK) < 16) ) units++;
    if ( units == 0 ) return 0;

    SET_MODULE_OWNER(&xlscsi_block_fops);

    result = register_blkdev(XLSCSI_MAJOR, XLSCSI_MAJOR_NAME, 
                             &xlscsi_block_fops);
    if ( result < 0 )
    {
	printk (KERN_ALERT "XL SCSI: can't get major %d\n", XLSCSI_MAJOR);
	return result;
    }

    /* Initialize global arrays. */
    for ( i = 0; i < XLSCSI_MAX; i++ )
    {
	xlscsi_blksize_size[i]  = 1024; //XXX 512;
	xlscsi_hardsect_size[i] = 512;
	xlscsi_max_sectors[i]   = 128*8; //XXX 128
    }

    blk_size[XLSCSI_MAJOR]      = NULL;
    blksize_size[XLSCSI_MAJOR]  = xlscsi_blksize_size;
    hardsect_size[XLSCSI_MAJOR] = xlscsi_hardsect_size;
    max_sectors[XLSCSI_MAJOR]   = xlscsi_max_sectors;
    read_ahead[XLSCSI_MAJOR]    = NULL; //XXX8;

    blk_init_queue(BLK_DEFAULT_QUEUE(XLSCSI_MAJOR), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as
     * soon as we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(XLSCSI_MAJOR), 0);

    /* We may register up to 16 devices in a sparse identifier space. */
    units = 16;

    /* Construct an appropriate gendisk structure. */
    minors    = units * (1<<SCSI_PARTN_BITS);
    gd        = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc(minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc(minors * sizeof(struct hd_struct), GFP_KERNEL);
    gd->major        = XLSCSI_MAJOR;
    gd->major_name   = XLSCSI_MAJOR_NAME;
    gd->minor_shift  = SCSI_PARTN_BITS; 
    gd->max_p	     = 1<<SCSI_PARTN_BITS;
    gd->nr_real	     = units;           
    gd->real_devices = kmalloc(units * sizeof(xl_disk_t), GFP_KERNEL);
    gd->next	     = NULL;            
    gd->fops         = &xlscsi_block_fops;
    gd->de_arr       = kmalloc(sizeof(*gd->de_arr) * units, GFP_KERNEL);
    gd->flags	     = kmalloc(sizeof(*gd->flags) * units, GFP_KERNEL);
    memset(gd->sizes, 0, minors * sizeof(int));
    memset(gd->part,  0, minors * sizeof(struct hd_struct));
    memset(gd->de_arr, 0, sizeof(*gd->de_arr) * units);
    memset(gd->flags, 0, sizeof(*gd->flags) * units);
    memset(gd->real_devices, 0, sizeof(xl_disk_t) * units);
    xlscsi_gendisk = gd;
    add_gendisk(gd);

    /* Now register each disk in turn. */
    for ( i = 0; i < xdi->count; i++ )
    {
        disk = xdi->disks[i].device & XENDEV_IDX_MASK;

        /* We can use the first 16 IDE devices. */
        if ( !IS_SCSI_XENDEV(xdi->disks[i].device) || (disk >= 16) ) continue;

        ((xl_disk_t *)gd->real_devices)[disk].capacity =
            xdi->disks[i].capacity;
        register_disk(gd,
                      MKDEV(XLSCSI_MAJOR, disk<<SCSI_PARTN_BITS), 
                      1<<SCSI_PARTN_BITS, 
                      &xlscsi_block_fops, 
                      xdi->disks[i].capacity);
    }
   
    printk(KERN_ALERT 
	   "XenoLinux Virtual SCSI Device Driver installed [device: %d]\n",
	   XLSCSI_MAJOR);

    return 0;
}


void xlscsi_cleanup(void)
{
    if ( xlscsi_gendisk == NULL ) return;

    blk_cleanup_queue(BLK_DEFAULT_QUEUE(XLSCSI_MAJOR));

    xlscsi_gendisk = NULL;

    read_ahead[XLSCSI_MAJOR] = 0;

    if ( blksize_size[XLSCSI_MAJOR] != NULL )
    { 
	kfree(blksize_size[XLSCSI_MAJOR]);
        blksize_size[XLSCSI_MAJOR] = NULL;
    }

    if ( hardsect_size[XLSCSI_MAJOR] != NULL )
    { 
	kfree(hardsect_size[XLSCSI_MAJOR]);
        hardsect_size[XLSCSI_MAJOR] = NULL;
    }
    
    if ( max_sectors[XLSCSI_MAJOR] != NULL )
    { 
	kfree(max_sectors[XLSCSI_MAJOR]);
        max_sectors[XLSCSI_MAJOR] = NULL;
    }
    
    if ( unregister_blkdev(XLSCSI_MAJOR, XLSCSI_MAJOR_NAME) != 0 )
    {
	printk(KERN_ALERT
	       "XenoLinux Virtual SCSI Device Driver uninstalled w/ errs\n");
    }
}

