/******************************************************************************
 * xl_ide.c
 * 
 * Xenolinux virtual IDE block-device driver.
 */

#include "xl_block.h"
#include <linux/blk.h>

#define XLIDE_MAX         256
#define XLIDE_MAJOR_NAME "hd"
static int xlide_blksize_size[XLIDE_MAX];
static int xlide_hardsect_size[XLIDE_MAX];
static int xlide_max_sectors[XLIDE_MAX];

#define XLIDE_NR_MAJORS     2

struct gendisk *xlide_gendisk[XLIDE_NR_MAJORS] = { NULL };

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

static int get_major(int major)
{
    int r = register_blkdev(major, XLIDE_MAJOR_NAME, &xlide_block_fops);
    if ( r < 0 )
        printk (KERN_ALERT "XL IDE: can't get major %d\n", XLIDE_MAJOR_0);
    return r;
}

static void setup_major(struct gendisk **pgd, 
                        xen_disk_info_t *xdi, int base, int major)
{
    int i, minors, disk, units = XLIDE_DEVS_PER_MAJOR;
    unsigned short minor; 
    unsigned char buf[64];
    struct gendisk *gd;

    blk_size[major]      = NULL;
    blksize_size[major]  = xlide_blksize_size + base*(1<<XLIDE_PARTN_SHIFT);
    hardsect_size[major] = xlide_hardsect_size + base*(1<<XLIDE_PARTN_SHIFT);
    max_sectors[major]   = xlide_max_sectors + base*(1<<XLIDE_PARTN_SHIFT);
    read_ahead[major]    = 8;

    blk_init_queue(BLK_DEFAULT_QUEUE(major), do_xlblk_request);

    /*
     * Turn off barking 'headactive' mode. We dequeue buffer heads as soon as 
     * we pass them down to Xen.
     */
    blk_queue_headactive(BLK_DEFAULT_QUEUE(major), 0);

    /* Construct an appropriate gendisk structure. */
    minors    = units * (1<<XLIDE_PARTN_SHIFT);
    gd        = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
    gd->sizes = kmalloc(minors * sizeof(int), GFP_KERNEL);
    gd->part  = kmalloc(minors * sizeof(struct hd_struct), GFP_KERNEL);
    gd->major        = major;
    gd->major_name   = XLIDE_MAJOR_NAME;
    gd->minor_shift  = XLIDE_PARTN_SHIFT; 
    gd->max_p	     = 1<<XLIDE_PARTN_SHIFT;
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
    *pgd = gd;
    add_gendisk(gd);
    
    /* Now register each disk in turn. */
    for ( i = 0; i < xdi->count; i++ )
    {
        disk  = xdi->disks[i].device & XENDEV_IDX_MASK;
        minor = (disk-base) << XLIDE_PARTN_SHIFT; 

        if ( !IS_IDE_XENDEV(xdi->disks[i].device) ||
             (disk < base) || (disk >= (base + XLIDE_DEVS_PER_MAJOR)) ) 
            continue;

        ((xl_disk_t *)gd->real_devices)[disk-base].capacity =
            xdi->disks[i].capacity;

        switch (xdi->disks[i].type) 
        { 
        case XD_TYPE_CDROM:
            set_device_ro(MKDEV(major, minor), 1); 

        case XD_TYPE_FLOPPY: 
        case XD_TYPE_TAPE:
            gd->flags[disk] = GENHD_FL_REMOVABLE; 
            printk(KERN_ALERT "Skipping partition check on %s /dev/%s\n", 
                   xdi->disks[i].type==XD_TYPE_CDROM ? "cdrom" : 
                   (xdi->disks[i].type==XD_TYPE_TAPE ? "tape" : "floppy"), 
                   disk_name(gd, minor, buf)); 
            break; 

        case XD_TYPE_DISK: 
            register_disk(gd, 
                          MKDEV(major, minor), 
                          1<<XLIDE_PARTN_SHIFT, 
                          &xlide_block_fops, xdi->disks[i].capacity);
            break; 

        default: 
            printk(KERN_ALERT "XenoLinux: unknown ide device type %d\n", 
                   xdi->disks[i].type); 
            break; 
        }
    }

    return;
}


int xlide_init(xen_disk_info_t *xdi) 
{
    int i, units;

    /* If we don't have any usable IDE devices we may as well bail now. */
    units = 0;
    for ( i = 0; i < xdi->count; i++ )
        if ( IS_IDE_XENDEV(xdi->disks[i].device) &&
             ((xdi->disks[i].device & XENDEV_IDX_MASK) <
              (XLIDE_NR_MAJORS*XLIDE_DEVS_PER_MAJOR)) ) 
            units++;
    if ( units == 0 ) return 0;

    SET_MODULE_OWNER(&xlide_block_fops);
    
    if ( get_major(XLIDE_MAJOR_0) < 0 )
        return 0;
    if ( get_major(XLIDE_MAJOR_1) < 0 )
    {
        (void)unregister_blkdev(XLIDE_MAJOR_0, XLIDE_MAJOR_NAME);
        return 0;
    }

    /* Initialize global arrays. */
    for ( i = 0; i < XLIDE_MAX; i++ )
    {
        xlide_blksize_size[i]  = 512;
        xlide_hardsect_size[i] = 512;
        xlide_max_sectors[i]   = 128;
    }

    setup_major(&xlide_gendisk[0], xdi, 0*XLIDE_DEVS_PER_MAJOR, XLIDE_MAJOR_0);
    setup_major(&xlide_gendisk[1], xdi, 1*XLIDE_DEVS_PER_MAJOR, XLIDE_MAJOR_1);

    return 0;
}


static void cleanup_major(int major)
{
    blk_cleanup_queue(BLK_DEFAULT_QUEUE(major));

    read_ahead[major] = 0;

    if ( blksize_size[major] != NULL )
    { 
	kfree(blksize_size[major]);
        blksize_size[major] = NULL;
    }

    if ( hardsect_size[major] != NULL )
    { 
	kfree(hardsect_size[major]);
        hardsect_size[major] = NULL;
    }
    
    if ( max_sectors[major] != NULL )
    { 
	kfree(max_sectors[major]);
        max_sectors[major] = NULL;
    }
    
    (void)unregister_blkdev(major, XLIDE_MAJOR_NAME);
}

void xlide_cleanup(void)
{
    if ( xlide_gendisk[0] == NULL ) return;
    xlide_gendisk[0] = NULL;
    cleanup_major(XLIDE_MAJOR_0);
    cleanup_major(XLIDE_MAJOR_1);
}

