/******************************************************************************
 * xl_vbd.c
 * 
 * Xenolinux virtual block-device driver (xvd).
 * 
 */

#include "xl_block.h"

// #define MAJOR_NR XLVIRT_MAJOR
#include <linux/blk.h>

/* Copied from linux/ide.h */
typedef unsigned char byte; 

#define XLVBD_MAX_MAJORS  64  /* total number of vbds we support */

struct gendisk *xlvbd_gendisk[XLVBD_MAX_MAJORS] = { NULL };

/* For convenience we distinguish between ide, scsi and 'other' (i.e. 
** potentially combinations of the two) in the naming scheme and in a 
** few other places (like default readahead, etc). 
*/
#define XLIDE_MAJOR_NAME  "hd"
#define XLSCSI_MAJOR_NAME "sd"
#define XLVBD_MAJOR_NAME "xvd"

#define XLIDE_DEVS_PER_MAJOR   2
#define XLSCSI_DEVS_PER_MAJOR 16
#define XLVBD_DEVS_PER_MAJOR  16


#define XLIDE_PARTN_SHIFT  6    /* amount to shift minor to get 'real' minor */
#define XLIDE_MAX_PART    (1 << XLIDE_PARTN_SHIFT)     /* minors per ide vbd */

#define XLSCSI_PARTN_SHIFT 4    /* amount to shift minor to get 'real' minor */
#define XLSCSI_MAX_PART   (1 << XLSCSI_PARTN_SHIFT)   /* minors per scsi vbd */

#define XLVBD_PARTN_SHIFT  6    /* amount to shift minor to get 'real' minor */
#define XLVBD_MAX_PART    (1 << XLVBD_PARTN_SHIFT) /* minors per 'other' vbd */


/* the below are for the use of the generic drivers/block/ll_rw_block.c code */
static int xlide_blksize_size[256];
static int xlide_hardsect_size[256];
static int xlide_max_sectors[256];
static int xlscsi_blksize_size[256];
static int xlscsi_hardsect_size[256];
static int xlscsi_max_sectors[256];
static int xlvbd_blksize_size[256];
static int xlvbd_hardsect_size[256];
static int xlvbd_max_sectors[256];


static struct block_device_operations xlvbd_block_fops = 
{
    open:               xenolinux_block_open,
    release:            xenolinux_block_release,
    ioctl:              xenolinux_block_ioctl,
    check_media_change: xenolinux_block_check,
    revalidate:         xenolinux_block_revalidate,
};


typedef unsigned char bool; 

/* 
** Set up all the linux device goop for the virtual block devices (vbd's)
** that xen tells us about. Note that although from xen's pov VBDs are 
** addressed simply an opaque 16-bit device number, the domain creation 
** tools conventionally allocate these numbers to correspond to those 
** used by 'real' linux -- this is just for convenience as it means e.g. 
** that the same /etc/fstab can be used when booting with or without xen.
*/
int __init xlvbd_init(xen_disk_info_t *xdi)
{
    int i, result, max_part; 
    struct gendisk *gd = NULL;
    kdev_t device; 
    unsigned short major, minor, partno; 
    bool is_ide, is_scsi; 
    char *major_name; 
    unsigned char buf[64]; 
    int majors[256]; 

    SET_MODULE_OWNER(&xlvbd_block_fops);

    /* Initialize the global arrays. */
    for (i = 0; i < 256; i++) 
    {
	/* from the generic ide code (drivers/ide/ide-probe.c, etc) */
	xlide_blksize_size[i]  = 1024;
	xlide_hardsect_size[i] = 512;
	xlide_max_sectors[i]   = 128;  /* 'hwif->rqsize' if we knew it */

	/* from the generic scsi disk code (drivers/scsi/sd.c) */
	xlscsi_blksize_size[i]  = 1024; //XXX 512;
	xlscsi_hardsect_size[i] = 512;
	xlscsi_max_sectors[i]   = 128*8; //XXX 128;

	/* we don't really know what to set these too since it depends */
	xlvbd_blksize_size[i]  = 512;
	xlvbd_hardsect_size[i] = 512;
	xlvbd_max_sectors[i]   = 128;
    }


    /* keep track of which majors we've seen so far */
    for (i = 0; i < 256; i++) 
	majors[i] = 0; 

    /* 
    ** We need to loop through each major device we've been told about and: 
    ** a) register the appropriate blkdev 
    ** b) setup the indexed-by-major global arrays (blk_size[], 
    **    blksize_size[], hardsect_size[], max_sectors[], read_ahead[]) 
    ** c) setup the block queue + make it sensible
    ** d) create an appropriate gendisk structure, and 
    ** e) register the gendisk 
    */
    for (i = 0; i < xdi->count; i++)
    {
	device = xdi->disks[i].device;
	major  = MAJOR(device); 
	minor  = MINOR(device);
	is_ide = IDE_DISK_MAJOR(major);  /* is this an ide device? */
	is_scsi= SCSI_BLK_MAJOR(major);  /* is this a scsi device? */
	
	if(is_ide) { 
	    major_name = XLIDE_MAJOR_NAME; 
	    max_part   = XLIDE_MAX_PART;
	} else if(is_scsi) { 
	    major_name = XLSCSI_MAJOR_NAME;
	    max_part   = XLSCSI_MAX_PART;
	} else { 
	    major_name = XLVBD_MAJOR_NAME;
	    max_part   = XLVBD_MAX_PART;
	}

	/* 
	** XXX SMH: conventionally we assume a minor device if the 
	** corresponding linux device number would be a minor device; 
	** minor devices require slightly different handling than 
	** 'full' devices (e.g. in terms of partition table handling). 
	*/
	partno = minor & (max_part - 1); 

	if(!majors[major]) {

	    result = register_blkdev(major, major_name, &xlvbd_block_fops);
	    if (result < 0) {
		printk(KERN_ALERT "XL VBD: can't get major %d\n", major);
		continue; 
	    }

	    blk_size[major]      = NULL;
	    if(is_ide) { 
		blksize_size[major]  = xlide_blksize_size;
		hardsect_size[major] = xlide_hardsect_size;
		max_sectors[major]   = xlide_max_sectors;
		read_ahead[major]    = 8; // from drivers/ide/ide-probe.c
	    } else if(is_scsi) { 
		blksize_size[major]  = xlscsi_blksize_size;
		hardsect_size[major] = xlscsi_hardsect_size;
		max_sectors[major]   = xlscsi_max_sectors;
		read_ahead[major]    = 0; // XXX 8; -- guessing 
	    } else { 
		blksize_size[major]  = xlvbd_blksize_size;
		hardsect_size[major] = xlvbd_hardsect_size;
		max_sectors[major]   = xlvbd_max_sectors;
		read_ahead[major]    = 8;
	    }
	
	    blk_init_queue(BLK_DEFAULT_QUEUE(major), do_xlblk_request);
	
	    /*
	     * Turn off barking 'headactive' mode. We dequeue buffer heads as
	     * soon as we pass them down to Xen.
	     */
	    blk_queue_headactive(BLK_DEFAULT_QUEUE(major), 0);

	    /* Construct an appropriate gendisk structure. */
	    gd             = kmalloc(sizeof(struct gendisk), GFP_KERNEL);
	    gd->major      = major;
	    gd->major_name = major_name; 
	    
	    gd->max_p      = max_part; 
	    if(is_ide) { 
		gd->minor_shift  = XLIDE_PARTN_SHIFT; 
		gd->nr_real      = XLIDE_DEVS_PER_MAJOR; 
	    } else if(is_scsi) { 
		gd->minor_shift  = XLSCSI_PARTN_SHIFT; 
		gd->nr_real      = XLSCSI_DEVS_PER_MAJOR; 
	    } else { 
		gd->minor_shift  = XLVBD_PARTN_SHIFT; 
		gd->nr_real      = XLVBD_DEVS_PER_MAJOR; 
	    }

	    /* 
	    ** The sizes[] and part[] arrays hold the sizes and other 
	    ** information about every partition with this 'major' (i.e. 
	    ** every disk sharing the 8 bit prefix * max partns per disk) 
	    */
	    gd->sizes = kmalloc(max_part*gd->nr_real*sizeof(int), GFP_KERNEL);
	    gd->part  = kmalloc(max_part*gd->nr_real*sizeof(struct hd_struct), 
				     GFP_KERNEL);
	    memset(gd->sizes, 0, max_part * gd->nr_real * sizeof(int));
	    memset(gd->part,  0, max_part * gd->nr_real 
		   * sizeof(struct hd_struct));


	    gd->real_devices = kmalloc(gd->nr_real * sizeof(xl_disk_t), 
				       GFP_KERNEL);
	    memset(gd->real_devices, 0, gd->nr_real * sizeof(xl_disk_t));

	    gd->next   = NULL;            
	    gd->fops   = &xlvbd_block_fops;

	    gd->de_arr = kmalloc(gd->nr_real * sizeof(*gd->de_arr), 
				 GFP_KERNEL);
	    gd->flags  = kmalloc(gd->nr_real * sizeof(*gd->flags), GFP_KERNEL);
	    
	    memset(gd->de_arr, 0, gd->nr_real * sizeof(*gd->de_arr));
	    memset(gd->flags, 0, gd->nr_real *  sizeof(*gd->flags));

	    /* 
	    ** Keep track of gendisk both locally and in the global array. 
	    ** XXX SMH: can probably do without local copy -- FIXME later 
	    */
	    xlvbd_gendisk[i] = gd;
	    add_gendisk(gd);

	    /* XXX SMH: not clear on what 'real_devices' is indexed by; 
	       hence using unit number for now but in old code was 'disk' aka 
	       sequence number assigned by xen during probe = barfle? */
	    ((xl_disk_t *)gd->real_devices)[minor>>gd->minor_shift].capacity =
	    xdi->disks[i].capacity;

	    
	    /* remember that we've done this major */
	    majors[major] = 1; 
	} else 
	    /* Continue the setup of this gendisk */
	    gd = get_gendisk(device); 

	if(XD_READONLY(xdi->disks[i].info)) 
	    set_device_ro(device, 1); 

	if(partno) { 

	    /* Need to skankily setup 'partition' information */
	    gd->part[partno].start_sect = 0; 
	    gd->part[partno].nr_sects   = xdi->disks[i].capacity; 
	    gd->sizes[partno]           = xdi->disks[i].capacity; 

	} else { 

	    /* Some final fix-ups depending on the device type */
	    switch (XD_TYPE(xdi->disks[i].info)) 
	    { 

	    case XD_TYPE_CDROM:
	    case XD_TYPE_FLOPPY: 
	    case XD_TYPE_TAPE:
		gd->flags[minor >> gd->minor_shift] = GENHD_FL_REMOVABLE; 
		printk(KERN_ALERT 
		       "Skipping partition check on %s /dev/%s\n", 
		       XD_TYPE(xdi->disks[i].info)==XD_TYPE_CDROM ? "cdrom" : 
		       (XD_TYPE(xdi->disks[i].info)==XD_TYPE_TAPE ? "tape" : 
			"floppy"), disk_name(gd, MINOR(device), buf)); 
		break; 
		
	    case XD_TYPE_DISK: 
		register_disk(gd, device, gd->nr_real, &xlvbd_block_fops, 
			      xdi->disks[i].capacity);
		break; 
		
	    default: 
		printk(KERN_ALERT "XenoLinux: unknown device type %d\n", 
		       XD_TYPE(xdi->disks[i].info)); 
		break; 
	    }

	}
	    
	printk(KERN_ALERT "XenoLinux Virtual Block Device Driver "
	       "installed [device: %04x]\n", device);
    }

    return 0;
}

/* 
** XXX SMH: crappy linear scan routine to map from a device number bac k
** to the relevant gendisk; could be made better if and when it becomes 
** an issue but for now we expect success within a few loop iterations. 
*/
struct gendisk *xldev_to_gendisk(kdev_t xldev)
{
    int i; 
    short major = MAJOR(xldev); 
    
    for(i = 0; i < XLVBD_MAX_MAJORS; i++) { 
	if(xlvbd_gendisk[i]->major == major)
	    return xlvbd_gendisk[i]; 
    }
    
    /* didn't find it -- death */
    BUG();
    return NULL; 
}

void xlvbd_cleanup(void)
{
    bool is_ide, is_scsi; 
    struct gendisk *gd; 
    char *major_name; 
    int major; 

    for(major = 0; major < XLVBD_MAX_MAJORS; major++) { 

	if(!(gd = xlvbd_gendisk[major]))
	    continue; 

	is_ide = IDE_DISK_MAJOR(major);  /* is this an ide device? */
	is_scsi= SCSI_BLK_MAJOR(major);  /* is this a scsi device? */

	blk_cleanup_queue(BLK_DEFAULT_QUEUE(major)); 
	
	if(is_ide) { 
	    major_name = XLIDE_MAJOR_NAME; 
	} else if(is_scsi) { 
	    major_name = XLSCSI_MAJOR_NAME;
	} else { 
	    major_name = XLVBD_MAJOR_NAME;
	}

	if (unregister_blkdev(major, major_name) != 0) 
	    printk(KERN_ALERT "XenoLinux Virtual Block Device Driver:"
		   "major device %04x uninstalled w/ errors\n", major); 

    }

    return; 
}


#ifdef MODULE
module_init(xlvbd_init);
module_exit(xlvbd_cleanup);
#endif
