/******************************************************************************
 * xl_vbd.c
 * 
 * Xenolinux virtual block-device driver (xvd).
 * 
 */

/* Some modifications to the original by Mark A. Williamson and (C) Intel
 * Research Cambridge */

#include "xl_block.h"
#include <linux/blk.h>

/*
 * For convenience we distinguish between ide, scsi and 'other' (i.e.
 * potentially combinations of the two) in the naming scheme and in a few 
 * other places (like default readahead, etc).
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

/* Used to record data in vbd_state[] and detect changes in configuration */
#define VBD_NODEV 1
#define VBD_KNOWN 2

/* The below are for the generic drivers/block/ll_rw_block.c code. */
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

 /* hold state about for all possible VBDs for use in handling updates */
static char vbd_state[65536];

/**
 * xlvbd_init_device - initialise a VBD device
 * @disk:              a xen_disk_t describing the VBD
 *
 * Takes a xen_disk_t * that describes a VBD the domain has access to.
 * Performs appropriate initialisation and registration of the device.
 *
 * Care needs to be taken when making re-entrant calls to ensure that
 * corruption does not occur.  Also, devices that are in use should not have
 * their details updated.  This is the caller's responsibility.
 */
int xlvbd_init_device(xen_disk_t *disk)
{
    int device = disk->device;
    int major  = MAJOR(device); 
    int minor  = MINOR(device);
    int is_ide = IDE_DISK_MAJOR(major);  /* is this an ide device? */
    int is_scsi= SCSI_BLK_MAJOR(major);  /* is this a scsi device? */
    int partno;
    char * major_name;
    int max_part;
    
    struct gendisk *gd;
    int result;
    int j;

    unsigned char buf[64];

    if ( is_ide )
    { 
	major_name = XLIDE_MAJOR_NAME; 
	max_part   = XLIDE_MAX_PART;
    }
    else if ( is_scsi )
    { 
	major_name = XLSCSI_MAJOR_NAME;
	max_part   = XLSCSI_MAX_PART;
    }
    else
    { 
	major_name = XLVBD_MAJOR_NAME;
	max_part   = XLVBD_MAX_PART;
    }
    
    partno = minor & (max_part - 1); 
    
    if ( (gd = get_gendisk(device)) == NULL )
    {
        result = register_blkdev(major, major_name, &xlvbd_block_fops);
        if ( result < 0 )
        {
            printk(KERN_ALERT "XL VBD: can't get major %d\n", major);
            return -1; /* XXX make this sane one day */
        }

        if ( is_ide )
        { 
            blksize_size[major]  = xlide_blksize_size;
            hardsect_size[major] = xlide_hardsect_size;
            max_sectors[major]   = xlide_max_sectors;
            read_ahead[major]    = 8; /* from drivers/ide/ide-probe.c */
        } 
        else if ( is_scsi )
        { 
            blksize_size[major]  = xlscsi_blksize_size;
            hardsect_size[major] = xlscsi_hardsect_size;
            max_sectors[major]   = xlscsi_max_sectors;
            read_ahead[major]    = 0; /* XXX 8; -- guessing */
        }
        else
        { 
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
        if ( is_ide )
        { 
            gd->minor_shift  = XLIDE_PARTN_SHIFT; 
            gd->nr_real      = XLIDE_DEVS_PER_MAJOR; 
        } 
        else if ( is_scsi )
        { 
            gd->minor_shift  = XLSCSI_PARTN_SHIFT; 
            gd->nr_real      = XLSCSI_DEVS_PER_MAJOR; 
        }
        else
        { 
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

        add_gendisk(gd);

        blk_size[major] = gd->sizes;
    }

    if ( XD_READONLY(disk->info) )
        set_device_ro(device, 1); 

    gd->flags[minor >> gd->minor_shift] |= GENHD_FL_XENO;
        
    if ( partno != 0 )
    {
        /*
         * If this was previously set up as a real disc we will have set 
         * up partition-table information. Virtual partitions override 
         * 'real' partitions, and the two cannot coexist on a device.
         */
        if ( gd->sizes[minor & ~(max_part-1)] != 0 )
        {
            kdev_t dev = device & ~(max_part-1);
            for ( j = max_part - 1; j >= 0; j-- )
            {
                invalidate_device(dev+j, 1);
                gd->part[MINOR(dev+j)].start_sect = 0;
                gd->part[MINOR(dev+j)].nr_sects   = 0;
                gd->sizes[MINOR(dev+j)]           = 0;

                vbd_state[dev+j] &= ~VBD_KNOWN;
            }
            printk(KERN_ALERT
                   "Virtual partitions found for /dev/%s - ignoring any "
                   "real partition information we may have found.\n",
                   disk_name(gd, MINOR(device), buf));
        }

        /* Need to skankily setup 'partition' information */
        gd->part[minor].start_sect = 0; 
        gd->part[minor].nr_sects   = disk->capacity; 
        gd->sizes[minor]           = disk->capacity; 

        gd->flags[minor >> gd->minor_shift] |= GENHD_FL_VIRT_PARTNS;

        vbd_state[device] |= VBD_KNOWN;
    }
    else
    {
        /* Some final fix-ups depending on the device type */
        switch ( XD_TYPE(disk->info) )
        { 
        case XD_TYPE_CDROM:
        case XD_TYPE_FLOPPY: 
        case XD_TYPE_TAPE:
            gd->part[minor].nr_sects = disk->capacity;
            gd->sizes[minor] = disk->capacity>>(BLOCK_SIZE_BITS-9);
            gd->flags[minor >> gd->minor_shift] |= GENHD_FL_REMOVABLE; 
            printk(KERN_ALERT 
                   "Skipping partition check on %s /dev/%s\n", 
                   XD_TYPE(disk->info)==XD_TYPE_CDROM ? "cdrom" : 
                   (XD_TYPE(disk->info)==XD_TYPE_TAPE ? "tape" : 
                    "floppy"), disk_name(gd, MINOR(device), buf)); 

            vbd_state[device] |= VBD_KNOWN; /* remember the VBD is there now */
            break; 

        case XD_TYPE_DISK:
            /* Only check partitions on real discs (not virtual!). */
            if ( gd->flags[minor>>gd->minor_shift] & GENHD_FL_VIRT_PARTNS )
            {
                printk(KERN_ALERT
                       "Skipping partition check on virtual /dev/%s\n",
                       disk_name(gd, MINOR(device), buf));
                break;
            }
            register_disk(gd, device, gd->max_p, &xlvbd_block_fops, 
                          disk->capacity);

            vbd_state[device] |= VBD_KNOWN; /* remember the VBD is there now */
            
            break; 

        default:
            printk(KERN_ALERT "XenoLinux: unknown device type %d\n", 
                   XD_TYPE(disk->info)); 
            break; 
        }
    }

    printk(KERN_ALERT "XenoLinux Virtual Block Device Driver "
           "installed [device: %04x]\n", device);

    return 0;
}


/**
 * xlvbd_remove - see if a VBD should be removed and do so if appropriate
 * @device:       numeric device ID
 *
 * Updates the gendisk structure and invalidates devices.
 *
 * This is OK for now but in future, should perhaps consider where this should
 * deallocate gendisks / unregister devices?
 */
int xlvbd_remove(int device)
{
    int major  = MAJOR(device); 
    int minor  = MINOR(device);
    int is_ide = IDE_DISK_MAJOR(major);  /* is this an ide device? */
    int is_scsi= SCSI_BLK_MAJOR(major);  /* is this a scsi device? */
    int i;                               /* loop counter */
    int partno;
    int max_part;
    char * major_name;
    
    struct gendisk *gd;

    DPRINTK("xl_vbd.c::xlvbd_remove() - Removing a VBD\n");
  
    /* if device is in use then we shouldn't change its settings */
    if(xldev_to_xldisk(device)->usage)
    {
        DPRINTK("xl_vbd.c::xlvbd_remove() - VBD in use, could not remove\n");
        printk(KERN_ALERT "Removing XenoLinux VBD failed - "
               "in use [device: %x]\n", device);
        return -1;
    }

    if((gd = get_gendisk(device)) == NULL)
    {
        printk(KERN_ALERT
               "xl_vbd.c::xlvbd_remove() - ERROR could not get gendisk\n");
        
        return -1;
    }

    if ( is_ide )
    { 
        major_name = XLIDE_MAJOR_NAME; 
        max_part   = XLIDE_MAX_PART;
    }
    else if ( is_scsi )
    { 
        major_name = XLSCSI_MAJOR_NAME;
        max_part   = XLSCSI_MAX_PART;
    }
    else
    { 
        major_name = XLVBD_MAJOR_NAME;
        max_part   = XLVBD_MAX_PART;
    }

    partno = minor & (max_part - 1); 

    DPRINTK("Got partno = 0x%x\n", partno);

    if(partno) /* if the VBD is mapped to a "partition" device node in Linux */
    {
        int should_clear_virtpart = 1; /* if this is set true we should clear
                                        * the GENHD_FL_VIRT_PARTNS flag in the
                                        * gendisk */
        
        gd->sizes[minor] = 0;

        for(i = 0; i < max_part; i++)
            if(gd->sizes[minor - partno + i]) should_clear_virtpart = 0;
        
        /* if there aren't any virtual partitions here then clear the flag for
         * this unit */
        if(should_clear_virtpart)
        {
            gd->flags[minor >> gd->minor_shift] &= ~GENHD_FL_VIRT_PARTNS;

            DPRINTK("xl_vbd.c::xlvbd_remove() - "
                    "cleared virtual partition flag\n");
        }
        
	gd->part[MINOR(device)].start_sect = 0;
        gd->part[MINOR(device)].nr_sects   = 0;
        gd->sizes[MINOR(device)]           = 0;
        
        invalidate_device(device, 1);

        vbd_state[device] &= ~VBD_KNOWN; /* forget VBD was ever there */
    }
    else /* the VBD is mapped to a "whole disk drive" device node in Linux */
    {
        for ( i = max_part - 1; i >= 0; i-- )
        {
            invalidate_device(device+i, 1);
            gd->part[MINOR(device+i)].start_sect = 0;
            gd->part[MINOR(device+i)].nr_sects   = 0;
            gd->sizes[MINOR(device+i)]           = 0;
            
            vbd_state[device+i] &= ~VBD_KNOWN; /* forget VBD was ever there */
        }
    }

    printk(KERN_ALERT "XenoLinux Virtual Block Device removed "
           " [device: %04x]\n", device);
    return 0;
}

/*
 * Set up all the linux device goop for the virtual block devices (vbd's) that 
 * xen tells us about. Note that although from xen's pov VBDs are addressed 
 * simply an opaque 16-bit device number, the domain creation tools 
 * conventionally allocate these numbers to correspond to those used by 'real' 
 * linux -- this is just for convenience as it means e.g. that the same 
 * /etc/fstab can be used when booting with or without xen.
 */
int __init xlvbd_init(xen_disk_info_t *xdi)
{
    int i; /* loop counter */
    
    SET_MODULE_OWNER(&xlvbd_block_fops);

    /* Initialize the global arrays. */

    for( i = 0; i < 65536; i++)
        vbd_state[i] = VBD_NODEV;

    for ( i = 0; i < 256; i++ ) 
    {
        /* from the generic ide code (drivers/ide/ide-probe.c, etc) */
        xlide_blksize_size[i]  = 1024;
        xlide_hardsect_size[i] = 512;
        xlide_max_sectors[i]   = 128;  /* 'hwif->rqsize' if we knew it */

        /* from the generic scsi disk code (drivers/scsi/sd.c) */
        xlscsi_blksize_size[i]  = 1024; /* XXX 512; */
        xlscsi_hardsect_size[i] = 512;
        xlscsi_max_sectors[i]   = 128*8; /* XXX 128; */

        /* we don't really know what to set these too since it depends */
        xlvbd_blksize_size[i]  = 512;
        xlvbd_hardsect_size[i] = 512;
        xlvbd_max_sectors[i]   = 128;
    }

    /*
     * We need to loop through each major device we've been told about and: 
     * a) register the appropriate blkdev 
     * b) setup the indexed-by-major global arrays (blk_size[], 
     *    blksize_size[], hardsect_size[], max_sectors[], read_ahead[]) 
     * c) setup the block queue + make it sensible
     * d) create an appropriate gendisk structure, and 
     * e) register the gendisk 
     */
    for ( i = 0; i < xdi->count; i++ )
    {
        xlvbd_init_device(&xdi->disks[i]);
    }

    return 0;
}

/**
 * xlvbd_update_vbds - reprobes the VBD status and performs updates driver state
 *
 * The VBDs need to be updated in this way when the domain is initialised and
 * also each time we receive an XLBLK_UPDATE event.
 *
 * The vbd_state array is consistent on entry to and exit from this function but
 * not whilst the function runs, so this should not be called re-entrantly.
 */
void xlvbd_update_vbds(void)
{
    int i;            /* loop counter       */
    int ret;          /* return values      */
    block_io_op_t op; /* for talking to Xen */

    xen_disk_info_t *xdi = &xlblk_disk_info; /* pointer to structures in
                                              * xl_block.c */

    /* Probe for disk information. */
    memset(&op, 0, sizeof(op)); 
    op.cmd = BLOCK_IO_OP_VBD_PROBE; 
    op.u.probe_params.domain = 0;
    
    xdi->count = 0; /* need to keep resetting this to zero because the probe
                     * will append results after "used" space in the array */

    memcpy(&op.u.probe_params.xdi, &xlblk_disk_info, sizeof(xlblk_disk_info)); 

    ret = HYPERVISOR_block_io_op(&op);
    
    if ( ret )
    {
        printk(KERN_ALERT "Could not probe disks (%d)\n", ret);
    }

    /* copy back the [updated] count parameter */
    xlblk_disk_info.count = op.u.probe_params.xdi.count;

    DPRINTK("Retrieved %d disks\n",op.u.probe_params.xdi.count);
    
    
    for( i = 0; i < 65536; i++ )
        vbd_state[i] |= VBD_NODEV;
    
    for( i = 0; i < xdi->count; i++ )
    {
        int device = xdi->disks[i].device;
        xl_disk_t *d;

        vbd_state[device] &= ~VBD_NODEV;

        DPRINTK("Inspecting xen_disk_t: device = %hx, info = %hx, "
                "capacity = %lx, domain = %d\n",
                xdi->disks[i].device, xdi->disks[i].info, xdi->disks[i].capacity,
                xdi->disks[i].domain); 

        if(xdi->disks[i].info & XD_FLAG_VIRT)
        {
            /* RACE: need to fix this for SMP / pre-emptive kernels */

            d = xldev_to_xldisk(device);

            /* only go on to monkey with this stuff if we successfully got the
            * xldisk and it says no-one else is using the disk OR if we didn't
            * successfully retrieve the xldisk (so it doesn't exist and nobody
            * can be using it), otherwise skip on to the next device */
            if(d != NULL && d->usage > 0)
            {
                printk(KERN_ALERT "XenoLinux VBD Driver: "
                    "skipping update in a disk currently in use");
                DPRINTK("Usage = %d\n", d->usage);
                continue; /* skip to next device */
            }
            
            printk(KERN_ALERT "XenoLinux VBD Driver: updating a VBD "
                   "[device: %x]\n", device);
            /* also takes care of any overrides (i.e. due to VBDs mapped to
             * partitions overriding VBDs mapped to disks) and of registering
             * disks */
            xlvbd_init_device(xdi->disks + i);
        }
        
    }

    for( i = 0; i < 65536; i++ )
    {
        switch(vbd_state[i])
        {
        case VBD_NODEV | VBD_KNOWN: /* a VBD we knew about before has gone */
           
            DPRINTK("About to remove VBD 0x%x\n",i);
               
            ret = xlvbd_remove(i);

            if(ret) DPRINTK("Failed to remove VBD\n");

            break;

        case VBD_NODEV: /* there's nothing here and there wasn't anything
                         * before */
            break;
            
        case VBD_KNOWN: /* the device is present and it's set up */
            break;

        case 0:         /* there's a device present we haven't set up - either
                         * one of the "non virtual" VBDs or we weren't able to
                         * update it because it was mounted */
            break;

        default:        /* if there's any other weird combination, something
                         * unexpected is happening */
            printk(KERN_ALERT "xl_vbd.c::xlvbd_update_vbds: BUG - Unknown state "
                   "when updating VBDs: 0x%x\n", vbd_state[i]);
        }
    }

}

void xlvbd_cleanup(void)
{
    int is_ide, is_scsi, i; 
    struct gendisk *gd; 
    char *major_name; 
    int major; 

    for ( major = 0; major < MAX_BLKDEV; major++ )
    {
        if ( (gd = get_gendisk(MKDEV(major, 0))) == NULL )
            continue; 

        /*
         * If this is a 'Xeno' blkdev then at least one unit will have the Xeno
         * flag set.
         */
        for ( i = 0; i < gd->nr_real; i++ )
            if ( gd->flags[i] & GENHD_FL_XENO )
                break;
        if ( i == gd->nr_real )
            continue;
        
        is_ide  = IDE_DISK_MAJOR(major);  /* is this an ide device? */
        is_scsi = SCSI_BLK_MAJOR(major);  /* is this a scsi device? */

        blk_cleanup_queue(BLK_DEFAULT_QUEUE(major)); 

        if ( is_ide ) 
            major_name = XLIDE_MAJOR_NAME; 
        else if ( is_scsi )
            major_name = XLSCSI_MAJOR_NAME;
        else 
            major_name = XLVBD_MAJOR_NAME;

        if ( unregister_blkdev(major, major_name) != 0 ) 
            printk(KERN_ALERT "XenoLinux Virtual Block Device Driver:"
                   "major device %04x uninstalled w/ errors\n", major);

        /* XXX shouldn't we remove the gendisk from the kernel linked list and
         * deallocate the memory here? */
    }
}

#ifdef MODULE
module_init(xlvbd_init);
module_exit(xlvbd_cleanup);
#endif
