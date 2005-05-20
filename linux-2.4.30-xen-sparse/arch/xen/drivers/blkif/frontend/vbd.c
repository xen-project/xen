/******************************************************************************
 * arch/xen/drivers/blkif/frontend/vbd.c
 * 
 * Xenolinux virtual block-device driver.
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 */

#include "common.h"
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

#define XLVBD_PARTN_SHIFT  4    /* amount to shift minor to get 'real' minor */
#define XLVBD_MAX_PART    (1 << XLVBD_PARTN_SHIFT) /* minors per 'other' vbd */

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

/* Information about our VBDs. */
#define MAX_VBDS 64
static int nr_vbds;
static vdisk_t *vbd_info;

static struct block_device_operations xlvbd_block_fops = 
{
    open:               blkif_open,
    release:            blkif_release,
    ioctl:              blkif_ioctl,
    check_media_change: blkif_check,
    revalidate:         blkif_revalidate,
};

static int xlvbd_get_vbd_info(vdisk_t *disk_info)
{
    vdisk_t         *buf = (vdisk_t *)__get_free_page(GFP_KERNEL);
    blkif_request_t  req;
    blkif_response_t rsp;
    int              nr;

    memset(&req, 0, sizeof(req));
    req.operation   = BLKIF_OP_PROBE;
    req.nr_segments = 1;
    req.frame_and_sects[0] = virt_to_machine(buf) | 7;

    blkif_control_send(&req, &rsp);

    if ( rsp.status <= 0 )
    {
        printk(KERN_ALERT "Could not probe disks (%d)\n", rsp.status);
        return -1;
    }

    if ( (nr = rsp.status) > MAX_VBDS )
         nr = MAX_VBDS;
    memcpy(disk_info, buf, nr * sizeof(vdisk_t));

    return nr;
}

/*
 * xlvbd_init_device - initialise a VBD device
 * @disk:              a vdisk_t describing the VBD
 *
 * Takes a vdisk_t * that describes a VBD the domain has access to.
 * Performs appropriate initialisation and registration of the device.
 *
 * Care needs to be taken when making re-entrant calls to ensure that
 * corruption does not occur.  Also, devices that are in use should not have
 * their details updated.  This is the caller's responsibility.
 */
static int xlvbd_init_device(vdisk_t *xd)
{
    int device = xd->device;
    int major  = MAJOR(device); 
    int minor  = MINOR(device);
    int is_ide = IDE_DISK_MAJOR(major);  /* is this an ide device? */
    int is_scsi= SCSI_BLK_MAJOR(major);  /* is this a scsi device? */
    char *major_name;
    struct gendisk *gd;
    struct block_device *bd;
    xl_disk_t *disk;
    int i, rc = 0, max_part, partno;
    unsigned long capacity;

    unsigned char buf[64];

    if ( (bd = bdget(device)) == NULL )
        return -1;

    /*
     * Update of partition info, and check of usage count, is protected
     * by the per-block-device semaphore.
     */
    down(&bd->bd_sem);

    if ( ((disk = xldev_to_xldisk(device)) != NULL) && (disk->usage != 0) )
    {
        printk(KERN_ALERT "VBD update failed - in use [dev=%x]\n", device);
        rc = -1;
        goto out;
    }

    if ( is_ide ) {

	major_name = XLIDE_MAJOR_NAME; 
	max_part   = XLIDE_MAX_PART;

    } else if ( is_scsi ) {

	major_name = XLSCSI_MAJOR_NAME;
	max_part   = XLSCSI_MAX_PART;

    } else if (VDISK_VIRTUAL(xd->info)) {

	major_name = XLVBD_MAJOR_NAME;
	max_part   = XLVBD_MAX_PART;

    } else { 

        /* SMH: hmm - probably a CCISS driver or sim; assume CCISS for now */
	printk(KERN_ALERT "Assuming device %02x:%02x is CCISS/SCSI\n", 
	       major, minor);
	is_scsi    = 1; 
	major_name = "cciss"; 
	max_part   = XLSCSI_MAX_PART;

    }
    
    partno = minor & (max_part - 1); 
    
    if ( (gd = get_gendisk(device)) == NULL )
    {
        rc = register_blkdev(major, major_name, &xlvbd_block_fops);
        if ( rc < 0 )
        {
            printk(KERN_ALERT "XL VBD: can't get major %d\n", major);
            goto out;
        }

        if ( is_ide )
        { 
            blksize_size[major]  = xlide_blksize_size;
            hardsect_size[major] = xlide_hardsect_size;
            max_sectors[major]   = xlide_max_sectors;
            read_ahead[major]    = 8;
        } 
        else if ( is_scsi )
        { 
            blksize_size[major]  = xlscsi_blksize_size;
            hardsect_size[major] = xlscsi_hardsect_size;
            max_sectors[major]   = xlscsi_max_sectors;
            read_ahead[major]    = 8;
        }
        else
        { 
            blksize_size[major]  = xlvbd_blksize_size;
            hardsect_size[major] = xlvbd_hardsect_size;
            max_sectors[major]   = xlvbd_max_sectors;
            read_ahead[major]    = 8;
        }

        blk_init_queue(BLK_DEFAULT_QUEUE(major), do_blkif_request);

        /*
         * Turn off barking 'headactive' mode. We dequeue buffer heads as
         * soon as we pass them to the back-end driver.
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

    if ( VDISK_READONLY(xd->info) )
        set_device_ro(device, 1); 

    gd->flags[minor >> gd->minor_shift] |= GENHD_FL_XEN;

    /* NB. Linux 2.4 only handles 32-bit sector offsets and capacities. */
    capacity = (unsigned long)xd->capacity;

    if ( partno != 0 )
    {
        /*
         * If this was previously set up as a real disc we will have set 
         * up partition-table information. Virtual partitions override 
         * 'real' partitions, and the two cannot coexist on a device.
         */
        if ( !(gd->flags[minor >> gd->minor_shift] & GENHD_FL_VIRT_PARTNS) &&
             (gd->sizes[minor & ~(max_part-1)] != 0) )
        {
            /*
             * Any non-zero sub-partition entries must be cleaned out before
             * installing 'virtual' partition entries. The two types cannot
             * coexist, and virtual partitions are favoured.
             */
            kdev_t dev = device & ~(max_part-1);
            for ( i = max_part - 1; i > 0; i-- )
            {
                invalidate_device(dev+i, 1);
                gd->part[MINOR(dev+i)].start_sect = 0;
                gd->part[MINOR(dev+i)].nr_sects   = 0;
                gd->sizes[MINOR(dev+i)]           = 0;
            }
            printk(KERN_ALERT
                   "Virtual partitions found for /dev/%s - ignoring any "
                   "real partition information we may have found.\n",
                   disk_name(gd, MINOR(device), buf));
        }

        /* Need to skankily setup 'partition' information */
        gd->part[minor].start_sect = 0; 
        gd->part[minor].nr_sects   = capacity; 
        gd->sizes[minor]           = capacity >>(BLOCK_SIZE_BITS-9); 

        gd->flags[minor >> gd->minor_shift] |= GENHD_FL_VIRT_PARTNS;
    }
    else
    {
        gd->part[minor].nr_sects = capacity;
        gd->sizes[minor] = capacity>>(BLOCK_SIZE_BITS-9);
        
        /* Some final fix-ups depending on the device type */
        switch ( VDISK_TYPE(xd->info) )
        { 
        case VDISK_TYPE_CDROM:
        case VDISK_TYPE_FLOPPY: 
        case VDISK_TYPE_TAPE:
            gd->flags[minor >> gd->minor_shift] |= GENHD_FL_REMOVABLE; 
            printk(KERN_ALERT 
                   "Skipping partition check on %s /dev/%s\n", 
                   VDISK_TYPE(xd->info)==VDISK_TYPE_CDROM ? "cdrom" : 
                   (VDISK_TYPE(xd->info)==VDISK_TYPE_TAPE ? "tape" : 
                    "floppy"), disk_name(gd, MINOR(device), buf)); 
            break; 

        case VDISK_TYPE_DISK:
            /* Only check partitions on real discs (not virtual!). */
            if ( gd->flags[minor>>gd->minor_shift] & GENHD_FL_VIRT_PARTNS )
            {
                printk(KERN_ALERT
                       "Skipping partition check on virtual /dev/%s\n",
                       disk_name(gd, MINOR(device), buf));
                break;
            }
            register_disk(gd, device, gd->max_p, &xlvbd_block_fops, capacity);
            break; 

        default:
            printk(KERN_ALERT "XenoLinux: unknown device type %d\n", 
                   VDISK_TYPE(xd->info)); 
            break; 
        }
    }

 out:
    up(&bd->bd_sem);
    bdput(bd);    
    return rc;
}


/*
 * xlvbd_remove_device - remove a device node if possible
 * @device:       numeric device ID
 *
 * Updates the gendisk structure and invalidates devices.
 *
 * This is OK for now but in future, should perhaps consider where this should
 * deallocate gendisks / unregister devices.
 */
static int xlvbd_remove_device(int device)
{
    int i, rc = 0, minor = MINOR(device);
    struct gendisk *gd;
    struct block_device *bd;
    xl_disk_t *disk = NULL;

    if ( (bd = bdget(device)) == NULL )
        return -1;

    /*
     * Update of partition info, and check of usage count, is protected
     * by the per-block-device semaphore.
     */
    down(&bd->bd_sem);

    if ( ((gd = get_gendisk(device)) == NULL) ||
         ((disk = xldev_to_xldisk(device)) == NULL) )
        BUG();

    if ( disk->usage != 0 )
    {
        printk(KERN_ALERT "VBD removal failed - in use [dev=%x]\n", device);
        rc = -1;
        goto out;
    }
 
    if ( (minor & (gd->max_p-1)) != 0 )
    {
        /* 1: The VBD is mapped to a partition rather than a whole unit. */
        invalidate_device(device, 1);
	gd->part[minor].start_sect = 0;
        gd->part[minor].nr_sects   = 0;
        gd->sizes[minor]           = 0;

        /* Clear the consists-of-virtual-partitions flag if possible. */
        gd->flags[minor >> gd->minor_shift] &= ~GENHD_FL_VIRT_PARTNS;
        for ( i = 1; i < gd->max_p; i++ )
            if ( gd->sizes[(minor & ~(gd->max_p-1)) + i] != 0 )
                gd->flags[minor >> gd->minor_shift] |= GENHD_FL_VIRT_PARTNS;

        /*
         * If all virtual partitions are now gone, and a 'whole unit' VBD is
         * present, then we can try to grok the unit's real partition table.
         */
        if ( !(gd->flags[minor >> gd->minor_shift] & GENHD_FL_VIRT_PARTNS) &&
             (gd->sizes[minor & ~(gd->max_p-1)] != 0) &&
             !(gd->flags[minor >> gd->minor_shift] & GENHD_FL_REMOVABLE) )
        {
            register_disk(gd,
                          device&~(gd->max_p-1), 
                          gd->max_p, 
                          &xlvbd_block_fops,
                          gd->part[minor&~(gd->max_p-1)].nr_sects);
        }
    }
    else
    {
        /*
         * 2: The VBD is mapped to an entire 'unit'. Clear all partitions.
         * NB. The partition entries are only cleared if there are no VBDs
         * mapped to individual partitions on this unit.
         */
        i = gd->max_p - 1; /* Default: clear subpartitions as well. */
        if ( gd->flags[minor >> gd->minor_shift] & GENHD_FL_VIRT_PARTNS )
            i = 0; /* 'Virtual' mode: only clear the 'whole unit' entry. */
        while ( i >= 0 )
        {
            invalidate_device(device+i, 1);
            gd->part[minor+i].start_sect = 0;
            gd->part[minor+i].nr_sects   = 0;
            gd->sizes[minor+i]           = 0;
            i--;
        }
    }

 out:
    up(&bd->bd_sem);
    bdput(bd);
    return rc;
}

/*
 * xlvbd_update_vbds - reprobes the VBD status and performs updates driver
 * state. The VBDs need to be updated in this way when the domain is
 * initialised and also each time we receive an XLBLK_UPDATE event.
 */
void xlvbd_update_vbds(void)
{
    int i, j, k, old_nr, new_nr;
    vdisk_t *old_info, *new_info, *merged_info;

    old_info = vbd_info;
    old_nr   = nr_vbds;

    new_info = kmalloc(MAX_VBDS * sizeof(vdisk_t), GFP_KERNEL);
    if (!new_info)
        return;

    if ( unlikely(new_nr = xlvbd_get_vbd_info(new_info)) < 0 )
        goto out;

    /*
     * Final list maximum size is old list + new list. This occurs only when
     * old list and new list do not overlap at all, and we cannot yet destroy
     * VBDs in the old list because the usage counts are busy.
     */
    merged_info = kmalloc((old_nr + new_nr) * sizeof(vdisk_t), GFP_KERNEL);
    if (!merged_info)
        goto out;

    /* @i tracks old list; @j tracks new list; @k tracks merged list. */
    i = j = k = 0;

    while ( (i < old_nr) && (j < new_nr) )
    {
        if ( old_info[i].device < new_info[j].device )
        {
            if ( xlvbd_remove_device(old_info[i].device) != 0 )
                memcpy(&merged_info[k++], &old_info[i], sizeof(vdisk_t));
            i++;
        }
        else if ( old_info[i].device > new_info[j].device )
        {
            if ( xlvbd_init_device(&new_info[j]) == 0 )
                memcpy(&merged_info[k++], &new_info[j], sizeof(vdisk_t));
            j++;
        }
        else
        {
            if ( ((old_info[i].capacity == new_info[j].capacity) &&
                  (old_info[i].info == new_info[j].info)) ||
                 (xlvbd_remove_device(old_info[i].device) != 0) )
                memcpy(&merged_info[k++], &old_info[i], sizeof(vdisk_t));
            else if ( xlvbd_init_device(&new_info[j]) == 0 )
                memcpy(&merged_info[k++], &new_info[j], sizeof(vdisk_t));
            i++; j++;
        }
    }

    for ( ; i < old_nr; i++ )
    {
        if ( xlvbd_remove_device(old_info[i].device) != 0 )
            memcpy(&merged_info[k++], &old_info[i], sizeof(vdisk_t));
    }

    for ( ; j < new_nr; j++ )
    {
        if ( xlvbd_init_device(&new_info[j]) == 0 )
            memcpy(&merged_info[k++], &new_info[j], sizeof(vdisk_t));
    }

    vbd_info = merged_info;
    nr_vbds  = k;

    kfree(old_info);
out:
    kfree(new_info);
}


/*
 * Set up all the linux device goop for the virtual block devices (vbd's) that
 * we know about. Note that although from the backend driver's p.o.v. VBDs are
 * addressed simply an opaque 16-bit device number, the domain creation tools 
 * conventionally allocate these numbers to correspond to those used by 'real' 
 * linux -- this is just for convenience as it means e.g. that the same 
 * /etc/fstab can be used when booting with or without Xen.
 */
int xlvbd_init(void)
{
    int i;
    
    /*
     * If compiled as a module, we don't support unloading yet. We therefore 
     * permanently increment the reference count to disallow it.
     */
    SET_MODULE_OWNER(&xlvbd_block_fops);
    MOD_INC_USE_COUNT;

    /* Initialize the global arrays. */
    for ( i = 0; i < 256; i++ ) 
    {
        xlide_blksize_size[i]  = 1024;
        xlide_hardsect_size[i] = 512;
        xlide_max_sectors[i]   = 512;

        xlscsi_blksize_size[i]  = 1024;
        xlscsi_hardsect_size[i] = 512;
        xlscsi_max_sectors[i]   = 512;

        xlvbd_blksize_size[i]  = 512;
        xlvbd_hardsect_size[i] = 512;
        xlvbd_max_sectors[i]   = 512;
    }

    vbd_info = kmalloc(MAX_VBDS * sizeof(vdisk_t), GFP_KERNEL);
    if (!vbd_info)
        return -ENOMEM;

    nr_vbds  = xlvbd_get_vbd_info(vbd_info);

    if ( nr_vbds < 0 )
    {
        kfree(vbd_info);
        vbd_info = NULL;
        nr_vbds  = 0;
    }
    else
    {
        for ( i = 0; i < nr_vbds; i++ )
            xlvbd_init_device(&vbd_info[i]);
    }

    return 0;
}
