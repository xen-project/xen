/******************************************************************************
 * vbd.c
 * 
 * XenLinux virtual block-device driver (xvd).
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004, Christian Limpach
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "block.h"
#include <linux/blkdev.h>

/*
 * For convenience we distinguish between ide, scsi and 'other' (i.e.
 * potentially combinations of the two) in the naming scheme and in a few 
 * other places (like default readahead, etc).
 */

#define NUM_IDE_MAJORS 10
#define NUM_SCSI_MAJORS 9
#define NUM_VBD_MAJORS 1

static struct xlbd_type_info xlbd_ide_type = {
    .partn_shift = 6,
    .partn_per_major = 2,
    // XXXcl todo blksize_size[major]  = 1024;
    .hardsect_size = 512,
    .max_sectors = 128,  /* 'hwif->rqsize' if we knew it */
    // XXXcl todo read_ahead[major]    = 8; /* from drivers/ide/ide-probe.c */
    .name = "hd",
};

static struct xlbd_type_info xlbd_scsi_type = {
    .partn_shift = 4,
    .partn_per_major = 16,
    // XXXcl todo blksize_size[major]  = 1024; /* XXX 512; */
    .hardsect_size = 512,
    .max_sectors = 128*8, /* XXX 128; */
    // XXXcl todo read_ahead[major]    = 0; /* XXX 8; -- guessing */
    .name = "sd",
};

static struct xlbd_type_info xlbd_vbd_type = {
    .partn_shift = 4,
    .partn_per_major = 16,
    // XXXcl todo blksize_size[major]  = 512;
    .hardsect_size = 512,
    .max_sectors = 128,
    // XXXcl todo read_ahead[major]    = 8;
    .name = "xvd",
};

static struct xlbd_major_info *major_info[NUM_IDE_MAJORS + NUM_SCSI_MAJORS +
                                         NUM_VBD_MAJORS];

/* Information about our VBDs. */
#define MAX_VBDS 64
static int nr_vbds;
static vdisk_t *vbd_info;

struct request_queue *xlbd_blk_queue = NULL;

#define MAJOR_XEN(dev) ((dev)>>8)
#define MINOR_XEN(dev) ((dev) & 0xff)

static struct block_device_operations xlvbd_block_fops = 
{
    .owner  = THIS_MODULE,
    .open  = blkif_open,
    .release = blkif_release,
    .ioctl  = blkif_ioctl,
#if 0
    check_media_change: blkif_check,
    revalidate:         blkif_revalidate,
#endif
};

spinlock_t blkif_io_lock = SPIN_LOCK_UNLOCKED;

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

    free_page((unsigned long)buf);

    return nr;
}

static struct xlbd_major_info *xlbd_get_major_info(int xd_device, int *minor)
{
    int mi_idx, new_major;
    int xd_major = MAJOR_XEN(xd_device); 
    int xd_minor = MINOR_XEN(xd_device);

    *minor = xd_minor;

    switch (xd_major) {
    case IDE0_MAJOR: mi_idx = 0; new_major = IDE0_MAJOR; break;
    case IDE1_MAJOR: mi_idx = 1; new_major = IDE1_MAJOR; break;
    case IDE2_MAJOR: mi_idx = 2; new_major = IDE2_MAJOR; break;
    case IDE3_MAJOR: mi_idx = 3; new_major = IDE3_MAJOR; break;
    case IDE4_MAJOR: mi_idx = 4; new_major = IDE4_MAJOR; break;
    case IDE5_MAJOR: mi_idx = 5; new_major = IDE5_MAJOR; break;
    case IDE6_MAJOR: mi_idx = 6; new_major = IDE6_MAJOR; break;
    case IDE7_MAJOR: mi_idx = 7; new_major = IDE7_MAJOR; break;
    case IDE8_MAJOR: mi_idx = 8; new_major = IDE8_MAJOR; break;
    case IDE9_MAJOR: mi_idx = 9; new_major = IDE9_MAJOR; break;
    case SCSI_DISK0_MAJOR: mi_idx = 10; new_major = SCSI_DISK0_MAJOR; break;
    case SCSI_DISK1_MAJOR ... SCSI_DISK7_MAJOR:
        mi_idx = 11 + xd_major - SCSI_DISK1_MAJOR;
        new_major = SCSI_DISK1_MAJOR + xd_major - SCSI_DISK1_MAJOR;
        break;
    case SCSI_CDROM_MAJOR: mi_idx = 18; new_major = SCSI_CDROM_MAJOR; break;
    default: mi_idx = 19; new_major = 0;/* XXXcl notyet */ break;
    }

    if (major_info[mi_idx])
        return major_info[mi_idx];

    major_info[mi_idx] = kmalloc(sizeof(struct xlbd_major_info), GFP_KERNEL);
    if (major_info[mi_idx] == NULL)
        return NULL;

    memset(major_info[mi_idx], 0, sizeof(struct xlbd_major_info));

    switch (mi_idx) {
    case 0 ... (NUM_IDE_MAJORS - 1):
        major_info[mi_idx]->type = &xlbd_ide_type;
        major_info[mi_idx]->index = mi_idx;
        break;
    case NUM_IDE_MAJORS ... (NUM_IDE_MAJORS + NUM_SCSI_MAJORS - 1):
        major_info[mi_idx]->type = &xlbd_scsi_type;
        major_info[mi_idx]->index = mi_idx - NUM_IDE_MAJORS;
        break;
        case (NUM_IDE_MAJORS + NUM_SCSI_MAJORS) ...
            (NUM_IDE_MAJORS + NUM_SCSI_MAJORS + NUM_VBD_MAJORS - 1):
                major_info[mi_idx]->type = &xlbd_vbd_type;
        major_info[mi_idx]->index = mi_idx -
            (NUM_IDE_MAJORS + NUM_SCSI_MAJORS);
        break;
    }
    major_info[mi_idx]->major = new_major;

    if (register_blkdev(major_info[mi_idx]->major, major_info[mi_idx]->type->name)) {
        printk(KERN_ALERT "XL VBD: can't get major %d with name %s\n",
               major_info[mi_idx]->major, major_info[mi_idx]->type->name);
        goto out;
    }

    devfs_mk_dir(major_info[mi_idx]->type->name);

    return major_info[mi_idx];

 out:
    kfree(major_info[mi_idx]);
    major_info[mi_idx] = NULL;
    return NULL;
}

static struct gendisk *xlvbd_get_gendisk(struct xlbd_major_info *mi,
                                         int xd_minor, vdisk_t *xd)
{
    struct gendisk *gd;
    struct xlbd_disk_info *di;
    int device, partno;

    device = MKDEV(mi->major, xd_minor);
    gd = get_gendisk(device, &partno);
    if ( gd != NULL )
        return gd;

    di = kmalloc(sizeof(struct xlbd_disk_info), GFP_KERNEL);
    if ( di == NULL )
        return NULL;
    di->mi = mi;
    di->xd_device = xd->device;

    /* Construct an appropriate gendisk structure. */
    gd = alloc_disk(1);
    if ( gd == NULL )
        goto out;

    gd->major = mi->major;
    gd->first_minor = xd_minor;
    gd->fops = &xlvbd_block_fops;
    gd->private_data = di;
    sprintf(gd->disk_name, "%s%c%d", mi->type->name,
            'a' + mi->index * mi->type->partn_per_major +
            (xd_minor >> mi->type->partn_shift),
            xd_minor & ((1 << mi->type->partn_shift) - 1));

    set_capacity(gd, xd->capacity);

    if ( xlbd_blk_queue == NULL )
    {
        xlbd_blk_queue = blk_init_queue(do_blkif_request,
                                        &blkif_io_lock);
        if ( xlbd_blk_queue == NULL )
            goto out;
        elevator_init(xlbd_blk_queue, "noop");

        /*
         * Turn off barking 'headactive' mode. We dequeue
         * buffer heads as soon as we pass them to back-end
         * driver.
         */
        blk_queue_headactive(xlbd_blk_queue, 0);

        /* Hard sector size and max sectors impersonate the equiv. hardware. */
        blk_queue_hardsect_size(
            xlbd_blk_queue, mi->type->hardsect_size);
        blk_queue_max_sectors(
            xlbd_blk_queue, mi->type->max_sectors);

        /* Each segment in a request is up to an aligned page in size. */
        blk_queue_segment_boundary(xlbd_blk_queue, PAGE_SIZE - 1);
        blk_queue_max_segment_size(xlbd_blk_queue, PAGE_SIZE);

        /* Ensure a merged request will fit in a single I/O ring slot. */
        blk_queue_max_phys_segments(
            xlbd_blk_queue, BLKIF_MAX_SEGMENTS_PER_REQUEST);
        blk_queue_max_hw_segments(
            xlbd_blk_queue, BLKIF_MAX_SEGMENTS_PER_REQUEST);

        /* Make sure buffer addresses are sector-aligned. */
        blk_queue_dma_alignment(xlbd_blk_queue, 511);
    }
    gd->queue = xlbd_blk_queue;

    add_disk(gd);

    return gd;

 out:
    if ( gd != NULL )
        del_gendisk(gd);
    kfree(di);
    return NULL;
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
    struct block_device *bd;
    struct gendisk *gd;
    struct xlbd_major_info *mi;
    int device;
    int minor;

    int err = -ENOMEM;

    mi = xlbd_get_major_info(xd->device, &minor);
    if (mi == NULL)
        return -EPERM;

    device = MKDEV(mi->major, minor);

    if ((bd = bdget(device)) == NULL)
        return -EPERM;

    /*
     * Update of partition info, and check of usage count, is protected
     * by the per-block-device semaphore.
     */
    down(&bd->bd_sem);

    gd = xlvbd_get_gendisk(mi, minor, xd);
    if (mi == NULL) {
        err = -EPERM;
        goto out;
    }

    if (VDISK_READONLY(xd->info))
        set_disk_ro(gd, 1); 

    /* Some final fix-ups depending on the device type */
    switch (VDISK_TYPE(xd->info)) { 
    case VDISK_TYPE_CDROM:
        gd->flags |= GENHD_FL_REMOVABLE | GENHD_FL_CD; 
        /* FALLTHROUGH */
    case VDISK_TYPE_FLOPPY: 
    case VDISK_TYPE_TAPE:
        gd->flags |= GENHD_FL_REMOVABLE; 
        break; 

    case VDISK_TYPE_DISK:
        break; 

    default:
        printk(KERN_ALERT "XenLinux: unknown device type %d\n", 
               VDISK_TYPE(xd->info)); 
        break; 
    }

    err = 0;
 out:
    up(&bd->bd_sem);
    bdput(bd);    
    return err;
}

#if 0
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
    xen_block_t *disk = NULL;

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
    if ( unlikely(new_nr = xlvbd_get_vbd_info(new_info)) < 0 )
    {
        kfree(new_info);
        return;
    }

    /*
     * Final list maximum size is old list + new list. This occurs only when
     * old list and new list do not overlap at all, and we cannot yet destroy
     * VBDs in the old list because the usage counts are busy.
     */
    merged_info = kmalloc((old_nr + new_nr) * sizeof(vdisk_t), GFP_KERNEL);

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
    kfree(new_info);
}
#endif

/*
 * Set up all the linux device goop for the virtual block devices
 * (vbd's) that we know about. Note that although from the backend
 * driver's p.o.v. VBDs are addressed simply an opaque 16-bit device
 * number, the domain creation tools conventionally allocate these
 * numbers to correspond to those used by 'real' linux -- this is just
 * for convenience as it means e.g. that the same /etc/fstab can be
 * used when booting with or without Xen.
 */
int xlvbd_init(void)
{
    int i;

    /*
     * If compiled as a module, we don't support unloading yet. We
     * therefore permanently increment the reference count to
     * disallow it.
     */
    /* MOD_INC_USE_COUNT; */

    memset(major_info, 0, sizeof(major_info));

    for (i = 0; i < sizeof(major_info) / sizeof(major_info[0]); i++) {
    }

    vbd_info = kmalloc(MAX_VBDS * sizeof(vdisk_t), GFP_KERNEL);
    nr_vbds  = xlvbd_get_vbd_info(vbd_info);

    if (nr_vbds < 0) {
        kfree(vbd_info);
        vbd_info = NULL;
        nr_vbds  = 0;
    } else {
        for (i = 0; i < nr_vbds; i++)
            xlvbd_init_device(&vbd_info[i]);
    }

    return 0;
}
