/******************************************************************************
 * vbd.c
 * 
 * XenLinux virtual block-device driver (xvd).
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004-2005, Christian Limpach
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
#include <linux/list.h>

/*
 * For convenience we distinguish between ide, scsi and 'other' (i.e.,
 * potentially combinations of the two) in the naming scheme and in a few other
 * places.
 */

#define NUM_IDE_MAJORS 10
#define NUM_SCSI_MAJORS 9
#define NUM_VBD_MAJORS 1

struct lvdisk
{
    blkif_sector_t capacity; /*  0: Size in terms of 512-byte sectors.   */
    blkif_vdev_t   device;   /*  8: Device number (opaque 16 bit value). */
    u16            info; 
    struct list_head list;
};

static struct xlbd_type_info xlbd_ide_type = {
    .partn_shift = 6,
    .disks_per_major = 2,
    .devname = "ide",
    .diskname = "hd",
};

static struct xlbd_type_info xlbd_scsi_type = {
    .partn_shift = 4,
    .disks_per_major = 16,
    .devname = "sd",
    .diskname = "sd",
};

static struct xlbd_type_info xlbd_vbd_type = {
    .partn_shift = 4,
    .disks_per_major = 16,
    .devname = "xvd",
    .diskname = "xvd",
};

static struct xlbd_major_info *major_info[NUM_IDE_MAJORS + NUM_SCSI_MAJORS +
                                         NUM_VBD_MAJORS];

#define XLBD_MAJOR_IDE_START    0
#define XLBD_MAJOR_SCSI_START   (NUM_IDE_MAJORS)
#define XLBD_MAJOR_VBD_START    (NUM_IDE_MAJORS + NUM_SCSI_MAJORS)

#define XLBD_MAJOR_IDE_RANGE    XLBD_MAJOR_IDE_START ... XLBD_MAJOR_SCSI_START - 1
#define XLBD_MAJOR_SCSI_RANGE   XLBD_MAJOR_SCSI_START ... XLBD_MAJOR_VBD_START - 1
#define XLBD_MAJOR_VBD_RANGE    XLBD_MAJOR_VBD_START ... XLBD_MAJOR_VBD_START + NUM_VBD_MAJORS - 1

/* Information about our VBDs. */
#define MAX_VBDS 64
struct list_head vbds_list;

#define MAJOR_XEN(dev) ((dev)>>8)
#define MINOR_XEN(dev) ((dev) & 0xff)

static struct block_device_operations xlvbd_block_fops = 
{
    .owner  = THIS_MODULE,
    .open  = blkif_open,
    .release = blkif_release,
    .ioctl  = blkif_ioctl,
};

spinlock_t blkif_io_lock = SPIN_LOCK_UNLOCKED;

static struct lvdisk *xlvbd_device_alloc(void)
{
    struct lvdisk *disk;

    disk = kmalloc(sizeof(*disk), GFP_KERNEL);
    if (disk != NULL) {
        memset(disk, 0, sizeof(*disk));
        INIT_LIST_HEAD(&disk->list);
    }
    return disk;
}

static void xlvbd_device_free(struct lvdisk *disk)
{
    list_del(&disk->list);
    kfree(disk);
}

static vdisk_t *xlvbd_probe(int *ret)
{
    blkif_response_t rsp;
    blkif_request_t req;
    vdisk_t *disk_info = NULL;
    unsigned long buf;
    int nr;

    buf = __get_free_page(GFP_KERNEL);
    if ((void *)buf == NULL)
        goto out;

    memset(&req, 0, sizeof(req));
    req.operation = BLKIF_OP_PROBE;
    req.nr_segments = 1;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    blkif_control_probe_send(&req, &rsp,
                             (unsigned long)(virt_to_machine(buf)));
#else
    req.frame_and_sects[0] = blkif_fas(virt_to_machine(buf), 0, (PAGE_SIZE/512)-1);

    blkif_control_send(&req, &rsp);
#endif
    if ( rsp.status <= 0 ) {
        WPRINTK("Could not probe disks (%d)\n", rsp.status);
        goto out;
    }
    nr = rsp.status;
    if ( nr > MAX_VBDS )
        nr = MAX_VBDS;

    disk_info = kmalloc(nr * sizeof(vdisk_t), GFP_KERNEL);
    if (disk_info != NULL)
        memcpy(disk_info, (void *) buf, nr * sizeof(vdisk_t));

    if (ret != NULL)
        *ret = nr;

out:
    free_page(buf);
    return disk_info;
}

static struct xlbd_major_info *xlbd_alloc_major_info(
    int major, int minor, int index)
{
    struct xlbd_major_info *ptr;

    ptr = kmalloc(sizeof(struct xlbd_major_info), GFP_KERNEL);
    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(struct xlbd_major_info));

    ptr->major = major;

    switch (index) {
    case XLBD_MAJOR_IDE_RANGE:
        ptr->type = &xlbd_ide_type;
        ptr->index = index - XLBD_MAJOR_IDE_START;
        break;
    case XLBD_MAJOR_SCSI_RANGE:
        ptr->type = &xlbd_scsi_type;
        ptr->index = index - XLBD_MAJOR_SCSI_START;
        break;
    case XLBD_MAJOR_VBD_RANGE:
        ptr->type = &xlbd_vbd_type;
        ptr->index = index - XLBD_MAJOR_VBD_START;
        break;
    }
    
    if (register_blkdev(ptr->major, ptr->type->devname)) {
        WPRINTK("can't get major %d with name %s\n",
                ptr->major, ptr->type->devname);
        kfree(ptr);
        return NULL;
    }

    devfs_mk_dir(ptr->type->devname);
    major_info[index] = ptr;
    return ptr;
}

static struct xlbd_major_info *xlbd_get_major_info(int device)
{
    int major, minor, index;

    major = MAJOR_XEN(device);
    minor = MINOR_XEN(device);

    switch (major) {
    case IDE0_MAJOR: index = 0; break;
    case IDE1_MAJOR: index = 1; break;
    case IDE2_MAJOR: index = 2; break;
    case IDE3_MAJOR: index = 3; break;
    case IDE4_MAJOR: index = 4; break;
    case IDE5_MAJOR: index = 5; break;
    case IDE6_MAJOR: index = 6; break;
    case IDE7_MAJOR: index = 7; break;
    case IDE8_MAJOR: index = 8; break;
    case IDE9_MAJOR: index = 9; break;
    case SCSI_DISK0_MAJOR: index = 10; break;
    case SCSI_DISK1_MAJOR ... SCSI_DISK7_MAJOR:
        index = 11 + major - SCSI_DISK1_MAJOR;
        break;
    case SCSI_CDROM_MAJOR: index = 18; break;
    default: index = 19; break;
    }

    return ((major_info[index] != NULL) ? major_info[index] :
            xlbd_alloc_major_info(major, minor, index));
}

static int xlvbd_init_blk_queue(struct gendisk *gd, vdisk_t *disk)
{
    request_queue_t *rq;

    rq = blk_init_queue(do_blkif_request, &blkif_io_lock);
    if (rq == NULL)
        return -1;

    elevator_init(rq, "noop");

    /* Hard sector size and max sectors impersonate the equiv. hardware. */
    blk_queue_hardsect_size(rq, disk->sector_size);
    blk_queue_max_sectors(rq, 512);

    /* Each segment in a request is up to an aligned page in size. */
    blk_queue_segment_boundary(rq, PAGE_SIZE - 1);
    blk_queue_max_segment_size(rq, PAGE_SIZE);

    /* Ensure a merged request will fit in a single I/O ring slot. */
    blk_queue_max_phys_segments(rq, BLKIF_MAX_SEGMENTS_PER_REQUEST);
    blk_queue_max_hw_segments(rq, BLKIF_MAX_SEGMENTS_PER_REQUEST);

    /* Make sure buffer addresses are sector-aligned. */
    blk_queue_dma_alignment(rq, 511);

    gd->queue = rq;

    return 0;
}

struct gendisk *xlvbd_alloc_gendisk(
    struct xlbd_major_info *mi, int minor, vdisk_t *disk)
{
    struct gendisk *gd;
    struct xlbd_disk_info *di;
    int nr_minors = 1;

    di = kmalloc(sizeof(struct xlbd_disk_info), GFP_KERNEL);
    if (di == NULL)
        return NULL;
    memset(di, 0, sizeof(*di));
    di->mi = mi;
    di->xd_device = disk->device;

    if ((minor & ((1 << mi->type->partn_shift) - 1)) == 0)
        nr_minors = 1 << mi->type->partn_shift;

    gd = alloc_disk(nr_minors);
    if (gd == NULL)
        goto out;

    if (nr_minors > 1)
        sprintf(gd->disk_name, "%s%c", mi->type->diskname,
                'a' + mi->index * mi->type->disks_per_major +
                    (minor >> mi->type->partn_shift));
    else
        sprintf(gd->disk_name, "%s%c%d", mi->type->diskname,
                'a' + mi->index * mi->type->disks_per_major +
                (minor >> mi->type->partn_shift),
                minor & ((1 << mi->type->partn_shift) - 1));

    gd->major = mi->major;
    gd->first_minor = minor;
    gd->fops = &xlvbd_block_fops;
    gd->private_data = di;
    set_capacity(gd, disk->capacity);

    if (xlvbd_init_blk_queue(gd, disk)) {
        del_gendisk(gd);
        goto out;
    }

    di->rq = gd->queue;

    if (disk->info & VDISK_READONLY)
        set_disk_ro(gd, 1);

    if (disk->info & VDISK_REMOVABLE)
        gd->flags |= GENHD_FL_REMOVABLE;

    if (disk->info & VDISK_CDROM)
        gd->flags |= GENHD_FL_CD;

    add_disk(gd);

    return gd;

out:
    kfree(di);
    return NULL;
}

static int xlvbd_device_add(struct list_head *list, vdisk_t *disk)
{
    struct lvdisk *new;
    int minor;
    dev_t device;
    struct block_device *bd;
    struct gendisk *gd;
    struct xlbd_major_info *mi;

    mi = xlbd_get_major_info(disk->device);
    if (mi == NULL)
        return -EPERM;

    new = xlvbd_device_alloc();
    if (new == NULL)
        return -1;
    new->capacity = disk->capacity;
    new->device = disk->device;
    new->info = disk->info;
    
    minor = MINOR_XEN(disk->device);
    device = MKDEV(mi->major, minor);
    
    bd = bdget(device);
    if (bd == NULL)
        goto out;
    
    gd = xlvbd_alloc_gendisk(mi, minor, disk);
    if (gd == NULL)
        goto out_bd;

    list_add(&new->list, list);
out_bd:
    bdput(bd);
out:
    return 0;
}

static int xlvbd_device_del(struct lvdisk *disk)
{
    dev_t device;
    struct block_device *bd;
    struct gendisk *gd;
    struct xlbd_disk_info *di;
    int ret = 0, unused;
    request_queue_t *rq;

    device = MKDEV(MAJOR_XEN(disk->device), MINOR_XEN(disk->device));

    bd = bdget(device);
    if (bd == NULL)
        return -1;

    gd = get_gendisk(device, &unused);
    di = gd->private_data;

    if (di->mi->usage != 0) {
        WPRINTK("disk removal failed: used [dev=%x]\n", device);
        ret = -1;
        goto out;
    }

    rq = gd->queue;
    del_gendisk(gd);
    put_disk(gd);
    blk_cleanup_queue(rq);

    xlvbd_device_free(disk);
out:
    bdput(bd);
    return ret;
}

static int xlvbd_device_update(struct lvdisk *ldisk, vdisk_t *disk)
{
    dev_t device;
    struct block_device *bd;
    struct gendisk *gd;
    int unused;

    if ((ldisk->capacity == disk->capacity) && (ldisk->info == disk->info))
        return 0;    

    device = MKDEV(MAJOR_XEN(ldisk->device), MINOR_XEN(ldisk->device));

    bd = bdget(device);
    if (bd == NULL)
        return -1;

    gd = get_gendisk(device, &unused);
    set_capacity(gd, disk->capacity);    
    ldisk->capacity = disk->capacity;

    bdput(bd);

    return 0;
}

void xlvbd_refresh(void)
{
    vdisk_t *newdisks;
    struct list_head *tmp, *tmp2;
    struct lvdisk *disk;
    int i, nr;

    newdisks = xlvbd_probe(&nr);
    if (newdisks == NULL) {
        WPRINTK("failed to probe\n");
        return;
    }
    
    i = 0;
    list_for_each_safe(tmp, tmp2, &vbds_list) {
        disk = list_entry(tmp, struct lvdisk, list);
        
        for (i = 0; i < nr; i++) {
            if ( !newdisks[i].device )
                continue;
            if ( disk->device == newdisks[i].device ) {
                xlvbd_device_update(disk, &newdisks[i]);
                newdisks[i].device = 0;
                break;
            }
        }
        if (i == nr) {
            xlvbd_device_del(disk);
            newdisks[i].device = 0;
        }
    }
    for (i = 0; i < nr; i++)
        if ( newdisks[i].device )
            xlvbd_device_add(&vbds_list, &newdisks[i]);
    kfree(newdisks);
}

/*
 * xlvbd_update_vbds - reprobes the VBD status and performs updates driver
 * state. The VBDs need to be updated in this way when the domain is
 * initialised and also each time we receive an XLBLK_UPDATE event.
 */
void xlvbd_update_vbds(void)
{
    xlvbd_refresh();
}

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
    int i, nr;
    vdisk_t *disks;

    INIT_LIST_HEAD(&vbds_list);

    memset(major_info, 0, sizeof(major_info));
    
    disks = xlvbd_probe(&nr);
    if (disks == NULL) {
        WPRINTK("failed to probe\n");
        return -1;
    }

    for (i = 0; i < nr; i++)
        xlvbd_device_add(&vbds_list, &disks[i]);

    kfree(disks);
    return 0;
}
