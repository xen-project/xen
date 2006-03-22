/******************************************************************************
 * vbd.c
 * 
 * XenLinux virtual block-device driver (xvd).
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Modifications by Mark A. Williamson are (c) Intel Research Cambridge
 * Copyright (c) 2004-2005, Christian Limpach
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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

#define BLKIF_MAJOR(dev) ((dev)>>8)
#define BLKIF_MINOR(dev) ((dev) & 0xff)

/*
 * For convenience we distinguish between ide, scsi and 'other' (i.e.,
 * potentially combinations of the two) in the naming scheme and in a few other
 * places.
 */

#define NUM_IDE_MAJORS 10
#define NUM_SCSI_MAJORS 9
#define NUM_VBD_MAJORS 1

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

#define XLBD_MAJOR_IDE_START	0
#define XLBD_MAJOR_SCSI_START	(NUM_IDE_MAJORS)
#define XLBD_MAJOR_VBD_START	(NUM_IDE_MAJORS + NUM_SCSI_MAJORS)

#define XLBD_MAJOR_IDE_RANGE	XLBD_MAJOR_IDE_START ... XLBD_MAJOR_SCSI_START - 1
#define XLBD_MAJOR_SCSI_RANGE	XLBD_MAJOR_SCSI_START ... XLBD_MAJOR_VBD_START - 1
#define XLBD_MAJOR_VBD_RANGE	XLBD_MAJOR_VBD_START ... XLBD_MAJOR_VBD_START + NUM_VBD_MAJORS - 1

/* Information about our VBDs. */
#define MAX_VBDS 64
static LIST_HEAD(vbds_list);

static struct block_device_operations xlvbd_block_fops =
{
	.owner = THIS_MODULE,
	.open = blkif_open,
	.release = blkif_release,
	.ioctl  = blkif_ioctl,
};

spinlock_t blkif_io_lock = SPIN_LOCK_UNLOCKED;

static struct xlbd_major_info *
xlbd_alloc_major_info(int major, int minor, int index)
{
	struct xlbd_major_info *ptr;

	ptr = kzalloc(sizeof(struct xlbd_major_info), GFP_KERNEL);
	if (ptr == NULL)
		return NULL;

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

	printk("Registering block device major %i\n", ptr->major);
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

static struct xlbd_major_info *
xlbd_get_major_info(int vdevice)
{
	struct xlbd_major_info *mi;
	int major, minor, index;

	major = BLKIF_MAJOR(vdevice);
	minor = BLKIF_MINOR(vdevice);

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

	mi = ((major_info[index] != NULL) ? major_info[index] :
	      xlbd_alloc_major_info(major, minor, index));
	if (mi)
		mi->usage++;
	return mi;
}

static void
xlbd_put_major_info(struct xlbd_major_info *mi)
{
	mi->usage--;
	/* XXX: release major if 0 */
}

static int
xlvbd_init_blk_queue(struct gendisk *gd, u16 sector_size)
{
	request_queue_t *rq;

	rq = blk_init_queue(do_blkif_request, &blkif_io_lock);
	if (rq == NULL)
		return -1;

	elevator_init(rq, "noop");

	/* Hard sector size and max sectors impersonate the equiv. hardware. */
	blk_queue_hardsect_size(rq, sector_size);
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

static int
xlvbd_alloc_gendisk(int minor, blkif_sector_t capacity, int vdevice,
		    u16 vdisk_info, u16 sector_size,
		    struct blkfront_info *info)
{
	struct gendisk *gd;
	struct xlbd_major_info *mi;
	int nr_minors = 1;
	int err = -ENODEV;

	BUG_ON(info->gd != NULL);
	BUG_ON(info->mi != NULL);
	BUG_ON(info->rq != NULL);

	mi = xlbd_get_major_info(vdevice);
	if (mi == NULL)
		goto out;
	info->mi = mi;

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
	gd->private_data = info;
	gd->driverfs_dev = &(info->xbdev->dev);
	set_capacity(gd, capacity);

	if (xlvbd_init_blk_queue(gd, sector_size)) {
		del_gendisk(gd);
		goto out;
	}

	info->rq = gd->queue;

	if (vdisk_info & VDISK_READONLY)
		set_disk_ro(gd, 1);

	if (vdisk_info & VDISK_REMOVABLE)
		gd->flags |= GENHD_FL_REMOVABLE;

	if (vdisk_info & VDISK_CDROM)
		gd->flags |= GENHD_FL_CD;

	info->gd = gd;

	return 0;

 out:
	if (mi)
		xlbd_put_major_info(mi);
	info->mi = NULL;
	return err;
}

int
xlvbd_add(blkif_sector_t capacity, int vdevice, u16 vdisk_info,
	  u16 sector_size, struct blkfront_info *info)
{
	struct block_device *bd;
	int err = 0;

	info->dev = MKDEV(BLKIF_MAJOR(vdevice), BLKIF_MINOR(vdevice));

	bd = bdget(info->dev);
	if (bd == NULL)
		return -ENODEV;

	err = xlvbd_alloc_gendisk(BLKIF_MINOR(vdevice), capacity, vdevice,
				  vdisk_info, sector_size, info);

	bdput(bd);
	return err;
}

void
xlvbd_del(struct blkfront_info *info)
{
	if (info->mi == NULL)
		return;

	BUG_ON(info->gd == NULL);
	del_gendisk(info->gd);
	put_disk(info->gd);
	info->gd = NULL;

	xlbd_put_major_info(info->mi);
	info->mi = NULL;

	BUG_ON(info->rq == NULL);
	blk_cleanup_queue(info->rq);
	info->rq = NULL;
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
