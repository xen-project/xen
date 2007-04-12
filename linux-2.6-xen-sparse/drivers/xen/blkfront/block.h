/******************************************************************************
 * block.h
 * 
 * Shared definitions between all levels of XenLinux Virtual block devices.
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

#ifndef __XEN_DRIVERS_BLOCK_H__
#define __XEN_DRIVERS_BLOCK_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/blkdev.h>
#include <linux/major.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <xen/gnttab.h>
#include <xen/interface/xen.h>
#include <xen/interface/io/blkif.h>
#include <xen/interface/io/ring.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#define DPRINTK(_f, _a...) pr_debug(_f, ## _a)

#if 0
#define DPRINTK_IOCTL(_f, _a...) printk(KERN_ALERT _f, ## _a)
#else
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

struct xlbd_type_info
{
	int partn_shift;
	int disks_per_major;
	char *devname;
	char *diskname;
};

struct xlbd_major_info
{
	int major;
	int index;
	int usage;
	struct xlbd_type_info *type;
};

struct blk_shadow {
	blkif_request_t req;
	unsigned long request;
	unsigned long frame[BLKIF_MAX_SEGMENTS_PER_REQUEST];
};

#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
struct blkfront_info
{
	struct xenbus_device *xbdev;
	dev_t dev;
 	struct gendisk *gd;
	int vdevice;
	blkif_vdev_t handle;
	int connected;
	int ring_ref;
	blkif_front_ring_t ring;
	unsigned int irq;
	struct xlbd_major_info *mi;
	request_queue_t *rq;
	struct work_struct work;
	struct gnttab_free_callback callback;
	struct blk_shadow shadow[BLK_RING_SIZE];
	unsigned long shadow_free;
	int feature_barrier;

	/**
	 * The number of people holding this device open.  We won't allow a
	 * hot-unplug unless this is 0.
	 */
	int users;
};

extern spinlock_t blkif_io_lock;

extern int blkif_open(struct inode *inode, struct file *filep);
extern int blkif_release(struct inode *inode, struct file *filep);
extern int blkif_ioctl(struct inode *inode, struct file *filep,
		       unsigned command, unsigned long argument);
extern int blkif_getgeo(struct block_device *, struct hd_geometry *);
extern int blkif_check(dev_t dev);
extern int blkif_revalidate(dev_t dev);
extern void do_blkif_request (request_queue_t *rq);

/* Virtual block-device subsystem. */
/* Note that xlvbd_add doesn't call add_disk for you: you're expected
   to call add_disk on info->gd once the disk is properly connected
   up. */
int xlvbd_add(blkif_sector_t capacity, int device,
	      u16 vdisk_info, u16 sector_size, struct blkfront_info *info);
void xlvbd_del(struct blkfront_info *info);
int xlvbd_barrier(struct blkfront_info *info);

#endif /* __XEN_DRIVERS_BLOCK_H__ */
