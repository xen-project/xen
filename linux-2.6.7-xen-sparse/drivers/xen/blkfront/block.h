/******************************************************************************
 * block.h
 * 
 * Shared definitions between all levels of XenLinux Virtual block devices.
 */

#ifndef __XEN_DRIVERS_BLOCK_H__
#define __XEN_DRIVERS_BLOCK_H__

#include <linux/config.h>
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
#include <linux/devfs_fs_kernel.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm-xen/hypervisor-ifs/io/blkif.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#if 0
#define DPRINTK(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif

#if 0
#define DPRINTK_IOCTL(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

struct xlbd_type_info {
	int partn_shift;
	int devs_per_major;
	int hardsect_size;
	int max_sectors;
	char *name;
};

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
struct xlbd_major_info {
	int major;
	int usage;
	int xd_device;
	struct xlbd_type_info *type;
};

struct xlbd_disk_info {
	int xd_device;
	struct xlbd_major_info *mi;
};

typedef struct xen_block {
	int usage;
} xen_block_t;

extern struct request_queue *xlbd_blk_queue;
extern spinlock_t blkif_io_lock;

extern int blkif_open(struct inode *inode, struct file *filep);
extern int blkif_release(struct inode *inode, struct file *filep);
extern int blkif_ioctl(struct inode *inode, struct file *filep,
                           unsigned command, unsigned long argument);
extern int blkif_check(dev_t dev);
extern int blkif_revalidate(dev_t dev);
extern void blkif_control_send(blkif_request_t *req, blkif_response_t *rsp);
extern void do_blkif_request (request_queue_t *rq); 

extern void xlvbd_update_vbds(void);

/* Virtual block-device subsystem. */
extern int  xlvbd_init(void);
extern void xlvbd_cleanup(void); 

#endif /* __XEN_DRIVERS_BLOCK_H__ */
