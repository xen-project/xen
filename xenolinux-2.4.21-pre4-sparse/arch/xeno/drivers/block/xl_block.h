/******************************************************************************
 * xl_block.h
 * 
 * Shared definitions between all levels of XenoLinux Virtual block devices.
 */

#ifndef __XL_BLOCK_H__
#define __XL_BLOCK_H__

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

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#if 0
#define DPRINTK(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#define DPRINTK_IOCTL(_f, _a...) printk ( KERN_ALERT _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#define DPRINTK_IOCTL(_f, _a...) ((void)0)
#endif

/*
 * We have one of these per XL-IDE, XL-SCSI, and XL-VIRT device.
 * They hang in an array off the gendisk structure. We may end up putting
 * all kinds of interesting stuff here :-)
 */
typedef struct xl_disk {
    int usage;
    unsigned long capacity;
} xl_disk_t;

/* Generic layer. */
extern int xenolinux_control_msg(int operration, char *buffer);
extern int xenolinux_block_open(struct inode *inode, struct file *filep);
extern int xenolinux_block_release(struct inode *inode, struct file *filep);
extern int xenolinux_block_ioctl(struct inode *inode, struct file *filep,
				 unsigned command, unsigned long argument);
extern int xenolinux_block_check(kdev_t dev);
extern int xenolinux_block_revalidate(kdev_t dev);
extern void do_xlblk_request (request_queue_t *rq); 

/* Fake IDE subsystem. */
extern int  xlide_init(xen_disk_info_t *xdi);
extern int  xlide_hwsect(int minor); 
extern void xlide_cleanup(void); 
extern struct gendisk *xlide_gendisk;

/* Fake SCSI subsystem. */
extern int  xlscsi_init(xen_disk_info_t *xdi);
extern int  xlscsi_hwsect(int minor); 
extern void xlscsi_cleanup(void); 
extern struct gendisk *xlscsi_gendisk;

/* Virtual block-device subsystem. */
extern int  xlsegment_hwsect(int minor); 
extern struct gendisk *xlsegment_gendisk;

#endif /* __XL_BLOCK_H__ */
