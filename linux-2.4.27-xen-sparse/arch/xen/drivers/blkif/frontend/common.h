/******************************************************************************
 * arch/xen/drivers/blkif/frontend/common.h
 * 
 * Shared definitions between all levels of XenoLinux Virtual block devices.
 */

#ifndef __XEN_DRIVERS_COMMON_H__
#define __XEN_DRIVERS_COMMON_H__

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
#include <asm/xen-public/xen.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <asm/xen-public/io/blkif.h>

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

/* Private gendisk->flags[] values. */
#define GENHD_FL_XEN        2 /* Is unit a Xen block device?  */
#define GENHD_FL_VIRT_PARTNS 4 /* Are unit partitions virtual? */

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.
 * They hang in an array off the gendisk structure. We may end up putting
 * all kinds of interesting stuff here :-)
 */
typedef struct xl_disk {
    int usage;
} xl_disk_t;

extern int blkif_open(struct inode *inode, struct file *filep);
extern int blkif_release(struct inode *inode, struct file *filep);
extern int blkif_ioctl(struct inode *inode, struct file *filep,
                                 unsigned command, unsigned long argument);
extern int blkif_check(kdev_t dev);
extern int blkif_revalidate(kdev_t dev);
extern void blkif_control_send(blkif_request_t *req, blkif_response_t *rsp);
extern void do_blkif_request (request_queue_t *rq); 

extern void xlvbd_update_vbds(void);

static inline xl_disk_t *xldev_to_xldisk(kdev_t xldev)
{
    struct gendisk *gd = get_gendisk(xldev);
    
    if ( gd == NULL ) 
        return NULL;
    
    return (xl_disk_t *)gd->real_devices + 
        (MINOR(xldev) >> gd->minor_shift);
}


/* Virtual block-device subsystem. */
extern int  xlvbd_init(void);
extern void xlvbd_cleanup(void); 

#endif /* __XEN_DRIVERS_COMMON_H__ */
