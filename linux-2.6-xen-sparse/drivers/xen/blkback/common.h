/* 
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

#ifndef __BLKIF__BACKEND__COMMON_H__
#define __BLKIF__BACKEND__COMMON_H__

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <xen/evtchn.h>
#include <asm/hypervisor.h>
#include <xen/interface/io/blkif.h>
#include <xen/interface/io/ring.h>
#include <xen/gnttab.h>
#include <xen/driver_util.h>

#define DPRINTK(_f, _a...) pr_debug("(file=%s, line=%d) " _f, \
                                    __FILE__ , __LINE__ , ## _a )

struct vbd {
	blkif_vdev_t   handle;      /* what the domain refers to this vbd as */
	unsigned char  readonly;    /* Non-zero -> read-only */
	unsigned char  type;        /* VDISK_xxx */
	u32            pdevice;     /* phys device that this vbd maps to */
	struct block_device *bdev;
}; 

struct backend_info; 

typedef struct blkif_st {
	/* Unique identifier for this interface. */
	domid_t           domid;
	unsigned int      handle;
	/* Physical parameters of the comms window. */
	unsigned int      evtchn;
	unsigned int      irq;
	/* Comms information. */
	blkif_back_ring_t blk_ring;
	struct vm_struct *blk_ring_area;
	/* The VBD attached to this interface. */
	struct vbd        vbd;
	/* Back pointer to the backend_info. */
	struct backend_info *be; 
	/* Private fields. */
	enum { DISCONNECTED, CONNECTED } status;
#ifdef CONFIG_XEN_BLKDEV_TAP_BE
	/* Is this a blktap frontend */
	unsigned int     is_blktap;
#endif
	spinlock_t       blk_ring_lock;
	atomic_t         refcnt;

	wait_queue_head_t   wq;
	struct task_struct  *xenblkd;
	atomic_t            io_pending;
	request_queue_t     *plug;

	/* statistics */
	unsigned long       st_print;
	int                 st_rd_req;
	int                 st_wr_req;
	int                 st_oo_req;

	struct work_struct free_work;

	grant_handle_t shmem_handle;
	grant_ref_t    shmem_ref;
} blkif_t;

blkif_t *alloc_blkif(domid_t domid);
void free_blkif_callback(blkif_t *blkif);
int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn);

#define blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define blkif_put(_b)					\
	do {						\
		if (atomic_dec_and_test(&(_b)->refcnt))	\
			free_blkif_callback(_b);	\
	} while (0)

/* Create a vbd. */
int vbd_create(blkif_t *blkif, blkif_vdev_t vdevice, unsigned major,
	       unsigned minor, int readonly);
void vbd_free(struct vbd *vbd);

unsigned long vbd_size(struct vbd *vbd);
unsigned int vbd_info(struct vbd *vbd);
unsigned long vbd_secsize(struct vbd *vbd);

struct phys_req {
	unsigned short       dev;
	unsigned short       nr_sects;
	struct block_device *bdev;
	blkif_sector_t       sector_number;
};

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation); 

void blkif_interface_init(void);

void blkif_xenbus_init(void);

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs);
int blkif_schedule(void *arg);

void update_blkif_status(blkif_t *blkif); 

#endif /* __BLKIF__BACKEND__COMMON_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
