/******************************************************************************
 * drivers/xen/blktap/blktap.c
 * 
 * Back-end driver for user level virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. Requests
 * are remapped to a user-space memory region.
 *
 * Based on the blkback driver code.
 * 
 * Copyright (c) 2004-2005, Andrew Warfield and Julian Chesterfield
 *
 * Clean ups and fix ups:
 *    Copyright (c) 2006, Steven Rostedt - Red Hat, Inc.
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

#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <asm/hypervisor.h>
#include "common.h"
#include <xen/balloon.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/gfp.h>
#include <linux/poll.h>
#include <asm/tlbflush.h>

#define MAX_TAP_DEV 256     /*the maximum number of tapdisk ring devices    */
#define MAX_DEV_NAME 100    /*the max tapdisk ring device name e.g. blktap0 */


struct class *xen_class;
EXPORT_SYMBOL_GPL(xen_class);

/*
 * Setup the xen class.  This should probably go in another file, but
 * since blktap is the only user of it so far, it gets to keep it.
 */
int setup_xen_class(void)
{
	int ret;

	if (xen_class)
		return 0;

	xen_class = class_create(THIS_MODULE, "xen");
	if ((ret = IS_ERR(xen_class))) {
		xen_class = NULL;
		return ret;
	}

	return 0;
}

/*
 * The maximum number of requests that can be outstanding at any time
 * is determined by 
 *
 *   [mmap_alloc * MAX_PENDING_REQS * BLKIF_MAX_SEGMENTS_PER_REQUEST] 
 *
 * where mmap_alloc < MAX_DYNAMIC_MEM.
 *
 * TODO:
 * mmap_alloc is initialised to 2 and should be adjustable on the fly via
 * sysfs.
 */
#define BLK_RING_SIZE		__RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)
#define MAX_DYNAMIC_MEM		BLK_RING_SIZE
#define MAX_PENDING_REQS	BLK_RING_SIZE
#define MMAP_PAGES (MAX_PENDING_REQS * BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define MMAP_VADDR(_start, _req,_seg)                                   \
        (_start +                                                       \
         ((_req) * BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE) +        \
         ((_seg) * PAGE_SIZE))
static int blkif_reqs = MAX_PENDING_REQS;
static int mmap_pages = MMAP_PAGES;

#define RING_PAGES 1 /* BLKTAP - immediately before the mmap area, we
		      * have a bunch of pages reserved for shared
		      * memory rings.
		      */

/*Data struct handed back to userspace for tapdisk device to VBD mapping*/
typedef struct domid_translate {
	unsigned short domid;
	unsigned short busid;
} domid_translate_t ;

/*Data struct associated with each of the tapdisk devices*/
typedef struct tap_blkif {
	struct vm_area_struct *vma;   /*Shared memory area                   */
	unsigned long rings_vstart;   /*Kernel memory mapping                */
	unsigned long user_vstart;    /*User memory mapping                  */
	unsigned long dev_inuse;      /*One process opens device at a time.  */
	unsigned long dev_pending;    /*In process of being opened           */
	unsigned long ring_ok;        /*make this ring->state                */
	blkif_front_ring_t ufe_ring;  /*Rings up to user space.              */
	wait_queue_head_t wait;       /*for poll                             */
	unsigned long mode;           /*current switching mode               */
	int minor;                    /*Minor number for tapdisk device      */
	pid_t pid;                    /*tapdisk process id                   */
	enum { RUNNING, CLEANSHUTDOWN } status; /*Detect a clean userspace 
						  shutdown                   */
	unsigned long *idx_map;       /*Record the user ring id to kern 
					[req id, idx] tuple                  */
	blkif_t *blkif;               /*Associate blkif with tapdev          */
	struct domid_translate trans; /*Translation from domid to bus.       */
} tap_blkif_t;

static struct tap_blkif *tapfds[MAX_TAP_DEV];
static int blktap_next_minor;

static int __init set_blkif_reqs(char *str)
{
	get_option(&str, &blkif_reqs);
	return 1;
}
__setup("blkif_reqs=", set_blkif_reqs);

/* Run-time switchable: /sys/module/blktap/parameters/ */
static unsigned int log_stats = 0;
static unsigned int debug_lvl = 0;
module_param(log_stats, int, 0644);
module_param(debug_lvl, int, 0644);

/*
 * Each outstanding request that we've passed to the lower device layers has a 
 * 'pending_req' allocated to it. Each buffer_head that completes decrements 
 * the pendcnt towards zero. When it hits zero, the specified domain has a 
 * response queued for it, with the saved 'id' passed back.
 */
typedef struct {
	blkif_t       *blkif;
	unsigned long  id;
	unsigned short mem_idx;
	int            nr_pages;
	atomic_t       pendcnt;
	unsigned short operation;
	int            status;
	struct list_head free_list;
	int            inuse;
} pending_req_t;

static pending_req_t *pending_reqs[MAX_PENDING_REQS];
static struct list_head pending_free;
static DEFINE_SPINLOCK(pending_free_lock);
static DECLARE_WAIT_QUEUE_HEAD (pending_free_wq);
static int alloc_pending_reqs;

typedef unsigned int PEND_RING_IDX;

static inline int MASK_PEND_IDX(int i) { 
	return (i & (MAX_PENDING_REQS-1));
}

static inline unsigned int RTN_PEND_IDX(pending_req_t *req, int idx) {
	return (req - pending_reqs[idx]);
}

#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

#define BLKBACK_INVALID_HANDLE (~0)

static struct page **foreign_pages[MAX_DYNAMIC_MEM];
static inline unsigned long idx_to_kaddr(
	unsigned int mmap_idx, unsigned int req_idx, unsigned int sg_idx)
{
	unsigned int arr_idx = req_idx*BLKIF_MAX_SEGMENTS_PER_REQUEST + sg_idx;
	unsigned long pfn = page_to_pfn(foreign_pages[mmap_idx][arr_idx]);
	return (unsigned long)pfn_to_kaddr(pfn);
}

static unsigned short mmap_alloc = 0;
static unsigned short mmap_lock = 0;
static unsigned short mmap_inuse = 0;

/******************************************************************
 * GRANT HANDLES
 */

/* When using grant tables to map a frame for device access then the
 * handle returned must be used to unmap the frame. This is needed to
 * drop the ref count on the frame.
 */
struct grant_handle_pair
{
        grant_handle_t kernel;
        grant_handle_t user;
};
#define INVALID_GRANT_HANDLE	0xFFFF

static struct grant_handle_pair 
    pending_grant_handles[MAX_DYNAMIC_MEM][MMAP_PAGES];
#define pending_handle(_id, _idx, _i) \
    (pending_grant_handles[_id][((_idx) * BLKIF_MAX_SEGMENTS_PER_REQUEST) \
    + (_i)])


static int blktap_read_ufe_ring(tap_blkif_t *info); /*local prototypes*/

#define BLKTAP_MINOR 0  /*/dev/xen/blktap has a dynamic major */
#define BLKTAP_DEV_DIR  "/dev/xen"

static int blktap_major;

/* blktap IOCTLs: */
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2 /* currently unused */
#define BLKTAP_IOCTL_SETMODE         3
#define BLKTAP_IOCTL_SENDPID	     4
#define BLKTAP_IOCTL_NEWINTF	     5
#define BLKTAP_IOCTL_MINOR	     6
#define BLKTAP_IOCTL_MAJOR	     7
#define BLKTAP_QUERY_ALLOC_REQS      8
#define BLKTAP_IOCTL_FREEINTF        9
#define BLKTAP_IOCTL_PRINT_IDXS      100  

/* blktap switching modes: (Set with BLKTAP_IOCTL_SETMODE)             */
#define BLKTAP_MODE_PASSTHROUGH      0x00000000  /* default            */
#define BLKTAP_MODE_INTERCEPT_FE     0x00000001
#define BLKTAP_MODE_INTERCEPT_BE     0x00000002  /* unimp.             */

#define BLKTAP_MODE_INTERPOSE \
           (BLKTAP_MODE_INTERCEPT_FE | BLKTAP_MODE_INTERCEPT_BE)


static inline int BLKTAP_MODE_VALID(unsigned long arg)
{
	return ((arg == BLKTAP_MODE_PASSTHROUGH ) ||
		(arg == BLKTAP_MODE_INTERCEPT_FE) ||
                (arg == BLKTAP_MODE_INTERPOSE   ));
}

/* Requests passing through the tap to userspace are re-assigned an ID.
 * We must record a mapping between the BE [IDX,ID] tuple and the userspace
 * ring ID. 
 */

static inline unsigned long MAKE_ID(domid_t fe_dom, PEND_RING_IDX idx)
{
        return ((fe_dom << 16) | MASK_PEND_IDX(idx));
}

extern inline PEND_RING_IDX ID_TO_IDX(unsigned long id)
{
        return (PEND_RING_IDX)(id & 0x0000ffff);
}

extern inline int ID_TO_MIDX(unsigned long id)
{
        return (int)(id >> 16);
}

#define INVALID_REQ 0xdead0000

/*TODO: Convert to a free list*/
static inline int GET_NEXT_REQ(unsigned long *idx_map)
{
	int i;
	for (i = 0; i < MAX_PENDING_REQS; i++)
		if (idx_map[i] == INVALID_REQ)
			return i;

	return INVALID_REQ;
}


#define BLKTAP_INVALID_HANDLE(_g) \
    (((_g->kernel) == INVALID_GRANT_HANDLE) &&  \
     ((_g->user) == INVALID_GRANT_HANDLE))

#define BLKTAP_INVALIDATE_HANDLE(_g) do {       \
    (_g)->kernel = INVALID_GRANT_HANDLE; (_g)->user = INVALID_GRANT_HANDLE; \
    } while(0)


/******************************************************************
 * BLKTAP VM OPS
 */

static struct page *blktap_nopage(struct vm_area_struct *vma,
				  unsigned long address,
				  int *type)
{
	/*
	 * if the page has not been mapped in by the driver then return
	 * NOPAGE_SIGBUS to the domain.
	 */

	return NOPAGE_SIGBUS;
}

struct vm_operations_struct blktap_vm_ops = {
	nopage:   blktap_nopage,
};

/******************************************************************
 * BLKTAP FILE OPS
 */
 
/*Function Declarations*/
static tap_blkif_t *get_next_free_dev(void);
static int blktap_open(struct inode *inode, struct file *filp);
static int blktap_release(struct inode *inode, struct file *filp);
static int blktap_mmap(struct file *filp, struct vm_area_struct *vma);
static int blktap_ioctl(struct inode *inode, struct file *filp,
                        unsigned int cmd, unsigned long arg);
static unsigned int blktap_poll(struct file *file, poll_table *wait);

static struct file_operations blktap_fops = {
	.owner   = THIS_MODULE,
	.poll    = blktap_poll,
	.ioctl   = blktap_ioctl,
	.open    = blktap_open,
	.release = blktap_release,
	.mmap    = blktap_mmap,
};


static tap_blkif_t *get_next_free_dev(void)
{
	tap_blkif_t *info;
	int minor;

	/*
	 * This is called only from the ioctl, which
	 * means we should always have interrupts enabled.
	 */
	BUG_ON(irqs_disabled());

	spin_lock_irq(&pending_free_lock);

	/* tapfds[0] is always NULL */

	for (minor = 1; minor < blktap_next_minor; minor++) {
		info = tapfds[minor];
		/* we could have failed a previous attempt. */
		if (!info ||
		    ((info->dev_inuse == 0) &&
		     (info->dev_pending == 0)) ) {
			info->dev_pending = 1;
			goto found;
		}
	}
	info = NULL;
	minor = -1;

	/*
	 * We didn't find free device. If we can still allocate
	 * more, then we grab the next device minor that is
	 * available.  This is done while we are still under
	 * the protection of the pending_free_lock.
	 */
	if (blktap_next_minor < MAX_TAP_DEV)
		minor = blktap_next_minor++;
found:
	spin_unlock_irq(&pending_free_lock);

	if (!info && minor > 0) {
		info = kzalloc(sizeof(*info), GFP_KERNEL);
		if (unlikely(!info)) {
			/*
			 * If we failed here, try to put back
			 * the next minor number. But if one
			 * was just taken, then we just lose this
			 * minor.  We can try to allocate this
			 * minor again later.
			 */
			spin_lock_irq(&pending_free_lock);
			if (blktap_next_minor == minor+1)
				blktap_next_minor--;
			spin_unlock_irq(&pending_free_lock);
			goto out;
		}

		info->minor = minor;
		/*
		 * Make sure that we have a minor before others can
		 * see us.
		 */
		wmb();
		tapfds[minor] = info;

		class_device_create(xen_class, NULL,
				    MKDEV(blktap_major, minor), NULL,
				    "blktap%d", minor);
	}

out:
	return info;
}

int dom_to_devid(domid_t domid, int xenbus_id, blkif_t *blkif) 
{
	tap_blkif_t *info;
	int i;

	for (i = 1; i < blktap_next_minor; i++) {
		info = tapfds[i];
		if ( info &&
		     (info->trans.domid == domid) &&
		     (info->trans.busid == xenbus_id) ) {
			info->blkif = blkif;
			info->status = RUNNING;
			return i;
		}
	}
	return -1;
}

void signal_tapdisk(int idx) 
{
	tap_blkif_t *info;
	struct task_struct *ptask;

	info = tapfds[idx];
	if ((idx < 0) || (idx > MAX_TAP_DEV) || !info)
		return;

	if (info->pid > 0) {
		ptask = find_task_by_pid(info->pid);
		if (ptask)
			info->status = CLEANSHUTDOWN;
	}
	info->blkif = NULL;

	return;
}

static int blktap_open(struct inode *inode, struct file *filp)
{
	blkif_sring_t *sring;
	int idx = iminor(inode) - BLKTAP_MINOR;
	tap_blkif_t *info;
	int i;
	
	/* ctrl device, treat differently */
	if (!idx)
		return 0;

	info = tapfds[idx];

	if ((idx < 0) || (idx > MAX_TAP_DEV) || !info) {
		WPRINTK("Unable to open device /dev/xen/blktap%d\n",
			idx);
		return -ENODEV;
	}

	DPRINTK("Opening device /dev/xen/blktap%d\n",idx);
	
	/*Only one process can access device at a time*/
	if (test_and_set_bit(0, &info->dev_inuse))
		return -EBUSY;

	info->dev_pending = 0;
	    
	/* Allocate the fe ring. */
	sring = (blkif_sring_t *)get_zeroed_page(GFP_KERNEL);
	if (sring == NULL)
		goto fail_nomem;

	SetPageReserved(virt_to_page(sring));
    
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&info->ufe_ring, sring, PAGE_SIZE);
	
	filp->private_data = info;
	info->vma = NULL;

	info->idx_map = kmalloc(sizeof(unsigned long) * MAX_PENDING_REQS, 
				GFP_KERNEL);
	
	if (idx > 0) {
		init_waitqueue_head(&info->wait);
		for (i = 0; i < MAX_PENDING_REQS; i++) 
			info->idx_map[i] = INVALID_REQ;
	}

	DPRINTK("Tap open: device /dev/xen/blktap%d\n",idx);
	return 0;

 fail_nomem:
	return -ENOMEM;
}

static int blktap_release(struct inode *inode, struct file *filp)
{
	tap_blkif_t *info = filp->private_data;
	
	/* check for control device */
	if (!info)
		return 0;

	info->dev_inuse = 0;
	DPRINTK("Freeing device [/dev/xen/blktap%d]\n",info->minor);

	/* Free the ring page. */
	ClearPageReserved(virt_to_page(info->ufe_ring.sring));
	free_page((unsigned long) info->ufe_ring.sring);

	/* Clear any active mappings and free foreign map table */
	if (info->vma) {
		zap_page_range(
			info->vma, info->vma->vm_start, 
			info->vma->vm_end - info->vma->vm_start, NULL);
		info->vma = NULL;
	}
	
	if ( (info->status != CLEANSHUTDOWN) && (info->blkif != NULL) ) {
		if (info->blkif->xenblkd != NULL) {
			kthread_stop(info->blkif->xenblkd);
			info->blkif->xenblkd = NULL;
		}
		info->status = CLEANSHUTDOWN;
	}	
	return 0;
}


/* Note on mmap:
 * We need to map pages to user space in a way that will allow the block
 * subsystem set up direct IO to them.  This couldn't be done before, because
 * there isn't really a sane way to translate a user virtual address down to a 
 * physical address when the page belongs to another domain.
 *
 * My first approach was to map the page in to kernel memory, add an entry
 * for it in the physical frame list (using alloc_lomem_region as in blkback)
 * and then attempt to map that page up to user space.  This is disallowed
 * by xen though, which realizes that we don't really own the machine frame
 * underlying the physical page.
 *
 * The new approach is to provide explicit support for this in xen linux.
 * The VMA now has a flag, VM_FOREIGN, to indicate that it contains pages
 * mapped from other vms.  vma->vm_private_data is set up as a mapping 
 * from pages to actual page structs.  There is a new clause in get_user_pages
 * that does the right thing for this sort of mapping.
 */
static int blktap_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int size;
	struct page **map;
	int i;
	tap_blkif_t *info = filp->private_data;

	if (info == NULL) {
		WPRINTK("blktap: mmap, retrieving idx failed\n");
		return -ENOMEM;
	}
	
	vma->vm_flags |= VM_RESERVED;
	vma->vm_ops = &blktap_vm_ops;

	size = vma->vm_end - vma->vm_start;
	if (size != ((mmap_pages + RING_PAGES) << PAGE_SHIFT)) {
		WPRINTK("you _must_ map exactly %d pages!\n",
		       mmap_pages + RING_PAGES);
		return -EAGAIN;
	}

	size >>= PAGE_SHIFT;
	info->rings_vstart = vma->vm_start;
	info->user_vstart  = info->rings_vstart + (RING_PAGES << PAGE_SHIFT);
    
	/* Map the ring pages to the start of the region and reserve it. */
	if (remap_pfn_range(vma, vma->vm_start, 
			    __pa(info->ufe_ring.sring) >> PAGE_SHIFT, 
			    PAGE_SIZE, vma->vm_page_prot)) {
		WPRINTK("Mapping user ring failed!\n");
		goto fail;
	}

	/* Mark this VM as containing foreign pages, and set up mappings. */
	map = kzalloc(((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)
		      * sizeof(struct page_struct*),
		      GFP_KERNEL);
	if (map == NULL) {
		WPRINTK("Couldn't alloc VM_FOREIGN map.\n");
		goto fail;
	}

	for (i = 0; i < ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT); i++)
		map[i] = NULL;
    
	vma->vm_private_data = map;
	vma->vm_flags |= VM_FOREIGN;

	info->vma = vma;
	info->ring_ok = 1;
	return 0;
 fail:
	/* Clear any active mappings. */
	zap_page_range(vma, vma->vm_start, 
		       vma->vm_end - vma->vm_start, NULL);

	return -ENOMEM;
}


static int blktap_ioctl(struct inode *inode, struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
	tap_blkif_t *info = filp->private_data;

	switch(cmd) {
	case BLKTAP_IOCTL_KICK_FE: 
	{
		/* There are fe messages to process. */
		return blktap_read_ufe_ring(info);
	}
	case BLKTAP_IOCTL_SETMODE:
	{
		if (info) {
			if (BLKTAP_MODE_VALID(arg)) {
				info->mode = arg;
				/* XXX: may need to flush rings here. */
				DPRINTK("blktap: set mode to %lx\n", 
				       arg);
				return 0;
			}
		}
		return 0;
	}
	case BLKTAP_IOCTL_PRINT_IDXS:
        {
		if (info) {
			printk("User Rings: \n-----------\n");
			printk("UF: rsp_cons: %2d, req_prod_prv: %2d "
				"| req_prod: %2d, rsp_prod: %2d\n",
				info->ufe_ring.rsp_cons,
				info->ufe_ring.req_prod_pvt,
				info->ufe_ring.sring->req_prod,
				info->ufe_ring.sring->rsp_prod);
		}
            	return 0;
        }
	case BLKTAP_IOCTL_SENDPID:
	{
		if (info) {
			info->pid = (pid_t)arg;
			DPRINTK("blktap: pid received %d\n", 
			       info->pid);
		}
		return 0;
	}
	case BLKTAP_IOCTL_NEWINTF:
	{		
		uint64_t val = (uint64_t)arg;
		domid_translate_t *tr = (domid_translate_t *)&val;

		DPRINTK("NEWINTF Req for domid %d and bus id %d\n", 
		       tr->domid, tr->busid);
		info = get_next_free_dev();
		if (!info) {
			WPRINTK("Error initialising /dev/xen/blktap - "
				"No more devices\n");
			return -1;
		}
		info->trans.domid = tr->domid;
		info->trans.busid = tr->busid;
		return info->minor;
	}
	case BLKTAP_IOCTL_FREEINTF:
	{
		unsigned long dev = arg;
		unsigned long flags;

		info = tapfds[dev];

		if ((dev > MAX_TAP_DEV) || !info)
			return 0; /* should this be an error? */

		spin_lock_irqsave(&pending_free_lock, flags);
		if (info->dev_pending)
			info->dev_pending = 0;
		spin_unlock_irqrestore(&pending_free_lock, flags);

		return 0;
	}
	case BLKTAP_IOCTL_MINOR:
	{
		unsigned long dev = arg;

		info = tapfds[dev];

		if ((dev > MAX_TAP_DEV) || !info)
			return -EINVAL;

		return info->minor;
	}
	case BLKTAP_IOCTL_MAJOR:
		return blktap_major;

	case BLKTAP_QUERY_ALLOC_REQS:
	{
		WPRINTK("BLKTAP_QUERY_ALLOC_REQS ioctl: %d/%d\n",
		       alloc_pending_reqs, blkif_reqs);
		return (alloc_pending_reqs/blkif_reqs) * 100;
	}
	}
	return -ENOIOCTLCMD;
}

static unsigned int blktap_poll(struct file *filp, poll_table *wait)
{
	tap_blkif_t *info = filp->private_data;
	
	/* do not work on the control device */
	if (!info)
		return 0;

	poll_wait(filp, &info->wait, wait);
	if (info->ufe_ring.req_prod_pvt != info->ufe_ring.sring->req_prod) {
		RING_PUSH_REQUESTS(&info->ufe_ring);
		return POLLIN | POLLRDNORM;
	}
	return 0;
}

void blktap_kick_user(int idx)
{
	tap_blkif_t *info;

	info = tapfds[idx];

	if ((idx < 0) || (idx > MAX_TAP_DEV) || !info)
		return;

	wake_up_interruptible(&info->wait);

	return;
}

static int do_block_io_op(blkif_t *blkif);
static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req);
static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st);

/******************************************************************
 * misc small helpers
 */
static int req_increase(void)
{
	int i, j;

	if (mmap_alloc >= MAX_PENDING_REQS || mmap_lock) 
		return -EINVAL;

	pending_reqs[mmap_alloc]  = kzalloc(sizeof(pending_req_t)
					    * blkif_reqs, GFP_KERNEL);
	foreign_pages[mmap_alloc] = alloc_empty_pages_and_pagevec(mmap_pages);

	if (!pending_reqs[mmap_alloc] || !foreign_pages[mmap_alloc])
		goto out_of_memory;

	DPRINTK("%s: reqs=%d, pages=%d\n",
		__FUNCTION__, blkif_reqs, mmap_pages);

	for (i = 0; i < MAX_PENDING_REQS; i++) {
		list_add_tail(&pending_reqs[mmap_alloc][i].free_list, 
			      &pending_free);
		pending_reqs[mmap_alloc][i].mem_idx = mmap_alloc;
		for (j = 0; j < BLKIF_MAX_SEGMENTS_PER_REQUEST; j++)
			BLKTAP_INVALIDATE_HANDLE(&pending_handle(mmap_alloc, 
								 i, j));
	}

	mmap_alloc++;
	DPRINTK("# MMAPs increased to %d\n",mmap_alloc);
	return 0;

 out_of_memory:
	free_empty_pages_and_pagevec(foreign_pages[mmap_alloc], mmap_pages);
	kfree(pending_reqs[mmap_alloc]);
	WPRINTK("%s: out of memory\n", __FUNCTION__);
	return -ENOMEM;
}

static void mmap_req_del(int mmap)
{
	BUG_ON(!spin_is_locked(&pending_free_lock));

	kfree(pending_reqs[mmap]);
	pending_reqs[mmap] = NULL;

	free_empty_pages_and_pagevec(foreign_pages[mmap_alloc], mmap_pages);
	foreign_pages[mmap] = NULL;

	mmap_lock = 0;
	DPRINTK("# MMAPs decreased to %d\n",mmap_alloc);
	mmap_alloc--;
}

static pending_req_t* alloc_req(void)
{
	pending_req_t *req = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pending_free_lock, flags);

	if (!list_empty(&pending_free)) {
		req = list_entry(pending_free.next, pending_req_t, free_list);
		list_del(&req->free_list);
	}

	if (req) {
		req->inuse = 1;
		alloc_pending_reqs++;
	}
	spin_unlock_irqrestore(&pending_free_lock, flags);

	return req;
}

static void free_req(pending_req_t *req)
{
	unsigned long flags;
	int was_empty;

	spin_lock_irqsave(&pending_free_lock, flags);

	alloc_pending_reqs--;
	req->inuse = 0;
	if (mmap_lock && (req->mem_idx == mmap_alloc-1)) {
		mmap_inuse--;
		if (mmap_inuse == 0) mmap_req_del(mmap_alloc-1);
		spin_unlock_irqrestore(&pending_free_lock, flags);
		return;
	}
	was_empty = list_empty(&pending_free);
	list_add(&req->free_list, &pending_free);

	spin_unlock_irqrestore(&pending_free_lock, flags);

	if (was_empty)
		wake_up(&pending_free_wq);
}

static void fast_flush_area(pending_req_t *req, int k_idx, int u_idx,
			    int tapidx)
{
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
	unsigned int i, invcount = 0;
	struct grant_handle_pair *khandle;
	uint64_t ptep;
	int ret, mmap_idx;
	unsigned long kvaddr, uvaddr;
	tap_blkif_t *info;
	

	info = tapfds[tapidx];

	if ((tapidx < 0) || (tapidx > MAX_TAP_DEV) || !info) {
		WPRINTK("fast_flush: Couldn't get info!\n");
		return;
	}

	if (info->vma != NULL &&
	    xen_feature(XENFEAT_auto_translated_physmap)) {
		down_write(&info->vma->vm_mm->mmap_sem);
		zap_page_range(info->vma, 
			       MMAP_VADDR(info->user_vstart, u_idx, 0), 
			       req->nr_pages << PAGE_SHIFT, NULL);
		up_write(&info->vma->vm_mm->mmap_sem);
	}

	mmap_idx = req->mem_idx;

	for (i = 0; i < req->nr_pages; i++) {
		kvaddr = idx_to_kaddr(mmap_idx, k_idx, i);
		uvaddr = MMAP_VADDR(info->user_vstart, u_idx, i);

		khandle = &pending_handle(mmap_idx, k_idx, i);

		if (khandle->kernel != INVALID_GRANT_HANDLE) {
			gnttab_set_unmap_op(&unmap[invcount],
					    idx_to_kaddr(mmap_idx, k_idx, i),
					    GNTMAP_host_map, khandle->kernel);
			invcount++;
		}

		if (khandle->user != INVALID_GRANT_HANDLE) {
			BUG_ON(xen_feature(XENFEAT_auto_translated_physmap));
			if (create_lookup_pte_addr(
				info->vma->vm_mm,
				MMAP_VADDR(info->user_vstart, u_idx, i),
				&ptep) !=0) {
				WPRINTK("Couldn't get a pte addr!\n");
				return;
			}

			gnttab_set_unmap_op(&unmap[invcount], ptep,
					    GNTMAP_host_map
					    | GNTMAP_application_map
					    | GNTMAP_contains_pte,
					    khandle->user);
			invcount++;
		}

		BLKTAP_INVALIDATE_HANDLE(khandle);
	}
	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, unmap, invcount);
	BUG_ON(ret);
	
	if (info->vma != NULL && !xen_feature(XENFEAT_auto_translated_physmap))
		zap_page_range(info->vma, 
			       MMAP_VADDR(info->user_vstart, u_idx, 0), 
			       req->nr_pages << PAGE_SHIFT, NULL);
}

/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static void print_stats(blkif_t *blkif)
{
	printk(KERN_DEBUG "%s: oo %3d  |  rd %4d  |  wr %4d\n",
	       current->comm, blkif->st_oo_req,
	       blkif->st_rd_req, blkif->st_wr_req);
	blkif->st_print = jiffies + msecs_to_jiffies(10 * 1000);
	blkif->st_rd_req = 0;
	blkif->st_wr_req = 0;
	blkif->st_oo_req = 0;
}

int tap_blkif_schedule(void *arg)
{
	blkif_t *blkif = arg;

	blkif_get(blkif);

	if (debug_lvl)
		printk(KERN_DEBUG "%s: started\n", current->comm);

	while (!kthread_should_stop()) {
		wait_event_interruptible(
			blkif->wq,
			blkif->waiting_reqs || kthread_should_stop());
		wait_event_interruptible(
			pending_free_wq,
			!list_empty(&pending_free) || kthread_should_stop());

		blkif->waiting_reqs = 0;
		smp_mb(); /* clear flag *before* checking for work */

		if (do_block_io_op(blkif))
			blkif->waiting_reqs = 1;

		if (log_stats && time_after(jiffies, blkif->st_print))
			print_stats(blkif);
	}

	if (log_stats)
		print_stats(blkif);
	if (debug_lvl)
		printk(KERN_DEBUG "%s: exiting\n", current->comm);

	blkif->xenblkd = NULL;
	blkif_put(blkif);

	return 0;
}

/******************************************************************
 * COMPLETION CALLBACK -- Called by user level ioctl()
 */

static int blktap_read_ufe_ring(tap_blkif_t *info)
{
	/* This is called to read responses from the UFE ring. */
	RING_IDX i, j, rp;
	blkif_response_t *resp;
	blkif_t *blkif=NULL;
	int pending_idx, usr_idx, mmap_idx;
	pending_req_t *pending_req;
	
	if (!info)
		return 0;

	/* We currently only forward packets in INTERCEPT_FE mode. */
	if (!(info->mode & BLKTAP_MODE_INTERCEPT_FE))
		return 0;

	/* for each outstanding message on the UFEring  */
	rp = info->ufe_ring.sring->rsp_prod;
	rmb();
        
	for (i = info->ufe_ring.rsp_cons; i != rp; i++) {
		blkif_response_t res;
		resp = RING_GET_RESPONSE(&info->ufe_ring, i);
		memcpy(&res, resp, sizeof(res));
		mb(); /* rsp_cons read by RING_FULL() in do_block_io_op(). */
		++info->ufe_ring.rsp_cons;

		/*retrieve [usr_idx] to [mmap_idx,pending_idx] mapping*/
		usr_idx = (int)res.id;
		pending_idx = MASK_PEND_IDX(ID_TO_IDX(info->idx_map[usr_idx]));
		mmap_idx = ID_TO_MIDX(info->idx_map[usr_idx]);

		if ( (mmap_idx >= mmap_alloc) || 
		   (ID_TO_IDX(info->idx_map[usr_idx]) >= MAX_PENDING_REQS) )
			WPRINTK("Incorrect req map"
			       "[%d], internal map [%d,%d (%d)]\n", 
			       usr_idx, mmap_idx, 
			       ID_TO_IDX(info->idx_map[usr_idx]),
			       MASK_PEND_IDX(
				       ID_TO_IDX(info->idx_map[usr_idx])));

		pending_req = &pending_reqs[mmap_idx][pending_idx];
		blkif = pending_req->blkif;

		for (j = 0; j < pending_req->nr_pages; j++) {

			unsigned long kvaddr, uvaddr;
			struct page **map = info->vma->vm_private_data;
			struct page *pg;
			int offset;

			uvaddr = MMAP_VADDR(info->user_vstart, usr_idx, j);
			kvaddr = idx_to_kaddr(mmap_idx, pending_idx, j);

			pg = pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);
			ClearPageReserved(pg);
			offset = (uvaddr - info->vma->vm_start) 
				>> PAGE_SHIFT;
			map[offset] = NULL;
		}
		fast_flush_area(pending_req, pending_idx, usr_idx, info->minor);
		info->idx_map[usr_idx] = INVALID_REQ;
		make_response(blkif, pending_req->id, res.operation,
			      res.status);
		blkif_put(pending_req->blkif);
		free_req(pending_req);
	}
		
	return 0;
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

static void blkif_notify_work(blkif_t *blkif)
{
	blkif->waiting_reqs = 1;
	wake_up(&blkif->wq);
}

irqreturn_t tap_blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
	blkif_notify_work(dev_id);
	return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */
static int print_dbug = 1;
static int do_block_io_op(blkif_t *blkif)
{
	blkif_back_rings_t *blk_rings = &blkif->blk_rings;
	blkif_request_t req;
	pending_req_t *pending_req;
	RING_IDX rc, rp;
	int more_to_do = 0;
	tap_blkif_t *info;

	rc = blk_rings->common.req_cons;
	rp = blk_rings->common.sring->req_prod;
	rmb(); /* Ensure we see queued requests up to 'rp'. */

	/*Check blkif has corresponding UE ring*/
	if (blkif->dev_num < 0) {
		/*oops*/
		if (print_dbug) {
			WPRINTK("Corresponding UE " 
			       "ring does not exist!\n");
			print_dbug = 0; /*We only print this message once*/
		}
		return 0;
	}

	info = tapfds[blkif->dev_num];

	if (blkif->dev_num > MAX_TAP_DEV || !info || !info->dev_inuse) {
		if (print_dbug) {
			WPRINTK("Can't get UE info!\n");
			print_dbug = 0;
		}
		return 0;
	}

	while (rc != rp) {
		
		if (RING_FULL(&info->ufe_ring)) {
			WPRINTK("RING_FULL! More to do\n");
			more_to_do = 1;
			break;
		}

		if (RING_REQUEST_CONS_OVERFLOW(&blk_rings->common, rc)) {
			WPRINTK("RING_REQUEST_CONS_OVERFLOW!"
			       " More to do\n");
			more_to_do = 1;
			break;		
		}

		pending_req = alloc_req();
		if (NULL == pending_req) {
			blkif->st_oo_req++;
			more_to_do = 1;
			break;
		}

		switch (blkif->blk_protocol) {
		case BLKIF_PROTOCOL_NATIVE:
			memcpy(&req, RING_GET_REQUEST(&blk_rings->native, rc),
			       sizeof(req));
			break;
		case BLKIF_PROTOCOL_X86_32:
			blkif_get_x86_32_req(&req, RING_GET_REQUEST(&blk_rings->x86_32, rc));
			break;
		case BLKIF_PROTOCOL_X86_64:
			blkif_get_x86_64_req(&req, RING_GET_REQUEST(&blk_rings->x86_64, rc));
			break;
		default:
			BUG();
		}
		blk_rings->common.req_cons = ++rc; /* before make_response() */

		switch (req.operation) {
		case BLKIF_OP_READ:
			blkif->st_rd_req++;
			dispatch_rw_block_io(blkif, &req, pending_req);
			break;

		case BLKIF_OP_WRITE:
			blkif->st_wr_req++;
			dispatch_rw_block_io(blkif, &req, pending_req);
			break;

		default:
			WPRINTK("unknown operation [%d]\n",
				req.operation);
			make_response(blkif, req.id, req.operation,
				      BLKIF_RSP_ERROR);
			free_req(pending_req);
			break;
		}
	}
		
	blktap_kick_user(blkif->dev_num);

	return more_to_do;
}

static void dispatch_rw_block_io(blkif_t *blkif,
				 blkif_request_t *req,
				 pending_req_t *pending_req)
{
	extern void ll_rw_block(int rw, int nr, struct buffer_head * bhs[]);
	int op, operation = (req->operation == BLKIF_OP_WRITE) ? WRITE : READ;
	struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
	unsigned int nseg;
	int ret, i, nr_sects = 0;
	tap_blkif_t *info;
	uint64_t sector;
	blkif_request_t *target;
	int pending_idx = RTN_PEND_IDX(pending_req,pending_req->mem_idx);
	int usr_idx;
	uint16_t mmap_idx = pending_req->mem_idx;

	if (blkif->dev_num < 0 || blkif->dev_num > MAX_TAP_DEV)
		goto fail_response;

	info = tapfds[blkif->dev_num];
	if (info == NULL)
		goto fail_response;

	/* Check we have space on user ring - should never fail. */
	usr_idx = GET_NEXT_REQ(info->idx_map);
	if (usr_idx == INVALID_REQ) {
		BUG();
		goto fail_response;
	}

	/* Check that number of segments is sane. */
	nseg = req->nr_segments;
	if ( unlikely(nseg == 0) || 
	    unlikely(nseg > BLKIF_MAX_SEGMENTS_PER_REQUEST) ) {
		WPRINTK("Bad number of segments in request (%d)\n", nseg);
		goto fail_response;
	}
	
	/* Make sure userspace is ready. */
	if (!info->ring_ok) {
		WPRINTK("blktap: ring not ready for requests!\n");
		goto fail_response;
	}

	if (RING_FULL(&info->ufe_ring)) {
		WPRINTK("blktap: fe_ring is full, can't add "
			"IO Request will be dropped. %d %d\n",
			RING_SIZE(&info->ufe_ring),
			RING_SIZE(&blkif->blk_rings.common));
		goto fail_response;
	}

	pending_req->blkif     = blkif;
	pending_req->id        = req->id;
	pending_req->operation = operation;
	pending_req->status    = BLKIF_RSP_OKAY;
	pending_req->nr_pages  = nseg;
	op = 0;
	for (i = 0; i < nseg; i++) {
		unsigned long uvaddr;
		unsigned long kvaddr;
		uint64_t ptep;
		uint32_t flags;

		uvaddr = MMAP_VADDR(info->user_vstart, usr_idx, i);
		kvaddr = idx_to_kaddr(mmap_idx, pending_idx, i);

		sector = req->sector_number + ((PAGE_SIZE / 512) * i);
		if( (blkif->sectors > 0) && (sector >= blkif->sectors) ) {
			WPRINTK("BLKTAP: Sector request greater" 
			       "than size\n");
			WPRINTK("BLKTAP: %s request sector" 
			       "[%llu,%llu], Total [%llu]\n",
			       (req->operation == 
				BLKIF_OP_WRITE ? "WRITE" : "READ"),
				(long long unsigned) sector,
				(long long unsigned) sector>>9,
				(long long unsigned) blkif->sectors);
		}

		flags = GNTMAP_host_map;
		if (operation == WRITE)
			flags |= GNTMAP_readonly;
		gnttab_set_map_op(&map[op], kvaddr, flags,
				  req->seg[i].gref, blkif->domid);
		op++;

		if (!xen_feature(XENFEAT_auto_translated_physmap)) {
			/* Now map it to user. */
			ret = create_lookup_pte_addr(info->vma->vm_mm, 
						     uvaddr, &ptep);
			if (ret) {
				WPRINTK("Couldn't get a pte addr!\n");
				goto fail_flush;
			}

			flags = GNTMAP_host_map | GNTMAP_application_map
				| GNTMAP_contains_pte;
			if (operation == WRITE)
				flags |= GNTMAP_readonly;
			gnttab_set_map_op(&map[op], ptep, flags,
					  req->seg[i].gref, blkif->domid);
			op++;
		}

		nr_sects += (req->seg[i].last_sect - 
			     req->seg[i].first_sect + 1);
	}

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, op);
	BUG_ON(ret);

	if (!xen_feature(XENFEAT_auto_translated_physmap)) {
		for (i = 0; i < (nseg*2); i+=2) {
			unsigned long uvaddr;
			unsigned long kvaddr;
			unsigned long offset;
			struct page *pg;

			uvaddr = MMAP_VADDR(info->user_vstart, usr_idx, i/2);
			kvaddr = idx_to_kaddr(mmap_idx, pending_idx, i/2);

			if (unlikely(map[i].status != 0)) {
				WPRINTK("invalid kernel buffer -- "
					"could not remap it\n");
				ret |= 1;
				map[i].handle = INVALID_GRANT_HANDLE;
			}

			if (unlikely(map[i+1].status != 0)) {
				WPRINTK("invalid user buffer -- "
					"could not remap it\n");
				ret |= 1;
				map[i+1].handle = INVALID_GRANT_HANDLE;
			}

			pending_handle(mmap_idx, pending_idx, i/2).kernel 
				= map[i].handle;
			pending_handle(mmap_idx, pending_idx, i/2).user   
				= map[i+1].handle;

			if (ret)
				continue;

			set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT,
					    FOREIGN_FRAME(map[i].dev_bus_addr
							  >> PAGE_SHIFT));
			offset = (uvaddr - info->vma->vm_start) >> PAGE_SHIFT;
			pg = pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);
			((struct page **)info->vma->vm_private_data)[offset] =
				pg;
		}
	} else {
		for (i = 0; i < nseg; i++) {
			unsigned long uvaddr;
			unsigned long kvaddr;
			unsigned long offset;
			struct page *pg;

			uvaddr = MMAP_VADDR(info->user_vstart, usr_idx, i);
			kvaddr = idx_to_kaddr(mmap_idx, pending_idx, i);

			if (unlikely(map[i].status != 0)) {
				WPRINTK("invalid kernel buffer -- "
					"could not remap it\n");
				ret |= 1;
				map[i].handle = INVALID_GRANT_HANDLE;
			}

			pending_handle(mmap_idx, pending_idx, i).kernel 
				= map[i].handle;

			if (ret)
				continue;

			offset = (uvaddr - info->vma->vm_start) >> PAGE_SHIFT;
			pg = pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);
			((struct page **)info->vma->vm_private_data)[offset] =
				pg;
		}
	}

	if (ret)
		goto fail_flush;

	if (xen_feature(XENFEAT_auto_translated_physmap))
		down_write(&info->vma->vm_mm->mmap_sem);
	/* Mark mapped pages as reserved: */
	for (i = 0; i < req->nr_segments; i++) {
		unsigned long kvaddr;
		struct page *pg;

		kvaddr = idx_to_kaddr(mmap_idx, pending_idx, i);
		pg = pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);
		SetPageReserved(pg);
		if (xen_feature(XENFEAT_auto_translated_physmap)) {
			ret = vm_insert_page(info->vma,
					     MMAP_VADDR(info->user_vstart,
							usr_idx, i), pg);
			if (ret) {
				up_write(&info->vma->vm_mm->mmap_sem);
				goto fail_flush;
			}
		}
	}
	if (xen_feature(XENFEAT_auto_translated_physmap))
		up_write(&info->vma->vm_mm->mmap_sem);
	
	/*record [mmap_idx,pending_idx] to [usr_idx] mapping*/
	info->idx_map[usr_idx] = MAKE_ID(mmap_idx, pending_idx);

	blkif_get(blkif);
	/* Finally, write the request message to the user ring. */
	target = RING_GET_REQUEST(&info->ufe_ring,
				  info->ufe_ring.req_prod_pvt);
	memcpy(target, req, sizeof(*req));
	target->id = usr_idx;
	wmb(); /* blktap_poll() reads req_prod_pvt asynchronously */
	info->ufe_ring.req_prod_pvt++;

	if (operation == READ) {
		blkif->st_rd_sect += nr_sects;
	} else if (operation == WRITE) {
		blkif->st_wr_sect += nr_sects;
	}

	return;

 fail_flush:
	WPRINTK("Reached Fail_flush\n");
	fast_flush_area(pending_req, pending_idx, usr_idx, blkif->dev_num);
 fail_response:
	make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
	free_req(pending_req);
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st)
{
	blkif_response_t  resp;
	unsigned long     flags;
	blkif_back_rings_t *blk_rings = &blkif->blk_rings;
	int more_to_do = 0;
	int notify;

	resp.id        = id;
	resp.operation = op;
	resp.status    = st;

	spin_lock_irqsave(&blkif->blk_ring_lock, flags);
	/* Place on the response ring for the relevant domain. */
	switch (blkif->blk_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		memcpy(RING_GET_RESPONSE(&blk_rings->native,
					 blk_rings->native.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	case BLKIF_PROTOCOL_X86_32:
		memcpy(RING_GET_RESPONSE(&blk_rings->x86_32,
					 blk_rings->x86_32.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	case BLKIF_PROTOCOL_X86_64:
		memcpy(RING_GET_RESPONSE(&blk_rings->x86_64,
					 blk_rings->x86_64.rsp_prod_pvt),
		       &resp, sizeof(resp));
		break;
	default:
		BUG();
	}
	blk_rings->common.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&blk_rings->common, notify);

	if (blk_rings->common.rsp_prod_pvt == blk_rings->common.req_cons) {
		/*
		 * Tail check for pending requests. Allows frontend to avoid
		 * notifications if requests are already in flight (lower
		 * overheads and promotes batching).
		 */
		RING_FINAL_CHECK_FOR_REQUESTS(&blk_rings->common, more_to_do);
	} else if (RING_HAS_UNCONSUMED_REQUESTS(&blk_rings->common)) {
		more_to_do = 1;
	}

	spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);
	if (more_to_do)
		blkif_notify_work(blkif);
	if (notify)
		notify_remote_via_irq(blkif->irq);
}

static int __init blkif_init(void)
{
	int i, ret;

	if (!is_running_on_xen())
		return -ENODEV;

	INIT_LIST_HEAD(&pending_free);
        for(i = 0; i < 2; i++) {
		ret = req_increase();
		if (ret)
			break;
	}
	if (i == 0)
		return ret;

	tap_blkif_interface_init();

	alloc_pending_reqs = 0;

	tap_blkif_xenbus_init();

	/* Dynamically allocate a major for this device */
	ret = register_chrdev(0, "blktap", &blktap_fops);

	if (ret < 0) {
		WPRINTK("Couldn't register /dev/xen/blktap\n");
		return -ENOMEM;
	}	
	
	blktap_major = ret;

	/* tapfds[0] is always NULL */
	blktap_next_minor++;

	DPRINTK("Created misc_dev [/dev/xen/blktap%d]\n",i);

	/* Make sure the xen class exists */
	if (!setup_xen_class()) {
		/*
		 * This will allow udev to create the blktap ctrl device.
		 * We only want to create blktap0 first.  We don't want
		 * to flood the sysfs system with needless blktap devices.
		 * We only create the device when a request of a new device is
		 * made.
		 */
		class_device_create(xen_class, NULL,
				    MKDEV(blktap_major, 0), NULL,
				    "blktap0");
	} else {
		/* this is bad, but not fatal */
		WPRINTK("blktap: sysfs xen_class not created\n");
	}

	DPRINTK("Blktap device successfully created\n");

	return 0;
}

module_init(blkif_init);

MODULE_LICENSE("Dual BSD/GPL");
