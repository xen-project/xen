/******************************************************************************
 * arch/xen/drivers/blkif/blktap/blktap.c
 * 
 * This is a modified version of the block backend driver that remaps requests
 * to a user-space memory region.  It is intended to be used to write 
 * application-level servers that provide block interfaces to client VMs.
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <xen/balloon.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/gfp.h>
#include <linux/poll.h>
#include <asm/tlbflush.h>
#include "common.h"

/* Only one process may open /dev/xen/blktap at any time. */
static unsigned long blktap_dev_inuse;
unsigned long blktap_ring_ok; /* make this ring->state */

/* Rings up to user space. */
static blkif_front_ring_t blktap_ufe_ring;

/* for poll: */
static wait_queue_head_t blktap_wait;

/* current switching mode */
static unsigned long blktap_mode;

/* local prototypes */
static int blktap_read_ufe_ring(void);


/* /dev/xen/blktap resides at device number major=10, minor=200        */ 
#define BLKTAP_MINOR 202

/* blktap IOCTLs:                                                      */
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2 /* currently unused */
#define BLKTAP_IOCTL_SETMODE         3
#define BLKTAP_IOCTL_PRINT_IDXS      100  

/* blktap switching modes: (Set with BLKTAP_IOCTL_SETMODE)             */
#define BLKTAP_MODE_PASSTHROUGH      0x00000000  /* default            */
#define BLKTAP_MODE_INTERCEPT_FE     0x00000001
#define BLKTAP_MODE_INTERCEPT_BE     0x00000002  /* unimp. */
#define BLKTAP_MODE_COPY_FE          0x00000004  /* unimp. */
#define BLKTAP_MODE_COPY_BE          0x00000008  /* unimp. */
#define BLKTAP_MODE_COPY_FE_PAGES    0x00000010  /* unimp. */
#define BLKTAP_MODE_COPY_BE_PAGES    0x00000020  /* unimp. */

#define BLKTAP_MODE_INTERPOSE \
           (BLKTAP_MODE_INTERCEPT_FE | BLKTAP_MODE_INTERCEPT_BE)

#define BLKTAP_MODE_COPY_BOTH \
           (BLKTAP_MODE_COPY_FE | BLKTAP_MODE_COPY_BE)

#define BLKTAP_MODE_COPY_BOTH_PAGES \
           (BLKTAP_MODE_COPY_FE_PAGES | BLKTAP_MODE_COPY_BE_PAGES)

static inline int BLKTAP_MODE_VALID(unsigned long arg)
{
	return ((arg == BLKTAP_MODE_PASSTHROUGH ) ||
		(arg == BLKTAP_MODE_INTERCEPT_FE) ||
		(arg == BLKTAP_MODE_INTERPOSE   ));
/*
  return (
  ( arg == BLKTAP_MODE_PASSTHROUGH  ) ||
  ( arg == BLKTAP_MODE_INTERCEPT_FE ) ||
  ( arg == BLKTAP_MODE_INTERCEPT_BE ) ||
  ( arg == BLKTAP_MODE_INTERPOSE    ) ||
  ( (arg & ~BLKTAP_MODE_COPY_FE_PAGES) == BLKTAP_MODE_COPY_FE ) ||
  ( (arg & ~BLKTAP_MODE_COPY_BE_PAGES) == BLKTAP_MODE_COPY_BE ) ||
  ( (arg & ~BLKTAP_MODE_COPY_BOTH_PAGES) == BLKTAP_MODE_COPY_BOTH )
  );
*/
}


/******************************************************************
 * MMAP REGION
 */

/*
 * We use a big chunk of address space to map in-flight requests into,
 * and export this region up to user-space.  See the comments in blkback
 * about this -- the two must be kept in sync if the tap is used as a 
 * passthrough.
 */

#define MAX_PENDING_REQS 64
#define BATCH_PER_DOMAIN 16

/* immediately before the mmap area, we have a bunch of pages reserved
 * for shared memory rings.
 */
#define RING_PAGES 1 /* Front */ 

/* Where things are inside the device mapping. */
struct vm_area_struct *blktap_vma = NULL;
unsigned long mmap_vstart;  /* Kernel pages for mapping in data. */
unsigned long rings_vstart; /* start of mmaped vma               */
unsigned long user_vstart;  /* start of user mappings            */

#define MMAP_PAGES						\
	(MAX_PENDING_REQS * BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define MMAP_VADDR(_start, _req,_seg)					\
	(_start +							\
	 ((_req) * BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE) +	\
	 ((_seg) * PAGE_SIZE))

/*
 * Each outstanding request that we've passed to the lower device layers has a 
 * 'pending_req' allocated to it. Each buffer_head that completes decrements 
 * the pendcnt towards zero. When it hits zero, the specified domain has a 
 * response queued for it, with the saved 'id' passed back.
 */
typedef struct {
	blkif_t       *blkif;
	unsigned long  id;
	int            nr_pages;
	atomic_t       pendcnt;
	unsigned short operation;
	int            status;
} pending_req_t;

/*
 * We can't allocate pending_req's in order, since they may complete out of 
 * order. We therefore maintain an allocation ring. This ring also indicates 
 * when enough work has been passed down -- at that point the allocation ring 
 * will be empty.
 */
static pending_req_t pending_reqs[MAX_PENDING_REQS];
static unsigned char pending_ring[MAX_PENDING_REQS];
static DEFINE_SPINLOCK(pend_prod_lock);
/* NB. We use a different index type to differentiate from shared blk rings. */
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

/* Requests passing through the tap to the backend hijack the id field
 * in the request message.  In it we put the AR index _AND_ the fe domid.
 * the domid is used by the backend to map the pages properly.
 */

static inline unsigned long MAKE_ID(domid_t fe_dom, PEND_RING_IDX idx)
{
	return ((fe_dom << 16) | MASK_PEND_IDX(idx));
}

extern inline PEND_RING_IDX ID_TO_IDX(unsigned long id) 
{ 
	return (PEND_RING_IDX)(id & 0x0000ffff);
}

extern inline domid_t ID_TO_DOM(unsigned long id) 
{ 
	return (domid_t)(id >> 16); 
}



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
static struct grant_handle_pair pending_grant_handles[MMAP_PAGES];
#define pending_handle(_idx, _i) \
    (pending_grant_handles[((_idx) * BLKIF_MAX_SEGMENTS_PER_REQUEST) + (_i)])
#define BLKTAP_INVALID_HANDLE(_g) \
    (((_g->kernel) == 0xFFFF) && ((_g->user) == 0xFFFF))
#define BLKTAP_INVALIDATE_HANDLE(_g) do {       \
    (_g)->kernel = 0xFFFF; (_g)->user = 0xFFFF; \
    } while(0)


/******************************************************************
 * BLKTAP VM OPS
 */

static struct page *blktap_nopage(struct vm_area_struct *vma,
				  unsigned long address,
				  int *type)
{
	/*
	 * if the page has not been mapped in by the driver then generate
	 * a SIGBUS to the domain.
	 */
	force_sig(SIGBUS, current);

	return 0;
}

struct vm_operations_struct blktap_vm_ops = {
	.nopage = blktap_nopage,
};

/******************************************************************
 * BLKTAP FILE OPS
 */

static int blktap_open(struct inode *inode, struct file *filp)
{
	blkif_sring_t *sring;

	if (test_and_set_bit(0, &blktap_dev_inuse))
		return -EBUSY;
    
	/* Allocate the fe ring. */
	sring = (blkif_sring_t *)get_zeroed_page(GFP_KERNEL);
	if (sring == NULL)
		return -ENOMEM;

	SetPageReserved(virt_to_page(sring));
    
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&blktap_ufe_ring, sring, PAGE_SIZE);

	return 0;
}

static int blktap_release(struct inode *inode, struct file *filp)
{
	blktap_dev_inuse = 0;
	blktap_ring_ok = 0;

	/* Free the ring page. */
	ClearPageReserved(virt_to_page(blktap_ufe_ring.sring));
	free_page((unsigned long) blktap_ufe_ring.sring);

	/* Clear any active mappings and free foreign map table */
	if (blktap_vma != NULL) {
		zap_page_range(
			blktap_vma, blktap_vma->vm_start, 
			blktap_vma->vm_end - blktap_vma->vm_start, NULL);
		blktap_vma = NULL;
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

	DPRINTK(KERN_ALERT "blktap mmap (%lx, %lx)\n",
		vma->vm_start, vma->vm_end);

	vma->vm_flags |= VM_RESERVED;
	vma->vm_ops = &blktap_vm_ops;

	size = vma->vm_end - vma->vm_start;
	if (size != ((MMAP_PAGES + RING_PAGES) << PAGE_SHIFT)) {
		printk(KERN_INFO 
		       "blktap: you _must_ map exactly %d pages!\n",
		       MMAP_PAGES + RING_PAGES);
		return -EAGAIN;
	}

	size >>= PAGE_SHIFT;
	DPRINTK(KERN_INFO "blktap: 2 rings + %d pages.\n", size-1);
    
	rings_vstart = vma->vm_start;
	user_vstart  = rings_vstart + (RING_PAGES << PAGE_SHIFT);
    
	/* Map the ring pages to the start of the region and reserve it. */

	/* not sure if I really need to do this... */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (remap_pfn_range(vma, vma->vm_start, 
			    __pa(blktap_ufe_ring.sring) >> PAGE_SHIFT, 
			    PAGE_SIZE, vma->vm_page_prot)) {
		WPRINTK("Mapping user ring failed!\n");
		goto fail;
	}

	/* Mark this VM as containing foreign pages, and set up mappings. */
	map = kmalloc(((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)
		      * sizeof(struct page_struct*),
		      GFP_KERNEL);
	if (map == NULL) {
		WPRINTK("Couldn't alloc VM_FOREIGH map.\n");
		goto fail;
	}

	for (i = 0; i < ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT); i++)
		map[i] = NULL;
    
	vma->vm_private_data = map;
	vma->vm_flags |= VM_FOREIGN;

	blktap_vma = vma;
	blktap_ring_ok = 1;

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
	switch(cmd) {
	case BLKTAP_IOCTL_KICK_FE: /* There are fe messages to process. */
		return blktap_read_ufe_ring();

	case BLKTAP_IOCTL_SETMODE:
		if (BLKTAP_MODE_VALID(arg)) {
			blktap_mode = arg;
			/* XXX: may need to flush rings here. */
			printk(KERN_INFO "blktap: set mode to %lx\n", arg);
			return 0;
		}
	case BLKTAP_IOCTL_PRINT_IDXS:
        {
		//print_fe_ring_idxs();
		WPRINTK("User Rings: \n-----------\n");
		WPRINTK("UF: rsp_cons: %2d, req_prod_prv: %2d "
			"| req_prod: %2d, rsp_prod: %2d\n",
			blktap_ufe_ring.rsp_cons,
			blktap_ufe_ring.req_prod_pvt,
			blktap_ufe_ring.sring->req_prod,
			blktap_ufe_ring.sring->rsp_prod);
            
        }
	}
	return -ENOIOCTLCMD;
}

static unsigned int blktap_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &blktap_wait, wait);
	if (blktap_ufe_ring.req_prod_pvt != blktap_ufe_ring.sring->req_prod) {
		flush_tlb_all();
		RING_PUSH_REQUESTS(&blktap_ufe_ring);
		return POLLIN | POLLRDNORM;
	}

	return 0;
}

void blktap_kick_user(void)
{
	/* blktap_ring->req_prod = blktap_req_prod; */
	wake_up_interruptible(&blktap_wait);
}

static struct file_operations blktap_fops = {
	.owner   = THIS_MODULE,
	.poll    = blktap_poll,
	.ioctl   = blktap_ioctl,
	.open    = blktap_open,
	.release = blktap_release,
	.mmap    = blktap_mmap,
};



static int do_block_io_op(blkif_t *blkif, int max_to_do);
static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req);
static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st);


static void fast_flush_area(int idx, int nr_pages)
{
	struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
	unsigned int i, op = 0;
	struct grant_handle_pair *handle;
	uint64_t ptep;
	int ret;

	for ( i = 0; i < nr_pages; i++)
	{
		handle = &pending_handle(idx, i);
		if (BLKTAP_INVALID_HANDLE(handle))
			continue;

		gnttab_set_unmap_op(&unmap[op],
				    MMAP_VADDR(mmap_vstart, idx, i),
				    GNTMAP_host_map, handle->kernel);
		op++;

		if (create_lookup_pte_addr(
			    blktap_vma->vm_mm,
			    MMAP_VADDR(user_vstart, idx, i), 
			    &ptep) !=0) {
			DPRINTK("Couldn't get a pte addr!\n");
			return;
		}
		gnttab_set_unmap_grnat_ref(&unmap[op], ptep,
					   GNTMAP_host_map |
					   GNTMAP_application_map |
					   GNTMAP_contains_pte, handle->user);
		op++;
            
		BLKTAP_INVALIDATE_HANDLE(handle);
	}

	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, unmap, op);
	BUG_ON(ret);

	if (blktap_vma != NULL)
		zap_page_range(blktap_vma, 
			       MMAP_VADDR(user_vstart, idx, 0), 
			       nr_pages << PAGE_SHIFT, NULL);
}

/******************************************************************
 * BLOCK-DEVICE SCHEDULER LIST MAINTENANCE
 */

static struct list_head blkio_schedule_list;
static spinlock_t blkio_schedule_list_lock;

static int __on_blkdev_list(blkif_t *blkif)
{
	return blkif->blkdev_list.next != NULL;
}

static void remove_from_blkdev_list(blkif_t *blkif)
{
	unsigned long flags;

	if (!__on_blkdev_list(blkif))
		return;

	spin_lock_irqsave(&blkio_schedule_list_lock, flags);
	if (__on_blkdev_list(blkif)) {
		list_del(&blkif->blkdev_list);
		blkif->blkdev_list.next = NULL;
		blkif_put(blkif);
	}
	spin_unlock_irqrestore(&blkio_schedule_list_lock, flags);
}

static void add_to_blkdev_list_tail(blkif_t *blkif)
{
	unsigned long flags;

	if (__on_blkdev_list(blkif))
		return;

	spin_lock_irqsave(&blkio_schedule_list_lock, flags);
	if (!__on_blkdev_list(blkif) && (blkif->status == CONNECTED)) {
		list_add_tail(&blkif->blkdev_list, &blkio_schedule_list);
		blkif_get(blkif);
	}
	spin_unlock_irqrestore(&blkio_schedule_list_lock, flags);
}


/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static DECLARE_WAIT_QUEUE_HEAD(blkio_schedule_wait);

static int blkio_schedule(void *arg)
{
	DECLARE_WAITQUEUE(wq, current);

	blkif_t          *blkif;
	struct list_head *ent;

	daemonize("xenblkd");

	for (;;) {
		/* Wait for work to do. */
		add_wait_queue(&blkio_schedule_wait, &wq);
		set_current_state(TASK_INTERRUPTIBLE);
		if ((NR_PENDING_REQS == MAX_PENDING_REQS) || 
		    list_empty(&blkio_schedule_list))
			schedule();
		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&blkio_schedule_wait, &wq);

		/* Queue up a batch of requests. */
		while ((NR_PENDING_REQS < MAX_PENDING_REQS) &&
		       !list_empty(&blkio_schedule_list)) {
			ent = blkio_schedule_list.next;
			blkif = list_entry(ent, blkif_t, blkdev_list);
			blkif_get(blkif);
			remove_from_blkdev_list(blkif);
			if (do_block_io_op(blkif, BATCH_PER_DOMAIN))
				add_to_blkdev_list_tail(blkif);
			blkif_put(blkif);
		}
	}
}

static void maybe_trigger_blkio_schedule(void)
{
	/*
	 * Needed so that two processes, who together make the following
	 * predicate true, don't both read stale values and evaluate the
	 * predicate incorrectly. Incredibly unlikely to stall the scheduler
	 * on the x86, but...
	 */
	smp_mb();

	if ((NR_PENDING_REQS < (MAX_PENDING_REQS/2)) &&
	    !list_empty(&blkio_schedule_list))
		wake_up(&blkio_schedule_wait);
}



/******************************************************************
 * COMPLETION CALLBACK -- Called as bh->b_end_io()
 */


static int blktap_read_ufe_ring(void)
{
	/* This is called to read responses from the UFE ring. */

	RING_IDX i, j, rp;
	blkif_response_t *resp;
	blkif_t *blkif;
	int pending_idx;
	pending_req_t *pending_req;
	unsigned long     flags;

	/* if we are forwarding from UFERring to FERing */
	if (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) {

		/* for each outstanding message on the UFEring  */
		rp = blktap_ufe_ring.sring->rsp_prod;
		rmb();
        
		for (i = blktap_ufe_ring.rsp_cons; i != rp; i++) {
			resp = RING_GET_RESPONSE(&blktap_ufe_ring, i);
			pending_idx = MASK_PEND_IDX(ID_TO_IDX(resp->id));
			pending_req = &pending_reqs[pending_idx];
            
			blkif = pending_req->blkif;
			for (j = 0; j < pending_req->nr_pages; j++) {
				unsigned long vaddr;
				struct page **map = blktap_vma->vm_private_data;
				int offset; 

				vaddr  = MMAP_VADDR(user_vstart, pending_idx, j);
				offset = (vaddr - blktap_vma->vm_start) >> PAGE_SHIFT;

				//ClearPageReserved(virt_to_page(vaddr));
				ClearPageReserved((struct page *)map[offset]);
				map[offset] = NULL;
			}

			fast_flush_area(pending_idx, pending_req->nr_pages);
			make_response(blkif, pending_req->id, resp->operation, 
				      resp->status);
			blkif_put(pending_req->blkif);
			spin_lock_irqsave(&pend_prod_lock, flags);
			pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
			spin_unlock_irqrestore(&pend_prod_lock, flags);
		}
		blktap_ufe_ring.rsp_cons = i;
		maybe_trigger_blkio_schedule();
	}
	return 0;
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

irqreturn_t blkif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
	blkif_t *blkif = dev_id;
	add_to_blkdev_list_tail(blkif);
	maybe_trigger_blkio_schedule();
	return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */

static int do_block_io_op(blkif_t *blkif, int max_to_do)
{
	blkif_back_ring_t *blk_ring = &blkif->blk_ring;
	blkif_request_t *req;
	RING_IDX i, rp;
	int more_to_do = 0;
    
	rp = blk_ring->sring->req_prod;
	rmb(); /* Ensure we see queued requests up to 'rp'. */

	for (i = blk_ring->req_cons; 
	     (i != rp) && !RING_REQUEST_CONS_OVERFLOW(blk_ring, i);
	     i++ ) {
		if ((max_to_do-- == 0) ||
		    (NR_PENDING_REQS == MAX_PENDING_REQS)) {
			more_to_do = 1;
			break;
		}
        
		req = RING_GET_REQUEST(blk_ring, i);
		switch (req->operation) {
		case BLKIF_OP_READ:
		case BLKIF_OP_WRITE:
			dispatch_rw_block_io(blkif, req);
			break;

		default:
			DPRINTK("error: unknown block io operation [%d]\n",
				req->operation);
			make_response(blkif, req->id, req->operation,
				      BLKIF_RSP_ERROR);
			break;
		}
	}

	blk_ring->req_cons = i;
	blktap_kick_user();

	return more_to_do;
}

static void dispatch_rw_block_io(blkif_t *blkif, blkif_request_t *req)
{
	blkif_request_t *target;
	int i, pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];
	pending_req_t *pending_req;
	struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
	int op, ret;
	unsigned int nseg;
	int retval;

	/* Check that number of segments is sane. */
	nseg = req->nr_segments;
	if (unlikely(nseg == 0) || 
	    unlikely(nseg > BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
		DPRINTK("Bad number of segments in request (%d)\n", nseg);
		goto bad_descriptor;
	}

	/* Make sure userspace is ready. */
	if (!blktap_ring_ok) {
		DPRINTK("blktap: ring not ready for requests!\n");
		goto bad_descriptor;
	}
    

	if (RING_FULL(&blktap_ufe_ring)) {
		WPRINTK("blktap: fe_ring is full, can't add "
			"(very broken!).\n");
		goto bad_descriptor;
	}

	flush_cache_all(); /* a noop on intel... */

	/* Map the foreign pages directly in to the application */    
	op = 0;
	for (i = 0; i < req->nr_segments; i++) {

		unsigned long uvaddr;
		unsigned long kvaddr;
		uint64_t ptep;
		uint32_t flags;

		uvaddr = MMAP_VADDR(user_vstart, pending_idx, i);
		kvaddr = MMAP_VADDR(mmap_vstart, pending_idx, i);

		flags = GNTMAP_host_map;
		/* This needs a bit more thought in terms of interposition: 
		 * If we want to be able to modify pages during write using 
		 * grant table mappings, the guest will either need to allow 
		 * it, or we'll need to incur a copy. Bit of an fbufs moment. ;) */
		if (req->operation == BLKIF_OP_WRITE)
			flags |= GNTMAP_readonly;
		/* Map the remote page to kernel. */
		gnttab_set_map_op(&map[op], kvaddr, flags, req->seg[i].gref,
				  blkif->domid);
		op++;

		/* Now map it to user. */
		ret = create_lookup_pte_addr(blktap_vma->vm_mm, uvaddr, &ptep);
		if (ret) {
			DPRINTK("Couldn't get a pte addr!\n");
			fast_flush_area(pending_idx, req->nr_segments);
			goto bad_descriptor;
		}

		flags = GNTMAP_host_map | GNTMAP_application_map
			| GNTMAP_contains_pte;
		/* Above interposition comment applies here as well. */
		if (req->operation == BLKIF_OP_WRITE)
			flags |= GNTMAP_readonly;
		gnttab_set_map_op(&map[op], ptep, flags, req->seg[i].gref,
				  blkif->domid);
		op++;
	}

	retval = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, op);
	BUG_ON(retval);

	op = 0;
	for (i = 0; i < (req->nr_segments*2); i += 2) {
		unsigned long uvaddr;
		unsigned long kvaddr;
		unsigned long offset;
		int cancel = 0;

		uvaddr = MMAP_VADDR(user_vstart, pending_idx, i/2);
		kvaddr = MMAP_VADDR(mmap_vstart, pending_idx, i/2);

		if (unlikely(map[i].status)) {
			DPRINTK("Error on kernel grant mapping (%d)\n",
				map[i].status);
			ret = map[i].status;
			cancel = 1;
		}

		if (unlikely(map[i+1].status)) {
			DPRINTK("Error on user grant mapping (%d)\n",
				map[i+1].status);
			ret = map[i+1].status;
			cancel = 1;
		}

		if (cancel) {
			fast_flush_area(pending_idx, req->nr_segments);
			goto bad_descriptor;
		}

		/* Set the necessary mappings in p2m and in the VM_FOREIGN 
		 * vm_area_struct to allow user vaddr -> struct page lookups
		 * to work.  This is needed for direct IO to foreign pages. */
		set_phys_to_machine(__pa(kvaddr) >> PAGE_SHIFT,
				FOREIGN_FRAME(map[i].dev_bus_addr >> PAGE_SHIFT));

		offset = (uvaddr - blktap_vma->vm_start) >> PAGE_SHIFT;
		((struct page **)blktap_vma->vm_private_data)[offset] =
			pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);

		/* Save handles for unmapping later. */
		pending_handle(pending_idx, i/2).kernel = map[i].handle;
		pending_handle(pending_idx, i/2).user   = map[i+1].handle;
	}

	/* Mark mapped pages as reserved: */
	for (i = 0; i < req->nr_segments; i++) {
		unsigned long kvaddr;
		kvaddr = MMAP_VADDR(mmap_vstart, pending_idx, i);
		SetPageReserved(pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT));
	}

	pending_req = &pending_reqs[pending_idx];
	pending_req->blkif     = blkif;
	pending_req->id        = req->id;
	pending_req->operation = req->operation;
	pending_req->status    = BLKIF_RSP_OKAY;
	pending_req->nr_pages  = nseg;
	req->id = MAKE_ID(blkif->domid, pending_idx);
	//atomic_set(&pending_req->pendcnt, nbio);
	pending_cons++;
	blkif_get(blkif);

	/* Finally, write the request message to the user ring. */
	target = RING_GET_REQUEST(&blktap_ufe_ring,
				  blktap_ufe_ring.req_prod_pvt);
	memcpy(target, req, sizeof(*req));
	blktap_ufe_ring.req_prod_pvt++;
	return;

 bad_descriptor:
	make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(blkif_t *blkif, unsigned long id, 
                          unsigned short op, int st)
{
	blkif_response_t *resp;
	unsigned long     flags;
	blkif_back_ring_t *blk_ring = &blkif->blk_ring;

	/* Place on the response ring for the relevant domain. */ 
	spin_lock_irqsave(&blkif->blk_ring_lock, flags);
	resp = RING_GET_RESPONSE(blk_ring, blk_ring->rsp_prod_pvt);
	resp->id        = id;
	resp->operation = op;
	resp->status    = st;
	wmb(); /* Ensure other side can see the response fields. */
	blk_ring->rsp_prod_pvt++;
	RING_PUSH_RESPONSES(blk_ring);
	spin_unlock_irqrestore(&blkif->blk_ring_lock, flags);

	/* Kick the relevant domain. */
	notify_remote_via_irq(blkif->irq);
}

static struct miscdevice blktap_miscdev = {
	.minor        = BLKTAP_MINOR,
	.name         = "blktap",
	.fops         = &blktap_fops,
	.devfs_name   = "misc/blktap",
};

void blkif_deschedule(blkif_t *blkif)
{
	remove_from_blkdev_list(blkif);
}

static int __init blkif_init(void)
{
	int i, j, err;
	struct page *page;

	blkif_interface_init();

	page = balloon_alloc_empty_page_range(MMAP_PAGES);
	BUG_ON(page == NULL);
	mmap_vstart = (unsigned long)pfn_to_kaddr(page_to_pfn(page));

	pending_cons = 0;
	pending_prod = MAX_PENDING_REQS;
	memset(pending_reqs, 0, sizeof(pending_reqs));
	for ( i = 0; i < MAX_PENDING_REQS; i++ )
		pending_ring[i] = i;
    
	spin_lock_init(&blkio_schedule_list_lock);
	INIT_LIST_HEAD(&blkio_schedule_list);

	i = kernel_thread(blkio_schedule, 0, CLONE_FS | CLONE_FILES);
	BUG_ON(i<0);

	blkif_xenbus_init();

	for (i = 0; i < MAX_PENDING_REQS ; i++)
		for (j = 0; j < BLKIF_MAX_SEGMENTS_PER_REQUEST; j++)
			BLKTAP_INVALIDATE_HANDLE(&pending_handle(i, j));

	err = misc_register(&blktap_miscdev);
	if (err != 0) {
		printk(KERN_ALERT "Couldn't register /dev/misc/blktap (%d)\n",
		       err);
		return err;
	}

	init_waitqueue_head(&blktap_wait);

	return 0;
}

__initcall(blkif_init);
