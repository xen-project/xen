/*
 *  linux/drivers/block/ll_rw_blk.c
 *
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 1994,      Karl Keyte: Added support for disk statistics
 * Elevator latency, (C) 2000  Andrea Arcangeli <andrea@suse.de> SuSE
 * Queue request tables / lock, selectable elevator, Jens Axboe <axboe@suse.de>
 * kernel-doc documentation started by NeilBrown <neilb@cse.unsw.edu.au> -  July2000
 */

/*
 * This handles all read/write requests to block devices
 */
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/config.h>
#include <linux/locks.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>

#include <asm/system.h>
#include <asm/io.h>
#include <linux/blk.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/module.h>

/*
 * MAC Floppy IWM hooks
 */

#ifdef CONFIG_MAC_FLOPPY_IWM
extern int mac_floppy_init(void);
#endif

/*
 * For the allocated request tables
 */
static kmem_cache_t *request_cachep;

/*
 * The "disk" task queue is used to start the actual requests
 * after a plug
 */
DECLARE_TASK_QUEUE(tq_disk);

/*
 * Protect the request list against multiple users..
 *
 * With this spinlock the Linux block IO subsystem is 100% SMP threaded
 * from the IRQ event side, and almost 100% SMP threaded from the syscall
 * side (we still have protect against block device array operations, and
 * the do_request() side is casually still unsafe. The kernel lock protects
 * this part currently.).
 *
 * there is a fair chance that things will work just OK if these functions
 * are called with no global kernel lock held ...
 */
spinlock_t io_request_lock = SPIN_LOCK_UNLOCKED;

/* This specifies how many sectors to read ahead on the disk. */

int read_ahead[MAX_BLKDEV];

/* blk_dev_struct is:
 *	*request_fn
 *	*current_request
 */
struct blk_dev_struct blk_dev[MAX_BLKDEV]; /* initialized by blk_dev_init() */

/*
 * blk_size contains the size of all block-devices in units of 1024 byte
 * sectors:
 *
 * blk_size[MAJOR][MINOR]
 *
 * if (!blk_size[MAJOR]) then no minor size checking is done.
 */
int * blk_size[MAX_BLKDEV];

/*
 * blksize_size contains the size of all block-devices:
 *
 * blksize_size[MAJOR][MINOR]
 *
 * if (!blksize_size[MAJOR]) then 1024 bytes is assumed.
 */
int * blksize_size[MAX_BLKDEV];

/*
 * hardsect_size contains the size of the hardware sector of a device.
 *
 * hardsect_size[MAJOR][MINOR]
 *
 * if (!hardsect_size[MAJOR])
 *		then 512 bytes is assumed.
 * else
 *		sector_size is hardsect_size[MAJOR][MINOR]
 * This is currently set by some scsi devices and read by the msdos fs driver.
 * Other uses may appear later.
 */
int * hardsect_size[MAX_BLKDEV];

/*
 * The following tunes the read-ahead algorithm in mm/filemap.c
 */
int * max_readahead[MAX_BLKDEV];

/*
 * Max number of sectors per request
 */
int * max_sectors[MAX_BLKDEV];

/*
 * How many reqeusts do we allocate per queue,
 * and how many do we "batch" on freeing them?
 */
static int queue_nr_requests, batch_requests;

static inline int get_max_sectors(kdev_t dev)
{
	if (!max_sectors[MAJOR(dev)])
		return MAX_SECTORS;
	return max_sectors[MAJOR(dev)][MINOR(dev)];
}

inline request_queue_t *blk_get_queue(kdev_t dev)
{
	struct blk_dev_struct *bdev = blk_dev + MAJOR(dev);

	if (bdev->queue)
		return bdev->queue(dev);
	else
		return &blk_dev[MAJOR(dev)].request_queue;
}

static int __blk_cleanup_queue(struct request_list *list)
{
	struct list_head *head = &list->free;
	struct request *rq;
	int i = 0;

	while (!list_empty(head)) {
		rq = list_entry(head->next, struct request, queue);
		list_del(&rq->queue);
		kmem_cache_free(request_cachep, rq);
		i++;
	};

	if (i != list->count)
		printk("request list leak!\n");

	list->count = 0;
	return i;
}

/**
 * blk_cleanup_queue: - release a &request_queue_t when it is no longer needed
 * @q:    the request queue to be released
 *
 * Description:
 *     blk_cleanup_queue is the pair to blk_init_queue().  It should
 *     be called when a request queue is being released; typically
 *     when a block device is being de-registered.  Currently, its
 *     primary task it to free all the &struct request structures that
 *     were allocated to the queue.
 * Caveat: 
 *     Hopefully the low level driver will have finished any
 *     outstanding requests first...
 **/
void blk_cleanup_queue(request_queue_t * q)
{
	int count = queue_nr_requests;

	count -= __blk_cleanup_queue(&q->rq[READ]);
	count -= __blk_cleanup_queue(&q->rq[WRITE]);

	if (count)
		printk("blk_cleanup_queue: leaked requests (%d)\n", count);

	memset(q, 0, sizeof(*q));
}

/**
 * blk_queue_headactive - indicate whether head of request queue may be active
 * @q:       The queue which this applies to.
 * @active:  A flag indication where the head of the queue is active.
 *
 * Description:
 *    The driver for a block device may choose to leave the currently active
 *    request on the request queue, removing it only when it has completed.
 *    The queue handling routines assume this by default for safety reasons
 *    and will not involve the head of the request queue in any merging or
 *    reordering of requests when the queue is unplugged (and thus may be
 *    working on this particular request).
 *
 *    If a driver removes requests from the queue before processing them, then
 *    it may indicate that it does so, there by allowing the head of the queue
 *    to be involved in merging and reordering.  This is done be calling
 *    blk_queue_headactive() with an @active flag of %0.
 *
 *    If a driver processes several requests at once, it must remove them (or
 *    at least all but one of them) from the request queue.
 *
 *    When a queue is plugged the head will be assumed to be inactive.
 **/
 
void blk_queue_headactive(request_queue_t * q, int active)
{
	q->head_active = active;
}

/**
 * blk_queue_make_request - define an alternate make_request function for a device
 * @q:  the request queue for the device to be affected
 * @mfn: the alternate make_request function
 *
 * Description:
 *    The normal way for &struct buffer_heads to be passed to a device
 *    driver is for them to be collected into requests on a request
 *    queue, and then to allow the device driver to select requests
 *    off that queue when it is ready.  This works well for many block
 *    devices. However some block devices (typically virtual devices
 *    such as md or lvm) do not benefit from the processing on the
 *    request queue, and are served best by having the requests passed
 *    directly to them.  This can be achieved by providing a function
 *    to blk_queue_make_request().
 *
 * Caveat:
 *    The driver that does this *must* be able to deal appropriately
 *    with buffers in "highmemory", either by calling bh_kmap() to get
 *    a kernel mapping, to by calling create_bounce() to create a
 *    buffer in normal memory.
 **/

void blk_queue_make_request(request_queue_t * q, make_request_fn * mfn)
{
	q->make_request_fn = mfn;
}

static inline int ll_new_segment(request_queue_t *q, struct request *req, int max_segments)
{
	if (req->nr_segments < max_segments) {
		req->nr_segments++;
		return 1;
	}
	return 0;
}

static int ll_back_merge_fn(request_queue_t *q, struct request *req, 
			    struct buffer_head *bh, int max_segments)
{
	if (req->bhtail->b_data + req->bhtail->b_size == bh->b_data)
		return 1;
	return ll_new_segment(q, req, max_segments);
}

static int ll_front_merge_fn(request_queue_t *q, struct request *req, 
			     struct buffer_head *bh, int max_segments)
{
	if (bh->b_data + bh->b_size == req->bh->b_data)
		return 1;
	return ll_new_segment(q, req, max_segments);
}

static int ll_merge_requests_fn(request_queue_t *q, struct request *req,
				struct request *next, int max_segments)
{
	int total_segments = req->nr_segments + next->nr_segments;

	if (req->bhtail->b_data + req->bhtail->b_size == next->bh->b_data)
		total_segments--;
    
	if (total_segments > max_segments)
		return 0;

	req->nr_segments = total_segments;
	return 1;
}

/*
 * "plug" the device if there are no outstanding requests: this will
 * force the transfer to start only after we have put all the requests
 * on the list.
 *
 * This is called with interrupts off and no requests on the queue.
 * (and with the request spinlock acquired)
 */
static void generic_plug_device(request_queue_t *q, kdev_t dev)
{
	/*
	 * no need to replug device
	 */
	if (!list_empty(&q->queue_head) || q->plugged)
		return;

	q->plugged = 1;
	queue_task(&q->plug_tq, &tq_disk);
}

/*
 * remove the plug and let it rip..
 */
static inline void __generic_unplug_device(request_queue_t *q)
{
	if (q->plugged) {
		q->plugged = 0;
		if (!list_empty(&q->queue_head))
			q->request_fn(q);
	}
}

void generic_unplug_device(void *data)
{
	request_queue_t *q = (request_queue_t *) data;
	unsigned long flags;

	spin_lock_irqsave(&io_request_lock, flags);
	__generic_unplug_device(q);
	spin_unlock_irqrestore(&io_request_lock, flags);
}

static void blk_init_free_list(request_queue_t *q)
{
	struct request *rq;
	int i;

	INIT_LIST_HEAD(&q->rq[READ].free);
	INIT_LIST_HEAD(&q->rq[WRITE].free);
	q->rq[READ].count = 0;
	q->rq[WRITE].count = 0;

	/*
	 * Divide requests in half between read and write
	 */
	for (i = 0; i < queue_nr_requests; i++) {
		rq = kmem_cache_alloc(request_cachep, SLAB_KERNEL);
		if (rq == NULL) {
			/* We'll get a `leaked requests' message from blk_cleanup_queue */
			printk(KERN_EMERG "blk_init_free_list: error allocating requests\n");
			break;
		}
		memset(rq, 0, sizeof(struct request));
		rq->rq_status = RQ_INACTIVE;
		list_add(&rq->queue, &q->rq[i&1].free);
		q->rq[i&1].count++;
	}

	init_waitqueue_head(&q->wait_for_request);
	spin_lock_init(&q->queue_lock);
}

static int __make_request(request_queue_t * q, int rw, struct buffer_head * bh);

/**
 * blk_init_queue  - prepare a request queue for use with a block device
 * @q:    The &request_queue_t to be initialised
 * @rfn:  The function to be called to process requests that have been
 *        placed on the queue.
 *
 * Description:
 *    If a block device wishes to use the standard request handling procedures,
 *    which sorts requests and coalesces adjacent requests, then it must
 *    call blk_init_queue().  The function @rfn will be called when there
 *    are requests on the queue that need to be processed.  If the device
 *    supports plugging, then @rfn may not be called immediately when requests
 *    are available on the queue, but may be called at some time later instead.
 *    Plugged queues are generally unplugged when a buffer belonging to one
 *    of the requests on the queue is needed, or due to memory pressure.
 *
 *    @rfn is not required, or even expected, to remove all requests off the
 *    queue, but only as many as it can handle at a time.  If it does leave
 *    requests on the queue, it is responsible for arranging that the requests
 *    get dealt with eventually.
 *
 *    A global spin lock $io_request_lock must be held while manipulating the
 *    requests on the request queue.
 *
 *    The request on the head of the queue is by default assumed to be
 *    potentially active, and it is not considered for re-ordering or merging
 *    whenever the given queue is unplugged. This behaviour can be changed with
 *    blk_queue_headactive().
 *
 * Note:
 *    blk_init_queue() must be paired with a blk_cleanup_queue() call
 *    when the block device is deactivated (such as at module unload).
 **/
void blk_init_queue(request_queue_t * q, request_fn_proc * rfn)
{
	INIT_LIST_HEAD(&q->queue_head);
	elevator_init(&q->elevator, ELEVATOR_LINUS);
	blk_init_free_list(q);
	q->request_fn     	= rfn;
	q->back_merge_fn       	= ll_back_merge_fn;
	q->front_merge_fn      	= ll_front_merge_fn;
	q->merge_requests_fn	= ll_merge_requests_fn;
	q->make_request_fn	= __make_request;
	q->plug_tq.sync		= 0;
	q->plug_tq.routine	= &generic_unplug_device;
	q->plug_tq.data		= q;
	q->plugged        	= 0;
	/*
	 * These booleans describe the queue properties.  We set the
	 * default (and most common) values here.  Other drivers can
	 * use the appropriate functions to alter the queue properties.
	 * as appropriate.
	 */
	q->plug_device_fn 	= generic_plug_device;
	q->head_active    	= 1;
}

#define blkdev_free_rq(list) list_entry((list)->next, struct request, queue);
/*
 * Get a free request. io_request_lock must be held and interrupts
 * disabled on the way in.
 */
static inline struct request *get_request(request_queue_t *q, int rw)
{
	struct request *rq = NULL;
	struct request_list *rl = q->rq + rw;

	if (!list_empty(&rl->free)) {
		rq = blkdev_free_rq(&rl->free);
		list_del(&rq->queue);
		rl->count--;
		rq->rq_status = RQ_ACTIVE;
		rq->special = NULL;
		rq->q = q;
	}

	return rq;
}

/*
 * No available requests for this queue, unplug the device.
 */
static struct request *__get_request_wait(request_queue_t *q, int rw)
{
	register struct request *rq;
	DECLARE_WAITQUEUE(wait, current);

	generic_unplug_device(q);
	add_wait_queue(&q->wait_for_request, &wait);
	do {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (q->rq[rw].count < batch_requests)
			schedule();
		spin_lock_irq(&io_request_lock);
		rq = get_request(q,rw);
		spin_unlock_irq(&io_request_lock);
	} while (rq == NULL);
	remove_wait_queue(&q->wait_for_request, &wait);
	current->state = TASK_RUNNING;
	return rq;
}

static inline struct request *get_request_wait(request_queue_t *q, int rw)
{
	register struct request *rq;

	spin_lock_irq(&io_request_lock);
	rq = get_request(q, rw);
	spin_unlock_irq(&io_request_lock);
	if (rq)
		return rq;
	return __get_request_wait(q, rw);
}

/* RO fail safe mechanism */

static long ro_bits[MAX_BLKDEV][8];

int is_read_only(kdev_t dev)
{
	int minor,major;

	major = MAJOR(dev);
	minor = MINOR(dev);
	if (major < 0 || major >= MAX_BLKDEV) return 0;
	return ro_bits[major][minor >> 5] & (1 << (minor & 31));
}

void set_device_ro(kdev_t dev,int flag)
{
	int minor,major;

	major = MAJOR(dev);
	minor = MINOR(dev);
	if (major < 0 || major >= MAX_BLKDEV) return;
	if (flag) ro_bits[major][minor >> 5] |= 1 << (minor & 31);
	else ro_bits[major][minor >> 5] &= ~(1 << (minor & 31));
}

inline void drive_stat_acct (kdev_t dev, int rw,
				unsigned long nr_sectors, int new_io)
{
	unsigned int major = MAJOR(dev);
	unsigned int index;

	index = disk_index(dev);
	if ((index >= DK_MAX_DISK) || (major >= DK_MAX_MAJOR))
		return;

	kstat.dk_drive[major][index] += new_io;
	if (rw == READ) {
		kstat.dk_drive_rio[major][index] += new_io;
		kstat.dk_drive_rblk[major][index] += nr_sectors;
	} else if (rw == WRITE) {
		kstat.dk_drive_wio[major][index] += new_io;
		kstat.dk_drive_wblk[major][index] += nr_sectors;
	} else
		printk(KERN_ERR "drive_stat_acct: cmd not R/W?\n");
}

/*
 * add-request adds a request to the linked list.
 * io_request_lock is held and interrupts disabled, as we muck with the
 * request queue list.
 *
 * By this point, req->cmd is always either READ/WRITE, never READA,
 * which is important for drive_stat_acct() above.
 */
static inline void add_request(request_queue_t * q, struct request * req,
			       struct list_head *insert_here)
{
	drive_stat_acct(req->rq_dev, req->cmd, req->nr_sectors, 1);

	if (!q->plugged && q->head_active && insert_here == &q->queue_head) {
		spin_unlock_irq(&io_request_lock);
		BUG();
	}

	/*
	 * elevator indicated where it wants this request to be
	 * inserted at elevator_merge time
	 */
	list_add(&req->queue, insert_here);
}

/*
 * Must be called with io_request_lock held and interrupts disabled
 */
inline void blkdev_release_request(struct request *req)
{
	request_queue_t *q = req->q;
	int rw = req->cmd;

	req->rq_status = RQ_INACTIVE;
	req->q = NULL;

	/*
	 * Request may not have originated from ll_rw_blk. if not,
	 * assume it has free buffers and check waiters
	 */
	if (q) {
		list_add(&req->queue, &q->rq[rw].free);
		if (++q->rq[rw].count >= batch_requests && waitqueue_active(&q->wait_for_request))
			wake_up(&q->wait_for_request);
	}
}

/*
 * Has to be called with the request spinlock acquired
 */
static void attempt_merge(request_queue_t * q,
			  struct request *req,
			  int max_sectors,
			  int max_segments)
{
	struct request *next;
  
	next = blkdev_next_request(req);
	if (req->sector + req->nr_sectors != next->sector)
		return;
	if (req->cmd != next->cmd
	    || req->rq_dev != next->rq_dev
	    || req->nr_sectors + next->nr_sectors > max_sectors
	    || next->waiting)
		return;
	/*
	 * If we are not allowed to merge these requests, then
	 * return.  If we are allowed to merge, then the count
	 * will have been updated to the appropriate number,
	 * and we shouldn't do it here too.
	 */
	if (!q->merge_requests_fn(q, req, next, max_segments))
		return;

	q->elevator.elevator_merge_req_fn(req, next);
	req->bhtail->b_reqnext = next->bh;
	req->bhtail = next->bhtail;
	req->nr_sectors = req->hard_nr_sectors += next->hard_nr_sectors;
	list_del(&next->queue);
	blkdev_release_request(next);
}

static inline void attempt_back_merge(request_queue_t * q,
				      struct request *req,
				      int max_sectors,
				      int max_segments)
{
	if (&req->queue == q->queue_head.prev)
		return;
	attempt_merge(q, req, max_sectors, max_segments);
}

static inline void attempt_front_merge(request_queue_t * q,
				       struct list_head * head,
				       struct request *req,
				       int max_sectors,
				       int max_segments)
{
	struct list_head * prev;

	prev = req->queue.prev;
	if (head == prev)
		return;
	attempt_merge(q, blkdev_entry_to_request(prev), max_sectors, max_segments);
}

static int __make_request(request_queue_t * q, int rw,
				  struct buffer_head * bh)
{
	unsigned int sector, count;
	int max_segments = MAX_SEGMENTS;
	struct request * req, *freereq = NULL;
	int rw_ahead, max_sectors, el_ret;
	struct list_head *head, *insert_here;
	int latency;
	elevator_t *elevator = &q->elevator;

	count = bh->b_size >> 9;
	sector = bh->b_rsector;

	rw_ahead = 0;	/* normal case; gets changed below for READA */
	switch (rw) {
		case READA:
			rw_ahead = 1;
			rw = READ;	/* drop into READ */
		case READ:
		case WRITE:
			latency = elevator_request_latency(elevator, rw);
			break;
		default:
			BUG();
			goto end_io;
	}

	/* We'd better have a real physical mapping!
	   Check this bit only if the buffer was dirty and just locked
	   down by us so at this point flushpage will block and
	   won't clear the mapped bit under us. */
	if (!buffer_mapped(bh))
		BUG();

	/*
	 * Temporary solution - in 2.5 this will be done by the lowlevel
	 * driver. Create a bounce buffer if the buffer data points into
	 * high memory - keep the original buffer otherwise.
	 */
#if CONFIG_HIGHMEM
	bh = create_bounce(rw, bh);
#endif

/* look for a free request. */
	/*
	 * Try to coalesce the new request with old requests
	 */
	max_sectors = get_max_sectors(bh->b_rdev);

again:
	req = NULL;
	head = &q->queue_head;
	/*
	 * Now we acquire the request spinlock, we have to be mega careful
	 * not to schedule or do something nonatomic
	 */
	spin_lock_irq(&io_request_lock);

	insert_here = head->prev;
	if (list_empty(head)) {
		q->plug_device_fn(q, bh->b_rdev); /* is atomic */
		goto get_rq;
	} else if (q->head_active && !q->plugged)
		head = head->next;

	el_ret = elevator->elevator_merge_fn(q, &req, head, bh, rw,max_sectors);
	switch (el_ret) {

		case ELEVATOR_BACK_MERGE:
			if (!q->back_merge_fn(q, req, bh, max_segments))
				break;
			elevator->elevator_merge_cleanup_fn(q, req, count);
			req->bhtail->b_reqnext = bh;
			req->bhtail = bh;
			req->nr_sectors = req->hard_nr_sectors += count;
			blk_started_io(count);
			drive_stat_acct(req->rq_dev, req->cmd, count, 0);
			attempt_back_merge(q, req, max_sectors, max_segments);
			goto out;

		case ELEVATOR_FRONT_MERGE:
			if (!q->front_merge_fn(q, req, bh, max_segments))
				break;
			elevator->elevator_merge_cleanup_fn(q, req, count);
			bh->b_reqnext = req->bh;
			req->bh = bh;
			req->buffer = bh->b_data;
			req->current_nr_sectors = count;
			req->sector = req->hard_sector = sector;
			req->nr_sectors = req->hard_nr_sectors += count;
			blk_started_io(count);
			drive_stat_acct(req->rq_dev, req->cmd, count, 0);
			attempt_front_merge(q, head, req, max_sectors, max_segments);
			goto out;

		/*
		 * elevator says don't/can't merge. get new request
		 */
		case ELEVATOR_NO_MERGE:
			/*
			 * use elevator hints as to where to insert the
			 * request. if no hints, just add it to the back
			 * of the queue
			 */
			if (req)
				insert_here = &req->queue;
			break;

		default:
			printk("elevator returned crap (%d)\n", el_ret);
			BUG();
	}
		
	/*
	 * Grab a free request from the freelist - if that is empty, check
	 * if we are doing read ahead and abort instead of blocking for
	 * a free slot.
	 */
get_rq:
	if (freereq) {
		req = freereq;
		freereq = NULL;
	} else if ((req = get_request(q, rw)) == NULL) {
		spin_unlock_irq(&io_request_lock);
		if (rw_ahead)
			goto end_io;

		freereq = __get_request_wait(q, rw);
		goto again;
	}

/* fill up the request-info, and add it to the queue */
	req->elevator_sequence = latency;
	req->cmd = rw;
	req->errors = 0;
	req->hard_sector = req->sector = sector;
	req->hard_nr_sectors = req->nr_sectors = count;
	req->current_nr_sectors = count;
	req->nr_segments = 1; /* Always 1 for a new request. */
	req->nr_hw_segments = 1; /* Always 1 for a new request. */
	req->buffer = bh->b_data;
	req->waiting = NULL;
	req->bh = bh;
	req->bhtail = bh;
	req->rq_dev = bh->b_rdev;
	blk_started_io(count);
	add_request(q, req, insert_here);
out:
	if (freereq)
		blkdev_release_request(freereq);
	spin_unlock_irq(&io_request_lock);
	return 0;
end_io:
	bh->b_end_io(bh, test_bit(BH_Uptodate, &bh->b_state));
	return 0;
}

/**
 * generic_make_request: hand a buffer head to it's device driver for I/O
 * @rw:  READ, WRITE, or READA - what sort of I/O is desired.
 * @bh:  The buffer head describing the location in memory and on the device.
 *
 * generic_make_request() is used to make I/O requests of block
 * devices. It is passed a &struct buffer_head and a &rw value.  The
 * %READ and %WRITE options are (hopefully) obvious in meaning.  The
 * %READA value means that a read is required, but that the driver is
 * free to fail the request if, for example, it cannot get needed
 * resources immediately.
 *
 * generic_make_request() does not return any status.  The
 * success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the bh->b_end_io
 * function described (one day) else where.
 *
 * The caller of generic_make_request must make sure that b_page,
 * b_addr, b_size are set to describe the memory buffer, that b_rdev
 * and b_rsector are set to describe the device address, and the
 * b_end_io and optionally b_private are set to describe how
 * completion notification should be signaled.  BH_Mapped should also
 * be set (to confirm that b_dev and b_blocknr are valid).
 *
 * generic_make_request and the drivers it calls may use b_reqnext,
 * and may change b_rdev and b_rsector.  So the values of these fields
 * should NOT be depended on after the call to generic_make_request.
 * Because of this, the caller should record the device address
 * information in b_dev and b_blocknr.
 *
 * Apart from those fields mentioned above, no other fields, and in
 * particular, no other flags, are changed by generic_make_request or
 * any lower level drivers.
 * */
void generic_make_request (int rw, struct buffer_head * bh)
{
	int major = MAJOR(bh->b_rdev);
	int minorsize = 0;
	request_queue_t *q;

	if (!bh->b_end_io)
		BUG();

	/* Test device size, when known. */
	if (blk_size[major])
		minorsize = blk_size[major][MINOR(bh->b_rdev)];
	if (minorsize) {
		unsigned long maxsector = (minorsize << 1) + 1;
		unsigned long sector = bh->b_rsector;
		unsigned int count = bh->b_size >> 9;

		if (maxsector < count || maxsector - count < sector) {
			/* Yecch */
			bh->b_state &= (1 << BH_Lock) | (1 << BH_Mapped);

			/* This may well happen - the kernel calls bread()
			   without checking the size of the device, e.g.,
			   when mounting a device. */
			printk(KERN_INFO
			       "attempt to access beyond end of device\n");
			printk(KERN_INFO "%s: rw=%d, want=%ld, limit=%d\n",
			       kdevname(bh->b_rdev), rw,
			       (sector + count)>>1, minorsize);

			/* Yecch again */
			bh->b_end_io(bh, 0);
			return;
		}
	}

	/*
	 * Resolve the mapping until finished. (drivers are
	 * still free to implement/resolve their own stacking
	 * by explicitly returning 0)
	 */
	/* NOTE: we don't repeat the blk_size check for each new device.
	 * Stacking drivers are expected to know what they are doing.
	 */
	do {
		q = blk_get_queue(bh->b_rdev);
		if (!q) {
			printk(KERN_ERR
			       "generic_make_request: Trying to access "
			       "nonexistent block-device %s (%ld)\n",
			       kdevname(bh->b_rdev), bh->b_rsector);
			buffer_IO_error(bh);
			break;
		}
	} while (q->make_request_fn(q, rw, bh));
}


/**
 * submit_bh: submit a buffer_head to the block device later for I/O
 * @rw: whether to %READ or %WRITE, or maybe to %READA (read ahead)
 * @bh: The &struct buffer_head which describes the I/O
 *
 * submit_bh() is very similar in purpose to generic_make_request(), and
 * uses that function to do most of the work.
 *
 * The extra functionality provided by submit_bh is to determine
 * b_rsector from b_blocknr and b_size, and to set b_rdev from b_dev.
 * This is is appropriate for IO requests that come from the buffer
 * cache and page cache which (currently) always use aligned blocks.
 */
void submit_bh(int rw, struct buffer_head * bh)
{
	int count = bh->b_size >> 9;

	if (!test_bit(BH_Lock, &bh->b_state))
		BUG();

	set_bit(BH_Req, &bh->b_state);

	/*
	 * First step, 'identity mapping' - RAID or LVM might
	 * further remap this.
	 */
	bh->b_rdev = bh->b_dev;
	bh->b_rsector = bh->b_blocknr * count;

	generic_make_request(rw, bh);

	switch (rw) {
		case WRITE:
			kstat.pgpgout += count;
			break;
		default:
			kstat.pgpgin += count;
			break;
	}
}

/**
 * ll_rw_block: low-level access to block devices
 * @rw: whether to %READ or %WRITE or maybe %READA (readahead)
 * @nr: number of &struct buffer_heads in the array
 * @bhs: array of pointers to &struct buffer_head
 *
 * ll_rw_block() takes an array of pointers to &struct buffer_heads,
 * and requests an I/O operation on them, either a %READ or a %WRITE.
 * The third %READA option is described in the documentation for
 * generic_make_request() which ll_rw_block() calls.
 *
 * This function provides extra functionality that is not in
 * generic_make_request() that is relevant to buffers in the buffer
 * cache or page cache.  In particular it drops any buffer that it
 * cannot get a lock on (with the BH_Lock state bit), any buffer that
 * appears to be clean when doing a write request, and any buffer that
 * appears to be up-to-date when doing read request.  Further it marks
 * as clean buffers that are processed for writing (the buffer cache
 * wont assume that they are actually clean until the buffer gets
 * unlocked).
 *
 * ll_rw_block sets b_end_io to simple completion handler that marks
 * the buffer up-to-date (if approriate), unlocks the buffer and wakes
 * any waiters.  As client that needs a more interesting completion
 * routine should call submit_bh() (or generic_make_request())
 * directly.
 *
 * Caveat:
 *  All of the buffers must be for the same device, and must also be
 *  of the current approved size for the device.  */

void ll_rw_block(int rw, int nr, struct buffer_head * bhs[])
{
	unsigned int major;
	int correct_size;
	int i;

	if (!nr)
		return;

	major = MAJOR(bhs[0]->b_dev);

	/* Determine correct block size for this device. */
	correct_size = get_hardsect_size(bhs[0]->b_dev);

	/* Verify requested block sizes. */
	for (i = 0; i < nr; i++) {
		struct buffer_head *bh = bhs[i];
		if (bh->b_size % correct_size) {
			printk(KERN_NOTICE "ll_rw_block: device %s: "
			       "only %d-char blocks implemented (%u)\n",
			       kdevname(bhs[0]->b_dev),
			       correct_size, bh->b_size);
			goto sorry;
		}
	}

	if ((rw & WRITE) && is_read_only(bhs[0]->b_dev)) {
		printk(KERN_NOTICE "Can't write to read-only device %s\n",
		       kdevname(bhs[0]->b_dev));
		goto sorry;
	}

	for (i = 0; i < nr; i++) {
		struct buffer_head *bh = bhs[i];

		/* Only one thread can actually submit the I/O. */
		if (test_and_set_bit(BH_Lock, &bh->b_state))
			continue;

		/* We have the buffer lock */
		atomic_inc(&bh->b_count);
		bh->b_end_io = end_buffer_io_sync;

		switch(rw) {
		case WRITE:
			if (!atomic_set_buffer_clean(bh))
				/* Hmmph! Nothing to write */
				goto end_io;
			__mark_buffer_clean(bh);
			break;

		case READA:
		case READ:
			if (buffer_uptodate(bh))
				/* Hmmph! Already have it */
				goto end_io;
			break;
		default:
			BUG();
	end_io:
			bh->b_end_io(bh, test_bit(BH_Uptodate, &bh->b_state));
			continue;
		}

		submit_bh(rw, bh);
	}
	return;

sorry:
	/* Make sure we don't get infinite dirty retries.. */
	for (i = 0; i < nr; i++)
		mark_buffer_clean(bhs[i]);
}

#ifdef CONFIG_STRAM_SWAP
extern int stram_device_init (void);
#endif


/**
 * end_that_request_first - end I/O on one buffer.
 * @req:      the request being processed
 * @uptodate: 0 for I/O error
 * @name:     the name printed for an I/O error
 *
 * Description:
 *     Ends I/O on the first buffer attached to @req, and sets it up
 *     for the next buffer_head (if any) in the cluster.
 *     
 * Return:
 *     0 - we are done with this request, call end_that_request_last()
 *     1 - still buffers pending for this request
 *
 * Caveat: 
 *     Drivers implementing their own end_request handling must call
 *     blk_finished_io() appropriately.
 **/

int end_that_request_first (struct request *req, int uptodate, char *name)
{
	struct buffer_head * bh;
	int nsect;

	req->errors = 0;
	if (!uptodate)
		printk("end_request: I/O error, dev %s (%s), sector %lu\n",
			kdevname(req->rq_dev), name, req->sector);

	if ((bh = req->bh) != NULL) {
		nsect = bh->b_size >> 9;
		blk_finished_io(nsect);
		req->bh = bh->b_reqnext;
		bh->b_reqnext = NULL;
		bh->b_end_io(bh, uptodate);
		if ((bh = req->bh) != NULL) {
			req->hard_sector += nsect;
			req->hard_nr_sectors -= nsect;
			req->sector = req->hard_sector;
			req->nr_sectors = req->hard_nr_sectors;

			req->current_nr_sectors = bh->b_size >> 9;
			if (req->nr_sectors < req->current_nr_sectors) {
				req->nr_sectors = req->current_nr_sectors;
				printk("end_request: buffer-list destroyed\n");
			}
			req->buffer = bh->b_data;
			return 1;
		}
	}
	return 0;
}

void end_that_request_last(struct request *req)
{
	if (req->waiting != NULL)
		complete(req->waiting);

	blkdev_release_request(req);
}

#define MB(kb)	((kb) << 10)

int __init blk_dev_init(void)
{
	struct blk_dev_struct *dev;
	int total_ram;

	request_cachep = kmem_cache_create("blkdev_requests",
					   sizeof(struct request),
					   0, SLAB_HWCACHE_ALIGN, NULL, NULL);

	if (!request_cachep)
		panic("Can't create request pool slab cache\n");

	for (dev = blk_dev + MAX_BLKDEV; dev-- != blk_dev;)
		dev->queue = NULL;

	memset(ro_bits,0,sizeof(ro_bits));
	memset(max_readahead, 0, sizeof(max_readahead));
	memset(max_sectors, 0, sizeof(max_sectors));

	total_ram = nr_free_pages() << (PAGE_SHIFT - 10);

	/*
	 * Free request slots per queue.
	 * (Half for reads, half for writes)
	 */
	queue_nr_requests = 64;
	if (total_ram > MB(32))
		queue_nr_requests = 128;

	/*
	 * Batch frees according to queue length
	 */
	batch_requests = queue_nr_requests/4;
	printk("block: %d slots per queue, batch=%d\n", queue_nr_requests, batch_requests);

#ifdef CONFIG_AMIGA_Z2RAM
	z2_init();
#endif
#ifdef CONFIG_STRAM_SWAP
	stram_device_init();
#endif
#ifdef CONFIG_BLK_DEV_RAM
	rd_init();
#endif
#ifdef CONFIG_ISP16_CDI
	isp16_init();
#endif
#if defined(CONFIG_IDE) && defined(CONFIG_BLK_DEV_IDE)
	ide_init();		/* this MUST precede hd_init */
#endif
#if defined(CONFIG_IDE) && defined(CONFIG_BLK_DEV_HD)
	hd_init();
#endif
#ifdef CONFIG_BLK_DEV_PS2
	ps2esdi_init();
#endif
#ifdef CONFIG_BLK_DEV_XD
	xd_init();
#endif
#ifdef CONFIG_BLK_DEV_MFM
	mfm_init();
#endif
#ifdef CONFIG_PARIDE
	{ extern void paride_init(void); paride_init(); };
#endif
#ifdef CONFIG_MAC_FLOPPY
	swim3_init();
#endif
#ifdef CONFIG_BLK_DEV_SWIM_IOP
	swimiop_init();
#endif
#ifdef CONFIG_AMIGA_FLOPPY
	amiga_floppy_init();
#endif
#ifdef CONFIG_ATARI_FLOPPY
	atari_floppy_init();
#endif
#ifdef CONFIG_BLK_DEV_FD
	floppy_init();
#else
#if defined(__i386__) && !defined(CONFIG_XENO) /* Do we even need this? */
	outb_p(0xc, 0x3f2);
#endif
#endif
#ifdef CONFIG_CDU31A
	cdu31a_init();
#endif
#ifdef CONFIG_ATARI_ACSI
	acsi_init();
#endif
#ifdef CONFIG_MCD
	mcd_init();
#endif
#ifdef CONFIG_MCDX
	mcdx_init();
#endif
#ifdef CONFIG_SBPCD
	sbpcd_init();
#endif
#ifdef CONFIG_AZTCD
	aztcd_init();
#endif
#ifdef CONFIG_CDU535
	sony535_init();
#endif
#ifdef CONFIG_GSCD
	gscd_init();
#endif
#ifdef CONFIG_CM206
	cm206_init();
#endif
#ifdef CONFIG_OPTCD
	optcd_init();
#endif
#ifdef CONFIG_SJCD
	sjcd_init();
#endif
#ifdef CONFIG_APBLOCK
	ap_init();
#endif
#ifdef CONFIG_DDV
	ddv_init();
#endif
#ifdef CONFIG_MDISK
	mdisk_init();
#endif
#ifdef CONFIG_DASD
	dasd_init();
#endif
#if defined(CONFIG_S390_TAPE) && defined(CONFIG_S390_TAPE_BLOCK)
	tapeblock_init();
#endif
#ifdef CONFIG_BLK_DEV_XPRAM
        xpram_init();
#endif

#ifdef CONFIG_SUN_JSFLASH
	jsfd_init();
#endif
	return 0;
};

EXPORT_SYMBOL(io_request_lock);
EXPORT_SYMBOL(end_that_request_first);
EXPORT_SYMBOL(end_that_request_last);
EXPORT_SYMBOL(blk_init_queue);
EXPORT_SYMBOL(blk_get_queue);
EXPORT_SYMBOL(blk_cleanup_queue);
EXPORT_SYMBOL(blk_queue_headactive);
EXPORT_SYMBOL(blk_queue_make_request);
EXPORT_SYMBOL(generic_make_request);
EXPORT_SYMBOL(blkdev_release_request);
EXPORT_SYMBOL(generic_unplug_device);
