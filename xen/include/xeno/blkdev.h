#ifndef _LINUX_BLKDEV_H
#define _LINUX_BLKDEV_H

#include <xeno/lib.h>
#include <asm/atomic.h>
#include <asm/bitops.h>
#include <xeno/list.h>
#include <xeno/kdev_t.h>
#include <xeno/sched.h>
#include <xeno/mm.h>

/* Some defines from fs.h that may actually be useful to the blkdev layer. */
#define READ 0
#define WRITE 1
#define READA 2
#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)

typedef struct {
    struct task_struct *domain;
    unsigned long       id;
    atomic_t            pendcnt;
    unsigned short      operation;
    unsigned short      status;
} pending_req_t;

extern kdev_t xendev_to_physdev(unsigned short xendev);

extern void init_blkdev_info(struct task_struct *);
extern void unlink_blkdev_info(struct task_struct *);
extern void destroy_blkdev_info(struct task_struct *);

extern int unregister_blkdev(unsigned int, const char *);
extern int invalidate_device(kdev_t, int);
extern int check_disk_change(kdev_t);
struct block_device;
extern void invalidate_bdev(struct block_device *, int);

/*
 * Metainformation regarding block devices is kept in inode and file
 * structures. We don't actually want those so we define just as much 
 * as we need right here.
 */
struct file {
};
struct inode {
    kdev_t i_rdev; /* for _open and _release, specifies the blkdev */
    struct block_device *i_bdev;
};

struct block_device_operations {
        int (*open) (struct inode *, struct file *);
        int (*release) (struct inode *, struct file *);
        int (*ioctl) (struct inode *, struct file *, unsigned, unsigned long);
        int (*check_media_change) (kdev_t);
        int (*revalidate) (kdev_t);
};


enum bh_state_bits {
        BH_Uptodate,    /* 1 if the buffer contains valid data */
        BH_Dirty,       /* 1 if the buffer is dirty */
        BH_Lock,        /* 1 if the buffer is locked */
        BH_Req,         /* 0 if the buffer has been invalidated */
        BH_Mapped,      /* 1 if the buffer has a disk mapping */
        BH_New,         /* 1 if the buffer is new and not yet written out */
        BH_Async,       /* 1 if the buffer is under end_buffer_io_async I/O */
        BH_Wait_IO,     /* 1 if we should write out this buffer */
        BH_Launder,     /* 1 if we can throttle on this buffer */
        BH_JBD,         /* 1 if it has an attached journal_head */
        BH_Read,        /* 1 if request is a read from disc */
        BH_Write        /* 1 if request is a write to disc */
};

struct buffer_head {
        unsigned long b_rsector;        /* Real buffer location on disk */
        unsigned short b_size;          /* block size */
        kdev_t b_dev;                   /* device (B_FREE = free) */
        unsigned long b_state;          /* buffer state bitmap (see above) */
        struct buffer_head *b_reqnext;  /* request queue */
        char *b_data;                  /* pointer to data block */
        void (*b_end_io)(struct buffer_head *bh, int uptodate);
        pending_req_t *pending_req;
};

#define b_rdev b_dev /* In Xen, there's no device layering (eg. s/w RAID). */

typedef void (bh_end_io_t)(struct buffer_head *bh, int uptodate);
void init_buffer(struct buffer_head *, bh_end_io_t *, void *);

#define __buffer_state(bh, state)       (((bh)->b_state & (1UL << BH_##state)) != 0)

#define buffer_uptodate(bh)     __buffer_state(bh,Uptodate)
#define buffer_dirty(bh)        __buffer_state(bh,Dirty)
#define buffer_locked(bh)       __buffer_state(bh,Lock)
#define buffer_req(bh)          __buffer_state(bh,Req)
#define buffer_mapped(bh)       __buffer_state(bh,Mapped)
#define buffer_new(bh)          __buffer_state(bh,New)
#define buffer_async(bh)        __buffer_state(bh,Async)
#define buffer_launder(bh)      __buffer_state(bh,Launder)

#define bh_offset(bh)           ((unsigned long)(bh)->b_data & ~PAGE_MASK)

extern void set_bh_page(struct buffer_head *bh, struct pfn_info *page, unsigned long offset);

#define atomic_set_buffer_clean(bh) test_and_clear_bit(BH_Dirty, &(bh)->b_state)

static inline void __mark_buffer_clean(struct buffer_head *bh)
{
    panic("__mark_buffer_clean");
}

static inline void mark_buffer_clean(struct buffer_head * bh)
{
        if (atomic_set_buffer_clean(bh))
                __mark_buffer_clean(bh);
}

static inline void buffer_IO_error(struct buffer_head * bh)
{
    mark_buffer_clean(bh);
    /* b_end_io has to clear the BH_Uptodate bitflag in the error case! */
    bh->b_end_io(bh, 0);
}

/**** XXX END OF BUFFER_HEAD STUFF XXXX ****/

#include <xeno/major.h>
#include <xeno/sched.h>
#include <xeno/genhd.h>
#include <xeno/tqueue.h>
#include <xeno/list.h>

struct request_queue;
typedef struct request_queue request_queue_t;
struct elevator_s;
typedef struct elevator_s elevator_t;

/*
 * Ok, this is an expanded form so that we can use the same
 * request for paging requests.
 */
struct request {
	struct list_head queue;
	int elevator_sequence;

	volatile int rq_status;	/* should split this into a few status bits */
#define RQ_INACTIVE		(-1)
#define RQ_ACTIVE		1
#define RQ_SCSI_BUSY		0xffff
#define RQ_SCSI_DONE		0xfffe
#define RQ_SCSI_DISCONNECTING	0xffe0

	kdev_t rq_dev;
	int cmd;		/* READ or WRITE */
	int errors;
	unsigned long start_time;
	unsigned long sector;
	unsigned long nr_sectors;
	unsigned long hard_sector, hard_nr_sectors;
	unsigned int nr_segments;
	unsigned int nr_hw_segments;
	unsigned long current_nr_sectors;
	void * special;
	char * buffer;
	struct completion * waiting;
	struct buffer_head * bh;
	struct buffer_head * bhtail;
	request_queue_t *q;
};

#include <xeno/elevator.h>

typedef int (merge_request_fn) (request_queue_t *q, 
				struct request  *req,
				struct buffer_head *bh,
				int);
typedef int (merge_requests_fn) (request_queue_t *q, 
				 struct request  *req,
				 struct request  *req2,
				 int);
typedef void (request_fn_proc) (request_queue_t *q);
typedef request_queue_t * (queue_proc) (kdev_t dev);
typedef int (make_request_fn) (request_queue_t *q, int rw, struct buffer_head *bh);
typedef void (plug_device_fn) (request_queue_t *q, kdev_t device);
typedef void (unplug_device_fn) (void *q);

/*
 * Default nr free requests per queue, ll_rw_blk will scale it down
 * according to available RAM at init time
 */
#define QUEUE_NR_REQUESTS	8192

struct request_list {
	unsigned int count;
	struct list_head free;
};

struct request_queue
{
	/*
	 * the queue request freelist, one for reads and one for writes
	 */
	struct request_list	rq[2];

	/*
	 * The total number of requests on each queue
	 */
	int nr_requests;

	/*
	 * Batching threshold for sleep/wakeup decisions
	 */
	int batch_requests;

	/*
	 * Together with queue_head for cacheline sharing
	 */
	struct list_head	queue_head;
	elevator_t		elevator;

	request_fn_proc		* request_fn;
	merge_request_fn	* back_merge_fn;
	merge_request_fn	* front_merge_fn;
	merge_requests_fn	* merge_requests_fn;
	make_request_fn		* make_request_fn;
	plug_device_fn		* plug_device_fn;
	/*
	 * The queue owner gets to use this for whatever they like.
	 * ll_rw_blk doesn't touch it.
	 */
	void			* queuedata;

	/*
	 * This is used to remove the plug when tq_disk runs.
	 */
	struct tq_struct	plug_tq;

	/*
	 * Boolean that indicates whether this queue is plugged or not.
	 */
	char			plugged;

	/*
	 * Boolean that indicates whether current_request is active or
	 * not.
	 */
	char			head_active;

	/*
	 * Is meant to protect the queue in the future instead of
	 * io_request_lock
	 */
	spinlock_t		queue_lock;

#if 0
	/*
	 * Tasks wait here for free read and write requests
	 */
	wait_queue_head_t	wait_for_requests[2];
#endif
};

struct blk_dev_struct {
	/*
	 * queue_proc has to be atomic
	 */
	request_queue_t		request_queue;
	queue_proc		*queue;
	void			*data;
};

struct sec_size {
	unsigned block_size;
	unsigned block_size_bits;
};

/*
 * Used to indicate the default queue for drivers that don't bother
 * to implement multiple queues.  We have this access macro here
 * so as to eliminate the need for each and every block device
 * driver to know about the internal structure of blk_dev[].
 */
#define BLK_DEFAULT_QUEUE(_MAJOR)  &blk_dev[_MAJOR].request_queue

extern struct sec_size * blk_sec[MAX_BLKDEV];
extern struct blk_dev_struct blk_dev[MAX_BLKDEV];
extern void grok_partitions(struct gendisk *dev, int drive, unsigned minors, long size);
extern void register_disk(struct gendisk *dev, kdev_t first, unsigned minors, struct block_device_operations *ops, long size);
extern void generic_make_request(int rw, struct buffer_head * bh);
extern inline request_queue_t *blk_get_queue(kdev_t dev);
extern void blkdev_release_request(struct request *);

/*
 * Access functions for manipulating queue properties
 */
extern int blk_grow_request_list(request_queue_t *q, int nr_requests);
extern void blk_init_queue(request_queue_t *, request_fn_proc *);
extern void blk_cleanup_queue(request_queue_t *);
extern void blk_queue_headactive(request_queue_t *, int);
extern void blk_queue_make_request(request_queue_t *, make_request_fn *);
extern void generic_unplug_device(void *);

extern int * blk_size[MAX_BLKDEV];

extern int * blksize_size[MAX_BLKDEV];

extern int * hardsect_size[MAX_BLKDEV];

/*extern int * max_readahead[MAX_BLKDEV];*/

extern int * max_sectors[MAX_BLKDEV];

extern int * max_segments[MAX_BLKDEV];

#define MAX_SEGMENTS 128
#define MAX_SECTORS 255

#define PageAlignSize(size) (((size) + PAGE_SIZE -1) & PAGE_MASK)

#define blkdev_entry_to_request(entry) list_entry((entry), struct request, queue)
#define blkdev_entry_next_request(entry) blkdev_entry_to_request((entry)->next)
#define blkdev_entry_prev_request(entry) blkdev_entry_to_request((entry)->prev)
#define blkdev_next_request(req) blkdev_entry_to_request((req)->queue.next)
#define blkdev_prev_request(req) blkdev_entry_to_request((req)->queue.prev)

extern void drive_stat_acct (kdev_t dev, int rw,
					unsigned long nr_sectors, int new_io);

static inline int get_hardsect_size(kdev_t dev)
{
	int retval = 512;
	int major = MAJOR(dev);

	if (hardsect_size[major]) {
		int minor = MINOR(dev);
		if (hardsect_size[major][minor])
			retval = hardsect_size[major][minor];
	}
	return retval;
}

#define blk_finished_io(nsects)	do { } while (0)
#define blk_started_io(nsects)	do { } while (0)

static inline unsigned int blksize_bits(unsigned int size)
{
	unsigned int bits = 8;
	do {
		bits++;
		size >>= 1;
	} while (size > 256);
	return bits;
}

static inline unsigned int block_size(kdev_t dev)
{
	int retval = BLOCK_SIZE;
	int major = MAJOR(dev);

	if (blksize_size[major]) {
		int minor = MINOR(dev);
		if (blksize_size[major][minor])
			retval = blksize_size[major][minor];
	}
	return retval;
}

#endif
