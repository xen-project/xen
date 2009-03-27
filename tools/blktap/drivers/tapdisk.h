/* tapdisk.h
 *
 * Generic disk interface for blktap-based image adapters.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 * 
 * Some notes on the tap_disk interface:
 * 
 * tap_disk aims to provide a generic interface to easily implement new 
 * types of image accessors.  The structure-of-function-calls is similar
 * to disk interfaces used in qemu/denali/etc, with the significant 
 * difference being the expectation of asynchronous rather than synchronous 
 * I/O.  The asynchronous interface is intended to allow lots of requests to
 * be pipelined through a disk, without the disk requiring any of its own
 * threads of control.  As such, a batch of requests is delivered to the disk
 * using:
 * 
 *    td_queue_[read,write]()
 * 
 * and passing in a completion callback, which the disk is responsible for 
 * tracking.  The end of a back is marked with a call to:
 * 
 *    td_submit()
 * 
 * The disk implementation must provide a file handle, which is used to 
 * indicate that it needs to do work.  tapdisk will add this file handle 
 * (returned from td_get_fd()) to it's poll set, and will call into the disk
 * using td_do_callbacks() whenever there is data pending.
 * 
 * Two disk implementations demonstrate how this interface may be used to 
 * implement disks with both asynchronous and synchronous calls.  block-aio.c
 * maps this interface down onto the linux libaio calls, while block-sync uses 
 * normal posix read/write.
 * 
 * A few things to realize about the sync case, which doesn't need to defer 
 * io completions:
 * 
 *   - td_queue_[read,write]() call read/write directly, and then call the 
 *     callback immediately.  The MUST then return a value greater than 0
 *     in order to tell tapdisk that requests have finished early, and to 
 *     force responses to be kicked to the clents.
 * 
 *   - The fd used for poll is an otherwise unused pipe, which allows poll to 
 *     be safely called without ever returning anything.
 *
 * NOTE: tapdisk uses the number of sectors submitted per request as a 
 * ref count.  Plugins must use the callback function to communicate the
 * completion--or error--of every sector submitted to them.
 *
 * td_get_parent_id returns:
 *     0 if parent id successfully retrieved
 *     TD_NO_PARENT if no parent exists
 *     -errno on error
 */

#ifndef TAPDISK_H_
#define TAPDISK_H_

#include <stdint.h>
#include <syslog.h>
#include <stdio.h>
#include "blktaplib.h"

/*If enabled, log all debug messages to syslog*/
#if 1
#define DPRINTF(_f, _a...) syslog( LOG_DEBUG, __FILE__ ":%d: " _f , __LINE__, ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* Things disks need to know about, these should probably be in a higher-level
 * header. */
#define MAX_SEGMENTS_PER_REQ    11
#define SECTOR_SHIFT             9
#define DEFAULT_SECTOR_SIZE    512

#define MAX_IOFD                 2

#define BLK_NOT_ALLOCATED       99
#define TD_NO_PARENT             1

typedef uint32_t td_flag_t;

#define TD_RDONLY                1

struct td_state;
struct tap_disk;

struct disk_id {
	char *name;
	int drivertype;
};

struct disk_driver {
	int early;
	char *name;
	void *private;
	td_flag_t flags;
	int io_fd[MAX_IOFD];
	struct tap_disk *drv;
	struct td_state *td_state;
	struct disk_driver *next;
};

/* This structure represents the state of an active virtual disk.           */
struct td_state {
	struct disk_driver *disks;
	void *blkif;
	void *image;
	void *ring_info;
	void *fd_entry;
	uint64_t sector_size;
	uint64_t size;
	unsigned int       info;
};

/* Prototype of the callback to activate as requests complete.              */
typedef int (*td_callback_t)(struct disk_driver *dd, int res, uint64_t sector,
			     int nb_sectors, int id, void *private);

/* Structure describing the interface to a virtual disk implementation.     */
/* See note at the top of this file describing this interface.              */
struct tap_disk {
	const char *disk_type;
	int private_data_size;
	int (*td_open)           (struct disk_driver *dd, 
				  const char *name, td_flag_t flags);
	int (*td_queue_read)     (struct disk_driver *dd, uint64_t sector,
				  int nb_sectors, char *buf, td_callback_t cb,
				  int id, void *prv);
	int (*td_queue_write)    (struct disk_driver *dd, uint64_t sector,
				  int nb_sectors, char *buf, td_callback_t cb, 
				  int id, void *prv);
	int (*td_submit)         (struct disk_driver *dd);
	int (*td_close)          (struct disk_driver *dd);
	int (*td_do_callbacks)   (struct disk_driver *dd, int sid);
	int (*td_get_parent_id)  (struct disk_driver *dd, struct disk_id *id);
	int (*td_validate_parent)(struct disk_driver *dd, 
				  struct disk_driver *p, td_flag_t flags);
};

typedef struct disk_info {
	int  idnum;
	char name[50];       /* e.g. "RAMDISK" */
	char handle[10];     /* xend handle, e.g. 'ram' */
	int  single_handler; /* is there a single controller for all */
	                     /* instances of disk type? */
	int  use_ioemu;      /* backend provider: 0 = tapdisk; 1 = ioemu */

#ifdef TAPDISK
	struct tap_disk *drv;	
#endif
} disk_info_t;

void debug_fe_ring(struct td_state *s);

extern struct tap_disk tapdisk_aio;
extern struct tap_disk tapdisk_sync;
extern struct tap_disk tapdisk_vmdk;
extern struct tap_disk tapdisk_ram;
extern struct tap_disk tapdisk_qcow;
extern struct tap_disk tapdisk_qcow2;


/*Define Individual Disk Parameters here */
static disk_info_t aio_disk = {
	DISK_TYPE_AIO,
	"raw image (aio)",
	"aio",
	0,
	0,
#ifdef TAPDISK
	&tapdisk_aio,
#endif
};

static disk_info_t sync_disk = {
	DISK_TYPE_SYNC,
	"raw image (sync)",
	"sync",
	0,
	0,
#ifdef TAPDISK
	&tapdisk_sync,
#endif
};

static disk_info_t vmdk_disk = {
	DISK_TYPE_VMDK,
	"vmware image (vmdk)",
	"vmdk",
	1,
	0,
#ifdef TAPDISK
	&tapdisk_vmdk,
#endif
};

static disk_info_t ram_disk = {
	DISK_TYPE_RAM,
	"ramdisk image (ram)",
	"ram",
	1,
	0,
#ifdef TAPDISK
	&tapdisk_ram,
#endif
};

static disk_info_t qcow_disk = {
	DISK_TYPE_QCOW,
	"qcow disk (qcow)",
	"qcow",
	0,
	0,
#ifdef TAPDISK
	&tapdisk_qcow,
#endif
};

static disk_info_t qcow2_disk = {
	DISK_TYPE_QCOW2,
	"qcow2 disk (qcow2)",
	"qcow2",
	0,
	0,
#ifdef TAPDISK
	&tapdisk_qcow2,
#endif
};

/*Main disk info array */
static disk_info_t *dtypes[] = {
	&aio_disk,
	&sync_disk,
	&vmdk_disk,
	&ram_disk,
	&qcow_disk,
	&qcow2_disk,
};

typedef struct driver_list_entry {
	struct blkif *blkif;
	struct driver_list_entry **pprev, *next;
} driver_list_entry_t;

typedef struct fd_list_entry {
	int cookie;
	int  tap_fd;
	struct td_state *s;
	struct fd_list_entry **pprev, *next;
} fd_list_entry_t;

int qcow_create(const char *filename, uint64_t total_size,
		const char *backing_file, int flags);

int qcow2_create(const char *filename, uint64_t total_size,
		const char *backing_file, int flags);
#endif /*TAPDISK_H_*/
