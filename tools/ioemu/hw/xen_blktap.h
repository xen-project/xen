/* xen_blktap.h
 *
 * Generic disk interface for blktap-based image adapters.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 */

#ifndef XEN_BLKTAP_H_ 
#define XEN_BLKTAP_H_

#include <stdint.h>
#include <syslog.h>
#include <stdio.h>

#include "block_int.h"

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

struct disk_id {
	char *name;
	int drivertype;
};

/* This structure represents the state of an active virtual disk.           */
struct td_state {
	BlockDriverState* bs;
	td_flag_t flags;
	void *blkif;
	void *image;
	void *ring_info;
	void *fd_entry;
	uint64_t sector_size;
	uint64_t size;
	unsigned int       info;
};

typedef struct fd_list_entry {
	int cookie;
	int  tap_fd;
	struct td_state *s;
	struct fd_list_entry **pprev, *next;
} fd_list_entry_t;

#endif /*XEN_BLKTAP_H_*/
