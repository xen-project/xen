/* blktaplib.h
 *
 * Blktap library userspace code.
 *
 * (c) 2005 Andrew Warfield and Julian Chesterfield
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

#ifndef __BLKTAPLIB_H__
#define __BLKTAPLIB_H__

#include <xenctrl.h>
#include <sys/param.h>
#include <sys/user.h>
#include <xen/xen.h>
#include <xen/io/blkif.h>
#include <xen/io/ring.h>
#include <xenstore.h>
#include <sys/types.h>
#include <unistd.h>

#define BLK_RING_SIZE __CONST_RING_SIZE(blkif, XC_PAGE_SIZE)

/* size of the extra VMA area to map in attached pages. */
#define BLKTAP_VMA_PAGES BLK_RING_SIZE

/* blktap IOCTLs: These must correspond with the blktap driver ioctls*/
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2
#define BLKTAP_IOCTL_SETMODE         3
#define BLKTAP_IOCTL_SENDPID	     4
#define BLKTAP_IOCTL_NEWINTF	     5
#define BLKTAP_IOCTL_MINOR	     6
#define BLKTAP_IOCTL_MAJOR	     7
#define BLKTAP_QUERY_ALLOC_REQS      8
#define BLKTAP_IOCTL_FREEINTF	     9
#define BLKTAP_IOCTL_NEWINTF_EXT     50
#define BLKTAP_IOCTL_PRINT_IDXS      100   

/* blktap switching modes: (Set with BLKTAP_IOCTL_SETMODE)             */
#define BLKTAP_MODE_PASSTHROUGH      0x00000000  /* default            */
#define BLKTAP_MODE_INTERCEPT_FE     0x00000001
#define BLKTAP_MODE_INTERCEPT_BE     0x00000002

#define BLKTAP_MODE_INTERPOSE \
           (BLKTAP_MODE_INTERCEPT_FE | BLKTAP_MODE_INTERCEPT_BE)

static inline int BLKTAP_MODE_VALID(unsigned long arg)
{
	return (
		( arg == BLKTAP_MODE_PASSTHROUGH  ) ||
		( arg == BLKTAP_MODE_INTERCEPT_FE ) ||
		( arg == BLKTAP_MODE_INTERPOSE    ) );
}

#define MAX_REQUESTS            BLK_RING_SIZE

#define BLKTAP_IOCTL_KICK 1
#define MAX_PENDING_REQS	BLK_RING_SIZE
#define BLKTAP_DEV_DIR   "/dev/xen"
#define BLKTAP_DEV_NAME  "blktap"
#define BLKTAP_DEV_MINOR 0
#define BLKTAP_CTRL_DIR   "/var/run/tap"

extern int blktap_major;

#define BLKTAP_RING_PAGES       1 /* Front */
#define BLKTAP_MMAP_REGION_SIZE (BLKTAP_RING_PAGES + MMAP_PAGES)

struct blkif;

typedef struct {
	blkif_request_t  req;
	struct blkif    *blkif;
	int              submitting;
	int              secs_pending;
        int16_t          status;
} pending_req_t;

struct blkif_ops {
	unsigned long long (*get_size)(struct blkif *blkif);
	unsigned long (*get_secsize)(struct blkif *blkif);
	unsigned int (*get_info)(struct blkif *blkif);
};

typedef struct blkif {
	domid_t domid;
	long int handle;
	
	long int pdev;
	long int readonly;
	
	enum { DISCONNECTED, DISCONNECTING, CONNECTED } state;
	
	struct blkif_ops *ops;
	struct blkif *hash_next;
	
	void *prv;  /* device-specific data */
	void *info; /*Image parameter passing */
	pending_req_t pending_list[MAX_REQUESTS];
	int devnum;
	int fds[2];
	int be_id;
	int major;
	int minor;
	pid_t tappid;
	int drivertype;
	uint16_t cookie;
} blkif_t;

typedef struct blkif_info {
	char *params;
} blkif_info_t;

void register_new_devmap_hook(int (*fn)(blkif_t *blkif));
void register_new_unmap_hook(int (*fn)(blkif_t *blkif));
void register_new_blkif_hook(int (*fn)(blkif_t *blkif));
blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle);
blkif_t *alloc_blkif(domid_t domid);
int blkif_init(blkif_t *blkif, long int handle, long int pdev, 
               long int readonly);
void free_blkif(blkif_t *blkif);
void __init_blkif(void);

typedef struct busy_state {
	int seg_idx;
	blkif_request_t *req;
} busy_state_t;

typedef struct tapdev_info {
	int fd;
	char *mem;
	blkif_sring_t *sring;
	blkif_back_ring_t  fe_ring;
	unsigned long vstart;
	blkif_t *blkif;
	busy_state_t busy;
} tapdev_info_t;

typedef struct domid_translate {
	unsigned short domid;
	unsigned short busid;
} domid_translate_t ;

typedef struct domid_translate_ext {
	unsigned short domid;
	uint32_t busid;
} domid_translate_ext_t ;

typedef struct image {
	unsigned long long size;
	unsigned long secsize;
	unsigned int info;
} image_t;

/* 16-byte message header, immediately followed by message payload. */
typedef struct msg_hdr {
	uint16_t   type;
	uint16_t   len;
	uint16_t   drivertype;
	uint16_t   cookie;
	uint8_t    readonly;
	uint8_t    pad[7];
} msg_hdr_t;

typedef struct msg_newdev {
	uint8_t     devnum;
	uint16_t    domid;
} msg_newdev_t;

typedef struct msg_pid {
	pid_t     pid;
} msg_pid_t;

#define READ 0
#define WRITE 1

/*Control Messages between manager and tapdev*/
#define CTLMSG_PARAMS      1
#define CTLMSG_IMG         2
#define CTLMSG_IMG_FAIL    3
#define CTLMSG_NEWDEV      4
#define CTLMSG_NEWDEV_RSP  5
#define CTLMSG_NEWDEV_FAIL 6
#define CTLMSG_CLOSE       7
#define CTLMSG_CLOSE_RSP   8
#define CTLMSG_PID         9
#define CTLMSG_PID_RSP     10

/* disk driver types */
#define MAX_DISK_TYPES     20

#define DISK_TYPE_AIO      0
#define DISK_TYPE_SYNC     1
#define DISK_TYPE_VMDK     2
#define DISK_TYPE_RAM      3
#define DISK_TYPE_QCOW     4
#define DISK_TYPE_QCOW2    5

/* xenstore/xenbus: */
#define DOMNAME "Domain-0"
int setup_probe_watch(struct xs_handle *h);


/* Abitrary values, must match the underlying driver... */
#define MAX_TAP_DEV 100

/* Accessing attached data page mappings */
#define MMAP_PAGES                                              \
    (MAX_PENDING_REQS * BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define MMAP_VADDR(_vstart,_req,_seg)                                   \
    ((_vstart) +                                              \
     ((_req) * BLKIF_MAX_SEGMENTS_PER_REQUEST * getpagesize()) +    \
     ((_seg) * getpagesize()))


#endif /* __BLKTAPLIB_H__ */
