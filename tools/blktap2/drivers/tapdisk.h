/*
 * Copyright (c) 2007, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * tracking.  Disks should transform these requests as necessary and return
 * the resulting iocbs to tapdisk using td_prep_[read,write]() and 
 * td_queue_tiocb().
 *
 * NOTE: tapdisk uses the number of sectors submitted per request as a 
 * ref count.  Plugins must use the callback function to communicate the
 * completion -- or error -- of every sector submitted to them.
 *
 * td_get_parent_id returns:
 *     0 if parent id successfully retrieved
 *     TD_NO_PARENT if no parent exists
 *     -errno on error
 */

#ifndef _TAPDISK_H_
#define _TAPDISK_H_

#include <time.h>
#include <stdint.h>

#include "list.h"
#include "blktaplib.h"
#include "tapdisk-log.h"
#include "tapdisk-utils.h"

#ifdef MEMSHR
#include "memshr.h"
#endif

#define DPRINTF(_f, _a...)           syslog(LOG_INFO, _f, ##_a)
#define EPRINTF(_f, _a...)           syslog(LOG_ERR, "tap-err:%s: " _f, __func__, ##_a)
#define PERROR(_f, _a...)            EPRINTF(_f ": %s", ##_a, strerror(errno))

#define MAX_SEGMENTS_PER_REQ         11
#define SECTOR_SHIFT                 9
#define DEFAULT_SECTOR_SIZE          512

#define TAPDISK_DATA_REQUESTS       (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)

//#define BLK_NOT_ALLOCATED            (-99)
#define TD_NO_PARENT                 1

#define MAX_RAMDISK_SIZE             1024000 /*500MB disk limit*/

#define TD_OP_READ                   0
#define TD_OP_WRITE                  1

#define TD_OPEN_QUIET                0x00001
#define TD_OPEN_QUERY                0x00002
#define TD_OPEN_RDONLY               0x00004
#define TD_OPEN_STRICT               0x00008
#define TD_OPEN_SHAREABLE            0x00010
#define TD_OPEN_ADD_CACHE            0x00020
#define TD_OPEN_VHD_INDEX            0x00040
#define TD_OPEN_LOG_DIRTY            0x00080

#define TD_CREATE_SPARSE             0x00001
#define TD_CREATE_MULTITYPE          0x00002

#define td_flag_set(word, flag)      ((word) |= (flag))
#define td_flag_clear(word, flag)    ((word) &= ~(flag))
#define td_flag_test(word, flag)     ((word) & (flag))

typedef uint16_t                     td_uuid_t;
typedef uint32_t                     td_flag_t;
typedef uint64_t                     td_sector_t;
typedef struct td_disk_id            td_disk_id_t;
typedef struct td_disk_info          td_disk_info_t;
typedef struct td_request            td_request_t;
typedef struct td_driver_handle      td_driver_t;
typedef struct td_image_handle       td_image_t;

struct td_disk_id {
	char                        *name;
	int                          drivertype;
};

struct td_disk_info {
	td_sector_t                  size;
        uint64_t                     sector_size;
	uint32_t                     info;
};

struct td_request {
	int                          op;
	char                        *buf;
	td_sector_t                  sec;
	int                          secs;

	uint8_t                      blocked; /* blocked on a dependency */

	td_image_t                  *image;

	void * /*td_callback_t*/     cb;
	void                        *cb_data;

	uint64_t                     id;
	int                          sidx;
	void                        *private;
    
#ifdef MEMSHR
	share_tuple_t                memshr_hnd;
#endif
};

/* 
 * Prototype of the callback to activate as requests complete.
 */
typedef void (*td_callback_t)(td_request_t, int);

/* 
 * Structure describing the interface to a virtual disk implementation.
 * See note at the top of this file describing this interface.
 */
struct tap_disk {
	const char                  *disk_type;
	td_flag_t                    flags;
	int                          private_data_size;
	int (*td_open)               (td_driver_t *, const char *, td_flag_t);
	int (*td_close)              (td_driver_t *);
	int (*td_get_parent_id)      (td_driver_t *, td_disk_id_t *);
	int (*td_validate_parent)    (td_driver_t *, td_driver_t *, td_flag_t);
	void (*td_queue_read)        (td_driver_t *, td_request_t);
	void (*td_queue_write)       (td_driver_t *, td_request_t);
	void (*td_debug)             (td_driver_t *);
};

#endif
