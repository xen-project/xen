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
 */

#ifndef __DISKTYPES_H__
#define __DISKTYPES_H__

typedef struct disk_info {
       int  idnum;
       char name[50];       /* e.g. "RAMDISK" */
       char handle[10];     /* xend handle, e.g. 'ram' */
       int  single_handler; /* is there a single controller for all */
                            /* instances of disk type? */
#ifdef TAPDISK
       struct tap_disk *drv;
#endif
} disk_info_t;

extern struct tap_disk tapdisk_aio;
/* extern struct tap_disk tapdisk_sync;    */
/* extern struct tap_disk tapdisk_vmdk;    */
/* extern struct tap_disk tapdisk_vhdsync; */
extern struct tap_disk tapdisk_vhd;
extern struct tap_disk tapdisk_ram;
 extern struct tap_disk tapdisk_qcow; 
extern struct tap_disk tapdisk_block_cache;
extern struct tap_disk tapdisk_log;
extern struct tap_disk tapdisk_remus;

#define MAX_DISK_TYPES        20

#define DISK_TYPE_AIO         0
#define DISK_TYPE_SYNC        1
#define DISK_TYPE_VMDK        2
#define DISK_TYPE_VHDSYNC     3
#define DISK_TYPE_VHD         4
#define DISK_TYPE_RAM         5
#define DISK_TYPE_QCOW        6
#define DISK_TYPE_BLOCK_CACHE 7
#define DISK_TYPE_LOG         9
#define DISK_TYPE_REMUS       10

/*Define Individual Disk Parameters here */
static disk_info_t null_disk = {
       -1,
       "null disk",
       "null",
       0,
#ifdef TAPDISK
       0,
#endif
};

static disk_info_t aio_disk = {
       DISK_TYPE_AIO,
       "raw image (aio)",
       "aio",
       0,
#ifdef TAPDISK
       &tapdisk_aio,
#endif
};
/*
static disk_info_t sync_disk = {
       DISK_TYPE_SYNC,
       "raw image (sync)",
       "sync",
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
#ifdef TAPDISK
       &tapdisk_vmdk,
#endif
};

static disk_info_t vhdsync_disk = {
       DISK_TYPE_VHDSYNC,
       "virtual server image (vhd) - synchronous",
       "vhdsync",
       1,
#ifdef TAPDISK
       &tapdisk_vhdsync,
#endif
};
*/

static disk_info_t vhd_disk = {
       DISK_TYPE_VHD,
       "virtual server image (vhd)",
       "vhd",
       0,
#ifdef TAPDISK
       &tapdisk_vhd,
#endif
};


static disk_info_t ram_disk = {
       DISK_TYPE_RAM,
       "ramdisk image (ram)",
       "ram",
       1,
#ifdef TAPDISK
       &tapdisk_ram,
#endif
};


static disk_info_t qcow_disk = {
       DISK_TYPE_QCOW,
       "qcow disk (qcow)",
       "qcow",
       0,
#ifdef TAPDISK
       &tapdisk_qcow,
#endif
};


static disk_info_t block_cache_disk = {
       DISK_TYPE_BLOCK_CACHE,
       "block cache image (bc)",
       "bc",
       1,
#ifdef TAPDISK
       &tapdisk_block_cache,
#endif
};

static disk_info_t log_disk = {
	DISK_TYPE_LOG,
	"write logger (log)",
	"log",
	0,
#ifdef TAPDISK
	&tapdisk_log,
#endif
};

static disk_info_t remus_disk = {
       DISK_TYPE_REMUS,
       "remus disk replicator (remus)",
       "remus",
       0,
#ifdef TAPDISK
       &tapdisk_remus,
#endif
};

/*Main disk info array */
static disk_info_t *dtypes[] = {
       &aio_disk,
       &null_disk, /* &sync_disk, */
       &null_disk, /* &vmdk_disk, */
        &null_disk, /* &vhdsync_disk, */
       &vhd_disk,
       &ram_disk,
       &qcow_disk,
       &block_cache_disk,
       &null_disk,
       &log_disk,
       &remus_disk,
};

#endif
