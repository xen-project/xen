/*
 * Copyright (c) 2007, 2010, XenSource Inc.
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

#define DISK_TYPE_AIO         0
#define DISK_TYPE_SYNC        1
#define DISK_TYPE_VMDK        2
#define DISK_TYPE_VHDSYNC     3
#define DISK_TYPE_VHD         4
#define DISK_TYPE_RAM         5
#define DISK_TYPE_QCOW        6
#define DISK_TYPE_BLOCK_CACHE 7
#define DISK_TYPE_LOG         8
#define DISK_TYPE_REMUS       9
#define DISK_TYPE_VINDEX      10

#define DISK_TYPE_NAME_MAX    32

typedef struct disk_info {
	const char     *name; /* driver name, e.g. 'aio' */
	char           *desc;  /* e.g. "raw image" */
	unsigned int    flags; 
} disk_info_t;

extern const disk_info_t     *tapdisk_disk_types[];
extern const struct tap_disk *tapdisk_disk_drivers[];

/* one single controller for all instances of disk type */
#define DISK_TYPE_SINGLE_CONTROLLER (1<<0)

int tapdisk_disktype_find(const char *name);
int tapdisk_disktype_parse_params(const char *params, const char **_path);
int tapdisk_parse_disk_type(const char *, const char **, int *);

#endif
