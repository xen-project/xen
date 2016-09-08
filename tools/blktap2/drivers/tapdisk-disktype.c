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

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "tapdisk-disktype.h"
#include "tapdisk-message.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof *(a))

static const disk_info_t aio_disk = {
       "aio",
       "raw image (aio)",
       0,
};

static const disk_info_t sync_disk = {
       "sync",
       "raw image (sync)",
       0,
};

static const disk_info_t vmdk_disk = {
       "vmdk",
       "vmware image (vmdk)",
       1,
};

static const disk_info_t vhdsync_disk = {
       "vhdsync",
       "virtual server image (vhd) - synchronous",
       1,
};

static const disk_info_t vhd_disk = {
       "vhd",
       "virtual server image (vhd)",
       0,
};


static const disk_info_t ram_disk = {
       "ram",
       "ramdisk image (ram)",
       1,
};

static const disk_info_t qcow_disk = {
       "qcow",
       "qcow disk (qcow)",
       0,
};

static const disk_info_t block_cache_disk = {
       "bc",
       "block cache image (bc)",
       1,
};

static const disk_info_t vhd_index_disk = {
       "vhdi",
       "vhd index image (vhdi)",
       1,
};

static const disk_info_t log_disk = {
	"log",
	"write logger (log)",
	0,
};

static const disk_info_t remus_disk = {
       "remus",
       "remus disk replicator (remus)",
       0,
};

const disk_info_t *tapdisk_disk_types[] = {
	[DISK_TYPE_AIO]	= &aio_disk,
	[DISK_TYPE_SYNC]	= &sync_disk,
	[DISK_TYPE_VMDK]	= &vmdk_disk,
	[DISK_TYPE_VHDSYNC]	= &vhdsync_disk,
	[DISK_TYPE_VHD]	= &vhd_disk,
	[DISK_TYPE_RAM]	= &ram_disk,
	[DISK_TYPE_QCOW]	= &qcow_disk,
	[DISK_TYPE_BLOCK_CACHE] = &block_cache_disk,
	[DISK_TYPE_LOG]	= &log_disk,
	[DISK_TYPE_VINDEX]	= &vhd_index_disk,
	[DISK_TYPE_REMUS]	= &remus_disk,
};

extern struct tap_disk tapdisk_aio;
extern struct tap_disk tapdisk_vhdsync;
extern struct tap_disk tapdisk_vhd;
extern struct tap_disk tapdisk_ram;
extern struct tap_disk tapdisk_qcow;
extern struct tap_disk tapdisk_block_cache;
extern struct tap_disk tapdisk_log;
extern struct tap_disk tapdisk_remus;

const struct tap_disk *tapdisk_disk_drivers[ARRAY_SIZE(tapdisk_disk_types)] = {
	[DISK_TYPE_AIO]         = &tapdisk_aio,
	[DISK_TYPE_VHD]         = &tapdisk_vhd,
	[DISK_TYPE_RAM]         = &tapdisk_ram,
	[DISK_TYPE_QCOW]        = &tapdisk_qcow,
	[DISK_TYPE_BLOCK_CACHE] = &tapdisk_block_cache,
	[DISK_TYPE_LOG]         = &tapdisk_log,
	[DISK_TYPE_REMUS]       = &tapdisk_remus,
};

int
tapdisk_disktype_find(const char *name)
{
	const disk_info_t *info;
	int i;

	for (i = 0; i < ARRAY_SIZE(tapdisk_disk_types); ++i) {
		info = tapdisk_disk_types[i];
		if (!info)
			continue;

		if (strcmp(name, info->name))
			continue;

		if (!tapdisk_disk_drivers[i])
			return -ENOSYS;

		return i;
	}

	return -ENOENT;
}

int
tapdisk_disktype_parse_params(const char *params, const char **_path)
{
	char name[DISK_TYPE_NAME_MAX], *ptr;
	size_t len;
	int type;

	ptr = strchr(params, ':');
	if (!ptr)
		return -EINVAL;

	len = ptr - params;

	if (len > sizeof(name) - 1)
		return -ENAMETOOLONG;

	memset(name, 0, sizeof(name));
	strncpy(name, params, len);

	type = tapdisk_disktype_find(name);

	if (type >= 0)
		*_path = params + len + 1;

	return type;
}

int
tapdisk_parse_disk_type(const char *params, const char **_path, int *_type)
{
	int type;

	type = tapdisk_disktype_parse_params(params, _path);
	if (type < 0)
		return type;

	*_type = type;

	return 0;
}
