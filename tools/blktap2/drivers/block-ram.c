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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>

#include "blk.h"
#include "tapdisk.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"

char *img;
long int   disksector_size;
long int   disksize;
long int   diskinfo;
static int connections = 0;

struct tdram_state {
        int fd;
};

/*Get Image size, secsize*/
static int get_image_info(int fd, td_disk_info_t *info)
{
	int ret;
	long size;
	unsigned long total_size;
	struct statvfs statBuf;
	struct stat stat;

	ret = fstat(fd, &stat);
	if (ret != 0) {
		DPRINTF("ERROR: fstat failed, Couldn't stat image");
		return -EINVAL;
	}

	if (S_ISBLK(stat.st_mode)) {
		/*Accessing block device directly*/
		info->size = 0;
		if (blk_getimagesize(fd, &info->size) != 0)
			return -EINVAL;

		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(info->size << SECTOR_SHIFT),
			(long long unsigned)info->size);

		/*Get the sector size*/
		if (blk_getsectorsize(fd, &info->sector_size) != 0)
			info->sector_size = DEFAULT_SECTOR_SIZE;

	} else {
		/*Local file? try fstat instead*/
		info->size = (stat.st_size >> SECTOR_SHIFT);
		info->sector_size = DEFAULT_SECTOR_SIZE;
		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(info->size << SECTOR_SHIFT),
			(long long unsigned)info->size);
	}

	if (info->size == 0) {		
		info->size =((uint64_t) MAX_RAMDISK_SIZE);
		info->sector_size = DEFAULT_SECTOR_SIZE;
	}
	info->info = 0;

        /*Store variables locally*/
	disksector_size = info->sector_size;
	disksize        = info->size;
	diskinfo        = info->info;
	DPRINTF("Image sector_size: \n\t[%"PRIu64"]\n",
		info->sector_size);

	return 0;
}

/* Open the disk file and initialize ram state. */
int tdram_open (td_driver_t *driver, const char *name, td_flag_t flags)
{
	char *p;
	uint64_t size;
	int i, fd, ret = 0, count = 0, o_flags;
	struct tdram_state *prv = (struct tdram_state *)driver->data;

	connections++;

	if (connections > 1) {
		driver->info.sector_size = disksector_size;
		driver->info.size        = disksize;
		driver->info.info        = diskinfo; 
		DPRINTF("Image already open, returning parameters:\n");
		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(driver->info.size << SECTOR_SHIFT),
			(long long unsigned)driver->info.size);
		DPRINTF("Image sector_size: \n\t[%"PRIu64"]\n",
			driver->info.sector_size);

		prv->fd = -1;
		goto done;
	}

	/* Open the file */
	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags == TD_OPEN_RDONLY) ? O_RDONLY : O_RDWR);
        fd = open(name, o_flags);

        if ((fd == -1) && (errno == EINVAL)) {

                /* Maybe O_DIRECT isn't supported. */
		o_flags &= ~O_DIRECT;
                fd = open(name, o_flags);
                if (fd != -1) DPRINTF("WARNING: Accessing image without"
                                     "O_DIRECT! (%s)\n", name);

        } else if (fd != -1) DPRINTF("open(%s) with O_DIRECT\n", name);
	
        if (fd == -1) {
		DPRINTF("Unable to open [%s]!\n",name);
        	ret = 0 - errno;
        	goto done;
        }

        prv->fd = fd;

	ret = get_image_info(fd, &driver->info);
	size = MAX_RAMDISK_SIZE;

	if (driver->info.size > size) {
		DPRINTF("Disk exceeds limit, must be less than [%d]MB",
			(MAX_RAMDISK_SIZE<<SECTOR_SHIFT)>>20);
		return -ENOMEM;
	}

	/*Read the image into memory*/
	if (posix_memalign((void **)&img, 
			   DEFAULT_SECTOR_SIZE,
			   driver->info.size << SECTOR_SHIFT)) {
		DPRINTF("Mem malloc failed\n");
		return -errno;
	}
	p = img;
	DPRINTF("Reading %llu bytes.......",
		(long long unsigned)driver->info.size << SECTOR_SHIFT);

	for (i = 0; i < driver->info.size; i++) {
		ret = read(prv->fd, p, driver->info.sector_size);
		if (ret != driver->info.sector_size) {
			DPRINTF("ret = %d, errno = %d\n", ret, errno);
			ret = 0 - errno;
			break;
		} else {
			count += ret;
			p = img + count;
		}
	}
	DPRINTF("[%d]\n",count);
	if (count != driver->info.size << SECTOR_SHIFT) {
		ret = -1;
	} else {
		ret = 0;
	}

done:
	return ret;
}

void tdram_queue_read(td_driver_t *driver, td_request_t treq)
{
	struct tdram_state *prv = (struct tdram_state *)driver->data;
	int      size    = treq.secs * driver->info.sector_size;
	uint64_t offset  = treq.sec * (uint64_t)driver->info.sector_size;

	memcpy(treq.buf, img + offset, size);

	td_complete_request(treq, 0);
}

void tdram_queue_write(td_driver_t *driver, td_request_t treq)
{
	struct tdram_state *prv = (struct tdram_state *)driver->data;
	int      size    = treq.secs * driver->info.sector_size;
	uint64_t offset  = treq.sec * (uint64_t)driver->info.sector_size;
	
	/* We assume that write access is controlled
	 * at a higher level for multiple disks */
	memcpy(img + offset, treq.buf, size);

	td_complete_request(treq, 0);
}

int tdram_close(td_driver_t *driver)
{
	struct tdram_state *prv = (struct tdram_state *)driver->data;
	
	connections--;
	
	return 0;
}

int tdram_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	return TD_NO_PARENT;
}

int tdram_validate_parent(td_driver_t *driver,
			  td_driver_t *pdriver, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_ram = {
	.disk_type          = "tapdisk_ram",
	.flags              = 0,
	.private_data_size  = sizeof(struct tdram_state),
	.td_open            = tdram_open,
	.td_close           = tdram_close,
	.td_queue_read      = tdram_queue_read,
	.td_queue_write     = tdram_queue_write,
	.td_get_parent_id   = tdram_get_parent_id,
	.td_validate_parent = tdram_validate_parent,
	.td_debug           = NULL,
};
