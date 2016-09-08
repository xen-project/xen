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

#include "blk.h"
#include "tapdisk.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"

#define MAX_AIO_REQS         TAPDISK_DATA_REQUESTS

struct tdaio_state;

struct aio_request {
	td_request_t         treq;
	struct tiocb         tiocb;
	struct tdaio_state  *state;
};

struct tdaio_state {
	int                  fd;
	td_driver_t         *driver;

	int                  aio_free_count;	
	struct aio_request   aio_requests[MAX_AIO_REQS];
	struct aio_request  *aio_free_list[MAX_AIO_REQS];
};

/*Get Image size, secsize*/
static int tdaio_get_image_info(int fd, td_disk_info_t *info)
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
		info->size =((uint64_t) 16836057);
		info->sector_size = DEFAULT_SECTOR_SIZE;
	}
	info->info = 0;

	return 0;
}

/* Open the disk file and initialize aio state. */
int tdaio_open(td_driver_t *driver, const char *name, td_flag_t flags)
{
	int i, fd, ret, o_flags;
	struct tdaio_state *prv;

	ret = 0;
	prv = (struct tdaio_state *)driver->data;

	DPRINTF("block-aio open('%s')", name);

	memset(prv, 0, sizeof(struct tdaio_state));

	prv->aio_free_count = MAX_AIO_REQS;
	for (i = 0; i < MAX_AIO_REQS; i++)
		prv->aio_free_list[i] = &prv->aio_requests[i];

	/* Open the file */
	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags & TD_OPEN_RDONLY) ? O_RDONLY : O_RDWR);
        fd = open(name, o_flags);

        if ( (fd == -1) && (errno == EINVAL) ) {

                /* Maybe O_DIRECT isn't supported. */
		o_flags &= ~O_DIRECT;
                fd = open(name, o_flags);
                if (fd != -1) DPRINTF("WARNING: Accessing image without"
                                     "O_DIRECT! (%s)\n", name);

        } else if (fd != -1) DPRINTF("open(%s) with O_DIRECT\n", name);
	
        if (fd == -1) {
		DPRINTF("Unable to open [%s] (%d)!\n", name, 0 - errno);
        	ret = 0 - errno;
        	goto done;
        }

	ret = tdaio_get_image_info(fd, &driver->info);
	if (ret) {
		close(fd);
		goto done;
	}

        prv->fd = fd;

done:
	return ret;	
}

void tdaio_complete(void *arg, struct tiocb *tiocb, int err)
{
	struct aio_request *aio = (struct aio_request *)arg;
	struct tdaio_state *prv = aio->state;

	td_complete_request(aio->treq, err);
	prv->aio_free_list[prv->aio_free_count++] = aio;
}

void tdaio_queue_read(td_driver_t *driver, td_request_t treq)
{
	int size;
	uint64_t offset;
	struct aio_request *aio;
	struct tdaio_state *prv;

	prv    = (struct tdaio_state *)driver->data;
	size   = treq.secs * driver->info.sector_size;
	offset = treq.sec  * (uint64_t)driver->info.sector_size;

	if (prv->aio_free_count == 0)
		goto fail;

	aio        = prv->aio_free_list[--prv->aio_free_count];
	aio->treq  = treq;
	aio->state = prv;

	td_prep_read(&aio->tiocb, prv->fd, treq.buf,
		     size, offset, tdaio_complete, aio);
	td_queue_tiocb(driver, &aio->tiocb);

	return;

fail:
	td_complete_request(treq, -EBUSY);
}

void tdaio_queue_write(td_driver_t *driver, td_request_t treq)
{
	int size;
	uint64_t offset;
	struct aio_request *aio;
	struct tdaio_state *prv;

	prv     = (struct tdaio_state *)driver->data;
	size    = treq.secs * driver->info.sector_size;
	offset  = treq.sec  * (uint64_t)driver->info.sector_size;

	if (prv->aio_free_count == 0)
		goto fail;

	aio        = prv->aio_free_list[--prv->aio_free_count];
	aio->treq  = treq;
	aio->state = prv;

	td_prep_write(&aio->tiocb, prv->fd, treq.buf,
		      size, offset, tdaio_complete, aio);
	td_queue_tiocb(driver, &aio->tiocb);

	return;

fail:
	td_complete_request(treq, -EBUSY);
}

int tdaio_close(td_driver_t *driver)
{
	struct tdaio_state *prv = (struct tdaio_state *)driver->data;
	
	close(prv->fd);

	return 0;
}

int tdaio_get_parent_id(td_driver_t *driver, td_disk_id_t *id)
{
	return TD_NO_PARENT;
}

int tdaio_validate_parent(td_driver_t *driver,
			  td_driver_t *pdriver, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_aio = {
	.disk_type          = "tapdisk_aio",
	.flags              = 0,
	.private_data_size  = sizeof(struct tdaio_state),
	.td_open            = tdaio_open,
	.td_close           = tdaio_close,
	.td_queue_read      = tdaio_queue_read,
	.td_queue_write     = tdaio_queue_write,
	.td_get_parent_id   = tdaio_get_parent_id,
	.td_validate_parent = tdaio_validate_parent,
	.td_debug           = NULL,
};
