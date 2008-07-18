/* block-aio.c
 *
 * libaio-based raw disk implementation.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 *
 * NB: This code is not thread-safe.
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


#include <errno.h>
#include <libaio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "tapdisk.h"
#include "tapaio.h"
#include "blk.h"

#define MAX_AIO_REQS (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif

struct tdaio_state {
	int fd;
	tap_aio_context_t aio;
};


/*Get Image size, secsize*/
static int get_image_info(struct td_state *s, int fd)
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
		if (blk_getimagesize(fd, &s->size) != 0)
			return -EINVAL;

		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);

		/*Get the sector size*/
		if (blk_getsectorsize(fd, &s->sector_size) != 0)
			s->sector_size = DEFAULT_SECTOR_SIZE;

	} else {
		/*Local file? try fstat instead*/
		s->size = (stat.st_size >> SECTOR_SHIFT);
		s->sector_size = DEFAULT_SECTOR_SIZE;
		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);
	}

	if (s->size == 0) {		
		s->size =((uint64_t) 16836057);
		s->sector_size = DEFAULT_SECTOR_SIZE;
	}
	s->info = 0;

	return 0;
}

static inline void init_fds(struct disk_driver *dd)
{
	int i;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	for(i = 0; i < MAX_IOFD; i++) 
		dd->io_fd[i] = 0;

	dd->io_fd[0] = prv->aio.aio_ctx.pollfd;
}

/* Open the disk file and initialize aio state. */
static int tdaio_open (struct disk_driver *dd, const char *name, td_flag_t flags)
{
	int i, fd, ret = 0, o_flags;
	struct td_state    *s   = dd->td_state;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	DPRINTF("block-aio open('%s')", name);

	/* Initialize AIO */
	ret = tap_aio_init(&prv->aio, 0, MAX_AIO_REQS);
	if (ret != 0)
		return ret;

	/* Open the file */
	o_flags = O_DIRECT | O_LARGEFILE | 
		((flags == TD_RDONLY) ? O_RDONLY : O_RDWR);
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

        prv->fd = fd;

	init_fds(dd);
	ret = get_image_info(s, fd);

done:
	return ret;	
}

static int tdaio_queue_read(struct disk_driver *dd, uint64_t sector,
		     int nb_sectors, char *buf, td_callback_t cb,
		     int id, void *private)
{
	struct   td_state    *s   = dd->td_state;
	struct   tdaio_state *prv = (struct tdaio_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;

	return tap_aio_read(&prv->aio, prv->fd, size, offset, buf, 
		cb, id, sector, private);
}
			
static int tdaio_queue_write(struct disk_driver *dd, uint64_t sector,
		      int nb_sectors, char *buf, td_callback_t cb,
		      int id, void *private)
{
	struct   td_state    *s   = dd->td_state;
	struct   tdaio_state *prv = (struct tdaio_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;

	return tap_aio_write(&prv->aio, prv->fd, size, offset, buf,
		cb, id, sector, private);
}

static int tdaio_submit(struct disk_driver *dd)
{
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	return tap_aio_submit(&prv->aio);
}
			
static int tdaio_close(struct disk_driver *dd)
{
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;
	
	io_destroy(prv->aio.aio_ctx.aio_ctx);
	close(prv->fd);

	return 0;
}

static int tdaio_do_callbacks(struct disk_driver *dd, int sid)
{
	int i, nr_events, rsp = 0;
	struct io_event *ep;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	nr_events = tap_aio_get_events(&prv->aio.aio_ctx);
repeat:
	for (ep = prv->aio.aio_events, i = nr_events; i-- > 0; ep++) {
		struct iocb        *io  = ep->obj;
		struct pending_aio *pio;
		
		pio = &prv->aio.pending_aio[(long)io->data];
		rsp += pio->cb(dd, ep->res == io->u.c.nbytes ? 0 : 1,
			       pio->sector, io->u.c.nbytes >> 9, 
			       pio->id, pio->private);

		prv->aio.iocb_free[prv->aio.iocb_free_count++] = io;
	}

	if (nr_events) {
		nr_events = tap_aio_more_events(&prv->aio.aio_ctx);
		goto repeat;
	}

	tap_aio_continue(&prv->aio.aio_ctx);

	return rsp;
}

static int tdaio_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	return TD_NO_PARENT;
}

static int tdaio_validate_parent(struct disk_driver *dd, 
			  struct disk_driver *parent, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_aio = {
	.disk_type          = "tapdisk_aio",
	.private_data_size  = sizeof(struct tdaio_state),
	.td_open            = tdaio_open,
	.td_queue_read      = tdaio_queue_read,
	.td_queue_write     = tdaio_queue_write,
	.td_submit          = tdaio_submit,
	.td_close           = tdaio_close,
	.td_do_callbacks    = tdaio_do_callbacks,
	.td_get_parent_id   = tdaio_get_parent_id,
	.td_validate_parent = tdaio_validate_parent
};
