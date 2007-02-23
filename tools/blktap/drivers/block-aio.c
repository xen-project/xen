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
#include <linux/fs.h>
#include "tapdisk.h"


/**
 * We used a kernel patch to return an fd associated with the AIO context
 * so that we can concurrently poll on synchronous and async descriptors.
 * This is signalled by passing 1 as the io context to io_setup.
 */
#define REQUEST_ASYNC_FD 1

#define MAX_AIO_REQS (MAX_REQUESTS * MAX_SEGMENTS_PER_REQ)

struct pending_aio {
	td_callback_t cb;
	int id;
	void *private;
	uint64_t lsec;
};

struct tdaio_state {
	int fd;
	
	/* libaio state */
	io_context_t       aio_ctx;
	struct iocb        iocb_list  [MAX_AIO_REQS];
	struct iocb       *iocb_free  [MAX_AIO_REQS];
	struct pending_aio pending_aio[MAX_AIO_REQS];
	int                iocb_free_count;
	struct iocb       *iocb_queue[MAX_AIO_REQS];
	int                iocb_queued;
	int                poll_fd; /* NB: we require aio_poll support */
	struct io_event    aio_events[MAX_AIO_REQS];
};

#define IOCB_IDX(_s, _io) ((_io) - (_s)->iocb_list)

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
		s->size = 0;
		if (ioctl(fd,BLKGETSIZE,&s->size)!=0) {
			DPRINTF("ERR: BLKGETSIZE failed, couldn't stat image");
			return -EINVAL;
		}

		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);

		/*Get the sector size*/
#if defined(BLKSSZGET)
		{
			int arg;
			s->sector_size = DEFAULT_SECTOR_SIZE;
			ioctl(fd, BLKSSZGET, &s->sector_size);
			
			if (s->sector_size != DEFAULT_SECTOR_SIZE)
				DPRINTF("Note: sector size is %ld (not %d)\n",
					s->sector_size, DEFAULT_SECTOR_SIZE);
		}
#else
		s->sector_size = DEFAULT_SECTOR_SIZE;
#endif

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

	dd->io_fd[0] = prv->poll_fd;
}

/* Open the disk file and initialize aio state. */
int tdaio_open (struct disk_driver *dd, const char *name, td_flag_t flags)
{
	int i, fd, ret = 0, o_flags;
	struct td_state    *s   = dd->td_state;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	DPRINTF("block-aio open('%s')", name);
	/* Initialize AIO */
	prv->iocb_free_count = MAX_AIO_REQS;
	prv->iocb_queued     = 0;
	
	prv->aio_ctx = (io_context_t) REQUEST_ASYNC_FD;
	prv->poll_fd = io_setup(MAX_AIO_REQS, &prv->aio_ctx);

	if (prv->poll_fd < 0) {
		ret = prv->poll_fd;
                if (ret == -EAGAIN) {
                        DPRINTF("Couldn't setup AIO context.  If you are "
                                "trying to concurrently use a large number "
                                "of blktap-based disks, you may need to "
                                "increase the system-wide aio request limit. "
                                "(e.g. 'echo echo 1048576 > /proc/sys/fs/"
                                "aio-max-nr')\n");
                } else {
                        DPRINTF("Couldn't get fd for AIO poll support.  This "
                                "is probably because your kernel does not "
                                "have the aio-poll patch applied.\n");
                }
		goto done;
	}

	for (i=0;i<MAX_AIO_REQS;i++)
		prv->iocb_free[i] = &prv->iocb_list[i];

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

int tdaio_queue_read(struct disk_driver *dd, uint64_t sector,
		     int nb_sectors, char *buf, td_callback_t cb,
		     int id, void *private)
{
	struct   iocb *io;
	struct   pending_aio *pio;
	struct   td_state    *s   = dd->td_state;
	struct   tdaio_state *prv = (struct tdaio_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	long     ioidx;
	
	if (prv->iocb_free_count == 0)
		return -ENOMEM;
	io = prv->iocb_free[--prv->iocb_free_count];
	
	ioidx = IOCB_IDX(prv, io);
	pio = &prv->pending_aio[ioidx];
	pio->cb = cb;
	pio->id = id;
	pio->private = private;
	pio->lsec = sector;
	
	io_prep_pread(io, prv->fd, buf, size, offset);
	io->data = (void *)ioidx;
	
	prv->iocb_queue[prv->iocb_queued++] = io;

	return 0;
}
			
int tdaio_queue_write(struct disk_driver *dd, uint64_t sector,
		      int nb_sectors, char *buf, td_callback_t cb,
		      int id, void *private)
{
	struct   iocb *io;
	struct   pending_aio *pio;
	struct   td_state    *s   = dd->td_state;
	struct   tdaio_state *prv = (struct tdaio_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	long     ioidx;
	
	if (prv->iocb_free_count == 0)
		return -ENOMEM;
	io = prv->iocb_free[--prv->iocb_free_count];
	
	ioidx = IOCB_IDX(prv, io);
	pio = &prv->pending_aio[ioidx];
	pio->cb = cb;
	pio->id = id;
	pio->private = private;
	pio->lsec = sector;
	
	io_prep_pwrite(io, prv->fd, buf, size, offset);
	io->data = (void *)ioidx;
	
	prv->iocb_queue[prv->iocb_queued++] = io;

	return 0;
}
			
int tdaio_submit(struct disk_driver *dd)
{
	int ret;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	if (!prv->iocb_queued)
		return 0;

	ret = io_submit(prv->aio_ctx, prv->iocb_queued, prv->iocb_queue);
	
	/* XXX: TODO: Handle error conditions here. */
	
	/* Success case: */
	prv->iocb_queued = 0;
	
	return 0;
}

int tdaio_close(struct disk_driver *dd)
{
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;
	
	io_destroy(prv->aio_ctx);
	close(prv->fd);

	return 0;
}

int tdaio_do_callbacks(struct disk_driver *dd, int sid)
{
	int ret, i, rsp = 0;
	struct io_event *ep;
	struct tdaio_state *prv = (struct tdaio_state *)dd->private;

	/* Non-blocking test for completed io. */
	ret = io_getevents(prv->aio_ctx, 0, MAX_AIO_REQS, prv->aio_events,
			   NULL);
			
	for (ep=prv->aio_events,i=ret; i-->0; ep++) {
		struct iocb        *io  = ep->obj;
		struct pending_aio *pio;
		
		pio = &prv->pending_aio[(long)io->data];
		rsp += pio->cb(dd, ep->res == io->u.c.nbytes ? 0 : 1,
			       pio->lsec, io->u.c.nbytes >> 9, 
			       pio->id, pio->private);

		prv->iocb_free[prv->iocb_free_count++] = io;
	}
	return rsp;
}

int tdaio_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	return TD_NO_PARENT;
}

int tdaio_validate_parent(struct disk_driver *dd, 
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
