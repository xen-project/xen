/* block-sync.c
 *
 * simple slow synchronous raw disk implementation.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "tapdisk.h"
#include "blk.h"

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif

struct tdsync_state {
	int fd;
	int poll_pipe[2]; /* dummy fd for polling on */
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
		DPRINTF("Image size: \n\tpre sector_shift  [%lluu]\n\tpost "
			"sector_shift [%lluu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);
	}

	if (s->size == 0)
		return -EINVAL;

	s->info = 0;

	return 0;
}

static inline void init_fds(struct disk_driver *dd)
{
	int i;
	struct tdsync_state *prv = (struct tdsync_state *)dd->private;
	
	for(i = 0; i < MAX_IOFD; i++)
		dd->io_fd[i] = 0;

	dd->io_fd[0] = prv->poll_pipe[0];
}

/* Open the disk file and initialize aio state. */
static int tdsync_open (struct disk_driver *dd, const char *name, td_flag_t flags)
{
	int i, fd, ret = 0, o_flags;
	struct td_state     *s   = dd->td_state;
	struct tdsync_state *prv = (struct tdsync_state *)dd->private;
	
	/* set up a pipe so that we can hand back a poll fd that won't fire.*/
	ret = pipe(prv->poll_pipe);
	if (ret != 0)
		return (0 - errno);
	
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
		DPRINTF("Unable to open [%s]!\n",name);
        	ret = 0 - errno;
        	goto done;
        }

        prv->fd = fd;

	init_fds(dd);
	ret = get_image_info(s, fd);
done:
	return ret;	
}

static int tdsync_queue_read(struct disk_driver *dd, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct td_state     *s   = dd->td_state;
	struct tdsync_state *prv = (struct tdsync_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	int ret;
	
	ret = lseek(prv->fd, offset, SEEK_SET);
	if (ret != (off_t)-1) {
		ret = read(prv->fd, buf, size);
		if (ret != size) {
			ret = 0 - errno;
		} else {
			ret = 1;
		} 
	} else ret = 0 - errno;
		
	return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
}

static int tdsync_queue_write(struct disk_driver *dd, uint64_t sector,
			       int nb_sectors, char *buf, td_callback_t cb,
			       int id, void *private)
{
	struct td_state     *s   = dd->td_state;
	struct tdsync_state *prv = (struct tdsync_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	int ret = 0;
	
	ret = lseek(prv->fd, offset, SEEK_SET);
	if (ret != (off_t)-1) {
		ret = write(prv->fd, buf, size);
		if (ret != size) {
			ret = 0 - errno;
		} else {
			ret = 1;
		}
	} else ret = 0 - errno;
		
	return cb(dd, (ret < 0) ? ret : 0, sector, nb_sectors, id, private);
}
 		
static int tdsync_submit(struct disk_driver *dd)
{
	return 0;	
}

static int tdsync_close(struct disk_driver *dd)
{
	struct tdsync_state *prv = (struct tdsync_state *)dd->private;
	
	close(prv->fd);
	close(prv->poll_pipe[0]);
	close(prv->poll_pipe[1]);
	
	return 0;
}

static int tdsync_do_callbacks(struct disk_driver *dd, int sid)
{
	/* always ask for a kick */
	return 1;
}

static int tdsync_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	return TD_NO_PARENT;
}

static int tdsync_validate_parent(struct disk_driver *dd, 
			   struct disk_driver *parent, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_sync = {
	.disk_type           = "tapdisk_sync",
	.private_data_size   = sizeof(struct tdsync_state),
	.td_open             = tdsync_open,
	.td_queue_read       = tdsync_queue_read,
	.td_queue_write      = tdsync_queue_write,
	.td_submit           = tdsync_submit,
	.td_close            = tdsync_close,
	.td_do_callbacks     = tdsync_do_callbacks,
	.td_get_parent_id    = tdsync_get_parent_id,
	.td_validate_parent  = tdsync_validate_parent
};
