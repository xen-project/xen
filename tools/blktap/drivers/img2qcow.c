/* img2qcow.c
 *
 * Generates a qcow format disk and fills it from an existing image.
 *
 * (c) 2006 Julian Chesterfield and Andrew Warfield
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
#include <string.h>
#include "tapdisk.h"
#include "blk.h"

#if 1
#define DFPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define DFPRINTF(_f, _a...) ((void)0)
#endif

/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif


#define TAPDISK 1
#define BLOCK_PROCESSSZ 4096

static int maxfds, *io_fd, running = 1, complete = 0;
static int returned_events = 0, submit_events = 0;
static uint64_t prev = 0;
static char output[25];

static void print_bytes(void *ptr, int length)
{
  int i,k;
  unsigned char *p = ptr;

    DFPRINTF("Buf dump, length %d:\n",length);
    for (k = 0; k < length; k++) {
        DFPRINTF("%x",*p);
        *p++;
	if(k % 16 == 0) DFPRINTF("\n");
        else if(k % 2 == 0) DFPRINTF(" ");	
    }
    DFPRINTF("\n");
    return;
}

static void debug_output(uint64_t progress, uint64_t size)
{
	uint64_t blocks = size/20;

	/*Output progress every 5% */	
	if (progress/blocks > prev) {
		memcpy(output+prev+1,"=>",2);
		prev++;
		DFPRINTF("\r%s     %llu%%", output, 
			(long long)(prev-1)*5);
	}
	return;
}

static inline void LOCAL_FD_SET(fd_set *readfds) 
{
	FD_SET(io_fd[0], readfds);
	maxfds = io_fd[0] + 1;
	
	return;
}

static int get_image_info(struct td_state *s, int fd)
{
	int ret;
	long size;
	unsigned long total_size;
	struct statvfs statBuf;
	struct stat stat;

	ret = fstat(fd, &stat);
	if (ret != 0) {
		DFPRINTF("ERROR: fstat failed, Couldn't stat image");
		return -EINVAL;
	}

	if (S_ISBLK(stat.st_mode)) {
		/*Accessing block device directly*/
		if (blk_getimagesize(fd, &s->size) != 0)
			return -EINVAL;

		DFPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
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
		DFPRINTF("Image size: [%llu]\n",
			(long long unsigned)s->size);
	}

	return 0;
}

static int send_responses(struct disk_driver *dd, int res, uint64_t sec, 
			  int nr_secs, int idx, void *private)
{
	if (res < 0) DFPRINTF("AIO FAILURE: res [%d]!\n",res);
	
	returned_events++;
	
	free(private);
	return 0;
}

int main(int argc, char *argv[])
{
	struct disk_driver dd;
	struct td_state *s;
	int ret = -1, fd, len;
	fd_set readfds;
	struct timeval timeout;
	uint64_t i;
	char *buf;

	if (argc != 3) {
		fprintf(stderr, "Qcow-utils: v1.0.0\n");
		fprintf(stderr, "usage: %s <QCOW FILENAME> <SRC IMAGE>\n", 
			argv[0]);
		exit(-1);
	}

	s = malloc(sizeof(struct td_state));
	
	/*Open image*/
	fd = open(argv[2], O_RDONLY | O_LARGEFILE);
	
        if (fd == -1) {
                DFPRINTF("Unable to open [%s], (err %d)!\n",argv[2],0 - errno);
                exit(-1);
        }
	
	get_image_info(s, fd);
	
	/*Create qcow file*/
	ret = qcow_create(argv[1],s->size<<SECTOR_SHIFT,NULL,0);
	
	if (ret < 0) {
		DFPRINTF("Unable to create QCOW file\n");
		exit(-1);
	} else DFPRINTF("Qcow file created: size %llu sectors\n",
			(long long unsigned)s->size);
	
	dd.td_state = s;
	dd.drv      = &tapdisk_qcow;
	dd.private  = malloc(dd.drv->private_data_size);

        /*Open qcow file*/
        if (dd.drv->td_open(&dd, argv[1], 0)!=0) {
		DFPRINTF("Unable to open Qcow file [%s]\n",argv[1]);
		exit(-1);
	}

	io_fd = dd.io_fd;

	/*Initialise the output string*/
	memset(output,0x20,25);
	output[0] = '[';
	output[22] = ']';
	output[23] = '\0';
	DFPRINTF("%s",output);

	i = 0;
	while (running) {
		timeout.tv_sec = 0;
		
		if (!complete) {
			/*Read sector from image*/
			if (lseek(fd, i, SEEK_SET) == (off_t)-1) {
				DFPRINTF("Unable to access file offset %llu\n",
				       (long long)i);
				exit(-1);
			}
			
			if( (ret = posix_memalign((void **)&buf, 
						  BLOCK_PROCESSSZ, 
						  BLOCK_PROCESSSZ)) != 0) {
				DFPRINTF("Unable to read memalign buf (%d)\n",ret);
				exit(-1);				
			}
		
			/*We attempt to read 4k sized blocks*/
			len = read(fd, buf, BLOCK_PROCESSSZ);
			if (len < 512) {
				DFPRINTF("Unable to read sector %llu\n",
				       (long long unsigned) (i >> 9));
				complete = 1;
				continue;
			}
			
			if (len % 512) {
				len = (len >> 9) << 9;
			}

			ret = dd.drv->td_queue_write(&dd, i >> 9,
						     len >> 9, buf, 
						     send_responses, 0, buf);
				
			if (!ret) submit_events++;
				
			if (ret < 0) {
				DFPRINTF("UNABLE TO WRITE block [%llu]\n",
				       (long long unsigned) (i >> 9));
			} else i += len;
			
			if (i >> 9 == s->size) complete = 1;

			debug_output(i,s->size << 9);
			
			if ((submit_events % 10 == 0) || complete) 
				dd.drv->td_submit(&dd);
			timeout.tv_usec = 0;
			
		} else {
			timeout.tv_usec = 1000;
			if (!submit_events) running = 0;
		}
		

		/*Check AIO FD*/
		LOCAL_FD_SET(&readfds);
                ret = select(maxfds + 1, &readfds, (fd_set *) 0,
                             (fd_set *) 0, &timeout);
			     
		if (ret > 0) dd.drv->td_do_callbacks(&dd, 0);
		if (complete && (returned_events == submit_events)) 
			running = 0;
	}
	memcpy(output+prev+1,"=",1);
	DFPRINTF("\r%s     100%%\nTRANSFER COMPLETE\n\n", output);
        dd.drv->td_close(&dd);
        free(dd.private);
        free(s);
		
	return 0;
}
