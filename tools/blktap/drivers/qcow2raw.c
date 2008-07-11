/* qcow2raw.c
 *
 * Generates raw image data from an existing qcow image
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
#include <inttypes.h>
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
#define O_LARGEFILE 0
#endif

#define TAPDISK 1
#define BLOCK_PROCESSSZ 4096

static int maxfds, *qcowio_fd, *aio_fd, running = 1, complete = 0; 
static int returned_read_events = 0, returned_write_events = 0;
static int submit_events = 0;
static uint32_t read_idx = 0, write_idx = 0;
struct disk_driver ddqcow, ddaio;
static uint64_t prev = 0, written = 0;
static char output[25];

static void print_bytes(void *ptr, int length)
{
  int i,k;
  unsigned char *p = ptr;

    DFPRINTF("Buf dump, length %d:\n",length);
    for (k = 0; k < length; k++) {
        DFPRINTF("%x",*p);
        *p++;
	if (k % 16 == 0) DFPRINTF("\n");
        else if (k % 2 == 0) DFPRINTF(" ");	
    }
    DFPRINTF("\n");
    return;
}

static void debug_output(uint64_t progress, uint64_t size)
{
	/*Output progress every 5% */	
	uint64_t blocks = size/20;

	if (progress/blocks > prev) {
		memcpy(output+prev+1,"=>",2);
		prev++;
		DFPRINTF("\r%s     %llu%%", 
			output, (long long)((prev-1)*5));
	}
	return;
}

static inline void LOCAL_FD_SET(fd_set *readfds) 
{
	FD_SET(qcowio_fd[0], readfds);
	FD_SET(aio_fd[0], readfds);
	
	maxfds = (qcowio_fd[0] > aio_fd[0] ? qcowio_fd[0] : aio_fd[0]) + 1;
	
	return;
}

static int send_write_responses(struct disk_driver *dd, int res, uint64_t sec,
				int nr_secs, int idx, void *private)
{
	if (res < 0) {
		DFPRINTF("AIO FAILURE: res [%d]!\n",res);
		return 0;
	}
	written += BLOCK_PROCESSSZ;
	returned_write_events++;
	write_idx = idx;

	debug_output(written, dd->td_state->size << 9);
	free(private);
	return 0;
}

static int send_read_responses(struct disk_driver *dd, int res, uint64_t sec,
			       int nr_secs, int idx, void *private)
{
	int ret;

	if (res < 0) DFPRINTF("AIO FAILURE: res [%d]!\n",res);
	
	returned_read_events++;
	read_idx = idx;
	
	ret = ddaio.drv->td_queue_write(&ddaio, idx, BLOCK_PROCESSSZ>>9, private, 
					send_write_responses, idx, private);
	if (ret != 0) {
		DFPRINTF("ERROR in submitting queue write!\n");
		return 0;
	}

	if ( (returned_read_events == submit_events) || 
	     (returned_read_events % 10 == 0) ) {
		ddaio.drv->td_submit(&ddaio);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = -1, fd, len,input;
	uint64_t size;
	fd_set readfds;
	struct timeval timeout;
	uint64_t i;
	char *buf;
	struct stat finfo;

	if (argc != 3) {
		fprintf(stderr, "Qcow-utils: v1.0.0\n");
		fprintf(stderr, "usage: %s <Dest File descriptor> "
			"<Qcow SRC IMAGE>\n", 
		       argv[0]);
		exit(-1);
	}

	ddqcow.td_state = malloc(sizeof(struct td_state));
	ddaio.td_state  = malloc(sizeof(struct td_state));
	
	/*Open qcow source file*/	
	ddqcow.drv = &tapdisk_qcow;
	ddqcow.private = malloc(ddqcow.drv->private_data_size);

        if (ddqcow.drv->td_open(&ddqcow, argv[2], TD_RDONLY)!=0) {
		DFPRINTF("Unable to open Qcow file [%s]\n",argv[2]);
		exit(-1);
	} else DFPRINTF("QCOW file opened, size %llu\n",
		      (long long unsigned)ddqcow.td_state->size);

	qcowio_fd = ddqcow.io_fd;

        /*Setup aio destination file*/
	ret = stat(argv[1],&finfo);
	if (ret == -1) {
		/*Check errno*/
		switch(errno) {
		case ENOENT:
			/*File doesn't exist, create*/
			fd = open(argv[1], 
				  O_RDWR | O_LARGEFILE | O_CREAT, 0644);
			if (fd < 0) {
				DFPRINTF("ERROR creating file [%s] "
					 "(errno %d)\n",
				       argv[1], 0 - errno);
				exit(-1);
			}
			if (ftruncate(fd, (off_t)ddqcow.td_state->size<<9) < 0) {
				DFPRINTF("Unable to create file "
					"[%s] of size %llu (errno %d). "
					 "Exiting...\n",
					argv[1], 
					(long long unsigned)ddqcow.td_state->size<<9, 
					0 - errno);
				close(fd);
				exit(-1);
			}
			close(fd);
			break;
		case  ENXIO:
			DFPRINTF("ERROR Device [%s] does not exist\n",argv[1]);
			exit(-1);
		default: 
			DFPRINTF("An error occurred opening Device [%s] "
				 "(errno %d)\n",
			       argv[1], 0 - errno);
			exit(-1);
		}
	} else {		
		fprintf(stderr, "WARNING: All existing data in "
			"%s will be overwritten.\nDo you wish to continue? "
			"(y or n)  ",
			argv[1]);
		if (getchar() != 'y') {
			DFPRINTF("Exiting...\n");
			exit(-1);
		}
		
		/*TODO - Test the existing file or device for adequate space*/
		fd = open(argv[1], O_RDWR | O_LARGEFILE);
		if (fd < 0) {
			DFPRINTF("ERROR: opening file [%s] (errno %d)\n",
			       argv[1], 0 - errno);
			exit(-1);
		}

		if (S_ISBLK(finfo.st_mode)) {
			if (blk_getimagesize(fd, &size) != 0) {
				close(fd);
				return -1;
			}

			if (size < ddqcow.td_state->size<<9) {
				DFPRINTF("ERROR: Not enough space on device "
					"%s (%"PRIu64" bytes available, "
					"%llu bytes required\n",
					argv[1], size, 
					(long long unsigned)ddqcow.td_state->size<<9);
				close(fd);
				exit(-1);				
			}
		} else {
			if (ftruncate(fd, (off_t)ddqcow.td_state->size<<9) < 0) {
				DFPRINTF("Unable to create file "
					"[%s] of size %llu (errno %d). "
					 "Exiting...\n",
					argv[1], 
					(long long unsigned)ddqcow.td_state->size<<9, 
					 0 - errno);
				close(fd);
				exit(-1);
			} else DFPRINTF("File [%s] truncated to length %llu "
					"(%llu)\n", 
				       argv[1], 
				       (long long unsigned)ddqcow.td_state->size<<9, 
				       (long long unsigned)ddqcow.td_state->size);
		}
		close(fd);
	}

	/*Open aio destination file*/	
	ddaio.drv = &tapdisk_aio;
	ddaio.private = malloc(ddaio.drv->private_data_size);

        if (ddaio.drv->td_open(&ddaio, argv[1], 0)!=0) {
		DFPRINTF("Unable to open Qcow file [%s]\n", argv[1]);
		exit(-1);
	}

	aio_fd = ddaio.io_fd;

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
			/*Read Pages from qcow image*/
			if ( (ret = posix_memalign((void **)&buf, 
						   BLOCK_PROCESSSZ, 
						   BLOCK_PROCESSSZ))
			     != 0) {
				DFPRINTF("Unable to alloc memory (%d)\n",ret);
				exit(-1);				
			}
		
			/*Attempt to read 4k sized blocks*/
			submit_events++;
			ret = ddqcow.drv->td_queue_read(&ddqcow, i>>9,
							BLOCK_PROCESSSZ>>9, buf, 
							send_read_responses, i>>9, buf);

			if (ret < 0) {
				DFPRINTF("UNABLE TO READ block [%llu]\n",
				       (long long unsigned)i);
				exit(-1);
			} else {
				i += BLOCK_PROCESSSZ;
			}

			if (i >= ddqcow.td_state->size<<9) {
				complete = 1;
			}
			
			if ((submit_events % 10 == 0) || complete) 
				ddqcow.drv->td_submit(&ddqcow);
			timeout.tv_usec = 0;
			
		} else {
			timeout.tv_usec = 1000;
			if (!submit_events) running = 0;
		}
		

		/*Check AIO FD*/
		LOCAL_FD_SET(&readfds);
                ret = select(maxfds + 1, &readfds, (fd_set *) 0,
                             (fd_set *) 0, &timeout);
			     
		if (ret > 0) {
			if (FD_ISSET(qcowio_fd[0], &readfds)) 
				ddqcow.drv->td_do_callbacks(&ddqcow, 0);
			if (FD_ISSET(aio_fd[0], &readfds)) 
				ddaio.drv->td_do_callbacks(&ddaio, 0);
		}
		if (complete && (returned_write_events == submit_events)) 
			running = 0;
	}
	memcpy(output+prev+1,"=",1);
	DFPRINTF("\r%s     100%%\nTRANSFER COMPLETE\n\n", output);
		
	return 0;
}
