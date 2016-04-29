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
#include <zlib.h>
#include <inttypes.h>
#include <libaio.h>

#include "bswap.h"
#include "aes.h"
#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-disktype.h"
#include "qcow.h"
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

#define BLOCK_PROCESSSZ 4096
#define QCOW_VBD 0
#define PROGRESS_QUANT 2

static int running = 1, complete = 0;
static int returned_events = 0, submit_events = 0;
static uint32_t read_idx = 0;
td_driver_t *ddqcow;
td_vbd_t* qcow_vbd;
static uint64_t prev = 0, written = 0;
static char output[(100/PROGRESS_QUANT) + 5];

extern tapdisk_server_t server;


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
  //Output progress every PROGRESS_QUANT                                  
  uint64_t blocks = size/(100/PROGRESS_QUANT);

  if (progress/blocks > prev) {
    memcpy(output+prev+1,"=>",2);
    prev++;
    DFPRINTF("\r%s     %"PRIi64"%%",
             output, (int64_t)((prev-1)*PROGRESS_QUANT));
  }
  return;
}

static int get_image_info(td_disk_info_t *driver, int fd)
{
	int ret;
	long size;
	unsigned long total_size;
	struct statvfs statBuf;
	struct stat stat;
	uint64_t sector_size=DEFAULT_SECTOR_SIZE;

	ret = fstat(fd, &stat);
	if (ret != 0) {
		DFPRINTF("ERROR: fstat failed, Couldn't stat image");
		return -EINVAL;
	}

	if (S_ISBLK(stat.st_mode)) {
		/*Accessing block device directly*/
		if (blk_getimagesize(fd, &driver->size) != 0)
			return -EINVAL;

		DFPRINTF("Image size: \n\tpre sector_shift  [%"PRIu64"]\n\tpost "
			"sector_shift [%"PRIu64"]\n",
			(uint64_t)(driver->size << SECTOR_SHIFT),
			(uint64_t)driver->size);

		/*Get the sector size*/
		if (!blk_getsectorsize(fd, &sector_size))
		  driver->sector_size = sector_size;

	} else {
		/*Local file? try fstat instead*/
		driver->size = (stat.st_size >> SECTOR_SHIFT);
		driver->sector_size = DEFAULT_SECTOR_SIZE;
		DFPRINTF("Image size: [%"PRIu64"]\n",
			(uint64_t)driver->size);
	}

	return 0;
}

void send_responses(td_request_t treq, int err)
{
  if (err < 0) {
    DFPRINTF("AIO FAILURE: res [%d]!\n",err);
    return;
  }

  returned_events++;

  free(treq.buf);
} 

int main(int argc, const char *argv[])
{
        int ret = -1, fd, len, err;
	struct timeval timeout;
	uint64_t i;
	char *buf = NULL;
	td_request_t treq;
        td_disk_info_t info;
        td_vbd_request_t* vreq;

	if (argc != 3) {
		fprintf(stderr, "Qcow-utils: v1.0.0\n");
		fprintf(stderr, "usage: %s <QCOW FILENAME> <SRC IMAGE>\n", 
			argv[0]);
		exit(-1);
	}


	/*Open image*/
	fd = open(argv[2], O_RDONLY | O_LARGEFILE);
	
        if (fd == -1) {
                DFPRINTF("Unable to open [%s], (err %d)!\n",argv[2],0 - errno);
                exit(-1);
        }
	
	get_image_info(&info, fd);

	/*Create qcow file*/
	ret = qcow_create(argv[1],info.size<<SECTOR_SHIFT,NULL,0);
	
	if (ret < 0) {
		DFPRINTF("Unable to create QCOW file\n");
		exit(-1);
	} else DFPRINTF("Qcow file created: size %"PRIu64" sectors\n",
			(uint64_t)info.size);
	
        /* Open Qcow image*/
        err = tapdisk_server_initialize();
        if( err ) {
          DPRINTF("qcow2raw Couldn't initialize server instance.\n");
          return err;
        }

        err=tapdisk_vbd_initialize(QCOW_VBD);
        if( err ) {
          DPRINTF("qcow2raw Couldn't initialize qcow vbd.\n");
          return err;
        }

        qcow_vbd = tapdisk_server_get_vbd(QCOW_VBD);
        if (!qcow_vbd) {
          err = -ENODEV;
          DPRINTF("qcow2raw Couldn't create qcow vbd.\n");
          return err;
        }

        err = tapdisk_vbd_open_vdi(qcow_vbd, argv[1], DISK_TYPE_QCOW,
                                   TAPDISK_STORAGE_TYPE_DEFAULT,
                                   0);
        if( err ) {
          DPRINTF("qcow2raw Couldn't open qcow file.\n");
          return err;
        }

        ddqcow=(tapdisk_vbd_first_image(qcow_vbd))->driver;

        /*Initialise the output string*/
        memset(output,0x20,(100/PROGRESS_QUANT)+5);
        output[0] = '[';
        output[(100/PROGRESS_QUANT)+2] = ']';
        output[(100/PROGRESS_QUANT)+3] = '\0';
        DFPRINTF("%s",output);

	i = 0;
	while (running) {
		
		if (!complete) {
			/*Read sector from image*/
			if (lseek(fd, i*512, SEEK_SET) == (off_t)-1) {
				DFPRINTF("Unable to access file offset %"PRIu64"\n",
				       (uint64_t)i*512);
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
				DFPRINTF("Unable to read sector %"PRIu64"\n",
					 (uint64_t) (i));
				complete = 1;
				continue;
			}
			
			len = (len >> 9);

			treq.op = TD_OP_WRITE;
			treq.buf = buf;
			treq.sec = i;
			treq.secs = len;
			treq.image = 0;
			treq.cb = send_responses;
			treq.cb_data = buf;
			treq.id = 0;
			treq.sidx = 0;
                        vreq = calloc(1, sizeof(td_vbd_request_t));
			treq.private = vreq; 
                        
			vreq->submitting = 1;
                        INIT_LIST_HEAD(&vreq->next);
                        tapdisk_vbd_move_request(treq.private,
                                                 &qcow_vbd->pending_requests);

                        ddqcow->ops->td_queue_write(ddqcow,treq);
                        --vreq->submitting;

			submit_events++;

			i += len;

			if (i == info.size) 
			  complete = 1;

                        tapdisk_submit_all_tiocbs(&server.aio_queue);
			debug_output(i,info.size);
                }
		
		while(returned_events != submit_events) {
		    ret = scheduler_wait_for_events(&server.scheduler);
		    if (ret < 0) {
		      DFPRINTF("server wait returned %d\n", ret);
		      sleep(2);
		    }
		}

		if (complete && (returned_events == submit_events)) 
			running = 0;
	}
	memcpy(output+prev+1,"=",1);
	DFPRINTF("\r%s     100%%\nTRANSFER COMPLETE\n\n", output);

        ddqcow->ops->td_close(ddqcow);
        free(ddqcow->data);

	return 0;
}
