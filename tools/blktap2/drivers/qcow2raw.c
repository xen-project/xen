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

#include "bswap.h"
#include "aes.h"
#include "blk.h"
#include "tapdisk.h"
#include "tapdisk-server.h"
#include "tapdisk-driver.h"
#include "tapdisk-interface.h"
#include "tapdisk-disktype.h"
#include "qcow.h"

#if 1
#define DFPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define DFPRINTF(_f, _a...) ((void)0)
#endif


/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#define BLOCK_PROCESSSZ 4096
#define QCOW_VBD 0
#define AIO_VBD 1
#define WINDOW 32
#define PROGRESS_QUANT 2

static int running = 1, complete = 0; 
static int returned_read_events = 0, returned_write_events = 0;
static int submit_events = 0;
static uint32_t read_idx = 0;
td_driver_t *ddqcow, *ddaio;
td_vbd_t* qcow_vbd, *aio_vbd;
static uint64_t prev = 0, written = 0;
static char output[(100/PROGRESS_QUANT) + 5];

extern tapdisk_server_t server;

struct request_info {
  void* buf;
  uint64_t logical_sec;
  int pending;
};

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
        //Output progress every PROGRESS_QUANT 
        uint64_t blocks = size/(100/PROGRESS_QUANT);

	if (progress/blocks > prev) {
		memcpy(output+prev+1,"=>",2);
		prev++;
		DFPRINTF("\r%s     %"PRIu64"%%", 
			output, (uint64_t)((prev-1)*PROGRESS_QUANT));
	}
	return;
}

static void send_write_responses(td_request_t treq, int err)
{
        struct request_info* req;

	if (err < 0) {
		DFPRINTF("AIO FAILURE: res [%d]!\n",err);
		return;
	}
	returned_write_events+=treq.secs;
        written += treq.secs;

        req= (struct request_info*)treq.cb_data;

        //Wait for whole request to complete.
        req->pending-=treq.secs;
        if(req->pending)
          return;

        //Whole request has completed, we can free buffers. 
        free(req->buf);
        free(req);

	debug_output(written, ddaio->info.size);
	
	return;
}

static void send_read_responses(td_request_t treq, int err)
{
	int ret;
        struct request_info* req;
        td_vbd_request_t* vreq;

	if (err < 0)  {
	  DFPRINTF("AIO FAILURE: res [%d]!\n",err); 
	  return;
	}
	returned_read_events+=treq.secs;

        req= (struct request_info*)treq.cb_data;

        //do nothing until all fragments complete.
        req->pending-=treq.secs;

        if(req->pending)
          return;

        //This read is done.
        tapdisk_vbd_complete_vbd_request(qcow_vbd, treq.private);


        treq.op      = TD_OP_WRITE;
        treq.buf     = req->buf;
        treq.sec     = req->logical_sec;
        treq.secs    = BLOCK_PROCESSSZ>>9;
        treq.image   = tapdisk_vbd_first_image(aio_vbd);
        treq.cb      = send_write_responses;
        treq.id      = 0;
        treq.sidx    = 0;

        req->pending = BLOCK_PROCESSSZ>>9;
        treq.cb_data = req;

        vreq         = calloc(1, sizeof(td_vbd_request_t));
        treq.private = vreq;

        //Put it in the VBD's queue, so we don't lose
        //track of it.
        vreq->submitting = 1;
        INIT_LIST_HEAD(&vreq->next);
        tapdisk_vbd_move_request(treq.private, 
                                 &aio_vbd->pending_requests);

        ddaio->ops->td_queue_write(ddaio,treq);
        --vreq->submitting;

        tapdisk_submit_all_tiocbs(&server.aio_queue);

	return;
}

int main(int argc, const char *argv[])
{
	int ret = -1, fd, len,input;
	uint64_t size;
	struct timeval timeout;
	uint64_t i;
	char *buf = NULL;
	struct stat finfo;
	td_request_t treq;
	td_vbd_request_t* vreq;
        struct request_info* req;
        int err;

	if (argc != 3) {
		fprintf(stderr, "Qcow-utils: v1.0.0\n");
		fprintf(stderr, "usage: %s <Dest File descriptor> "
			"<Qcow SRC IMAGE>\n", 
		       argv[0]);
		exit(-1);
	}

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

        err = tapdisk_vbd_open_vdi(qcow_vbd, argv[2], DISK_TYPE_QCOW,
                                   TAPDISK_STORAGE_TYPE_DEFAULT,
                                   TD_OPEN_RDONLY);
        if( err ) {
          DPRINTF("qcow2raw Couldn't open qcow file.\n");
          return err;
        }

        ddqcow=(tapdisk_vbd_first_image(qcow_vbd))->driver;

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
			if (ftruncate(fd, (off_t)ddqcow->info.size<<9) < 0) {
				DFPRINTF("Unable to create file "
					"[%s] of size %"PRIu64" (errno %d). "
					 "Exiting...\n",
					argv[1], 
					(uint64_t)ddqcow->info.size<<9, 
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

			if (size < ddqcow->info.size<<9) {
				DFPRINTF("ERROR: Not enough space on device "
					"%s (%"PRIu64" bytes available, "
					"%"PRIu64" bytes required\n",
					argv[1], size, 
					(uint64_t)ddqcow->info.size<<9);
				close(fd);
				exit(-1);				
			}
		} else {
			if (ftruncate(fd, (off_t)ddqcow->info.size<<9) < 0) {
				DFPRINTF("Unable to create file "
					"[%s] of size %"PRIu64" (errno %d). "
					 "Exiting...\n",
					argv[1], 
					(uint64_t)ddqcow->info.size<<9, 
					 0 - errno);
				close(fd);
				exit(-1);
			} else DFPRINTF("File [%s] truncated to length %"PRIu64" "
					"(%"PRIu64")\n", 
				       argv[1], 
				       (uint64_t)ddqcow->info.size<<9, 
				       (uint64_t)ddqcow->info.size);
		}
		close(fd);
	}

        //Now the output file should be there, reopen it as an aio VBD
        err=tapdisk_vbd_initialize(AIO_VBD);
        if( err ) {
          DPRINTF("qcow2raw Couldn't initialize aio vbd.\n");
          return err;
        }

        aio_vbd = tapdisk_server_get_vbd(AIO_VBD);
        if (!aio_vbd) {
          err = -ENODEV;
          DPRINTF("qcow2raw Couldn't create aio vbd.\n");
          return err;
        }

        err = tapdisk_vbd_open_vdi(aio_vbd, argv[1], DISK_TYPE_AIO,
                                   TAPDISK_STORAGE_TYPE_DEFAULT,
                                   0);
        if( err ) {
          DPRINTF("qcow2raw Couldn't open aio file.\n");
          return err;
        }

        ddaio=(tapdisk_vbd_first_image(aio_vbd))->driver;

	/*Initialise the output string*/
	memset(output,0x20,(100/PROGRESS_QUANT)+5);
	output[0] = '[';
        output[(100/PROGRESS_QUANT)+2] = ']';
        output[(100/PROGRESS_QUANT)+3] = '\0';
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
			submit_events+=BLOCK_PROCESSSZ>>9;

			//Set up the read request
			treq.op      = TD_OP_READ;
			treq.buf     = buf;
			treq.sec     = i;
			treq.secs    = BLOCK_PROCESSSZ>>9;
			treq.image   = tapdisk_vbd_first_image(qcow_vbd);
			treq.cb      = send_read_responses;
			treq.id      = 0;
			treq.sidx    = 0;

                        req = calloc(1, sizeof(struct request_info));
                        req->buf = buf;
                        req->logical_sec = i;
                        req->pending = BLOCK_PROCESSSZ>>9;
			treq.cb_data = req;

                        vreq         = calloc(1, sizeof(td_vbd_request_t));
                        treq.private = vreq;

                        //Put it in the VBD's queue, so we don't lose
                        //track of it.
                        vreq->submitting = 1;
                        INIT_LIST_HEAD(&vreq->next);
                        tapdisk_vbd_move_request(treq.private, 
                                                 &qcow_vbd->pending_requests);

			ddqcow->ops->td_queue_read(ddqcow, treq);
                        --vreq->submitting;

			i += BLOCK_PROCESSSZ>>9;

			if (i >= ddqcow->info.size)
			  complete = 1;

			
			tapdisk_submit_all_tiocbs(&server.aio_queue);
		}
		

		while(returned_write_events != submit_events) {
		  ret = scheduler_wait_for_events(&server.scheduler);
		  if (ret < 0) {
		    DFPRINTF("server wait returned %d\n", ret);
		    sleep(2);
		  }
		}
		if (complete && (returned_write_events == submit_events)) 
			running = 0;
	}
	memcpy(output+prev+1,"=",1);
	DFPRINTF("\r%s     100%%\nTRANSFER COMPLETE\n\n", output);

	ddqcow->ops->td_close(ddqcow);
	ddaio->ops->td_close(ddaio);
	free(ddqcow->data);
	free(ddaio->data);
		
	return 0;
}
