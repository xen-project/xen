/*
 * Copyright (c) 2006 Andrew Warfield and Julian Chesterfield
 * Copyright (c) 2007 Red Hat, Inc.
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

#ifndef __TAPAIO_H__
#define __TAPAIO_H__

#include <pthread.h>
#include <libaio.h>
#include <stdint.h>

#include "tapdisk.h"

#define IOCB_IDX(_ctx, _io) ((_io) - (_ctx)->iocb_list)

struct tap_aio_internal_context {
        io_context_t     aio_ctx;

        struct io_event *aio_events;
        int              max_aio_events;

        pthread_t        aio_thread;
        int              command_fd[2];
        int              completion_fd[2];
        int              pollfd;
        unsigned int     poll_in_thread : 1;
};
	

typedef struct tap_aio_internal_context tap_aio_internal_context_t;


struct pending_aio {
	td_callback_t cb;
	int id;
	void *private;
	int nb_sectors;
	char *buf;
	uint64_t sector;
};

	
struct tap_aio_context {
	tap_aio_internal_context_t    aio_ctx;

	int                  max_aio_reqs;
	struct iocb         *iocb_list;
	struct iocb        **iocb_free;
	struct pending_aio  *pending_aio;
	int                  iocb_free_count;
	struct iocb        **iocb_queue;
	int	             iocb_queued;
	struct io_event     *aio_events;

	/* Locking bitmap for AIO reads/writes */
	uint8_t *sector_lock;		   
};

typedef struct tap_aio_context tap_aio_context_t;

void tap_aio_continue   (tap_aio_internal_context_t *ctx);
int  tap_aio_get_events (tap_aio_internal_context_t *ctx);
int  tap_aio_more_events(tap_aio_internal_context_t *ctx);


int tap_aio_init(tap_aio_context_t *ctx, uint64_t sectors,
		int max_aio_reqs);
void tap_aio_free(tap_aio_context_t *ctx);

int tap_aio_can_lock(tap_aio_context_t *ctx, uint64_t sector);
int tap_aio_lock(tap_aio_context_t *ctx, uint64_t sector);
void tap_aio_unlock(tap_aio_context_t *ctx, uint64_t sector);


int tap_aio_read(tap_aio_context_t *ctx, int fd, int size, 
		uint64_t offset, char *buf, td_callback_t cb,
		int id, uint64_t sector, void *private);
int tap_aio_write(tap_aio_context_t *ctx, int fd, int size,
		uint64_t offset, char *buf, td_callback_t cb,
		int id, uint64_t sector, void *private);
int tap_aio_submit(tap_aio_context_t *ctx);

#endif /* __TAPAIO_H__ */
