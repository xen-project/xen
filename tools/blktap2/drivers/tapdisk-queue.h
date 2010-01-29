/* 
 * Copyright (c) 2008, XenSource Inc.
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

#ifndef TAPDISK_QUEUE_H
#define TAPDISK_QUEUE_H

#include <libaio.h>

#include "io-optimize.h"
#include "scheduler.h"

struct tiocb;
struct tfilter;

typedef void (*td_queue_callback_t)(void *arg, struct tiocb *, int err);


struct tiocb {
	td_queue_callback_t   cb;
	void                 *arg;

	struct iocb           iocb;
	struct tiocb         *next;
};

struct tlist {
	struct tiocb         *head;
	struct tiocb         *tail;
};

struct tqueue {
	int                   size;
	int                   sync;

	int                   poll_fd;
	event_id_t	      event;
	io_context_t          aio_ctx;
	struct opioctx        opioctx;

	int                   queued;
	struct iocb         **iocbs;
	struct io_event      *aio_events;

	/* number of iocbs pending in the aio layer */
	int                   iocbs_pending;

	/* number of tiocbs pending in the queue -- 
	 * this is likely to be larger than iocbs_pending 
	 * due to request coalescing */
	int                   tiocbs_pending;

	/* iocbs may be deferred if the aio ring is full.
	 * tapdisk_queue_complete will ensure deferred
	 * iocbs are queued as slots become available. */
	struct tlist          deferred;
	int                   tiocbs_deferred;

	/* optional tapdisk filter */
	struct tfilter       *filter;

	uint64_t              deferrals;
};

/*
 * Interface for request producer (i.e., tapdisk)
 * NB: the following functions may cause additional tiocbs to be queued:
 *        - tapdisk_submit_tiocbs
 *        - tapdisk_cancel_tiocbs
 *        - tapdisk_complete_tiocbs
 * The *_all_tiocbs variants will handle the first two cases;
 * be sure to call submit after calling complete in the third case.
 */
#define tapdisk_queue_count(q) ((q)->queued)
#define tapdisk_queue_empty(q) ((q)->queued == 0)
#define tapdisk_queue_full(q)  \
	(((q)->tiocbs_pending + (q)->queued) >= (q)->size)
int tapdisk_init_queue(struct tqueue *, int size, int sync, struct tfilter *);
void tapdisk_free_queue(struct tqueue *);
void tapdisk_debug_queue(struct tqueue *);
void tapdisk_queue_tiocb(struct tqueue *, struct tiocb *);
int tapdisk_submit_tiocbs(struct tqueue *);
int tapdisk_submit_all_tiocbs(struct tqueue *);
int tapdisk_cancel_tiocbs(struct tqueue *);
int tapdisk_cancel_all_tiocbs(struct tqueue *);
void tapdisk_prep_tiocb(struct tiocb *, int, int, char *, size_t,
			long long, td_queue_callback_t, void *);

#endif
