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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <libaio.h>
#ifdef __linux__
#include <linux/version.h>
#endif

#include "tapdisk.h"
#include "tapdisk-log.h"
#include "tapdisk-queue.h"
#include "tapdisk-filter.h"
#include "tapdisk-server.h"
#include "tapdisk-utils.h"

#include "libaio-compat.h"
#include "atomicio.h"

#define WARN(_f, _a...) tlog_write(TLOG_WARN, _f, ##_a)
#define DBG(_f, _a...) tlog_write(TLOG_DBG, _f, ##_a)
#define ERR(_err, _f, _a...) tlog_error(_err, _f, ##_a)

/*
 * We used a kernel patch to return an fd associated with the AIO context
 * so that we can concurrently poll on synchronous and async descriptors.
 * This is signalled by passing 1 as the io context to io_setup.
 */
#define REQUEST_ASYNC_FD ((io_context_t)1)

static inline void
queue_tiocb(struct tqueue *queue, struct tiocb *tiocb)
{
	struct iocb *iocb = &tiocb->iocb;

	if (queue->queued) {
		struct tiocb *prev = (struct tiocb *)
			queue->iocbs[queue->queued - 1]->data;
		prev->next = tiocb;
	}

	queue->iocbs[queue->queued++] = iocb;
}

static inline int
deferred_tiocbs(struct tqueue *queue)
{
	return (queue->deferred.head != NULL);
}

static inline void
defer_tiocb(struct tqueue *queue, struct tiocb *tiocb)
{
	struct tlist *list = &queue->deferred;

	if (!list->head)
		list->head = list->tail = tiocb;
	else
		list->tail = list->tail->next = tiocb;

	queue->tiocbs_deferred++;
	queue->deferrals++;
}

static inline void
queue_deferred_tiocb(struct tqueue *queue)
{
	struct tlist *list = &queue->deferred;

	if (list->head) {
		struct tiocb *tiocb = list->head;

		list->head = tiocb->next;
		if (!list->head)
			list->tail = NULL;

		queue_tiocb(queue, tiocb);
		queue->tiocbs_deferred--;
	}
}

static inline void
queue_deferred_tiocbs(struct tqueue *queue)
{
	while (!tapdisk_queue_full(queue) && deferred_tiocbs(queue))
		queue_deferred_tiocb(queue);
}

/*
 * td_complete may queue more tiocbs
 */
static void
complete_tiocb(struct tqueue *queue, struct tiocb *tiocb, unsigned long res)
{
	int err;
	struct iocb *iocb = &tiocb->iocb;

	if (res == iocb->u.c.nbytes)
		err = 0;
	else if ((int)res < 0)
		err = (int)res;
	else
		err = -EIO;

	tiocb->cb(tiocb->arg, tiocb, err);
}

static int
cancel_tiocbs(struct tqueue *queue, int err)
{
	int queued;
	struct tiocb *tiocb;

	if (!queue->queued)
		return 0;

	/* 
	 * td_complete may queue more tiocbs, which
	 * will overwrite the contents of queue->iocbs.
	 * use a private linked list to keep track
	 * of the tiocbs we're cancelling. 
	 */
	tiocb  = queue->iocbs[0]->data;
	queued = queue->queued;
	queue->queued = 0;

	for (; tiocb != NULL; tiocb = tiocb->next)
		complete_tiocb(queue, tiocb, err);

	return queued;
}

static int
fail_tiocbs(struct tqueue *queue, int succeeded, int total, int err)
{
	ERR(err, "io_submit error: %d of %d failed",
	    total - succeeded, total);

	/* take any non-submitted, merged iocbs 
	 * off of the queue, split them, and fail them */
	queue->queued = io_expand_iocbs(&queue->opioctx,
					queue->iocbs, succeeded, total);

	return cancel_tiocbs(queue, err);
}

/*
 * rwio
 */

struct rwio {
	struct io_event *aio_events;
};

static void
tapdisk_rwio_destroy(struct tqueue *queue)
{
	struct rwio *rwio = queue->tio_data;

	if (rwio->aio_events) {
		free(rwio->aio_events);
		rwio->aio_events = NULL;
	}
}

static int
tapdisk_rwio_setup(struct tqueue *queue, int size)
{
	struct rwio *rwio = queue->tio_data;
	int err;

	rwio->aio_events = calloc(size, sizeof(struct io_event));
	if (!rwio->aio_events)
		return -errno;

	return 0;
}

static inline ssize_t
tapdisk_rwio_rw(const struct iocb *iocb)
{
	int fd        = iocb->aio_fildes;
	char *buf     = iocb->u.c.buf;
	long long off = iocb->u.c.offset;
	size_t size   = iocb->u.c.nbytes;
	ssize_t (*func)(int, void *, size_t) = 
		(iocb->aio_lio_opcode == IO_CMD_PWRITE ? vwrite : read);

	if (lseek(fd, off, SEEK_SET) == (off_t)-1)
		return -errno;

	if (atomicio(func, fd, buf, size) != size)
		return -errno;

	return size;
}

static int
tapdisk_rwio_submit(struct tqueue *queue)
{
	struct rwio *rwio = queue->tio_data;
	int i, merged, split;
	struct iocb *iocb;
	struct tiocb *tiocb;
	struct io_event *ep;

	if (!queue->queued)
		return 0;

	tapdisk_filter_iocbs(queue->filter, queue->iocbs, queue->queued);
	merged = io_merge(&queue->opioctx, queue->iocbs, queue->queued);

	queue->queued = 0;

	for (i = 0; i < merged; i++) {
		ep      = rwio->aio_events + i;
		iocb    = queue->iocbs[i];
		ep->obj = iocb;
		ep->res = tapdisk_rwio_rw(iocb);
	}

	split = io_split(&queue->opioctx, rwio->aio_events, merged);
	tapdisk_filter_events(queue->filter, rwio->aio_events, split);

	for (i = split, ep = rwio->aio_events; i-- > 0; ep++) {
		iocb  = ep->obj;
		tiocb = iocb->data;
		complete_tiocb(queue, tiocb, ep->res);
	}

	queue_deferred_tiocbs(queue);

	return split;
}

static const struct tio td_tio_rwio = {
	.name        = "rwio",
	.data_size   = 0,
	.tio_setup   = NULL,
	.tio_destroy = NULL,
	.tio_submit  = tapdisk_rwio_submit
};

/*
 * libaio
 */

struct lio {
	io_context_t     aio_ctx;
	struct io_event *aio_events;

	int              event_fd;
	int              event_id;

	int              flags;
};

#define LIO_FLAG_EVENTFD        (1<<0)

static int
tapdisk_lio_check_resfd(void)
{
#if defined(__linux__)
	return tapdisk_linux_version() >= KERNEL_VERSION(2, 6, 22);
#else
	return 1;
#endif
}

static void
tapdisk_lio_destroy_aio(struct tqueue *queue)
{
	struct lio *lio = queue->tio_data;

	if (lio->event_fd >= 0) {
		close(lio->event_fd);
		lio->event_fd = -1;
	}

	if (lio->aio_ctx) {
		io_destroy(lio->aio_ctx);
		lio->aio_ctx = 0;
	}
}

static int
__lio_setup_aio_poll(struct tqueue *queue, int qlen)
{
	struct lio *lio = queue->tio_data;
	int err, fd;

	lio->aio_ctx = REQUEST_ASYNC_FD;

	fd = io_setup(qlen, &lio->aio_ctx);
	if (fd < 0) {
		lio->aio_ctx = 0;
		err = -errno;

		if (err == -EINVAL)
			goto fail_fd;

		goto fail;
	}

	lio->event_fd = fd;

	return 0;

fail_fd:
	DPRINTF("Couldn't get fd for AIO poll support. This is probably "
		"because your kernel does not have the aio-poll patch "
		"applied.\n");
fail:
	return err;
}

static int
__lio_setup_aio_eventfd(struct tqueue *queue, int qlen)
{
	struct lio *lio = queue->tio_data;
	int err;

	err = io_setup(qlen, &lio->aio_ctx);
	if (err < 0) {
		lio->aio_ctx = 0;
		return err;
	}

	lio->event_fd = tapdisk_sys_eventfd(0);
	if (lio->event_fd < 0)
		return  -errno;

	lio->flags |= LIO_FLAG_EVENTFD;

	return 0;
}

static int
tapdisk_lio_setup_aio(struct tqueue *queue, int qlen)
{
	struct lio *lio = queue->tio_data;
	int err;

	lio->aio_ctx  =  0;
	lio->event_fd = -1;

	/*
	 * prefer the mainline eventfd(2) api, if available.
	 * if not, fall back to the poll fd patch.
	 */

	err = !tapdisk_lio_check_resfd();
	if (!err)
		err = __lio_setup_aio_eventfd(queue, qlen);
	if (err)
		err = __lio_setup_aio_poll(queue, qlen);

	if (err == -EAGAIN)
		goto fail_rsv;
fail:
	return err;

fail_rsv:
	DPRINTF("Couldn't setup AIO context. If you are trying to "
		"concurrently use a large number of blktap-based disks, you may "
		"need to increase the system-wide aio request limit. "
		"(e.g. 'echo 1048576 > /proc/sys/fs/aio-max-nr')\n");
	goto fail;
}


static void
tapdisk_lio_destroy(struct tqueue *queue)
{
	struct lio *lio = queue->tio_data;

	if (!lio)
		return;

	if (lio->event_id >= 0) {
		tapdisk_server_unregister_event(lio->event_id);
		lio->event_id = -1;
	}

	tapdisk_lio_destroy_aio(queue);

	if (lio->aio_events) {
		free(lio->aio_events);
		lio->aio_events = NULL;
	}
}

static void
tapdisk_lio_set_eventfd(struct tqueue *queue, int n, struct iocb **iocbs)
{
	struct lio *lio = queue->tio_data;
	int i;

	if (lio->flags & LIO_FLAG_EVENTFD)
		for (i = 0; i < n; ++i)
			__io_set_eventfd(iocbs[i], lio->event_fd);
}

static void
tapdisk_lio_ack_event(struct tqueue *queue)
{
	struct lio *lio = queue->tio_data;
	uint64_t val;

	if (lio->flags & LIO_FLAG_EVENTFD)
		read_exact(lio->event_fd, &val, sizeof(val));
}

static void
tapdisk_lio_event(event_id_t id, char mode, void *private)
{
	struct tqueue *queue = private;
	struct lio *lio;
	int i, ret, split;
	struct iocb *iocb;
	struct tiocb *tiocb;
	struct io_event *ep;

	tapdisk_lio_ack_event(queue);

	lio   = queue->tio_data;
	ret   = io_getevents(lio->aio_ctx, 0,
			     queue->size, lio->aio_events, NULL);
	split = io_split(&queue->opioctx, lio->aio_events, ret);
	tapdisk_filter_events(queue->filter, lio->aio_events, split);

	DBG("events: %d, tiocbs: %d\n", ret, split);

	queue->iocbs_pending  -= ret;
	queue->tiocbs_pending -= split;

	for (i = split, ep = lio->aio_events; i-- > 0; ep++) {
		iocb  = ep->obj;
		tiocb = iocb->data;
		complete_tiocb(queue, tiocb, ep->res);
	}

	queue_deferred_tiocbs(queue);
}

static int
tapdisk_lio_setup(struct tqueue *queue, int qlen)
{
	struct lio *lio = queue->tio_data;
	size_t sz;
	int err;

	lio->event_id = -1;

	err = tapdisk_lio_setup_aio(queue, qlen);
	if (err)
		goto fail;

	lio->event_id =
		tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					      lio->event_fd, 0,
					      tapdisk_lio_event,
					      queue);
	err = lio->event_id;
	if (err < 0)
		goto fail;

	lio->aio_events = calloc(qlen, sizeof(struct io_event));
	if (!lio->aio_events) {
		err = -errno;
		goto fail;
	}

	return 0;

fail:
	tapdisk_lio_destroy(queue);
	return err;
}

static int
tapdisk_lio_submit(struct tqueue *queue)
{
	struct lio *lio = queue->tio_data;
	int merged, submitted, err = 0;

	if (!queue->queued)
		return 0;

	tapdisk_filter_iocbs(queue->filter, queue->iocbs, queue->queued);
	merged    = io_merge(&queue->opioctx, queue->iocbs, queue->queued);
	tapdisk_lio_set_eventfd(queue, merged, queue->iocbs);
	submitted = io_submit(lio->aio_ctx, merged, queue->iocbs);

	DBG("queued: %d, merged: %d, submitted: %d\n",
	    queue->queued, merged, submitted);

	if (submitted < 0) {
		err = submitted;
		submitted = 0;
	} else if (submitted < merged)
		err = -EIO;

	queue->iocbs_pending  += submitted;
	queue->tiocbs_pending += queue->queued;
	queue->queued          = 0;

	if (err)
		queue->tiocbs_pending -= 
			fail_tiocbs(queue, submitted, merged, err);

	return submitted;
}

static const struct tio td_tio_lio = {
	.name        = "lio",
	.data_size   = sizeof(struct lio),
	.tio_setup   = tapdisk_lio_setup,
	.tio_destroy = tapdisk_lio_destroy,
	.tio_submit  = tapdisk_lio_submit,
};

static void
tapdisk_queue_free_io(struct tqueue *queue)
{
	if (queue->tio) {
		if (queue->tio->tio_destroy)
			queue->tio->tio_destroy(queue);
		queue->tio = NULL;
	}

	if (queue->tio_data) {
		free(queue->tio_data);
		queue->tio_data = NULL;
	}
}

static int
tapdisk_queue_init_io(struct tqueue *queue, int drv)
{
	const struct tio *tio;
	int err;

	switch (drv) {
	case TIO_DRV_LIO:
		tio = &td_tio_lio;
		break;
	case TIO_DRV_RWIO:
		tio = &td_tio_rwio;
		break;
	default:
		err = -EINVAL;
		goto fail;
	}

	queue->tio_data = calloc(1, tio->data_size);
	if (!queue->tio_data) {
		PERROR("malloc(%zu)", tio->data_size);
		err = -errno;
		goto fail;
	}

	queue->tio = tio;

	if (tio->tio_setup) {
		err = tio->tio_setup(queue, queue->size);
		if (err)
			goto fail;
	}

	DPRINTF("I/O queue driver: %s\n", tio->name);

	return 0;

fail:
	tapdisk_queue_free_io(queue);
	return err;
}

int
tapdisk_init_queue(struct tqueue *queue, int size,
		   int drv, struct tfilter *filter)
{
	int i, err;

	memset(queue, 0, sizeof(struct tqueue));

	queue->size   = size;
	queue->filter = filter;

	if (!size)
		return 0;

	err = tapdisk_queue_init_io(queue, drv);
	if (err)
		goto fail;

	queue->iocbs = calloc(size, sizeof(struct iocb *));
	if (!queue->iocbs) {
		err = -errno;
		goto fail;
	}

	err = opio_init(&queue->opioctx, size);
	if (err)
		goto fail;

	return 0;

 fail:
	tapdisk_free_queue(queue);
	return err;
}

void
tapdisk_free_queue(struct tqueue *queue)
{
	tapdisk_queue_free_io(queue);

	free(queue->iocbs);
	queue->iocbs = NULL;

	opio_free(&queue->opioctx);
}

void 
tapdisk_debug_queue(struct tqueue *queue)
{
	struct tiocb *tiocb = queue->deferred.head;

	WARN("TAPDISK QUEUE:\n");
	WARN("size: %d, tio: %s, queued: %d, iocbs_pending: %d, "
	     "tiocbs_pending: %d, tiocbs_deferred: %d, deferrals: %"PRIx64"\n",
	     queue->size, queue->tio->name, queue->queued, queue->iocbs_pending,
	     queue->tiocbs_pending, queue->tiocbs_deferred, queue->deferrals);

	if (tiocb) {
		WARN("deferred:\n");
		for (; tiocb != NULL; tiocb = tiocb->next) {
			struct iocb *io = &tiocb->iocb;
			WARN("%s of %lu bytes at %lld\n",
			     (io->aio_lio_opcode == IO_CMD_PWRITE ?
			      "write" : "read"),
			     io->u.c.nbytes, io->u.c.offset);
		}
	}
}

void
tapdisk_prep_tiocb(struct tiocb *tiocb, int fd, int rw, char *buf, size_t size,
		   long long offset, td_queue_callback_t cb, void *arg)
{
	struct iocb *iocb = &tiocb->iocb;

	if (rw)
		io_prep_pwrite(iocb, fd, buf, size, offset);
	else
		io_prep_pread(iocb, fd, buf, size, offset);

	iocb->data  = tiocb;
	tiocb->cb   = cb;
	tiocb->arg  = arg;
	tiocb->next = NULL;
}

void
tapdisk_queue_tiocb(struct tqueue *queue, struct tiocb *tiocb)
{
	if (!tapdisk_queue_full(queue))
		queue_tiocb(queue, tiocb);
	else
		defer_tiocb(queue, tiocb);
}


/*
 * fail_tiocbs may queue more tiocbs
 */
int
tapdisk_submit_tiocbs(struct tqueue *queue)
{
	return queue->tio->tio_submit(queue);
}

int
tapdisk_submit_all_tiocbs(struct tqueue *queue)
{
	int submitted = 0;

	do {
		submitted += tapdisk_submit_tiocbs(queue);
	} while (!tapdisk_queue_empty(queue));

	return submitted;
}

/*
 * cancel_tiocbs may queue more tiocbs
 */
int
tapdisk_cancel_tiocbs(struct tqueue *queue)
{
	return cancel_tiocbs(queue, -EIO);
}

int
tapdisk_cancel_all_tiocbs(struct tqueue *queue)
{
	int cancelled = 0;

	do {
		cancelled += tapdisk_cancel_tiocbs(queue);
	} while (!tapdisk_queue_empty(queue));

	return cancelled;
}
