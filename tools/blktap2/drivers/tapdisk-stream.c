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
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "list.h"
#include "scheduler.h"
#include "tapdisk-vbd.h"
#include "tapdisk-server.h"
#include "tapdisk-disktype.h"
#include "tapdisk-utils.h"

#define POLL_READ                        0
#define POLL_WRITE                       1

#define MIN(a, b)                        ((a) < (b) ? (a) : (b))

struct tapdisk_stream_poll {
	int                              pipe[2];
	int                              set;
};

struct tapdisk_stream_request {
	uint64_t                         sec;
	uint32_t                         secs;
	uint64_t                         seqno;
	blkif_request_t                  blkif_req;
	struct list_head                 next;
};

struct tapdisk_stream {
	td_vbd_t                        *vbd;

	unsigned int                     id;
	int                              in_fd;
	int                              out_fd;

	int                              err;

	uint64_t                         cur;
	uint64_t                         start;
	uint64_t                         end;

	uint64_t                         started;
	uint64_t                         completed;

	struct tapdisk_stream_poll       poll;
	event_id_t                       enqueue_event_id;

	struct list_head                 free_list;
	struct list_head                 pending_list;
	struct list_head                 completed_list;

	struct tapdisk_stream_request    requests[MAX_REQUESTS];
};

static unsigned int tapdisk_stream_count;

static void tapdisk_stream_close_image(struct tapdisk_stream *);

static void
usage(const char *app, int err)
{
	printf("usage: %s <-n type:/path/to/image> "
	       "[-c sector count] [-s skip sectors]\n", app);
	exit(err);
}

static inline void
tapdisk_stream_poll_initialize(struct tapdisk_stream_poll *p)
{
	p->set = 0;
	p->pipe[POLL_READ] = p->pipe[POLL_WRITE] = -1;
}

static int
tapdisk_stream_poll_open(struct tapdisk_stream_poll *p)
{
	int err;

	tapdisk_stream_poll_initialize(p);

	err = pipe(p->pipe);
	if (err)
		return -errno;

	err = fcntl(p->pipe[POLL_READ], F_SETFL, O_NONBLOCK);
	if (err)
		goto out;

	err = fcntl(p->pipe[POLL_WRITE], F_SETFL, O_NONBLOCK);
	if (err)
		goto out;

	return 0;

out:
	close(p->pipe[POLL_READ]);
	close(p->pipe[POLL_WRITE]);
	tapdisk_stream_poll_initialize(p);
	return -errno;
}

static void
tapdisk_stream_poll_close(struct tapdisk_stream_poll *p)
{
	if (p->pipe[POLL_READ] != -1)
		close(p->pipe[POLL_READ]);
	if (p->pipe[POLL_WRITE] != -1)
		close(p->pipe[POLL_WRITE]);
	tapdisk_stream_poll_initialize(p);
}

static inline void
tapdisk_stream_poll_clear(struct tapdisk_stream_poll *p)
{
	int dummy;

	read_exact(p->pipe[POLL_READ], &dummy, sizeof(dummy));
	p->set = 0;
}

static inline void
tapdisk_stream_poll_set(struct tapdisk_stream_poll *p)
{
	int dummy = 0;

	if (!p->set) {
		write_exact(p->pipe[POLL_WRITE], &dummy, sizeof(dummy));
		p->set = 1;
	}
}

static inline int
tapdisk_stream_stop(struct tapdisk_stream *s)
{
	return (list_empty(&s->pending_list) && (s->cur == s->end || s->err));
}

static inline void
tapdisk_stream_initialize_request(struct tapdisk_stream_request *req)
{
	memset(req, 0, sizeof(*req));
	INIT_LIST_HEAD(&req->next);
}

static inline int
tapdisk_stream_request_idx(struct tapdisk_stream *s,
			   struct tapdisk_stream_request *req)
{
	return (req - s->requests);
}

static inline struct tapdisk_stream_request *
tapdisk_stream_get_request(struct tapdisk_stream *s)
{
	struct tapdisk_stream_request *req;

	if (list_empty(&s->free_list))
		return NULL;

	req = list_entry(s->free_list.next,
			 struct tapdisk_stream_request, next);

	list_del_init(&req->next);
	tapdisk_stream_initialize_request(req);

	return req;
}

static void
tapdisk_stream_print_request(struct tapdisk_stream *s,
			     struct tapdisk_stream_request *sreq)
{
	unsigned long idx = (unsigned long)tapdisk_stream_request_idx(s, sreq);
	char *buf = (char *)MMAP_VADDR(s->vbd->ring.vstart, idx, 0);
	write_exact(s->out_fd, buf, sreq->secs << SECTOR_SHIFT);
}

static void
tapdisk_stream_write_data(struct tapdisk_stream *s)
{
	struct tapdisk_stream_request *sreq, *tmp;

	list_for_each_entry_safe(sreq, tmp, &s->completed_list, next) {
		if (sreq->seqno != s->completed)
			break;

		s->completed++;
		tapdisk_stream_print_request(s, sreq);

		list_del_init(&sreq->next);
		list_add_tail(&sreq->next, &s->free_list);
	}
}

static inline void
tapdisk_stream_queue_completed(struct tapdisk_stream *s,
			       struct tapdisk_stream_request *sreq)
{
	struct tapdisk_stream_request *itr;

	list_for_each_entry(itr, &s->completed_list, next)
		if (sreq->seqno < itr->seqno) {
			list_add_tail(&sreq->next, &itr->next);
			return;
		}

	list_add_tail(&sreq->next, &s->completed_list);
}

static void
tapdisk_stream_dequeue(void *arg, blkif_response_t *rsp)
{
	struct tapdisk_stream *s = (struct tapdisk_stream *)arg;
	struct tapdisk_stream_request *sreq = s->requests + rsp->id;

	list_del_init(&sreq->next);

	if (rsp->status == BLKIF_RSP_OKAY)
		tapdisk_stream_queue_completed(s, sreq);
	else {
		s->err = EIO;
		list_add_tail(&sreq->next, &s->free_list);
		fprintf(stderr, "error reading sector 0x%"PRIu64"\n", sreq->sec);
	}

	tapdisk_stream_write_data(s);
	tapdisk_stream_poll_set(&s->poll);
}

static void
tapdisk_stream_enqueue(event_id_t id, char mode, void *arg)
{
	td_vbd_t *vbd;
	int i, idx, psize;
	struct tapdisk_stream *s = (struct tapdisk_stream *)arg;

	vbd = s->vbd;
	tapdisk_stream_poll_clear(&s->poll);

	if (tapdisk_stream_stop(s)) {
		tapdisk_stream_close_image(s);
		return;
	}

	psize = getpagesize();

	while (s->cur < s->end && !s->err) {
		blkif_request_t *breq;
		td_vbd_request_t *vreq;
		struct tapdisk_stream_request *sreq;

		sreq = tapdisk_stream_get_request(s);
		if (!sreq)
			break;

		idx                 = tapdisk_stream_request_idx(s, sreq);

		sreq->sec           = s->cur;
		sreq->secs          = 0;
		sreq->seqno         = s->started++;

		breq                = &sreq->blkif_req;
		breq->id            = idx;
		breq->nr_segments   = 0;
		breq->sector_number = sreq->sec;
		breq->operation     = BLKIF_OP_READ;

		for (i = 0; i < BLKIF_MAX_SEGMENTS_PER_REQUEST; i++) {
			uint32_t secs = MIN(s->end - s->cur, psize >> SECTOR_SHIFT);
			struct blkif_request_segment *seg = breq->seg + i;

			if (!secs)
				break;

			sreq->secs += secs;
			s->cur     += secs;

			seg->first_sect = 0;
			seg->last_sect  = secs - 1;
			breq->nr_segments++;
		}

		vreq = vbd->request_list + idx;

		assert(list_empty(&vreq->next));
		assert(vreq->secs_pending == 0);

		memcpy(&vreq->req, breq, sizeof(*breq));
		vbd->received++;
		vreq->vbd = vbd;

		tapdisk_vbd_move_request(vreq, &vbd->new_requests);
		list_add_tail(&sreq->next, &s->pending_list);
	}

	tapdisk_vbd_issue_requests(vbd);
}

static int
tapdisk_stream_open_image(struct tapdisk_stream *s, const char *path, int type)
{
	int err;

	s->id = tapdisk_stream_count++;

	err = tapdisk_server_initialize();
	if (err)
		goto out;

	err = tapdisk_vbd_initialize(s->id);
	if (err)
		goto out;

	s->vbd = tapdisk_server_get_vbd(s->id);
	if (!s->vbd) {
		err = ENODEV;
		goto out;
	}

	tapdisk_vbd_set_callback(s->vbd, tapdisk_stream_dequeue, s);

	err = tapdisk_vbd_open_vdi(s->vbd, path, type,
				   TAPDISK_STORAGE_TYPE_DEFAULT,
				   TD_OPEN_RDONLY);
	if (err)
		goto out;

	s->vbd->reopened = 1;
	err = 0;

out:
	if (err)
		fprintf(stderr, "failed to open %s: %d\n", path, err);
	return err;
}

static void
tapdisk_stream_close_image(struct tapdisk_stream *s)
{
	td_vbd_t *vbd;

	vbd = tapdisk_server_get_vbd(s->id);
	if (vbd) {
		tapdisk_vbd_close_vdi(vbd);
		tapdisk_server_remove_vbd(vbd);
		free((void *)vbd->ring.vstart);
		free(vbd->name);
		free(vbd);
		s->vbd = NULL;
	}
}

static int
tapdisk_stream_set_position(struct tapdisk_stream *s,
			    uint64_t count, uint64_t skip)
{
	int err;
	image_t image;

	err = tapdisk_vbd_get_image_info(s->vbd, &image);
	if (err) {
		fprintf(stderr, "failed getting image size: %d\n", err);
		return err;
	}

	if (count == (uint64_t)-1)
		count = image.size - skip;

	if (count + skip > image.size) {
		fprintf(stderr, "0x%"PRIx64" past end of image 0x%"PRIx64"\n",
			(uint64_t) (count + skip), (uint64_t) image.size);
		return -EINVAL;
	}

	s->start = skip;
	s->cur   = s->start;
	s->end   = s->start + count;

	return 0;
}

static int
tapdisk_stream_initialize_requests(struct tapdisk_stream *s)
{
	size_t size;
	td_ring_t *ring;
	int err, i, psize;

	ring  = &s->vbd->ring;
	psize = getpagesize();
	size  = psize * BLKTAP_MMAP_REGION_SIZE;

	/* sneaky -- set up ring->vstart so tapdisk_vbd will use our buffers */
	err = posix_memalign((void **)&ring->vstart, psize, size);
	if (err) {
		fprintf(stderr, "failed to allocate buffers: %d\n", err);
		ring->vstart = 0;
		return err;
	}

	for (i = 0; i < MAX_REQUESTS; i++) {
		struct tapdisk_stream_request *req = s->requests + i;
		tapdisk_stream_initialize_request(req);
		list_add_tail(&req->next, &s->free_list);
	}

	return 0;
}

static int
tapdisk_stream_register_enqueue_event(struct tapdisk_stream *s)
{
	int err;
	struct tapdisk_stream_poll *p = &s->poll;

	err = tapdisk_stream_poll_open(p);
	if (err)
		goto out;

	err = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					    p->pipe[POLL_READ], 0,
					    tapdisk_stream_enqueue, s);
	if (err < 0)
		goto out;

	s->enqueue_event_id = err;
	err = 0;

out:
	if (err)
		fprintf(stderr, "failed to register event: %d\n", err);
	return err;
}

static void
tapdisk_stream_unregister_enqueue_event(struct tapdisk_stream *s)
{
	if (s->enqueue_event_id) {
		tapdisk_server_unregister_event(s->enqueue_event_id);
		s->enqueue_event_id = 0;
	}
	tapdisk_stream_poll_close(&s->poll);
}

static inline void
tapdisk_stream_initialize(struct tapdisk_stream *s)
{
	memset(s, 0, sizeof(*s));
	s->in_fd = s->out_fd = -1;
	INIT_LIST_HEAD(&s->free_list);
	INIT_LIST_HEAD(&s->pending_list);
	INIT_LIST_HEAD(&s->completed_list);
}

static int
tapdisk_stream_open_fds(struct tapdisk_stream *s)
{
	s->out_fd = dup(STDOUT_FILENO);
	if (s->out_fd == -1) {
		fprintf(stderr, "failed to open output: %d\n", errno);
		return errno;
	}

	return 0;
}

static int
tapdisk_stream_open(struct tapdisk_stream *s, const char *path,
		    int type, uint64_t count, uint64_t skip)
{
	int err;

	tapdisk_stream_initialize(s);

	err = tapdisk_stream_open_fds(s);
	if (err)
		return err;

	err = tapdisk_stream_open_image(s, path, type);
	if (err)
		return err;

	err = tapdisk_stream_set_position(s, count, skip);
	if (err)
		return err;

	err = tapdisk_stream_initialize_requests(s);
	if (err)
		return err;

	err = tapdisk_stream_register_enqueue_event(s);
	if (err)
		return err;

	return 0;
}

static void
tapdisk_stream_release(struct tapdisk_stream *s)
{
	close(s->out_fd);
	tapdisk_stream_close_image(s);
	tapdisk_stream_unregister_enqueue_event(s);
}

static int
tapdisk_stream_run(struct tapdisk_stream *s)
{
	tapdisk_stream_enqueue(s->enqueue_event_id, SCHEDULER_POLL_READ_FD, s);
	tapdisk_server_run();
	return s->err;
}

int
main(int argc, char *argv[])
{
	int c, err, type;
	const char *params;
	const disk_info_t *info;
	const char *path;
	uint64_t count, skip;
	struct tapdisk_stream stream;

	err    = 0;
	skip   = 0;
	count  = (uint64_t)-1;
	params = NULL;

	while ((c = getopt(argc, argv, "n:c:s:h")) != -1) {
		switch (c) {
		case 'n':
			params = optarg;
			break;
		case 'c':
			count = strtoull(optarg, NULL, 10);
			break;
		case 's':
			skip = strtoull(optarg, NULL, 10);
			break;
		default:
			err = EINVAL;
		case 'h':
			usage(argv[0], err);
		}
	}

	if (!params)
		usage(argv[0], EINVAL);

	type = tapdisk_disktype_parse_params(params, &path);
	if (type < 0) {
		err = type;
		fprintf(stderr, "invalid argument %s: %d\n", params, err);
		return err;
	}

	tapdisk_start_logging("tapdisk-stream");

	err = tapdisk_stream_open(&stream, path, type, count, skip);
	if (err)
		goto out;

	err = tapdisk_stream_run(&stream);
	if (err)
		goto out;

	err = 0;

out:
	tapdisk_stream_release(&stream);
	tapdisk_stop_logging();
	return err;
}
