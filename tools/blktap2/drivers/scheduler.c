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
#include <string.h>
#include <sys/time.h>

#include "scheduler.h"
#include "tapdisk-log.h"

#define DBG(_f, _a...)               tlog_write(TLOG_DBG, _f, ##_a)

#define SCHEDULER_MAX_TIMEOUT        600
#define SCHEDULER_POLL_FD           (SCHEDULER_POLL_READ_FD |	\
				     SCHEDULER_POLL_WRITE_FD |	\
				     SCHEDULER_POLL_EXCEPT_FD)

#define MIN(a, b)                   ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                   ((a) >= (b) ? (a) : (b))

#define scheduler_for_each_event(s, event, tmp)	\
	list_for_each_entry_safe(event, tmp, &(s)->events, next)

typedef struct event {
	char                         mode;
	event_id_t                   id;

	int                          fd;
	int                          timeout;
	int                          deadline;

	event_cb_t                   cb;
	void                        *private;

	struct list_head             next;
} event_t;

static void
scheduler_prepare_events(scheduler_t *s)
{
	int diff;
	struct timeval now;
	event_t *event, *tmp;

	FD_ZERO(&s->read_fds);
	FD_ZERO(&s->write_fds);
	FD_ZERO(&s->except_fds);

	s->max_fd  = 0;
	s->timeout = SCHEDULER_MAX_TIMEOUT;

	gettimeofday(&now, NULL);

	scheduler_for_each_event(s, event, tmp) {
		if (event->mode & SCHEDULER_POLL_READ_FD) {
			FD_SET(event->fd, &s->read_fds);
			s->max_fd = MAX(event->fd, s->max_fd);
		}

		if (event->mode & SCHEDULER_POLL_WRITE_FD) {
			FD_SET(event->fd, &s->write_fds);
			s->max_fd = MAX(event->fd, s->max_fd);
		}

		if (event->mode & SCHEDULER_POLL_EXCEPT_FD) {
			FD_SET(event->fd, &s->except_fds);
			s->max_fd = MAX(event->fd, s->max_fd);
		}

		if (event->mode & SCHEDULER_POLL_TIMEOUT) {
			diff = event->deadline - now.tv_sec;
			if (diff > 0)
				s->timeout = MIN(s->timeout, diff);
			else
				s->timeout = 0;
		}
	}

	s->timeout = MIN(s->timeout, s->max_timeout);
}

static void
scheduler_event_callback(event_t *event, char mode)
{
	if (event->mode & SCHEDULER_POLL_TIMEOUT) {
		struct timeval now;
		gettimeofday(&now, NULL);
		event->deadline = now.tv_sec + event->timeout;
	}

	event->cb(event->id, mode, event->private);
}

static void
scheduler_run_events(scheduler_t *s)
{
	struct timeval now;
	event_t *event, *tmp;

	gettimeofday(&now, NULL);

 again:
	s->restart = 0;

	scheduler_for_each_event(s, event, tmp) {
		if ((event->mode & SCHEDULER_POLL_READ_FD) &&
		    FD_ISSET(event->fd, &s->read_fds)) {
			FD_CLR(event->fd, &s->read_fds);
			scheduler_event_callback(event, SCHEDULER_POLL_READ_FD);
			goto next;
		}

		if ((event->mode & SCHEDULER_POLL_WRITE_FD) &&
		    FD_ISSET(event->fd, &s->write_fds)) {
			FD_CLR(event->fd, &s->write_fds);
			scheduler_event_callback(event, SCHEDULER_POLL_WRITE_FD);
			goto next;
		}

		if ((event->mode & SCHEDULER_POLL_EXCEPT_FD) &&
		    FD_ISSET(event->fd, &s->except_fds)) {
			FD_CLR(event->fd, &s->except_fds);
			scheduler_event_callback(event, SCHEDULER_POLL_EXCEPT_FD);
			goto next;
		}

		if ((event->mode & SCHEDULER_POLL_TIMEOUT) &&
		    (event->deadline <= now.tv_sec))
		    scheduler_event_callback(event, SCHEDULER_POLL_TIMEOUT);

	next:
		if (s->restart)
			goto again;
	}
}

int
scheduler_register_event(scheduler_t *s, char mode, int fd,
			 int timeout, event_cb_t cb, void *private)
{
	event_t *event;
	struct timeval now;

	if (!cb)
		return -EINVAL;

	if (!(mode & SCHEDULER_POLL_TIMEOUT) && !(mode & SCHEDULER_POLL_FD))
		return -EINVAL;

	event = calloc(1, sizeof(event_t));
	if (!event)
		return -ENOMEM;

	gettimeofday(&now, NULL);

	INIT_LIST_HEAD(&event->next);

	event->mode     = mode;
	event->fd       = fd;
	event->timeout  = timeout;
	event->deadline = now.tv_sec + timeout;
	event->cb       = cb;
	event->private  = private;
	event->id       = s->uuid++;

	if (!s->uuid)
		s->uuid++;

	list_add_tail(&event->next, &s->events);

	return event->id;
}

void
scheduler_unregister_event(scheduler_t *s, event_id_t id)
{
	event_t *event, *tmp;

	if (!id)
		return;

	scheduler_for_each_event(s, event, tmp)
		if (event->id == id) {
			list_del(&event->next);
			free(event);
			s->restart = 1;
			break;
		}
}

void
scheduler_set_max_timeout(scheduler_t *s, int timeout)
{
	if (timeout >= 0)
		s->max_timeout = MIN(s->max_timeout, timeout);
}

int
scheduler_wait_for_events(scheduler_t *s)
{
	int ret;
	struct timeval tv;

	scheduler_prepare_events(s);

	tv.tv_sec  = s->timeout;
	tv.tv_usec = 0;

	DBG("timeout: %d, max_timeout: %d\n",
	    s->timeout, s->max_timeout);

	ret = select(s->max_fd + 1, &s->read_fds,
		     &s->write_fds, &s->except_fds, &tv);

	s->restart     = 0;
	s->timeout     = SCHEDULER_MAX_TIMEOUT;
	s->max_timeout = SCHEDULER_MAX_TIMEOUT;

	if (ret < 0)
		return ret;

	scheduler_run_events(s);

	return ret;
}

void
scheduler_initialize(scheduler_t *s)
{
	memset(s, 0, sizeof(scheduler_t));

	s->uuid = 1;

	FD_ZERO(&s->read_fds);
	FD_ZERO(&s->write_fds);
	FD_ZERO(&s->except_fds);

	INIT_LIST_HEAD(&s->events);
}
