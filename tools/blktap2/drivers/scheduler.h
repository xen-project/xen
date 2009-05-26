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
#ifndef _SCHEDULER_H_
#define _SCHEDULER_H_

#include <sys/select.h>

#include "list.h"

#define SCHEDULER_POLL_READ_FD       0x1
#define SCHEDULER_POLL_WRITE_FD      0x2
#define SCHEDULER_POLL_EXCEPT_FD     0x4
#define SCHEDULER_POLL_TIMEOUT       0x8

typedef int                          event_id_t;
typedef void (*event_cb_t)          (event_id_t id, char mode, void *private);

typedef struct scheduler {
	fd_set                       read_fds;
	fd_set                       write_fds;
	fd_set                       except_fds;

	struct list_head             events;

	int                          uuid;
	int                          max_fd;
	int                          timeout;
	int                          restart;
	int                          max_timeout;
} scheduler_t;

void scheduler_initialize(scheduler_t *);
event_id_t scheduler_register_event(scheduler_t *, char mode,
				    int fd, int timeout,
				    event_cb_t cb, void *private);
void scheduler_unregister_event(scheduler_t *,  event_id_t);
void scheduler_set_max_timeout(scheduler_t *, int);
int scheduler_wait_for_events(scheduler_t *);

#endif
