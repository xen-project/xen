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
#ifndef _TAPDISK_RING_H_
#define _TAPDISK_RING_H_

#include <inttypes.h>

#include <xenctrl.h>
#include <xen/io/ring.h>

typedef struct td_uring             td_uring_t;
typedef struct td_uring_header      td_uring_header_t;
typedef struct td_uring_request     td_uring_request_t;
typedef struct td_uring_response    td_uring_response_t;

struct td_uring {
	int                         ctlfd;

	char                       *shmem_path;
	char                       *ctlfd_path;

	void                       *shmem;
	void                       *ring_area;
	void                       *data_area;
};

struct td_uring_header {
	char                        cookie[8];
	uint32_t                    version;
	uint32_t                    shmem_size;
	uint32_t                    ring_size;
	uint32_t                    data_size;
	char                        reserved[4064];
};

struct td_uring_request {
	uint8_t                     op;
	uint64_t                    id;
	uint64_t                    sec;
	uint32_t                    secs;
	uint32_t                    offset;
};

struct td_uring_response {
	uint8_t                     op;
	uint64_t                    id;
	uint8_t                     status;
};

DEFINE_RING_TYPES(td_uring, td_uring_request_t, td_uring_response_t);

int tapdisk_uring_create(td_uring_t *, const char *location,
			uint32_t ring_size, uint32_t data_size);
int tapdisk_uring_destroy(td_uring_t *);

int tapdisk_uring_connect(td_uring_t *, const char *location);
int tapdisk_uring_disconnect(td_uring_t *);

int tapdisk_uring_poll(td_uring_t *);
int tapdisk_uring_kick(td_uring_t *);

#endif
