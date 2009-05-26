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
#ifndef TAPDISK_FILTER_H
#define TAPDISK_FILTER_H

#include <libaio.h>
#include <inttypes.h>
#include <time.h>

#define TD_INJECT_FAULTS     0x00001  /* simulate random IO failures */
#define TD_CHECK_INTEGRITY   0x00002  /* check data integrity */

#define TD_FAULT_RATE        5

struct dhash {
	uint64_t             hash;
	struct timeval       time;
};

struct fiocb {
	size_t               bytes;
	void                *data;
};

struct tfilter {
	int                  mode;
	uint64_t             secs;
	int                  iocbs;

	struct dhash        *dhash;

	int                  ffree;
	struct fiocb        *fiocbs;
	struct fiocb       **flist;
};

struct tfilter *tapdisk_init_tfilter(int mode, int iocbs, uint64_t secs);
void tapdisk_free_tfilter(struct tfilter *);
void tapdisk_filter_iocbs(struct tfilter *, struct iocb **, int);
void tapdisk_filter_events(struct tfilter *, struct io_event *, int);

#endif
