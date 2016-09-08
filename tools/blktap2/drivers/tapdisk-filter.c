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

#include <stdlib.h>
#include <unistd.h>
#include <libaio.h>
#include <syslog.h>
#include <sys/time.h>

#include "tapdisk-log.h"
#include "tapdisk-filter.h"

#define RSEED      7
#define PRE_CHECK  0
#define POST_CHECK 1

#define WRITE_INTEGRITY   "buffer integrity failure after write"
#define READ_INTEGRITY    "disk integrity failure after read"

#define DBG(f, a...) tlog_write(TLOG_WARN, f, ##a)

/*
 * simulate IO errors by knocking request size to zero before
 * submitting and restoring original size before returning
 */
static inline void
inject_fault(struct tfilter *filter, struct iocb *io)
{
	struct fiocb *fio;

	if (!filter->ffree)
		return;

	fio = filter->flist[--filter->ffree];

	fio->bytes     = io->u.c.nbytes;
	fio->data      = io->data;
	io->u.c.nbytes = 0;
	io->data       = fio;
}

static inline int
fault_injected(struct tfilter *filter, struct iocb *io)
{
	unsigned long iop   = (unsigned long)io->data;
	unsigned long start = (unsigned long)filter->fiocbs;
	unsigned long end   = start + (filter->iocbs * sizeof(struct fiocb));

	return (iop >= start && iop < end);
}

static inline void
recover_fault(struct tfilter *filter, struct iocb *io)
{
	struct fiocb *fio = (struct fiocb *)io->data;

	io->u.c.nbytes = fio->bytes;
	io->data       = fio->data;

	memset(fio, 0, sizeof(struct fiocb));
	filter->flist[filter->ffree++] = fio;
}

static inline uint64_t
chksum(char *buf)
{
	int i, num   = 512 >> 3;
	uint64_t *p  = (uint64_t *)buf;
	uint64_t sum = 0;

	for (i = 0; i < num; i++)
		sum += p[i];

	return sum;
}

static inline void
check_hash(struct tfilter *filter, uint64_t sec, char *buf, char *type)
{
	uint64_t sum;
	struct dhash *hash;

	hash = filter->dhash + sec;
	if (!hash->time.tv_sec)
		return;

	sum = chksum(buf);
	if (hash->hash != chksum(buf)) {
		struct timeval now;
		gettimeofday(&now, NULL);
		DBG("%s: hash table: 0x%020" PRIx64 " at %012lu.%06llu, "
		    "from disk: 0x%020" PRIx64 " at %012lu.%06llu\n",
		    type, hash->hash, hash->time.tv_sec,
		    (unsigned long long)hash->time.tv_usec, sum,
		    now.tv_sec, (unsigned long long)now.tv_usec);
	}
}

static inline void
insert_hash(struct tfilter *filter, uint64_t sec, char *buf)
{
	struct dhash *hash;

	hash = filter->dhash + sec;
	hash->hash = chksum(buf);
	gettimeofday(&hash->time, NULL);
}

static void
check_sector(struct tfilter *filter, int type, int rw, uint64_t sec, char *buf)
{
	struct dhash *hash;

	if (sec >= filter->secs)
		return;

	hash = filter->dhash + sec;

	if (rw) {
		if (type == PRE_CHECK)
			insert_hash(filter, sec, buf);
		else
			check_hash(filter, sec, buf, WRITE_INTEGRITY);
	} else if (type == POST_CHECK) {
		check_hash(filter, sec, buf, READ_INTEGRITY);
		insert_hash(filter, sec, buf);
	}
}

static void
check_data(struct tfilter *filter, int type, struct iocb *io)
{
	int rw;
	uint64_t i, sec;

	rw = (io->aio_lio_opcode == IO_CMD_PWRITE);

	for (i = 0; i < io->u.c.nbytes; i += 512) {
		char *buf    = io->u.c.buf + i;
		uint64_t sec = (io->u.c.offset + i) >> 9;
		check_sector(filter, type, rw, sec, buf);
	}
}

struct tfilter *
tapdisk_init_tfilter(int mode, int iocbs, uint64_t secs)
{
	int i;
	struct tfilter *filter = NULL;

	if (!mode)
		return NULL;

	filter = calloc(1, sizeof(struct tfilter));
	if (!filter)
		goto fail;

	filter->mode  = mode;
	filter->secs  = secs;
	filter->iocbs = iocbs;

	if (filter->mode & TD_INJECT_FAULTS) {
		filter->fiocbs = calloc(iocbs, sizeof(struct fiocb));
		filter->flist  = calloc(iocbs, sizeof(struct fiocb *));
		if (!filter->fiocbs || !filter->flist)
			filter->mode &= ~TD_INJECT_FAULTS;
		else {
			srand(RSEED);
			filter->ffree = iocbs;
			for (i = 0; i < iocbs; i++)
				filter->flist[i] = filter->fiocbs + i;
		}
	}

	if (filter->mode & TD_CHECK_INTEGRITY) {
		filter->dhash = calloc(secs, sizeof(struct dhash));
		if (!filter->dhash)
			filter->mode &= ~TD_CHECK_INTEGRITY;
	}

	syslog(LOG_WARNING, "WARNING: "
	       "FILTERING IN MODE 0x%04x\n", filter->mode);

	return filter;

 fail:
	tapdisk_free_tfilter(filter);
	return NULL;
}

void
tapdisk_free_tfilter(struct tfilter *filter)
{
	if (!filter)
		return;

	free(filter->dhash);
	free(filter->flist);
	free(filter->fiocbs);
	free(filter);
}

void
tapdisk_filter_iocbs(struct tfilter *filter, struct iocb **iocbs, int num)
{
	int i;

	if (!filter)
		return;

	for (i = 0; i < num; i++) {
		struct iocb *io = iocbs[i];

		if (filter->mode & TD_INJECT_FAULTS) {
			if ((random() % 100) <= TD_FAULT_RATE) {
				inject_fault(filter, io);
				continue;
			}
		}

		if (filter->mode & TD_CHECK_INTEGRITY)
			check_data(filter, PRE_CHECK, io);
	}
}

void
tapdisk_filter_events(struct tfilter *filter, struct io_event *events, int num)
{
	int i;

	if (!filter)
		return;

	for (i = 0; i < num; i++) {
		struct iocb *io = events[i].obj;

		if (filter->mode & TD_INJECT_FAULTS) {
			if (fault_injected(filter, io)) {
				recover_fault(filter, io);
				continue;
			}
		}

		if (filter->mode & TD_CHECK_INTEGRITY)
			check_data(filter, POST_CHECK, io);
	}
}
