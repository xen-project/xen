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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/time.h>

#include "tapdisk-log.h"
#include "tapdisk-utils.h"

#define MAX_ENTRY_LEN      512
#define MAX_ERROR_MESSAGES 16

struct error {
	int            cnt;
	int            err;
	char          *func;
	char           msg[MAX_ENTRY_LEN];
};

struct ehandle {
	int            cnt;
	int            dropped;
	struct error   errors[MAX_ERROR_MESSAGES];
};

struct tlog {
	char          *p;
	int            size;
	uint64_t       cnt;
	char          *buf;
	int            level;
	char          *file;
	int            append;
};

static struct ehandle tapdisk_err;
static struct tlog tapdisk_log;

void
open_tlog(char *file, size_t bytes, int level, int append)
{
	tapdisk_log.size = ((bytes + 511) & (~511));

	if (asprintf(&tapdisk_log.file, "%s.%d", file, getpid()) == -1)
		return;

	if (posix_memalign((void **)&tapdisk_log.buf, 512, tapdisk_log.size)) {
		free(tapdisk_log.file);
		tapdisk_log.buf = NULL;
		return;
	}

	memset(tapdisk_log.buf, 0, tapdisk_log.size);

	tapdisk_log.p      = tapdisk_log.buf;
	tapdisk_log.level  = level;
	tapdisk_log.append = append;
}

void
close_tlog(void)
{
	if (!tapdisk_log.buf)
		return;

	if (tapdisk_log.append)
		tlog_flush();

	free(tapdisk_log.buf);
	free(tapdisk_log.file);

	memset(&tapdisk_log, 0, sizeof(struct tlog));
}

void
__tlog_write(int level, const char *func, const char *fmt, ...)
{
	char *buf;
	va_list ap;
	struct timeval t;
	int ret, len, avail;

	if (!tapdisk_log.buf)
		return;

	if (level > tapdisk_log.level)
		return;

	avail = tapdisk_log.size - (tapdisk_log.p - tapdisk_log.buf);
	if (avail < MAX_ENTRY_LEN) {
		if (tapdisk_log.append)
			tlog_flush();
		tapdisk_log.p = tapdisk_log.buf;
	}

	buf = tapdisk_log.p;
	gettimeofday(&t, NULL);
	len = snprintf(buf, MAX_ENTRY_LEN - 1, "%08"PRIu64":%010ld.%06lld:"
		       "%s ", tapdisk_log.cnt,
			t.tv_sec, (unsigned long long)t.tv_usec, func);

	va_start(ap, fmt);
	ret = vsnprintf(buf + len, MAX_ENTRY_LEN - (len + 1), fmt, ap);
	va_end(ap);

	len = (ret < MAX_ENTRY_LEN - (len + 1) ?
	       len + ret : MAX_ENTRY_LEN - 1);
	buf[len] = '\0';

	tapdisk_log.cnt++;
	tapdisk_log.p += len;
}

void
__tlog_error(int err, const char *func, const char *fmt, ...)
{
	va_list ap;
	int i, len, ret;
	struct error *e;
	struct timeval t;

	err = (err > 0 ? err : -err);

	for (i = 0; i < tapdisk_err.cnt; i++) {
		e = &tapdisk_err.errors[i];
		if (e->err == err && e->func == func) {
			e->cnt++;
			return;
		}
	}

	if (tapdisk_err.cnt >= MAX_ERROR_MESSAGES) {
		tapdisk_err.dropped++;
		return;
	}

	gettimeofday(&t, NULL);
	e = &tapdisk_err.errors[tapdisk_err.cnt];

	len = snprintf(e->msg, MAX_ENTRY_LEN - 1, "%010ld.%06lld:%s ",
		       t.tv_sec, (unsigned long long)t.tv_usec, func);

	va_start(ap, fmt);
	ret = vsnprintf(e->msg + len, MAX_ENTRY_LEN - (len + 1), fmt, ap);
	va_end(ap);

	len = (ret < MAX_ENTRY_LEN - (len + 1) ?
	       len + ret : MAX_ENTRY_LEN - 1);
	e->msg[len] = '\0';

	e->cnt++;
	e->err  = err;
	e->func = (char *)func;
	tapdisk_err.cnt++;
}

void
tlog_print_errors(void)
{
	int i;
	struct error *e;

	for (i = 0; i < tapdisk_err.cnt; i++) {
		e = &tapdisk_err.errors[i];
		syslog(LOG_INFO, "TAPDISK ERROR: errno %d at %s (cnt = %d): "
		       "%s\n", e->err, e->func, e->cnt, e->msg);
	}

	if (tapdisk_err.dropped)
		syslog(LOG_INFO, "TAPDISK ERROR: %d other error messages "
		       "dropped\n", tapdisk_err.dropped);
}

void
tlog_flush_errors(void)
{
	int i;
	struct error *e;

	for (i = 0; i < tapdisk_err.cnt; i++) {
		e = &tapdisk_err.errors[i];
		tlog_write(TLOG_WARN, "TAPDISK ERROR: errno %d at %s "
			   "(cnt = %d): %s\n", e->err, e->func, e->cnt,
			   e->msg);
	}

	if (tapdisk_err.dropped)
		tlog_write(TLOG_WARN, "TAPDISK ERROR: %d other error messages "
		       "dropped\n", tapdisk_err.dropped);
}

void
tlog_flush(void)
{
	int fd, flags;
	size_t size, wsize;

	if (!tapdisk_log.buf)
		return;

	flags = O_CREAT | O_WRONLY | O_DIRECT | O_NONBLOCK;
	if (!tapdisk_log.append)
		flags |= O_TRUNC;

	fd = open(tapdisk_log.file, flags, 0644);
	if (fd == -1)
		return;

	if (tapdisk_log.append)
		if (lseek(fd, 0, SEEK_END) == (off_t)-1)
			goto out;

	tlog_flush_errors();

	size  = tapdisk_log.p - tapdisk_log.buf;
	wsize = ((size + 511) & (~511));

	memset(tapdisk_log.buf + size, '\n', wsize - size);
	write_exact(fd, tapdisk_log.buf, wsize);

	tapdisk_log.p = tapdisk_log.buf;

out:
	close(fd);
}
