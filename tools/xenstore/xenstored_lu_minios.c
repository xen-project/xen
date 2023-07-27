/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Live Update for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include <xen-tools/common-macros.h>

#include "talloc.h"
#include "xenstored_lu.h"

/* Mini-OS only knows about MAP_ANON. */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef NO_LIVE_UPDATE
void lu_get_dump_state(struct lu_dump_state *state)
{
}

void lu_close_dump_state(struct lu_dump_state *state)
{
}

FILE *lu_dump_open(const void *ctx)
{
	lu_status->dump_size = ROUNDUP(talloc_total_size(NULL) * 2,
				       XC_PAGE_SHIFT);
	lu_status->dump_state = mmap(NULL, lu_status->dump_size,
				     PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (lu_status->dump_state == MAP_FAILED)
		return NULL;

	return fmemopen(lu_status->dump_state, lu_status->dump_size, "w");
}

void lu_dump_close(FILE *fp)
{
	size_t size;

	size = ftell(fp);
	size = ROUNDUP(size, XC_PAGE_SHIFT);
	munmap(lu_status->dump_state + size, lu_status->dump_size - size);
	lu_status->dump_size = size;

	fclose(fp);
}

char *lu_exec(const void *ctx, int argc, char **argv)
{
	return "NYI";
}

void lu_destroy_arch(void *data)
{
	if (lu_status->dump_state)
		munmap(lu_status->dump_state, lu_status->dump_size);
}

static const char *lu_binary_alloc(const void *ctx, struct connection *conn,
				   unsigned long size)
{
	const char *ret;

	syslog(LOG_INFO, "live-update: binary size %lu\n", size);

	ret = lu_begin(conn);
	if (ret)
		return ret;

	lu_status->kernel = talloc_size(lu_status, size);
	if (!lu_status->kernel)
		return "Allocation failure.";

	lu_status->kernel_size = size;
	lu_status->kernel_off = 0;

	errno = 0;
	return NULL;
}

static const char *lu_binary_save(const void *ctx, struct connection *conn,
				  unsigned int size, const char *data)
{
	if (!lu_status || lu_status->conn != conn)
		return "Not in live-update session.";

	if (lu_status->kernel_off + size > lu_status->kernel_size)
		return "Too much kernel data.";

	memcpy(lu_status->kernel + lu_status->kernel_off, data, size);
	lu_status->kernel_off += size;

	errno = 0;
	return NULL;
}

const char *lu_arch(const void *ctx, struct connection *conn, const char **vec,
		    int num)
{
	if (num == 2 && !strcmp(vec[0], "-b"))
		return lu_binary_alloc(ctx, conn, atol(vec[1]));
	if (num > 2 && !strcmp(vec[0], "-d"))
		return lu_binary_save(ctx, conn, atoi(vec[1]), vec[2]);

	errno = EINVAL;
	return NULL;
}
#endif
