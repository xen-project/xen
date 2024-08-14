/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Live Update for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#include <stdlib.h>
#include <syslog.h>

#include "talloc.h"
#include "lu.h"

#ifndef NO_LIVE_UPDATE
char *lu_exec(const void *ctx, int argc, char **argv)
{
	return "NYI";
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
