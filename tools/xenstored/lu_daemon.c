/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Live Update for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#include <syslog.h>
#include <sys/stat.h>

#include "talloc.h"
#include "core.h"
#include "lu.h"

#ifndef NO_LIVE_UPDATE
char *lu_exec(const void *ctx, int argc, char **argv)
{
	argv[0] = lu_status->filename;
	execvp(argv[0], argv);

	return "Error activating new binary.";
}

static const char *lu_binary(const void *ctx, struct connection *conn,
			     const char *filename)
{
	const char *ret;
	struct stat statbuf;

	syslog(LOG_INFO, "live-update: binary %s\n", filename);

	if (stat(filename, &statbuf))
		return "File not accessible.";
	if (!(statbuf.st_mode & (S_IXOTH | S_IXGRP | S_IXUSR)))
		return "File not executable.";

	ret = lu_begin(conn);
	if (ret)
		return ret;

	lu_status->filename = talloc_strdup(lu_status, filename);
	if (!lu_status->filename)
		return "Allocation failure.";

	errno = 0;
	return NULL;
}

const char *lu_arch(const void *ctx, struct connection *conn, const char **vec,
		    int num)
{
	if (num == 2 && !strcmp(vec[0], "-f"))
		return lu_binary(ctx, conn, vec[1]);

	errno = EINVAL;
	return NULL;
}
#endif
