/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Live Update for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#include <assert.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <xen-tools/xenstore-common.h>

#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_lu.h"

#ifndef NO_LIVE_UPDATE
void lu_get_dump_state(struct lu_dump_state *state)
{
	struct stat statbuf;

	state->size = 0;

	state->filename = talloc_asprintf(NULL, "%s/state_dump",
					  xenstore_daemon_rundir());
	if (!state->filename)
		barf("Allocation failure");

	state->fd = open(state->filename, O_RDONLY);
	if (state->fd < 0)
		return;
	if (fstat(state->fd, &statbuf) != 0)
		goto out_close;
	state->size = statbuf.st_size;

	state->buf = mmap(NULL, state->size, PROT_READ, MAP_PRIVATE,
			  state->fd, 0);
	if (state->buf == MAP_FAILED) {
		state->size = 0;
		goto out_close;
	}

	return;

 out_close:
	close(state->fd);
}

void lu_close_dump_state(struct lu_dump_state *state)
{
	assert(state->filename != NULL);

	munmap(state->buf, state->size);
	close(state->fd);

	unlink(state->filename);
	talloc_free(state->filename);
}

FILE *lu_dump_open(const void *ctx)
{
	char *filename;
	int fd;

	filename = talloc_asprintf(ctx, "%s/state_dump",
				   xenstore_daemon_rundir());
	if (!filename)
		return NULL;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return NULL;

	return fdopen(fd, "w");
}

void lu_dump_close(FILE *fp)
{
	fclose(fp);
}

char *lu_exec(const void *ctx, int argc, char **argv)
{
	argv[0] = lu_status->filename;
	execvp(argv[0], argv);

	return "Error activating new binary.";
}

void lu_destroy_arch(void *data)
{
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
