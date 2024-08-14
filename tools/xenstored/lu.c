/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Live Update interfaces for Xen Store Daemon.
 * Copyright (C) 2022 Juergen Gross, SUSE LLC
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "talloc.h"
#include "core.h"
#include "domain.h"
#include "lu.h"
#include "watch.h"

#ifndef NO_LIVE_UPDATE

struct lu_dump_state {
	void *buf;
	unsigned int size;
	int fd;
	char *filename;
};

struct live_update *lu_status;

static int lu_destroy(void *data)
{
	lu_status = NULL;

	return 0;
}

const char *lu_begin(struct connection *conn)
{
	if (lu_status)
		return "live-update session already active.";

	lu_status = talloc_zero(conn, struct live_update);
	if (!lu_status)
		return "Allocation failure.";
	lu_status->conn = conn;
	talloc_set_destructor(lu_status, lu_destroy);

	return NULL;
}

struct connection *lu_get_connection(void)
{
	return lu_status ? lu_status->conn : NULL;
}

unsigned int lu_write_response(FILE *fp)
{
	struct xsd_sockmsg msg;

	assert(lu_status);

	msg = lu_status->in->hdr.msg;

	msg.len = sizeof("OK");
	if (fp && fwrite(&msg, sizeof(msg), 1, fp) != 1)
		return 0;
	if (fp && fwrite("OK", msg.len, 1, fp) != 1)
		return 0;

	return sizeof(msg) + msg.len;
}

bool lu_is_pending(void)
{
	return lu_status != NULL;
}

static void lu_get_dump_state(struct lu_dump_state *state)
{
	struct stat statbuf;

	state->size = 0;

	state->filename = talloc_asprintf(NULL, "%s/state_dump",
					  xenstore_rundir());
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

static void lu_close_dump_state(struct lu_dump_state *state)
{
	assert(state->filename != NULL);

	munmap(state->buf, state->size);
	close(state->fd);

	unlink(state->filename);
	talloc_free(state->filename);
}

void lu_read_state(void)
{
	struct lu_dump_state state = {};
	struct xs_state_record_header *head;
	void *ctx = talloc_new(NULL); /* Work context for subfunctions. */
	struct xs_state_preamble *pre;

	syslog(LOG_INFO, "live-update: read state\n");
	lu_get_dump_state(&state);
	if (state.size == 0)
		barf_perror("No state found after live-update");

	pre = state.buf;
	if (memcmp(pre->ident, XS_STATE_IDENT, sizeof(pre->ident)) ||
	    pre->version != htobe32(XS_STATE_VERSION) ||
	    pre->flags != XS_STATE_FLAGS)
		barf("Unknown record identifier");
	for (head = state.buf + sizeof(*pre);
	     head->type != XS_STATE_TYPE_END &&
		(void *)head - state.buf < state.size;
	     head = (void *)head + sizeof(*head) + head->length) {
		switch (head->type) {
		case XS_STATE_TYPE_GLOBAL:
			read_state_global(ctx, head + 1);
			break;
		case XS_STATE_TYPE_CONN:
			read_state_connection(ctx, head + 1);
			break;
		case XS_STATE_TYPE_WATCH:
			read_state_watch(ctx, head + 1);
			break;
		case XS_STATE_TYPE_TA:
			xprintf("live-update: ignore transaction record\n");
			break;
		case XS_STATE_TYPE_NODE:
			read_state_node(ctx, head + 1);
			break;
		default:
			xprintf("live-update: unknown state record %08x\n",
				head->type);
			break;
		}
	}

	lu_close_dump_state(&state);

	talloc_free(ctx);

	/*
	 * We may have missed the VIRQ_DOM_EXC notification and a domain may
	 * have died while we were live-updating. So check all the domains are
	 * still alive.
	 */
	check_domains();
}

static const char *lu_abort(const void *ctx, struct connection *conn)
{
	syslog(LOG_INFO, "live-update: abort\n");

	if (!lu_status)
		return "No live-update session active.";

	/* Destructor will do the real abort handling. */
	talloc_free(lu_status);

	return NULL;
}

static const char *lu_cmdline(const void *ctx, struct connection *conn,
			      const char *cmdline)
{
	syslog(LOG_INFO, "live-update: cmdline %s\n", cmdline);

	if (!lu_status || lu_status->conn != conn)
		return "Not in live-update session.";

	lu_status->cmdline = talloc_strdup(lu_status, cmdline);
	if (!lu_status->cmdline)
		return "Allocation failure.";

	return NULL;
}

static bool lu_check_lu_allowed(void)
{
	struct connection *conn;
	time_t now = time(NULL);
	unsigned int ta_total = 0, ta_long = 0;

	list_for_each_entry(conn, &connections, list) {
		if (conn->ta_start_time) {
			ta_total++;
			if (now - conn->ta_start_time >= lu_status->timeout)
				ta_long++;
		}
	}

	/*
	 * Allow LiveUpdate if one of the following conditions is met:
	 *	- There is no active transactions
	 *	- All transactions are long running (e.g. they have been
	 *	active for more than lu_status->timeout sec) and the admin as
	 *	requested to force the operation.
	 */
	return ta_total ? (lu_status->force && ta_long == ta_total) : true;
}

static const char *lu_reject_reason(const void *ctx)
{
	char *ret = NULL;
	struct connection *conn;
	time_t now = time(NULL);

	list_for_each_entry(conn, &connections, list) {
		unsigned long tdiff = now - conn->ta_start_time;

		if (conn->ta_start_time && (tdiff >= lu_status->timeout)) {
			ret = talloc_asprintf(ctx, "%s\nDomain %u: %ld s",
					      ret ? : "Domains with long running transactions:",
					      conn->id, tdiff);
		}
	}

	return ret ? (const char *)ret : "Overlapping transactions";
}

static FILE *lu_dump_open(const void *ctx)
{
	char *filename;
	int fd;

	filename = talloc_asprintf(ctx, "%s/state_dump",
				   xenstore_rundir());
	if (!filename)
		return NULL;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return NULL;

	return fdopen(fd, "w");
}

static void lu_dump_close(FILE *fp)
{
	fclose(fp);
}

static const char *lu_dump_state(const void *ctx, struct connection *conn)
{
	FILE *fp;
	const char *ret;
	struct xs_state_record_header end;
	struct xs_state_preamble pre;

	fp = lu_dump_open(ctx);
	if (!fp)
		return "Dump state open error";

	memcpy(pre.ident, XS_STATE_IDENT, sizeof(pre.ident));
	pre.version = htobe32(XS_STATE_VERSION);
	pre.flags = XS_STATE_FLAGS;
	if (fwrite(&pre, sizeof(pre), 1, fp) != 1) {
		ret = "Dump write error";
		goto out;
	}

	ret = dump_state_global(fp);
	if (ret)
		goto out;
	ret = dump_state_connections(fp);
	if (ret)
		goto out;
	ret = dump_state_nodes(fp, ctx);
	if (ret)
		goto out;

	end.type = XS_STATE_TYPE_END;
	end.length = 0;
	if (fwrite(&end, sizeof(end), 1, fp) != 1)
		ret = "Dump write error";

 out:
	lu_dump_close(fp);

	return ret;
}

static const char *lu_activate_binary(const void *ctx)
{
	int argc;
	char **argv;
	unsigned int i;

	if (lu_status->cmdline) {
		argc = 4;   /* At least one arg + progname + "-U" + NULL. */
		for (i = 0; lu_status->cmdline[i]; i++)
			if (isspace(lu_status->cmdline[i]))
				argc++;
		argv = talloc_array(ctx, char *, argc);
		if (!argv)
			return "Allocation failure.";

		i = 0;
		argc = 1;
		argv[1] = strtok(lu_status->cmdline, " \t");
		while (argv[argc]) {
			if (!strcmp(argv[argc], "-U"))
				i = 1;
			argc++;
			argv[argc] = strtok(NULL, " \t");
		}

		if (!i) {
			argv[argc++] = "-U";
			argv[argc] = NULL;
		}
	} else {
		for (i = 0; i < orig_argc; i++)
			if (!strcmp(orig_argv[i], "-U"))
				break;

		argc = orig_argc;
		argv = talloc_array(ctx, char *, orig_argc + 2);
		if (!argv)
			return "Allocation failure.";

		memcpy(argv, orig_argv, orig_argc * sizeof(*argv));
		if (i == orig_argc)
			argv[argc++] = "-U";
		argv[argc] = NULL;
	}

	domain_deinit();

	return lu_exec(ctx, argc, argv);
}

static bool do_lu_start(struct delayed_request *req)
{
	time_t now = time(NULL);
	const char *ret;
	struct buffered_data *saved_in;
	struct connection *conn = req->data;

	/*
	 * Cancellation may have been requested asynchronously. In this
	 * case, lu_status will be NULL.
	 */
	if (!lu_status) {
		ret = "Cancellation was requested";
		goto out;
	}

	assert(lu_status->conn == conn);

	if (!lu_check_lu_allowed()) {
		if (now < lu_status->started_at + lu_status->timeout)
			return false;
		if (!lu_status->force) {
			ret = lu_reject_reason(req);
			goto out;
		}
	}

	assert(req->in == lu_status->in);
	/* Dump out internal state, including "OK" for live update. */
	ret = lu_dump_state(req->in, conn);
	if (!ret) {
		/* Perform the activation of new binary. */
		ret = lu_activate_binary(req->in);
	}

	/* We will reach this point only in case of failure. */
 out:
	/*
	 * send_reply() will send the response for conn->in. Save the current
	 * conn->in and restore it afterwards.
	 */
	saved_in = conn->in;
	conn->in = req->in;
	send_reply(conn, XS_CONTROL, ret, strlen(ret) + 1);
	conn->in = saved_in;
	talloc_free(lu_status);

	return true;
}

static const char *lu_start(const void *ctx, struct connection *conn,
			    bool force, unsigned int to)
{
	syslog(LOG_INFO, "live-update: start, force=%d, to=%u\n", force, to);

	if (!lu_status || lu_status->conn != conn)
		return "Not in live-update session.";

#ifdef __MINIOS__
	if (lu_status->kernel_size != lu_status->kernel_off)
		return "Kernel not complete.";
#endif

	lu_status->force = force;
	lu_status->timeout = to;
	lu_status->started_at = time(NULL);
	lu_status->in = conn->in;

	errno = delay_request(conn, conn->in, do_lu_start, conn, false);

	return NULL;
}

int do_control_lu(const void *ctx, struct connection *conn, const char **vec,
		  int num)
{
	const char *ret = NULL;
	unsigned int i;
	bool force = false;
	unsigned int to = 0;

	if (num < 1)
		return EINVAL;

	if (!strcmp(vec[0], "-a")) {
		if (num == 1)
			ret = lu_abort(ctx, conn);
		else
			return EINVAL;
	} else if (!strcmp(vec[0], "-c")) {
		if (num == 2)
			ret = lu_cmdline(ctx, conn, vec[1]);
		else
			return EINVAL;
	} else if (!strcmp(vec[0], "-s")) {
		for (i = 1; i < num; i++) {
			if (!strcmp(vec[i], "-F"))
				force = true;
			else if (!strcmp(vec[i], "-t") && i < num - 1) {
				i++;
				to = atoi(vec[i]);
			} else
				return EINVAL;
		}
		ret = lu_start(ctx, conn, force, to);
		if (!ret)
			return errno;
	} else {
		ret = lu_arch(ctx, conn, vec, num);
		if (!ret && errno)
			return errno;
	}

	if (!ret)
		ret = "OK";
	send_reply(conn, XS_CONTROL, ret, strlen(ret) + 1);
	return 0;
}
#endif
