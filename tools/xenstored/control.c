/*
    Interactive commands for Xen Store Daemon.
    Copyright (C) 2017 Juergen Gross, SUSE Linux GmbH

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <xen-tools/xenstore-common.h>

#include "utils.h"
#include "talloc.h"
#include "core.h"
#include "control.h"
#include "domain.h"
#include "lu.h"

struct cmd_s {
	char *cmd;
	int (*func)(const void *, struct connection *, const char **, int);
	char *pars;
	/*
	 * max_pars can be used to limit the size of the parameter vector,
	 * e.g. in case of large binary parts in the parameters.
	 * The command is included in the count, so 1 means just the command
	 * without any parameter.
	 * 0 == no limit (the default)
	 */
	unsigned int max_pars;
};

static int do_control_check(const void *ctx, struct connection *conn,
			    const char **vec, int num)
{
	if (num)
		return EINVAL;

	check_store();

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_log(const void *ctx, struct connection *conn,
			  const char **vec, int num)
{
	int ret;

	if (num == 0) {
		char *resp = talloc_asprintf(ctx, "Log switch settings:\n");
		unsigned int idx;
		bool on;

		if (!resp)
			return ENOMEM;
		for (idx = 0; trace_switches[idx]; idx++) {
			on = trace_flags & (1u << idx);
			resp = talloc_asprintf_append(resp, "%-8s: %s\n",
						      trace_switches[idx],
						      on ? "on" : "off");
			if (!resp)
				return ENOMEM;
		}

		send_reply(conn, XS_CONTROL, resp, strlen(resp) + 1);
		return 0;
	}

	if (num != 1)
		return EINVAL;

	if (!strcmp(vec[0], "on"))
		reopen_log();
	else if (!strcmp(vec[0], "off"))
		close_log();
	else {
		ret = set_trace_switch(vec[0]);
		if (ret)
			return ret;
	}

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int quota_show_current(const void *ctx, struct connection *conn,
			      const struct quota *quotas)
{
	char *resp;
	unsigned int i;

	resp = talloc_strdup(ctx, "Quota settings:\n");
	if (!resp)
		return ENOMEM;

	for (i = 0; i < ACC_N; i++) {
		if (!quotas[i].name)
			continue;
		resp = talloc_asprintf_append(resp, "%-17s: %8d %s\n",
					      quotas[i].name, quotas[i].val,
					      quotas[i].descr);
		if (!resp)
			return ENOMEM;
	}

	send_reply(conn, XS_CONTROL, resp, strlen(resp) + 1);

	return 0;
}

static int quota_set(const void *ctx, struct connection *conn,
		     const char **vec, int num, struct quota *quotas)
{
	unsigned int i;
	int val;

	if (num != 2)
		return EINVAL;

	val = atoi(vec[1]);
	if (val < 1)
		return EINVAL;

	for (i = 0; i < ACC_N; i++) {
		if (quotas[i].name && !strcmp(vec[0], quotas[i].name)) {
			quotas[i].val = val;
			send_ack(conn, XS_CONTROL);
			return 0;
		}
	}

	return EINVAL;
}

static int quota_get(const void *ctx, struct connection *conn,
		     const char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	return domain_get_quota(ctx, conn, atoi(vec[0]));
}

static int quota_max(const void *ctx, struct connection *conn,
		     const char **vec, int num)
{
	if (num > 1)
		return EINVAL;

	if (num == 1) {
		if (!strcmp(vec[0], "-r"))
			domain_reset_global_acc();
		else
			return EINVAL;
	}

	return domain_max_global_acc(ctx, conn);
}

static int do_control_quota(const void *ctx, struct connection *conn,
			    const char **vec, int num)
{
	if (num == 0)
		return quota_show_current(ctx, conn, hard_quotas);

	if (!strcmp(vec[0], "set"))
		return quota_set(ctx, conn, vec + 1, num - 1, hard_quotas);

	if (!strcmp(vec[0], "max"))
		return quota_max(ctx, conn, vec + 1, num - 1);

	return quota_get(ctx, conn, vec, num);
}

static int do_control_quota_s(const void *ctx, struct connection *conn,
			      const char **vec, int num)
{
	if (num == 0)
		return quota_show_current(ctx, conn, soft_quotas);

	if (!strcmp(vec[0], "set"))
		return quota_set(ctx, conn, vec + 1, num - 1, soft_quotas);

	return EINVAL;
}

static int do_control_logfile(const void *ctx, struct connection *conn,
			      const char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	close_log();
	talloc_free(tracefile);
	tracefile = absolute_filename(NULL, vec[0]);
	reopen_log();

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_memreport(const void *ctx, struct connection *conn,
				const char **vec, int num)
{
	FILE *fp;
	const char *filename;
	int fd;

	if (num > 1)
		return EINVAL;

	if (num == 0) {
		if (tracefd < 0) {
			if (!tracefile)
				return EBADF;
			fp = fopen(tracefile, "a");
		} else {
			/*
			 * Use dup() in order to avoid closing the file later
			 * with fclose() which will release stream resources.
			 */
			fd = dup(tracefd);
			if (fd < 0)
				return EBADF;
			fp = fdopen(fd, "a");
			if (!fp)
				close(fd);
		}
	} else {
		filename = absolute_filename(ctx, vec[0]);
		if (!filename)
			return ENOMEM;
		fp = fopen(filename, "a");
	}

	if (!fp)
		return EBADF;

	talloc_report_full(NULL, fp);
	fclose(fp);

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_print(const void *ctx, struct connection *conn,
			    const char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	xprintf("control: %s", vec[0]);

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_help(const void *, struct connection *, const char **,
			   int);

static struct cmd_s cmds[] = {
	{ "check", do_control_check, "" },
	{ "log", do_control_log, "[on|off|+<switch>|-<switch>]" },

#ifndef NO_LIVE_UPDATE
	/*
	 * The parameters are those of the xenstore-control utility!
	 * Depending on environment (Mini-OS or daemon) the live-update
	 * sequence is split into several sub-operations:
	 * 1. Specification of new binary
	 *    daemon:  -f <filename>
	 *    Mini-OS: -b <binary-size>
	 *             -d <size> <data-bytes> (multiple of those)
	 * 2. New command-line (optional): -c <cmdline>
	 * 3. Start of update: -s [-F] [-t <timeout>]
	 * Any sub-operation needs to respond with the string "OK" in case
	 * of success, any other response indicates failure.
	 * A started live-update sequence can be aborted via "-a" (not
	 * needed in case of failure for the first or last live-update
	 * sub-operation).
	 */
	{ "live-update", do_control_lu,
		"[-c <cmdline>] [-F] [-t <timeout>] <file>\n"
		"    Default timeout is 60 seconds.", 5 },
#endif
	{ "logfile", do_control_logfile, "<file>" },
	{ "memreport", do_control_memreport, "[<file>]" },
	{ "print", do_control_print, "<string>" },
	{ "quota", do_control_quota,
		"[set <name> <val>|<domid>|max [-r]]" },
	{ "quota-soft", do_control_quota_s, "[set <name> <val>]" },
	{ "help", do_control_help, "" },
};

static int do_control_help(const void *ctx, struct connection *conn,
			   const char **vec, int num)
{
	int cmd;
	char *resp;

	if (num)
		return EINVAL;

	resp = talloc_asprintf(ctx, "%s", "");
	if (!resp)
		return ENOMEM;
	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++) {
		resp = talloc_asprintf_append(resp, "%-15s %s\n",
					      cmds[cmd].cmd, cmds[cmd].pars);
		if (!resp)
			return ENOMEM;
	}

	send_reply(conn, XS_CONTROL, resp, strlen(resp) + 1);
	return 0;
}

int do_control(const void *ctx, struct connection *conn,
	       struct buffered_data *in)
{
	unsigned int cmd, num, off;
	const char **vec = NULL;

	if (domain_is_unprivileged(conn))
		return EACCES;

	off = get_string(in, 0);
	if (!off)
		return EINVAL;
	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++)
		if (streq(in->buffer, cmds[cmd].cmd))
			break;
	if (cmd == ARRAY_SIZE(cmds))
		return EINVAL;

	num = xenstore_count_strings(in->buffer, in->used);
	if (cmds[cmd].max_pars)
		num = min(num, cmds[cmd].max_pars);
	vec = (const char **)talloc_array(ctx, char *, num);
	if (!vec)
		return ENOMEM;
	if (get_strings(in, vec, num) < num)
		return EIO;

	return cmds[cmd].func(ctx, conn, vec + 1, num - 1);
}
