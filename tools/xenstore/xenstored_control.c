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

#include "utils.h"
#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_control.h"
#include "xenstored_domain.h"

struct cmd_s {
	char *cmd;
	int (*func)(const void *, struct connection *, char **, int);
	char *pars;
};

static int do_control_check(const void *ctx, struct connection *conn,
			    char **vec, int num)
{
	if (num)
		return EINVAL;

	check_store();

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_log(const void *ctx, struct connection *conn,
			  char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	if (!strcmp(vec[0], "on"))
		reopen_log();
	else if (!strcmp(vec[0], "off"))
		close_log();
	else
		return EINVAL;

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_logfile(const void *ctx, struct connection *conn,
			      char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	close_log();
	talloc_free(tracefile);
	tracefile = talloc_strdup(NULL, vec[0]);
	reopen_log();

	send_ack(conn, XS_CONTROL);
	return 0;
}

struct quota {
	const char *name;
	int *quota;
	const char *descr;
};

static const struct quota hard_quotas[] = {
	{ "nodes", &quota_nb_entry_per_domain, "Nodes per domain" },
	{ "watches", &quota_nb_watch_per_domain, "Watches per domain" },
	{ "transactions", &quota_max_transaction, "Transactions per domain" },
	{ "outstanding", &quota_req_outstanding,
		"Outstanding requests per domain" },
	{ "transaction-nodes", &quota_trans_nodes,
		"Max. number of accessed nodes per transaction" },
	{ "memory", &quota_memory_per_domain_hard,
		"Total Xenstore memory per domain (error level)" },
	{ "node-size", &quota_max_entry_size, "Max. size of a node" },
	{ "permissions", &quota_nb_perms_per_node,
		"Max. number of permissions per node" },
	{ NULL, NULL, NULL }
};

static const struct quota soft_quotas[] = {
	{ "memory", &quota_memory_per_domain_soft,
		"Total Xenstore memory per domain (warning level)" },
	{ NULL, NULL, NULL }
};

static int quota_show_current(const void *ctx, struct connection *conn,
			      const struct quota *quotas)
{
	char *resp;
	unsigned int i;

	resp = talloc_strdup(ctx, "Quota settings:\n");
	if (!resp)
		return ENOMEM;

	for (i = 0; quotas[i].quota; i++) {
		resp = talloc_asprintf_append(resp, "%-17s: %8d %s\n",
					      quotas[i].name, *quotas[i].quota,
					      quotas[i].descr);
		if (!resp)
			return ENOMEM;
	}

	send_reply(conn, XS_CONTROL, resp, strlen(resp) + 1);

	return 0;
}

static int quota_set(const void *ctx, struct connection *conn,
		     char **vec, int num, const struct quota *quotas)
{
	unsigned int i;
	int val;

	if (num != 2)
		return EINVAL;

	val = atoi(vec[1]);
	if (val < 1)
		return EINVAL;

	for (i = 0; quotas[i].quota; i++) {
		if (!strcmp(vec[0], quotas[i].name)) {
			*quotas[i].quota = val;
			send_ack(conn, XS_CONTROL);
			return 0;
		}
	}

	return EINVAL;
}

static int quota_get(const void *ctx, struct connection *conn,
		     char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	return domain_get_quota(ctx, conn, atoi(vec[0]));
}

static int do_control_quota(const void *ctx, struct connection *conn,
			    char **vec, int num)
{
	if (num == 0)
		return quota_show_current(ctx, conn, hard_quotas);

	if (!strcmp(vec[0], "set"))
		return quota_set(ctx, conn, vec + 1, num - 1, hard_quotas);

	return quota_get(ctx, conn, vec, num);
}

static int do_control_quota_s(const void *ctx, struct connection *conn,
			      char **vec, int num)
{
	if (num == 0)
		return quota_show_current(ctx, conn, soft_quotas);

	if (!strcmp(vec[0], "set"))
		return quota_set(ctx, conn, vec + 1, num - 1, soft_quotas);

	return EINVAL;
}

static int do_control_memreport(const void *ctx, struct connection *conn,
				char **vec, int num)
{
	FILE *fp;
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
	} else
		fp = fopen(vec[0], "a");

	if (!fp)
		return EBADF;

	talloc_report_full(NULL, fp);
	fclose(fp);

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_print(const void *ctx, struct connection *conn,
			    char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	xprintf("control: %s", vec[0]);

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_help(const void *, struct connection *, char **, int);

static struct cmd_s cmds[] = {
	{ "check", do_control_check, "" },
	{ "log", do_control_log, "on|off" },
	{ "logfile", do_control_logfile, "<file>" },
	{ "memreport", do_control_memreport, "[<file>]" },
	{ "print", do_control_print, "<string>" },
	{ "quota", do_control_quota, "[set <name> <val>|<domid>]" },
	{ "quota-soft", do_control_quota_s, "[set <name> <val>]" },
	{ "help", do_control_help, "" },
};

static int do_control_help(const void *ctx, struct connection *conn,
			   char **vec, int num)
{
	int cmd, len = 0;
	char *resp;

	if (num)
		return EINVAL;

	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++) {
		len += strlen(cmds[cmd].cmd) + 1;
		len += strlen(cmds[cmd].pars) + 1;
	}
	len++;

	resp = talloc_array(ctx, char, len);
	if (!resp)
		return ENOMEM;

	len = 0;
	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++) {
		strcpy(resp + len, cmds[cmd].cmd);
		len += strlen(cmds[cmd].cmd);
		resp[len] = '\t';
		len++;
		strcpy(resp + len, cmds[cmd].pars);
		len += strlen(cmds[cmd].pars);
		resp[len] = '\n';
		len++;
	}
	resp[len] = 0;

	send_reply(conn, XS_CONTROL, resp, len);
	return 0;
}

int do_control(const void *ctx, struct connection *conn,
	       struct buffered_data *in)
{
	int num;
	int cmd;
	char **vec;

	if (domain_is_unprivileged(conn))
		return EACCES;

	num = xs_count_strings(in->buffer, in->used);
	if (num < 1)
		return EINVAL;
	vec = talloc_array(ctx, char *, num);
	if (!vec)
		return ENOMEM;
	if (get_strings(in, vec, num) != num)
		return EIO;

	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++)
		if (streq(vec[0], cmds[cmd].cmd))
			return cmds[cmd].func(ctx, conn, vec + 1, num - 1);

	return EINVAL;
}
