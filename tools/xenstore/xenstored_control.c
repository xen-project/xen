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
#include <string.h>

#include "utils.h"
#include "talloc.h"
#include "xenstored_core.h"
#include "xenstored_control.h"

struct cmd_s {
	char *cmd;
	int (*func)(void *, struct connection *, char **, int);
	char *pars;
};

static int do_control_check(void *ctx, struct connection *conn,
			    char **vec, int num)
{
	if (num)
		return EINVAL;

	check_store();

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_log(void *ctx, struct connection *conn,
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

#ifdef __MINIOS__
static int do_control_memreport(void *ctx, struct connection *conn,
				char **vec, int num)
{
	if (num)
		return EINVAL;

	talloc_report_full(NULL, stdout);

	send_ack(conn, XS_CONTROL);
	return 0;
}
#else
static int do_control_logfile(void *ctx, struct connection *conn,
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

static int do_control_memreport(void *ctx, struct connection *conn,
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
#endif

static int do_control_print(void *ctx, struct connection *conn,
			    char **vec, int num)
{
	if (num != 1)
		return EINVAL;

	xprintf("control: %s", vec[0]);

	send_ack(conn, XS_CONTROL);
	return 0;
}

static int do_control_help(void *, struct connection *, char **, int);

static struct cmd_s cmds[] = {
	{ "check", do_control_check, "" },
	{ "log", do_control_log, "on|off" },
#ifdef __MINIOS__
	{ "memreport", do_control_memreport, "" },
#else
	{ "logfile", do_control_logfile, "<file>" },
	{ "memreport", do_control_memreport, "[<file>]" },
#endif
	{ "print", do_control_print, "<string>" },
	{ "help", do_control_help, "" },
};

static int do_control_help(void *ctx, struct connection *conn,
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

int do_control(struct connection *conn, struct buffered_data *in)
{
	int num;
	int cmd;
	char **vec;

	if (conn->id != 0)
		return EACCES;

	num = xs_count_strings(in->buffer, in->used);
	if (num < 1)
		return EINVAL;
	vec = talloc_array(in, char *, num);
	if (!vec)
		return ENOMEM;
	if (get_strings(in, vec, num) != num)
		return EIO;

	for (cmd = 0; cmd < ARRAY_SIZE(cmds); cmd++)
		if (streq(vec[0], cmds[cmd].cmd))
			return cmds[cmd].func(in, conn, vec + 1, num - 1);

	return EINVAL;
}
