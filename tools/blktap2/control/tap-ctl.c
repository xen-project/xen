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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "tap-ctl.h"

typedef int (*tap_ctl_func_t) (int, char **);

struct command {
	char                     *name;
	tap_ctl_func_t            func;
};

static void
tap_cli_list_usage(FILE *stream)
{
	fprintf(stream,
		"usage: list [-h] [-p pid] [-m minor] [-t type] [-f file]\n");
}

static void
tap_ctl_list_row(tap_list_t *entry)
{
	char minor_str[10] = "-";
	char state_str[10] = "-";
	char pid_str[10]   = "-";

	if (entry->pid != -1)
		sprintf(pid_str, "%d", entry->pid);

	if (entry->minor != -1)
		sprintf(minor_str, "%d", entry->minor);

	if (entry->state != -1)
		sprintf(state_str, "%x", entry->state);

	printf("%8s %2s %4s %10s %s\n",
	       pid_str, minor_str, state_str,
	       entry->type ? : "-", entry->path ? : "-");
}

static void
tap_ctl_list_dict(tap_list_t *entry)
{
	int d = 0;

	if (entry->pid != -1) {
		if (d) putc(' ', stdout);
		d = printf("pid=%d", entry->pid);
	}

	if (entry->minor != -1) {
		if (d) putc(' ', stdout);
		d = printf("minor=%d", entry->minor);
	}

	if (entry->state != -1) {
		if (d) putc(' ', stdout);
		d = printf("state=%d", entry->state);
	}

	if (entry->type && entry->path) {
		if (d) putc(' ', stdout);
		d = printf("args=%s:%s", entry->type, entry->path);
	}

	putc('\n', stdout);
}

int
tap_cli_list(int argc, char **argv)
{
	tap_list_t **list, **_entry;
	int c, minor, tty, err;
	const char *type, *file;
	pid_t pid;

	err = tap_ctl_list(&list);
	if (err)
		return -err;

	pid   = -1;
	minor = -1;
	type  = NULL;
	file  = NULL;

	while ((c = getopt(argc, argv, "m:p:t:f:h")) != -1) {
		switch (c) {
		case 'm':
			minor = atoi(optarg);
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 't':
			type = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_list_usage(stdout);
			return 0;
		}
	}

	tty = isatty(STDOUT_FILENO);

	for (_entry = list; *_entry != NULL; ++_entry) {
		tap_list_t *entry  = *_entry;

		if (minor >= 0 && entry->minor != minor)
			continue;

		if (pid >= 0 && entry->pid != pid)
			continue;

		if (type && (!entry->type || strcmp(entry->type, type)))
			continue;

		if (file && (!entry->path || strcmp(entry->path, file)))
			continue;

		if (tty)
			tap_ctl_list_row(entry);
		else
			tap_ctl_list_dict(entry);
	}

	tap_ctl_free_list(list);

	return 0;

usage:
	tap_cli_list_usage(stderr);
	return EINVAL;
}

static void
tap_cli_allocate_usage(FILE *stream)
{
	fprintf(stream, "usage: allocate [-d device name]>\n");
}

static int
tap_cli_allocate(int argc, char **argv)
{
	char *devname;
	int c, minor, err;

	devname = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, "d:h")) != -1) {
		switch (c) {
		case 'd':
			devname = optarg;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_allocate_usage(stdout);
			return 0;
		}
	}

	err = tap_ctl_allocate(&minor, &devname);
	if (!err)
		printf("%s\n", devname);

	return err;

usage:
	tap_cli_allocate_usage(stderr);
	return EINVAL;
}

static void
tap_cli_free_usage(FILE *stream)
{
	fprintf(stream, "usage: free <-m minor>\n");
}

static int
tap_cli_free(int argc, char **argv)
{
	int c, minor;

	minor = -1;

	optind = 0;
	while ((c = getopt(argc, argv, "m:h")) != -1) {
		switch (c) {
		case 'm':
			minor = atoi(optarg);
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_free_usage(stdout);
			return 0;
		}
	}

	if (minor == -1)
		goto usage;

	return tap_ctl_free(minor);

usage:
	tap_cli_free_usage(stderr);
	return EINVAL;
}

static void
tap_cli_create_usage(FILE *stream)
{
	fprintf(stream, "usage: create <-a args> [-d device name]\n");
}

static int
tap_cli_create(int argc, char **argv)
{
	int c, err;
	char *args, *devname;

	args    = NULL;
	devname = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, "a:d:h")) != -1) {
		switch (c) {
		case 'a':
			args = optarg;
			break;
		case 'd':
			devname = optarg;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_create_usage(stdout);
			return 0;
		}
	}

	if (!args)
		goto usage;

	err = tap_ctl_create(args, &devname);
	if (!err)
		printf("%s\n", devname);

	return err;

usage:
	tap_cli_create_usage(stderr);
	return EINVAL;
}

static void
tap_cli_destroy_usage(FILE *stream)
{
	fprintf(stream, "usage: destroy <-p pid> <-m minor>\n");
}

static int
tap_cli_destroy(int argc, char **argv)
{
	int c, pid, minor;

	pid   = -1;
	minor = -1;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_destroy_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_destroy(pid, minor);

usage:
	tap_cli_destroy_usage(stderr);
	return EINVAL;
}

static void
tap_cli_spawn_usage(FILE *stream)
{
	fprintf(stream, "usage: spawn\n");
}

static int
tap_cli_spawn(int argc, char **argv)
{
	int c;
	pid_t task;

	optind = 0;
	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
		case '?':
			goto usage;
		case 'h':
			tap_cli_spawn_usage(stdout);
			return 0;
		}
	}

	task = tap_ctl_spawn();
	if (task < 0) {
		printf("spawn failed: %d\n", errno);
		return task;
	}

	printf("tapdisk spawned with pid %d\n", task);
	return 0;

usage:
	tap_cli_spawn_usage(stderr);
	return EINVAL;
}

static void
tap_cli_attach_usage(FILE *stream)
{
	fprintf(stream, "usage: attach <-p pid> <-m minor>\n");
}

static int
tap_cli_attach(int argc, char **argv)
{
	int c, pid, minor;

	pid   = -1;
	minor = -1;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_attach_usage(stderr);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_attach(pid, minor);

usage:
	tap_cli_attach_usage(stderr);
	return EINVAL;
}

static void
tap_cli_detach_usage(FILE *stream)
{
	fprintf(stream, "usage: detach <-p pid> <-m minor>\n");
}

static int
tap_cli_detach(int argc, char **argv)
{
	int c, pid, minor;

	pid   = -1;
	minor = -1;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_detach_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_detach(pid, minor);

usage:
	tap_cli_detach_usage(stderr);
	return EINVAL;
}

static void
tap_cli_close_usage(FILE *stream)
{
	fprintf(stream, "usage: close <-p pid> <-m minor> [-f force]\n");
}

static int
tap_cli_close(int argc, char **argv)
{
	int c, pid, minor, force;

	pid   = -1;
	minor = -1;
	force = 0;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:fh")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case 'f':
			force = -1;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_close_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_close(pid, minor, force);

usage:
	tap_cli_close_usage(stderr);
	return EINVAL;
}

static void
tap_cli_pause_usage(FILE *stream)
{
	fprintf(stream, "usage: pause <-p pid> <-m minor>\n");
}

static int
tap_cli_pause(int argc, char **argv)
{
	int c, pid, minor;

	pid   = -1;
	minor = -1;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_pause_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_pause(pid, minor);

usage:
	tap_cli_pause_usage(stderr);
	return EINVAL;
}

static void
tap_cli_unpause_usage(FILE *stream)
{
	fprintf(stream, "usage: unpause <-p pid> <-m minor> [-a args]\n");
}

int
tap_cli_unpause(int argc, char **argv)
{
	const char *args;
	int c, pid, minor;

	pid   = -1;
	minor = -1;
	args  = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, "p:m:a:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case 'a':
			args = optarg;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_unpause_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1)
		goto usage;

	return tap_ctl_unpause(pid, minor, args);

usage:
	tap_cli_unpause_usage(stderr);
	return EINVAL;
}

static void
tap_cli_major_usage(FILE *stream)
{
	fprintf(stream, "usage: major [-h]\n");
}

static int
tap_cli_major(int argc, char **argv)
{
	int c, chr, major;

	chr = 0;

	while ((c = getopt(argc, argv, "bch")) != -1) {
		switch (c) {
		case 'b':
			chr = 0;
			break;
		case 'c':
			chr = 1;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_major_usage(stdout);
			return 0;
		default:
			goto usage;
		}
	}

	if (chr)
		major = -EINVAL;
	else
		major = tap_ctl_blk_major();

	if (major < 0)
		return -major;

	printf("%d\n", major);

	return 0;

usage:
	tap_cli_major_usage(stderr);
	return EINVAL;
}

static void
tap_cli_open_usage(FILE *stream)
{
	fprintf(stream, "usage: open <-p pid> <-m minor> <-a args>\n");
}

static int
tap_cli_open(int argc, char **argv)
{
	const char *args;
	int c, pid, minor;

	pid   = -1;
	minor = -1;
	args  = NULL;

	optind = 0;
	while ((c = getopt(argc, argv, "a:m:p:h")) != -1) {
		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'm':
			minor = atoi(optarg);
			break;
		case 'a':
			args = optarg;
			break;
		case '?':
			goto usage;
		case 'h':
			tap_cli_open_usage(stdout);
			return 0;
		}
	}

	if (pid == -1 || minor == -1 || !args)
		goto usage;

	return tap_ctl_open(pid, minor, args);

usage:
	tap_cli_open_usage(stderr);
	return EINVAL;
}

static void
tap_cli_check_usage(FILE *stream)
{
	fprintf(stream, "usage: check\n"
		"(checks whether environment is suitable for tapdisk2)\n");
}

static int
tap_cli_check(int argc, char **argv)
{
	int err;
	const char *msg;

	if (argc != 1)
		goto usage;

	err = tap_ctl_check(&msg);
	printf("%s\n", msg);

	return err;

usage:
	tap_cli_check_usage(stderr);
	return EINVAL;
}

struct command commands[] = {
	{ .name = "list",         .func = tap_cli_list          },
	{ .name = "allocate",     .func = tap_cli_allocate      },
	{ .name = "free",         .func = tap_cli_free          },
	{ .name = "create",       .func = tap_cli_create        },
	{ .name = "destroy",      .func = tap_cli_destroy       },
	{ .name = "spawn",        .func = tap_cli_spawn         },
	{ .name = "attach",       .func = tap_cli_attach        },
	{ .name = "detach",       .func = tap_cli_detach        },
	{ .name = "open",         .func = tap_cli_open          },
	{ .name = "close",        .func = tap_cli_close         },
	{ .name = "pause",        .func = tap_cli_pause         },
	{ .name = "unpause",      .func = tap_cli_unpause       },
	{ .name = "major",        .func = tap_cli_major         },
	{ .name = "check",        .func = tap_cli_check         },
};

#define print_commands()					\
	do {							\
		int i, n;					\
		n = sizeof(commands) / sizeof(struct command);	\
		printf("COMMAND := { ");			\
		printf("%s", commands[0].name);			\
		for (i = 1; i < n; i++)				\
			printf(" | %s", commands[i].name);	\
		printf(" }\n");					\
	} while (0)

void
help(void)
{
	printf("usage: tap-ctl COMMAND [OPTIONS]\n");
	print_commands();
	exit(0);
}

struct command *
get_command(char *command)
{
	int i, n;

	if (strnlen(command, 25) >= 25)
		return NULL;

	n = sizeof(commands) / sizeof (struct command);

	for (i = 0; i < n; i++)
		if (!strcmp(command, commands[i].name))
			return &commands[i];

	return NULL;
}

int
main(int argc, char *argv[])
{
	char **cargv;
	const char *msg;
	struct command *cmd;
	int cargc, i, cnt, ret;

#ifdef CORE_DUMP
	#include <sys/resource.h>
	struct rlimit rlim;
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		PERROR("setrlimit failed");
#endif

	ret = 0;

	if (argc < 2)
		help();

	cargc = argc - 1;
	cmd   = get_command(argv[1]);
	if (!cmd) {
		EPRINTF("invalid COMMAND %s", argv[1]);
		help();
	}

	ret = tap_ctl_check(&msg);
	if (ret) {
		printf("%s\n", msg);
		return ret;
	}

	cargv = malloc(sizeof(char *) * cargc);
	if (!cargv)
		exit(ENOMEM);

	cnt      = 1;
	cargv[0] = cmd->name;
	for (i = 1; i < cargc; i++) {
		char *arg = argv[i + (argc - cargc)];

		if (!strcmp(arg, "--debug")) {
			tap_ctl_debug = 1;
			continue;
		}

		cargv[cnt++] = arg;
	}

	ret = cmd->func(cnt, cargv);

	free(cargv);

	return (ret >= 0 ? ret : -ret);
}
