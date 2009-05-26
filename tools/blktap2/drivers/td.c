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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>

#include "libvhd.h"
#include "vhd-util.h"
#include "tapdisk-utils.h"

#if 1
#define DFPRINTF(_f, _a...) fprintf ( stdout, _f , ## _a )
#else
#define DFPRINTF(_f, _a...) ((void)0)
#endif

typedef enum {
	TD_FIELD_HIDDEN  = 0,
	TD_FIELD_INVALID = 1
} td_field_t;

struct vdi_field {
	char       *name;
	td_field_t  id;
};

static struct vdi_field td_vdi_fields[TD_FIELD_INVALID] = {
	{ .id = TD_FIELD_HIDDEN, .name = "hidden" }
};

typedef enum {
	TD_CMD_CREATE    = 0,
	TD_CMD_SNAPSHOT,
/*	TD_CMD_COALESCE,       */
	TD_CMD_QUERY,
/* 	TD_CMD_RESIZE,         */
	TD_CMD_SET,
/*	TD_CMD_REPAIR,         */
/*	TD_CMD_FILL,           */
/*	TD_CMD_READ,           */
	TD_CMD_INVALID,
} td_command_t;

struct command {
	td_command_t  id;
	char         *name;
	int           needs_type;
};

struct command commands[TD_CMD_INVALID] = {
	{ .id = TD_CMD_CREATE,   .name = "create",   .needs_type = 1 },
	{ .id = TD_CMD_SNAPSHOT, .name = "snapshot", .needs_type = 1 },
/*	{ .id = TD_CMD_COALESCE, .name = "coalesce", .needs_type = 1 },    */
	{ .id =	TD_CMD_QUERY,    .name = "query",    .needs_type = 1 },
/*	{ .id =	TD_CMD_RESIZE,   .name = "resize",   .needs_type = 1 },    */
	{ .id = TD_CMD_SET,      .name = "set",      .needs_type = 1 },
/*	{ .id = TD_CMD_REPAIR,   .name = "repair",   .needs_type = 1 },    */
/*	{ .id = TD_CMD_FILL,     .name = "fill",     .needs_type = 1 },    */
/*	{ .id = TD_CMD_READ,     .name = "read",     .needs_type = 1 },    */
};

typedef enum {
	TD_TYPE_VHD         = 0,
	TD_TYPE_AIO,
	TD_TYPE_INVALID,
} td_disk_t;

const char *td_disk_types[TD_TYPE_INVALID] = {
	"vhd",
	"aio",
};

#define print_commands()						\
	do {								\
		int i;							\
		fprintf(stderr, "COMMAND := { ");			\
		fprintf(stderr, "%s", commands[0].name);		\
		for (i = 1; i < TD_CMD_INVALID; i++)			\
			fprintf(stderr, " | %s", commands[i].name);	\
		fprintf(stderr, " }\n");				\
	} while (0)

#define print_disk_types()						\
	do {								\
		int i;							\
		fprintf(stderr, "TYPE := { ");				\
		fprintf(stderr, "%s", td_disk_types[0]);		\
		for (i = 1; i < TD_TYPE_INVALID; i++)			\
			fprintf(stderr, " | %s", td_disk_types[i]);	\
		fprintf(stderr, " }\n");				\
	} while (0);

#define print_field_names()						\
	do {								\
		int i;							\
		fprintf(stderr, "FIELD := { ");				\
		fprintf(stderr, "%s", td_vdi_fields[0].name);		\
		for (i = 1; i < TD_FIELD_INVALID; i++)			\
			fprintf(stderr, " | %s", td_vdi_fields[i].name); \
		fprintf(stderr, " }\n");				\
	} while (0)

void 
help(void)
{
	fprintf(stderr, "Tapdisk Utilities: v1.0.0\n");
	fprintf(stderr, "usage: td-util COMMAND [TYPE] [OPTIONS]\n");
	print_commands();
	print_disk_types();
	exit(-1);
}

struct command *
get_command(char *command)
{
	int i;

	for (i = 0; i < TD_CMD_INVALID; i++)
		if (!strcmp(command, commands[i].name))
			return &commands[i];

	return NULL;
}

struct vdi_field *
get_field(char *field)
{
	int i;

	for (i = 0; i < TD_FIELD_INVALID; i++)
		if (!strcmp(field, td_vdi_fields[i].name))
			return &td_vdi_fields[i];

	return NULL;
}

int
get_driver_type(char *type)
{
	int i;

	if (strnlen(type, 25) >= 25)
		return -ENAMETOOLONG;

	for (i = 0; i < TD_TYPE_INVALID; i++)
		if (!strcmp(type, td_disk_types[i]))
			return i;

	return -TD_TYPE_INVALID;
}

int
td_create(int type, int argc, char *argv[])
{
	ssize_t mb;
	uint64_t size;
	char *name, *buf;
	int c, i, fd, sparse = 1, fixedsize = 0;

	while ((c = getopt(argc, argv, "hrb")) != -1) {
		switch(c) {
		case 'r':
			sparse = 0;
			break;
		case 'b':
			fixedsize = 1;
			break;
		default:
			fprintf(stderr, "Unknown option %c\n", (char)c);
		case 'h':
			goto usage;
		}
	}

	if (optind != (argc - 2))
		goto usage;

	mb   = 1 << 20;
	size = atoi(argv[optind++]);
	size = size << 20;
	name = argv[optind];

	if (strnlen(name, MAX_NAME_LEN) == MAX_NAME_LEN) {
		fprintf(stderr, "Device name too long\n");
		return ENAMETOOLONG;
	}

	if (type == TD_TYPE_VHD) {
		int cargc = 0;
		char sbuf[32], *cargv[10];

		size >>= 20;

		memset(cargv, 0, sizeof(cargv));
		snprintf(sbuf, sizeof(sbuf) - 1, "%"PRIu64, size);
		cargv[cargc++] = "create";
		cargv[cargc++] = "-n";
		cargv[cargc++] = name;
		cargv[cargc++] = "-s";
		cargv[cargc++] = sbuf;
		if (!sparse)
			cargv[cargc++] = "-r";
		if (fixedsize)
			cargv[cargc++] = "-b";

		return vhd_util_create(cargc, cargv);
	}

	/* generic create */
	if (sparse) {
		fprintf(stderr, "Cannot create sparse %s image\n",
			td_disk_types[type]);
		return EINVAL;
	}

	buf = calloc(1, mb);
	if (!buf)
		return ENOMEM;

	fd = open(name, O_WRONLY | O_DIRECT | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		free(buf);
		return errno;
	}

	size >>= 20;
	for (i = 0; i < size; i++)
		if (write(fd, buf, mb) != mb) {
			close(fd);
			unlink(name);
			free(buf);
			return EIO;
		}

	close(fd);
	free(buf);
	return 0;

 usage:
	fprintf(stderr, "usage: td-util create %s [-h help] [-r reserve] "
		"[-b file_is_fixed_size] <SIZE(MB)> <FILENAME>\n",
		td_disk_types[type]);
	return EINVAL;
}

int
td_snapshot(int type, int argc, char *argv[])
{
	char *cargv[10];
	int c, err, cargc;
	struct stat stats;
	char *name, *backing, *limit = NULL;
	int fixedsize = 0, rawparent = 0;

	if (type != TD_TYPE_VHD) {
		fprintf(stderr, "Cannot create snapshot of %s image type\n",
			td_disk_types[type]);
		return EINVAL;
	}

	while ((c = getopt(argc, argv, "hbml:")) != -1) {
		switch(c) {
		case 'b':
			fixedsize = 1;
			break;
		case 'm':
			rawparent = 1;
			break;
		case 'l':
			limit = optarg;
			break;
		case 'h':
			err = 0;
			goto usage;
		default:
			err = EINVAL;
			goto usage;
		}
	}

	if (optind != (argc - 2)) {
		err = EINVAL;
		goto usage;
	}

	name    = argv[optind++];
	backing = argv[optind++];

	if (strnlen(name, MAX_NAME_LEN) == MAX_NAME_LEN ||
	    strnlen(backing, MAX_NAME_LEN) == MAX_NAME_LEN) {
		fprintf(stderr, "Device name too long\n");
		return ENAMETOOLONG;
	}

	if (stat(backing, &stats) == -1) {
		fprintf(stderr, "File %s not found\n", backing);
		return errno;
	}

	cargc = 0;
	memset(cargv, 0, sizeof(cargv));
	cargv[cargc++] = "snapshot";
	cargv[cargc++] = "-n";
	cargv[cargc++] = name;
	cargv[cargc++] = "-p";
	cargv[cargc++] = backing;
	if (fixedsize)
		cargv[cargc++] = "-b";
	if (rawparent)
		cargv[cargc++] = "-m";
	if (limit) {
		cargv[cargc++] = "-l";
		cargv[cargc++] = limit;
	}
	return vhd_util_snapshot(cargc, cargv);

 usage:
	fprintf(stderr, "usage: td-util snapshot %s [-h help] [-m parent_raw] "
		"[-b file_is_fixed_size] [-l snapshot depth limit] "
		"<FILENAME> <BACKING_FILENAME>\n", td_disk_types[type]);
	return err;
}

int
td_coalesce(int type, int argc, char *argv[])
{
	int c, ret, cargc;
	char *name, *pname, *cargv[3];

	if (type != TD_TYPE_VHD) {
		fprintf(stderr, "Cannot create snapshot of %s image type\n",
			td_disk_types[type]);
		return EINVAL;
	}

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch(c) {
		default:
			fprintf(stderr, "Unknown option %c\n", (char)c);
		case 'h':
			goto usage;
		}
	}

	if (optind != (argc - 1))
		goto usage;

	name = argv[optind++];

	if (strnlen(name, MAX_NAME_LEN) == MAX_NAME_LEN) {
		fprintf(stderr, "Device name too long\n");
		return ENAMETOOLONG;
	}

	cargc = 0;
	memset(cargv, 0, sizeof(cargv));
	cargv[cargc++] = "coalesce";
	cargv[cargc++] = "-n";
	cargv[cargc++] = name;
	ret = vhd_util_coalesce(cargc, cargv);
	if (ret)
		printf("coalesce failed: %d\n", ret);

	return ret;

 usage:
	fprintf(stderr, "usage: td-util coalesce %s [-h help] "
		"<FILENAME>\n", td_disk_types[type]);
	return EINVAL;
}

int
td_query(int type, int argc, char *argv[])
{
	char *name;
	int c, size = 0, parent = 0, fields = 0, depth = 0, err = 0;

	while ((c = getopt(argc, argv, "hvpfd")) != -1) {
		switch(c) {
		case 'v':
			size = 1;
			break;
		case 'p':
			parent = 1;
			break;
		case 'f':
			fields = 1;
			break;
		case 'd':
			depth = 1;
			break;
		case 'h':
			err = 0;
			goto usage;
		default:
			err = EINVAL;
			goto usage;
		}
	}

	if (optind != (argc - 1)) {
		err = EINVAL;
		goto usage;
	}

	name = argv[optind++];

	if (strnlen(name, MAX_NAME_LEN) == MAX_NAME_LEN) {
		fprintf(stderr, "Device name too long\n");
		return ENAMETOOLONG;
	}

	if (type == TD_TYPE_VHD) {
		vhd_context_t vhd;

		err = vhd_open(&vhd, name, VHD_OPEN_RDONLY);
		if (err) {
			printf("failed opening %s: %d\n", name, err);
			return err;
		}

		if (size)
			printf("%"PRIu64"\n", vhd.footer.curr_size >> 20);

		if (parent) {
			if (vhd.footer.type != HD_TYPE_DIFF)
				printf("%s has no parent\n", name);
			else {
				char *pname;

				err = vhd_parent_locator_get(&vhd, &pname);
				if (err)
					printf("failed getting parent: %d\n",
					       err);
				else {
					printf("%s\n", pname);
					free(pname);
				}
			}
		}

		if (fields) {
			int ret, hidden;

			ret = vhd_hidden(&vhd, &hidden);
			if (ret) {
				printf("failed checking 'hidden' field: %d\n",
				       ret);
				err = (err ? : ret);
			} else
				printf("%s: %d\n",
				       td_vdi_fields[TD_FIELD_HIDDEN].name,
				       hidden);
		}

		if (depth) {
			int ret, length;

			ret = vhd_chain_depth(&vhd, &length);
			if (ret)
				printf("error checking chain depth: %d\n", ret);
			else
				printf("chain depth: %d\n", length);

			err = (err ? : ret);
		}

		vhd_close(&vhd);

	} else if (type == TD_TYPE_AIO) {
		if (size) {
			int fd;
			uint64_t secs;
			uint32_t ssize;

			fd = open(name, O_RDONLY | O_LARGEFILE);
			if (fd == -1) {
				printf("failed opening %s: %d\n", name, errno);
				return -errno;
			}

			err = tapdisk_get_image_size(fd, &secs, &ssize);
			close(fd);

			if (err) {
				printf("failed getting size for %s: %d\n:",
				       name, err);
				return err;
			}

			printf("%"PRIu64"\n", secs >> 11);
		}

		if (parent)
			printf("%s has no parent\n", name);

		if (fields) {
			int i;

			for (i = 0; i < TD_FIELD_INVALID; i++)
				printf("%s: 0\n", td_vdi_fields[i].name);
		}
	}

	return err;

 usage:
	fprintf(stderr, "usage: td-util query %s [-h help] [-v virtsize] "
		"[-p parent] [-f fields]  <FILENAME>\n", td_disk_types[type]);
	return err;
}

int
td_set_field(int type, int argc, char *argv[])
{
	int ret, i, c, cargc;
	struct vdi_field *field;
	char *name, *value, *cargv[7];

	if (type != TD_TYPE_VHD) {
		fprintf(stderr, "Cannot set fields of %s images\n",
			td_disk_types[type]);
		return EINVAL;
	}

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch(c) {
		default:
			fprintf(stderr, "Unknown option %c\n", (char)c);
		case 'h':
			goto usage;
		}
	}

	if (optind != (argc - 3))
		goto usage;

	name  = argv[optind++];

	field = get_field(argv[optind]);
	if (!field || field->id != TD_FIELD_HIDDEN) {
		fprintf(stderr, "Invalid field %s\n", argv[optind]);
		goto usage;
	}

	value = argv[++optind];

	cargc = 0;
	memset(cargv, 0, sizeof(cargv));
	cargv[cargc++] = "set";
	cargv[cargc++] = "-n";
	cargv[cargc++] = name;
	cargv[cargc++] = "-f";
	cargv[cargc++] = field->name;
	cargv[cargc++] = "-v";
	cargv[cargc++] = value;
	return vhd_util_set_field(cargc, cargv);

 usage:
	fprintf(stderr, "usage: td-util set %s [-h help] "
		"<FILENAME> <FIELD> <VALUE>\n", td_disk_types[type]);
	print_field_names();
	return EINVAL;
}

int
main(int argc, char *argv[])
{
	char **cargv;
	struct command *cmd;
	int cargc, i, type = -1, ret = 0;

#ifdef CORE_DUMP
	struct rlimit rlim;
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		fprintf(stderr, "setrlimit failed: %d\n", errno);
#endif

	if (argc < 2)
		help();

	cargc = argc - 1;
	cmd   = get_command(argv[1]);
	if (!cmd) {
		fprintf(stderr, "invalid COMMAND %s\n", argv[1]);
		help();
	}

	if (cmd->needs_type) {
		if (argc < 3) {
			fprintf(stderr, "td-util %s requires a TYPE\n",
				cmd->name);
			print_disk_types();
			exit(-1);
		}

		type = get_driver_type(argv[2]);
		if (type < 0) {
			fprintf(stderr, "invalid TYPE '%s'.\n", argv[2]);
			print_disk_types();
			exit(-1);
		}
		--cargc;
	}

	cargv = malloc(sizeof(char *) * cargc);
	if (!cargv)
		exit(ENOMEM);

	cargv[0] = cmd->name;
	for (i = 1; i < cargc; i++)
		cargv[i] = argv[i + (argc - cargc)];

	switch(cmd->id) {
	case TD_CMD_CREATE:
		ret = td_create(type, cargc, cargv);
		break;
	case TD_CMD_SNAPSHOT:
		ret = td_snapshot(type, cargc, cargv);
		break;
/*
	case TD_CMD_COALESCE:
		ret = td_coalesce(type, cargc, cargv);
		break;
*/
	case TD_CMD_QUERY:
		ret = td_query(type, cargc, cargv);
		break;
/*
	case TD_CMD_RESIZE:
		ret = td_resize(type, cargc, cargv);
		break;
*/
	case TD_CMD_SET:
		ret = td_set_field(type, cargc, cargv);
		break;
/*
	case TD_CMD_REPAIR:
		ret = td_repair(type, cargc, cargv);
		break;
	case TD_CMD_FILL:
		ret = td_fill(type, cargc, cargv);
		break;
	case TD_CMD_READ:
		ret = td_read(type, cargc, cargv);
		break;
*/
	default:
	case TD_CMD_INVALID:
		ret = EINVAL;
		break;
	}

	free(cargv);

	return (ret >= 0 ? ret : -ret);
}
