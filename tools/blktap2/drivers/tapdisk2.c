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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#ifdef MEMSHR
#include <memshr.h>
#endif

#include "tapdisk.h"
#include "blktap2.h"
#include "tapdisk-vbd.h"
#include "tapdisk-utils.h"
#include "tapdisk-server.h"

#define TAPDISK2_VBD 0

#define cprintf(_err, _f, _a...)					\
	do {								\
		if (child_out) {					\
			fprintf(child_out, "%d: " _f, _err, ##_a);	\
			fflush(child_out);				\
		}							\
	} while (0)

#define CHILD_ERR(_err, _f, _a...)					\
	do {								\
		EPRINTF(_f, ##_a);					\
		cprintf(_err, _f, ##_a);				\
	} while (0)

static int channel[2];
static FILE *child_out;
static struct blktap2_handle handle;

static int
tapdisk2_prepare_directory(void)
{
	int err;
	char *ptr, *name, *start;

	err = access(BLKTAP2_DIRECTORY, W_OK | R_OK);
	if (!err)
		return 0;

	name = strdup(BLKTAP2_DIRECTORY);
	if (!name)
		return -ENOMEM;

	start = name;

	for (;;) {
		ptr = strchr(start + 1, '/');
		if (ptr)
			*ptr = '\0';

		err = mkdir(name, 0755);
		if (err && errno != EEXIST) {
			err = -errno;
			CHILD_ERR(err, "failed to create directory %s: %d\n",
				  name, err);
			break;
		}

		if (!ptr)
			break;
		else {
			*ptr = '/';
			start = ptr + 1;
		}
	}

	free(name);
	return err;
}

static int
tapdisk2_make_device(char *devname, int major, int minor, int perm)
{
	int err;
	struct stat st;

	err = tapdisk2_prepare_directory();
	if (err)
		return err;

	if (!access(devname, F_OK))
		if (unlink(devname)) {
			CHILD_ERR(errno, "error unlinking %s: %d\n",
				  devname, errno);
			return -errno;
		}

	err = mknod(devname, perm, makedev(major, minor));
	if (err) {
		CHILD_ERR(errno, "mknod %s failed: %d\n", devname, -errno);
		return -errno;
	}

	DPRINTF("Created %s device\n", devname);
	return 0;
}

static int
tapdisk2_check_environment(void)
{
	FILE *f;
	int err, minor;
	char name[256];

	if (!access(BLKTAP2_CONTROL_DEVICE, R_OK | W_OK))
		return 0;

	memset(name, 0, sizeof(name));

	f = fopen("/proc/misc", "r");
	if (!f) {
		CHILD_ERR(errno, "failed to open /proc/misc: %d\n", errno);
		return -errno;
	}

	while (fscanf(f, "%d %256s", &minor, name) == 2)
		if (!strcmp(name, BLKTAP2_CONTROL_NAME)) {
			err = tapdisk2_make_device(BLKTAP2_CONTROL_DEVICE,
						   MISC_MAJOR_NUMBER,
						   minor, S_IFCHR | 0600);
			goto out;
		}

	err = -ENOSYS;
	CHILD_ERR(err, "didn't find %s in /proc/misc\n", BLKTAP2_CONTROL_NAME);

out:
	fclose(f);
	return err;
}

static void
tapdisk2_free_device(void)
{
	int fd, err;

	fd = open(BLKTAP2_CONTROL_DEVICE, O_RDONLY);
	if (fd == -1) {
		CHILD_ERR(errno, "failed to open control device: %d\n", errno);
		return;
	}

	err = ioctl(fd, BLKTAP2_IOCTL_FREE_TAP, handle.minor);
	close(fd);
}

static int
tapdisk2_prepare_device(void)
{
	char *name;
	int fd, err;

	fd = open(BLKTAP2_CONTROL_DEVICE, O_RDONLY);
	if (fd == -1) {
		CHILD_ERR(errno, "failed to open control device: %d\n", errno);
		return -errno;
	}

	err = ioctl(fd, BLKTAP2_IOCTL_ALLOC_TAP, &handle);
	close(fd);
	if (err == -1) {
		CHILD_ERR(errno, "failed to allocate new device: %d\n", errno);
		return -errno;
	}

	err = asprintf(&name, "%s%d", BLKTAP2_RING_DEVICE, handle.minor);
	if (err == -1) {
		err = -ENOMEM;
		goto fail;
	}

	err = tapdisk2_make_device(name, handle.ring,
				   handle.minor, S_IFCHR | 0600);
	free(name);
	if (err) {
		CHILD_ERR(err, "creating ring device for %d failed: %d\n",
			  handle.minor, err);
		goto fail;
	}

	err = asprintf(&name, "%s%d", BLKTAP2_IO_DEVICE, handle.minor);
	if (err == -1) {
		err = -ENOMEM;
		goto fail;
	}

	err = tapdisk2_make_device(name, handle.device,
				   handle.minor, S_IFBLK | 0600);
	free(name);
	if (err) {
		CHILD_ERR(err, "creating IO device for %d failed: %d\n",
			  handle.minor, err);
		goto fail;
	}

	DPRINTF("new interface: ring: %u, device: %u, minor: %u\n",
		handle.ring, handle.device, handle.minor);

	return 0;

fail:
	tapdisk2_free_device();
	return err;
}

static int
tapdisk2_open_device(int type, const char *path, const char *name)
{
	int err;
	td_vbd_t *vbd;
	image_t image;
	char *devname;
	struct blktap2_params params;

	err = tapdisk_vbd_initialize(TAPDISK2_VBD);
	if (err)
		return err;

	vbd = tapdisk_server_get_vbd(TAPDISK2_VBD);
	if (!vbd) {
		err = -ENODEV;
		CHILD_ERR(err, "couldn't find vbd\n");
		return err;
	}

	err = asprintf(&devname, "%s%d", BLKTAP2_RING_DEVICE, handle.minor);
	if (err == -1) {
		err = -ENOMEM;
		CHILD_ERR(err, "couldn't allocate ring\n");
		return err;
	}

	err = tapdisk_vbd_parse_stack(vbd, name);
	if (err) {
		CHILD_ERR(err, "vbd_parse_stack failed: %d\n", err);
		return err;
	}

	/* TODO: clean this up */
	err = tapdisk_vbd_open(vbd, path, type,
			       TAPDISK_STORAGE_TYPE_DEFAULT,
			       devname, 0);
	free(devname);
	if (err) {
		CHILD_ERR(err, "vbd open failed: %d\n", err);
		return err;
	}

	memset(&params, 0, sizeof(params));
	tapdisk_vbd_get_image_info(vbd, &image);

	params.capacity    = image.size;
	params.sector_size = image.secsize;
	snprintf(params.name, sizeof(params.name) - 1, "%s", name);

	err = ioctl(vbd->ring.fd, BLKTAP2_IOCTL_CREATE_DEVICE, &params);
	if (err) {
		err = -errno;
		CHILD_ERR(err, "create device failed: %d\n", err);
		return err;
	}

	return 0;
}

static int
tapdisk2_set_child_fds(void)
{
	int i, err;

	err = dup2(channel[1], STDOUT_FILENO);
	if (err == -1) {
		CHILD_ERR(errno, "failed duping pipe: %d\n", errno);
		return errno;
	}

	child_out = fdopen(STDOUT_FILENO, "w");
	if (!child_out) {
		CHILD_ERR(errno, "failed setting child_out: %d\n", errno);
		return errno;
	}

	for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
		if (i != STDOUT_FILENO)
			close(i);

	return 0;
}

static int
tapdisk2_create_device(const char *params)
{
	char *path;
	int err, type;

	chdir("/");
	tapdisk_start_logging("tapdisk2");

	err = tapdisk2_set_child_fds();
	if (err)
		goto out;

	err = tapdisk2_check_environment();
	if (err)
		goto out;

	err = tapdisk_parse_disk_type(params, &path, &type);
	if (err)
		goto out;

	err = tapdisk2_prepare_device();
	if (err)
		goto out;

	err = tapdisk_server_initialize();
	if (err)
		goto fail;

	err = tapdisk2_open_device(type, path, params);
	if (err)
		goto fail;

	cprintf(0, "%s%d\n", BLKTAP2_IO_DEVICE, handle.minor);
	close(STDOUT_FILENO);

	err = tapdisk_server_run();
	if (err)
		goto fail;

	err = 0;

out:
	tapdisk_stop_logging();
	return err;

fail:
	tapdisk2_free_device();
	goto out;
}

static int
tapdisk2_wait_for_device(void)
{
	int err;
	char msg[1024];
	FILE *parent_in;

	close(channel[1]);
	parent_in = fdopen(channel[0], "r");
	if (!parent_in) {
		printf("failed to connect to child: %d\n", errno);
		return errno;
	}

	memset(msg, 0, sizeof(msg));
	if (fscanf(parent_in, "%d: %1023[^\n]", &err, msg) != 2) {
		printf("unrecognized child response\n");
		return EINVAL;
	}

	printf("%s\n", msg);
	return (err >= 0 ? err : -err);
}

static void
usage(const char *app, int err)
{
	fprintf(stderr, "usage: %s <-n file>\n", app);
	exit(err);
}

int
main(int argc, char *argv[])
{
	int c;
	char *params;

	params = NULL;

	while ((c = getopt(argc, argv, "n:s:h")) != -1) {
		switch (c) {
		case 'n':
			params = optarg;
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		case 's':
#ifdef MEMSHR
			memshr_set_domid(atoi(optarg));
#else
			fprintf(stderr, "MEMSHR support not compiled in.\n");
			exit(EXIT_FAILURE);
#endif
			break;
		default:
			usage(argv[0], EINVAL);
		}
	}

	if (!params || optind != argc)
		usage(argv[0], EINVAL);

	if (pipe(channel) == -1) {
		printf("pipe failed: %d\n", errno);
		return errno;
	}

	switch (fork()) {
	case -1:
		printf("fork failed: %d\n", errno);
		return errno;
	case 0:
		return tapdisk2_create_device(params);
	default:
		return tapdisk2_wait_for_device();
	}
}
