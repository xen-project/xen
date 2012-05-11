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
#include <stdlib.h>
#include <unistd.h>
#ifdef MEMSHR
#include <memshr.h>
#endif

#include "tapdisk.h"
#include "tapdisk-utils.h"
#include "tapdisk-server.h"
#include "tapdisk-control.h"

static void
usage(const char *app, int err)
{
	fprintf(stderr, "usage: %s [-D] <-u uuid> <-c control socket>\n", app);
	exit(err);
}

int
main(int argc, char *argv[])
{
	char *control;
	int c, err, nodaemon;

	control  = NULL;
	nodaemon = 0;

	while ((c = getopt(argc, argv, "s:Dh")) != -1) {
		switch (c) {
		case 'D':
			nodaemon = 1;
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

	if (optind != argc)
		usage(argv[0], EINVAL);

	if (chdir("/")) {
		DPRINTF("failed to chdir(/): %d\n", errno);
		err = 1;
		goto out;
	}

	tapdisk_start_logging("tapdisk2");

	err = tapdisk_server_init();
	if (err) {
		DPRINTF("failed to initialize server: %d\n", err);
		goto out;
	}

	if (!nodaemon) {
		err = daemon(0, 1);
		if (err) {
			DPRINTF("failed to daemonize: %d\n", errno);
			goto out;
		}
	}

	err = tapdisk_control_open(&control);
	if (err) {
		DPRINTF("failed to open control socket: %d\n", err);
		goto out;
	}

	fprintf(stdout, "%s\n", control);
	fflush(stdout);

	if (!nodaemon) {
		int fd;

		fd = open("/dev/null", O_RDWR);
		if (fd != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}
	}

	err = tapdisk_server_complete();
	if (err) {
		DPRINTF("failed to complete server: %d\n", err);
		goto out;
	}

	err = tapdisk_server_run();

out:
	tapdisk_control_close();
	tapdisk_stop_logging();
	return err;
}
