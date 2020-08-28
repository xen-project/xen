/**
 * @file
 * @section AUTHORS
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 *  Authors:
 *       Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *       Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *
 * @section LICENSE
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * @section DESCRIPTION
 *
 * This is a test program for libxenvchan.  Communications are bidirectional,
 * with either server (grant offeror) or client able to read and write.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <libxenvchan.h>

static void usage(char** argv)
{
	fprintf(stderr, "usage:\n"
		"\t%s [client|server] domainid nodepath [rbufsiz wbufsiz]\n",
		argv[0]);
	exit(1);
}

#define BUFSIZE 5000
char inbuf[BUFSIZE];
char outbuf[BUFSIZE];
int insiz = 0;
int outsiz = 0;
struct libxenvchan *ctrl = 0;

static void vchan_wr(void) {
	int ret;

	if (!insiz)
		return;
	ret = libxenvchan_write(ctrl, inbuf, insiz);
	if (ret < 0) {
		fprintf(stderr, "vchan write failed\n");
		exit(1);
	}
	if (ret > 0) {
		insiz -= ret;
		memmove(inbuf, inbuf + ret, insiz);
	}
}

static void stdout_wr(void) {
	int ret;

	if (!outsiz)
		return;
	ret = write(1, outbuf, outsiz);
	if (ret < 0 && errno != EAGAIN)
		exit(1);
	if (ret > 0) {
		outsiz -= ret;
		memmove(outbuf, outbuf + ret, outsiz);
	}
}

static int set_nonblocking(int fd, int nonblocking) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	if (nonblocking)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		return -1;

	return 0;
}

/**
    Simple libxenvchan application, both client and server.
	Both sides may write and read, both from the libxenvchan and from 
	stdin/stdout (just like netcat).
*/

int main(int argc, char **argv)
{
	int ret;
	int libxenvchan_fd;
	if (argc < 4 || argv[3][0] != '/')
		usage(argv);
	if (!strcmp(argv[1], "server")) {
		int rsiz = argc > 4 ? atoi(argv[4]) : 0;
		int wsiz = argc > 5 ? atoi(argv[5]) : 0;
		ctrl = libxenvchan_server_init(NULL, atoi(argv[2]), argv[3], rsiz, wsiz);
	} else if (!strcmp(argv[1], "client"))
		ctrl = libxenvchan_client_init(NULL, atoi(argv[2]), argv[3]);
	else
		usage(argv);
	if (!ctrl) {
		perror("libxenvchan_*_init");
		exit(1);
	}

	if (set_nonblocking(0, 1) || set_nonblocking(1, 1)) {
		perror("set_nonblocking");
		exit(1);
	}

	libxenvchan_fd = libxenvchan_fd_for_select(ctrl);
	for (;;) {
		fd_set rfds;
		fd_set wfds;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (insiz != BUFSIZE)
			FD_SET(0, &rfds);
		if (outsiz)
			FD_SET(1, &wfds);
		FD_SET(libxenvchan_fd, &rfds);
		ret = select(libxenvchan_fd + 1, &rfds, &wfds, NULL, NULL);
		if (ret < 0) {
			perror("select");
			exit(1);
		}
		if (FD_ISSET(0, &rfds)) {
			ret = read(0, inbuf + insiz, BUFSIZE - insiz);
			if (ret < 0 && errno != EAGAIN)
				exit(1);
			if (ret == 0) {
				while (insiz) {
					vchan_wr();
					libxenvchan_wait(ctrl);
				}
				return 0;
			}
			if (ret)
				insiz += ret;
			vchan_wr();
		}
		if (FD_ISSET(libxenvchan_fd, &rfds)) {
			libxenvchan_wait(ctrl);
			vchan_wr();
		}
		if (FD_ISSET(1, &wfds))
			stdout_wr();
		while (libxenvchan_data_ready(ctrl) && outsiz < BUFSIZE) {
			ret = libxenvchan_read(ctrl, outbuf + outsiz, BUFSIZE - outsiz);
			if (ret < 0)
				exit(1);
			outsiz += ret;
			stdout_wr();
		}
		if (!libxenvchan_is_open(ctrl)) {
			if (set_nonblocking(1, 0)) {
				perror("set_nonblocking");
				exit(1);
			}
			while (outsiz)
				stdout_wr();
			return 0;
		}
	}
}
