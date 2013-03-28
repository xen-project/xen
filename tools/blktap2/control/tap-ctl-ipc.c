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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tap-ctl.h"
#include "blktap2.h"

int tap_ctl_debug = 0;

int
tap_ctl_read_message(int fd, tapdisk_message_t *message, int timeout)
{
	fd_set readfds;
	int ret, len, offset;
	struct timeval tv, *t;

	t      = NULL;
	offset = 0;
	len    = sizeof(tapdisk_message_t);

	if (timeout) {
		tv.tv_sec  = timeout;
		tv.tv_usec = 0;
		t = &tv;
	}

	memset(message, 0, sizeof(tapdisk_message_t));

	while (offset < len) {
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		ret = select(fd + 1, &readfds, NULL, NULL, t);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		else if (FD_ISSET(fd, &readfds)) {
			ret = read(fd, message + offset, len - offset);
			if (ret <= 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			offset += ret;
		} else
			break;
	}

	if (offset != len) {
		EPRINTF("failure reading message\n");
		return -EIO;
	}

	DBG("received '%s' message (uuid = %u)\n",
	    tapdisk_message_name(message->type), message->cookie);

	return 0;
}

int
tap_ctl_write_message(int fd, tapdisk_message_t *message, int timeout)
{
	fd_set writefds;
	int ret, len, offset;
	struct timeval tv, *t;

	t      = NULL;
	offset = 0;
	len    = sizeof(tapdisk_message_t);

	if (timeout) {
		tv.tv_sec  = timeout;
		tv.tv_usec = 0;
		t = &tv;
	}

	DBG("sending '%s' message (uuid = %u)\n",
	    tapdisk_message_name(message->type), message->cookie);

	while (offset < len) {
		FD_ZERO(&writefds);
		FD_SET(fd, &writefds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, NULL, &writefds, NULL, t);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		else if (FD_ISSET(fd, &writefds)) {
			ret = write(fd, message + offset, len - offset);
			if (ret <= 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			offset += ret;
		} else
			break;
	}

	if (offset != len) {
		EPRINTF("failure writing message\n");
		return -EIO;
	}

	return 0;
}

int
tap_ctl_send_and_receive(int sfd, tapdisk_message_t *message, int timeout)
{
	int err;

	err = tap_ctl_write_message(sfd, message, timeout);
	if (err) {
		EPRINTF("failed to send '%s' message\n",
			tapdisk_message_name(message->type));
		return err;
	}

	err = tap_ctl_read_message(sfd, message, timeout);
	if (err) {
		EPRINTF("failed to receive '%s' message\n",
			tapdisk_message_name(message->type));
		return err;
	}

	return 0;
}

char *
tap_ctl_socket_name(int id)
{
	char *name;

	if (asprintf(&name, "%s/%s%d",
		     BLKTAP2_CONTROL_DIR, BLKTAP2_CONTROL_SOCKET, id) == -1)
		return NULL;

	return name;
}

int
tap_ctl_connect(const char *name, int *sfd)
{
	int fd, err;
	struct sockaddr_un saddr;

	*sfd = -1;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		EPRINTF("couldn't create socket for %s: %d\n", name, errno);
		return -errno;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	strcpy(saddr.sun_path, name);

	err = connect(fd, (const struct sockaddr *)&saddr, sizeof(saddr));
	if (err) {
		EPRINTF("couldn't connect to %s: %d\n", name, errno);
		close(fd);
		return -errno;
	}

	*sfd = fd;
	return 0;
}

int
tap_ctl_connect_id(int id, int *sfd)
{
	int err;
	char *name;

	*sfd = -1;

	if (id < 0) {
		EPRINTF("invalid id %d\n", id);
		return -EINVAL;
	}

	name = tap_ctl_socket_name(id);
	if (!name) {
		EPRINTF("couldn't name socket for %d\n", id);
		return -ENOMEM;
	}

	err = tap_ctl_connect(name, sfd);
	free(name);

	return err;
}

int
tap_ctl_connect_send_and_receive(int id, tapdisk_message_t *message, int timeout)
{
	int err, sfd;

	err = tap_ctl_connect_id(id, &sfd);
	if (err)
		return err;

	err = tap_ctl_send_and_receive(sfd, message, timeout);

	close(sfd);
	return err;
}
