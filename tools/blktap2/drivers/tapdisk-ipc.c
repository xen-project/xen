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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "tapdisk.h"
#include "tapdisk-ipc.h"
#include "tapdisk-vbd.h"
#include "tapdisk-server.h"

static void
tapdisk_ipc_read_event(event_id_t id, char mode, void *private)
{
	td_ipc_t *ipc = private;
	tapdisk_ipc_read(ipc);
}

static void
__tapdisk_ipc_init(td_ipc_t *ipc)
{
	ipc->rfd = -1;
	ipc->wfd = -1;
	ipc->rfd_event = -1;
}

int
tapdisk_ipc_open(td_ipc_t *ipc, const char *read, const char *write)
{
	int err;

	memset(ipc, 0, sizeof(td_ipc_t));
	__tapdisk_ipc_init(ipc);

	if (read) {
		ipc->rfd = open(read, O_RDWR | O_NONBLOCK);
		if (ipc->rfd < 0) {
			err = -errno;
			EPRINTF("FD open failed %s: %d\n", read, err);
			goto fail;
		}

		ipc->rfd_event = 
			tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
						      ipc->rfd, 0,
						      tapdisk_ipc_read_event,
						      ipc);
		if (ipc->rfd_event < 0) {
			err = ipc->rfd_event;
			goto fail;
		}
	}

	if (write) {
		ipc->wfd = open(write, O_RDWR | O_NONBLOCK);
		if (ipc->wfd < 0) {
			err = -errno;
			EPRINTF("FD open failed %s, %d\n", write, err);
			goto fail;
		}
	}

	return 0;

fail:
	tapdisk_ipc_close(ipc);
	return err;
}

void
tapdisk_ipc_close(td_ipc_t *ipc)
{
	if (ipc->rfd > 0)
		close(ipc->rfd);

	if (ipc->wfd > 0)
		close(ipc->wfd);

	if (ipc->rfd_event >= 0)
		tapdisk_server_unregister_event(ipc->rfd_event);

	__tapdisk_ipc_init(ipc);
}

static int
tapdisk_ipc_write_message(int fd, tapdisk_message_t *message, int timeout)
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

	DPRINTF("sending '%s' message (uuid = %u)\n",
		tapdisk_message_name(message->type), message->cookie);

	while (offset < len) {
		FD_ZERO(&writefds);
		FD_SET(fd, &writefds);

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, NULL, &writefds, NULL, t);
		if (ret == -1)
			break;
		else if (FD_ISSET(fd, &writefds)) {
			ret = write(fd, message + offset, len - offset);
			if (ret <= 0)
				break;
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
tapdisk_ipc_write(td_ipc_t *ipc, int type)
{
	tapdisk_message_t message;

	if (ipc->wfd == -1)
		return 0;

	memset(&message, 0, sizeof(tapdisk_message_t));
	message.type   = type;
	message.cookie = ipc->uuid;

	return tapdisk_ipc_write_message(ipc->wfd, &message, 2);
}

int
tapdisk_ipc_write_error(td_ipc_t *ipc, const char *text)
{
	tapdisk_message_t message;

	memset(&message, 0, sizeof(message));
	message.type   = TAPDISK_MESSAGE_RUNTIME_ERROR;
	message.cookie = ipc->uuid;
	snprintf(message.u.string.text, sizeof(message.u.string.text), "%s", text);

	return tapdisk_ipc_write_message(ipc->wfd, &message, 2);
}

static int
tapdisk_ipc_read_message(int fd, tapdisk_message_t *message, int timeout)
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

		/* we don't bother reinitializing tv. at worst, it will wait a
		 * bit more time than expected. */

		ret = select(fd + 1, &readfds, NULL, NULL, t);
		if (ret == -1)
			break;
		else if (FD_ISSET(fd, &readfds)) {
			ret = read(fd, message + offset, len - offset);
			if (ret <= 0)
				break;
			offset += ret;
		} else
			break;
	}

	if (offset != len) {
		EPRINTF("failure reading message\n");
		return -EIO;
	}

	DPRINTF("received '%s' message (uuid = %u)\n",
		tapdisk_message_name(message->type), message->cookie);

	return 0;
}

int
tapdisk_ipc_read(td_ipc_t *ipc)
{
	int err;
	td_vbd_t *vbd;
	td_uuid_t uuid;
	tapdisk_message_t message;

	err = tapdisk_ipc_read_message(ipc->rfd, &message, 2);
	if (err) {
		tapdisk_server_check_state();
		return err;
	}

	uuid = message.cookie;
	vbd  = tapdisk_server_get_vbd(uuid);

	if (!vbd && message.type != TAPDISK_MESSAGE_PID) {
		EPRINTF("received message for non-existing vbd: %u\n", uuid);
		err = -EINVAL;
		goto fail;
	}

	switch (message.type) {
	case TAPDISK_MESSAGE_PID:
		err = tapdisk_vbd_initialize(ipc->rfd, ipc->wfd, uuid);

		memset(&message, 0, sizeof(tapdisk_message_t));
		message.cookie = uuid;

		if (!err) {
			message.type          = TAPDISK_MESSAGE_PID_RSP;
			message.u.tapdisk_pid = getpid();
		} else
			message.type          = TAPDISK_MESSAGE_ERROR;

		return tapdisk_ipc_write_message(ipc->wfd, &message, 0);

	case TAPDISK_MESSAGE_OPEN:
	{
		image_t image;
		char *devname;
		td_flag_t flags;

		flags = 0;

		if (message.u.params.flags & TAPDISK_MESSAGE_FLAG_RDONLY)
			flags |= TD_OPEN_RDONLY;
		if (message.u.params.flags & TAPDISK_MESSAGE_FLAG_SHARED)
			flags |= TD_OPEN_SHAREABLE;
		if (message.u.params.flags & TAPDISK_MESSAGE_FLAG_ADD_CACHE)
			flags |= TD_OPEN_ADD_CACHE;
		if (message.u.params.flags & TAPDISK_MESSAGE_FLAG_VHD_INDEX)
			flags |= TD_OPEN_VHD_INDEX;
		if (message.u.params.flags & TAPDISK_MESSAGE_FLAG_LOG_DIRTY)
			flags |= TD_OPEN_LOG_DIRTY;

		err   = asprintf(&devname, "%s/%s%d",
				 BLKTAP_DEV_DIR, BLKTAP_DEV_NAME,
				 message.u.params.devnum);
		if (err == -1)
			goto fail;

		err   = tapdisk_vbd_open(vbd,
					 message.u.params.path,
					 message.drivertype,
					 message.u.params.storage,
					 devname, flags);
		free(devname);
		if (err)
			goto fail;

		err   = tapdisk_vbd_get_image_info(vbd, &image);
		if (err)
			goto fail;

		memset(&message, 0, sizeof(tapdisk_message_t));
		message.cookie              = uuid;
		message.u.image.sectors     = image.size;
		message.u.image.sector_size = image.secsize;
		message.u.image.info        = image.info;
		message.type                = TAPDISK_MESSAGE_OPEN_RSP;

		return tapdisk_ipc_write_message(ipc->wfd, &message, 0);
	}

	case TAPDISK_MESSAGE_PAUSE:
		tapdisk_vbd_pause(vbd);
		return 0; /* response written asynchronously */

	case TAPDISK_MESSAGE_RESUME:
		tapdisk_vbd_resume(vbd,
				   message.u.params.path,
				   message.drivertype);
		return 0; /* response written asynchronously */

	case TAPDISK_MESSAGE_CLOSE:
		tapdisk_vbd_close(vbd);
		return 0; /* response written asynchronously */

	case TAPDISK_MESSAGE_EXIT:
		return 0;
	}

	err = -EINVAL;
	EPRINTF("received unrecognized message %s, uuid = %d\n",
		tapdisk_message_name(message.type), uuid);

fail:
	memset(&message, 0, sizeof(tapdisk_message_t));
	message.cookie = uuid;
	message.type   = TAPDISK_MESSAGE_ERROR;
	tapdisk_ipc_write_message(ipc->wfd, &message, 2);
	tapdisk_server_check_state();

	return -err;
}
