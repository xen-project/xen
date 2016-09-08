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
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "list.h"
#include "tapdisk.h"
#include "blktap2.h"
#include "blktaplib.h"
#include "tapdisk-vbd.h"
#include "tapdisk-utils.h"
#include "tapdisk-server.h"
#include "tapdisk-message.h"
#include "tapdisk-disktype.h"

struct tapdisk_control {
	char              *path;
	int                socket;
	int                event_id;
};

struct tapdisk_control_connection {
	int                socket;
	event_id_t         event_id;
};

static struct tapdisk_control td_control;

static void
tapdisk_control_initialize(void)
{
	td_control.socket   = -1;
	td_control.event_id = -1;

	signal(SIGPIPE, SIG_IGN);
}

void
tapdisk_control_close(void)
{
	if (td_control.path) {
		unlink(td_control.path);
		free(td_control.path);
		td_control.path = NULL;
	}

	if (td_control.socket != -1) {
		close(td_control.socket);
		td_control.socket = -1;
	}
}

static struct tapdisk_control_connection *
tapdisk_control_allocate_connection(int fd)
{
	struct tapdisk_control_connection *connection;
	size_t sz;

	connection = calloc(1, sizeof(*connection));
	if (!connection) {
		EPRINTF("calloc");
		return NULL;
	}

	connection->socket = fd;
	return connection;
}

static void
tapdisk_control_close_connection(struct tapdisk_control_connection *connection)
{
	tapdisk_server_unregister_event(connection->event_id);
	close(connection->socket);
	free(connection);
}

static int
tapdisk_control_read_message(int fd, tapdisk_message_t *message, int timeout)
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
		EPRINTF("failure reading message (wanted %d but got %d)\n",
			len, offset);
		return -EIO;
	}

	DPRINTF("received '%s' message (uuid = %u)\n",
		tapdisk_message_name(message->type), message->cookie);

	return 0;
}

static int
tapdisk_control_write_message(int fd, tapdisk_message_t *message, int timeout)
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

static int
tapdisk_control_validate_request(tapdisk_message_t *request)
{
	if (strnlen(request->u.params.path,
		    TAPDISK_MESSAGE_MAX_PATH_LENGTH) >=
	    TAPDISK_MESSAGE_MAX_PATH_LENGTH)
		return EINVAL;

	return 0;
}

static void
tapdisk_control_list_minors(struct tapdisk_control_connection *connection,
			    tapdisk_message_t *request)
{
	int i;
	td_vbd_t *vbd;
	struct list_head *head;
	tapdisk_message_t response;

	i = 0;
	memset(&response, 0, sizeof(response));

	response.type = TAPDISK_MESSAGE_LIST_MINORS_RSP;
	response.cookie = request->cookie;

	head = tapdisk_server_get_all_vbds();

	list_for_each_entry(vbd, head, next) {
		response.u.minors.list[i++] = vbd->minor;
		if (i >= TAPDISK_MESSAGE_MAX_MINORS) {
			response.type = TAPDISK_MESSAGE_ERROR;
			response.u.response.error = ERANGE;
			break;
		}
	}

	response.u.minors.count = i;
	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_list(struct tapdisk_control_connection *connection,
		     tapdisk_message_t *request)
{
	td_vbd_t *vbd;
	struct list_head *head;
	tapdisk_message_t response;
	int count, i;

	memset(&response, 0, sizeof(response));
	response.type = TAPDISK_MESSAGE_LIST_RSP;
	response.cookie = request->cookie;

	head = tapdisk_server_get_all_vbds();

	count = 0;
	list_for_each_entry(vbd, head, next)
		count++;

	list_for_each_entry(vbd, head, next) {
		response.u.list.count   = count--;
		response.u.list.minor   = vbd->minor;
		response.u.list.state   = vbd->state;
		response.u.list.path[0] = 0;

		if (!list_empty(&vbd->images)) {
			td_image_t *image = list_entry(vbd->images.next,
						       td_image_t, next);
			snprintf(response.u.list.path,
				 sizeof(response.u.list.path),
				 "%s:%s",
				 tapdisk_disk_types[image->type]->name,
				 image->name);
		}

		tapdisk_control_write_message(connection->socket, &response, 2);
	}

	response.u.list.count   = count;
	response.u.list.minor   = -1;
	response.u.list.path[0] = 0;

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_get_pid(struct tapdisk_control_connection *connection,
			tapdisk_message_t *request)
{
	tapdisk_message_t response;

	memset(&response, 0, sizeof(response));
	response.type = TAPDISK_MESSAGE_PID_RSP;
	response.cookie = request->cookie;
	response.u.tapdisk_pid = getpid();

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_attach_vbd(struct tapdisk_control_connection *connection,
			   tapdisk_message_t *request)
{
	tapdisk_message_t response;
	char *devname;
	td_vbd_t *vbd;
	struct blktap2_params params;
	image_t image;
	int minor, err;

	/*
	 * TODO: check for max vbds per process
	 */

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (vbd) {
		err = -EEXIST;
		goto out;
	}

	minor = request->cookie;
	if (minor < 0) {
		err = -EINVAL;
		goto out;
	}

	vbd = tapdisk_vbd_create(minor);
	if (!vbd) {
		err = -ENOMEM;
		goto out;
	}

	err = asprintf(&devname, BLKTAP2_RING_DEVICE"%d", minor);
	if (err == -1) {
		err = -ENOMEM;
		goto fail_vbd;
	}

	err = tapdisk_vbd_attach(vbd, devname, minor);
	free(devname);
	if (err)
		goto fail_vbd;

	tapdisk_server_add_vbd(vbd);

out:
	memset(&response, 0, sizeof(response));
	response.type = TAPDISK_MESSAGE_ATTACH_RSP;
	response.cookie = request->cookie;
	response.u.response.error = -err;

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);

	return;

fail_vbd:
	tapdisk_vbd_detach(vbd);
	free(vbd);
	goto out;
}


static void
tapdisk_control_detach_vbd(struct tapdisk_control_connection *connection,
			   tapdisk_message_t *request)
{
	tapdisk_message_t response;
	td_vbd_t *vbd;
	int err;

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (!vbd) {
		err = -EINVAL;
		goto out;
	}

	tapdisk_vbd_detach(vbd);

	if (list_empty(&vbd->images)) {
		tapdisk_server_remove_vbd(vbd);
		free(vbd);
	}

	err = 0;
out:
	memset(&response, 0, sizeof(response));
	response.type = TAPDISK_MESSAGE_DETACH_RSP;
	response.cookie = request->cookie;
	response.u.response.error = -err;

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_open_image(struct tapdisk_control_connection *connection,
			   tapdisk_message_t *request)
{
	int err;
	image_t image;
	td_vbd_t *vbd;
	td_flag_t flags;
	tapdisk_message_t response;
	struct blktap2_params params;

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (!vbd) {
		err = -EINVAL;
		goto out;
	}

	if (vbd->minor == -1) {
		err = -EINVAL;
		goto out;
	}

	if (vbd->name) {
		err = -EALREADY;
		goto out;
	}

	flags = 0;
	if (request->u.params.flags & TAPDISK_MESSAGE_FLAG_RDONLY)
		flags |= TD_OPEN_RDONLY;
	if (request->u.params.flags & TAPDISK_MESSAGE_FLAG_SHARED)
		flags |= TD_OPEN_SHAREABLE;
	if (request->u.params.flags & TAPDISK_MESSAGE_FLAG_ADD_CACHE)
		flags |= TD_OPEN_ADD_CACHE;
	if (request->u.params.flags & TAPDISK_MESSAGE_FLAG_VHD_INDEX)
		flags |= TD_OPEN_VHD_INDEX;
	if (request->u.params.flags & TAPDISK_MESSAGE_FLAG_LOG_DIRTY)
		flags |= TD_OPEN_LOG_DIRTY;

	vbd->name = strndup(request->u.params.path,
			    sizeof(request->u.params.path));
	if (!vbd->name) {
		err = -ENOMEM;
		goto out;
	}

	err = tapdisk_vbd_parse_stack(vbd, request->u.params.path);
	if (err)
		goto out;

	err = tapdisk_vbd_open_stack(vbd, request->u.params.storage, flags);
	if (err)
		goto out;

	err = tapdisk_vbd_get_image_info(vbd, &image);
	if (err)
		goto fail_close;

	params.capacity = image.size;
	params.sector_size = image.secsize;
	strncpy(params.name, vbd->name, BLKTAP2_MAX_MESSAGE_LEN);

	err = ioctl(vbd->ring.fd, BLKTAP2_IOCTL_CREATE_DEVICE, &params);
	if (err && errno != EEXIST) {
		err = -errno;
		EPRINTF("create device failed: %d\n", err);
		goto fail_close;
	}

	err = 0;

out:
	memset(&response, 0, sizeof(response));
	response.cookie = request->cookie;

	if (err) {
		response.type                = TAPDISK_MESSAGE_ERROR;
		response.u.response.error    = -err;
	} else {
		response.u.image.sectors     = image.size;
		response.u.image.sector_size = image.secsize;
		response.u.image.info        = image.info;
		response.type                = TAPDISK_MESSAGE_OPEN_RSP;
	}

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);

	return;

fail_close:
	tapdisk_vbd_close_vdi(vbd);
	free(vbd->name);
	vbd->name = NULL;
	goto out;
}

static void
tapdisk_control_close_image(struct tapdisk_control_connection *connection,
			    tapdisk_message_t *request)
{
	tapdisk_message_t response;
	td_vbd_t *vbd;
	int err;

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (!vbd) {
		err = -EINVAL;
		goto out;
	}

	if (!list_empty(&vbd->pending_requests)) {
		err = -EAGAIN;
		goto out;
	}

	tapdisk_vbd_close_vdi(vbd);

	/* NB. vbd->name free should probably belong into close_vdi,
	   but the current blktap1 reopen-stuff likely depends on a
	   lifetime extended until shutdown. */
	free(vbd->name);
	vbd->name = NULL;

	if (vbd->minor == -1) {
		tapdisk_server_remove_vbd(vbd);
		tapdisk_vbd_free(vbd);
	}

	err = 0;
out:
	memset(&response, 0, sizeof(response));
	response.type = TAPDISK_MESSAGE_CLOSE_RSP;
	response.cookie = request->cookie;
	response.u.response.error = -err;

	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_pause_vbd(struct tapdisk_control_connection *connection,
			  tapdisk_message_t *request)
{
	int err;
	td_vbd_t *vbd;
	tapdisk_message_t response;

	memset(&response, 0, sizeof(response));

	response.type = TAPDISK_MESSAGE_PAUSE_RSP;

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (!vbd) {
		err = -EINVAL;
		goto out;
	}

	do {
		err = tapdisk_vbd_pause(vbd);

		if (!err || err != -EAGAIN)
			break;

		tapdisk_server_iterate();
	} while (1);

out:
	response.cookie = request->cookie;
	response.u.response.error = -err;
	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_resume_vbd(struct tapdisk_control_connection *connection,
			   tapdisk_message_t *request)
{
	int err;
	td_vbd_t *vbd;
	tapdisk_message_t response;

	memset(&response, 0, sizeof(response));

	response.type = TAPDISK_MESSAGE_RESUME_RSP;

	vbd = tapdisk_server_get_vbd(request->cookie);
	if (!vbd) {
		err = -EINVAL;
		goto out;
	}

	if (!td_flag_test(vbd->state, TD_VBD_PAUSED)) {
		err = -EINVAL;
		goto out;
	}

	if (request->u.params.path[0]) {
		free(vbd->name);
		vbd->name = strndup(request->u.params.path,
				    sizeof(request->u.params.path));
		if (!vbd->name) {
			err = -ENOMEM;
			goto out;
		}
	} else if (!vbd->name) {
		err = -EINVAL;
		goto out;
	}

	err = tapdisk_vbd_parse_stack(vbd, vbd->name);
	if (err)
		goto out;

	err = tapdisk_vbd_resume(vbd, NULL, -1);
	if (err)
		goto out;

out:
	response.cookie = request->cookie;
	response.u.response.error = -err;
	tapdisk_control_write_message(connection->socket, &response, 2);
	tapdisk_control_close_connection(connection);
}

static void
tapdisk_control_handle_request(event_id_t id, char mode, void *private)
{
	int err;
	tapdisk_message_t message;
	struct tapdisk_control_connection *connection =
		(struct tapdisk_control_connection *)private;

	if (tapdisk_control_read_message(connection->socket, &message, 2)) {
		EPRINTF("failed to read message from %d\n", connection->socket);
		tapdisk_control_close_connection(connection);
		return;
	}

	err = tapdisk_control_validate_request(&message);
	if (err)
		goto fail;

	switch (message.type) {
	case TAPDISK_MESSAGE_PID:
		return tapdisk_control_get_pid(connection, &message);
	case TAPDISK_MESSAGE_LIST_MINORS:
		return tapdisk_control_list_minors(connection, &message);
	case TAPDISK_MESSAGE_LIST:
		return tapdisk_control_list(connection, &message);
	case TAPDISK_MESSAGE_ATTACH:
		return tapdisk_control_attach_vbd(connection, &message);
	case TAPDISK_MESSAGE_DETACH:
		return tapdisk_control_detach_vbd(connection, &message);
	case TAPDISK_MESSAGE_OPEN:
		return tapdisk_control_open_image(connection, &message);
	case TAPDISK_MESSAGE_PAUSE:
		return tapdisk_control_pause_vbd(connection, &message);
	case TAPDISK_MESSAGE_RESUME:
		return tapdisk_control_resume_vbd(connection, &message);
	case TAPDISK_MESSAGE_CLOSE:
		return tapdisk_control_close_image(connection, &message);
	default: {
		tapdisk_message_t response;
	fail:

		EPRINTF("received unsupported message '%s'\n",
			tapdisk_message_name(message.type));

		memset(&response, 0, sizeof(response));

		response.type = TAPDISK_MESSAGE_ERROR;
		response.u.response.error = (err ? -err : EINVAL);
		tapdisk_control_write_message(connection->socket, &response, 2);

		tapdisk_control_close_connection(connection);
		break;
	}
	}
}

static void
tapdisk_control_accept(event_id_t id, char mode, void *private)
{
	int err, fd;
	struct tapdisk_control_connection *connection;

	fd = accept(td_control.socket, NULL, NULL);
	if (fd == -1) {
		EPRINTF("failed to accept new control connection: %d\n", errno);
		return;
	}

	connection = tapdisk_control_allocate_connection(fd);
	if (!connection) {
		close(fd);
		EPRINTF("failed to allocate new control connection\n");
	}

	err = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					    connection->socket, 0,
					    tapdisk_control_handle_request,
					    connection);
	if (err == -1) {
		close(fd);
		free(connection);
		EPRINTF("failed to register new control event: %d\n", err);
	}

	connection->event_id = err;
}

static int
tapdisk_control_mkdir(const char *dir)
{
	int err;
	char *ptr, *name, *start;

	err = access(dir, W_OK | R_OK);
	if (!err)
		return 0;

	name = strdup(dir);
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
			EPRINTF("failed to create directory %s: %d\n",
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
tapdisk_control_create_socket(char **socket_path)
{
	int err, flags;
	struct sockaddr_un saddr;

	err = tapdisk_control_mkdir(BLKTAP2_CONTROL_DIR);
	if (err) {
		EPRINTF("failed to create directory %s: %d\n",
			BLKTAP2_CONTROL_DIR, err);
		return err;
	}

	err = asprintf(&td_control.path, "%s/%s%d",
		       BLKTAP2_CONTROL_DIR, BLKTAP2_CONTROL_SOCKET, getpid());
	if (err == -1) {
		td_control.path = NULL;
		err = (errno ? : ENOMEM);
		goto fail;
	}

	if (unlink(td_control.path) && errno != ENOENT) {
		err = errno;
		EPRINTF("failed to unlink %s: %d\n", td_control.path, errno);
		goto fail;
	}

	td_control.socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (td_control.socket == -1) {
		err = errno;
		EPRINTF("failed to create control socket: %d\n", err);
		goto fail;
	}

	memset(&saddr, 0, sizeof(saddr));
	strncpy(saddr.sun_path, td_control.path, sizeof(saddr.sun_path));
	saddr.sun_family = AF_UNIX;

	err = bind(td_control.socket,
		   (const struct sockaddr *)&saddr, sizeof(saddr));
	if (err == -1) {
		err = errno;
		EPRINTF("failed to bind to %s: %d\n", saddr.sun_path, err);
		goto fail;
	}

	err = listen(td_control.socket, 10);
	if (err == -1) {
		err = errno;
		EPRINTF("failed to listen: %d\n", err);
		goto fail;
	}

	err = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
					    td_control.socket, 0,
					    tapdisk_control_accept, NULL);
	if (err < 0) {
		EPRINTF("failed to add watch: %d\n", err);
		goto fail;
	}

	td_control.event_id = err;
	*socket_path = td_control.path;

	return 0;

fail:
	tapdisk_control_close();
	return err;
}

int
tapdisk_control_open(char **path)
{
	int err;

	tapdisk_control_initialize();

	return tapdisk_control_create_socket(path);
}
